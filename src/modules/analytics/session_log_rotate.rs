//! Session log 切桶、关闭后压缩与可选 S3 归档。
//!
//! 只处理本进程写过并已离开的那个文件。程序 log 不走这里。

use chrono::{DateTime, Local, Timelike};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{error, warn};

use crate::modules::server::s3::S3Signer;

const DEFAULT_ZSTD_LEVEL: i32 = 3;
const DEFAULT_SYNC_ZSTD_LEVEL: i32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompressMode {
    Zstd,
    None,
}

enum ArchiveSink {
    S3(S3Signer),
    #[cfg(test)]
    Capture(std::sync::Arc<Mutex<Vec<(String, Vec<u8>)>>>),
    #[cfg(test)]
    Fail,
}

impl ArchiveSink {
    async fn put(&self, key: &str, body: &[u8]) -> Result<(), String> {
        match self {
            Self::S3(signer) => signer
                .put_object(key, body)
                .await
                .map_err(|e| e.to_string()),
            #[cfg(test)]
            Self::Capture(buf) => {
                buf.lock().await.push((key.to_string(), body.to_vec()));
                Ok(())
            }
            #[cfg(test)]
            Self::Fail => Err("archive sink failed".to_string()),
        }
    }
}

#[derive(Clone, Debug)]
struct SessionLogSettings {
    enabled: bool,
    path: String,
    rotate_hours: u32,
    compress: CompressMode,
    zstd_level: i32,
    archive_prefix: String,
    sync_minutes: u64,
    sync_zstd_level: i32,
}

impl SessionLogSettings {
    fn from_env() -> Self {
        let compress = match std::env::var("SESSION_LOG_COMPRESS") {
            Err(_) => CompressMode::Zstd,
            Ok(raw) => match raw.to_ascii_lowercase().as_str() {
                "zstd" => CompressMode::Zstd,
                "none" => CompressMode::None,
                _ => {
                    warn!("SESSION_LOG_COMPRESS is invalid, using zstd");
                    CompressMode::Zstd
                }
            },
        };

        Self {
            enabled: parse_bool_env("SESSION_LOG_ENABLED", true),
            path: std::env::var("SESSION_LOG_PATH").unwrap_or_else(|_| "logs/sessions".to_string()),
            rotate_hours: parse_rotate_hours(),
            compress,
            zstd_level: parse_zstd_level("SESSION_LOG_ZSTD_LEVEL", DEFAULT_ZSTD_LEVEL),
            archive_prefix: std::env::var("SESSION_LOG_ARCHIVE_PREFIX").unwrap_or_default(),
            sync_minutes: parse_u64_env("SESSION_LOG_SYNC_MINUTES", 0),
            sync_zstd_level: parse_zstd_level(
                "SESSION_LOG_SYNC_ZSTD_LEVEL",
                DEFAULT_SYNC_ZSTD_LEVEL,
            ),
        }
    }
}

struct Guarded {
    remembered: Option<String>,
    closed: HashSet<String>,
}

struct SessionLogRotator {
    settings: SessionLogSettings,
    write_lock: Mutex<Guarded>,
    archive: Option<ArchiveSink>,
}

static GLOBAL: OnceLock<SessionLogRotator> = OnceLock::new();

fn global() -> &'static SessionLogRotator {
    GLOBAL.get_or_init(SessionLogRotator::from_env)
}

/// 追加一行已序列化的 JSON（调用方负责序列化，锁外）。
pub async fn append_line(line: &str) -> Result<(), String> {
    if !global().settings.enabled {
        return Ok(());
    }
    global().append_with_time(line, None).await
}

/// 若 remembered stem 已不是当前桶，关闭那一个文件。不扫目录。
pub async fn compress_stale_remembered() {
    global().compress_stale_remembered().await;
}

/// 启动当前桶分钟同步。无归档或间隔为 0 时不启动。
pub fn start_sync_ticker() {
    global().spawn_sync_ticker();
}

impl SessionLogRotator {
    fn from_env() -> Self {
        let settings = SessionLogSettings::from_env();
        let archive = match std::env::var("SESSION_LOG_ARCHIVE_S3") {
            Err(_) => None,
            Ok(url) if url.is_empty() => None,
            Ok(url) => match S3Signer::from_url(&url) {
                Ok(signer) => Some(ArchiveSink::S3(signer)),
                Err(_) => {
                    error!("SESSION_LOG_ARCHIVE_S3 is invalid");
                    None
                }
            },
        };
        Self::new(settings, archive)
    }

    fn new(settings: SessionLogSettings, archive: Option<ArchiveSink>) -> Self {
        Self {
            settings,
            write_lock: Mutex::new(Guarded {
                remembered: None,
                closed: HashSet::new(),
            }),
            archive,
        }
    }

    async fn append_line_at(&self, line: &str, now: DateTime<Local>) -> Result<(), String> {
        self.append_with_time(line, Some(now)).await
    }

    async fn append_with_time(
        &self,
        line: &str,
        now: Option<DateTime<Local>>,
    ) -> Result<(), String> {
        let dir = Path::new(&self.settings.path);
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("Failed to create log directory: {e}"))?;

        let to_close = {
            let mut g = self.write_lock.lock().await;
            // Sample time under the lock. A `now` captured before waiting can close
            // the file another task just started writing after a bucket boundary.
            let stem = bucket_stem(now.unwrap_or_else(Local::now), self.settings.rotate_hours);
            let prev = g.remembered.clone();
            g.remembered = Some(stem.clone());
            let stale = prev.filter(|p| p != &stem);
            let path = dir.join(format!("{stem}.log"));
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
                .map_err(|e| format!("Failed to open log file: {e}"))?;
            file.write_all(format!("{line}\n").as_bytes())
                .await
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            if let Err(e) = file.sync_all().await {
                warn!("Failed to sync session log: {e}");
            }
            stale
        };

        if let Some(prev) = to_close {
            self.close_stem(&prev).await;
        }
        Ok(())
    }

    async fn compress_stale_remembered(&self) {
        let stale = {
            let mut g = self.write_lock.lock().await;
            let current = bucket_stem(Local::now(), self.settings.rotate_hours);
            match &g.remembered {
                Some(rem) if rem != &current => {
                    let stem = rem.clone();
                    g.remembered = None;
                    Some(stem)
                }
                _ => None,
            }
        };
        if let Some(stem) = stale {
            self.close_stem(&stem).await;
        }
    }

    async fn close_stem(&self, stem: &str) {
        {
            let mut g = self.write_lock.lock().await;
            if g.remembered.as_deref() == Some(stem) {
                return;
            }
            if !g.closed.insert(stem.to_string()) {
                return;
            }
        }

        let dir = Path::new(&self.settings.path);
        let plain = dir.join(format!("{stem}.log"));
        let zst = dir.join(format!("{stem}.log.zst"));

        let upload_path = match self.prepare_closed_artifact(&plain, &zst).await {
            Ok(path) => path,
            Err(e) => {
                error!(stem, error = %e, "session log rotate failed");
                let mut g = self.write_lock.lock().await;
                g.closed.remove(stem);
                return;
            }
        };

        if let (Some(archive), Some(path)) = (&self.archive, upload_path.as_ref()) {
            match tokio::fs::read(path).await {
                Ok(body) => {
                    let key = format!("{}{stem}.log.zst", self.settings.archive_prefix);
                    if let Err(e) = archive.put(&key, &body).await {
                        error!(key, error = %e, "session log archive PUT failed");
                    }
                }
                Err(e) => error!(stem, error = %e, "session log archive read failed"),
            }
            if self.settings.compress == CompressMode::None && path != &zst && path != &plain {
                let _ = tokio::fs::remove_file(path).await;
            }
        }
    }

    /// 本地关闭产物。`Some` 是要上传的 `.zst`；无归档且 `none` 时为 `None`。
    async fn prepare_closed_artifact(
        &self,
        plain: &Path,
        zst: &Path,
    ) -> Result<Option<PathBuf>, String> {
        let plain_exists = tokio::fs::try_exists(plain).await.unwrap_or(false);
        let zst_exists = tokio::fs::try_exists(zst).await.unwrap_or(false);

        match self.settings.compress {
            CompressMode::Zstd => {
                if zst_exists {
                    if plain_exists {
                        let _ = tokio::fs::remove_file(plain).await;
                    }
                    return Ok(Some(zst.to_path_buf()));
                }
                if !plain_exists {
                    return Ok(None);
                }
                let level = self.settings.zstd_level;
                let src = plain.to_path_buf();
                let dest = zst.to_path_buf();
                tokio::task::spawn_blocking(move || zstd_compress_file(&src, &dest, level))
                    .await
                    .map_err(|e| e.to_string())??;
                let _ = tokio::fs::remove_file(plain).await;
                Ok(Some(zst.to_path_buf()))
            }
            CompressMode::None => {
                if self.archive.is_none() {
                    return Ok(None);
                }
                if !plain_exists {
                    return Ok(None);
                }
                let tmp = sibling_temp(zst, "upload");
                let level = self.settings.zstd_level;
                let src = plain.to_path_buf();
                let dest = tmp.clone();
                tokio::task::spawn_blocking(move || zstd_compress_file(&src, &dest, level))
                    .await
                    .map_err(|e| e.to_string())??;
                Ok(Some(tmp))
            }
        }
    }

    async fn sync_current(&self) -> Result<(), String> {
        let (stem, current) = {
            let g = self.write_lock.lock().await;
            let current = bucket_stem(Local::now(), self.settings.rotate_hours);
            (g.remembered.clone(), current)
        };
        let Some(stem) = stem else {
            return Ok(());
        };
        if stem != current {
            return Ok(());
        }

        let plain = Path::new(&self.settings.path).join(format!("{stem}.log"));
        let meta = match tokio::fs::metadata(&plain).await {
            Ok(m) if m.len() > 0 => m,
            _ => return Ok(()),
        };
        let _ = meta;

        let copy = sibling_temp(&plain, "sync-src");
        tokio::fs::copy(&plain, &copy)
            .await
            .map_err(|e| format!("session log sync copy failed: {e}"))?;
        let zst_tmp = sibling_temp(
            &Path::new(&self.settings.path).join(format!("{stem}.log.zst")),
            "sync",
        );
        let level = self.settings.sync_zstd_level;
        let src = copy.clone();
        let dest = zst_tmp.clone();
        let compress_result =
            tokio::task::spawn_blocking(move || zstd_compress_file(&src, &dest, level))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r);
        let _ = tokio::fs::remove_file(&copy).await;
        if let Err(e) = compress_result {
            let _ = tokio::fs::remove_file(&zst_tmp).await;
            return Err(e);
        }

        let still_current = {
            let g = self.write_lock.lock().await;
            let now_stem = bucket_stem(Local::now(), self.settings.rotate_hours);
            g.remembered.as_deref() == Some(stem.as_str()) && now_stem == stem
        };
        if !still_current {
            let _ = tokio::fs::remove_file(&zst_tmp).await;
            return Ok(());
        }

        if let Some(archive) = &self.archive {
            let body = tokio::fs::read(&zst_tmp)
                .await
                .map_err(|e| format!("session log sync read failed: {e}"))?;
            let key = format!("{}{stem}.log.zst", self.settings.archive_prefix);
            if let Err(e) = archive.put(&key, &body).await {
                let _ = tokio::fs::remove_file(&zst_tmp).await;
                return Err(e);
            }
        }
        let _ = tokio::fs::remove_file(&zst_tmp).await;
        Ok(())
    }

    fn spawn_sync_ticker(&'static self) {
        if self.settings.sync_minutes == 0 {
            return;
        }
        if self.archive.is_none() {
            warn!("SESSION_LOG_SYNC_MINUTES is set without SESSION_LOG_ARCHIVE_S3");
            return;
        }
        let minutes = self.settings.sync_minutes;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(minutes.saturating_mul(60)));
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(e) = self.sync_current().await {
                    error!(error = %e, "session log S3 sync failed");
                }
            }
        });
    }
}

pub(crate) fn bucket_stem(now: DateTime<Local>, hours: u32) -> String {
    let hours = hours.clamp(1, 24);
    if hours >= 24 {
        format!("sessions.{}", now.format("%Y-%m-%d"))
    } else {
        let hour = now.hour() / hours * hours;
        format!("sessions.{}-{:02}", now.format("%Y-%m-%d"), hour)
    }
}

fn parse_rotate_hours() -> u32 {
    match std::env::var("SESSION_LOG_ROTATE_HOURS") {
        Err(_) => 24,
        Ok(raw) => match raw.parse::<u32>() {
            Ok(n) if (1..=24).contains(&n) => n,
            _ => {
                warn!("SESSION_LOG_ROTATE_HOURS is invalid, using 24");
                24
            }
        },
    }
}

fn parse_zstd_level(var: &str, default: i32) -> i32 {
    match std::env::var(var) {
        Err(_) => default,
        Ok(raw) => match raw.parse::<i32>() {
            Ok(n) => n,
            Err(_) => {
                warn!(var, "invalid zstd level, using default");
                default
            }
        },
    }
}

fn parse_u64_env(var: &str, default: u64) -> u64 {
    match std::env::var(var) {
        Err(_) => default,
        Ok(raw) => match raw.parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                warn!(var, "invalid integer, using default");
                default
            }
        },
    }
}

fn parse_bool_env(var: &str, default: bool) -> bool {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn sibling_temp(path: &Path, tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.{tag}.{nanos}"))
}

fn zstd_compress_file(src: &Path, dest: &Path, level: i32) -> Result<(), String> {
    let tmp = sibling_temp(dest, "tmp");
    let result = (|| -> Result<(), String> {
        let mut input = std::fs::File::open(src).map_err(|e| e.to_string())?;
        let output = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        let mut encoder = match zstd::stream::write::Encoder::new(output, level) {
            Ok(encoder) => encoder,
            Err(_) => {
                warn!(level, "zstd level rejected, using default");
                let output = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
                zstd::stream::write::Encoder::new(output, DEFAULT_ZSTD_LEVEL)
                    .map_err(|e| e.to_string())?
            }
        };
        io::copy(&mut input, &mut encoder).map_err(|e| e.to_string())?;
        encoder.finish().map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, dest).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Arc;

    fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Local> {
        Local
            .with_ymd_and_hms(year, month, day, hour, 0, 0)
            .single()
            .expect("valid local time")
    }

    fn settings(dir: &Path, compress: CompressMode) -> SessionLogSettings {
        SessionLogSettings {
            enabled: true,
            path: dir.to_string_lossy().into_owned(),
            rotate_hours: 24,
            compress,
            zstd_level: 3,
            archive_prefix: String::new(),
            sync_minutes: 0,
            sync_zstd_level: 1,
        }
    }

    fn rotator(dir: &Path, compress: CompressMode) -> SessionLogRotator {
        SessionLogRotator::new(settings(dir, compress), None)
    }

    #[test]
    fn daily_stem_has_no_hour() {
        assert_eq!(bucket_stem(at(2026, 9, 11, 7), 24), "sessions.2026-09-11");
    }

    #[test]
    fn six_hour_stem_floors_to_bucket_start() {
        assert_eq!(bucket_stem(at(2026, 9, 11, 7), 6), "sessions.2026-09-11-06");
        assert_eq!(bucket_stem(at(2026, 9, 11, 0), 6), "sessions.2026-09-11-00");
    }

    #[tokio::test]
    async fn rotate_compresses_only_remembered_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let rot = rotator(dir.path(), CompressMode::Zstd);
        let stray = dir.path().join("sessions.2026-09-09.log");
        std::fs::write(&stray, "old-stray\n").unwrap();

        rot.append_line_at("{\"n\":1}", at(2026, 9, 11, 10))
            .await
            .unwrap();
        rot.append_line_at("{\"n\":2}", at(2026, 9, 12, 10))
            .await
            .unwrap();

        assert!(dir.path().join("sessions.2026-09-11.log.zst").exists());
        assert!(!dir.path().join("sessions.2026-09-11.log").exists());
        assert!(dir.path().join("sessions.2026-09-12.log").exists());
        assert_eq!(std::fs::read_to_string(&stray).unwrap(), "old-stray\n");
    }

    #[tokio::test]
    async fn first_write_does_not_compress_preexisting_file() {
        let dir = tempfile::tempdir().unwrap();
        let rot = rotator(dir.path(), CompressMode::Zstd);
        let old = dir.path().join("sessions.2026-09-10.log");
        std::fs::write(&old, "preexisting\n").unwrap();

        rot.append_line_at("{\"n\":1}", at(2026, 9, 11, 10))
            .await
            .unwrap();

        assert!(old.exists());
        assert!(!dir.path().join("sessions.2026-09-10.log.zst").exists());
        assert!(dir.path().join("sessions.2026-09-11.log").exists());
    }

    #[tokio::test]
    async fn compress_none_keeps_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let rot = rotator(dir.path(), CompressMode::None);
        rot.append_line_at("{\"n\":1}", at(2026, 9, 11, 10))
            .await
            .unwrap();
        rot.append_line_at("{\"n\":2}", at(2026, 9, 12, 10))
            .await
            .unwrap();

        assert!(dir.path().join("sessions.2026-09-11.log").exists());
        assert!(!dir.path().join("sessions.2026-09-11.log.zst").exists());
    }

    #[tokio::test]
    async fn concurrent_appends_are_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let rot = Arc::new(rotator(dir.path(), CompressMode::None));
        let a = {
            let rot = Arc::clone(&rot);
            tokio::spawn(async move { rot.append_line_at("{\"a\":1}", at(2026, 9, 11, 10)).await })
        };
        let b = {
            let rot = Arc::clone(&rot);
            tokio::spawn(async move { rot.append_line_at("{\"b\":2}", at(2026, 9, 11, 10)).await })
        };
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();

        let text = std::fs::read_to_string(dir.path().join("sessions.2026-09-11.log")).unwrap();
        let mut lines: Vec<_> = text.lines().collect();
        lines.sort();
        assert_eq!(lines, ["{\"a\":1}", "{\"b\":2}"]);
    }

    #[tokio::test]
    async fn compress_none_with_archive_puts_zst_and_keeps_plain() {
        let dir = tempfile::tempdir().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let mut cfg = settings(dir.path(), CompressMode::None);
        cfg.archive_prefix = "pref/".to_string();
        let rot = SessionLogRotator::new(cfg, Some(ArchiveSink::Capture(Arc::clone(&captured))));

        rot.append_line_at("{\"n\":1}", at(2026, 9, 11, 10))
            .await
            .unwrap();
        rot.append_line_at("{\"n\":2}", at(2026, 9, 12, 10))
            .await
            .unwrap();

        assert!(dir.path().join("sessions.2026-09-11.log").exists());
        assert!(!dir.path().join("sessions.2026-09-11.log.zst").exists());
        let puts = captured.lock().await;
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].0, "pref/sessions.2026-09-11.log.zst");
        assert!(!puts[0].1.is_empty());
    }

    #[tokio::test]
    async fn failed_archive_keeps_local_zst() {
        let dir = tempfile::tempdir().unwrap();
        let rot = SessionLogRotator::new(
            settings(dir.path(), CompressMode::Zstd),
            Some(ArchiveSink::Fail),
        );
        rot.append_line_at("{\"n\":1}", at(2026, 9, 11, 10))
            .await
            .unwrap();
        rot.append_line_at("{\"n\":2}", at(2026, 9, 12, 10))
            .await
            .unwrap();

        assert!(dir.path().join("sessions.2026-09-11.log.zst").exists());
        assert!(!dir.path().join("sessions.2026-09-11.log").exists());
    }

    #[tokio::test]
    async fn sync_leaves_local_plaintext_and_skips_without_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let rot = SessionLogRotator::new(
            settings(dir.path(), CompressMode::Zstd),
            Some(ArchiveSink::Capture(Arc::clone(&captured))),
        );
        std::fs::write(dir.path().join("sessions.2026-09-11.log"), "{\"n\":0}\n").unwrap();
        rot.sync_current().await.unwrap();
        assert!(captured.lock().await.is_empty());

        rot.append_line_at("{\"n\":1}", Local::now()).await.unwrap();
        rot.sync_current().await.unwrap();

        let stem = bucket_stem(Local::now(), 24);
        assert!(dir.path().join(format!("{stem}.log")).exists());
        assert!(!dir.path().join(format!("{stem}.log.zst")).exists());
        let puts = captured.lock().await;
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].0, format!("{stem}.log.zst"));
    }

    #[tokio::test]
    async fn sync_put_aborts_when_stem_changes() {
        let dir = tempfile::tempdir().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let rot = SessionLogRotator::new(
            settings(dir.path(), CompressMode::None),
            Some(ArchiveSink::Capture(Arc::clone(&captured))),
        );
        rot.append_line_at("{\"n\":1}", at(2026, 9, 11, 10))
            .await
            .unwrap();
        {
            let mut g = rot.write_lock.lock().await;
            g.remembered = Some("sessions.2026-09-12".to_string());
        }
        rot.sync_current().await.unwrap();
        assert!(captured.lock().await.is_empty());
        assert!(dir.path().join("sessions.2026-09-11.log").exists());
    }
}
