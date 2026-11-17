use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use tracing::{error, warn};

use crate::modules::analytics::session_log_rotate;

use crate::models::{InsightData, InsightItem};
use crate::modules::analytics::models::*;
use crate::modules::storage::data_store::DataStore;
use crate::modules::storage::data_store::SessionStats;
use crate::services::SessionService;

pub struct SessionLogger {
    redis: DataStore,
}

impl SessionLogger {
    pub fn new(redis: DataStore) -> Self {
        Self { redis }
    }

    /// 记录正常完成的 Session
    pub async fn log_session_completed(
        &self,
        session_id: &str,
        resource_id: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
        insights: Option<InsightData>,
    ) -> Result<(), String> {
        let session_stats = self
            .redis
            .get_session_stats(session_id)
            .await
            .map_err(|e| format!("Failed to get session stats: {e}"))?;

        if let Some(stats) = session_stats {
            let session_log = self
                .build_session_log(
                    "session_completed",
                    Some(session_id.to_string()),
                    resource_id,
                    client_ip,
                    user_agent,
                    &stats,
                    insights,
                )
                .await?;

            self.write_log(&session_log).await
        } else {
            Err(format!("Session {session_id} not found"))
        }
    }

    /// 记录超时的 Session
    pub async fn log_session_timeout(
        &self,
        session_id: &str,
        resource_id: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
    ) -> Result<(), String> {
        let session_stats = self
            .redis
            .get_session_stats(session_id)
            .await
            .map_err(|e| format!("Failed to get session stats: {e}"))?;

        if let Some(stats) = session_stats {
            let session_log = self
                .build_session_log(
                    "session_timeout",
                    Some(session_id.to_string()),
                    resource_id,
                    client_ip,
                    user_agent,
                    &stats,
                    None,
                )
                .await?;

            self.write_log(&session_log).await
        } else {
            warn!(
                "Session {} not found when trying to log timeout",
                session_id
            );
            Ok(())
        }
    }

    /// 记录直接下载
    #[allow(clippy::too_many_arguments)]
    pub async fn log_direct_download(
        &self,
        resource_id: &str,
        version: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
        cdn_url: &str,
        server_id: &str,
        server_weight: u32,
    ) -> Result<(), String> {
        let now = Utc::now();

        // 构建CDN记录
        let cdn_record = CdnRecordLog {
            url: cdn_url.to_string(),
            srv: Some(server_id.to_string()),
            wgt: Some(server_weight),
            ts: now.timestamp() as u64,
            pen: Some(false),
            rsn: Some("flow_selected".to_string()),
            ttfb: None,
            time: None,
            size: None,
            err: None,
            mode: None,
        };

        let chunk = ChunkLog {
            rng: "full_file".to_string(),
            att: 1,
            cdns: vec![cdn_record],
        };

        let session_log = SessionLog {
            start: now.timestamp() as u64, // direct download没有真正的session创建时间
            end: now.timestamp() as u64,
            log_type: "direct_download".to_string(),
            sid: None,
            rid: resource_id.to_string(),
            ver: version.to_string(),
            ua: user_agent,
            ip: (
                client_ip.to_string(),
                crate::modules::external::geolocation::get_ip_location_data(client_ip),
            ),
            chunks: vec![chunk],
        };

        self.write_log(&session_log).await
    }

    /// 记录缓存命中的下载
    ///
    /// 命中不经过 CDN，但仍合成一条 CDN 记录，把字节归到当初供出这份缓存的节点上，
    /// 否则缓存流量在按 `srv` 聚合的分析里会整体消失。`mode` 固定为 `cache`，便于剔除。
    #[allow(clippy::too_many_arguments)]
    pub async fn log_cached_download(
        &self,
        resource_id: &str,
        version: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
        session_id: Option<String>,
        file_size: u64,
        source_server: Option<&str>,
    ) -> Result<(), String> {
        let now = Utc::now();

        let cdn_record = CdnRecordLog {
            url: format!("cache://{resource_id}/{version}"),
            srv: source_server.map(|id| id.to_string()),
            wgt: None,
            ts: now.timestamp() as u64,
            pen: Some(false),
            rsn: Some("cache_hit".to_string()),
            ttfb: None,
            time: None,
            size: u32::try_from(file_size).ok(),
            err: None,
            mode: Some("cache".to_string()),
        };

        let chunk = ChunkLog {
            rng: "full_file".to_string(),
            att: 1,
            cdns: vec![cdn_record],
        };

        let session_log = SessionLog {
            start: now.timestamp() as u64, // cached download没有真正的session创建时间
            end: now.timestamp() as u64,
            log_type: "cached_download".to_string(),
            sid: session_id,
            rid: resource_id.to_string(),
            ver: version.to_string(),
            ua: user_agent,
            ip: (
                client_ip.to_string(),
                crate::modules::external::geolocation::get_ip_location_data(client_ip),
            ),
            chunks: vec![chunk],
        };

        self.write_log(&session_log).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_session_log(
        &self,
        log_type: &str,
        session_id: Option<String>,
        resource_id: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
        stats: &SessionStats,
        insights: Option<InsightData>,
    ) -> Result<SessionLog, String> {
        Ok(assemble_session_log(
            log_type,
            session_id,
            resource_id,
            client_ip,
            user_agent,
            stats,
            insights,
            Utc::now().timestamp() as u64,
        ))
    }

    /// 写入日志文件
    async fn write_log(&self, session_log: &SessionLog) -> Result<(), String> {
        if !self.is_enabled() {
            return Ok(());
        }

        let log_json = match serde_json::to_string(session_log) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize session log: {}", e);
                return Err(format!("Failed to serialize log: {e}"));
            }
        };

        session_log_rotate::append_line(&log_json).await
    }

    fn take_matching_insight(
        unmatched: &mut Vec<InsightItem>,
        record_url: &str,
        chunk_id: &str,
    ) -> Option<InsightItem> {
        let pos = unmatched.iter().position(|insight| {
            Self::urls_match(&insight.url, record_url)
                && Self::ranges_match(&insight.range, chunk_id)
        })?;
        Some(unmatched.remove(pos))
    }

    /// 检查是否启用日志记录
    pub fn is_enabled(&self) -> bool {
        std::env::var("SESSION_LOG_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true)
    }

    /// 检查两个URL是否匹配（忽略签名参数等差异）
    fn urls_match(insight_url: &str, cdn_url: &str) -> bool {
        // 简单的URL匹配，可以根据需要增强
        // 目前只做基本的字符串匹配，将来可以添加更智能的匹配逻辑
        insight_url == cdn_url
            || Self::extract_base_url(insight_url) == Self::extract_base_url(cdn_url)
    }

    /// 提取URL的基础部分（去除查询参数）
    fn extract_base_url(url: &str) -> &str {
        if let Some(pos) = url.find('?') {
            &url[..pos]
        } else {
            url
        }
    }

    /// 检查客户端range是否与 chunk key 的 range 段完全匹配。
    fn ranges_match(client_ranges: &[(u32, u32)], chunk_id: &str) -> bool {
        let chunk_id = SessionService::scoped_key_range(chunk_id);
        if Self::ranges_to_string(client_ranges) == chunk_id {
            return true;
        }
        // hashed 整文件：服务器是 `0-`，安装器上报 `(0, u32::MAX)`
        if let Some(start_str) = chunk_id.strip_suffix('-')
            && !start_str.is_empty()
            && !start_str.contains('-')
            && !chunk_id.contains(',')
            && let Ok(start) = start_str.parse::<u32>()
        {
            return client_ranges.len() == 1 && client_ranges[0].0 == start;
        }
        false
    }

    /// 将range列表转换为标准字符串格式
    fn ranges_to_string(ranges: &[(u32, u32)]) -> String {
        if ranges.is_empty() {
            return String::new();
        }

        // 按起始位置排序
        let mut sorted_ranges = ranges.to_vec();
        sorted_ranges.sort_by_key(|&(start, _)| start);

        // 转换为字符串格式
        if sorted_ranges.len() == 1 {
            // 单个range: "start-end"
            format!("{}-{}", sorted_ranges[0].0, sorted_ranges[0].1)
        } else {
            // 多个range: "start1-end1,start2-end2,..."
            sorted_ranges
                .iter()
                .map(|(start, end)| format!("{}-{}", start, end))
                .collect::<Vec<_>>()
                .join(",")
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_session_log(
    log_type: &str,
    session_id: Option<String>,
    resource_id: &str,
    client_ip: IpAddr,
    user_agent: Option<String>,
    stats: &SessionStats,
    insights: Option<InsightData>,
    now_ts: u64,
) -> SessionLog {
    let mut unmatched_insights = insights.map(|data| data.servers).unwrap_or_default();
    let mut chunks = Vec::new();

    for chunk_id in log_chunk_ids(stats) {
        let download_attempts = stats.download_counts.get(&chunk_id).copied().unwrap_or(0);
        let empty_records = Vec::new();
        let cdn_records = stats.cdn_records.get(&chunk_id).unwrap_or(&empty_records);
        let scoped = chunk_id.contains(':');

        let mut cdn_record_logs: Vec<CdnRecordLog> = cdn_records
            .iter()
            .map(|record| {
                let matched = SessionLogger::take_matching_insight(
                    &mut unmatched_insights,
                    &record.url,
                    &chunk_id,
                );
                CdnRecordLog {
                    url: record.url.clone(),
                    srv: record.server_id.clone(),
                    wgt: Some(record.weight),
                    ts: record.timestamp,
                    pen: Some(record.skip_penalty),
                    rsn: Some(
                        if record.skip_penalty {
                            "retry_fallback"
                        } else {
                            "flow_selected"
                        }
                        .to_string(),
                    ),
                    ttfb: matched.as_ref().map(|i| i.ttfb),
                    time: matched.as_ref().map(|i| i.time),
                    size: matched.as_ref().map(|i| i.size),
                    err: matched.as_ref().and_then(|i| i.error.clone()),
                    mode: matched.as_ref().and_then(|i| i.mode.clone()),
                }
            })
            .collect();

        // scoped key 只靠 URL 对齐 insight；相同 range 不能跨文件归堆。
        if !scoped {
            for insight in unmatched_insights.iter() {
                if SessionLogger::ranges_match(&insight.range, &chunk_id) {
                    cdn_record_logs.push(insight_only_record(insight, now_ts));
                }
            }
            unmatched_insights
                .retain(|insight| !SessionLogger::ranges_match(&insight.range, &chunk_id));
        }

        chunks.push(ChunkLog {
            rng: chunk_id,
            att: download_attempts,
            cdns: cdn_record_logs,
        });
    }

    let mut additional_chunks = HashMap::<String, Vec<InsightItem>>::new();
    for insight in unmatched_insights {
        for (start, end) in &insight.range {
            additional_chunks
                .entry(format!("{start}-{end}"))
                .or_default()
                .push(insight.clone());
        }
    }

    for (range_str, insight_items) in additional_chunks {
        chunks.push(ChunkLog {
            rng: range_str,
            att: 0,
            cdns: insight_items
                .into_iter()
                .map(|insight| insight_only_record(&insight, now_ts))
                .collect(),
        });
    }

    SessionLog {
        start: stats.created_at,
        end: now_ts,
        log_type: log_type.to_string(),
        sid: session_id,
        rid: resource_id.to_string(),
        ver: stats.version.clone(),
        ua: user_agent,
        ip: (
            client_ip.to_string(),
            crate::modules::external::geolocation::get_ip_location_data(client_ip),
        ),
        chunks,
    }
}

fn insight_only_record(insight: &InsightItem, now_ts: u64) -> CdnRecordLog {
    CdnRecordLog {
        url: insight.url.clone(),
        srv: None,
        wgt: None,
        ts: now_ts,
        pen: None,
        rsn: None,
        ttfb: Some(insight.ttfb),
        time: Some(insight.time),
        size: Some(insight.size),
        err: insight.error.clone(),
        mode: insight.mode.clone(),
    }
}

/// `session.chunks` 是白名单 range；已有 scoped key 覆盖该 range 时不再单写裸 key。
fn log_chunk_ids(stats: &SessionStats) -> Vec<String> {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    for key in stats.cdn_records.keys().chain(stats.download_counts.keys()) {
        if seen.insert(key.clone()) {
            ids.push(key.clone());
        }
    }
    for chunk in &stats.chunks {
        if seen.contains(chunk) {
            continue;
        }
        if ids
            .iter()
            .any(|id| SessionService::scoped_key_range(id) == chunk)
        {
            continue;
        }
        seen.insert(chunk.clone());
        ids.push(chunk.clone());
    }
    ids.sort();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CdnRecord;
    use std::net::{IpAddr, Ipv4Addr};

    fn insight(url: &str, range: Vec<(u32, u32)>, size: u32) -> InsightItem {
        InsightItem {
            url: url.to_string(),
            ttfb: 10,
            time: 20,
            size,
            error: None,
            range,
            mode: None,
        }
    }

    fn record(url: &str, server: &str) -> CdnRecord {
        CdnRecord {
            url: url.to_string(),
            server_id: Some(server.to_string()),
            skip_penalty: false,
            timestamp: 1,
            weight: 10,
            size: Some(100),
        }
    }

    fn stats(
        version: &str,
        chunks: Vec<&str>,
        download_counts: HashMap<String, u32>,
        cdn_records: HashMap<String, Vec<CdnRecord>>,
    ) -> SessionStats {
        SessionStats {
            resource_id: "resid".into(),
            version: version.into(),
            chunks: chunks.into_iter().map(str::to_string).collect(),
            download_counts,
            cdn_records,
            created_at: 100,
        }
    }

    fn assemble(stats: &SessionStats, insights: Option<InsightData>) -> SessionLog {
        assemble_session_log(
            "session_completed",
            Some("sid".into()),
            "resid",
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            None,
            stats,
            insights,
            200,
        )
    }

    fn chunk<'a>(log: &'a SessionLog, rng: &str) -> &'a ChunkLog {
        log.chunks.iter().find(|c| c.rng == rng).unwrap_or_else(|| {
            panic!(
                "missing chunk {rng}; have {:?}",
                log.chunks.iter().map(|c| &c.rng).collect::<Vec<_>>()
            )
        })
    }

    #[test]
    fn closed_range_matches_exact_chunk() {
        assert!(SessionLogger::ranges_match(&[(100, 200)], "100-200"));
        assert!(!SessionLogger::ranges_match(&[(100, 200)], "0-"));
        assert!(SessionLogger::ranges_match(
            &[(100, 200)],
            "a/one.bin:100-200"
        ));
        assert!(!SessionLogger::ranges_match(&[(100, 200)], "a/one.bin:0-"));
    }

    #[test]
    fn open_chunk_matches_same_start() {
        assert!(SessionLogger::ranges_match(&[(0, u32::MAX)], "0-"));
        assert!(SessionLogger::ranges_match(&[(0, 10)], "0-"));
        assert!(SessionLogger::ranges_match(
            &[(0, u32::MAX)],
            "a/one.bin:0-"
        ));
        assert!(!SessionLogger::ranges_match(&[(1, u32::MAX)], "0-"));
        assert!(!SessionLogger::ranges_match(&[(0, 10), (11, 20)], "0-"));
    }

    #[test]
    fn prefix_scoped_keys_keep_server_records() {
        let stats = stats(
            "1.2.3",
            vec!["0-"],
            HashMap::from([("a/one.bin:0-".into(), 2)]),
            HashMap::from([(
                "a/one.bin:0-".into(),
                vec![record("https://cdn.example/a/one.bin?sig=1", "cdn1")],
            )]),
        );
        let insights = InsightData {
            servers: vec![insight(
                "https://cdn.example/a/one.bin?sig=1",
                vec![(0, u32::MAX)],
                42,
            )],
        };
        let log = assemble(&stats, Some(insights));
        let file_chunk = chunk(&log, "a/one.bin:0-");
        assert_eq!(file_chunk.att, 2);
        assert_eq!(file_chunk.cdns.len(), 1);
        assert_eq!(file_chunk.cdns[0].srv.as_deref(), Some("cdn1"));
        assert_eq!(file_chunk.cdns[0].size, Some(42));
        assert!(!log.chunks.iter().any(|c| c.rng == "0-"));
        assert_eq!(log.ver, "1.2.3");
    }

    #[test]
    fn insight_is_consumed_once_across_retries() {
        let stats = stats(
            "1.0.0",
            vec!["0-"],
            HashMap::from([("0-".into(), 2)]),
            HashMap::from([(
                "0-".into(),
                vec![
                    record("https://cdn.example/file?sig=1", "cdn1"),
                    record("https://cdn.example/file?sig=2", "cdn2"),
                ],
            )]),
        );
        let insights = InsightData {
            servers: vec![insight(
                "https://cdn.example/file?sig=1",
                vec![(0, u32::MAX)],
                42,
            )],
        };
        let log = assemble(&stats, Some(insights));
        let cdns = &chunk(&log, "0-").cdns;
        assert_eq!(cdns.len(), 2);
        assert_eq!(cdns[0].size, Some(42));
        assert_eq!(cdns[0].srv.as_deref(), Some("cdn1"));
        assert_eq!(cdns[1].size, None);
        assert_eq!(cdns[1].srv.as_deref(), Some("cdn2"));
    }

    #[test]
    fn prefix_unmatched_insight_does_not_attach_by_range_only() {
        let stats = stats(
            "1.0.0",
            vec!["0-"],
            HashMap::new(),
            HashMap::from([
                (
                    "a/one.bin:0-".into(),
                    vec![record("https://cdn.example/a/one.bin", "cdn1")],
                ),
                (
                    "b/two.bin:0-".into(),
                    vec![record("https://cdn.example/b/two.bin", "cdn2")],
                ),
            ]),
        );
        let insights = InsightData {
            servers: vec![insight(
                "https://other.example/orphan",
                vec![(0, u32::MAX)],
                7,
            )],
        };
        let log = assemble(&stats, Some(insights));
        assert_eq!(chunk(&log, "a/one.bin:0-").cdns.len(), 1);
        assert_eq!(chunk(&log, "b/two.bin:0-").cdns.len(), 1);
        let extra = chunk(&log, "0-4294967295");
        assert_eq!(extra.cdns.len(), 1);
        assert_eq!(extra.cdns[0].size, Some(7));
        assert!(extra.cdns[0].srv.is_none());
    }

    #[test]
    fn ver_uses_session_version() {
        let stats = stats("9.9.9-rc", vec!["0-"], HashMap::new(), HashMap::new());
        let log = assemble(&stats, None);
        assert_eq!(log.ver, "9.9.9-rc");
        assert_eq!(chunk(&log, "0-").att, 0);
    }
}
