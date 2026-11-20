use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::{CertHashPolicy, ServerConfig};
use crate::modules::server::{HealthInfo, ServerImpl};
use crate::modules::storage::data_store::DataStore;
use crate::modules::version_file::hash_content;

pub const MAP_PATH_PREFIX: &str = "map:";
pub const EXTENT_MAP_MAX_BYTES: u64 = 16 * 1024 * 1024;
pub const EXTENT_MAP_TTL_SECONDS: u32 = 300;
pub const EXTENT_MAP_VERSION_TTL_SECONDS: u32 = 3600;
pub const EXTENT_MAP_NEGATIVE_TTL_SECONDS: u64 = 60;
const RAW_MANIFEST_L1_TTL_SECONDS: u64 = 60;
const RAW_MANIFEST_L1_MAX_ENTRIES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapPathSpec {
    pub manifest_path: String,
    pub base_dir: String,
}

pub fn is_map_path(path: &str) -> bool {
    path.starts_with(MAP_PATH_PREFIX)
}

/// Parses a `map:/dir/manifest.json` resource path into the storage manifest path
/// and its parent directory. Returns `None` when `path` does not carry the `map:` prefix.
pub fn parse_map_path(path: &str) -> Option<Result<MapPathSpec, String>> {
    let raw = path.strip_prefix(MAP_PATH_PREFIX)?;
    Some(parse_manifest_path(raw))
}

fn parse_manifest_path(raw: &str) -> Result<MapPathSpec, String> {
    if raw.is_empty() {
        return Err("map: path must not be empty".to_string());
    }
    if raw.ends_with('/') {
        return Err(format!(
            "map: path '{raw}' must refer to a manifest file, not a directory"
        ));
    }
    if raw
        .bytes()
        .any(|b| b == b'\\' || b == b'?' || b == b'#' || b.is_ascii_control())
    {
        return Err(format!("map: path '{raw}' contains forbidden characters"));
    }

    let trimmed = raw.strip_prefix('/').unwrap_or(raw);
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.is_empty()
        || segments
            .iter()
            .any(|seg| seg.is_empty() || *seg == "." || *seg == "..")
    {
        return Err(format!("map: path '{raw}' contains invalid path segments"));
    }

    let manifest_path = format!("/{}", segments.join("/"));
    let base_dir = if segments.len() == 1 {
        "/".to_string()
    } else {
        format!("/{}", segments[..segments.len() - 1].join("/"))
    };

    Ok(MapPathSpec {
        manifest_path,
        base_dir,
    })
}

/// Resolves a relative object path inside an extent manifest against `base_dir`,
/// rejecting absolute paths, directory traversal, empty segments, and query/fragment delimiters.
pub fn resolve_extent_object_path(base_dir: &str, rel_path: &str) -> Result<String, String> {
    if rel_path.is_empty() {
        return Err("extent path must not be empty".to_string());
    }
    if rel_path.starts_with('/') || rel_path.ends_with('/') {
        return Err(format!(
            "extent path '{rel_path}' must be a relative file path"
        ));
    }
    if rel_path
        .bytes()
        .any(|b| b == b'\\' || b == b'?' || b == b'#' || b.is_ascii_control())
    {
        return Err(format!(
            "extent path '{rel_path}' contains forbidden characters"
        ));
    }

    for seg in rel_path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(format!(
                "extent path '{rel_path}' contains invalid segment '{seg}'"
            ));
        }
    }

    if base_dir.is_empty() || base_dir == "/" {
        Ok(format!("/{rel_path}"))
    } else {
        Ok(format!("{}/{rel_path}", base_dir.trim_end_matches('/')))
    }
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawExtent {
    pub offset: u64,
    pub len: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub phys_offset: u64,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawExtentMap {
    pub size: u64,
    pub extents: Vec<RawExtent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedExtent {
    pub offset: u64,
    pub len: u64,
    pub phys_offset: u64,
    pub resolved_path: String,
    pub is_full_object: bool,
}

impl ValidatedExtent {
    pub fn end(&self) -> u64 {
        self.offset + self.len
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentMap {
    pub size: u64,
    pub extents: Vec<ValidatedExtent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedExtentSlice {
    pub phys_path: String,
    pub sign_range: Option<(u32, u32)>,
    pub fragment_range: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnmergeableError {
    EmptyOrOpenRange,
    MultipartRange,
    InvalidBounds {
        start: u64,
        end: u64,
    },
    OutOfBounds {
        start: u64,
        end: u64,
        size: u64,
    },
    UnmappedGap {
        start: u64,
        end: u64,
    },
    CrossesExtentBoundary {
        start: u64,
        end: u64,
        extent_end: u64,
    },
    PhysicalOffsetOverflow {
        phys_start: u64,
        phys_end: u64,
    },
}

impl fmt::Display for UnmergeableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyOrOpenRange => {
                write!(
                    f,
                    "ERR_RANGE_NOT_SATISFIABLE: explicit single byte range is required for map resource"
                )
            }
            Self::MultipartRange => {
                write!(
                    f,
                    "ERR_RANGE_NOT_SATISFIABLE: multipart byte ranges are not supported for map resource"
                )
            }
            Self::InvalidBounds { start, end } => {
                write!(f, "ERR_RANGE_NOT_SATISFIABLE: invalid range {start}-{end}")
            }
            Self::OutOfBounds { start, end, size } => {
                write!(
                    f,
                    "ERR_RANGE_NOT_SATISFIABLE: range {start}-{end} exceeds virtual size {size}"
                )
            }
            Self::UnmappedGap { start, end } => {
                write!(
                    f,
                    "ERR_RANGE_NOT_SATISFIABLE: range {start}-{end} starts in an unmapped gap"
                )
            }
            Self::CrossesExtentBoundary {
                start,
                end,
                extent_end,
            } => {
                write!(
                    f,
                    "ERR_RANGE_NOT_SATISFIABLE: range {start}-{end} crosses extent end {extent_end}"
                )
            }
            Self::PhysicalOffsetOverflow {
                phys_start,
                phys_end,
            } => {
                write!(
                    f,
                    "ERR_RANGE_NOT_SATISFIABLE: physical range {phys_start}-{phys_end} exceeds 32-bit signer limit"
                )
            }
        }
    }
}

impl ExtentMap {
    pub fn parse_and_validate(bytes: &[u8], base_dir: &str) -> Result<Self, String> {
        Self::parse_and_validate_with_compact(bytes, base_dir).map(|(map, _)| map)
    }

    /// Parses and validates `{ size, extents }` from a JSON root object while ignoring
    /// unrelated root keys, returning both the validated `ExtentMap` and its compact
    /// `{ size, extents }` JSON projection for storage caching.
    pub fn parse_and_validate_with_compact(
        bytes: &[u8],
        base_dir: &str,
    ) -> Result<(Self, String), String> {
        let mut raw: RawExtentMap =
            serde_json::from_slice(bytes).map_err(|e| format!("invalid extent map JSON: {e}"))?;
        if raw.size == 0 {
            return Err("extent map virtual size must be positive".to_string());
        }
        if raw.extents.is_empty() {
            return Err("extent map must contain at least one extent".to_string());
        }

        raw.extents.sort_by_key(|e| e.offset);

        let mut max_phys_end_by_path: HashMap<String, u64> = HashMap::new();
        let mut temp_extents = Vec::with_capacity(raw.extents.len());
        let mut prev_end = 0u64;

        for item in &raw.extents {
            if item.len == 0 {
                return Err(format!("extent at offset {} has zero length", item.offset));
            }
            if item.offset < prev_end {
                return Err(format!(
                    "overlapping extents: offset {} precedes previous end {prev_end}",
                    item.offset
                ));
            }
            let logical_end = item
                .offset
                .checked_add(item.len)
                .ok_or_else(|| format!("logical extent overflow at offset {}", item.offset))?;
            if logical_end > raw.size {
                return Err(format!(
                    "extent [{}..{logical_end}) exceeds virtual size {}",
                    item.offset, raw.size
                ));
            }
            let phys_end = item
                .phys_offset
                .checked_add(item.len)
                .ok_or_else(|| format!("physical extent overflow for '{}'", item.path))?;
            let resolved_path = resolve_extent_object_path(base_dir, &item.path)?;

            max_phys_end_by_path
                .entry(resolved_path.clone())
                .and_modify(|cur| *cur = (*cur).max(phys_end))
                .or_insert(phys_end);

            temp_extents.push((item.offset, item.len, item.phys_offset, resolved_path));
            prev_end = logical_end;
        }

        let compact_json = serde_json::to_string(&raw)
            .map_err(|e| format!("failed to serialize compact extent map: {e}"))?;

        let extents = temp_extents
            .into_iter()
            .map(|(offset, len, phys_offset, resolved_path)| {
                let max_phys_end = max_phys_end_by_path
                    .get(&resolved_path)
                    .copied()
                    .unwrap_or(len);
                let is_full_object = phys_offset == 0 && len == max_phys_end;
                ValidatedExtent {
                    offset,
                    len,
                    phys_offset,
                    resolved_path,
                    is_full_object,
                }
            })
            .collect();

        Ok((
            Self {
                size: raw.size,
                extents,
            },
            compact_json,
        ))
    }

    pub fn resolve_target_ranges(
        &self,
        ranges: Option<&[(u32, u32)]>,
        cdn_full_range: bool,
    ) -> Result<ResolvedExtentSlice, UnmergeableError> {
        if cdn_full_range {
            return Err(UnmergeableError::EmptyOrOpenRange);
        }
        let Some(ranges) = ranges else {
            return Err(UnmergeableError::EmptyOrOpenRange);
        };
        if ranges.is_empty() {
            return Err(UnmergeableError::EmptyOrOpenRange);
        }
        if ranges.len() > 1 {
            return Err(UnmergeableError::MultipartRange);
        }
        let (start, end) = (u64::from(ranges[0].0), u64::from(ranges[0].1));
        self.resolve_range(start, end)
    }

    pub fn resolve_range(
        &self,
        start: u64,
        end_inclusive: u64,
    ) -> Result<ResolvedExtentSlice, UnmergeableError> {
        if start > end_inclusive {
            return Err(UnmergeableError::InvalidBounds {
                start,
                end: end_inclusive,
            });
        }
        let Some(req_end_excl) = end_inclusive.checked_add(1) else {
            return Err(UnmergeableError::InvalidBounds {
                start,
                end: end_inclusive,
            });
        };
        if req_end_excl > self.size {
            return Err(UnmergeableError::OutOfBounds {
                start,
                end: end_inclusive,
                size: self.size,
            });
        }

        let Some(idx) = self
            .extents
            .partition_point(|e| e.offset <= start)
            .checked_sub(1)
        else {
            return Err(UnmergeableError::UnmappedGap {
                start,
                end: end_inclusive,
            });
        };

        let extent = &self.extents[idx];
        let extent_end = extent.end();
        if start >= extent_end {
            return Err(UnmergeableError::UnmappedGap {
                start,
                end: end_inclusive,
            });
        }
        if req_end_excl > extent_end {
            return Err(UnmergeableError::CrossesExtentBoundary {
                start,
                end: end_inclusive,
                extent_end,
            });
        }

        let rel_start = start - extent.offset;
        let req_len = req_end_excl - start;

        if rel_start == 0 && req_len == extent.len && extent.is_full_object {
            return Ok(ResolvedExtentSlice {
                phys_path: extent.resolved_path.clone(),
                sign_range: None,
                fragment_range: "0-".to_string(),
            });
        }

        let phys_start = extent.phys_offset + rel_start;
        let phys_end_incl = phys_start + req_len - 1;
        let (Ok(sign_start), Ok(sign_end)) =
            (u32::try_from(phys_start), u32::try_from(phys_end_incl))
        else {
            return Err(UnmergeableError::PhysicalOffsetOverflow {
                phys_start,
                phys_end: phys_end_incl,
            });
        };

        Ok(ResolvedExtentSlice {
            phys_path: extent.resolved_path.clone(),
            sign_range: Some((sign_start, sign_end)),
            fragment_range: format!("{phys_start}-{phys_end_incl}"),
        })
    }
}

pub fn append_range_fragment(url: &str, fragment_range: &str) -> String {
    if url.contains('#') {
        format!("{url}&range={fragment_range}")
    } else {
        format!("{url}#range={fragment_range}")
    }
}

pub fn extract_range_fragment(url: &str) -> Option<&str> {
    let (_, frag) = url.split_once('#')?;
    for pair in frag.split('&') {
        if let Some(val) = pair.strip_prefix("range=") {
            return Some(val);
        }
    }
    None
}

pub fn extent_map_storage_key(server_id: &str, resource_path: &str) -> String {
    let raw = format!("extent_map:{server_id}:{resource_path}");
    with_redis_prefix(&raw)
}

pub fn resource_extent_map_storage_key(resource_id: &str, version: &str) -> String {
    let raw = format!("extent_map_ver:{resource_id}:{version}");
    with_redis_prefix(&raw)
}

fn with_redis_prefix(raw: &str) -> String {
    match std::env::var("REDIS_PREFIX") {
        Ok(prefix) if !prefix.is_empty() => format!("{prefix}:{raw}"),
        _ => raw.to_string(),
    }
}

type ServerExtentKey = (String, String);
type ServerExtentEntry = (u64, Arc<ExtentMap>);
type VersionExtentKey = (String, String);
type VersionExtentEntry = (Instant, Arc<ExtentMap>);
type RawManifestEntry = (Instant, Bytes);
type InflightLock = Arc<tokio::sync::Mutex<()>>;

#[derive(Clone, Default)]
pub struct ExtentMapCache {
    l1_by_server: Arc<DashMap<ServerExtentKey, ServerExtentEntry>>,
    l1_by_version: Arc<DashMap<VersionExtentKey, VersionExtentEntry>>,
    l1_raw_by_version: Arc<DashMap<VersionExtentKey, RawManifestEntry>>,
    inflight: Arc<DashMap<ServerExtentKey, InflightLock>>,
}

impl ExtentMapCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns cached raw manifest bytes for `(resource_id, version)` if still fresh in memory.
    pub fn get_cached_raw_version_bytes(&self, resource_id: &str, version: &str) -> Option<Bytes> {
        let key = (resource_id.to_string(), version.to_string());
        if let Some(entry) = self.l1_raw_by_version.get(&key) {
            if Instant::now() < entry.0 {
                return Some(entry.1.clone());
            }
            drop(entry);
            self.l1_raw_by_version.remove(&key);
        }
        None
    }

    fn store_raw_version_bytes(&self, resource_id: &str, version: &str, raw_bytes: Bytes) {
        let now = Instant::now();
        if self.l1_raw_by_version.len() >= RAW_MANIFEST_L1_MAX_ENTRIES {
            self.l1_raw_by_version.retain(|_, (exp, _)| now < *exp);
            if self.l1_raw_by_version.len() >= RAW_MANIFEST_L1_MAX_ENTRIES {
                self.l1_raw_by_version.clear();
            }
        }
        self.l1_raw_by_version.insert(
            (resource_id.to_string(), version.to_string()),
            (
                now + Duration::from_secs(RAW_MANIFEST_L1_TTL_SECONDS),
                raw_bytes,
            ),
        );
    }

    /// Returns any already-known `ExtentMap` for `(resource_id, version)` without issuing network probes.
    pub async fn get_known_version_map(
        &self,
        data_store: &DataStore,
        resource_id: &str,
        version: &str,
        base_dir: &str,
    ) -> Option<Arc<ExtentMap>> {
        let ver_key = (resource_id.to_string(), version.to_string());
        if let Some(entry) = self.l1_by_version.get(&ver_key) {
            if Instant::now() < entry.0 {
                return Some(Arc::clone(&entry.1));
            }
            drop(entry);
            self.l1_by_version.remove(&ver_key);
        }

        let storage_key = resource_extent_map_storage_key(resource_id, version);
        let raw = data_store.get_string(&storage_key).await.ok().flatten()?;
        let parsed = Arc::new(ExtentMap::parse_and_validate(raw.as_bytes(), base_dir).ok()?);
        self.l1_by_version.insert(
            ver_key,
            (
                Instant::now() + Duration::from_secs(u64::from(EXTENT_MAP_TTL_SECONDS)),
                Arc::clone(&parsed),
            ),
        );
        Some(parsed)
    }

    /// Probes `(server_id, resource_path)` (reusing singleflight & compact storage cache) and
    /// returns the full raw JSON bytes of the manifest document so independent callers may
    /// project their own top-level fields without coupling schemas.
    #[allow(clippy::too_many_arguments)]
    pub async fn probe_server_manifest_bytes(
        &self,
        data_store: &DataStore,
        resource_id: &str,
        version: &str,
        server_id: &str,
        server_config: &ServerConfig,
        server_impl: &ServerImpl,
        resource_path: &str,
        spec: &MapPathSpec,
    ) -> Result<Option<Bytes>, String> {
        let Some(_map) = self
            .get_or_probe_server_map(
                data_store,
                resource_id,
                version,
                server_id,
                server_config,
                server_impl,
                resource_path,
                spec,
            )
            .await?
        else {
            return Ok(None);
        };

        if let Some(raw) = self.get_cached_raw_version_bytes(resource_id, version) {
            return Ok(Some(raw));
        }

        // Compact ExtentMap was recovered from DataStore after a process restart; fetch raw JSON once.
        let lock_key = (server_id.to_string(), resource_path.to_string());
        let mutex = self
            .inflight
            .entry(lock_key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutex.lock().await;

        if let Some(raw) = self.get_cached_raw_version_bytes(resource_id, version) {
            return Ok(Some(raw));
        }

        let probe = server_impl
            .fetch_small_file(
                server_config,
                &spec.manifest_path,
                Some(data_store),
                EXTENT_MAP_MAX_BYTES,
            )
            .await;
        if probe.is_alive
            && let Some(body) = probe.body
        {
            let raw_bytes = Bytes::from(body);
            self.store_raw_version_bytes(resource_id, version, raw_bytes.clone());
            return Ok(Some(raw_bytes));
        }
        Ok(None)
    }

    /// Loads or singleflight-probes the `ExtentMap` for `(server_id, resource_path)`.
    /// Returns `Ok(Some(map))` when the manifest is valid and cached, or `Ok(None)` when the
    /// node cannot currently serve a valid manifest for this version.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_or_probe_server_map(
        &self,
        data_store: &DataStore,
        resource_id: &str,
        version: &str,
        server_id: &str,
        server_config: &ServerConfig,
        server_impl: &ServerImpl,
        resource_path: &str,
        spec: &MapPathSpec,
    ) -> Result<Option<Arc<ExtentMap>>, String> {
        if let Some(cached) = self
            .try_read_cached_server_map(
                data_store,
                resource_id,
                version,
                server_id,
                server_config,
                resource_path,
                &spec.base_dir,
            )
            .await
        {
            return Ok(cached);
        }

        let lock_key = (server_id.to_string(), resource_path.to_string());
        let mutex = self
            .inflight
            .entry(lock_key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();

        let _guard = mutex.lock().await;

        if let Some(cached) = self
            .try_read_cached_server_map(
                data_store,
                resource_id,
                version,
                server_id,
                server_config,
                resource_path,
                &spec.base_dir,
            )
            .await
        {
            return Ok(cached);
        }

        let probe = server_impl
            .fetch_small_file(
                server_config,
                &spec.manifest_path,
                Some(data_store),
                EXTENT_MAP_MAX_BYTES,
            )
            .await;

        let now = chrono::Utc::now().timestamp() as u64;

        if probe.is_alive
            && let Some(body) = probe.body
        {
            match std::str::from_utf8(&body)
                .map_err(|e| format!("manifest is not UTF-8: {e}"))
                .and_then(|raw_str| {
                    ExtentMap::parse_and_validate_with_compact(raw_str.as_bytes(), &spec.base_dir)
                }) {
                Ok((parsed_map, compact_json)) => {
                    let health = HealthInfo {
                        is_alive: true,
                        file_size: Some(parsed_map.size),
                        last_check: now,
                        observed_cert_hash: probe.observed_cert_hash,
                        content_hash: Some(hash_content(&body)),
                    };
                    let _ = data_store
                        .set_health_info(server_id, resource_path, &health)
                        .await;
                    let _ = data_store
                        .set_string(
                            &extent_map_storage_key(server_id, resource_path),
                            &compact_json,
                            Some(EXTENT_MAP_TTL_SECONDS),
                        )
                        .await;
                    let _ = data_store
                        .set_string(
                            &resource_extent_map_storage_key(resource_id, version),
                            &compact_json,
                            Some(EXTENT_MAP_VERSION_TTL_SECONDS),
                        )
                        .await;

                    self.store_raw_version_bytes(resource_id, version, Bytes::from(body));

                    let arc_map = Arc::new(parsed_map);
                    self.l1_by_server
                        .insert(lock_key, (now, Arc::clone(&arc_map)));
                    self.l1_by_version.insert(
                        (resource_id.to_string(), version.to_string()),
                        (
                            Instant::now() + Duration::from_secs(u64::from(EXTENT_MAP_TTL_SECONDS)),
                            Arc::clone(&arc_map),
                        ),
                    );
                    return Ok(Some(arc_map));
                }
                Err(reason) => {
                    warn!(
                        server = %server_id,
                        path = %spec.manifest_path,
                        "Invalid extent map manifest: {reason}"
                    );
                }
            }
        }

        let dead_health = HealthInfo {
            is_alive: false,
            file_size: None,
            last_check: now,
            observed_cert_hash: probe.observed_cert_hash,
            content_hash: None,
        };
        let _ = data_store
            .set_health_info(server_id, resource_path, &dead_health)
            .await;
        self.l1_by_server.remove(&lock_key);
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    async fn try_read_cached_server_map(
        &self,
        data_store: &DataStore,
        resource_id: &str,
        version: &str,
        server_id: &str,
        server_config: &ServerConfig,
        resource_path: &str,
        base_dir: &str,
    ) -> Option<Option<Arc<ExtentMap>>> {
        let cached_health = data_store
            .get_health_info(server_id, resource_path)
            .await
            .ok()
            .flatten()?;

        if server_config.h3_only {
            let policy = server_config
                .cert_hash_policy()
                .unwrap_or(CertHashPolicy::ValidCert);
            if matches!(policy, CertHashPolicy::Trust) && cached_health.observed_cert_hash.is_none()
            {
                return None;
            }
        }

        if !cached_health.is_alive {
            let now = chrono::Utc::now().timestamp() as u64;
            if cached_health.last_check == 0
                || now.saturating_sub(cached_health.last_check) < EXTENT_MAP_NEGATIVE_TTL_SECONDS
            {
                return Some(None);
            }
            return None;
        }

        let server_key = (server_id.to_string(), resource_path.to_string());
        if let Some(entry) = self.l1_by_server.get(&server_key)
            && entry.0 == cached_health.last_check
        {
            return Some(Some(Arc::clone(&entry.1)));
        }

        let raw = data_store
            .get_string(&extent_map_storage_key(server_id, resource_path))
            .await
            .ok()
            .flatten()?;
        let parsed = Arc::new(ExtentMap::parse_and_validate(raw.as_bytes(), base_dir).ok()?);
        self.l1_by_server
            .insert(server_key, (cached_health.last_check, Arc::clone(&parsed)));
        self.l1_by_version.insert(
            (resource_id.to_string(), version.to_string()),
            (
                Instant::now() + Duration::from_secs(u64::from(EXTENT_MAP_TTL_SECONDS)),
                Arc::clone(&parsed),
            ),
        );
        Some(Some(parsed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::mocks::TestEnvironment;
    use axum::{Router, extract::State, http::StatusCode, routing::get};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parse_map_path_extracts_manifest_and_parent_directory() {
        let nested = parse_map_path("map:/bgi/BetterGI.Install.0.68.0.json")
            .expect("has prefix")
            .expect("valid spec");
        assert_eq!(nested.manifest_path, "/bgi/BetterGI.Install.0.68.0.json");
        assert_eq!(nested.base_dir, "/bgi");

        let root = parse_map_path("map:/manifest.json")
            .expect("has prefix")
            .expect("valid root spec");
        assert_eq!(root.manifest_path, "/manifest.json");
        assert_eq!(root.base_dir, "/");

        assert!(parse_map_path("/bgi/file.exe").is_none());
        assert!(parse_map_path("map:").unwrap().is_err());
        assert!(parse_map_path("map:/bgi/").unwrap().is_err());
        assert!(parse_map_path("map:/bgi/../secret.json").unwrap().is_err());
        assert!(parse_map_path("map:/bgi/a?x=1").unwrap().is_err());
        assert!(parse_map_path("map:/bgi/a#frag").unwrap().is_err());
    }

    #[test]
    fn resolve_extent_object_path_rejects_traversal_and_absolute_paths() {
        assert_eq!(
            resolve_extent_object_path("/bgi", "cas/9a8b7c").unwrap(),
            "/bgi/cas/9a8b7c"
        );
        assert_eq!(
            resolve_extent_object_path("/", "cas/9a8b7c").unwrap(),
            "/cas/9a8b7c"
        );
        for bad in [
            "",
            "/cas/9a8b",
            "cas/9a8b/",
            "../cas/9a8b",
            "cas/../9a8b",
            "cas/./9a8b",
            "cas//9a8b",
            "cas\\9a8b",
            "cas/9a8b?sig=1",
            "cas/9a8b#range=0-",
        ] {
            assert!(
                resolve_extent_object_path("/bgi", bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn extent_map_resolves_full_objects_subranges_stitched_packs_and_rejects_gaps() {
        // Extent 0 & Extent 3 share stitched physical pack `cas/pack0`;
        // Extent 1 & Extent 2 deduplicate to the same standalone CAS object `cas/blob_dup`.
        let manifest = serde_json::json!({
            "size": 1000,
            "extents": [
                { "offset": 0, "len": 100, "phys_offset": 0, "path": "cas/pack0" },
                { "offset": 120, "len": 200, "path": "cas/blob_dup" },
                { "offset": 350, "len": 200, "path": "cas/blob_dup" },
                { "offset": 600, "len": 300, "phys_offset": 100, "path": "cas/pack0" }
            ]
        });
        let map =
            ExtentMap::parse_and_validate(manifest.to_string().as_bytes(), "/bgi").expect("valid");

        // Full standalone CAS object (including deduplicated logical extents) -> None + "0-"
        for (start, end) in [(120, 319), (350, 549)] {
            let res = map.resolve_range(start, end).unwrap();
            assert_eq!(res.phys_path, "/bgi/cas/blob_dup");
            assert_eq!(res.sign_range, None);
            assert_eq!(res.fragment_range, "0-");
        }

        // Sub-slice inside standalone CAS object -> explicit physical range
        let slice = map.resolve_range(130, 179).unwrap();
        assert_eq!(slice.phys_path, "/bgi/cas/blob_dup");
        assert_eq!(slice.sign_range, Some((10, 59)));
        assert_eq!(slice.fragment_range, "10-59");

        // Stitched pack: Extent 0 covers 0..100 of a 400-byte physical file, so NOT "0-"
        let pack_head = map.resolve_range(0, 99).unwrap();
        assert_eq!(pack_head.phys_path, "/bgi/cas/pack0");
        assert_eq!(pack_head.sign_range, Some((0, 99)));
        assert_eq!(pack_head.fragment_range, "0-99");

        // Stitched pack: Extent 3 maps logical 650..749 -> physical 150..249
        let pack_tail = map.resolve_range(650, 749).unwrap();
        assert_eq!(pack_tail.phys_path, "/bgi/cas/pack0");
        assert_eq!(pack_tail.sign_range, Some((150, 249)));
        assert_eq!(pack_tail.fragment_range, "150-249");

        // Unmapped gap, cross-extent, out-of-bounds, open/multipart ranges all fail with ERR_RANGE_NOT_SATISFIABLE
        for bad in [(100, 119), (50, 150), (120, 360), (600, 1000)] {
            let err = map.resolve_range(bad.0, bad.1).unwrap_err();
            assert!(
                err.to_string().starts_with("ERR_RANGE_NOT_SATISFIABLE:"),
                "{err}"
            );
        }
        assert!(map.resolve_target_ranges(None, false).is_err());
        assert!(
            map.resolve_target_ranges(Some(&[(120, 319)]), true)
                .is_err()
        );
        assert!(
            map.resolve_target_ranges(Some(&[(0, 10), (20, 30)]), false)
                .is_err()
        );
    }

    #[tokio::test]
    async fn singleflight_coalesces_concurrent_probes_and_recovers_from_datastore_on_restart() {
        let hits = Arc::new(AtomicUsize::new(0));
        let manifest_body = serde_json::json!({
            "size": 5000,
            "extents": [
                { "offset": 0, "len": 2000, "path": "cas/head_hash" },
                { "offset": 2042, "len": 2958, "path": "cas/big_hash" }
            ]
        })
        .to_string();

        let app = Router::new()
            .route(
                "/bgi/app.json",
                get(
                    |State((counter, body)): State<(Arc<AtomicUsize>, String)>| async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(40)).await;
                        (StatusCode::OK, body)
                    },
                ),
            )
            .with_state((Arc::clone(&hits), manifest_body));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let env = TestEnvironment::new().await;
        let server_cfg: crate::config::ServerConfig = serde_yaml::from_str(&format!(
            "id: map_node\ntype: direct\nurl: \"http://{addr}\"\n"
        ))
        .unwrap();
        let server_impl = ServerImpl::new(&server_cfg).unwrap();
        let resource_path = "map:/bgi/app.json";
        let spec = parse_map_path(resource_path).unwrap().unwrap();

        let cache = ExtentMapCache::new();
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let store = env.data_store.clone();
            let cfg = server_cfg.clone();
            let imp = server_impl.clone();
            let spec = spec.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_probe_server_map(
                        &store,
                        "bgi_split",
                        "0.68.0",
                        "map_node",
                        &cfg,
                        &imp,
                        resource_path,
                        &spec,
                    )
                    .await
                    .unwrap()
                    .expect("manifest loaded")
            }));
        }

        for task in tasks {
            let map = task.await.unwrap();
            assert_eq!(map.size, 5000);
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "16 concurrent cold misses must coalesce into a single upstream GET"
        );

        let health = env
            .data_store
            .get_health_info("map_node", resource_path)
            .await
            .unwrap()
            .expect("health info persisted");
        assert!(health.is_alive);
        assert_eq!(health.file_size, Some(5000));

        // Simulate process restart with an empty in-memory cache backed by the same DataStore.
        let restarted_cache = ExtentMapCache::new();
        let recovered = restarted_cache
            .get_or_probe_server_map(
                &env.data_store,
                "bgi_split",
                "0.68.0",
                "map_node",
                &server_cfg,
                &server_impl,
                resource_path,
                &spec,
            )
            .await
            .unwrap()
            .expect("recovered from datastore");
        assert_eq!(recovered.size, 5000);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "warm DataStore must satisfy cold L1 after restart without re-probing"
        );
    }

    #[tokio::test]
    async fn extent_map_cache_persists_compact_projection_without_unrelated_root_fields() {
        let large_padding = "x".repeat(128 * 1024);
        let root_json = serde_json::json!({
            "size": 8192,
            "extents": [
                { "offset": 0, "len": 4096, "phys_offset": 0, "path": "cas/head" },
                { "offset": 4096, "len": 4096, "phys_offset": 128, "path": "cas/tail" }
            ],
            "installer_end": 2048,
            "index": { "a.bin": { "name": "a.bin", "offset": 2100, "raw_offset": 2085, "size": 100 } },
            "metadata": { "tag_name": "1.0.0", "blob": large_padding }
        })
        .to_string();

        let body_clone = root_json.clone();
        let app = Router::new().route(
            "/pkg/1.0.0.json",
            get(move || {
                let b = body_clone.clone();
                async move { (StatusCode::OK, b) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let env = TestEnvironment::new().await;
        let cache = ExtentMapCache::new();
        let resource_path = "map:/pkg/1.0.0.json";
        let spec = parse_map_path(resource_path).unwrap().unwrap();
        let server_cfg = ServerConfig {
            id: "map_srv".to_string(),
            url: format!("http://{addr}"),
            r#type: "direct".to_string(),
            ..Default::default()
        };
        let server_impl = ServerImpl::new(&server_cfg).unwrap();

        let map = cache
            .get_or_probe_server_map(
                &env.data_store,
                "pkg_res",
                "1.0.0",
                "map_srv",
                &server_cfg,
                &server_impl,
                resource_path,
                &spec,
            )
            .await
            .unwrap()
            .expect("manifest parsed");
        assert_eq!(map.size, 8192);
        assert_eq!(map.extents.len(), 2);

        let stored_srv = env
            .data_store
            .get_string(&extent_map_storage_key("map_srv", resource_path))
            .await
            .unwrap()
            .expect("compact server entry stored");
        assert!(
            stored_srv.len() < 256,
            "stored projection must omit bulky extra root keys, got len={}",
            stored_srv.len()
        );
        assert!(!stored_srv.contains("installer_end"));
        assert!(!stored_srv.contains("metadata"));

        let cached_raw = cache
            .get_cached_raw_version_bytes("pkg_res", "1.0.0")
            .expect("raw bytes retained in L1 for version");
        assert_eq!(cached_raw.len(), root_json.len());
    }
}
