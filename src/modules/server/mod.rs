use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

use crate::config::{AppConfig, CertHashPolicy, ServerConfig};
use crate::modules::network::h3_middleware::{CertVerifyPolicy, H3TransportInfo};
use crate::modules::storage::data_store::DataStore;

pub mod dfs_node;
pub mod dfs_sftp;
pub mod dfs_wt;
pub mod git_lfs;
pub mod s3;

/// 单次版本文件探测的总时限。
///
/// 底层客户端的分段超时（H3 连接 10s、HTTP 读 60s）之和远大于取一个版本文件该花的时间，
/// 而普查一轮要跨节点乘路径地探测多次。设总时限使单次探测的最坏耗时有明确上界。
const VERSION_FILE_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// 健康检查结果，包含存活状态和文件大小信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthInfo {
    pub is_alive: bool,
    pub file_size: Option<u64>,
    pub last_check: u64,
    #[serde(default)]
    pub observed_cert_hash: Option<String>,
    #[serde(default)]
    pub content_hash: Option<String>,
}

impl HealthInfo {
    pub fn connectivity(is_alive: bool, file_size: Option<u64>) -> Self {
        Self {
            is_alive,
            file_size,
            last_check: chrono::Utc::now().timestamp() as u64,
            observed_cert_hash: None,
            content_hash: None,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FileProbe {
    pub is_alive: bool,
    pub file_size: Option<u64>,
    pub observed_cert_hash: Option<String>,
    pub body: Option<Vec<u8>>,
}

/// 单个节点的连通性探测结果。
#[derive(Debug, Clone)]
pub struct ServerPing {
    pub server_id: String,
    pub health_check_path: String,
    pub is_alive: bool,
    pub file_size: Option<u64>,
    pub observed_cert_hash: Option<String>,
    pub last_check: u64,
}

/// 全量节点连通性探测的结果。
#[derive(Debug, Clone, Default)]
pub struct PingReport {
    /// 配置了健康检查路径、且服务器实现构造成功的节点。
    pub probed: Vec<ServerPing>,
    /// 配置了健康检查路径但无法构造实现的节点，属于配置错误。
    pub implementation_missing: Vec<String>,
}

impl PingReport {
    /// 探测失败的节点，供版本文件普查整轮跳过。
    pub fn unreachable(&self) -> HashSet<String> {
        self.probed
            .iter()
            .filter(|ping| !ping.is_alive)
            .map(|ping| ping.server_id.clone())
            .collect()
    }

    pub fn alive_count(&self) -> usize {
        self.probed.iter().filter(|ping| ping.is_alive).count()
    }
}

/// 配置了健康检查路径、且落在 `only` 内（或 `only` 为空即全量）的节点 id，已排序。
pub fn ping_candidate_ids(config: &AppConfig, only: Option<&HashSet<String>>) -> Vec<String> {
    let mut ids: Vec<String> = config
        .servers
        .iter()
        .filter(|(id, server)| {
            server.health_check_path.is_some() && only.is_none_or(|set| set.contains(*id))
        })
        .map(|(id, _)| id.clone())
        .collect();
    ids.sort();
    ids
}

/// 并发探测所有配置了健康检查路径的节点。不写存储。
///
/// 不读健康信息缓存：结果用于决定普查是否整轮跳过某节点，而过期的"不可达"判定会让该节点缺席
/// 一整轮多数派计算，节点数少时足以改变多数派是否成立，因此每次都实测。未配置健康检查路径的
/// 节点不出现在结果中——无从判定，交由普查按路径逐个探测。
pub async fn ping_servers(config: &AppConfig, concurrency: usize) -> PingReport {
    ping_selected_servers(config, None, concurrency, None).await
}

/// 与 [`ping_servers`] 相同，可把探测限制在给定节点集合。
///
/// 不读健康信息缓存。`store` 为 `Some` 时只写不读：把探测结论发布到
/// `health:{id}:{health_check_path}`，不改变跳过判定的来源。
pub async fn ping_selected_servers(
    config: &AppConfig,
    only: Option<&HashSet<String>>,
    concurrency: usize,
    store: Option<&DataStore>,
) -> PingReport {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut report = PingReport::default();
    let mut tasks = Vec::new();

    for server_id in ping_candidate_ids(config, only) {
        let server_config = match config.servers.get(&server_id) {
            Some(s) => s,
            None => continue,
        };
        let Some(health_check_path) = &server_config.health_check_path else {
            continue;
        };
        let Some(server_impl) = config.get_server(&server_id) else {
            report.implementation_missing.push(server_id.clone());
            continue;
        };

        let server_id = server_id.clone();
        let server_config = server_config.clone();
        let server_impl = server_impl.clone();
        let health_check_path = health_check_path.clone();
        let semaphore = semaphore.clone();
        tasks.push(async move {
            let _permit = semaphore.acquire().await.ok();
            debug!("Pinging server {} (path: {})", server_id, health_check_path);
            let info = server_impl
                .probe_liveness(&server_id, &server_config, &health_check_path, None)
                .await;
            ServerPing {
                server_id,
                health_check_path,
                is_alive: info.is_alive,
                file_size: info.file_size,
                observed_cert_hash: info.observed_cert_hash,
                last_check: info.last_check,
            }
        });
    }

    report.probed = futures::future::join_all(tasks).await;
    report.implementation_missing.sort_unstable();
    if let Some(store) = store {
        for ping in &report.probed {
            let info = HealthInfo {
                is_alive: ping.is_alive,
                file_size: ping.file_size,
                last_check: ping.last_check,
                observed_cert_hash: ping.observed_cert_hash.clone(),
                content_hash: None,
            };
            let _ = store
                .set_health_info(&ping.server_id, &ping.health_check_path, &info)
                .await;
        }
    }
    report
}

fn join_direct_url(base: &str, path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let rel = normalized.strip_prefix('/').unwrap_or(&normalized);
    if base.ends_with('/') {
        format!("{base}{rel}")
    } else {
        format!("{base}/{rel}")
    }
}

/// Range header map for S3 SigV4. Empty ranges omit the header.
fn range_header_map(ranges: &[(u32, u32)]) -> Option<BTreeMap<String, String>> {
    if ranges.is_empty() {
        return None;
    }
    let range_header = format!(
        "bytes={}",
        ranges
            .iter()
            .map(|(start, end)| format!("{start}-{end}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut headers = BTreeMap::new();
    headers.insert("range".to_string(), range_header);
    Some(headers)
}

/// 从HTTP响应中提取文件大小
fn extract_file_size_from_response(headers: &HeaderMap) -> Option<u64> {
    // 优先从 Content-Range 头部提取总大小 (Range请求的情况)
    // 格式: Content-Range: bytes 0-255/1048576
    if let Some(content_range) = headers.get("content-range")
        && let Ok(range_str) = content_range.to_str()
        && let Some(total_size_str) = range_str.split('/').nth(1)
        && let Ok(total_size) = total_size_str.parse::<u64>()
    {
        return Some(total_size);
    }

    // 如果是完整文件响应，从Content-Length获取
    headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

fn to_http3_url(url: &str) -> anyhow::Result<String> {
    let parsed = url::Url::parse(url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("probe URL is missing a host"))?;
    let host = if host.contains(':') {
        format!("[{}]", host.trim_start_matches('[').trim_end_matches(']'))
    } else {
        host.to_string()
    };
    let port = parsed.port_or_known_default().unwrap_or(443);
    let authority = if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    };
    let mut path = parsed.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(format!("http3://{authority}{path}"))
}

#[derive(Clone, Debug)]
pub enum ServerImpl {
    Direct(String),
    S3(s3::S3Signer),
    DfsNode(dfs_node::DfsNodeSigner),
    DfsWt(dfs_wt::DfsWtSigner),
    DfsSftp(dfs_sftp::DfsSftpSigner),
    GitLfs(git_lfs::GitLfsSigner),
}

impl ServerImpl {
    pub fn new(config: &ServerConfig) -> anyhow::Result<Self> {
        match config.r#type.as_str() {
            "s3" => {
                let signer = s3::S3Signer::from_url(&config.url)?;
                Ok(ServerImpl::S3(signer))
            }
            "dfs_node" => {
                let signer = dfs_node::DfsNodeSigner::from_url(&config.url)?;
                Ok(ServerImpl::DfsNode(signer))
            }
            "direct" => Ok(ServerImpl::Direct(config.url.clone())),
            "git_lfs" => {
                let signer = git_lfs::GitLfsSigner::from_url(&config.url)?;
                Ok(ServerImpl::GitLfs(signer))
            }
            "dfs_webtransport" => {
                let signer = dfs_wt::DfsWtSigner::from_url(&config.url)?;
                Ok(ServerImpl::DfsWt(signer))
            }
            "dfs_sftp" => {
                let fingerprint = config.ssh_fingerprint.as_deref().unwrap_or("");
                let signer = dfs_sftp::DfsSftpSigner::from_url(&config.url, fingerprint)?;
                Ok(ServerImpl::DfsSftp(signer))
            }
            _ => Err(anyhow::anyhow!(
                "Unsupported server type: {}",
                config.r#type
            )),
        }
    }
    pub async fn url(
        &self,
        path: &str,
        ranges: Option<Vec<(u32, u32)>>,
        session_id: Option<&str>,
        data_store: Option<&crate::modules::storage::data_store::DataStore>,
    ) -> anyhow::Result<String> {
        match self {
            ServerImpl::Direct(url) => Ok(join_direct_url(url, path)),
            ServerImpl::S3(signer) => {
                signer.generate_presigned_url(path, ranges.as_deref().and_then(range_header_map))
            }
            ServerImpl::DfsNode(signer) => {
                let session_id = session_id.unwrap_or("00000000000000000000000000000000");
                signer.generate_presigned_url(path, session_id, ranges)
            }
            ServerImpl::DfsWt(signer) => {
                let session_id = session_id.unwrap_or("00000000000000000000000000000000");
                signer.generate_presigned_url(path, session_id, ranges)
            }
            ServerImpl::DfsSftp(signer) => {
                let session_id = session_id.unwrap_or("00000000000000000000000000000000");
                signer.generate_presigned_url(path, session_id, ranges)
            }
            ServerImpl::GitLfs(signer) => {
                if let Some(store) = data_store {
                    signer.generate_url(path, store).await
                } else {
                    Err(anyhow::anyhow!("Git LFS requires data store for caching"))
                }
            }
        }
    }

    /// Sign a GET for `path`. `expires` overrides the backend default TTL.
    /// `session_id` is the dfs_node uuid; `None` uses the all-zero uuid.
    pub async fn url_expiring(
        &self,
        path: &str,
        ranges: Option<Vec<(u32, u32)>>,
        session_id: Option<&str>,
        data_store: Option<&crate::modules::storage::data_store::DataStore>,
        expires: u32,
    ) -> anyhow::Result<String> {
        const ZERO_UUID: &str = "00000000000000000000000000000000";
        let uuid = session_id.unwrap_or(ZERO_UUID);
        match self {
            ServerImpl::Direct(url) => Ok(join_direct_url(url, path)),
            ServerImpl::S3(signer) => {
                let headers = ranges.as_deref().and_then(range_header_map);
                signer.generate_presigned_url_expiring(path, headers, expires)
            }
            ServerImpl::DfsNode(signer) => Ok(signer.generate_presigned_url_expiring(
                path,
                uuid,
                ranges.as_deref(),
                Some(expires),
            )),
            ServerImpl::DfsWt(signer) => Ok(signer.generate_presigned_url_expiring(
                path,
                uuid,
                ranges.as_deref(),
                Some(expires),
            )),
            ServerImpl::DfsSftp(signer) => {
                signer.generate_presigned_url_expiring(path, uuid, ranges, Some(expires))
            }
            ServerImpl::GitLfs(signer) => {
                if let Some(store) = data_store {
                    signer.generate_url(path, store).await
                } else {
                    Err(anyhow::anyhow!("Git LFS requires data store for caching"))
                }
            }
        }
    }

    pub async fn is_alive(
        &self,
        server_id: &str,
        server_config: &ServerConfig,
        path: &str,
        redis: Option<&DataStore>,
    ) -> bool {
        if let Some(redis_store) = redis
            && let Ok(Some(cached_health)) = redis_store.get_health_info(server_id, path).await
        {
            if server_config.h3_only {
                let policy = server_config
                    .cert_hash_policy()
                    .unwrap_or(CertHashPolicy::ValidCert);
                let needs_fresh = matches!(policy, CertHashPolicy::Trust)
                    && cached_health.observed_cert_hash.is_none();
                if !needs_fresh {
                    return cached_health.is_alive;
                }
            } else {
                return cached_health.is_alive;
            }
        }

        let health_info = self
            .probe_liveness(server_id, server_config, path, redis)
            .await;
        if let Some(redis_store) = redis {
            let _ = redis_store
                .set_health_info(server_id, path, &health_info)
                .await;
        }
        health_info.is_alive
    }

    /// 实测连通性，不读不写健康缓存。`redis` 只给需要存储才能签 URL 的后端。
    pub async fn probe_liveness(
        &self,
        server_id: &str,
        server_config: &ServerConfig,
        path: &str,
        redis: Option<&DataStore>,
    ) -> HealthInfo {
        let check_url = self.url(path, Some(vec![(0, 255)]), None, redis).await;
        let check_url = match check_url {
            Ok(url) => url,
            Err(e) => {
                warn!("Keepalive URL generation failed for path {}: {:?}", path, e);
                return HealthInfo::connectivity(false, None);
            }
        };

        let (is_alive, file_size, observed_cert_hash) =
            if server_config.h3_only || server_config.r#type == "dfs_webtransport" {
                let policy = match server_config.cert_hash_policy() {
                    Ok(CertHashPolicy::ValidCert) => CertVerifyPolicy::ValidCert,
                    Ok(CertHashPolicy::Trust) => CertVerifyPolicy::Trust,
                    Ok(CertHashPolicy::PinnedHex(bytes)) => CertVerifyPolicy::PinnedHex(bytes),
                    Err(e) => {
                        warn!(
                            "Invalid cert_hash policy for server {} (treat as valid_cert): {}",
                            server_id, e
                        );
                        CertVerifyPolicy::ValidCert
                    }
                };

                let probe_url = match to_http3_url(&check_url) {
                    Ok(url) => url,
                    Err(e) => {
                        warn!("Invalid HTTP/3 keepalive URL {}: {:?}", check_url, e);
                        return HealthInfo::connectivity(false, None);
                    }
                };
                match crate::container::FETCH_CLIENT
                    .get(&probe_url)
                    .with_extension(policy)
                    .header("range", "bytes=0-255")
                    .send()
                    .await
                {
                    Ok(response) => {
                        let is_alive = response.status().is_success();
                        let file_size = if is_alive {
                            extract_file_size_from_response(response.headers())
                        } else {
                            None
                        };
                        let observed_cert_hash = response
                            .extensions()
                            .get::<H3TransportInfo>()
                            .and_then(|info| info.observed_cert_hash.clone());
                        if !is_alive {
                            warn!(
                                "HTTP/3 keepalive check failed for URL {}: status {}",
                                check_url,
                                response.status()
                            );
                        }
                        (is_alive, file_size, observed_cert_hash)
                    }
                    Err(e) => {
                        warn!(
                            "HTTP/3 keepalive probe failed for URL {}: {:?}",
                            check_url, e
                        );
                        (false, None, None)
                    }
                }
            } else if server_config.ssh_only || server_config.r#type == "dfs_sftp" {
                // SSH/SFTP health check: rewrite URL then use the multi-protocol client.
                let probe_caps = crate::modules::network::capabilities::ClientCapabilities {
                    h3: true,
                    wrtc: true,
                    wt: true,
                    ssh: true,
                    sftp: true,
                };
                let rewritten = crate::modules::network::capabilities::rewrite_url(
                    &check_url,
                    server_config,
                    None,
                    &probe_caps,
                )
                .unwrap_or_else(|_| check_url.clone());

                let ret = crate::container::FETCH_CLIENT
                    .get(&rewritten)
                    .header("range", "bytes=0-255")
                    .send()
                    .await;
                let ret = match ret {
                    Ok(response) => response,
                    Err(e) => {
                        let safe_url = rewritten.split('#').next().unwrap_or(&rewritten);
                        warn!(
                            "SSH/SFTP keepalive request failed for URL {}: {:?}",
                            safe_url, e
                        );
                        return HealthInfo::connectivity(false, None);
                    }
                };
                let is_alive = ret.status().is_success();
                let headers = ret.headers().clone();

                if !is_alive {
                    let status = ret.status();
                    let body = ret.text().await.unwrap_or_default();
                    let safe_url = rewritten.split('#').next().unwrap_or(&rewritten);
                    warn!(
                        "SSH/SFTP keepalive check failed for URL {}: status {} / {}",
                        safe_url, status, body
                    );
                }

                let file_size = if is_alive {
                    extract_file_size_from_response(&headers)
                } else {
                    None
                };

                (is_alive, file_size, None)
            } else {
                let ret = crate::container::FETCH_CLIENT
                    .get(check_url.clone())
                    .header("range", "bytes=0-255")
                    .send()
                    .await;
                let ret = match ret {
                    Ok(response) => response,
                    Err(e) => {
                        warn!("Keepalive request failed for URL {}: {:?}", check_url, e);
                        return HealthInfo::connectivity(false, None);
                    }
                };
                let is_alive = ret.status().is_success();
                let headers = ret.headers().clone();

                if !is_alive {
                    let status = ret.status();
                    let body = ret.text().await.unwrap_or_default();
                    warn!(
                        "Keepalive check failed for URL {}: status {} / {}",
                        check_url, status, body
                    );
                }

                let file_size = if is_alive {
                    extract_file_size_from_response(&headers)
                } else {
                    None
                };

                (is_alive, file_size, None)
            };

        HealthInfo {
            is_alive,
            file_size,
            last_check: chrono::Utc::now().timestamp() as u64,
            observed_cert_hash,
            content_hash: None,
        }
    }

    /// Fetch a small file in full (used for version-file content comparison).
    pub async fn fetch_small_file(
        &self,
        server_config: &ServerConfig,
        path: &str,
        redis: Option<&crate::modules::storage::data_store::DataStore>,
        max_bytes: u64,
    ) -> FileProbe {
        let check_url = match self.url(path, None, None, redis).await {
            Ok(url) => url,
            Err(e) => {
                warn!(
                    "Version-file URL generation failed for path {}: {:?}",
                    path, e
                );
                return FileProbe {
                    is_alive: false,
                    file_size: None,
                    observed_cert_hash: None,
                    body: None,
                };
            }
        };

        let (is_alive, file_size, observed_cert_hash, body) = match tokio::time::timeout(
            VERSION_FILE_PROBE_TIMEOUT,
            execute_full_probe(&check_url, server_config, max_bytes),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => {
                warn!(
                    "Version-file probe exceeded {}s for URL {}",
                    VERSION_FILE_PROBE_TIMEOUT.as_secs(),
                    check_url
                );
                (false, None, None, None)
            }
        };
        FileProbe {
            is_alive,
            file_size,
            observed_cert_hash,
            body,
        }
    }
}

async fn read_limited_body(
    response: reqwest::Response,
    max_bytes: u64,
) -> (Option<u64>, Option<Vec<u8>>) {
    let file_size =
        extract_file_size_from_response(response.headers()).or_else(|| response.content_length());
    if file_size.is_some_and(|size| size > max_bytes) {
        return (file_size, None);
    }
    match response.bytes().await {
        Ok(bytes) if bytes.len() as u64 <= max_bytes => {
            let len = file_size.or(Some(bytes.len() as u64));
            (len, Some(bytes.to_vec()))
        }
        Ok(bytes) => (file_size.or(Some(bytes.len() as u64)), None),
        Err(e) => {
            warn!("Failed to read probe body: {:?}", e);
            (file_size, None)
        }
    }
}

async fn execute_full_probe(
    check_url: &str,
    server_config: &ServerConfig,
    max_bytes: u64,
) -> (bool, Option<u64>, Option<String>, Option<Vec<u8>>) {
    if server_config.h3_only || server_config.r#type == "dfs_webtransport" {
        let policy = match server_config.cert_hash_policy() {
            Ok(CertHashPolicy::ValidCert) => CertVerifyPolicy::ValidCert,
            Ok(CertHashPolicy::Trust) => CertVerifyPolicy::Trust,
            Ok(CertHashPolicy::PinnedHex(bytes)) => CertVerifyPolicy::PinnedHex(bytes),
            Err(e) => {
                warn!(
                    "Invalid cert_hash policy for full probe (treat as valid_cert): {}",
                    e
                );
                CertVerifyPolicy::ValidCert
            }
        };
        let probe_url = match to_http3_url(check_url) {
            Ok(url) => url,
            Err(e) => {
                warn!("Invalid HTTP/3 version-file URL {}: {:?}", check_url, e);
                return (false, None, None, None);
            }
        };
        match crate::container::FETCH_CLIENT
            .get(&probe_url)
            .with_extension(policy)
            .send()
            .await
        {
            Ok(response) => {
                let observed_cert_hash = response
                    .extensions()
                    .get::<H3TransportInfo>()
                    .and_then(|info| info.observed_cert_hash.clone());
                if !response.status().is_success() {
                    warn!(
                        "HTTP/3 version-file probe failed for URL {}: status {}",
                        check_url,
                        response.status()
                    );
                    return (false, None, observed_cert_hash, None);
                }
                let (file_size, body) = read_limited_body(response, max_bytes).await;
                (true, file_size, observed_cert_hash, body)
            }
            Err(e) => {
                warn!(
                    "HTTP/3 version-file probe failed for URL {}: {:?}",
                    check_url, e
                );
                (false, None, None, None)
            }
        }
    } else if server_config.ssh_only || server_config.r#type == "dfs_sftp" {
        let probe_caps = crate::modules::network::capabilities::ClientCapabilities {
            h3: true,
            wrtc: true,
            wt: true,
            ssh: true,
            sftp: true,
        };
        let rewritten = crate::modules::network::capabilities::rewrite_url(
            check_url,
            server_config,
            None,
            &probe_caps,
        )
        .unwrap_or_else(|_| check_url.to_string());
        match crate::container::FETCH_CLIENT.get(&rewritten).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    let safe_url = rewritten.split('#').next().unwrap_or(&rewritten);
                    warn!(
                        "SSH/SFTP version-file probe failed for URL {}: status {} / {}",
                        safe_url, status, body
                    );
                    return (false, None, None, None);
                }
                let (file_size, body) = read_limited_body(response, max_bytes).await;
                (true, file_size, None, body)
            }
            Err(e) => {
                let safe_url = rewritten.split('#').next().unwrap_or(&rewritten);
                warn!(
                    "SSH/SFTP version-file request failed for URL {}: {:?}",
                    safe_url, e
                );
                (false, None, None, None)
            }
        }
    } else {
        match crate::container::FETCH_CLIENT.get(check_url).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    warn!(
                        "Version-file probe failed for URL {}: status {} / {}",
                        check_url, status, body
                    );
                    return (false, None, None, None);
                }
                let (file_size, body) = read_limited_body(response, max_bytes).await;
                (true, file_size, None, body)
            }
            Err(e) => {
                warn!("Version-file request failed for URL {}: {:?}", check_url, e);
                (false, None, None, None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HealthInfo, PingReport, ServerImpl, ServerPing, join_direct_url, ping_selected_servers,
        ping_servers, to_http3_url,
    };
    use crate::tests::mocks::TestEnvironment;

    fn ping(server_id: &str, is_alive: bool) -> ServerPing {
        ServerPing {
            server_id: server_id.to_string(),
            health_check_path: "health".to_string(),
            is_alive,
            file_size: None,
            observed_cert_hash: None,
            last_check: 0,
        }
    }

    #[test]
    fn unreachable_lists_only_failed_pings() {
        let report = PingReport {
            probed: vec![ping("alive", true), ping("dead", false)],
            implementation_missing: vec![],
        };

        let unreachable = report.unreachable();
        assert_eq!(unreachable.len(), 1);
        assert!(unreachable.contains("dead"));
        assert_eq!(report.alive_count(), 1);
    }

    #[test]
    fn servers_without_implementation_are_not_reported_unreachable() {
        // 无法构造实现的节点是配置错误，普查侧本就会给它记空观测，不该混进"不可达"集合
        let report = PingReport {
            probed: vec![],
            implementation_missing: vec!["broken".to_string()],
        };

        assert!(report.unreachable().is_empty());
        assert_eq!(report.alive_count(), 0);
    }

    #[tokio::test]
    async fn servers_without_health_check_path_are_not_probed() {
        let mut config = crate::tests::mocks::create_default_test_config();
        for server_config in config.servers.values_mut() {
            server_config.health_check_path = None;
        }

        let report = ping_servers(&config, 4).await;
        assert!(report.probed.is_empty());
        assert!(report.implementation_missing.is_empty());
        assert!(report.unreachable().is_empty());
    }

    fn rebuild_server_impl(config: &mut crate::config::AppConfig) {
        config.server_impl.clear();
        for (id, server_config) in config.servers.iter() {
            if let Ok(server) = ServerImpl::new(server_config) {
                config.server_impl.insert(id.clone(), server);
            }
        }
    }

    async fn fixture_with_health_paths() -> (crate::config::AppConfig, TestEnvironment) {
        let mut config = crate::tests::mocks::create_default_test_config();
        for (id, server) in config.servers.iter_mut() {
            server.url = "http://127.0.0.1:1".into();
            server.health_check_path = Some(format!("/health-{id}"));
        }
        rebuild_server_impl(&mut config);
        let env = TestEnvironment::with_config(config.clone()).await;
        (config, env)
    }

    #[tokio::test]
    async fn ping_writes_health_only_when_store_is_some() {
        let (config, env) = fixture_with_health_paths().await;
        let paths: Vec<(String, String)> = config
            .servers
            .iter()
            .filter_map(|(id, s)| {
                s.health_check_path
                    .as_ref()
                    .map(|p| (id.clone(), p.clone()))
            })
            .collect();
        assert!(!paths.is_empty());

        ping_selected_servers(&config, None, 4, None).await;
        for (id, path) in &paths {
            assert!(
                env.data_store
                    .get_health_info(id, path)
                    .await
                    .unwrap()
                    .is_none(),
                "store=None must not write {id}:{path}"
            );
        }

        let report = ping_selected_servers(&config, None, 4, Some(&env.data_store)).await;
        assert_eq!(report.probed.len(), paths.len());
        for (id, path) in &paths {
            let info = env
                .data_store
                .get_health_info(id, path)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("missing health for {id}:{path}"));
            assert!(!info.is_alive);
        }
    }

    #[tokio::test]
    async fn ping_overwrites_cached_dead_without_reading_it() {
        let (config, env) = fixture_with_health_paths().await;
        let (id, path) = config
            .servers
            .iter()
            .find_map(|(id, s)| {
                s.health_check_path
                    .as_ref()
                    .map(|p| (id.clone(), p.clone()))
            })
            .unwrap();
        env.data_store
            .set_health_info(
                &id,
                &path,
                &HealthInfo {
                    is_alive: false,
                    file_size: Some(999),
                    last_check: 1,
                    observed_cert_hash: None,
                    content_hash: None,
                },
            )
            .await
            .unwrap();

        ping_selected_servers(&config, None, 4, Some(&env.data_store)).await;
        let info = env
            .data_store
            .get_health_info(&id, &path)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            info.last_check, 1,
            "probe must overwrite the seeded last_check"
        );
        assert_ne!(info.file_size, Some(999));
    }

    #[test]
    fn join_direct_url_inserts_slash_when_base_has_none() {
        assert_eq!(
            join_direct_url("https://cdn.example.com", "/test/file.bin"),
            "https://cdn.example.com/test/file.bin"
        );
        assert_eq!(
            join_direct_url("https://cdn.example.com/", "/test/file.bin"),
            "https://cdn.example.com/test/file.bin"
        );
    }

    #[test]
    fn converts_https_probe_url_to_http3() {
        assert_eq!(
            to_http3_url("https://example.com/file?sig=abc").expect("valid probe URL"),
            "http3://example.com/file?sig=abc"
        );
    }

    #[test]
    fn preserves_non_default_probe_port() {
        assert_eq!(
            to_http3_url("https://example.com:8443/file").expect("valid probe URL"),
            "http3://example.com:8443/file"
        );
    }
}
