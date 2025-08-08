use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::warn;

use crate::config::ServerConfig;

pub mod dfs_node;
pub mod git_lfs;
pub mod s3;

/// 健康检查结果，包含存活状态和文件大小信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthInfo {
    pub is_alive: bool,
    pub file_size: Option<u64>,
    pub last_check: u64,
}

/// 从HTTP响应中提取文件大小
fn extract_file_size_from_response(response: &reqwest::Response) -> Option<u64> {
    // 优先从 Content-Range 头部提取总大小 (Range请求的情况)
    // 格式: Content-Range: bytes 0-255/1048576
    if let Some(content_range) = response.headers().get("content-range") {
        if let Ok(range_str) = content_range.to_str() {
            if let Some(total_size_str) = range_str.split('/').nth(1) {
                if let Ok(total_size) = total_size_str.parse::<u64>() {
                    return Some(total_size);
                }
            }
        }
    }

    // 如果是完整文件响应，从Content-Length获取
    response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

#[derive(Clone, Debug)]
pub enum ServerImpl {
    Direct(String),
    S3(s3::S3Signer),
    DfsNode(dfs_node::DfsNodeSigner),
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
            ServerImpl::Direct(url) => Ok(format!(
                "{}{}",
                url,
                path.strip_prefix('/').unwrap_or(path).replace('\\', "/")
            )),
            ServerImpl::S3(signer) => {
                let mut headers = BTreeMap::new();
                if let Some(ranges_vec) = ranges {
                    if !ranges_vec.is_empty() {
                        // S3 supports multiple ranges in a single Range header
                        let range_specs: Vec<String> = ranges_vec
                            .iter()
                            .map(|(start, end)| format!("{}-{}", start, end))
                            .collect();
                        let range_header = format!("bytes={}", range_specs.join(","));
                        headers.insert("range".to_string(), range_header);
                    }
                }
                signer.generate_presigned_url(path, Some(headers))
            }
            ServerImpl::DfsNode(signer) => {
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

    pub async fn is_alive(
        &self,
        server_id: &str,
        path: &str,
        redis: Option<&crate::modules::storage::data_store::DataStore>,
    ) -> bool {
        // Check cache first if Redis store is available
        if let Some(redis_store) = redis {
            if let Ok(Some(cached_health)) = redis_store.get_health_info(server_id, path).await {
                return cached_health.is_alive;
            }
        }

        // Perform actual health check
        let check_url = self.url(path, Some(vec![(0, 255)]), None, redis).await;
        let check_url = match check_url {
            Ok(url) => url,
            Err(e) => {
                warn!("Keepalive URL generation failed for path {}: {:?}", path, e);
                // Cache negative result
                if let Some(redis_store) = redis {
                    let health_info = HealthInfo {
                        is_alive: false,
                        file_size: None,
                        last_check: chrono::Utc::now().timestamp() as u64,
                    };
                    let _ = redis_store
                        .set_health_info(server_id, path, &health_info)
                        .await;
                }
                return false;
            }
        };
        let ret = crate::container::REQWEST_CLIENT
            .get(check_url.clone())
            .header("range", "bytes=0-255")
            .send()
            .await;
        let ret = match ret {
            Ok(response) => response,
            Err(e) => {
                warn!("Keepalive request failed for URL {}: {:?}", check_url, e);
                // Cache negative result
                if let Some(redis_store) = redis {
                    let health_info = HealthInfo {
                        is_alive: false,
                        file_size: None,
                        last_check: chrono::Utc::now().timestamp() as u64,
                    };
                    let _ = redis_store
                        .set_health_info(server_id, path, &health_info)
                        .await;
                }
                return false;
            }
        };
        let is_alive = ret.status().is_success();

        if !is_alive {
            warn!(
                "Keepalive check failed for URL {}: status {}",
                check_url,
                ret.status()
            );
        }

        // 从响应中提取文件大小信息
        let file_size = if is_alive {
            extract_file_size_from_response(&ret)
        } else {
            None
        };

        // 创建健康信息并缓存
        let health_info = HealthInfo {
            is_alive,
            file_size,
            last_check: chrono::Utc::now().timestamp() as u64,
        };

        if let Some(redis_store) = redis {
            let _ = redis_store
                .set_health_info(server_id, path, &health_info)
                .await;
        }

        is_alive
    }
}
