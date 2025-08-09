use axum::{Router, routing::get};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::modules::storage::data_store::DataStore;

pub mod chunk;
pub mod downloads;
pub mod metadata;
pub mod sessions;

// 解析range字符串为flowrunner的ranges格式
// "0-" 或整个文件 -> None
// "1024-2047" 等具体范围 -> Some(vec![(start, end)])
pub fn parse_range_for_flow(range_str: &str) -> Option<Vec<(u32, u32)>> {
    let parts: Vec<&str> = range_str.split('-').collect();
    if parts.len() != 2 {
        return None;
    }

    let start = parts[0].parse::<u32>().ok()?;

    // 如果是 "0-" 格式（从开头到结尾），返回 None 表示整个文件
    if parts[1].is_empty() && start == 0 {
        return None;
    }

    let end = if parts[1].is_empty() {
        // 其他 "X-" 格式，表示从X到文件末尾
        u32::MAX
    } else {
        parts[1].parse::<u32>().ok()?
    };

    Some(vec![(start, end)])
}

// 计算range覆盖的实际字节数
pub fn calculate_actual_bytes_from_range(range_str: Option<&str>, full_file_size: u64) -> u64 {
    if let Some(range_str) = range_str {
        if let Some(ranges) = parse_range_for_flow(range_str) {
            // 有具体range，计算range覆盖的字节数
            ranges
                .iter()
                .map(|(start, end)| {
                    if *end == u32::MAX {
                        // "X-" 格式，从start到文件结尾
                        full_file_size.saturating_sub(*start as u64)
                    } else {
                        // "X-Y" 格式，计算范围大小
                        (*end as u64).saturating_sub(*start as u64) + 1
                    }
                })
                .sum()
        } else {
            // parse_range_for_flow返回None表示整个文件("0-")
            full_file_size
        }
    } else {
        // 没有range参数，整个文件
        full_file_size
    }
}

// 宏用于记录请求指标
#[macro_export]
macro_rules! record_request_metrics {
    ($metrics:expr, $start_time:expr) => {
        $metrics.record_request();
        $metrics.record_request_duration($start_time.elapsed().as_secs_f64());
    };
}

// 宏用于记录流程执行指标
#[macro_export]
macro_rules! record_flow_metrics {
    ($metrics:expr, $success:expr) => {
        $metrics.record_flow_execution();
        if !$success {
            $metrics.record_flow_failure();
        }
    };
}

// 生成32位 hex 格式的 session ID
// 辅助函数：更新会话模式的流量统计
async fn update_session_bandwidth_stats(
    data_store: &DataStore,
    _session_id: &str,
    resource_id: &str,
    stats: &crate::modules::storage::data_store::SessionStats,
) {
    // 从每个成功下载的chunk中提取服务器信息和估算流量
    let mut server_usage: HashMap<String, u64> = HashMap::new();
    let mut total_bandwidth = 0u64;

    for (chunk_id, download_count) in &stats.download_counts {
        if *download_count > 0 {
            // 获取该chunk的CDN记录
            if let Some(cdn_records) = stats.cdn_records.get(chunk_id) {
                if let Some(latest_record) = cdn_records.last() {
                    if let Some(server_id) = &latest_record.server_id {
                        // 使用CdnRecord中记录的文件大小，如果没有则使用默认值
                        let estimated_chunk_size = latest_record.size.unwrap_or(1024 * 1024);

                        // 根据下载次数估算流量（通常一次成功即可）
                        let chunk_bandwidth = estimated_chunk_size
                            .min(estimated_chunk_size * (*download_count as u64));

                        // 累计到服务器使用量
                        *server_usage.entry(server_id.clone()).or_default() += chunk_bandwidth;
                        total_bandwidth += chunk_bandwidth;

                        debug!(
                            "Session bandwidth calculation: chunk={}, server={}, size={}, downloads={}",
                            chunk_id, server_id, chunk_bandwidth, download_count
                        );
                    }
                }
            }
        }
    }

    // 更新流量统计（资源级别和服务器级别）
    if total_bandwidth > 0 {
        // 首先更新全局资源统计，使用总带宽量
        if let Err(e) = data_store
            .update_resource_daily_bandwidth(resource_id, total_bandwidth)
            .await
        {
            warn!(
                "Failed to update resource daily bandwidth for {}: {}",
                resource_id, e
            );
        }
        if let Err(e) = data_store
            .update_global_daily_bandwidth(total_bandwidth)
            .await
        {
            warn!("Failed to update global daily bandwidth: {}", e);
        }

        // 分别更新各个服务器的流量统计
        let server_count = server_usage.len();
        for (server_id, bandwidth) in server_usage {
            if let Err(e) = data_store
                .update_server_daily_bandwidth(&server_id, bandwidth)
                .await
            {
                warn!(
                    "Failed to update server daily bandwidth for {}: {}",
                    server_id, e
                );
            }
        }

        info!(
            "Updated bandwidth stats: resource_id={}, total_bandwidth={}, servers={}",
            resource_id, total_bandwidth, server_count
        );
    }
}

// 路由设置
pub fn routes() -> Router {
    Router::new()
        .route(
            "/resource/{resid}",
            get(metadata::get_metadata).post(sessions::create_session),
        )
        .route(
            "/resource/{resid}/{*sub_path}",
            get(metadata::get_prefix_metadata).post(sessions::create_prefix_session),
        )
        .route(
            "/session/{sessionid}/{resid}",
            get(chunk::get_cdn).delete(sessions::delete_session),
        )
        .route(
            "/download/{resid}",
            get(downloads::download_redirect).post(downloads::download_json),
        )
        .route(
            "/download/{resid}/{*sub_path}",
            get(downloads::download_prefix_redirect).post(downloads::download_prefix_json),
        )
}
