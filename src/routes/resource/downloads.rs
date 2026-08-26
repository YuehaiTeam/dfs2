use axum::{
    extract::{Extension, Path, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

use crate::{
    config::DownloadPolicy,
    error::DfsError,
    modules::{
        external::geolocation,
        network::RealConnectInfo,
        network::capabilities::compute_capabilities,
        storage::{cache::should_cache_content, data_store::BandwidthUpdateBatch},
    },
    routes::resource::{calculate_actual_bytes_from_range, parse_range_for_flow},
};
use crate::{container::AppContext, modules::storage::data_store::CacheMetadata};
use crate::{
    error::DfsResult,
    modules::storage::cache::download_and_cache,
    responses::{ApiResponse, DownloadUrlResponse, ErrorResponse, ResponseData},
};

// 下载响应类型
#[derive(Debug)]
pub enum DownloadResponse {
    Cached {
        content: Vec<u8>,
        metadata: CacheMetadata,
        status: CacheStatus,
    },
    Redirect(String),
}

/// 本次响应的字节是取自缓存层，还是刚从源节点拉取并顺手回填
#[derive(Debug, Clone, Copy)]
pub enum CacheStatus {
    Hit,
    Miss,
}

impl CacheStatus {
    fn as_str(self) -> &'static str {
        match self {
            CacheStatus::Hit => "hit",
            CacheStatus::Miss => "miss",
        }
    }
}

/// 为缓存响应装配头部，缺少来源信息时省略 `x-dfs-cache-from`
fn cached_response_headers(metadata: &CacheMetadata, status: CacheStatus) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let remaining_max_age = metadata.remaining_max_age();

    if let Ok(value) = format!("public, max-age={remaining_max_age}").parse() {
        headers.insert("cache-control", value);
    }
    if let Ok(value) = metadata.etag.parse() {
        headers.insert("etag", value);
    }
    if let Ok(value) = status.as_str().parse() {
        headers.insert("x-dfs-cache-status", value);
    }
    if let Some(src) = metadata.src.as_deref()
        && let Ok(value) = src.parse()
    {
        headers.insert("x-dfs-cache-from", value);
    }
    if let Ok(value) = metadata.content_length.to_string().parse() {
        headers.insert("content-length", value);
    }

    let content_type = metadata
        .content_type
        .as_deref()
        .unwrap_or("application/octet-stream");
    if let Ok(value) = content_type.parse() {
        headers.insert("content-type", value);
    }

    headers
}

/// 可缓存内容的大小上限。超过这个大小的文件不进缓存，整份内容会驻留在数据存储里。
const CACHE_MAX_BYTES: u64 = 256 * 1024;

/// 为缓存回填单独调度一次取件。
///
/// 不复用发给客户端的那个 URL。它是按客户端的地理位置与传输能力选出来的，两处对不上：本进程
/// 无法发起 `h3wt://`、`wrtc://` 这类协议，取件会直接失败；而即使协议可行，客户端在国内选中的
/// 国内节点对海外的服务端也是反向绕行。回填内容会分发给此后所有客户端，取件方向应当由服务端
/// 自身的位置决定。
///
/// 回填失败不影响本次请求：客户端已经拿到了自己的 URL，这里只是没写进缓存。
#[allow(clippy::too_many_arguments)]
async fn fill_cache_via_internal_fetch(
    ctx: &AppContext,
    config: &crate::config::AppConfig,
    resid: &str,
    version: &str,
    path: &str,
    sub_path: Option<&str>,
    file_size: Option<u64>,
    flow_list: &[crate::modules::flow::config::FlowItem],
) -> Option<(CacheMetadata, Vec<u8>)> {
    let resource = config.get_resource(resid)?;
    if !crate::modules::storage::cache::cache_eligible(resource, sub_path) {
        return None;
    }

    let target = crate::models::FlowTarget {
        resource_id: resid.to_string(),
        version: version.to_string(),
        sub_path: sub_path.map(str::to_string),
        // 缓存存的是整个文件，与客户端本次请求的区间无关
        ranges: None,
        file_size,
    };
    let context = crate::models::FlowContext::internal();
    let options = crate::models::FlowOptions {
        cdn_full_range: false,
    };

    let flow_result = match ctx
        .flow_service
        .execute_flow(
            &target,
            &context,
            &options,
            flow_list,
            crate::models::FlowPenalties::default(),
            None,
        )
        .await
    {
        Ok(flow_result) => flow_result,
        Err(e) => {
            warn!("Cache fill for {resid}/{path} found no usable server: {e}");
            return None;
        }
    };

    let Some(source_server) = flow_result.selected_server_id.as_deref() else {
        warn!("Cache fill for {resid}/{path} produced a URL with no server attribution");
        return None;
    };

    // 大小闸门要问将要供出内容的那个节点，而不是客户端选中的节点
    let (fetch_size, max_age) = should_cache_content(
        config,
        &ctx.data_store,
        resid,
        sub_path,
        source_server,
        path,
    )
    .await?;

    if fetch_size >= CACHE_MAX_BYTES {
        debug!(
            "Not caching {resid}/{path}: {fetch_size} bytes exceeds the {CACHE_MAX_BYTES}-byte limit"
        );
        return None;
    }

    match download_and_cache(
        &flow_result.url,
        resid,
        version,
        path,
        &ctx.data_store,
        max_age,
        source_server,
    )
    .await
    {
        Ok(cached) => {
            debug!("Cached {resid}/{path} ({fetch_size} bytes) from {source_server}");
            Some(cached)
        }
        Err(e) => {
            warn!("Cache fill for {resid}/{path} from {source_server} failed: {e}");
            None
        }
    }
}

// 统一下载逻辑函数 - 合并原有的handle_download_request和handle_prefix_download_request
pub async fn handle_download_request_unified(
    resid: String,
    sub_path: Option<String>, // 关键参数：None=普通资源, Some=前缀资源
    session_id: Option<String>,
    range: Option<String>,
    ctx: &AppContext,
    client_ip: Option<std::net::IpAddr>,
    user_agent: Option<String>,
    h3_override: Option<String>, // X-DFS-Override header value for h3 capability detection
) -> DfsResult<DownloadResponse> {
    let config_guard = ctx.shared_config.load();

    // 统一资源验证：使用ResourceService验证资源存在性和类型
    let (validated_resid, _effective_version) = ctx
        .resource_service
        .validate_resource_and_version(&resid, "", sub_path.as_deref())
        .await?;

    let resource_config = config_guard.get_resource(&validated_resid).unwrap(); // 已验证存在

    // 保存原始 session_id 用于后续销毁
    let original_session_id = session_id.clone();

    // 提取 extras 信息和session对象用于 Flow 规则
    let (mut extras, mut enabled_session) = match &resource_config.download {
        DownloadPolicy::Disabled => {
            return Err(DfsError::download_not_allowed(
                &resid,
                "download is disabled for this resource",
            ));
        }
        DownloadPolicy::Free => {
            // 无需 session 验证，使用空 extras
            (serde_json::json!({}), None)
        }
        DownloadPolicy::Enabled => {
            // 需要验证 session
            let session_id = session_id.as_ref().ok_or_else(|| {
                DfsError::download_not_allowed(&resid, "session parameter is required")
            })?;

            // 获取并验证 session（使用统一的session服务）
            let session = ctx
                .session_service
                .get_validated_session(session_id)
                .await?;

            if session.resource_id != resid || session.sub_path != sub_path {
                return Err(DfsError::download_not_allowed(
                    &resid,
                    "session is bound to a different file",
                ));
            }

            // 验证 chunks：比较请求的 range 与 session chunks 是否一致
            if let Some(requested_range) = &range {
                // 请求带有 range 参数，检查 session 是否包含对应的 range
                if !session.chunks.contains(requested_range) {
                    return Err(DfsError::download_not_allowed(
                        &resid,
                        format!("session does not allow range '{requested_range}'"),
                    ));
                }
            } else {
                // 请求没有 range 参数，检查 session 是否包含 "0-"
                let has_zero_range = session.chunks.iter().any(|chunk| chunk.starts_with("0-"));
                if !has_zero_range {
                    return Err(DfsError::download_not_allowed(
                        &resid,
                        "chunks must contain '0-' range for download",
                    ));
                }
            }

            // 返回 session 的 extras 和 session 对象
            (session.extras.clone(), Some(session))
        }
    };

    // 获取版本对应的路径 - 使用统一的get_version_path函数
    let version: String = ctx.resource_service.get_effective_version(&resid).await?;
    let path = ctx
        .resource_service
        .get_version_path(&resid, &version, None, sub_path.as_deref())
        .ok_or_else(|| DfsError::path_not_found(&resid, &version))?;

    let is_version_file = ctx
        .version_file_service
        .is_version_file_request(&resid, &version, &path)
        .await;
    if is_version_file
        && ctx
            .version_file_service
            .is_split_failed(&resid, &path)
            .await
    {
        return Err(DfsError::download_not_allowed(
            &resid,
            "version file has no replica majority",
        ));
    }

    if matches!(resource_config.download, DownloadPolicy::Free) {
        if let Some(sid) = original_session_id.as_deref() {
            let mut stored_session = ctx.data_store.get_session(sid).await?;
            if stored_session.as_ref().is_some_and(|session| {
                session.is_direct_expired(chrono::Utc::now().timestamp() as u64)
            }) {
                ctx.session_service.remove_session(sid).await?;
                stored_session = None;
            }

            let session = match stored_session {
                Some(session) => {
                    // Free sid 只做粘滞回退，不锁死单个文件。同一资源下换 sub_path 必须能复用。
                    if session.resource_id != resid {
                        return Err(DfsError::download_not_allowed(
                            &resid,
                            "sid is already associated with a different download",
                        ));
                    }
                    if let Err(e) = ctx.session_service.refresh_session(sid).await {
                        warn!("Failed to refresh free sticky session {sid}: {e}");
                    }
                    session
                }
                None => {
                    let mut session = crate::models::Session {
                        resource_id: resid.clone(),
                        version: version.clone(),
                        chunks: vec![range.clone().unwrap_or_else(|| "0-".to_string())],
                        sub_path: None,
                        cdn_records: std::collections::HashMap::new(),
                        extras: serde_json::json!({"client_ip": client_ip.map(|ip| ip.to_string())}),
                        created_at: chrono::Utc::now().timestamp() as u64,
                        kind: crate::models::SessionKind::Direct,
                        expires_at: None,
                    };
                    session.make_direct();
                    ctx.session_service.store_session(sid, &session).await?;
                    session
                }
            };
            extras = session.extras.clone();
            enabled_session = Some(session);
        }
    } else if let Some(session) = enabled_session.as_mut() {
        if session.kind != crate::models::SessionKind::Direct {
            session.make_direct();
            if !session.chunks.iter().any(|chunk| chunk == "0-") {
                session.chunks.push("0-".to_string());
            }
            ctx.session_service
                .store_session(original_session_id.as_deref().unwrap_or_default(), session)
                .await?;
        }
    }

    // 检查资源是否启用缓存，如果是，先检查缓存
    if resource_config.cache_enabled {
        // 缓存启用条件判断（统一前缀资源的子路径模式匹配）
        let should_check_cache = if let Some(ref sub_path_val) = sub_path {
            // 前缀资源：检查子路径是否匹配缓存模式
            resource_config
                .cache_subpaths
                .iter()
                .any(|pattern| crate::modules::storage::cache::glob_match(pattern, sub_path_val))
        } else {
            // 普通资源：直接启用缓存检查
            true
        };

        if should_check_cache {
            // 先进行简单的缓存检查（不需要server_id）
            if let Ok(Some((metadata, content))) = ctx
                .data_store
                .get_full_cached_content(&resid, &version, &path)
                .await
            {
                // 缓存命中！所有下载策略都记日志，否则 enabled 资源的命中会完全没有痕迹
                if let Some(ip) = client_ip {
                    let session_logger = crate::modules::analytics::SessionLogger::new(
                        ctx.shared_config.clone(),
                        ctx.data_store.clone(),
                    );
                    let log_result = session_logger
                        .log_cached_download(
                            &resid,
                            &version,
                            ip,
                            user_agent.clone(),
                            original_session_id.clone(),
                            metadata.content_length,
                            metadata.src.as_deref(),
                        )
                        .await;
                    if let Err(e) = log_result {
                        let log_type = if sub_path.is_some() {
                            "cached prefix download"
                        } else {
                            "cached download"
                        };
                        error!("Failed to log {}: {}", log_type, e);
                    }
                }

                // 缓存命中时更新流量统计 - 使用"cache"作为server_id
                let file_size = metadata.content_length;
                let server_id = "cache";

                if let Err(e) = ctx
                    .data_store
                    .update_bandwidth_batch(BandwidthUpdateBatch {
                        resource_id: resid.clone(),
                        server_id: server_id.to_string(),
                        bytes: file_size,
                    })
                    .await
                {
                    warn!("Failed to update bandwidth for cached download: {}", e);
                }

                // 新增：记录分钟级流量
                ctx.bandwidth_cache_service
                    .record_bandwidth(server_id, file_size)
                    .await;

                // 记录缓存命中的调度请求 - 没有实际调度到服务器
                ctx.metrics
                    .record_scheduled_request(&resid, server_id, true);

                let cache_debug_msg = if sub_path.is_some() {
                    format!(
                        "Prefix cache hit: file_size={file_size}, resource_id={resid}, server_id={server_id}, sub_path={sub_path:?}"
                    )
                } else {
                    format!(
                        "Cache hit: file_size={file_size}, resource_id={resid}, server_id={server_id}"
                    )
                };
                debug!("{}", cache_debug_msg);

                return Ok(DownloadResponse::Cached {
                    content,
                    metadata,
                    status: CacheStatus::Hit,
                });
            }
        }
    }

    // 缓存未命中，需要进行实际的服务器调度
    // 从flow配置中提取服务器列表来获取文件大小（用于Size条件评估）
    let servers_from_flow: Vec<String> = resource_config
        .flow
        .iter()
        .flat_map(|flow_item| {
            flow_item.r#use.iter().filter_map(|flow_use| {
                if let crate::modules::flow::config::FlowUse::Server { id, .. } = flow_use {
                    Some(id.clone())
                } else {
                    None
                }
            })
        })
        .collect();

    debug!(
        "Starting file size detection for path: {}, servers from flow: {:?}",
        path, servers_from_flow
    );
    let file_size = {
        let mut size_candidate = None;
        for server_id in &servers_from_flow {
            debug!(
                "Checking health info for server: {}, path: {}",
                server_id, path
            );
            match ctx.data_store.get_health_info(server_id, &path).await {
                Ok(Some(health_info)) => {
                    debug!(
                        "Health info found for server {}: file_size={:?}, is_alive={}",
                        server_id, health_info.file_size, health_info.is_alive
                    );
                    if let Some(size) = health_info.file_size {
                        size_candidate = Some(size);
                        debug!(
                            "File size detected: {} bytes from server {}",
                            size, server_id
                        );
                        break;
                    }
                }
                Ok(None) => {
                    debug!("No health info found for server: {}", server_id);
                }
                Err(e) => {
                    debug!("Error getting health info for server {}: {}", server_id, e);
                }
            }
        }
        debug!("Final file size candidate: {:?}", size_candidate);
        size_candidate
    };

    // 解析range参数（保持原有逻辑，让flow规则正常工作）
    let parsed_ranges = range.as_ref().and_then(|r| parse_range_for_flow(r));

    // 根据range请求计算实际请求的文件大小
    let request_file_size = if let Some(ref ranges) = parsed_ranges {
        // 如果有range请求，计算range的总大小
        let range_size = Some(
            ranges
                .iter()
                .map(|(start, end)| (end - start + 1) as u64)
                .sum(),
        );
        debug!(
            "Range request detected: {:?}, calculated size: {:?}",
            ranges, range_size
        );
        range_size
    } else {
        // 如果没有range请求，使用完整文件大小
        debug!("No range request, using full file size: {:?}", file_size);
        file_size
    };
    debug!(
        "Final request_file_size for flow evaluation: {:?}",
        request_file_size
    );

    // 使用新的FlowService API生成下载 URL
    let target = crate::models::FlowTarget {
        resource_id: resid.clone(),
        version: version.clone(),
        sub_path: sub_path.clone(), // 关键差异：前缀资源有值，普通资源为None
        ranges: parsed_ranges.clone(),
        file_size: request_file_size, // 使用请求的实际大小
    };

    let context = crate::models::FlowContext {
        client_ip,
        session_id: original_session_id.clone(),
        extras,
        capabilities: compute_capabilities(h3_override.as_deref(), user_agent.as_deref()),
        internal: false,
    };

    let options = crate::models::FlowOptions {
        cdn_full_range: resource_config.legacy_client_full_range
            && resource_config.legacy_client_support, // 历史客户端全范围模式
    };

    // 记录调度结果日志
    let resource_path = if let Some(ref sub_path_val) = sub_path {
        format!("{resid}/{sub_path_val}")
    } else {
        resid.clone()
    };
    let file_size_mb = request_file_size
        .map(|size| size as f64 / 1024.0 / 1024.0)
        .unwrap_or(0.0);
    let flow_list = &resource_config.flow;
    let flow_result = if let (Some(sid), Some(session)) = (&original_session_id, &enabled_session) {
        let requested_ranges = parsed_ranges.unwrap_or_default();
        let chunk_key = ctx
            .session_service
            .generate_chunk_key_from_ranges(&requested_ranges);
        let count_key =
            crate::services::SessionService::scoped_download_key(sub_path.as_deref(), &chunk_key);
        if matches!(resource_config.download, DownloadPolicy::Enabled) {
            ctx.session_service
                .check_download_limit(sid, &count_key)
                .await?;
            ctx.session_service
                .run_flow_for_session(
                    session,
                    sid,
                    requested_ranges,
                    &ctx.flow_service,
                    client_ip,
                    request_file_size,
                    flow_list,
                    &options,
                    context.capabilities.clone(),
                )
                .await
                .map_err(|e| {
                    error!("ERROR {} size={:.2}MB {}", resource_path, file_size_mb, e);
                    DfsError::internal_error(format!("Failed to generate download URL: {e}"))
                })?
        } else {
            ctx.session_service
                .record_download_attempt(sid, &count_key)
                .await?;
            ctx.session_service
                .run_flow_for_sticky_download(
                    session,
                    sid,
                    &target,
                    &ctx.flow_service,
                    &context,
                    &options,
                    flow_list,
                )
                .await
                .map_err(|e| {
                    error!("ERROR {} size={:.2}MB {}", resource_path, file_size_mb, e);
                    DfsError::internal_error(format!("Failed to generate download URL: {e}"))
                })?
        }
    } else {
        // Free模式：无session，直接使用FlowService
        ctx.flow_service
            .execute_flow(
                &target,
                &context,
                &options,
                flow_list,
                crate::models::FlowPenalties::default(),
                None, // no session in free mode
            )
            .await
            .map_err(|e| {
                error!("ERROR {} size={:.2}MB {}", resource_path, file_size_mb, e);
                DfsError::internal_error(format!("Failed to generate download URL: {e}"))
            })?
    };
    let cdn_url = flow_result.url;

    info!(
        "{} size={:.2}MB -> {} weight={} ip={} geo={}",
        resource_path,
        file_size_mb,
        flow_result
            .selected_server_id
            .as_deref()
            .unwrap_or("unknown"),
        flow_result.selected_server_weight.unwrap_or(0),
        if let Some(ip) = client_ip {
            ip.to_string()
        } else {
            "unknown".to_string()
        },
        if let Some(ip) = client_ip {
            geolocation::get_ip_location_data(ip).unwrap_or("unknown".to_string())
        } else {
            "unknown".to_string()
        }
    );

    let cached_result = if is_version_file {
        None
    } else {
        fill_cache_via_internal_fetch(
            ctx,
            &config_guard,
            &resid,
            &version,
            &path,
            sub_path.as_deref(),
            file_size,
            flow_list,
        )
        .await
    };

    // 如果是 Free 模式，记录直接下载日志
    if matches!(resource_config.download, DownloadPolicy::Free) {
        if let Some(ip) = client_ip {
            let session_logger = crate::modules::analytics::SessionLogger::new(
                ctx.shared_config.clone(),
                ctx.data_store.clone(),
            );
            // 使用选中的服务器ID和权重，如果没有则使用默认值
            let server_id = flow_result
                .selected_server_id
                .as_deref()
                .unwrap_or("unknown");
            let server_weight = flow_result.selected_server_weight.unwrap_or(10);

            let log_result = session_logger
                .log_direct_download(
                    &resid,
                    &version,
                    ip,
                    user_agent.clone(),
                    &cdn_url,
                    server_id,
                    server_weight,
                )
                .await;
            if let Err(e) = log_result {
                let log_type = if sub_path.is_some() {
                    "prefix direct download"
                } else {
                    "direct download"
                };
                error!("Failed to log {}: {}", log_type, e);
            }
        }
    }

    // Direct session 保留到其短生命周期结束，以支持使用同一 sid 的节点回退。
    if matches!(resource_config.download, DownloadPolicy::Enabled) {
        if let Some(ref sid) = original_session_id {
            // 在删除之前记录直接下载日志
            if let Some(ip) = client_ip {
                let session_logger = crate::modules::analytics::SessionLogger::new(
                    ctx.shared_config.clone(),
                    ctx.data_store.clone(),
                );
                let server_id = flow_result
                    .selected_server_id
                    .as_deref()
                    .unwrap_or("unknown");
                let server_weight = flow_result.selected_server_weight.unwrap_or(10);

                let log_result = session_logger
                    .log_direct_download(
                        &resid,
                        &version, // 使用实际获取到的版本而不是resource_config.latest
                        ip,
                        user_agent.clone(),
                        &cdn_url,
                        server_id,
                        server_weight,
                    )
                    .await;
                if let Err(e) = log_result {
                    let log_type = if sub_path.is_some() {
                        "direct download for prefix"
                    } else {
                        "direct download"
                    };
                    error!("Failed to log {}: {}", log_type, e);
                }
            }
        }
    }

    // 记录调度请求指标（无论是否能获取文件大小）
    if let Some(server_id) = &flow_result.selected_server_id {
        ctx.metrics
            .record_scheduled_request(&resid, server_id, false);
    }

    // 更新流量统计（在成功生成下载URL后）
    if let Some(server_id) = &flow_result.selected_server_id {
        // 尝试从健康检查缓存获取文件大小
        if let Ok(Some(health_info)) = ctx.data_store.get_health_info(server_id, &path).await {
            if let Some(full_file_size) = health_info.file_size {
                // 根据range计算实际传输字节数
                let actual_bytes =
                    calculate_actual_bytes_from_range(range.as_deref(), full_file_size);

                // 1. 更新日流量统计（资源、服务器、全局）
                if let Err(e) = ctx
                    .data_store
                    .update_bandwidth_batch(BandwidthUpdateBatch {
                        resource_id: resid.clone(),
                        server_id: server_id.to_string(),
                        bytes: actual_bytes,
                    })
                    .await
                {
                    let server_type = if sub_path.is_some() {
                        "prefix server"
                    } else {
                        "server"
                    };
                    warn!(
                        "Failed to update daily bandwidth for {} {}: {}",
                        server_type, server_id, e
                    );
                }

                // 2. 记录分钟级流量（独立于日流量更新结果）
                ctx.bandwidth_cache_service
                    .record_bandwidth(server_id, actual_bytes)
                    .await;

                let debug_msg = if sub_path.is_some() {
                    format!(
                        "Updated prefix download bandwidth stats: actual_bytes={actual_bytes}, full_file_size={full_file_size}, range={range:?}, server_id={server_id}, session_id={original_session_id:?}"
                    )
                } else {
                    format!(
                        "Updated bandwidth stats: actual_bytes={actual_bytes}, full_file_size={full_file_size}, range={range:?}, resource_id={resid}, server_id={server_id}"
                    )
                };
                debug!("{}", debug_msg);
            }
        }
    }

    // 刚回填的内容直接回给客户端，对本次请求而言并不是命中
    if let Some((metadata, content)) = cached_result {
        return Ok(DownloadResponse::Cached {
            content,
            metadata,
            status: CacheStatus::Miss,
        });
    }

    Ok(DownloadResponse::Redirect(cdn_url))
}

// GET /download/{resid} - 重定向到下载链接
#[utoipa::path(
    get,
    path = "/download/{resid}",
    tag = "Resource",
    summary = "Download resource file (redirect)",
    description = "Downloads a complete resource file. Returns either a redirect to CDN URL or cached content directly. Supports both session-based and free download policies.",
    params(
        ("resid" = String, Path, description = "Resource identifier"),
        ("session" = Option<String>, Query, description = "Session ID (required for enabled download policy)")
    ),
    responses(
        (status = 200, description = "Cached content returned directly"),
        (status = 302, description = "Redirect to CDN download URL"),
        (status = 403, description = "Download not allowed", body = ErrorResponse),
        (status = 404, description = "Resource not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn download_redirect(
    Path(resid): Path<String>,
    Extension(ctx): Extension<AppContext>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 获取 session 参数
    let session_id = params.get("session").or_else(|| params.get("sid")).cloned();
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let h3_override = headers
        .get("X-DFS-Override")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match handle_download_request_unified(
        resid,
        None, // sub_path为None表示普通资源
        session_id,
        None, // range为None表示整个文件
        &ctx,
        client_ip,
        user_agent,
        h3_override,
    )
    .await
    {
        Ok(DownloadResponse::Cached {
            content,
            metadata,
            status,
        }) => {
            let headers = cached_response_headers(&metadata, status);
            Ok(crate::responses::ApiResponse::raw(content, headers))
        }
        Ok(DownloadResponse::Redirect(download_url)) => {
            Ok(crate::responses::ApiResponse::redirect(download_url))
        }
        Err(e) => Err(e),
    }
}

// POST /download/{resid} - 返回下载链接到响应体
#[utoipa::path(
    post,
    path = "/download/{resid}",
    tag = "Resource",
    summary = "Get download URL (JSON response)",
    description = "Returns download URL in JSON format instead of redirect. Supports both session-based and free download policies.",
    params(
        ("resid" = String, Path, description = "Resource identifier"),
        ("session" = Option<String>, Query, description = "Session ID (required for enabled download policy)")
    ),
    responses(
        (status = 200, description = "Download URL or cached content returned", body = DownloadUrlResponse),
        (status = 403, description = "Download not allowed", body = ErrorResponse),
        (status = 404, description = "Resource not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn download_json(
    Path(resid): Path<String>,
    Extension(ctx): Extension<AppContext>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 提取 range 参数（历史客户端支持）
    let range = params.get("range").cloned();

    // 统一从 sid 参数获取，支持历史客户端
    let session_id = {
        // 检查是否是历史客户端资源
        let config_guard = ctx.shared_config.load();
        let is_legacy_resource = config_guard
            .get_resource(&resid)
            .map(|r| r.legacy_client_support)
            .unwrap_or(false);
        let is_free = config_guard
            .get_resource(&resid)
            .map(|r| r.download == DownloadPolicy::Free)
            .unwrap_or(false);
        drop(config_guard);

        if is_legacy_resource && !is_free {
            // 历史客户端处理：sid 可能为空（第一次请求）
            let sid = params.get("sid").map(|s| s.as_str()).unwrap_or("");

            if sid.is_empty() {
                // 首次请求，使用ChallengeService生成legacy challenge并创建session
                let (validated_resid, effective_version) = ctx
                    .resource_service
                    .validate_resource_and_version(&resid, "", None)
                    .await?;
                match ctx
                    .challenge_service
                    .generate_legacy_challenge(
                        &validated_resid,
                        &effective_version,
                        None,
                        range.as_deref(),
                    )
                    .await
                {
                    Ok(challenge) => {
                        return Ok(ApiResponse::custom_status(
                            StatusCode::UNAUTHORIZED,
                            ResponseData::LegacyChallengeResponse {
                                challenge: challenge.format_data(), // 直接使用 "hash/source" 格式
                            },
                        ));
                    }
                    Err(e) => {
                        return Err(crate::error::DfsError::InternalError {
                            reason: format!("LEGACY_ERROR: {e}"),
                        });
                    }
                }
            } else {
                // 有sid，直接使用
                Some(sid.to_string())
            }
        } else {
            // 新客户端：使用 sid 参数
            params.get("sid").cloned()
        }
    };

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let h3_override = headers
        .get("X-DFS-Override")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let response_data = match handle_download_request_unified(
        resid,
        None, // sub_path为None表示普通资源
        session_id,
        range,
        &ctx,
        client_ip,
        user_agent,
        h3_override,
    )
    .await
    {
        Ok(DownloadResponse::Redirect(download_url)) => {
            ResponseData::Download { url: download_url }
        }
        Err(e) => return Err(e),
        // 移除缓存支持以保证历史客户端兼容性
        Ok(DownloadResponse::Cached { .. }) => {
            return Err(crate::error::DfsError::InvalidInput {
                field: "download_type".to_string(),
                reason: "Cached responses not supported in POST download".to_string(),
            });
        }
    };

    Ok(ApiResponse::success(response_data))
}

// GET /download/{resid}/*sub_path - 重定向到下载链接
#[utoipa::path(
    get,
    path = "/download/{resid}/{sub_path}",
    tag = "Resource",
    summary = "Download prefix resource file (redirect)",
    description = "Downloads a specific file from a prefix resource. Returns either a redirect to CDN URL or cached content directly.",
    params(
        ("resid" = String, Path, description = "Prefix resource identifier"),
        ("sub_path" = String, Path, description = "Sub-path within the prefix resource"),
        ("session" = Option<String>, Query, description = "Session ID (required for enabled download policy)")
    ),
    responses(
        (status = 200, description = "Cached content returned directly"),
        (status = 302, description = "Redirect to CDN download URL"),
        (status = 403, description = "Download not allowed", body = ErrorResponse),
        (status = 404, description = "Resource not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn download_prefix_redirect(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(ctx): Extension<AppContext>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 获取 session 参数
    let session_id = params.get("session").or_else(|| params.get("sid")).cloned();
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let h3_override = headers
        .get("X-DFS-Override")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match handle_download_request_unified(
        resid,
        Some(sub_path), // sub_path有值表示前缀资源
        session_id,
        None, // range为None表示整个文件
        &ctx,
        client_ip,
        user_agent,
        h3_override,
    )
    .await
    {
        Ok(DownloadResponse::Cached {
            content,
            metadata,
            status,
        }) => {
            let headers = cached_response_headers(&metadata, status);
            Ok(crate::responses::ApiResponse::raw(content, headers))
        }
        Ok(DownloadResponse::Redirect(download_url)) => {
            Ok(crate::responses::ApiResponse::redirect(download_url))
        }
        Err(e) => Err(e),
    }
}

// POST /download/{resid}/*sub_path - 返回下载链接到响应体
#[utoipa::path(
    post,
    path = "/download/{resid}/{sub_path}",
    tag = "Resource",
    summary = "Get prefix resource download URL (JSON response)",
    description = "Returns download URL for a specific file from a prefix resource in JSON format instead of redirect.",
    params(
        ("resid" = String, Path, description = "Prefix resource identifier"),
        ("sub_path" = String, Path, description = "Sub-path within the prefix resource"),
        ("session" = Option<String>, Query, description = "Session ID (required for enabled download policy)")
    ),
    responses(
        (status = 200, description = "Download URL or cached content returned", body = DownloadUrlResponse),
        (status = 403, description = "Download not allowed", body = ErrorResponse),
        (status = 404, description = "Resource not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn download_prefix_json(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(ctx): Extension<AppContext>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, crate::error::DfsError> {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 提取 range 参数（历史客户端支持）
    let range = params.get("range").cloned();

    // 统一从 sid 参数获取，支持历史客户端
    let session_id = {
        // 检查是否是历史客户端资源
        let config_guard = ctx.shared_config.load();
        let is_legacy_resource = config_guard
            .get_resource(&resid)
            .map(|r| r.legacy_client_support)
            .unwrap_or(false);
        let is_free = config_guard
            .get_resource(&resid)
            .map(|r| r.download == DownloadPolicy::Free)
            .unwrap_or(false);
        drop(config_guard);

        if is_legacy_resource && !is_free {
            // 历史客户端处理：sid 可能为空（第一次请求）
            let sid = params.get("sid").map(|s| s.as_str()).unwrap_or("");

            if sid.is_empty() {
                // 首次请求，使用ChallengeService生成legacy challenge并创建session
                let (validated_resid, effective_version) = ctx
                    .resource_service
                    .validate_resource_and_version(&resid, "", Some(&sub_path))
                    .await?;
                match ctx
                    .challenge_service
                    .generate_legacy_challenge(
                        &validated_resid,
                        &effective_version,
                        Some(&sub_path),
                        range.as_deref(),
                    )
                    .await
                {
                    Ok(challenge) => {
                        return Ok(ApiResponse::custom_status(
                            StatusCode::UNAUTHORIZED,
                            ResponseData::LegacyChallengeResponse {
                                challenge: challenge.format_data(), // 直接使用 "hash/source" 格式
                            },
                        ));
                    }
                    Err(e) => {
                        return Err(crate::error::DfsError::InternalError {
                            reason: format!("LEGACY_ERROR: {e}"),
                        });
                    }
                }
            } else {
                // 有sid，直接使用
                Some(sid.to_string())
            }
        } else {
            // 新客户端：使用 sid 参数
            params.get("sid").cloned()
        }
    };

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let h3_override = headers
        .get("X-DFS-Override")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let response_data = match handle_download_request_unified(
        resid,
        Some(sub_path), // sub_path有值表示前缀资源
        session_id,
        range,
        &ctx,
        client_ip,
        user_agent,
        h3_override,
    )
    .await
    {
        Ok(DownloadResponse::Redirect(download_url)) => {
            ResponseData::Download { url: download_url }
        }
        Err(e) => return Err(e),
        // 移除缓存支持以保证历史客户端兼容性
        Ok(DownloadResponse::Cached { .. }) => {
            return Err(crate::error::DfsError::InvalidInput {
                field: "download_type".to_string(),
                reason: "Cached responses not supported in POST download".to_string(),
            });
        }
    };

    Ok(ApiResponse::success(response_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::common::*;

    fn cache_metadata(src: Option<&str>) -> CacheMetadata {
        CacheMetadata {
            cached_at: 1_000,
            max_age: 300,
            content_length: 42,
            content_type: Some("application/json".to_string()),
            etag: "\"deadbeef\"".to_string(),
            src: src.map(|id| id.to_string()),
        }
    }

    #[test]
    fn cache_hit_exposes_source_node() {
        let headers = cached_response_headers(&cache_metadata(Some("iroha")), CacheStatus::Hit);
        assert_eq!(headers.get("x-dfs-cache-status").unwrap(), "hit");
        assert_eq!(headers.get("x-dfs-cache-from").unwrap(), "iroha");
        assert!(headers.get("x-cache").is_none());
    }

    #[test]
    fn freshly_filled_cache_reports_miss() {
        let headers = cached_response_headers(&cache_metadata(Some("muk")), CacheStatus::Miss);
        assert_eq!(headers.get("x-dfs-cache-status").unwrap(), "miss");
        assert_eq!(headers.get("x-dfs-cache-from").unwrap(), "muk");
    }

    #[test]
    fn entry_without_source_omits_from_header() {
        let headers = cached_response_headers(&cache_metadata(None), CacheStatus::Hit);
        assert_eq!(headers.get("x-dfs-cache-status").unwrap(), "hit");
        assert!(headers.get("x-dfs-cache-from").is_none());
    }

    #[tokio::test]
    async fn test_free_prefix_sid_reused_across_files() {
        let env = TestEnvironment::new().await;
        let sid = "folder-sticky-sid".to_string();

        let first = handle_download_request_unified(
            "free_assets".to_string(),
            Some("a/one.bin".to_string()),
            Some(sid.clone()),
            None,
            &env.app_context,
            Some("127.0.0.1".parse().unwrap()),
            None,
            None,
        )
        .await
        .expect("first file should schedule");

        let first_url = match first {
            DownloadResponse::Redirect(url) => url,
            other => panic!("expected redirect, got {other:?}"),
        };
        assert!(
            first_url.contains("/free/v1/a/one.bin") || first_url.contains("a/one.bin"),
            "first URL should use request path: {first_url}"
        );

        let penalties = env
            .services
            .session_service
            .get_schedule_penalties(&sid, Some("b/two.bin:0-"))
            .await
            .unwrap();
        assert!(
            penalties.banned.is_empty(),
            "first assignment is not a retry"
        );
        assert!(
            !penalties.demoted.is_empty(),
            "first file should demote its server for later spreading"
        );

        let second = handle_download_request_unified(
            "free_assets".to_string(),
            Some("b/two.bin".to_string()),
            Some(sid.clone()),
            None,
            &env.app_context,
            Some("127.0.0.1".parse().unwrap()),
            None,
            None,
        )
        .await
        .expect("same sid must work for a second file in the folder");

        let second_url = match second {
            DownloadResponse::Redirect(url) => url,
            other => panic!("expected redirect, got {other:?}"),
        };
        assert!(
            second_url.contains("/free/v1/b/two.bin") || second_url.contains("b/two.bin"),
            "second URL should follow the new request path: {second_url}"
        );

        let stored = env.data_store.get_session(&sid).await.unwrap().unwrap();
        assert_eq!(stored.resource_id, "free_assets");
        assert_eq!(stored.sub_path, None);
    }

    #[tokio::test]
    async fn test_free_sid_rejects_different_resource() {
        let env = TestEnvironment::new().await;
        let sid = "cross-resource-sid".to_string();

        handle_download_request_unified(
            "free_assets".to_string(),
            Some("a/one.bin".to_string()),
            Some(sid.clone()),
            None,
            &env.app_context,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let err = handle_download_request_unified(
            "free_other".to_string(),
            None,
            Some(sid),
            None,
            &env.app_context,
            None,
            None,
            None,
        )
        .await
        .expect_err("sid must not move to another resource");

        match err {
            DfsError::DownloadNotAllowed { reason, .. } => {
                assert!(reason.contains("already associated"));
            }
            other => panic!("expected download_not_allowed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_enabled_download_rejects_other_file() {
        let env = TestEnvironment::new().await;
        let sid = "enabled-bound-file";

        env.services
            .challenge_service
            .generate_and_store_challenge(sid, "game_assets", Some("a/one.bin"))
            .await
            .unwrap();
        let stored = env.data_store.get_challenge(sid).await.unwrap().unwrap();
        let challenge_json: serde_json::Value = serde_json::from_str(&stored).unwrap();
        let original_data = hex::decode(challenge_json["original_data"].as_str().unwrap()).unwrap();
        let answer = format!("{:x}", md5::compute(&original_data));

        crate::routes::resource::sessions::handle_create_session_unified(
            "game_assets".to_string(),
            Some("a/one.bin".to_string()),
            env.app_context.clone(),
            crate::models::CreateSessionRequest {
                version: "3.0.0".to_string(),
                chunks: vec!["0-".to_string()],
                sid: sid.to_string(),
                challenge: answer,
                extras: serde_json::json!({}),
            },
        )
        .await
        .unwrap();

        let err = handle_download_request_unified(
            "game_assets".to_string(),
            Some("b/two.bin".to_string()),
            Some(sid.to_string()),
            None,
            &env.app_context,
            None,
            None,
            None,
        )
        .await
        .expect_err("enabled session must not download another file");

        match err {
            DfsError::DownloadNotAllowed { reason, .. } => {
                assert!(reason.contains("different file"));
            }
            other => panic!("expected bound-to-file error, got {other:?}"),
        }
    }
}
