use axum::{
    extract::{Extension, Path, Query}, http::{HeaderMap, StatusCode}, response::{IntoResponse, Redirect}, Json
};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

use crate::{error::DfsResult, modules::storage::cache::download_and_cache, responses::{ApiResponse, DownloadUrlResponse, ErrorResponse, ResponseData}};
use crate::{
    config::DownloadPolicy,
    error::DfsError,
    modules::{
        network::RealConnectInfo,
        storage::{cache::should_cache_content, data_store::BandwidthUpdateBatch},
    },
    routes::resource::{calculate_actual_bytes_from_range, parse_range_for_flow},
};
use crate::{container::AppContext, modules::storage::data_store::CacheMetadata};

// 下载响应类型
#[derive(Debug)]
pub enum DownloadResponse {
    Cached {
        content: Vec<u8>,
        metadata: CacheMetadata,
    },
    Redirect(String),
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
) -> DfsResult<DownloadResponse> {
    let config_guard = ctx.shared_config.load();

    // 统一资源验证：使用ResourceService验证资源存在性和类型
    let (validated_resid, effective_version) = ctx
        .resource_service
        .validate_resource_and_version(&resid, "", sub_path.as_deref())
        .await?;

    let resource_config = config_guard.get_resource(&validated_resid).unwrap(); // 已验证存在

    // 保存原始 session_id 用于后续销毁
    let original_session_id = session_id.clone();

    // 提取 extras 信息和session对象用于 Flow 规则
    let (extras, enabled_session) = match &resource_config.download {
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

            // 验证 chunks：比较请求的 range 与 session chunks 是否一致
            if let Some(requested_range) = &range {
                // 请求带有 range 参数，检查 session 是否包含对应的 range
                if !session.chunks.contains(requested_range) {
                    return Err(DfsError::download_not_allowed(
                        &resid,
                        &format!("session does not allow range '{}'", requested_range),
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
    let version: String = ctx.resource_service.get_effective_version(&resid).await;
    let path = ctx
        .resource_service
        .get_version_path(&resid, &version, None, sub_path.as_deref())
        .ok_or_else(|| DfsError::path_not_found(&resid, &version))?;

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
                // 缓存命中！记录缓存命中日志
                if matches!(resource_config.download, DownloadPolicy::Free) {
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
                                metadata.content_length,
                                metadata.max_age,
                                &metadata.etag,
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

                // 记录缓存命中的调度请求 - 没有实际调度到服务器
                ctx.metrics
                    .record_scheduled_request(&resid, server_id, true);

                let cache_debug_msg = if sub_path.is_some() {
                    format!(
                        "Prefix cache hit: file_size={}, resource_id={}, server_id={}, sub_path={:?}",
                        file_size, resid, server_id, sub_path
                    )
                } else {
                    format!(
                        "Cache hit: file_size={}, resource_id={}, server_id={}",
                        file_size, resid, server_id
                    )
                };
                debug!("{}", cache_debug_msg);

                return Ok(DownloadResponse::Cached { content, metadata });
            }
        }
    }

    // 缓存未命中，需要进行实际的服务器调度
    // 从flow配置中提取服务器列表来获取文件大小（用于Size条件评估）
    let servers_from_flow: Vec<String> = resource_config.flow
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
    
    debug!("Starting file size detection for path: {}, servers from flow: {:?}", path, servers_from_flow);
    let file_size = {
        let mut size_candidate = None;
        for server_id in &servers_from_flow {
            debug!("Checking health info for server: {}, path: {}", server_id, path);
            match ctx.data_store.get_health_info(server_id, &path).await {
                Ok(Some(health_info)) => {
                    debug!("Health info found for server {}: file_size={:?}, is_alive={}", 
                           server_id, health_info.file_size, health_info.is_alive);
                    if let Some(size) = health_info.file_size {
                        size_candidate = Some(size);
                        debug!("File size detected: {} bytes from server {}", size, server_id);
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
        debug!("Range request detected: {:?}, calculated size: {:?}", ranges, range_size);
        range_size
    } else {
        // 如果没有range请求，使用完整文件大小
        debug!("No range request, using full file size: {:?}", file_size);
        file_size
    };
    debug!("Final request_file_size for flow evaluation: {:?}", request_file_size);

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
    };

    let options = crate::models::FlowOptions {
        cdn_full_range: resource_config.legacy_client_full_range
            && resource_config.legacy_client_support, // 历史客户端全范围模式
    };

    let flow_list = &resource_config.flow;
    let flow_result = if let (Some(sid), Some(session)) = (&original_session_id, &enabled_session) {
        // Enabled模式：有session，使用SessionService统一处理
        let requested_ranges = parsed_ranges.unwrap_or_default();
        ctx.session_service
            .run_flow_for_session(
                session,
                sid,
                requested_ranges,
                &ctx.flow_service,
                client_ip,
                request_file_size,
                flow_list,
            )
            .await
            .map_err(|e| {
                error!("Failed to run flow for session in download: {}", e);
                DfsError::internal_error(format!("Failed to generate download URL: {}", e))
            })?
    } else {
        // Free模式：无session，直接使用FlowService
        ctx.flow_service
            .execute_flow(
                &target,
                &context,
                &options,
                flow_list,
                vec![], // penalty_servers for direct download
            )
            .await
            .map_err(|e| {
                error!("Failed to run flow for download: {}", e);
                DfsError::internal_error(format!("Failed to generate download URL: {}", e))
            })?
    };
    let cdn_url = flow_result.url;

    // 记录调度结果日志
    let resource_path = if let Some(ref sub_path_val) = sub_path {
        format!("{}/{}", resid, sub_path_val)
    } else {
        resid.clone()
    };
    let file_size_mb = request_file_size.map(|size| size as f64 / 1024.0 / 1024.0).unwrap_or(0.0);
    info!("{} size={:.2}MB -> {} weight={}", 
          resource_path, 
          file_size_mb,
          flow_result.selected_server_id.as_deref().unwrap_or("unknown"),
          flow_result.selected_server_weight.unwrap_or(0));

    // 检查是否应该缓存
    let cached_result = if let Some((file_size, max_age)) = should_cache_content(
        &config_guard,
        &ctx.data_store,
        &resid,
        sub_path.as_deref(), // 传入子路径用于模式匹配
        flow_result
            .selected_server_id
            .as_deref()
            .unwrap_or("unknown"),
        &path,
    )
    .await
    {
        if file_size < 100 * 1024 {
            // 100KB限制
            // 下载并缓存
            download_and_cache(&cdn_url, &resid, &version, &path, &ctx.data_store, max_age)
                .await
                .ok()
        } else {
            None
        }
    } else {
        None
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

    // 如果是 enabled 模式且有 session，记录日志并销毁 session
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

            if let Err(e) = ctx.session_service.remove_session(sid).await {
                let session_type = if sub_path.is_some() {
                    "session after prefix download"
                } else {
                    "session after download"
                };
                warn!("Failed to remove {}: {}", session_type, e);
            } else {
                let session_type = if sub_path.is_some() {
                    "prefix download"
                } else {
                    "download"
                };
                info!("Session {} destroyed after {}", sid, session_type);
            }
        }
    }

    // 更新流量统计（在成功生成下载URL后）
    if let Some(server_id) = &flow_result.selected_server_id {
        // 尝试从健康检查缓存获取文件大小
        if let Ok(Some(health_info)) = ctx.data_store.get_health_info(server_id, &path).await {
            if let Some(full_file_size) = health_info.file_size {
                // 根据range计算实际传输字节数
                let actual_bytes =
                    calculate_actual_bytes_from_range(range.as_deref(), full_file_size);

                // 使用批量更新接口同时更新资源、服务器和全局流量统计
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
                        "Failed to update bandwidth for {} {}: {}",
                        server_type, server_id, e
                    );
                } else {
                    // 记录成功的调度请求（非缓存）
                    ctx.metrics
                        .record_scheduled_request(&resid, server_id, false);
                }

                let debug_msg = if sub_path.is_some() {
                    format!(
                        "Updated prefix download bandwidth stats: actual_bytes={}, full_file_size={}, range={:?}, server_id={}, session_id={:?}",
                        actual_bytes, full_file_size, range, server_id, original_session_id
                    )
                } else {
                    format!(
                        "Updated bandwidth stats: actual_bytes={}, full_file_size={}, range={:?}, resource_id={}, server_id={}",
                        actual_bytes, full_file_size, range, resid, server_id
                    )
                };
                debug!("{}", debug_msg);
            }
        }
    }

    // 如果有缓存结果，返回缓存内容
    if let Some((metadata, content)) = cached_result {
        return Ok(DownloadResponse::Cached { content, metadata });
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
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 获取 session 参数
    let session_id = params.get("session").map(|s| s.clone());
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match handle_download_request_unified(
        resid, None, // sub_path为None表示普通资源
        session_id, None, // range为None表示整个文件
        &ctx, client_ip, user_agent,
    )
    .await
    {
        Ok(DownloadResponse::Cached { content, metadata }) => {
            let remaining_max_age = metadata.remaining_max_age();

            let mut headers = HeaderMap::new();
            headers.insert(
                "cache-control",
                format!("public, max-age={}", remaining_max_age)
                    .parse()
                    .unwrap(),
            );
            headers.insert("etag", metadata.etag.parse().unwrap());
            headers.insert("x-cache", "HIT".parse().unwrap());
            headers.insert(
                "content-length",
                metadata.content_length.to_string().parse().unwrap(),
            );

            if let Some(ct) = metadata.content_type {
                headers.insert("content-type", ct.parse().unwrap());
            } else {
                headers.insert("content-type", "application/octet-stream".parse().unwrap());
            }

            (StatusCode::OK, headers, content).into_response()
        }
        Ok(DownloadResponse::Redirect(download_url)) => {
            Redirect::temporary(&download_url).into_response()
        }
        Err(e) => {
            let status_code = StatusCode::from_u16(e.http_status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status_code, Json(ApiResponse::error(e.to_string()))).into_response()
        }
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
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 提取 range 参数（历史客户端支持）
    let range = params.get("range").map(|s| s.clone());

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
                match ctx.challenge_service
                    .generate_legacy_challenge(&resid, range.as_deref())
                    .await
                {
                    Ok(challenge) => {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(ApiResponse::success(
                                ResponseData::LegacyChallengeResponse {
                                    challenge: challenge.format_data(), // 直接使用 "hash/source" 格式
                                },
                            )),
                        );
                    }
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse::error(format!(
                                "LEGACY_ERROR: {}",
                                e.to_string()
                            ))),
                        );
                    }
                }
            } else {
                // 有sid，直接使用
                Some(sid.to_string())
            }
        } else {
            // 新客户端：使用 sid 参数
            params.get("sid").map(|s| s.clone())
        }
    };

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match handle_download_request_unified(
        resid, None, // sub_path为None表示普通资源
        session_id, range, &ctx, client_ip, user_agent,
    )
    .await
    {
        Ok(DownloadResponse::Redirect(download_url)) => (
            StatusCode::OK,
            Json(ApiResponse::success(ResponseData::Download {
                url: download_url,
            })),
        ),
        Err(e) => {
            let status_code = StatusCode::from_u16(e.http_status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status_code, Json(ApiResponse::error(e.to_string())))
        }
        // 移除缓存支持以保证历史客户端兼容性
        Ok(DownloadResponse::Cached { .. }) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(
                "Cached responses not supported in POST download".to_string(),
            )),
        ),
    }
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
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 获取 session 参数
    let session_id = params.get("session").map(|s| s.clone());
    let user_agent = headers
        .get("user-agent")
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
    )
    .await
    {
        Ok(DownloadResponse::Cached { content, metadata }) => {
            let remaining_max_age = metadata.remaining_max_age();

            let mut headers = HeaderMap::new();
            headers.insert(
                "cache-control",
                format!("public, max-age={}", remaining_max_age)
                    .parse()
                    .unwrap(),
            );
            headers.insert("etag", metadata.etag.parse().unwrap());
            headers.insert("x-cache", "HIT".parse().unwrap());
            headers.insert(
                "content-length",
                metadata.content_length.to_string().parse().unwrap(),
            );

            if let Some(ct) = metadata.content_type {
                headers.insert("content-type", ct.parse().unwrap());
            } else {
                headers.insert("content-type", "application/octet-stream".parse().unwrap());
            }

            (StatusCode::OK, headers, content).into_response()
        }
        Ok(DownloadResponse::Redirect(download_url)) => {
            Redirect::temporary(&download_url).into_response()
        }
        Err(e) => {
            let status_code = StatusCode::from_u16(e.http_status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status_code, Json(ApiResponse::error(e.to_string()))).into_response()
        }
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
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 提取 range 参数（历史客户端支持）
    let range = params.get("range").map(|s| s.clone());

    // 统一从 sid 参数获取，支持历史客户端
    let session_id = {
        // 检查是否是历史客户端资源
        let config_guard = ctx.shared_config.load();
        let is_legacy_resource = config_guard
            .get_resource(&resid)
            .map(|r| r.legacy_client_support)
            .unwrap_or(false);
        drop(config_guard);

        if is_legacy_resource {
            // 历史客户端处理：sid 可能为空（第一次请求）
            let sid = params.get("sid").map(|s| s.as_str()).unwrap_or("");

            if sid.is_empty() {
                // 首次请求，使用ChallengeService生成legacy challenge并创建session
                match ctx.challenge_service
                    .generate_legacy_challenge(&resid, range.as_deref())
                    .await
                {
                    Ok(challenge) => {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(ApiResponse::success(
                                ResponseData::LegacyChallengeResponse {
                                    challenge: challenge.format_data(), // 直接使用 "hash/source" 格式
                                },
                            )),
                        );
                    }
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse::error(format!(
                                "LEGACY_ERROR: {}",
                                e.to_string()
                            ))),
                        );
                    }
                }
            } else {
                // 有sid，直接使用
                Some(sid.to_string())
            }
        } else {
            // 新客户端：使用 sid 参数
            params.get("sid").map(|s| s.clone())
        }
    };

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match handle_download_request_unified(
        resid,
        Some(sub_path), // sub_path有值表示前缀资源
        session_id,
        range,
        &ctx,
        client_ip,
        user_agent,
    )
    .await
    {
        Ok(DownloadResponse::Redirect(download_url)) => (
            StatusCode::OK,
            Json(ApiResponse::success(ResponseData::Download {
                url: download_url,
            })),
        ),
        Err(e) => {
            let status_code = StatusCode::from_u16(e.http_status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status_code, Json(ApiResponse::error(e.to_string())))
        }
        // 移除缓存支持以保证历史客户端兼容性
        Ok(DownloadResponse::Cached { .. }) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(
                "Cached responses not supported in POST download".to_string(),
            )),
        ),
    }
}
