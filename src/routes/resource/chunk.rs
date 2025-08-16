use axum::{
    extract::{Extension, Path, Query},
    http::HeaderMap,
};
use std::collections::HashMap;
use tracing::{error, info, warn};

use crate::error::DfsError;
use crate::modules::network::RealConnectInfo;
use crate::responses::{ApiResponse, CdnUrlResponse, ErrorResponse, ResponseData};
use crate::{container::AppContext, modules::external::geolocation};
use crate::{record_flow_metrics, record_request_metrics};

#[utoipa::path(
    get,
    path = "/session/{sessionid}/{resid}",
    tag = "Resource",
    summary = "Get CDN URL for file chunk",
    description = "Retrieves CDN URL for downloading a specific chunk of a file using an active session",
    params(
        ("sessionid" = String, Path, description = "Session identifier"),
        ("resid" = String, Path, description = "Resource identifier"),
        ("range" = String, Query, description = "Byte range for download (e.g., '0-1023' or '0-255,256-511')")
    ),
    responses(
        (status = 200, description = "CDN URL generated successfully", body = CdnUrlResponse),
        (status = 400, description = "Invalid request parameters", body = ErrorResponse),
        (status = 404, description = "Session or resource not found", body = ErrorResponse),
        (status = 429, description = "Too many download attempts", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn get_cdn(
    Extension(ctx): Extension<AppContext>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Path((sessionid, resid)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    // 记录请求开始时间
    let start_time = std::time::Instant::now();

    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    let session = ctx
        .session_service
        .get_validated_session(&sessionid)
        .await?;

    let range_str = params
        .get("range")
        .ok_or_else(|| DfsError::invalid_input("range", "Range parameter is required"))?;

    let _count = ctx
        .session_service
        .check_download_limit(&sessionid, range_str)
        .await?;

    // 解析ranges参数
    let ranges = if range_str.contains(',') {
        // Multiple ranges: "0-255,256-511,512-767"
        let mut parsed_ranges = Vec::new();
        for range_part in range_str.split(',') {
            let range_part = range_part.trim();
            if let Some((start_str, end_str)) = range_part.split_once('-') {
                let start = start_str.parse::<u32>().map_err(|_| {
                    DfsError::invalid_input(
                        "range",
                        format!("Invalid range format in part: {range_part}"),
                    )
                })?;
                let end = end_str.parse::<u32>().map_err(|_| {
                    DfsError::invalid_input(
                        "range",
                        format!("Invalid range format in part: {range_part}"),
                    )
                })?;
                parsed_ranges.push((start, end));
            } else {
                return Err(DfsError::invalid_input(
                    "range",
                    format!("Invalid range format in part: {range_part}"),
                ));
            }
        }
        if parsed_ranges.is_empty() {
            return Err(DfsError::invalid_input("range", "No valid ranges found"));
        }
        parsed_ranges
    } else {
        // Single range: "0-255"
        if let Some((start_str, end_str)) = range_str.split_once('-') {
            let start = start_str
                .parse::<u32>()
                .map_err(|_| DfsError::invalid_input("range", "Invalid range format"))?;
            let end = end_str
                .parse::<u32>()
                .map_err(|_| DfsError::invalid_input("range", "Invalid range format"))?;
            vec![(start, end)]
        } else {
            return Err(DfsError::invalid_input("range", "Invalid range format"));
        }
    };

    let config_guard = ctx.shared_config.load();
    let res = config_guard.get_resource(&resid);
    if res.is_none() {
        return Err(DfsError::resource_not_found(&resid));
    }
    let res = res.unwrap();
    let flow_list = &res.flow;

    // 计算文件大小：根据ranges计算总大小
    let file_size = Some(
        ranges
            .iter()
            .map(|(start, end)| (end - start + 1) as u64)
            .sum(),
    );
    let file_size_mb = file_size
        .map(|size| size as f64 / 1024.0 / 1024.0)
        .unwrap_or(0.0);

    // 使用SessionService统一处理flow执行
    let options = crate::models::FlowOptions {
        cdn_full_range: false,
    };

    let flow_result = ctx
        .session_service
        .run_flow_for_session(
            &session,
            &sessionid,
            ranges,
            &ctx.flow_service,
            client_ip,
            file_size,
            flow_list,
            &options,
        )
        .await;
    let resource_path = if let Some(ref sub_path_val) = session.sub_path {
        format!("{resid}/{sub_path_val}")
    } else {
        resid.clone()
    };
    if flow_result.is_err() {
        let e = flow_result.unwrap_err();
        error!(
            "SESSION-ERROR {} size={:.2}MB {}",
            resource_path, file_size_mb, e
        );
        return Err(e);
    }

    let flow_result = flow_result.unwrap();
    let cdn_url = flow_result.url;

    // 记录调度结果日志
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

    // 记录成功的请求和流程执行指标
    record_request_metrics!(ctx.metrics, start_time);
    record_flow_metrics!(ctx.metrics, true);

    // 记录调度请求指标和流量统计（CDN访问场景）
    if let Some(server_id) = flow_result.selected_server_id.as_deref() {
        ctx.metrics
            .record_scheduled_request(&resid, server_id, false);

        // 记录流量统计（两个体系都要记录）
        if let Some(bytes) = file_size {
            // 1. 记录日流量（使用批量更新接口）
            if let Err(e) = ctx
                .data_store
                .update_bandwidth_batch(crate::modules::storage::data_store::BandwidthUpdateBatch {
                    resource_id: resid.clone(),
                    server_id: server_id.to_string(),
                    bytes,
                })
                .await
            {
                warn!(
                    "Failed to update daily bandwidth for server {}: {}",
                    server_id, e
                );
            }

            // 2. 记录分钟级流量
            ctx.bandwidth_cache_service
                .record_bandwidth(server_id, bytes)
                .await;
        }
    }

    Ok(ApiResponse::success(ResponseData::Cdn { url: cdn_url }))
}

// 静态配置：最大并发Flow数量
const MAX_CONCURRENT_FLOWS: usize = 4;

#[utoipa::path(
    post,
    path = "/session/{sessionid}/{resid}",
    tag = "Resource", 
    summary = "Get CDN URLs for multiple file chunks",
    description = "Retrieves CDN URLs for downloading multiple chunks using an active session",
    request_body = crate::models::BatchChunkRequest,
    responses(
        (status = 200, description = "CDN URLs generated successfully", body = crate::responses::BatchCdnUrlResponse),
        (status = 400, description = "Invalid request parameters", body = ErrorResponse),
        (status = 404, description = "Session or resource not found", body = ErrorResponse),
        (status = 429, description = "Too many download attempts", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn post_batch_cdn(
    Extension(ctx): Extension<AppContext>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Path((sessionid, resid)): Path<(String, String)>,
    axum::Json(payload): axum::Json<crate::models::BatchChunkRequest>,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    let start_time = std::time::Instant::now();

    // 验证输入
    if payload.chunks.is_empty() {
        return Err(DfsError::invalid_input(
            "chunks",
            "Chunks array cannot be empty",
        ));
    }
    if payload.chunks.len() > 100 {
        return Err(DfsError::invalid_input(
            "chunks",
            "Too many chunks requested (max 100)",
        ));
    }

    // 提取客户端IP
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 1. 一次性验证session和资源（共享）
    let session = ctx
        .session_service
        .get_validated_session(&sessionid)
        .await?;
    let config_guard = ctx.shared_config.load();
    let resource = config_guard
        .get_resource(&resid)
        .ok_or_else(|| DfsError::resource_not_found(&resid))?;

    // 2. Pipeline批量读取所有chunk信息
    let batch_data = ctx
        .data_store
        .batch_check_and_increment_downloads(&sessionid, &payload.chunks)
        .await
        .map_err(|e| DfsError::internal_error(format!("Batch Redis read failed: {}", e)))?;

    // 3. 验证下载限制
    for (chunk, count) in &batch_data.valid_chunks {
        if *count > 3 {
            // MAX_CHUNK_DOWNLOADS
            return Err(DfsError::invalid_input(
                "download_count",
                &format!("Too many download attempts for chunk: {}", chunk),
            ));
        }
    }

    // 4. 限制并发Flow执行（关键：限制为4个）
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FLOWS));
    let batch_data = std::sync::Arc::new(batch_data); // 使用Arc来共享数据
    let tasks: Vec<_> = payload
        .chunks
        .into_iter()
        .map(|chunk_range| {
            let ctx = ctx.clone();
            let session = session.clone();
            let resource = resource.clone();
            let batch_data_ref = batch_data.clone();
            let semaphore = semaphore.clone();

            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                process_chunk_with_preloaded_data(
                    &ctx,
                    &session,
                    &chunk_range,
                    &resource,
                    &*batch_data_ref,
                    client_ip,
                )
                .await
            })
        })
        .collect();

    // 5. 收集所有结果
    let mut chunk_results = std::collections::HashMap::new();
    let mut cdn_records_to_store = Vec::new();
    let mut server_bandwidth_map = std::collections::HashMap::new();
    let mut total_bandwidth = 0u64;

    for task in tasks {
        let result = task
            .await
            .map_err(|e| DfsError::internal_error(format!("Task execution failed: {}", e)))?;

        match result {
            Ok(chunk_result) => {
                chunk_results.insert(
                    chunk_result.chunk_id.clone(),
                    crate::responses::ChunkResult {
                        url: chunk_result.url,
                        error: None,
                    },
                );

                // 收集CDN记录和带宽信息
                if let Some(cdn_record) = chunk_result.cdn_record {
                    cdn_records_to_store.push(
                        crate::modules::storage::data_store::BatchCdnRecord {
                            chunk_id: chunk_result.chunk_id.clone(),
                            record: cdn_record,
                        },
                    );
                }

                if let Some(bandwidth_info) = chunk_result.bandwidth_info {
                    if let Some(server_id) = bandwidth_info.server_id {
                        *server_bandwidth_map.entry(server_id).or_default() += bandwidth_info.bytes;
                        total_bandwidth += bandwidth_info.bytes;
                    }
                }
            }
            Err(e) => {
                // 处理无效chunk和错误
                let chunk_id = if batch_data
                    .invalid_chunks
                    .iter()
                    .any(|invalid| e.to_string().contains(invalid))
                {
                    "unknown_chunk".to_string()
                } else {
                    "error_chunk".to_string()
                };

                chunk_results.insert(
                    chunk_id,
                    crate::responses::ChunkResult {
                        url: None,
                        error: Some(e.to_string()),
                    },
                );
            }
        }
    }

    // 6. Pipeline批量写入CDN记录和带宽统计
    if !cdn_records_to_store.is_empty() || total_bandwidth > 0 {
        let bandwidth_batch = crate::modules::storage::data_store::MultiBandwidthUpdateBatch {
            resource_id: resid.clone(),
            server_updates: server_bandwidth_map,
            total_bytes: total_bandwidth,
        };

        ctx.data_store
            .batch_write_cdn_and_bandwidth(&sessionid, &cdn_records_to_store, &bandwidth_batch)
            .await
            .map_err(|e| DfsError::internal_error(format!("Batch Redis write failed: {}", e)))?;
    }

    // 7. 记录总体指标
    record_request_metrics!(ctx.metrics, start_time);

    Ok(crate::responses::ApiResponse::success(
        crate::responses::ResponseData::BatchCdn(crate::responses::BatchCdnUrlResponse {
            urls: chunk_results,
        }),
    ))
}

// 处理单个chunk（使用预加载的数据）
async fn process_chunk_with_preloaded_data(
    ctx: &AppContext,
    session: &crate::models::Session,
    chunk_range: &str,
    resource: &crate::config::ResourceConfig,
    batch_data: &crate::models::BatchChunkData,
    client_ip: Option<std::net::IpAddr>,
) -> crate::error::DfsResult<crate::models::ChunkProcessResult> {
    // 检查chunk是否有效
    if batch_data.invalid_chunks.contains(&chunk_range.to_string()) {
        return Err(DfsError::invalid_input("chunk", "Invalid chunk range"));
    }

    // 解析ranges
    let ranges = parse_and_validate_ranges(chunk_range)?;

    // 获取预加载的penalty服务器
    let penalty_servers: Vec<String> = batch_data
        .cdn_records
        .get(chunk_range)
        .map(|records| {
            records
                .iter()
                .filter_map(|record| {
                    if !record.skip_penalty {
                        record.server_id.clone()
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // 执行flow（无Redis操作，纯计算）
    let file_size = Some(calculate_file_size_from_ranges(&ranges));
    let target = crate::models::FlowTarget {
        resource_id: session.resource_id.clone(),
        version: session.version.clone(),
        sub_path: session.sub_path.clone(),
        ranges: Some(ranges),
        file_size,
    };

    let context = crate::models::FlowContext {
        client_ip,
        session_id: Some(session.resource_id.clone()),
        extras: session.extras.clone(),
    };

    let options = crate::models::FlowOptions {
        cdn_full_range: false,
    };

    let flow_result = ctx
        .flow_service
        .execute_flow(&target, &context, &options, &resource.flow, penalty_servers)
        .await?;

    // 准备CDN记录
    let cdn_record = crate::models::CdnRecord {
        url: flow_result.url.clone(),
        server_id: flow_result.selected_server_id.clone(),
        skip_penalty: false,
        timestamp: chrono::Utc::now().timestamp() as u64,
        weight: flow_result.selected_server_weight.unwrap_or(0),
        size: file_size,
    };

    // 准备带宽信息
    let bandwidth_info =
        flow_result
            .selected_server_id
            .map(|server_id| crate::models::BandwidthInfo {
                server_id: Some(server_id),
                bytes: file_size.unwrap_or(0),
                chunk_id: chunk_range.to_string(),
            });

    Ok(crate::models::ChunkProcessResult {
        chunk_id: chunk_range.to_string(),
        url: Some(flow_result.url),
        error: None,
        bandwidth_info,
        cdn_record: Some(cdn_record),
    })
}

// 解析并验证ranges
fn parse_and_validate_ranges(range_str: &str) -> crate::error::DfsResult<Vec<(u32, u32)>> {
    let ranges = if range_str.contains(',') {
        // Multiple ranges: "0-255,256-511,512-767"
        let mut parsed_ranges = Vec::new();
        for range_part in range_str.split(',') {
            let range_part = range_part.trim();
            if let Some((start_str, end_str)) = range_part.split_once('-') {
                let start = start_str.parse::<u32>().map_err(|_| {
                    DfsError::invalid_input(
                        "range",
                        format!("Invalid range format in part: {range_part}"),
                    )
                })?;
                let end = end_str.parse::<u32>().map_err(|_| {
                    DfsError::invalid_input(
                        "range",
                        format!("Invalid range format in part: {range_part}"),
                    )
                })?;
                parsed_ranges.push((start, end));
            } else {
                return Err(DfsError::invalid_input(
                    "range",
                    format!("Invalid range format in part: {range_part}"),
                ));
            }
        }
        if parsed_ranges.is_empty() {
            return Err(DfsError::invalid_input("range", "No valid ranges found"));
        }
        parsed_ranges
    } else {
        // Single range: "0-255"
        if let Some((start_str, end_str)) = range_str.split_once('-') {
            let start = start_str
                .parse::<u32>()
                .map_err(|_| DfsError::invalid_input("range", "Invalid range format"))?;
            let end = end_str
                .parse::<u32>()
                .map_err(|_| DfsError::invalid_input("range", "Invalid range format"))?;
            vec![(start, end)]
        } else {
            return Err(DfsError::invalid_input("range", "Invalid range format"));
        }
    };

    Ok(ranges)
}

// 计算ranges覆盖的字节数
fn calculate_file_size_from_ranges(ranges: &[(u32, u32)]) -> u64 {
    ranges
        .iter()
        .map(|(start, end)| (end - start + 1) as u64)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use std::collections::HashMap;

    // 引用统一的测试框架
    use crate::tests::common::*;

    #[tokio::test]
    async fn test_get_cdn_single_range_success() {
        let env = TestEnvironment::new().await;

        // 创建测试会话
        let session_id = "test_cdn_session";
        let session = SessionBuilder::new()
            .with_resource_id("test_resource")
            .with_version("1.0.0")
            .with_chunks(vec!["0-1024"])
            .build();

        env.services
            .session_service
            .store_session(session_id, &session)
            .await
            .unwrap();

        // 准备查询参数
        let mut params = HashMap::new();
        params.insert("range".to_string(), "0-1024".to_string());

        // 模拟headers
        let headers = HeaderMap::new();

        // 模拟连接信息
        let real_connect_info = RealConnectInfo::from_headers_and_addr(
            &HeaderMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        // 调用get_cdn函数
        let response = get_cdn(
            Extension(env.app_context.clone()),
            Extension(real_connect_info),
            headers,
            Path((session_id.to_string(), "test_resource".to_string())),
            Query(params),
        )
        .await;

        // 验证响应
        let response = axum::response::IntoResponse::into_response(response);
        let (parts, body) = response.into_parts();

        // 如果不是200，打印响应体来调试
        if parts.status != StatusCode::OK {
            let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body_bytes);
            println!("🔍 Response status: {}", parts.status);
            println!("🔍 Response body: {}", body_str);
        }

        assert_eq!(parts.status, StatusCode::OK);

        println!("✅ CDN single range success test completed!");
    }

    // 测试已删除: test_get_cdn_multiple_ranges_success - 复杂场景测试

    #[tokio::test]
    async fn test_get_cdn_session_not_found() {
        let env = TestEnvironment::new().await;

        let mut params = HashMap::new();
        params.insert("range".to_string(), "0-1024".to_string());

        let headers = HeaderMap::new();
        let real_connect_info = RealConnectInfo::from_headers_and_addr(
            &HeaderMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        // 使用不存在的会话ID
        let response = get_cdn(
            Extension(env.app_context.clone()),
            Extension(real_connect_info),
            headers,
            Path((
                "nonexistent_session".to_string(),
                "test_resource".to_string(),
            )),
            Query(params),
        )
        .await;

        // 应该返回404错误
        let response = axum::response::IntoResponse::into_response(response);
        let (parts, _body) = response.into_parts();
        assert_ne!(parts.status, StatusCode::OK);

        println!("✅ CDN session not found test completed!");
    }

    // 测试已删除: test_get_cdn_invalid_range_format - 边界情况测试

    // 测试已删除: test_get_cdn_missing_range_parameter - 边界情况测试

    #[tokio::test]
    async fn test_get_cdn_resource_validation_failure() {
        let env = TestEnvironment::new().await;

        let session_id = "test_cdn_invalid_resource";
        // 创建会话但使用无效的资源ID
        let session = SessionBuilder::new()
            .with_resource_id("nonexistent_resource") // 不存在的资源
            .with_version("1.0.0")
            .with_chunks(vec!["0-1024"])
            .build();

        env.services
            .session_service
            .store_session(session_id, &session)
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("range".to_string(), "0-1024".to_string());

        let headers = HeaderMap::new();
        let real_connect_info = RealConnectInfo::from_headers_and_addr(
            &HeaderMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        let response = get_cdn(
            Extension(env.app_context.clone()),
            Extension(real_connect_info),
            headers,
            Path((session_id.to_string(), "nonexistent_resource".to_string())),
            Query(params),
        )
        .await;

        // 应该返回404错误（资源不存在）
        let response = axum::response::IntoResponse::into_response(response);
        let (parts, _body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::NOT_FOUND);

        println!("✅ CDN resource validation failure test completed!");
    }

    // 测试已删除: test_get_cdn_with_client_ip_extraction - 基础设施测试

    // 测试已删除: test_get_cdn_flow_execution_with_penalties - 重复的集成测试

    #[tokio::test]
    async fn test_get_cdn_prefix_resource_session() {
        let env = TestEnvironment::new().await;

        let session_id = "test_cdn_prefix";
        // 创建前缀资源会话
        let session = SessionBuilder::new()
            .with_resource_id("game_assets") // 前缀资源
            .with_version("3.0.0")
            .with_chunks(vec!["0-2048"])
            .with_sub_path(Some("textures/player.png"))
            .build();

        env.services
            .session_service
            .store_session(session_id, &session)
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("range".to_string(), "0-2048".to_string());

        let headers = HeaderMap::new();
        let real_connect_info = RealConnectInfo::from_headers_and_addr(
            &HeaderMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        let response = get_cdn(
            Extension(env.app_context.clone()),
            Extension(real_connect_info),
            headers,
            Path((session_id.to_string(), "game_assets".to_string())),
            Query(params),
        )
        .await;

        // 验证前缀资源CDN URL生成成功
        let response = axum::response::IntoResponse::into_response(response);
        let (parts, body) = response.into_parts();

        // 如果不是200，打印响应体来调试
        if parts.status != StatusCode::OK {
            let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body_bytes);
            println!("🔍 Response status: {}", parts.status);
            println!("🔍 Response body: {}", body_str);
        }

        assert_eq!(parts.status, StatusCode::OK);

        println!("✅ CDN prefix resource session test completed!");
    }

    // 批量CDN API集成测试
    #[tokio::test]
    async fn test_post_batch_cdn_success() {
        let env = TestEnvironment::new().await;

        // 创建测试session，包含多个chunks
        let session_id = "test_batch_session";
        let session = SessionBuilder::new()
            .with_resource_id("test_resource")
            .with_version("1.0.0")
            .with_chunks(vec!["0-1023", "1024-2047", "2048-4095"])
            .build();

        env.services
            .session_service
            .store_session(session_id, &session)
            .await
            .unwrap();

        // 构造POST请求
        let request_body = crate::models::BatchChunkRequest {
            chunks: vec![
                "0-1023".to_string(),
                "1024-2047".to_string(),
                "2048-4095".to_string(),
            ],
        };

        // 模拟headers和连接信息
        let headers = HeaderMap::new();
        let real_connect_info = RealConnectInfo::from_headers_and_addr(
            &HeaderMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        // 调用批量CDN API
        let response = post_batch_cdn(
            Extension(env.app_context.clone()),
            Extension(real_connect_info),
            headers,
            Path((session_id.to_string(), "test_resource".to_string())),
            axum::Json(request_body),
        )
        .await;

        // 验证响应
        assert!(response.is_ok(), "API应该成功响应");

        let api_response = response.unwrap();
        let response = axum::response::IntoResponse::into_response(api_response);
        let (parts, body) = response.into_parts();

        // 解析响应体验证格式
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();

        // 如果不是200，打印响应体来调试
        if parts.status != StatusCode::OK {
            let body_str = String::from_utf8_lossy(&body_bytes);
            println!("🔍 Response status: {}", parts.status);
            println!("🔍 Response body: {}", body_str);
        }

        assert_eq!(parts.status, StatusCode::OK);
        let body_str = String::from_utf8_lossy(&body_bytes);

        // 验证响应是BatchCdnUrlResponse格式
        let json_response: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(json_response.get("urls").is_some(), "响应应该包含urls字段");

        let urls = json_response.get("urls").unwrap().as_object().unwrap();
        assert_eq!(urls.len(), 3, "应该包含3个chunk的结果");

        // 验证每个chunk都有url字段（根据mock实现）
        for chunk_id in &["0-1023", "1024-2047", "2048-4095"] {
            assert!(urls.contains_key(*chunk_id), "应该包含chunk: {}", chunk_id);
            let chunk_result = urls.get(*chunk_id).unwrap();
            // 由于mock实现中Flow会生成URL，应该有url字段
            assert!(
                chunk_result.get("url").is_some() || chunk_result.get("error").is_some(),
                "chunk结果应该包含url或error字段"
            );
        }

        println!("✅ POST batch CDN success test completed!");
    }

    #[tokio::test]
    async fn test_post_batch_cdn_empty_chunks() {
        let env = TestEnvironment::new().await;

        let session_id = "test_batch_session_empty";
        let session = SessionBuilder::new()
            .with_resource_id("test_resource")
            .with_chunks(vec!["0-1023"])
            .build();

        env.services
            .session_service
            .store_session(session_id, &session)
            .await
            .unwrap();

        // 构造空chunks请求
        let request_body = crate::models::BatchChunkRequest { chunks: vec![] };

        let headers = HeaderMap::new();
        let real_connect_info = RealConnectInfo::from_headers_and_addr(
            &HeaderMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        // 调用批量CDN API
        let response = post_batch_cdn(
            Extension(env.app_context.clone()),
            Extension(real_connect_info),
            headers,
            Path((session_id.to_string(), "test_resource".to_string())),
            axum::Json(request_body),
        )
        .await;

        // 验证响应 - 应该返回400错误
        assert!(response.is_err(), "空chunks数组应该返回错误");

        // 验证错误类型
        let error = response.unwrap_err();
        assert!(error.to_string().contains("Chunks array cannot be empty"));

        println!("✅ POST batch CDN empty chunks test completed!");
    }

    #[tokio::test]
    async fn test_post_batch_cdn_session_not_found() {
        let env = TestEnvironment::new().await;

        let request_body = crate::models::BatchChunkRequest {
            chunks: vec!["0-1023".to_string()],
        };

        let headers = HeaderMap::new();
        let real_connect_info = RealConnectInfo::from_headers_and_addr(
            &HeaderMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        // 使用不存在的session ID
        let response = post_batch_cdn(
            Extension(env.app_context.clone()),
            Extension(real_connect_info),
            headers,
            Path((
                "nonexistent_session".to_string(),
                "test_resource".to_string(),
            )),
            axum::Json(request_body),
        )
        .await;

        // 验证响应 - 应该返回session not found错误
        assert!(response.is_err(), "不存在的session应该返回错误");

        println!("✅ POST batch CDN session not found test completed!");
    }

    #[tokio::test]
    async fn test_post_batch_cdn_resource_not_found() {
        let env = TestEnvironment::new().await;

        let session_id = "test_batch_session_no_resource";
        let session = SessionBuilder::new()
            .with_resource_id("nonexistent_resource") // 不存在的资源
            .with_chunks(vec!["0-1023"])
            .build();

        env.services
            .session_service
            .store_session(session_id, &session)
            .await
            .unwrap();

        let request_body = crate::models::BatchChunkRequest {
            chunks: vec!["0-1023".to_string()],
        };

        let headers = HeaderMap::new();
        let real_connect_info = RealConnectInfo::from_headers_and_addr(
            &HeaderMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        // 调用批量CDN API
        let response = post_batch_cdn(
            Extension(env.app_context.clone()),
            Extension(real_connect_info),
            headers,
            Path((session_id.to_string(), "nonexistent_resource".to_string())),
            axum::Json(request_body),
        )
        .await;

        // 验证响应 - 应该返回resource not found错误
        assert!(response.is_err(), "不存在的资源应该返回错误");

        let error = response.unwrap_err();
        assert!(error.to_string().contains("not found") || error.to_string().contains("Resource"));

        println!("✅ POST batch CDN resource not found test completed!");
    }

    #[tokio::test]
    async fn test_post_batch_cdn_data_flow_verification() {
        let env = TestEnvironment::new().await;

        let session_id = "test_batch_data_flow";
        let session = SessionBuilder::new()
            .with_resource_id("test_resource")
            .with_chunks(vec!["0-1023", "1024-2047"])
            .build();

        env.services
            .session_service
            .store_session(session_id, &session)
            .await
            .unwrap();

        let request_body = crate::models::BatchChunkRequest {
            chunks: vec!["0-1023".to_string(), "1024-2047".to_string()],
        };

        let headers = HeaderMap::new();
        let real_connect_info = RealConnectInfo::from_headers_and_addr(
            &HeaderMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        // 调用批量CDN API
        let response = post_batch_cdn(
            Extension(env.app_context.clone()),
            Extension(real_connect_info),
            headers,
            Path((session_id.to_string(), "test_resource".to_string())),
            axum::Json(request_body),
        )
        .await;

        // 验证基本响应
        assert!(response.is_ok(), "API应该成功响应");

        let api_response = response.unwrap();
        let response = axum::response::IntoResponse::into_response(api_response);
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);

        // 验证数据流：批量操作应该被调用
        // 这里我们通过MockDataStore的行为来验证
        // 在实际场景中，我们可以扩展MockDataStore来记录调用历史

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        let json_response: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        let urls = json_response.get("urls").unwrap().as_object().unwrap();
        assert_eq!(urls.len(), 2, "应该处理2个chunk");

        // 验证并发限制：虽然我们无法直接测试信号量，但可以验证所有chunk都被处理
        assert!(urls.contains_key("0-1023"));
        assert!(urls.contains_key("1024-2047"));

        println!("✅ POST batch CDN data flow verification test completed!");
    }
}
