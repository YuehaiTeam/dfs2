use axum::{
    extract::{Extension, Path},
    http::HeaderMap,
};
use tracing::info;

use crate::error::DfsError;
use crate::modules::network::RealConnectInfo;
use crate::record_request_metrics;
use crate::responses::ErrorResponse;
use crate::{container::AppContext, modules::external::geolocation};

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

    // 预先计算IP字符串和地理位置信息（避免在每个chunk中重复计算）
    let client_ip_str = if let Some(ip) = client_ip {
        ip.to_string()
    } else {
        "unknown".to_string()
    };
    let client_geo_str = if let Some(ip) = client_ip {
        geolocation::get_ip_location_data(ip).unwrap_or("unknown".to_string())
    } else {
        "unknown".to_string()
    };

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
    let tasks_with_chunk_ids: Vec<_> = payload
        .chunks
        .into_iter()
        .map(|chunk_range| {
            let original_chunk_id = chunk_range.clone(); // 保存原始chunk_id
            let ctx = ctx.clone();
            let session = session.clone();
            let resource = resource.clone();
            let batch_data_ref = batch_data.clone();
            let semaphore = semaphore.clone();

            let task = tokio::spawn(async move {
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
            });
            
            (original_chunk_id, task) // 返回(chunk_id, task)元组
        })
        .collect();

    // 5. 收集所有结果
    let mut chunk_results = std::collections::HashMap::new();
    let mut cdn_records_to_store = Vec::new();
    let mut server_bandwidth_map = std::collections::HashMap::new();
    let mut total_bandwidth = 0u64;

    for (original_chunk_id, task) in tasks_with_chunk_ids {
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

                // 先获取weight用于日志记录
                let weight = chunk_result
                    .cdn_record
                    .as_ref()
                    .map(|r| r.weight)
                    .unwrap_or(0);

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
                        *server_bandwidth_map.entry(server_id.clone()).or_default() +=
                            bandwidth_info.bytes;
                        total_bandwidth += bandwidth_info.bytes;

                        // QPS metrics记录 (纯内存操作)
                        ctx.metrics
                            .record_scheduled_request(&resid, &server_id, false);

                        // 每个chunk的独立调度日志
                        let chunk_size_mb = bandwidth_info.bytes as f64 / 1024.0 / 1024.0;

                        info!(
                            "{}/{} size={:.2}MB -> {} weight={} ip={} geo={}",
                            if let Some(ref sub_path_val) = session.sub_path {
                                format!("{resid}/{sub_path_val}")
                            } else {
                                resid.clone()
                            },
                            chunk_result.chunk_id,
                            chunk_size_mb,
                            server_id,
                            weight,
                            client_ip_str,
                            client_geo_str
                        );
                    }
                }
            }
            Err(e) => {
                // 计算资源路径和文件大小用于日志记录
                let resource_path = if let Some(ref sub_path_val) = session.sub_path {
                    format!("{}/{}", resid, sub_path_val)
                } else {
                    resid.clone()
                };
                
                // 尝试解析chunk范围以计算文件大小
                let file_size_mb = if let Ok(ranges) = parse_and_validate_ranges(&original_chunk_id) {
                    calculate_file_size_from_ranges(&ranges) as f64 / (1024.0 * 1024.0)
                } else {
                    0.0
                };

                // 记录错误日志（与单个CDN获取保持一致的格式）
                tracing::error!(
                    "BATCH-ERROR {} chunk={} size={:.2}MB {}",
                    resource_path, original_chunk_id, file_size_mb, e
                );

                // 使用原始chunk_id而不是生成虚假的chunk_id
                chunk_results.insert(
                    original_chunk_id,
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
        // 克隆server_bandwidth_map用于分钟级流量统计
        let server_bandwidth_for_minute = server_bandwidth_map.clone();

        let bandwidth_batch = crate::modules::storage::data_store::MultiBandwidthUpdateBatch {
            resource_id: resid.clone(),
            server_updates: server_bandwidth_map,
            total_bytes: total_bandwidth,
        };

        ctx.data_store
            .batch_write_cdn_and_bandwidth(&sessionid, &cdn_records_to_store, &bandwidth_batch)
            .await
            .map_err(|e| DfsError::internal_error(format!("Batch Redis write failed: {}", e)))?;

        // 7. 记录分钟级流量统计 (内存缓存，定期批量写Redis)
        for (server_id, bytes) in &server_bandwidth_for_minute {
            ctx.bandwidth_cache_service
                .record_bandwidth(server_id, *bytes)
                .await;
        }
    }

    // 8. 记录总体指标
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
        .execute_flow(&target, &context, &options, &resource.flow, penalty_servers, Some(session))
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
    use crate::tests::common::*;
    use axum::http::{HeaderMap, StatusCode};
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

    #[tokio::test]
    async fn test_post_batch_cdn_error_chunk_id_preservation() {
        println!("🧪 Testing batch CDN error chunk_id preservation...");

        let env = TestEnvironment::new().await;

        // 创建session（有效的chunk和无效的chunk混合）
        let session_id = "test_error_session";
        let session = SessionBuilder::new()
            .with_resource_id("test_resource")
            .with_version("1.0.0")
            .with_chunks(vec!["0-1023", "1024-2047"]) // 只有这两个chunk是有效的
            .build();

        env.services
            .session_service
            .store_session(session_id, &session)
            .await
            .unwrap();

        // 准备包含无效chunk的请求
        let request_body = crate::models::BatchChunkRequest {
            chunks: vec![
                "0-1023".to_string(),     // 有效chunk
                "9999-10000".to_string(), // 无效chunk (不在session.chunks中)
                "1024-2047".to_string(),  // 有效chunk
                "invalid-format".to_string(), // 格式无效的chunk
            ],
        };

        // 模拟HTTP请求元数据
        let real_connect_info = RealConnectInfo {
            remote_addr: "192.168.1.100:8080".parse().unwrap(),
        };
        let headers = HeaderMap::new();

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

        assert_eq!(parts.status, StatusCode::OK);

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        let json_response: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        let urls = json_response.get("urls").unwrap().as_object().unwrap();
        
        // 验证所有chunk都有对应的结果，包括错误的chunk
        assert_eq!(urls.len(), 4, "应该返回所有4个chunk的结果");
        
        // 验证成功的chunk返回正确的chunk_id
        assert!(urls.contains_key("0-1023"), "应该包含有效chunk 0-1023");
        assert!(urls.contains_key("1024-2047"), "应该包含有效chunk 1024-2047");
        
        // 验证失败的chunk返回原始chunk_id而不是虚假的"error_chunk"或"unknown_chunk"
        assert!(urls.contains_key("9999-10000"), "应该包含chunk 9999-10000");
        assert!(urls.contains_key("invalid-format"), "应该包含失败的chunk invalid-format");
        
        // 注意：9999-10000在MockDataStore中被处理为有效（这是预期的，因为mock没有完全模拟所有验证）
        // 重点是验证它返回了正确的chunk_id而不是"error_chunk"
        let chunk_9999_result = urls.get("9999-10000").unwrap();
        // 这个chunk在mock环境中成功了，所以有URL
        assert!(chunk_9999_result.get("url").is_some(), "chunk 9999-10000在mock环境中应该有url字段");
        
        // invalid-format是真正格式错误的chunk，应该有error
        let malformed_chunk_result = urls.get("invalid-format").unwrap();
        assert!(malformed_chunk_result.get("error").is_some(), "格式错误的chunk应该有error字段");
        assert!(malformed_chunk_result.get("url").is_none() || malformed_chunk_result.get("url").unwrap().is_null(), "格式错误的chunk不应该有url字段");
        
        // 验证成功的chunk有url字段而没有error字段
        let success_chunk_result = urls.get("0-1023").unwrap();
        assert!(success_chunk_result.get("url").is_some(), "成功的chunk应该有url字段");
        assert!(success_chunk_result.get("error").is_none() || success_chunk_result.get("error").unwrap().is_null(), "成功的chunk不应该有error字段");

        println!("✅ POST batch CDN error chunk_id preservation test completed!");
        println!("   - 所有chunk都正确返回原始chunk_id，包括：");
        println!("     * 成功的chunk: 0-1023, 1024-2047, 9999-10000 (有url字段)");
        println!("     * 失败的chunk: invalid-format (有error字段)");
        println!("   - 修复验证：不再使用虚假的'error_chunk'或'unknown_chunk'作为key");
    }
}
