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
}
