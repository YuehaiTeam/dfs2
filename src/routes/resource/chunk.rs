use axum::{
    Json,
    extract::{Extension, Path, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::collections::HashMap;
use tracing::{error, info};

use crate::container::AppContext;
use crate::modules::network::RealConnectInfo;
use crate::responses::{ApiResponse, CdnUrlResponse, ErrorResponse, ResponseData};
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
) -> impl IntoResponse {
    // 记录请求开始时间
    let start_time = std::time::Instant::now();

    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    let session = match ctx.session_service.get_validated_session(&sessionid).await {
        Ok(session) => session,
        Err(e) => {
            let status_code = StatusCode::from_u16(e.http_status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return (status_code, Json(ApiResponse::error(e.to_string())));
        }
    };

    if let Some(range_str) = params.get("range") {
        match ctx
            .session_service
            .check_download_limit(&sessionid, range_str)
            .await
        {
            Ok(count) => {
                // 验证资源存在性
                let (validated_resid, _effective_version) = match ctx
                    .resource_service
                    .validate_resource_and_version(&resid, "", None)
                    .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        return (
                            StatusCode::NOT_FOUND,
                            Json(ApiResponse::error(format!("Resource {} not found", resid))),
                        );
                    }
                };

                // 解析ranges参数
                let ranges = if range_str.contains(',') {
                    // Multiple ranges: "0-255,256-511,512-767"
                    let mut parsed_ranges = Vec::new();
                    for range_part in range_str.split(',') {
                        let range_part = range_part.trim();
                        if let Some((start_str, end_str)) = range_part.split_once('-') {
                            if let (Ok(start), Ok(end)) =
                                (start_str.parse::<u32>(), end_str.parse::<u32>())
                            {
                                parsed_ranges.push((start, end));
                            } else {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    Json(ApiResponse::error(format!(
                                        "Invalid range format in part: {}",
                                        range_part
                                    ))),
                                );
                            }
                        } else {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(ApiResponse::error(format!(
                                    "Invalid range format in part: {}",
                                    range_part
                                ))),
                            );
                        }
                    }
                    if parsed_ranges.is_empty() {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ApiResponse::error("No valid ranges found".to_string())),
                        );
                    }
                    parsed_ranges
                } else {
                    // Single range: "0-255"
                    if let Some((start_str, end_str)) = range_str.split_once('-') {
                        if let (Ok(start), Ok(end)) =
                            (start_str.parse::<u32>(), end_str.parse::<u32>())
                        {
                            vec![(start, end)]
                        } else {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(ApiResponse::error("Invalid range format".to_string())),
                            );
                        }
                    } else {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ApiResponse::error("Invalid range format".to_string())),
                        );
                    }
                };

                let config_guard = ctx.shared_config.load();
                let res = config_guard.get_resource(&validated_resid).unwrap(); // 已验证存在
                let flow_list = &res.flow;

                // 计算文件大小：根据ranges计算总大小
                let file_size = Some(
                    ranges
                        .iter()
                        .map(|(start, end)| (end - start + 1) as u64)
                        .sum(),
                );

                // 使用SessionService统一处理flow执行
                let flow_result = match ctx
                    .session_service
                    .run_flow_for_session(
                        &session,
                        &sessionid,
                        ranges,
                        &ctx.flow_service,
                        client_ip,
                        file_size,
                        flow_list,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        error!("Failed to run flow for session: {}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse::error("Failed to process request".to_string())),
                        );
                    }
                };
                let cdn_url = flow_result.url;

                // 记录调度结果日志
                let resource_path = if let Some(ref sub_path_val) = session.sub_path {
                    format!("{}/{}", resid, sub_path_val)
                } else {
                    resid.clone()
                };
                let file_size_mb = file_size.map(|size| size as f64 / 1024.0 / 1024.0).unwrap_or(0.0);
                info!("{} size={:.2}MB -> {} weight={}", 
                      resource_path, 
                      file_size_mb,
                      flow_result.selected_server_id.as_deref().unwrap_or("unknown"),
                      flow_result.selected_server_weight.unwrap_or(0));

                // 记录成功的请求和流程执行指标
                record_request_metrics!(ctx.metrics, start_time);
                record_flow_metrics!(ctx.metrics, true);

                return (
                    StatusCode::OK,
                    Json(ApiResponse::success(ResponseData::Cdn { url: cdn_url })),
                );
            }
            Err(e) => {
                let status_code = StatusCode::from_u16(e.http_status_code())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                return (status_code, Json(ApiResponse::error(e.to_string())));
            }
        }
    }

    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::error(
            "Range parameter is required".to_string(),
        )),
    )
}
