use axum::{
    Json,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;
use std::collections::HashMap;
use tracing::{error, info};

use crate::{
    container::AppContext, models::{CreateSessionRequest, DeleteSessionRequest, Session}, modules::network::RealConnectInfo, responses::{ApiResponse, ChallengeResponse, EmptyResponse, ErrorResponse, ResponseData, SessionCreatedResponse}, routes::resource::update_session_bandwidth_stats, services::session_service
};

pub async fn handle_create_session_unified(
    resid: String,
    sub_path: Option<String>, // 关键参数：None=普通资源, Some=前缀资源
    ctx: AppContext,
    mut req: CreateSessionRequest,
) -> impl IntoResponse {
    // 读锁访问配置
    let config_guard = ctx.get_config();

    // 验证资源和版本（统一处理前缀和普通资源）
    let (validated_resid, effective_version) = match ctx
        .resource_service
        .validate_resource_and_version(&resid, &req.version, sub_path.as_deref())
        .await
    {
        Ok(result) => result,
        Err(e) => {
            let status_code = if sub_path.is_some() {
                StatusCode::BAD_REQUEST // 前缀资源错误
            } else {
                StatusCode::NOT_FOUND // 普通资源错误
            };
            let error_msg = if sub_path.is_some() {
                e.to_string()
            } else {
                format!("资源 {} 不存在", resid)
            };
            return (status_code, Json(ApiResponse::error(error_msg)));
        }
    };

    let resource_config = config_guard.get_resource(&validated_resid).unwrap(); // 已验证存在

    // 使用已验证的版本
    let version = effective_version;

    // 获取路径（统一处理）
    let path = match ctx.resource_service.get_version_path(&resid, &version, None, sub_path.as_deref()) {
        Some(p) => p,
        None => {
            let error_msg = if sub_path.is_some() {
                "无法构建资源路径".to_string()
            } else {
                "无法获取资源路径".to_string()
            };
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(error_msg)),
            );
        }
    };

    if req.sid.is_empty() {
        req.sid = session_service::generate_session_id();
    }

    if req.challenge.is_empty() {
        // Challenge生成（统一处理）
        let config_guard = ctx.shared_config.load();
        let challenge_config = config_guard.get_challenge_config(&resid);

        // 使用ChallengeService统一处理challenge生成
        match ctx
            .challenge_service
            .generate_and_store_challenge(&req.sid, &validated_resid, sub_path.as_deref())
            .await
        {
            Ok(challenge_response) => {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(ApiResponse::Success(ResponseData::Challenge {
                        challenge: challenge_response.challenge,
                        data: challenge_response.data,
                        sid: challenge_response.sid,
                    })),
                );
            }
            Err(e) => {
                let error_msg = if sub_path.is_some() {
                    format!("Failed to generate challenge for prefix resource: {}", e)
                } else {
                    format!("Failed to generate challenge: {}", e)
                };
                error!("{}", error_msg);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(
                        "Failed to generate challenge".to_string(),
                    )),
                );
            }
        }
    }

    // Challenge验证（统一处理）
    let debug_mode = config_guard.debug_mode;
    match ctx
        .challenge_service
        .verify_challenge_response(
            &req.sid,
            &req.challenge,
            &validated_resid,
            sub_path.as_deref(),
            debug_mode,
        )
        .await
    {
        Ok(true) => {
            // Challenge验证成功，继续创建session
        }
        Ok(false) => {
            let status_code = if sub_path.is_some() {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::PAYMENT_REQUIRED
            };
            return (
                status_code,
                Json(ApiResponse::error(
                    "Challenge verification failed".to_string(),
                )),
            );
        }
        Err(e) => {
            error!("Challenge verification error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Challenge verification error".to_string(),
                )),
            );
        }
    }

    // Challenge验证成功，移除challenge
    let _ = ctx.challenge_service.remove_challenge(&req.sid).await;

    // 创建会话（统一逻辑）
    let session = Session {
        resource_id: resid.clone(),
        version: version.clone(),
        chunks: req.chunks.clone(),
        sub_path: sub_path.clone(), // 关键差异：前缀资源保存sub_path
        cdn_records: HashMap::new(),
        extras: req.extras.clone(),
    };

    if let Err(e) = ctx.session_service.store_session(&req.sid, &session).await {
        error!("Failed to store session in Redis: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Failed to create session".to_string())),
        );
    }

    // 生成服务器尝试列表
    let tries = vec![];

    // 记录会话创建指标
    ctx.metrics.record_session_created();

    (
        StatusCode::OK,
        Json(ApiResponse::success(ResponseData::Session {
            tries,
            sid: req.sid.clone(),
        })),
    )
}

#[utoipa::path(
    post,
    path = "/resource/{resid}",
    tag = "Resource",
    summary = "Create session for resource access",
    description = "Creates a new session for accessing a resource, handles challenge verification and returns session ID with server tries list",
    params(
        ("resid" = String, Path, description = "Resource identifier")
    ),
    request_body = CreateSessionRequest,
    responses(
        (status = 200, description = "Session created successfully", body = SessionCreatedResponse),
        (status = 402, description = "Challenge required or failed", body = ChallengeResponse),
        (status = 404, description = "Resource not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[axum::debug_handler]
pub async fn create_session(
    Path(resid): Path<String>,
    Extension(ctx): Extension<AppContext>,
    Json(req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    handle_create_session_unified(resid, None, ctx, req).await
}

#[utoipa::path(
    post,
    path = "/resource/{resid}/{sub_path}",
    tag = "Resource",
    summary = "Create session for prefix resource access",
    description = "Creates a new session for accessing a specific file within a prefix resource, handles challenge verification",
    params(
        ("resid" = String, Path, description = "Prefix resource identifier"),
        ("sub_path" = String, Path, description = "Sub-path within the prefix resource")
    ),
    request_body = CreateSessionRequest,
    responses(
        (status = 200, description = "Session created successfully", body = SessionCreatedResponse),
        (status = 400, description = "Resource is not a prefix type", body = ErrorResponse),
        (status = 402, description = "Challenge required or failed", body = ChallengeResponse),
        (status = 404, description = "Resource not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[allow(unused_variables)]
#[axum::debug_handler]
pub async fn create_prefix_session(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(ctx): Extension<AppContext>,
    Json(req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    handle_create_session_unified(resid, Some(sub_path), ctx, req).await
}

#[utoipa::path(
    delete,
    path = "/session/{sessionid}/{resid}",
    tag = "Resource",
    summary = "Delete session and get statistics",
    description = "Deletes a session and returns statistics about downloads, bandwidth usage, and CDN performance",
    params(
        ("sessionid" = String, Path, description = "Session identifier"),
        ("resid" = String, Path, description = "Resource identifier")
    ),
    request_body(content = DeleteSessionRequest, description = "Optional insights data from client"),
    responses(
        (status = 200, description = "Session deleted successfully", body = EmptyResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[allow(unused_variables)]
pub async fn delete_session(
    Extension(ctx): Extension<AppContext>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Path((sessionid, resid)): Path<(String, String)>,
    req_body: Option<Json<DeleteSessionRequest>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 在删除之前获取会话统计信息
    match ctx.session_service.get_session_stats(&sessionid).await {
        Ok(Some(stats)) => {
            // 如果有客户端IP，记录结构化日志
            if let Some(ip) = client_ip {
                let session_logger = crate::modules::analytics::SessionLogger::new(
                    ctx.shared_config.clone(),
                    ctx.data_store.clone(),
                );
                let insights = req_body
                    .as_ref()
                    .and_then(|Json(req)| req.insights.as_ref());
                let user_agent = headers
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                if let Err(e) = session_logger
                    .log_session_completed(&sessionid, &resid, ip, user_agent, insights.cloned())
                    .await
                {
                    error!("Failed to log session completion: {}", e);
                }
            }

            // 合并所有统计信息（保留原有的JSON日志）
            let complete_stats = if let Some(Json(req)) = req_body {
                // 如果有请求体，包含 insights 信息
                if let Some(insights) = req.insights {
                    json!({
                        "session_id": sessionid,
                        "resource_id": resid,
                        "resource_id": &stats.resource_id,
                        "version": &stats.version,
                        "chunks": stats.chunks,
                        "download_counts": stats.download_counts,
                        "cdn_records": stats.cdn_records,  // 包含了CDN调度记录
                        "insights": {
                            "bandwidth": insights.bandwidth,
                            "ttfb": insights.ttfb,
                        }
                    })
                } else {
                    json!({
                        "session_id": sessionid,
                        "resource_id": resid,
                        "resource_id": &stats.resource_id,
                        "version": &stats.version,
                        "chunks": stats.chunks,
                        "download_counts": stats.download_counts,
                        "cdn_records": stats.cdn_records,
                    })
                }
            } else {
                // 如果没有请求体，不包含 insights 信息
                json!({
                    "session_id": sessionid,
                    "resource_id": resid,
                    "chunks": stats.chunks,
                    "download_counts": stats.download_counts,
                    "cdn_records": stats.cdn_records,
                })
            };

            info!("Session completed: {}", complete_stats);

            // 更新流量统计（基于会话完成情况）
            update_session_bandwidth_stats(&ctx.data_store, &sessionid, &resid, &stats).await;

            // 删除会话
            if let Err(e) = ctx.session_service.remove_session(&sessionid).await {
                error!("Failed to remove session: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error("Failed to delete session".to_string())),
                );
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("Session not found".to_string())),
            );
        }
        Err(e) => {
            error!("Failed to get session statistics: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Failed to get session statistics".to_string(),
                )),
            );
        }
    }

    (
        StatusCode::OK,
        Json(ApiResponse::success(ResponseData::Empty)),
    )
}
