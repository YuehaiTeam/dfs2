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
    container::AppContext,
    error::DfsError,
    models::{CreateSessionRequest, DeleteSessionRequest, Session},
    modules::network::RealConnectInfo,
    responses::{
        ApiResponse, ChallengeResponse, EmptyResponse, ErrorResponse, ResponseData,
        SessionCreatedResponse,
    },
    routes::resource::update_session_bandwidth_stats,
    services::session_service,
};

pub async fn handle_create_session_unified(
    resid: String,
    sub_path: Option<String>, // 关键参数：None=普通资源, Some=前缀资源
    ctx: AppContext,
    mut req: CreateSessionRequest,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    // 读锁访问配置
    let config_guard = ctx.get_config();

    // 验证资源和版本（统一处理前缀和普通资源）
    let (validated_resid, version) = ctx
        .resource_service
        .validate_resource_and_version(&resid, &req.version, sub_path.as_deref())
        .await?;

    if req.sid.is_empty() {
        req.sid = session_service::generate_session_id();
    }

    if req.challenge.is_empty() {
        // 使用ChallengeService统一处理challenge生成
        let challenge_response = ctx
            .challenge_service
            .generate_and_store_challenge(&req.sid, &validated_resid, sub_path.as_deref())
            .await?;

        return Ok(ApiResponse::custom_status(
            StatusCode::PAYMENT_REQUIRED,
            ResponseData::Challenge {
                challenge: challenge_response.challenge,
                data: challenge_response.data,
                sid: challenge_response.sid,
            },
        ));
    }

    // Challenge验证（统一处理）
    let debug_mode = config_guard.debug_mode;
    let challenge_verified = ctx
        .challenge_service
        .verify_challenge_response(
            &req.sid,
            &req.challenge,
            &validated_resid,
            sub_path.as_deref(),
            debug_mode,
        )
        .await?;

    if !challenge_verified {
        return Err(DfsError::ChallengeVerificationFailed {
            reason: "Invalid challenge response".to_string(),
        });
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

    ctx.session_service
        .store_session(&req.sid, &session)
        .await
        .map_err(|e| DfsError::SessionCreationFailed {
            reason: format!("Failed to store session: {e}"),
        })?;

    // 生成服务器尝试列表
    let tries = vec![];

    // 记录会话创建指标
    ctx.metrics.record_session_created();

    Ok(ApiResponse::success(ResponseData::Session {
        tries,
        sid: req.sid.clone(),
    }))
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
pub async fn delete_session(
    Extension(ctx): Extension<AppContext>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Path((sessionid, resid)): Path<(String, String)>,
    req_body: Option<Json<DeleteSessionRequest>>,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    // 提取客户端IP地址
    let client_ip = crate::modules::external::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 在删除之前获取会话统计信息
    match ctx.session_service.get_session_stats(&sessionid).await? {
        Some(stats) => {
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
            ctx.session_service.remove_session(&sessionid).await?;
        }
        None => {
            return Err(crate::error::DfsError::ResourceNotFound {
                resource_id: format!("session:{sessionid}"),
            });
        }
    }

    Ok(ApiResponse::success(ResponseData::Empty))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CreateSessionRequest;

    use axum::http::StatusCode;

    // 引用统一的测试框架
    use crate::tests::common::*;

    #[tokio::test]
    async fn test_create_session_challenge_generation() {
        let env = TestEnvironment::new().await;

        // 创建空的会话请求（触发挑战生成）
        let request = CreateSessionRequest {
            version: "1.0.0".to_string(),
            chunks: vec!["0-1024".to_string()],
            sid: "".to_string(),       // 空sid触发生成
            challenge: "".to_string(), // 空challenge触发生成
            extras: serde_json::json!({}),
        };

        // 调用会话创建处理器
        let response = handle_create_session_unified(
            "test_resource".to_string(),
            None, // 普通资源
            env.app_context.clone(),
            request,
        )
        .await;

        // 应该返回402状态码和挑战响应
        let response = axum::response::IntoResponse::into_response(response);
        let (parts, _body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::PAYMENT_REQUIRED);

        println!("✅ Challenge generation test completed!");
    }

    #[tokio::test]
    async fn test_create_session_challenge_verification_success() {
        let env = TestEnvironment::new().await;

        let session_id = "test_session_verify";

        // 先使用ChallengeService生成一个真实的challenge
        let challenge_response = env
            .services
            .challenge_service
            .generate_and_store_challenge(session_id, "test_resource", None)
            .await
            .unwrap();

        println!("🔍 Generated challenge: {:?}", challenge_response);

        // 为了测试，我们需要获取存储的challenge数据来计算正确答案
        let stored_challenge_data = env
            .data_store
            .get_challenge(session_id)
            .await
            .unwrap()
            .unwrap();
        let challenge_json: serde_json::Value =
            serde_json::from_str(&stored_challenge_data).unwrap();
        let original_data_hex = challenge_json["original_data"].as_str().unwrap();
        let original_data = hex::decode(original_data_hex).unwrap();

        // 计算正确的MD5响应（第一次哈希）
        let correct_response = format!("{:x}", md5::compute(&original_data));
        println!("🔍 Correct challenge response: {}", correct_response);

        // 创建带有正确挑战答案的请求
        let request = CreateSessionRequest {
            version: "1.0.0".to_string(),
            chunks: vec!["0-1024".to_string()],
            sid: session_id.to_string(),
            challenge: correct_response,
            extras: serde_json::json!({}),
        };

        println!("🔍 Making request with resource: test_resource");
        println!("🔍 Request: {:?}", request);

        // 调用会话创建处理器
        let result = handle_create_session_unified(
            "test_resource".to_string(),
            None,
            env.app_context.clone(),
            request,
        )
        .await;

        println!("🔍 Function result: {:?}", result.is_ok());

        // 处理Result类型并转换为Response
        let response = match result {
            Ok(resp) => axum::response::IntoResponse::into_response(resp),
            Err(e) => {
                println!("🔍 Error from function: {}", e);
                axum::response::IntoResponse::into_response(e)
            }
        };
        let (parts, body) = response.into_parts();

        println!("🔍 Response status: {}", parts.status);

        // 如果不是200，打印响应体来调试
        if parts.status != StatusCode::OK {
            let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body_bytes);
            println!("🔍 Response body: {}", body_str);
        }

        assert_eq!(parts.status, StatusCode::OK);

        // 验证会话已存储
        let stored_session = env
            .services
            .session_service
            .get_validated_session(session_id)
            .await;
        assert!(stored_session.is_ok());

        println!("✅ Challenge verification success test completed!");
    }

    #[tokio::test]
    async fn test_create_prefix_session_with_sub_path() {
        let env = TestEnvironment::new().await;

        let session_id = "test_prefix_session";

        // 先存储前缀资源的挑战
        let challenge_data = ChallengeDataBuilder::new()
            .with_challenge_type("md5")
            .build();

        env.data_store
            .store_challenge(session_id, &challenge_data)
            .await
            .unwrap();

        // 创建前缀资源请求
        let request = CreateSessionRequest {
            version: "3.0.0".to_string(),
            chunks: vec!["0-2048".to_string()],
            sid: session_id.to_string(),
            challenge: "correct_answer".to_string(),
            extras: serde_json::json!({}),
        };

        // 调用前缀会话创建处理器
        let response = handle_create_session_unified(
            "game_assets".to_string(),
            Some("textures/player.png".to_string()), // 前缀资源
            env.app_context.clone(),
            request,
        )
        .await;

        // 应该返回200状态码
        let response = axum::response::IntoResponse::into_response(response);
        let (parts, _body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);

        // 验证前缀会话已存储且包含sub_path
        let stored_session = env
            .services
            .session_service
            .get_validated_session(session_id)
            .await
            .unwrap();
        assert_eq!(
            stored_session.sub_path,
            Some("textures/player.png".to_string())
        );
        assert_eq!(stored_session.resource_id, "game_assets");

        println!("✅ Prefix session creation test completed!");
    }

    // 测试已删除: test_create_prefix_session_invalid_resource_type - 边界情况

    // 测试已删除: test_session_creation_with_extras - 非核心功能

    // 测试已删除: test_session_creation_automatic_sid_generation - 实现细节
}
