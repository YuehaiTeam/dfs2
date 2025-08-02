use axum::{
    Json, Router,
    extract::{Extension, Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::challenge::{ChallengeType, generate_challenge};
use crate::config::{AppConfig, DownloadPolicy};
use crate::error::{DfsError, DfsResult};
use crate::models::{CreateSessionRequest, DeleteSessionRequest, Session};
use crate::responses::{ApiResponse, ResponseData};
use crate::cache::{should_cache_content, download_and_cache};
use crate::data_store::CacheMetadata;
use crate::{
    app_state::{MAX_CHUNK_DOWNLOADS, DataStore},
    modules::flow::runner::{FlowRunner, RunFlowParams},
    modules::thirdparty::kachina,
    RealConnectInfo,
};

// 错误码常量定义
const E_RESOURCE_NOT_FOUND: &str = "E_RESOURCE_NOT_FOUND";
const E_VERSION_NOT_FOUND: &str = "E_VERSION_NOT_FOUND";
const E_PATH_NOT_FOUND: &str = "E_PATH_NOT_FOUND";

// 下载响应类型
#[derive(Debug)]
enum DownloadResponse {
    Cached {
        content: Vec<u8>,
        metadata: CacheMetadata,
    },
    Redirect(String),
}

// 生成会话尝试服务器列表
async fn generate_session_tries(
    config: &AppConfig,
    resid: &str,
    file_path: &str,  // 新增：完整文件路径用于健康检查
    redis: &DataStore,
) -> DfsResult<Vec<String>> {
    let resource_config = config.get_resource(resid).ok_or_else(|| {
        warn!("Resource {} not found when generating tries", resid);
        DfsError::resource_not_found(resid)
    })?;

    // 使用传入的完整文件路径进行健康检查（支持前缀资源）
    let path = file_path;

    // 如果资源配置中定义了tries列表，验证健康状态并使用
    let server_candidates = if !resource_config.tries.is_empty() {
        &resource_config.tries
    } else {
        // 否则，使用server列表作为候选服务器
        &resource_config.server
    };

    let mut healthy_servers = Vec::new();
    let mut unhealthy_servers = Vec::new();

    for server_id in server_candidates {
        // 检查服务器是否在全局配置中存在
        if let Some(server_impl) = config.get_server(server_id) {
            // 进行健康检查
            let is_healthy = server_impl.is_alive(server_id, &path, Some(redis)).await;

            if is_healthy {
                healthy_servers.push(server_id.clone());
            } else {
                unhealthy_servers.push(server_id.clone());
                warn!("Server {} is unhealthy for path {}", server_id, path);
            }
        } else {
            warn!(
                "Server {} referenced in resource {} but not found in global config",
                server_id, resid
            );
        }
    }

    // 优先返回健康的服务器，不健康的服务器放在后面作为备选
    let mut tries = healthy_servers;
    tries.extend(unhealthy_servers);

    // 如果没有可用的服务器，返回错误
    if tries.is_empty() {
        error!("No valid servers found for resource {}", resid);
        return Err(DfsError::server_unavailable(
            "no_servers_available".to_string(),
        ));
    }

    info!("Generated tries list for resource {}: {:?}", resid, tries);
    Ok(tries)
}

#[allow(unused_variables)]
async fn get_metadata(
    Path(resid): Path<String>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(runner): Extension<FlowRunner>,
    Extension(redis): Extension<DataStore>,
) -> impl IntoResponse {
    // 获取资源配置和文件路径用于缓存key
    let cache_key = {
        let config_guard = config.read().await;

        // 检查资源是否存在
        let resource_config = match config_guard.get_resource(&resid) {
            Some(rc) => rc,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ApiResponse::error(E_RESOURCE_NOT_FOUND.to_string())),
                );
            }
        };

        // 获取版本对应的默认路径
        let version = &resource_config.latest;
        let path = match config_guard.get_version_path(&resid, version, None) {
            Some(p) => p,
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(E_PATH_NOT_FOUND.to_string())),
                );
            }
        };

        if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
            if !prefix.is_empty() {
                format!("{}:kachina_meta:{}", prefix, path)
            } else {
                format!("kachina_meta:{}", path)
            }
        } else {
            format!("kachina_meta:{}", path)
        }
    };

    // 先检查缓存
    if let Ok(Some(cached_data)) = redis.get_cached_metadata(&cache_key).await {
        if let Ok(cached_json) = serde_json::from_str::<serde_json::Value>(&cached_data) {
            return (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Metadata {
                    dfs_version: "1.0.0".to_string(),
                    name: format!("resource-{}", resid),
                    data: cached_json,
                })),
            );
        }
    }

    // 使用 kachina 模块解析 KachinaInstaller 文件
    match kachina::parse_kachina_metadata(&config, &runner, &resid, None).await {
        Ok(Some(metadata)) => {
            // 返回解析后的数据
            let response_data = json!({
                "index": metadata.index,
                "metadata": metadata.metadata,
                "installer_end": metadata.installer_end
            });

            // 缓存解析结果，缓存1小时 (3600秒)
            if let Ok(cache_value) = serde_json::to_string(&response_data) {
                if let Err(e) = redis
                    .set_cached_metadata(&cache_key, &cache_value, 3600)
                    .await
                {
                    warn!("Failed to cache metadata: {}", e);
                }
            }

            (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Metadata {
                    dfs_version: "1.0.0".to_string(),
                    name: format!("resource-{}", resid),
                    data: response_data,
                })),
            )
        }
        Ok(None) => {
            // 不是 KachinaInstaller 文件，返回 null
            let null_data = json!(null);

            // 也缓存 null 结果，避免重复检查
            if let Ok(cache_value) = serde_json::to_string(&null_data) {
                if let Err(e) = redis
                    .set_cached_metadata(&cache_key, &cache_value, 3600)
                    .await
                {
                    warn!("Failed to cache null metadata: {}", e);
                }
            }

            (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Metadata {
                    dfs_version: "1.0.0".to_string(),
                    name: format!("resource-{}", resid),
                    data: null_data,
                })),
            )
        }
        Err(error_msg) => {
            error!("Failed to parse kachina metadata: {}", error_msg);
            let status_code = if error_msg.starts_with(E_RESOURCE_NOT_FOUND)
                || error_msg.starts_with(E_VERSION_NOT_FOUND)
            {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status_code, Json(ApiResponse::error(error_msg)))
        }
    }
}

#[allow(unused_variables)]
#[axum::debug_handler]
async fn create_session(
    Path(resid): Path<String>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Json(mut req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    // 读锁访问配置
    let config_guard = config.read().await;

    // 检查资源是否存在
    let resource_config = match config_guard.get_resource(&resid) {
        Some(rc) => rc,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error(format!("资源 {} 不存在", resid))),
            );
        }
    };

    // 使用配置文件中的版本路径
    let version = if req.version.is_empty() || req.version == "latest" {
        resource_config.latest.as_str()
    } else {
        req.version.as_str()
    };

    // 检查版本是否存在
    if !resource_config.versions.contains_key(version) {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(format!("版本 {} 不存在", version))),
        );
    }

    // 获取版本对应的默认路径
    let path = match config_guard.get_version_path(&resid, version, None) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("无法获取资源路径".to_string())),
            );
        }
    };

    if req.sid.is_empty() {
        req.sid = Uuid::new_v4().to_string();
    }

    if req.challenge.is_empty() {
        // Get challenge configuration from config file (resource-specific or global)
        let config_guard = config.read().await;
        let challenge_config = config_guard.get_challenge_config(&resid);
        
        // Generate challenge based on configuration
        let base_data = format!("data/{}/{}", resid, req.sid);
        let challenge_type = challenge_config.get_effective_type();
        
        // Create actual challenge config for generation
        let generation_config = crate::challenge::ChallengeConfig {
            challenge_type,
            difficulty: if challenge_type == ChallengeType::Sha256 {
                challenge_config.get_sha256_difficulty()
            } else {
                2 // MD5 always uses 2, Web doesn't use this field
            },
        };
        
        let challenge = generate_challenge(&generation_config, &base_data);

        // Handle Web challenges differently using the plugin system
        if challenge.challenge_type == ChallengeType::Web {
            // For Web challenges, use the configured web plugin
            let web_plugin_id = &challenge_config.web_plugin;

            let challenge_data = serde_json::json!({
                "session_id": req.sid,
                "resource_id": resid,
                "base_data": base_data,
            });

            match runner
                .run_challenge_plugin(
                    &web_plugin_id,
                    "generate",
                    challenge_data,
                    serde_json::json!({}),
                )
                .await
            {
                Ok(plugin_result) => {
                    // Expect plugin to return {"url": "...", "token": "..."} or similar
                    if let Some(verification_url) =
                        plugin_result.get("url").and_then(|v| v.as_str())
                    {
                        // Store the plugin result for later verification
                        let web_challenge_json = serde_json::json!({
                            "type": "web",
                            "plugin_id": web_plugin_id,
                            "plugin_result": plugin_result,
                            "verification_url": verification_url,
                        });

                        if let Err(e) = redis
                            .store_challenge(&req.sid, &web_challenge_json.to_string())
                            .await
                        {
                            error!("Failed to store web challenge: {}", e);
                        }

                        return (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(ApiResponse::Success(ResponseData::Challenge {
                                challenge: "web".to_string(),
                                data: verification_url.to_string(),
                                sid: req.sid,
                            })),
                        );
                    } else {
                        warn!(
                            "Web challenge plugin {} did not return a valid URL",
                            web_plugin_id
                        );
                        // Fall back to generating a different challenge type
                        let fallback_config = crate::challenge::ChallengeConfig {
                            challenge_type: ChallengeType::Md5,
                            difficulty: 2,
                        };
                        let fallback_challenge = generate_challenge(&fallback_config, &base_data);

                        let challenge_json = serde_json::json!({
                            "type": "md5",
                            "hash": fallback_challenge.hash,
                            "partial_data": fallback_challenge.partial_data,
                            "missing_bytes": fallback_challenge.missing_bytes,
                            "original_data": hex::encode(&fallback_challenge.original_data),
                        });

                        if let Err(e) = redis
                            .store_challenge(&req.sid, &challenge_json.to_string())
                            .await
                        {
                            error!("Failed to store fallback challenge: {}", e);
                        }

                        return (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(ApiResponse::Success(ResponseData::Challenge {
                                challenge: "md5".to_string(),
                                data: fallback_challenge.format_data(),
                                sid: req.sid,
                            })),
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to run web challenge plugin {}: {}",
                        web_plugin_id, e
                    );
                    // Fall back to MD5 challenge
                    let fallback_config = crate::challenge::ChallengeConfig {
                        challenge_type: ChallengeType::Md5,
                        difficulty: 2,
                    };
                    let fallback_challenge = generate_challenge(&fallback_config, &base_data);

                    let challenge_json = serde_json::json!({
                        "type": "md5",
                        "hash": fallback_challenge.hash,
                        "partial_data": fallback_challenge.partial_data,
                        "missing_bytes": fallback_challenge.missing_bytes,
                        "original_data": hex::encode(&fallback_challenge.original_data),
                    });

                    if let Err(e) = redis
                        .store_challenge(&req.sid, &challenge_json.to_string())
                        .await
                    {
                        error!("Failed to store fallback challenge: {}", e);
                    }

                    return (
                        StatusCode::PAYMENT_REQUIRED,
                        Json(ApiResponse::Success(ResponseData::Challenge {
                            challenge: "md5".to_string(),
                            data: fallback_challenge.format_data(),
                            sid: req.sid,
                        })),
                    );
                }
            }
        }

        // Store challenge in Redis for later verification
        let challenge_json = serde_json::json!({
            "type": match challenge.challenge_type {
                ChallengeType::Md5 => "md5",
                ChallengeType::Sha256 => "sha256",
                ChallengeType::Web => "web",
            },
            "hash": challenge.hash,
            "partial_data": challenge.partial_data,
            "missing_bytes": challenge.missing_bytes,
            "original_data": hex::encode(&challenge.original_data),
        });

        if let Err(e) = redis
            .store_challenge(&req.sid, &challenge_json.to_string())
            .await
        {
            error!("Failed to store challenge: {}", e);
        }

        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(ApiResponse::Success(ResponseData::Challenge {
                challenge: match challenge.challenge_type {
                    ChallengeType::Md5 => "md5".to_string(),
                    ChallengeType::Sha256 => "sha256".to_string(),
                    ChallengeType::Web => "web".to_string(),
                },
                data: challenge.format_data(),
                sid: req.sid,
            })),
        );
    }

    // Verify challenge response
    if let Ok(Some(challenge_data)) = redis.get_challenge(&req.sid).await {
        if let Ok(challenge_json) = serde_json::from_str::<serde_json::Value>(&challenge_data) {
            let challenge_type_str = challenge_json["type"].as_str().unwrap_or("md5");

            match challenge_type_str {
                "web" => {
                    // Handle Web challenge verification through plugin
                    if let (Some(plugin_id), Some(plugin_result)) = (
                        challenge_json["plugin_id"].as_str(),
                        challenge_json["plugin_result"].as_object(),
                    ) {
                        let verify_data = serde_json::json!({
                            "session_id": req.sid,
                            "resource_id": resid,
                            "user_response": req.challenge,
                            "original_result": plugin_result,
                        });

                        match runner
                            .run_challenge_plugin(
                                plugin_id,
                                "verify",
                                verify_data,
                                serde_json::json!({}),
                            )
                            .await
                        {
                            Ok(verification_result) => {
                                let verification_success = verification_result
                                    .get("success")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);

                                if !verification_success {
                                    if config_guard.debug_mode {
                                        debug!("Web challenge failed but allowing in debug mode");
                                        debug!("Plugin ID: {}", plugin_id);
                                        debug!("User Response: {}", req.challenge);
                                        debug!("Verification Result: {}", verification_result);
                                    } else {
                                        return (
                                            StatusCode::PAYMENT_REQUIRED,
                                            Json(ApiResponse::error(
                                                "Web challenge verification failed".to_string(),
                                            )),
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Failed to verify web challenge with plugin {}: {}",
                                    plugin_id, e
                                );
                                if !config_guard.debug_mode {
                                    return (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        Json(ApiResponse::error(
                                            "Web challenge verification error".to_string(),
                                        )),
                                    );
                                } else {
                                    debug!(
                                        "Web challenge verification error but allowing in debug mode: {}",
                                        e
                                    );
                                }
                            }
                        }
                    } else {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse::error("Invalid web challenge data".to_string())),
                        );
                    }
                }
                _ => {
                    // Handle MD5/SHA256 challenges as before
                    if let (Some(hash), Some(partial_data), Some(original_data_hex)) = (
                        challenge_json["hash"].as_str(),
                        challenge_json["partial_data"].as_str(),
                        challenge_json["original_data"].as_str(),
                    ) {
                        let challenge_type = match challenge_type_str {
                            "md5" => ChallengeType::Md5,
                            "sha256" => ChallengeType::Sha256,
                            _ => ChallengeType::Md5,
                        };

                        let original_data = hex::decode(original_data_hex).unwrap_or_default();
                        let stored_challenge = crate::challenge::Challenge {
                            challenge_type,
                            hash: hash.to_string(),
                            partial_data: partial_data.to_string(),
                            missing_bytes: challenge_json["missing_bytes"].as_u64().unwrap_or(2)
                                as u8,
                            original_data,
                        };

                        // Verify the challenge response or skip in debug mode
                        let verification_success = stored_challenge.verify(&req.challenge);

                        if !verification_success.success {
                            // In debug mode, provide helpful debug information
                            if config_guard.debug_mode {
                                let expected_answer = hex::encode(&stored_challenge.original_data);

                                // In debug mode, allow the challenge to pass anyway but log debug info
                                debug!("Challenge failed but allowing in debug mode");
                                debug!("Challenge Type: {}", challenge_type_str);
                                debug!("Submitted: {}", req.challenge);
                                debug!("Expected: {}", stored_challenge.get_expected());
                                debug!("Hash: {}", stored_challenge.hash);
                                debug!("Partial Data: {}", stored_challenge.partial_data);
                            } else {
                                return (
                                    StatusCode::PAYMENT_REQUIRED,
                                    Json(ApiResponse::error(
                                        "Invalid challenge response".to_string(),
                                    )),
                                );
                            }
                        }
                    } else {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse::error("Invalid challenge data".to_string())),
                        );
                    }
                }
            }

            // Remove challenge after verification (successful or debug skip)
            let _ = redis.remove_challenge(&req.sid).await;
        } else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Failed to parse challenge data".to_string(),
                )),
            );
        }
    } else {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(ApiResponse::error(
                "Challenge not found or expired".to_string(),
            )),
        );
    }

    let session = Session {
        path,
        chunks: req.chunks.clone(),
        cdn_records: HashMap::new(),
    };

    if let Err(e) = redis.store_session(&req.sid, &session).await {
        error!("Failed to store session in Redis: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Failed to create session".to_string())),
        );
    }

    // 获取测试服务器列表（使用会话的路径）
    let tries = match generate_session_tries(&config_guard, &resid, &session.path, &redis).await {
        Ok(tries) => tries,
        Err(e) => {
            error!("Failed to generate session tries: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(format!(
                    "Failed to generate server list: {}",
                    e
                ))),
            );
        }
    };

    (
        StatusCode::OK,
        Json(ApiResponse::success(ResponseData::Session {
            tries,
            sid: req.sid.clone(),
        })),
    )
}

#[allow(unused_variables)]
async fn get_cdn(
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Path((sessionid, resid)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip =
        crate::modules::geolocation::extract_client_ip(&headers).or_else(|| Some(real_connect_info.remote_addr.ip()));

    let session = match redis.get_session(&sessionid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("Session not found".to_string())),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("Failed to access session".to_string())),
            );
        }
    };

    if let Some(range_str) = params.get("range") {
        match redis.increment_download_count(&sessionid, range_str).await {
            Ok(Some(count)) => {
                // 刷新会话过期时间
                if let Err(e) = redis.refresh_session(&sessionid).await {
                    warn!("Failed to refresh session: {}", e);
                }

                if count > *MAX_CHUNK_DOWNLOADS {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(ApiResponse::error("Too many download attempts".to_string())),
                    );
                }

                // 读锁访问配置
                let config_guard = config.read().await;
                let res = config_guard.get_resource(&resid);

                let res = match res {
                    Some(resource) => resource,
                    None => {
                        return (
                            StatusCode::NOT_FOUND,
                            Json(ApiResponse::error(format!("Resource {} not found", resid))),
                        );
                    }
                };
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
                    Some(parsed_ranges)
                } else {
                    // Single range: "0-255"
                    if let Some((start_str, end_str)) = range_str.split_once('-') {
                        if let (Ok(start), Ok(end)) =
                            (start_str.parse::<u32>(), end_str.parse::<u32>())
                        {
                            Some(vec![(start, end)])
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

                // run flow
                let flow_list = &res.flow;

                // 计算文件大小：根据ranges计算总大小
                let file_size = if let Some(ref ranges) = ranges {
                    // 计算所有ranges的总大小
                    Some(
                        ranges
                            .iter()
                            .map(|(start, end)| (end - start + 1) as u64)
                            .sum(),
                    )
                } else {
                    None
                };

                let mut params = RunFlowParams {
                    path: session.path.clone(),
                    ranges,
                    extras: serde_json::json!({}),
                    session_id: Some(sessionid.clone()),
                    client_ip, // 传递客户端IP信息用于流规则判断
                    file_size, // 根据ranges计算出的文件大小
                    plugin_server_mapping: HashMap::new(), // 初始化插件服务器映射
                    resource_id: resid.clone(),            // 新增：资源ID
                    sub_path: None,                        // 对于普通文件资源，子路径为None
                    selected_server_id: None,              // 初始化为None，由poolize函数设置
                    selected_server_weight: None,          // 初始化为None，由poolize函数设置
                };
                let flow_res = runner.run_flow(flow_list, &mut params).await;
                let cdn_url = match flow_res {
                    Ok(url) => url,
                    Err(e) => {
                        error!("Failed to run flow: {}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse::error("Failed to process request".to_string())),
                        );
                    }
                };

                return (
                    StatusCode::OK,
                    Json(ApiResponse::success(ResponseData::Cdn { url: cdn_url })),
                );
            }
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error("Invalid chunk range".to_string())),
                );
            }
            Err(e) => {
                error!("Failed to increment download count: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error("Failed to process request".to_string())),
                );
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

#[allow(unused_variables)]
async fn delete_session(
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Path((resid, sessionid)): Path<(String, String)>,
    req_body: Option<Json<DeleteSessionRequest>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 在删除之前获取会话统计信息
    match redis.get_session_stats(&sessionid).await {
        Ok(Some(stats)) => {
            // 如果有客户端IP，记录结构化日志
            if let Some(ip) = client_ip {
                let session_logger = crate::analytics::SessionLogger::new(config.clone(), redis.clone());
                let insights = req_body.as_ref().and_then(|Json(req)| req.insights.as_ref());
                let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
                
                if let Err(e) = session_logger.log_session_completed(&sessionid, &resid, ip, user_agent, insights.cloned()).await {
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
                        "path": stats.path,
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
                        "path": stats.path,
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
                    "path": stats.path,
                    "chunks": stats.chunks,
                    "download_counts": stats.download_counts,
                    "cdn_records": stats.cdn_records,
                })
            };

            info!("Session completed: {}", complete_stats);

            // 更新流量统计（基于会话完成情况）
            update_session_bandwidth_stats(&redis, &sessionid, &resid, &stats).await;

            // 删除会话
            if let Err(e) = redis.remove_session(&sessionid).await {
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

// 共享下载逻辑函数
async fn handle_download_request(
    resid: String,
    session_id: Option<String>,
    config: Arc<RwLock<AppConfig>>,
    redis: DataStore,
    runner: FlowRunner,
    client_ip: Option<std::net::IpAddr>,
    user_agent: Option<String>,
) -> DfsResult<DownloadResponse> {
    let config_guard = config.read().await;
    
    // 检查资源是否存在
    let resource_config = config_guard.get_resource(&resid)
        .ok_or_else(|| DfsError::resource_not_found(&resid))?;
    
    // 保存原始 session_id 用于后续销毁
    let original_session_id = session_id.clone();
    
    // 检查下载策略
    match &resource_config.download {
        DownloadPolicy::Disabled => {
            return Err(DfsError::download_not_allowed(
                &resid,
                "download is disabled for this resource",
            ));
        }
        DownloadPolicy::Free => {
            // 无需 session 验证，直接生成下载链接
        }
        DownloadPolicy::Enabled => {
            // 需要验证 session
            let session_id = session_id.as_ref().ok_or_else(|| {
                DfsError::download_not_allowed(&resid, "session parameter is required")
            })?;
            
            // 获取 session
            let session = redis.get_session(session_id).await.map_err(|e| {
                DfsError::redis_error("get_session", e.to_string())
            })?;
            
            let session = session.ok_or_else(|| {
                DfsError::SessionNotFound { session_id: session_id.clone() }
            })?;
            
            // 验证 chunks 包含 "0-"
            let has_zero_range = session.chunks.iter().any(|chunk| chunk.starts_with("0-"));
            if !has_zero_range {
                return Err(DfsError::download_not_allowed(
                    &resid,
                    "chunks must contain '0-' range for download",
                ));
            }
        }
    }
    
    // 获取版本对应的默认路径
    let version = &resource_config.latest;
    let path = config_guard
        .get_version_path(&resid, version, None)
        .ok_or_else(|| DfsError::path_not_found(&resid, version))?;
    
    // 尝试从任一服务器获取文件大小（用于Size条件评估）
    let file_size = {
        let mut size_candidate = None;
        for server_id in &resource_config.server {
            if let Ok(Some(health_info)) = redis.get_health_info(server_id, &path).await {
                if let Some(size) = health_info.file_size {
                    size_candidate = Some(size);
                    break;
                }
            }
        }
        size_candidate
    };
    
    // 使用流系统生成下载 URL（完整文件下载）
    let mut params = RunFlowParams {
        path,
        ranges: None, // 完整文件下载
        extras: serde_json::json!({}),
        session_id: original_session_id.clone(),
        client_ip,
        file_size, // 从健康检查获取的文件大小，用于Size条件评估
        plugin_server_mapping: HashMap::new(), // 初始化插件服务器映射
        resource_id: resid.clone(),            // 新增：资源ID
        sub_path: None,                        // 下载时暂不支持子路径参数
        selected_server_id: None,              // 初始化为None，由poolize函数设置
        selected_server_weight: None,          // 初始化为None，由poolize函数设置
    };
    
    let flow_list = &resource_config.flow;
    let cdn_url = runner.run_flow(flow_list, &mut params).await.map_err(|e| {
        error!("Failed to run flow for download: {}", e);
        DfsError::internal_error(format!("Failed to generate download URL: {}", e))
    })?;
    
    // 检查是否应该缓存
    if let Some((file_size, max_age)) = should_cache_content(
        &config_guard, &redis, &resid, None, // sub_path为None，这是普通文件下载
        params.selected_server_id.as_deref().unwrap_or("unknown"), 
        &params.path
    ).await {
        if file_size < 100 * 1024 { // 100KB限制
            // 检查缓存
            if let Ok(Some((metadata, content))) = redis.get_full_cached_content(
                &resid, &version, &params.path
            ).await {
                // 记录缓存命中日志
                if matches!(resource_config.download, DownloadPolicy::Free) {
                    if let Some(ip) = client_ip {
                        let session_logger = crate::analytics::SessionLogger::new(config.clone(), redis.clone());
                        if let Err(e) = session_logger.log_cached_download(
                            &resid,
                            &version,
                            &params.path,
                            ip,
                            user_agent.clone(),
                            metadata.content_length,
                            metadata.max_age,
                            &metadata.etag,
                        ).await {
                            error!("Failed to log cached download: {}", e);
                        }
                    }
                }
                
                // 缓存命中时更新流量统计
                let file_size = metadata.content_length;
                if let Some(ref session_id) = original_session_id {
                    if let Err(e) = redis.update_daily_bandwidth(session_id, file_size).await {
                        warn!("Failed to update daily bandwidth for cached download session {}: {}", session_id, e);
                    }
                }
                
                // 注意：缓存下载没有特定的server_id，我们不更新server级别的流量统计
                debug!("Updated bandwidth stats for cached download: file_size={}, session_id={:?}", 
                       file_size, original_session_id);
                
                return Ok(DownloadResponse::Cached { content, metadata });
            }
            
            // 下载并缓存
            if let Ok((metadata, content)) = download_and_cache(
                &cdn_url, &resid, &version, &params.path, &redis, max_age
            ).await {
                return Ok(DownloadResponse::Cached { content, metadata });
            }
        }
    }
    
    // 如果是 Free 模式，记录直接下载日志
    if matches!(resource_config.download, DownloadPolicy::Free) {
        if let Some(ip) = client_ip {
            let session_logger = crate::analytics::SessionLogger::new(config.clone(), redis.clone());
            // 使用选中的服务器ID和权重，如果没有则使用默认值
            let server_id = params.selected_server_id
                .as_deref()
                .unwrap_or("unknown");
            let server_weight = params.selected_server_weight.unwrap_or(10);
            
            if let Err(e) = session_logger.log_direct_download(
                &resid,
                version,
                &params.path,
                ip,
                user_agent.clone(),
                &cdn_url,
                server_id,
                server_weight,
            ).await {
                error!("Failed to log direct download: {}", e);
            }
        }
    }
    
    // 如果是 enabled 模式且有 session，销毁 session
    if matches!(resource_config.download, DownloadPolicy::Enabled) {
        if let Some(ref sid) = original_session_id {
            if let Err(e) = redis.remove_session(sid).await {
                warn!("Failed to remove session after download: {}", e);
            } else {
                info!("Session {} destroyed after download", sid);
            }
        }
    }
    
    // 更新流量统计（在成功生成下载URL后）
    if let Some(server_id) = &params.selected_server_id {
        // 尝试从健康检查缓存获取文件大小
        if let Ok(Some(health_info)) = redis.get_health_info(server_id, &params.path).await {
            if let Some(file_size) = health_info.file_size {
                // 更新session级别的流量统计（如果有session_id）
                if let Some(ref session_id) = original_session_id {
                    if let Err(e) = redis.update_daily_bandwidth(session_id, file_size).await {
                        warn!("Failed to update daily bandwidth for session {}: {}", session_id, e);
                    }
                }
                
                // 更新server级别的流量统计
                if let Err(e) = redis.update_server_daily_bandwidth(server_id, file_size).await {
                    warn!("Failed to update server daily bandwidth for {}: {}", server_id, e);
                }
                
                debug!("Updated bandwidth stats: file_size={}, server_id={}, session_id={:?}", 
                       file_size, server_id, original_session_id);
            }
        }
    }
    
    Ok(DownloadResponse::Redirect(cdn_url))
}

// GET /download/{resid} - 重定向到下载链接
async fn download_redirect(
    Path(resid): Path<String>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));
    
    // 获取 session 参数
    let session_id = params.get("session").map(|s| s.clone());
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    
    match handle_download_request(resid, session_id, config, redis, runner, client_ip, user_agent).await {
        Ok(DownloadResponse::Cached { content, metadata }) => {
            let remaining_max_age = metadata.remaining_max_age();
            
            let mut headers = HeaderMap::new();
            headers.insert("cache-control", format!("public, max-age={}", remaining_max_age).parse().unwrap());
            headers.insert("etag", metadata.etag.parse().unwrap());
            headers.insert("x-cache", "HIT".parse().unwrap());
            headers.insert("content-length", metadata.content_length.to_string().parse().unwrap());
            
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
            let status_code = StatusCode::from_u16(e.http_status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status_code, Json(ApiResponse::error(e.to_string()))).into_response()
        }
    }
}

// POST /download/{resid} - 返回下载链接到响应体
async fn download_json(
    Path(resid): Path<String>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));
    
    // 获取 session 参数
    let session_id = params.get("session").map(|s| s.clone());
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    
    match handle_download_request(resid, session_id, config, redis, runner, client_ip, user_agent).await {
        Ok(DownloadResponse::Cached { content, metadata }) => {
            // 对于JSON响应，返回base64编码的内容和元数据
            let content_base64 = general_purpose::STANDARD.encode(&content);
            let response_data = serde_json::json!({
                "cached": true,
                "content": content_base64,
                "content_type": metadata.content_type,
                "etag": metadata.etag,
                "max_age": metadata.remaining_max_age(),
                "size": metadata.content_length
            });
            (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Raw(response_data))),
            )
        }
        Ok(DownloadResponse::Redirect(download_url)) => (
            StatusCode::OK,
            Json(ApiResponse::success(ResponseData::Download {
                url: download_url,
            })),
        ),
        Err(e) => {
            let status_code = StatusCode::from_u16(e.http_status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status_code, Json(ApiResponse::error(e.to_string())))
        }
    }
}

#[allow(unused_variables)]
async fn get_prefix_metadata(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(runner): Extension<FlowRunner>,
    Extension(redis): Extension<DataStore>,
) -> impl IntoResponse {
    // 读锁访问配置
    let config_guard = config.read().await;

    // 检查资源是否存在且为前缀类型
    let resource_config = match config_guard.get_resource(&resid) {
        Some(rc) if rc.resource_type == "prefix" => rc,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Resource is not a prefix type".to_string())),
            );
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error(E_RESOURCE_NOT_FOUND.to_string())),
            );
        }
    };

    // 获取完整文件路径
    let version = &resource_config.latest;
    let full_path = match config_guard.get_version_path_with_sub(&resid, version, None, Some(&sub_path)) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(E_PATH_NOT_FOUND.to_string())),
            );
        }
    };

    // 生成缓存key（基于完整路径）
    let cache_key = if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
        if !prefix.is_empty() {
            format!("{}:kachina_meta:{}", prefix, full_path)
        } else {
            format!("kachina_meta:{}", full_path)
        }
    } else {
        format!("kachina_meta:{}", full_path)
    };

    // 先检查缓存
    if let Ok(Some(cached_data)) = redis.get_cached_metadata(&cache_key).await {
        if let Ok(cached_json) = serde_json::from_str::<serde_json::Value>(&cached_data) {
            return (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Metadata {
                    dfs_version: "1.0.0".to_string(),
                    name: format!("resource-{}/{}", resid, sub_path),
                    data: cached_json,
                })),
            );
        }
    }

    // 使用 kachina 模块解析文件（使用完整路径）
    match kachina::parse_kachina_metadata(&config, &runner, &resid, Some(&full_path)).await {
        Ok(Some(metadata)) => {
            let response_data = json!({
                "index": metadata.index,
                "metadata": metadata.metadata,
                "installer_end": metadata.installer_end
            });

            // 缓存解析结果
            if let Ok(cache_value) = serde_json::to_string(&response_data) {
                if let Err(e) = redis
                    .set_cached_metadata(&cache_key, &cache_value, 3600)
                    .await
                {
                    warn!("Failed to cache prefix metadata: {}", e);
                }
            }

            (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Metadata {
                    dfs_version: "1.0.0".to_string(),
                    name: format!("resource-{}/{}", resid, sub_path),
                    data: response_data,
                })),
            )
        }
        Ok(None) => {
            let null_data = json!(null);

            // 缓存 null 结果
            if let Ok(cache_value) = serde_json::to_string(&null_data) {
                if let Err(e) = redis
                    .set_cached_metadata(&cache_key, &cache_value, 3600)
                    .await
                {
                    warn!("Failed to cache null prefix metadata: {}", e);
                }
            }

            (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Metadata {
                    dfs_version: "1.0.0".to_string(),
                    name: format!("resource-{}/{}", resid, sub_path),
                    data: null_data,
                })),
            )
        }
        Err(error_msg) => {
            error!("Failed to parse prefix kachina metadata: {}", error_msg);
            let status_code = if error_msg.starts_with(E_RESOURCE_NOT_FOUND)
                || error_msg.starts_with(E_VERSION_NOT_FOUND)
            {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status_code, Json(ApiResponse::error(error_msg)))
        }
    }
}

#[allow(unused_variables)]
#[axum::debug_handler]
async fn create_prefix_session(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Json(mut req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    // 读锁访问配置
    let config_guard = config.read().await;

    // 检查资源是否存在且为前缀类型
    let resource_config = match config_guard.get_resource(&resid) {
        Some(rc) if rc.resource_type == "prefix" => rc,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error("Resource is not a prefix type".to_string())),
            );
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error(format!("资源 {} 不存在", resid))),
            );
        }
    };

    // 使用配置文件中的版本路径
    let version = if req.version.is_empty() || req.version == "latest" {
        resource_config.latest.as_str()
    } else {
        req.version.as_str()
    };

    // 检查版本是否存在
    if !resource_config.versions.contains_key(version) {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(format!("版本 {} 不存在", version))),
        );
    }

    // 获取完整文件路径（前缀 + 子路径）
    let full_path = match config_guard.get_version_path_with_sub(&resid, version, None, Some(&sub_path)) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("无法构建资源路径".to_string())),
            );
        }
    };

    if req.sid.is_empty() {
        req.sid = Uuid::new_v4().to_string();
    }

    if req.challenge.is_empty() {
        // 挑战生成逻辑与原函数相同，但使用完整路径和前缀资源信息
        let config_guard = config.read().await;
        let challenge_config = config_guard.get_challenge_config(&resid);
        
        let base_data = format!("data/{}/{}/{}", resid, sub_path, req.sid);
        let challenge_type = challenge_config.get_effective_type();
        
        let generation_config = crate::challenge::ChallengeConfig {
            challenge_type,
            difficulty: if challenge_type == ChallengeType::Sha256 {
                challenge_config.get_sha256_difficulty()
            } else {
                2
            },
        };
        
        let challenge = generate_challenge(&generation_config, &base_data);

        // Web challenges 处理逻辑与原函数相同
        if challenge.challenge_type == ChallengeType::Web {
            let web_plugin_id = &challenge_config.web_plugin;

            let challenge_data = serde_json::json!({
                "session_id": req.sid,
                "resource_id": resid,
                "sub_path": sub_path,
                "base_data": base_data,
            });

            match runner
                .run_challenge_plugin(
                    &web_plugin_id,
                    "generate",
                    challenge_data,
                    serde_json::json!({}),
                )
                .await
            {
                Ok(plugin_result) => {
                    if let Some(verification_url) =
                        plugin_result.get("url").and_then(|v| v.as_str())
                    {
                        let web_challenge_json = serde_json::json!({
                            "type": "web",
                            "plugin_id": web_plugin_id,
                            "plugin_result": plugin_result,
                            "verification_url": verification_url,
                        });

                        if let Err(e) = redis
                            .store_challenge(&req.sid, &web_challenge_json.to_string())
                            .await
                        {
                            error!("Failed to store web challenge: {}", e);
                        }

                        return (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(ApiResponse::Success(ResponseData::Challenge {
                                challenge: "web".to_string(),
                                data: verification_url.to_string(),
                                sid: req.sid,
                            })),
                        );
                    } else {
                        // Fallback 逻辑...
                        let fallback_config = crate::challenge::ChallengeConfig {
                            challenge_type: ChallengeType::Md5,
                            difficulty: 2,
                        };
                        let fallback_challenge = generate_challenge(&fallback_config, &base_data);

                        let challenge_json = serde_json::json!({
                            "type": "md5",
                            "hash": fallback_challenge.hash,
                            "partial_data": fallback_challenge.partial_data,
                            "missing_bytes": fallback_challenge.missing_bytes,
                            "original_data": hex::encode(&fallback_challenge.original_data),
                        });

                        if let Err(e) = redis
                            .store_challenge(&req.sid, &challenge_json.to_string())
                            .await
                        {
                            error!("Failed to store fallback challenge: {}", e);
                        }

                        return (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(ApiResponse::Success(ResponseData::Challenge {
                                challenge: "md5".to_string(),
                                data: fallback_challenge.format_data(),
                                sid: req.sid,
                            })),
                        );
                    }
                }
                Err(e) => {
                    error!("Failed to run web challenge plugin {}: {}", web_plugin_id, e);
                    // Fallback to MD5
                    let fallback_config = crate::challenge::ChallengeConfig {
                        challenge_type: ChallengeType::Md5,
                        difficulty: 2,
                    };
                    let fallback_challenge = generate_challenge(&fallback_config, &base_data);

                    let challenge_json = serde_json::json!({
                        "type": "md5",
                        "hash": fallback_challenge.hash,
                        "partial_data": fallback_challenge.partial_data,
                        "missing_bytes": fallback_challenge.missing_bytes,
                        "original_data": hex::encode(&fallback_challenge.original_data),
                    });

                    if let Err(e) = redis
                        .store_challenge(&req.sid, &challenge_json.to_string())
                        .await
                    {
                        error!("Failed to store fallback challenge: {}", e);
                    }

                    return (
                        StatusCode::PAYMENT_REQUIRED,
                        Json(ApiResponse::Success(ResponseData::Challenge {
                            challenge: "md5".to_string(),
                            data: fallback_challenge.format_data(),
                            sid: req.sid,
                        })),
                    );
                }
            }
        }

        // 存储非 Web 挑战
        let challenge_json = serde_json::json!({
            "type": match challenge.challenge_type {
                ChallengeType::Md5 => "md5",
                ChallengeType::Sha256 => "sha256",
                ChallengeType::Web => "web",
            },
            "hash": challenge.hash,
            "partial_data": challenge.partial_data,
            "missing_bytes": challenge.missing_bytes,
            "original_data": hex::encode(&challenge.original_data),
        });

        if let Err(e) = redis
            .store_challenge(&req.sid, &challenge_json.to_string())
            .await
        {
            error!("Failed to store challenge: {}", e);
        }

        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(ApiResponse::Success(ResponseData::Challenge {
                challenge: match challenge.challenge_type {
                    ChallengeType::Md5 => "md5".to_string(),
                    ChallengeType::Sha256 => "sha256".to_string(),
                    ChallengeType::Web => "web".to_string(),
                },
                data: challenge.format_data(),
                sid: req.sid,
            })),
        );
    }

    // 验证挑战响应（与原函数相同的逻辑）
    if let Ok(Some(challenge_data)) = redis.get_challenge(&req.sid).await {
        if let Ok(challenge_json) = serde_json::from_str::<serde_json::Value>(&challenge_data) {
            let challenge_type_str = challenge_json["type"].as_str().unwrap_or("md5");

            match challenge_type_str {
                "web" => {
                    // Web 挑战验证...
                    if let (Some(plugin_id), Some(plugin_result)) = (
                        challenge_json["plugin_id"].as_str(),
                        challenge_json["plugin_result"].as_object(),
                    ) {
                        let verify_data = serde_json::json!({
                            "session_id": req.sid,
                            "resource_id": resid,
                            "sub_path": sub_path,
                            "user_response": req.challenge,
                            "original_result": plugin_result,
                        });

                        match runner
                            .run_challenge_plugin(
                                plugin_id,
                                "verify",
                                verify_data,
                                serde_json::json!({}),
                            )
                            .await
                        {
                            Ok(verification_result) => {
                                let verification_success = verification_result
                                    .get("success")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);

                                if !verification_success && !config_guard.debug_mode {
                                    return (
                                        StatusCode::PAYMENT_REQUIRED,
                                        Json(ApiResponse::error(
                                            "Web challenge verification failed".to_string(),
                                        )),
                                    );
                                }
                            }
                            Err(e) => {
                                error!("Failed to verify web challenge: {}", e);
                                if !config_guard.debug_mode {
                                    return (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        Json(ApiResponse::error(
                                            "Web challenge verification error".to_string(),
                                        )),
                                    );
                                }
                            }
                        }
                    } else {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse::error("Invalid web challenge data".to_string())),
                        );
                    }
                }
                _ => {
                    // MD5/SHA256 挑战验证...
                    if let (Some(hash), Some(partial_data), Some(original_data_hex)) = (
                        challenge_json["hash"].as_str(),
                        challenge_json["partial_data"].as_str(),
                        challenge_json["original_data"].as_str(),
                    ) {
                        let challenge_type = match challenge_type_str {
                            "md5" => ChallengeType::Md5,
                            "sha256" => ChallengeType::Sha256,
                            _ => ChallengeType::Md5,
                        };

                        let original_data = hex::decode(original_data_hex).unwrap_or_default();
                        let stored_challenge = crate::challenge::Challenge {
                            challenge_type,
                            hash: hash.to_string(),
                            partial_data: partial_data.to_string(),
                            missing_bytes: challenge_json["missing_bytes"].as_u64().unwrap_or(2) as u8,
                            original_data,
                        };

                        let verification_success = stored_challenge.verify(&req.challenge);

                        if !verification_success.success && !config_guard.debug_mode {
                            return (
                                StatusCode::PAYMENT_REQUIRED,
                                Json(ApiResponse::error(
                                    "Invalid challenge response".to_string(),
                                )),
                            );
                        }

                        if config_guard.debug_mode && !verification_success.success {
                            debug!("Challenge failed but allowing in debug mode");
                            debug!("Challenge Type: {}", challenge_type_str);
                            debug!("Submitted: {}", req.challenge);
                            debug!("Expected: {}", stored_challenge.get_expected());
                        }
                    } else {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse::error("Invalid challenge data".to_string())),
                        );
                    }
                }
            }

            // 移除挑战
            let _ = redis.remove_challenge(&req.sid).await;
        } else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(
                    "Failed to parse challenge data".to_string(),
                )),
            );
        }
    } else {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(ApiResponse::error(
                "Challenge not found or expired".to_string(),
            )),
        );
    }

    // 创建会话（使用完整文件路径）
    let session = Session {
        path: full_path.clone(),
        chunks: req.chunks.clone(),
        cdn_records: HashMap::new(),
    };

    if let Err(e) = redis.store_session(&req.sid, &session).await {
        error!("Failed to store session in Redis: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Failed to create session".to_string())),
        );
    }

    // 生成服务器尝试列表（使用完整文件路径进行健康检查）
    let tries = match generate_session_tries(&config_guard, &resid, &full_path, &redis).await {
        Ok(tries) => tries,
        Err(e) => {
            error!("Failed to generate session tries: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(format!(
                    "Failed to generate server list: {}",
                    e
                ))),
            );
        }
    };

    (
        StatusCode::OK,
        Json(ApiResponse::success(ResponseData::Session {
            tries,
            sid: req.sid.clone(),
        })),
    )
}

// 共享前缀下载逻辑函数
async fn handle_prefix_download_request(
    resid: String,
    sub_path: String,
    session_id: Option<String>,
    config: Arc<RwLock<AppConfig>>,
    redis: DataStore,
    runner: FlowRunner,
    client_ip: Option<std::net::IpAddr>,
    user_agent: Option<String>,
) -> DfsResult<DownloadResponse> {
    let config_guard = config.read().await;
    
    // 检查资源是否存在且为前缀类型
    let resource_config = match config_guard.get_resource(&resid) {
        Some(rc) if rc.resource_type == "prefix" => rc,
        Some(_) => {
            return Err(DfsError::download_not_allowed(
                &resid,
                "resource is not a prefix type",
            ));
        }
        None => {
            return Err(DfsError::resource_not_found(&resid));
        }
    };
    
    // 保存原始 session_id 用于后续销毁
    let original_session_id = session_id.clone();
    
    // 检查下载策略
    match &resource_config.download {
        DownloadPolicy::Disabled => {
            return Err(DfsError::download_not_allowed(
                &resid,
                "download is disabled for this resource",
            ));
        }
        DownloadPolicy::Free => {
            // 无需 session 验证，直接生成下载链接
        }
        DownloadPolicy::Enabled => {
            // 需要验证 session
            let session_id = session_id.as_ref().ok_or_else(|| {
                DfsError::download_not_allowed(&resid, "session parameter is required")
            })?;
            
            // 获取 session
            let session = redis.get_session(session_id).await.map_err(|e| {
                DfsError::redis_error("get_session", e.to_string())
            })?;
            
            let session = session.ok_or_else(|| {
                DfsError::SessionNotFound { session_id: session_id.clone() }
            })?;
            
            // 验证会话路径是否匹配请求的文件
            let version = &resource_config.latest;
            let expected_path = config_guard
                .get_version_path_with_sub(&resid, version, None, Some(&sub_path))
                .ok_or_else(|| DfsError::path_not_found(&resid, version))?;
                
            if session.path != expected_path {
                return Err(DfsError::download_not_allowed(
                    &resid,
                    "session path does not match requested file",
                ));
            }
            
            // 验证 chunks 包含 "0-"
            let has_zero_range = session.chunks.iter().any(|chunk| chunk.starts_with("0-"));
            if !has_zero_range {
                return Err(DfsError::download_not_allowed(
                    &resid,
                    "chunks must contain '0-' range for download",
                ));
            }
        }
    }
    
    // 获取完整文件路径
    let version = &resource_config.latest;
    let full_path = config_guard
        .get_version_path_with_sub(&resid, version, None, Some(&sub_path))
        .ok_or_else(|| DfsError::path_not_found(&resid, version))?;
    
    // 尝试从任一服务器获取文件大小（用于Size条件评估）
    let file_size = {
        let mut size_candidate = None;
        for server_id in &resource_config.server {
            if let Ok(Some(health_info)) = redis.get_health_info(server_id, &full_path).await {
                if let Some(size) = health_info.file_size {
                    size_candidate = Some(size);
                    break;
                }
            }
        }
        size_candidate
    };
    
    // 使用流系统生成下载 URL（完整文件下载）
    let mut params = RunFlowParams {
        path: full_path,
        ranges: None, // 完整文件下载
        extras: serde_json::json!({}),
        session_id: original_session_id.clone(),
        client_ip,
        file_size, // 从健康检查获取的文件大小，用于Size条件评估
        plugin_server_mapping: HashMap::new(), // 初始化插件服务器映射
        resource_id: resid.clone(),            // 资源ID
        sub_path: Some(sub_path.clone()),              // 子路径
        selected_server_id: None,              // 初始化为None，由poolize函数设置
        selected_server_weight: None,          // 初始化为None，由poolize函数设置
    };
    
    let flow_list = &resource_config.flow;
    let cdn_url = runner.run_flow(flow_list, &mut params).await.map_err(|e| {
        error!("Failed to run flow for prefix download: {}", e);
        DfsError::internal_error(format!("Failed to generate download URL: {}", e))
    })?;
    
    // 检查是否应该缓存（前缀资源）
    if let Some((file_size, max_age)) = should_cache_content(
        &config_guard, &redis, &resid, Some(&sub_path), // 传入子路径用于模式匹配
        params.selected_server_id.as_deref().unwrap_or("unknown"), 
        &params.path
    ).await {
        if file_size < 100 * 1024 { // 100KB限制
            // 检查缓存
            if let Ok(Some((metadata, content))) = redis.get_full_cached_content(
                &resid, &version, &params.path
            ).await {
                // 记录缓存命中日志
                if matches!(resource_config.download, DownloadPolicy::Free) {
                    if let Some(ip) = client_ip {
                        let session_logger = crate::analytics::SessionLogger::new(config.clone(), redis.clone());
                        if let Err(e) = session_logger.log_cached_download(
                            &resid,
                            &version,
                            &params.path,
                            ip,
                            user_agent.clone(),
                            metadata.content_length,
                            metadata.max_age,
                            &metadata.etag,
                        ).await {
                            error!("Failed to log cached prefix download: {}", e);
                        }
                    }
                }
                
                // 缓存命中时更新流量统计
                let file_size = metadata.content_length;
                if let Some(ref session_id) = original_session_id {
                    if let Err(e) = redis.update_daily_bandwidth(session_id, file_size).await {
                        warn!("Failed to update daily bandwidth for cached prefix download session {}: {}", session_id, e);
                    }
                }
                
                debug!("Updated bandwidth stats for cached prefix download: file_size={}, session_id={:?}", 
                       file_size, original_session_id);
                
                return Ok(DownloadResponse::Cached { content, metadata });
            }
            
            // 下载并缓存
            if let Ok((metadata, content)) = download_and_cache(
                &cdn_url, &resid, &version, &params.path, &redis, max_age
            ).await {
                return Ok(DownloadResponse::Cached { content, metadata });
            }
        }
    }
    
    // 如果是 Free 模式，记录直接下载日志
    if matches!(resource_config.download, DownloadPolicy::Free) {
        if let Some(ip) = client_ip {
            let session_logger = crate::analytics::SessionLogger::new(config.clone(), redis.clone());
            // 使用选中的服务器ID和权重，如果没有则使用默认值
            let server_id = params.selected_server_id
                .as_deref()
                .unwrap_or("unknown");
            let server_weight = params.selected_server_weight.unwrap_or(10);
            
            if let Err(e) = session_logger.log_direct_download(
                &resid,
                version,
                &params.path,
                ip,
                user_agent.clone(),
                &cdn_url,
                server_id,
                server_weight,
            ).await {
                error!("Failed to log prefix direct download: {}", e);
            }
        }
    }
    
    // 如果是 enabled 模式且有 session，销毁 session
    if matches!(resource_config.download, DownloadPolicy::Enabled) {
        if let Some(ref sid) = original_session_id {
            if let Err(e) = redis.remove_session(sid).await {
                warn!("Failed to remove session after prefix download: {}", e);
            } else {
                info!("Session {} destroyed after prefix download", sid);
            }
        }
    }
    
    // 更新流量统计（在成功生成下载URL后）
    if let Some(server_id) = &params.selected_server_id {
        // 尝试从健康检查缓存获取文件大小
        if let Ok(Some(health_info)) = redis.get_health_info(server_id, &params.path).await {
            if let Some(file_size) = health_info.file_size {
                // 更新session级别的流量统计（如果有session_id）
                if let Some(ref session_id) = original_session_id {
                    if let Err(e) = redis.update_daily_bandwidth(session_id, file_size).await {
                        warn!("Failed to update daily bandwidth for session {}: {}", session_id, e);
                    }
                }
                
                // 更新server级别的流量统计
                if let Err(e) = redis.update_server_daily_bandwidth(server_id, file_size).await {
                    warn!("Failed to update server daily bandwidth for {}: {}", server_id, e);
                }
                
                debug!("Updated prefix download bandwidth stats: file_size={}, server_id={}, session_id={:?}", 
                       file_size, server_id, original_session_id);
            }
        }
    }
    
    Ok(DownloadResponse::Redirect(cdn_url))
}

// GET /download/{resid}/*sub_path - 重定向到下载链接
async fn download_prefix_redirect(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));
    
    // 获取 session 参数
    let session_id = params.get("session").map(|s| s.clone());
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    
    match handle_prefix_download_request(resid, sub_path, session_id, config, redis, runner, client_ip, user_agent).await {
        Ok(DownloadResponse::Cached { content, metadata }) => {
            let remaining_max_age = metadata.remaining_max_age();
            
            let mut headers = HeaderMap::new();
            headers.insert("cache-control", format!("public, max-age={}", remaining_max_age).parse().unwrap());
            headers.insert("etag", metadata.etag.parse().unwrap());
            headers.insert("x-cache", "HIT".parse().unwrap());
            headers.insert("content-length", metadata.content_length.to_string().parse().unwrap());
            
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
            let status_code = StatusCode::from_u16(e.http_status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status_code, Json(ApiResponse::error(e.to_string()))).into_response()
        }
    }
}

// POST /download/{resid}/*sub_path - 返回下载链接到响应体
async fn download_prefix_json(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));
    
    // 获取 session 参数
    let session_id = params.get("session").map(|s| s.clone());
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    
    match handle_prefix_download_request(resid, sub_path, session_id, config, redis, runner, client_ip, user_agent).await {
        Ok(DownloadResponse::Cached { content, metadata }) => {
            // 对于JSON响应，返回base64编码的内容和元数据
            let content_base64 = general_purpose::STANDARD.encode(&content);
            let response_data = serde_json::json!({
                "cached": true,
                "content": content_base64,
                "content_type": metadata.content_type,
                "etag": metadata.etag,
                "max_age": metadata.remaining_max_age(),
                "size": metadata.content_length
            });
            (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Raw(response_data))),
            )
        }
        Ok(DownloadResponse::Redirect(download_url)) => (
            StatusCode::OK,
            Json(ApiResponse::success(ResponseData::Download {
                url: download_url,
            })),
        ),
        Err(e) => {
            let status_code = StatusCode::from_u16(e.http_status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status_code, Json(ApiResponse::error(e.to_string())))
        }
    }
}

// 辅助函数：更新会话模式的流量统计
async fn update_session_bandwidth_stats(
    redis: &DataStore,
    session_id: &str,
    resource_id: &str,
    stats: &crate::data_store::SessionStats,
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
                        // 尝试从健康检查获取文件大小，如果无法获取则使用估算值
                        let estimated_chunk_size = if let Ok(Some(health_info)) = 
                            redis.get_health_info(server_id, &stats.path).await {
                            health_info.file_size.unwrap_or(1024 * 1024) // 默认1MB
                        } else {
                            1024 * 1024 // 默认1MB
                        };
                        
                        // 根据下载次数估算流量（通常一次成功即可）
                        let chunk_bandwidth = estimated_chunk_size.min(estimated_chunk_size * (*download_count as u64));
                        
                        // 累计到服务器使用量
                        *server_usage.entry(server_id.clone()).or_default() += chunk_bandwidth;
                        total_bandwidth += chunk_bandwidth;
                        
                        debug!("Session bandwidth calculation: chunk={}, server={}, size={}, downloads={}", 
                               chunk_id, server_id, chunk_bandwidth, download_count);
                    }
                }
            }
        }
    }
    
    // 更新session级别的流量统计
    if total_bandwidth > 0 {
        if let Err(e) = redis.update_daily_bandwidth(session_id, total_bandwidth).await {
            warn!("Failed to update session daily bandwidth for {}: {}", session_id, e);
        }
        
        // 更新各个服务器的流量统计
        let server_count = server_usage.len();
        for (server_id, bandwidth) in server_usage {
            if let Err(e) = redis.update_server_daily_bandwidth(&server_id, bandwidth).await {
                warn!("Failed to update server daily bandwidth for {}: {}", server_id, e);
            }
        }
        
        info!("Updated session bandwidth stats: session_id={}, resource_id={}, total_bandwidth={}, servers={}", 
              session_id, resource_id, total_bandwidth, server_count);
    }
}

pub fn routes() -> Router {
    Router::new()
        .route("/resource/{resid}", get(get_metadata).post(create_session))
        .route("/resource/{resid}/{*sub_path}", get(get_prefix_metadata).post(create_prefix_session))
        .route(
            "/session/{sessionid}/{resid}",
            get(get_cdn).delete(delete_session),
        )
        .route("/download/{resid}", get(download_redirect).post(download_json))
        .route("/download/{resid}/{*sub_path}", get(download_prefix_redirect).post(download_prefix_json))
}
