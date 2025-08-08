use axum::{
    Json, Router,
    extract::{Extension, Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::get,
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::cache::{download_and_cache, should_cache_content};
use crate::challenge::{ChallengeType, generate_challenge};
use crate::config::{AppConfig, DownloadPolicy};
use crate::data_store::BandwidthUpdateBatch;
use crate::data_store::CacheMetadata;
use crate::error::{DfsError, DfsResult};
use crate::legacy_client::LegacyClientHandler;
use crate::models::{CreateSessionRequest, DeleteSessionRequest, Session};
use crate::responses::{
    ApiResponse, CdnUrlResponse, ChallengeResponse, DownloadUrlResponse, EmptyResponse,
    ErrorResponse, MetadataResponse, ResponseData, SessionCreatedResponse,
};
use crate::{
    RealConnectInfo,
    app_state::{DataStore, MAX_CHUNK_DOWNLOADS},
    metrics::Metrics,
    modules::flow::runner::{FlowRunner, RunFlowParams},
    modules::thirdparty::kachina,
};

// 查询参数结构体
#[derive(Deserialize, Debug)]
struct MetadataQuery {
    /// 是否返回 kachina metadata (有参数 = 是, 未设置 = 否)
    with_metadata: Option<String>,
}

// 错误码常量定义
const E_RESOURCE_NOT_FOUND: &str = "E_RESOURCE_NOT_FOUND";
const E_VERSION_NOT_FOUND: &str = "E_VERSION_NOT_FOUND";

// 解析range字符串为flowrunner的ranges格式
// "0-" 或整个文件 -> None
// "1024-2047" 等具体范围 -> Some(vec![(start, end)])
fn parse_range_for_flow(range_str: &str) -> Option<Vec<(u32, u32)>> {
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
fn calculate_actual_bytes_from_range(range_str: Option<&str>, full_file_size: u64) -> u64 {
    if let Some(range_str) = range_str {
        if let Some(ranges) = parse_range_for_flow(range_str) {
            // 有具体range，计算range覆盖的字节数
            ranges
                .iter()
                .map(|(start, end)| {
                    let end_byte = if *end == u32::MAX {
                        // "X-" 格式，从start到文件结尾
                        full_file_size.saturating_sub(*start as u64)
                    } else {
                        // "X-Y" 格式，计算范围大小
                        (*end as u64).saturating_sub(*start as u64) + 1
                    };
                    end_byte
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
macro_rules! record_request_metrics {
    ($metrics:expr, $start_time:expr) => {
        $metrics.record_request();
        $metrics.record_request_duration($start_time.elapsed().as_secs_f64());
    };
}

// 宏用于记录流程执行指标
macro_rules! record_flow_metrics {
    ($metrics:expr, $success:expr) => {
        $metrics.record_flow_execution();
        if !$success {
            $metrics.record_flow_failure();
        }
    };
}

const E_PATH_NOT_FOUND: &str = "E_PATH_NOT_FOUND";

// 生成32位 hex 格式的 session ID
fn generate_hex_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

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
    _config: &AppConfig,
    _resid: &str,
    _file_path: &str,
    _redis: &DataStore,
) -> DfsResult<Vec<String>> {
    // 此函数已废弃，始终返回空数组
    Ok(Vec::new())
}

#[utoipa::path(
    get,
    path = "/resource/{resid}",
    tag = "Resource",
    summary = "Get resource metadata",
    description = "Retrieves metadata for a specific resource, including KachinaInstaller information if available",
    params(
        ("resid" = String, Path, description = "Resource identifier")
    ),
    responses(
        (status = 200, description = "Metadata retrieved successfully", body = MetadataResponse),
        (status = 404, description = "Resource not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[allow(unused_variables)]
async fn get_metadata(
    Path(resid): Path<String>,
    Query(query): Query<MetadataQuery>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(runner): Extension<FlowRunner>,
    Extension(redis): Extension<DataStore>,
    Extension(metrics): Extension<Arc<Metrics>>,
    Extension(version_cache): Extension<Arc<crate::modules::version_provider::VersionCache>>,
) -> impl IntoResponse {
    let start_time = std::time::Instant::now();

    // 检查是否请求 kachina metadata（有参数就是 true，无参数就是 false）
    let with_metadata = query.with_metadata.is_some();

    // 获取changelog（优先级：版本提供者 > 静态配置）
    let changelog = get_resource_changelog(&config, &version_cache, &resid).await;

    // 获取基本资源信息
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

    // 获取有效版本（考虑动态版本提供者）
    let effective_version = config_guard
        .get_effective_version_with_cache(&resid, Some(&version_cache))
        .await;

    // 如果不需要 kachina metadata，直接返回基本信息
    if !with_metadata {
        // 记录成功的请求指标
        record_request_metrics!(metrics, start_time);

        return (
            StatusCode::OK,
            Json(ApiResponse::success(ResponseData::Metadata {
                resource_version: effective_version,
                name: resid.clone(),
                changelog: changelog.clone(),
                data: json!(null), // 不返回 kachina metadata
            })),
        );
    }

    // 以下是 kachina metadata 处理逻辑
    let path = match config_guard.get_version_path(&resid, &effective_version, None) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(E_PATH_NOT_FOUND.to_string())),
            );
        }
    };

    let cache_key = if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
        if !prefix.is_empty() {
            format!("{}:kachina_meta:{}", prefix, path)
        } else {
            format!("kachina_meta:{}", path)
        }
    } else {
        format!("kachina_meta:{}", path)
    };

    drop(config_guard); // 释放配置锁

    // 先检查缓存
    if let Ok(Some(cached_data)) = redis.get_cached_metadata(&cache_key).await {
        if let Ok(cached_json) = serde_json::from_str::<serde_json::Value>(&cached_data) {
            return (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Metadata {
                    resource_version: effective_version.clone(),
                    name: resid.clone(),
                    changelog: changelog.clone(),
                    data: cached_json,
                })),
            );
        }
    }

    // 使用 kachina 模块解析 KachinaInstaller 文件
    match kachina::parse_kachina_metadata(&config, &runner, &resid, Some(&effective_version)).await {
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

            // 记录成功的请求指标
            record_request_metrics!(metrics, start_time);

            (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Metadata {
                    resource_version: effective_version.clone(),
                    name: resid.clone(),
                    changelog: changelog.clone(),
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

            // 记录成功的请求指标
            record_request_metrics!(metrics, start_time);

            (
                StatusCode::OK,
                Json(ApiResponse::success(ResponseData::Metadata {
                    resource_version: effective_version.clone(),
                    name: resid.clone(),
                    changelog: changelog.clone(),
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

            // 记录错误的请求指标
            record_request_metrics!(metrics, start_time);

            (status_code, Json(ApiResponse::error(error_msg)))
        }
    }
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
#[allow(unused_variables)]
#[axum::debug_handler]
async fn create_session(
    Path(resid): Path<String>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(metrics): Extension<Arc<Metrics>>,
    Extension(version_cache): Extension<Arc<crate::modules::version_provider::VersionCache>>,
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
        // 获取有效版本（考虑动态版本提供者）
        config_guard
            .get_effective_version_with_cache(&resid, Some(&version_cache))
            .await
    } else {
        req.version.clone()
    };

    // 检查版本是否存在或有default模板
    if !resource_config.versions.contains_key(&version)
        && !resource_config.versions.contains_key("default")
    {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(format!("版本 {} 不存在", version))),
        );
    }

    // 获取版本对应的默认路径
    let path = match config_guard.get_version_path(&resid, &version, None) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("无法获取资源路径".to_string())),
            );
        }
    };

    if req.sid.is_empty() {
        req.sid = generate_hex_session_id();
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
        resource_id: resid.clone(),
        version: version.clone(),
        chunks: req.chunks.clone(),
        cdn_records: HashMap::new(),
        extras: req.extras.clone(),
    };

    if let Err(e) = redis.store_session(&req.sid, &session).await {
        error!("Failed to store session in Redis: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Failed to create session".to_string())),
        );
    }

    // 获取测试服务器列表（使用会话的路径）
    let tries = vec![];

    // 记录会话创建指标
    metrics.record_session_created();

    (
        StatusCode::OK,
        Json(ApiResponse::success(ResponseData::Session {
            tries,
            sid: req.sid.clone(),
        })),
    )
}

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
#[allow(unused_variables)]
async fn get_cdn(
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    Extension(metrics): Extension<Arc<Metrics>>,
    headers: HeaderMap,
    Path((sessionid, resid)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 记录请求开始时间
    let start_time = std::time::Instant::now();

    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

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
                    ranges,
                    extras: session.extras.clone(),
                    session_id: Some(sessionid.clone()),
                    client_ip,                             // 传递客户端IP信息用于流规则判断
                    file_size,                             // 根据ranges计算出的文件大小
                    plugin_server_mapping: HashMap::new(), // 初始化插件服务器映射
                    resource_id: resid.clone(),
                    version: session.version.clone(),
                    sub_path: None,               // 对于普通文件资源，子路径为None
                    selected_server_id: None,     // 初始化为None，由poolize函数设置
                    selected_server_weight: None, // 初始化为None，由poolize函数设置
                    cdn_full_range: false,        // get_cdn接口不使用全范围模式
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

                // 记录成功的请求和流程执行指标
                record_request_metrics!(metrics, start_time);
                record_flow_metrics!(metrics, true);

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
async fn delete_session(
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    Extension(metrics): Extension<Arc<Metrics>>,
    headers: HeaderMap,
    Path((sessionid, resid)): Path<(String, String)>,
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
                let session_logger =
                    crate::analytics::SessionLogger::new(config.clone(), redis.clone());
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
    range: Option<String>,
    config: Arc<RwLock<AppConfig>>,
    redis: DataStore,
    runner: FlowRunner,
    client_ip: Option<std::net::IpAddr>,
    user_agent: Option<String>,
    metrics: Arc<Metrics>,
    version_cache: Arc<crate::modules::version_provider::VersionCache>,
) -> DfsResult<DownloadResponse> {
    let config_guard = config.read().await;

    // 检查资源是否存在
    let resource_config = config_guard
        .get_resource(&resid)
        .ok_or_else(|| DfsError::resource_not_found(&resid))?;

    // 保存原始 session_id 用于后续销毁
    let original_session_id = session_id.clone();

    // 提取 extras 信息用于 Flow 规则
    let extras = match &resource_config.download {
        DownloadPolicy::Disabled => {
            return Err(DfsError::download_not_allowed(
                &resid,
                "download is disabled for this resource",
            ));
        }
        DownloadPolicy::Free => {
            // 无需 session 验证，使用空 extras
            serde_json::json!({})
        }
        DownloadPolicy::Enabled => {
            // 需要验证 session
            let session_id = session_id.as_ref().ok_or_else(|| {
                DfsError::download_not_allowed(&resid, "session parameter is required")
            })?;

            // 获取 session
            let session = redis
                .get_session(session_id)
                .await
                .map_err(|e| DfsError::redis_error("get_session", e.to_string()))?;

            let session = session.ok_or_else(|| DfsError::SessionNotFound {
                session_id: session_id.clone(),
            })?;

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

            // 返回 session 的 extras
            session.extras.clone()
        }
    };

    // 获取版本对应的默认路径
    let version = config_guard
        .get_effective_version_with_cache(&resid, Some(&version_cache))
        .await;
    let path = config_guard
        .get_version_path(&resid, &version, None)
        .ok_or_else(|| DfsError::path_not_found(&resid, &version))?;

    // 检查资源是否启用缓存，如果是，先检查缓存
    if resource_config.cache_enabled {
        // 先进行简单的缓存检查（不需要server_id）
        if let Ok(Some((metadata, content))) =
            redis.get_full_cached_content(&resid, &version, &path).await
        {
            // 缓存命中！记录缓存命中日志
            if matches!(resource_config.download, DownloadPolicy::Free) {
                if let Some(ip) = client_ip {
                    let session_logger =
                        crate::analytics::SessionLogger::new(config.clone(), redis.clone());
                    if let Err(e) = session_logger
                        .log_cached_download(
                            &resid,
                            &version,
                            ip,
                            user_agent.clone(),
                            metadata.content_length,
                            metadata.max_age,
                            &metadata.etag,
                        )
                        .await
                    {
                        error!("Failed to log cached download: {}", e);
                    }
                }
            }

            // 缓存命中时更新流量统计 - 使用"cache"作为server_id
            let file_size = metadata.content_length;
            let server_id = "cache";

            if let Err(e) = redis
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
            metrics.record_scheduled_request(&resid, server_id, true);

            debug!(
                "Cache hit: file_size={}, resource_id={}, server_id={}",
                file_size, resid, server_id
            );

            return Ok(DownloadResponse::Cached { content, metadata });
        }
    }

    // 缓存未命中，需要进行实际的服务器调度
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

    // 解析range参数（保持原有逻辑，让flow规则正常工作）
    let parsed_ranges = range.as_ref().and_then(|r| parse_range_for_flow(r));

    // 根据range请求计算实际请求的文件大小
    let request_file_size = if let Some(ref ranges) = parsed_ranges {
        // 如果有range请求，计算range的总大小
        Some(
            ranges
                .iter()
                .map(|(start, end)| (end - start + 1) as u64)
                .sum(),
        )
    } else {
        // 如果没有range请求，使用完整文件大小
        file_size
    };

    // 使用流系统生成下载 URL
    let mut params = RunFlowParams {
        ranges: parsed_ranges,
        extras,
        session_id: original_session_id.clone(),
        client_ip,
        file_size: request_file_size, // 使用请求的实际大小，用于Size条件评估
        plugin_server_mapping: HashMap::new(), // 初始化插件服务器映射
        resource_id: resid.clone(),   // 新增：资源ID
        version: version.clone(),     // 使用获取到的版本
        sub_path: None,               // 下载时暂不支持子路径参数
        selected_server_id: None,     // 初始化为None，由poolize函数设置
        selected_server_weight: None, // 初始化为None，由poolize函数设置
        cdn_full_range: resource_config.legacy_client_full_range
            && resource_config.legacy_client_support, // 历史客户端全范围模式
    };

    let flow_list = &resource_config.flow;
    let cdn_url = runner.run_flow(flow_list, &mut params).await.map_err(|e| {
        error!("Failed to run flow for download: {}", e);
        DfsError::internal_error(format!("Failed to generate download URL: {}", e))
    })?;

    // 检查是否应该缓存
    let cached_result = if let Some((file_size, max_age)) = should_cache_content(
        &config_guard,
        &redis,
        &resid,
        None, // sub_path为None，这是普通文件下载
        params.selected_server_id.as_deref().unwrap_or("unknown"),
        &path,
    )
    .await
    {
        if file_size < 100 * 1024 {
            // 100KB限制
            // 下载并缓存
            download_and_cache(&cdn_url, &resid, &version, &path, &redis, max_age)
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
            let session_logger =
                crate::analytics::SessionLogger::new(config.clone(), redis.clone());
            // 使用选中的服务器ID和权重，如果没有则使用默认值
            let server_id = params.selected_server_id.as_deref().unwrap_or("unknown");
            let server_weight = params.selected_server_weight.unwrap_or(10);

            if let Err(e) = session_logger
                .log_direct_download(
                    &resid,
                    &version,
                    ip,
                    user_agent.clone(),
                    &cdn_url,
                    server_id,
                    server_weight,
                )
                .await
            {
                error!("Failed to log direct download: {}", e);
            }
        }
    }

    // 如果是 enabled 模式且有 session，记录日志并销毁 session
    if matches!(resource_config.download, DownloadPolicy::Enabled) {
        if let Some(ref sid) = original_session_id {
            // 在删除之前记录直接下载日志
            if let Some(ip) = client_ip {
                let session_logger =
                    crate::analytics::SessionLogger::new(config.clone(), redis.clone());
                let server_id = params.selected_server_id.as_deref().unwrap_or("unknown");
                let server_weight = params.selected_server_weight.unwrap_or(10);

                if let Err(e) = session_logger
                    .log_direct_download(
                        &resid,
                        &resource_config.latest,
                        ip,
                        user_agent.clone(),
                        &cdn_url, // 添加缺失的 cdn_url 参数
                        server_id,
                        server_weight,
                    )
                    .await
                {
                    error!("Failed to log direct download: {}", e);
                }
            }

            if let Err(e) = redis.remove_session(sid).await {
                warn!("Failed to remove session after download: {}", e);
            }
        }
    }

    // 更新流量统计（在成功生成下载URL后）
    if let Some(server_id) = &params.selected_server_id {
        // 尝试从健康检查缓存获取文件大小
        if let Ok(Some(health_info)) = redis.get_health_info(server_id, &path).await {
            if let Some(full_file_size) = health_info.file_size {
                // 根据range计算实际传输字节数
                let actual_bytes =
                    calculate_actual_bytes_from_range(range.as_deref(), full_file_size);

                // 使用批量更新接口同时更新资源、服务器和全局流量统计
                if let Err(e) = redis
                    .update_bandwidth_batch(BandwidthUpdateBatch {
                        resource_id: resid.clone(),
                        server_id: server_id.clone(),
                        bytes: actual_bytes,
                    })
                    .await
                {
                    warn!("Failed to update bandwidth for server {}: {}", server_id, e);
                } else {
                    // 记录成功的调度请求（非缓存）
                    metrics.record_scheduled_request(&resid, server_id, false);
                }

                debug!(
                    "Updated bandwidth stats: actual_bytes={}, full_file_size={}, range={:?}, resource_id={}, server_id={}",
                    actual_bytes, full_file_size, range, resid, server_id
                );
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
async fn download_redirect(
    Path(resid): Path<String>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    Extension(metrics): Extension<Arc<Metrics>>,
    Extension(version_cache): Extension<Arc<crate::modules::version_provider::VersionCache>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 获取 session 参数
    let session_id = params.get("session").map(|s| s.clone());
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match handle_download_request(
        resid,
        session_id,
        None,
        config,
        redis,
        runner,
        client_ip,
        user_agent,
        metrics,
        version_cache,
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
async fn download_json(
    Path(resid): Path<String>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    Extension(metrics): Extension<Arc<Metrics>>,
    Extension(version_cache): Extension<Arc<crate::modules::version_provider::VersionCache>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 提取 range 参数（历史客户端支持）
    let range = params.get("range").map(|s| s.clone());

    // 统一从 sid 参数获取，支持历史客户端
    let session_id = {
        let legacy_handler = LegacyClientHandler::new(config.clone(), redis.clone());

        // 检查是否是历史客户端资源
        let config_guard = config.read().await;
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
                // 首次请求，生成challenge并创建session
                match legacy_handler
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

    match handle_download_request(
        resid,
        session_id,
        range,
        config,
        redis,
        runner,
        client_ip,
        user_agent,
        metrics,
        version_cache,
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

#[utoipa::path(
    get,
    path = "/resource/{resid}/{sub_path}",
    tag = "Resource",
    summary = "Get prefix resource metadata",
    description = "Retrieves metadata for a specific file within a prefix resource using sub-path",
    params(
        ("resid" = String, Path, description = "Prefix resource identifier"),
        ("sub_path" = String, Path, description = "Sub-path within the prefix resource")
    ),
    responses(
        (status = 200, description = "Metadata retrieved successfully", body = MetadataResponse),
        (status = 400, description = "Resource is not a prefix type", body = ErrorResponse),
        (status = 404, description = "Resource not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[allow(unused_variables)]
async fn get_prefix_metadata(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(runner): Extension<FlowRunner>,
    Extension(redis): Extension<DataStore>,
    Extension(version_cache): Extension<Arc<crate::modules::version_provider::VersionCache>>,
) -> impl IntoResponse {
    // 获取changelog（优先级：版本提供者 > 静态配置）
    let changelog = get_resource_changelog(&config, &version_cache, &resid).await;

    // 读锁访问配置
    let config_guard = config.read().await;

    // 检查资源是否存在且为前缀类型
    let resource_config = match config_guard.get_resource(&resid) {
        Some(rc) if rc.resource_type == "prefix" => rc,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Resource is not a prefix type".to_string(),
                )),
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
    let version = config_guard
        .get_effective_version_with_cache(&resid, Some(&version_cache))
        .await;
    let full_path =
        match config_guard.get_version_path_with_sub(&resid, &version, None, Some(&sub_path)) {
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
                    resource_version: version.clone(),
                    name: format!("{}/{}", resid, sub_path),
                    changelog: changelog.clone(),
                    data: cached_json,
                })),
            );
        }
    }

    // 使用 kachina 模块解析文件（使用动态版本）
    match kachina::parse_kachina_metadata(&config, &runner, &resid, Some(&version)).await {
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
                    resource_version: version.clone(),
                    name: format!("{}/{}", resid, sub_path),
                    changelog: changelog.clone(),
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
                    resource_version: version.clone(),
                    name: format!("{}/{}", resid, sub_path),
                    changelog: changelog.clone(),
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
async fn create_prefix_session(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(metrics): Extension<Arc<Metrics>>,
    Extension(version_cache): Extension<Arc<crate::modules::version_provider::VersionCache>>,
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
                Json(ApiResponse::error(
                    "Resource is not a prefix type".to_string(),
                )),
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
        // 获取有效版本（考虑动态版本提供者）
        config_guard
            .get_effective_version_with_cache(&resid, Some(&version_cache))
            .await
    } else {
        req.version.clone()
    };

    // 检查版本是否存在或有default模板
    if !resource_config.versions.contains_key(&version)
        && !resource_config.versions.contains_key("default")
    {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(format!("版本 {} 不存在", version))),
        );
    }

    // 获取完整文件路径（前缀 + 子路径）
    let full_path =
        match config_guard.get_version_path_with_sub(&resid, &version, None, Some(&sub_path)) {
            Some(p) => p,
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error("无法构建资源路径".to_string())),
                );
            }
        };

    if req.sid.is_empty() {
        req.sid = generate_hex_session_id();
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
                    error!(
                        "Failed to run web challenge plugin {}: {}",
                        web_plugin_id, e
                    );
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
                            missing_bytes: challenge_json["missing_bytes"].as_u64().unwrap_or(2)
                                as u8,
                            original_data,
                        };

                        let verification_success = stored_challenge.verify(&req.challenge);

                        if !verification_success.success && !config_guard.debug_mode {
                            return (
                                StatusCode::PAYMENT_REQUIRED,
                                Json(ApiResponse::error("Invalid challenge response".to_string())),
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
        resource_id: resid.clone(),
        version: version.clone(),
        chunks: req.chunks.clone(),
        cdn_records: HashMap::new(),
        extras: req.extras.clone(),
    };

    if let Err(e) = redis.store_session(&req.sid, &session).await {
        error!("Failed to store session in Redis: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Failed to create session".to_string())),
        );
    }

    // 生成服务器尝试列表（使用完整文件路径进行健康检查）
    let tries = vec![];

    // 记录会话创建指标
    metrics.record_session_created();

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
    range: Option<String>,
    config: Arc<RwLock<AppConfig>>,
    redis: DataStore,
    runner: FlowRunner,
    client_ip: Option<std::net::IpAddr>,
    user_agent: Option<String>,
    metrics: Arc<Metrics>,
    version_cache: Arc<crate::modules::version_provider::VersionCache>,
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

    // 提取 extras 信息用于 Flow 规则
    let extras = match &resource_config.download {
        DownloadPolicy::Disabled => {
            return Err(DfsError::download_not_allowed(
                &resid,
                "download is disabled for this resource",
            ));
        }
        DownloadPolicy::Free => {
            // 无需 session 验证，使用空 extras
            serde_json::json!({})
        }
        DownloadPolicy::Enabled => {
            // 需要验证 session
            let session_id = session_id.as_ref().ok_or_else(|| {
                DfsError::download_not_allowed(&resid, "session parameter is required")
            })?;

            // 获取 session
            let session = redis
                .get_session(session_id)
                .await
                .map_err(|e| DfsError::redis_error("get_session", e.to_string()))?;

            let session = session.ok_or_else(|| DfsError::SessionNotFound {
                session_id: session_id.clone(),
            })?;

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

            // 返回 session 的 extras
            session.extras.clone()
        }
    };

    // 获取动态版本
    let version = config_guard.get_effective_version_with_cache(&resid, Some(&version_cache)).await;
    let full_path = config_guard
        .get_version_path_with_sub(&resid, &version, None, Some(&sub_path))
        .ok_or_else(|| DfsError::path_not_found(&resid, &version))?;

    // 检查资源是否启用缓存，如果是，先检查缓存
    if resource_config.cache_enabled {
        // 检查子路径是否匹配缓存模式
        if resource_config
            .cache_subpaths
            .iter()
            .any(|pattern| crate::cache::glob_match(pattern, &sub_path))
        {
            // 先进行简单的缓存检查（不需要server_id）
            if let Ok(Some((metadata, content))) = redis
                .get_full_cached_content(&resid, &version, &full_path)
                .await
            {
                // 缓存命中！记录缓存命中日志
                if matches!(resource_config.download, DownloadPolicy::Free) {
                    if let Some(ip) = client_ip {
                        let session_logger =
                            crate::analytics::SessionLogger::new(config.clone(), redis.clone());
                        if let Err(e) = session_logger
                            .log_cached_download(
                                &resid,
                                &version,
                                ip,
                                user_agent.clone(),
                                metadata.content_length,
                                metadata.max_age,
                                &metadata.etag,
                            )
                            .await
                        {
                            error!("Failed to log cached prefix download: {}", e);
                        }
                    }
                }

                // 缓存命中时更新流量统计 - 使用"cache"作为server_id
                let file_size = metadata.content_length;
                let server_id = "cache";

                if let Err(e) = redis
                    .update_bandwidth_batch(BandwidthUpdateBatch {
                        resource_id: resid.clone(),
                        server_id: server_id.to_string(),
                        bytes: file_size,
                    })
                    .await
                {
                    warn!(
                        "Failed to update bandwidth for cached prefix download: {}",
                        e
                    );
                }

                // 记录缓存命中的调度请求 - 没有实际调度到服务器
                metrics.record_scheduled_request(&resid, server_id, true);

                debug!(
                    "Prefix cache hit: file_size={}, resource_id={}, server_id={}, sub_path={}",
                    file_size, resid, server_id, sub_path
                );

                return Ok(DownloadResponse::Cached { content, metadata });
            }
        }
    }

    // 缓存未命中，需要进行实际的服务器调度
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

    // 解析range参数（保持原有逻辑，让flow规则正常工作）
    let parsed_ranges = range.as_ref().and_then(|r| parse_range_for_flow(r));

    // 根据range请求计算实际请求的文件大小
    let request_file_size = if let Some(ref ranges) = parsed_ranges {
        // 如果有range请求，计算range的总大小
        Some(
            ranges
                .iter()
                .map(|(start, end)| (end - start + 1) as u64)
                .sum(),
        )
    } else {
        // 如果没有range请求，使用完整文件大小
        file_size
    };

    // 使用流系统生成下载 URL
    let mut params = RunFlowParams {
        ranges: parsed_ranges,
        extras,
        session_id: original_session_id.clone(),
        client_ip,
        file_size: request_file_size, // 使用请求的实际大小，用于Size条件评估
        plugin_server_mapping: HashMap::new(), // 初始化插件服务器映射
        resource_id: resid.clone(),   // 资源ID
        version: version.clone(),     // 使用获取到的版本
        sub_path: Some(sub_path.clone()), // 子路径
        selected_server_id: None,     // 初始化为None，由poolize函数设置
        selected_server_weight: None, // 初始化为None，由poolize函数设置
        cdn_full_range: resource_config.legacy_client_full_range
            && resource_config.legacy_client_support, // 历史客户端全范围模式
    };

    let flow_list = &resource_config.flow;
    let cdn_url = runner.run_flow(flow_list, &mut params).await.map_err(|e| {
        error!("Failed to run flow for prefix download: {}", e);
        DfsError::internal_error(format!("Failed to generate download URL: {}", e))
    })?;

    // 检查是否应该缓存（前缀资源）
    let cached_result = if let Some((file_size, max_age)) = should_cache_content(
        &config_guard,
        &redis,
        &resid,
        Some(&sub_path), // 传入子路径用于模式匹配
        params.selected_server_id.as_deref().unwrap_or("unknown"),
        &full_path,
    )
    .await
    {
        if file_size < 100 * 1024 {
            // 100KB限制
            // 下载并缓存
            download_and_cache(&cdn_url, &resid, &version, &full_path, &redis, max_age)
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
            let session_logger =
                crate::analytics::SessionLogger::new(config.clone(), redis.clone());
            // 使用选中的服务器ID和权重，如果没有则使用默认值
            let server_id = params.selected_server_id.as_deref().unwrap_or("unknown");
            let server_weight = params.selected_server_weight.unwrap_or(10);

            if let Err(e) = session_logger
                .log_direct_download(
                    &resid,
                    &version,
                    ip,
                    user_agent.clone(),
                    &cdn_url,
                    server_id,
                    server_weight,
                )
                .await
            {
                error!("Failed to log prefix direct download: {}", e);
            }
        }
    }

    // 如果是 enabled 模式且有 session，记录日志并销毁 session
    if matches!(resource_config.download, DownloadPolicy::Enabled) {
        if let Some(ref sid) = original_session_id {
            // 在删除之前记录直接下载日志
            if let Some(ip) = client_ip {
                let session_logger =
                    crate::analytics::SessionLogger::new(config.clone(), redis.clone());
                let server_id = params.selected_server_id.as_deref().unwrap_or("unknown");
                let server_weight = params.selected_server_weight.unwrap_or(10);

                if let Err(e) = session_logger
                    .log_direct_download(
                        &resid,
                        &resource_config.latest,
                        ip,
                        user_agent.clone(),
                        &cdn_url, // 添加缺失的 cdn_url 参数
                        server_id,
                        server_weight,
                    )
                    .await
                {
                    error!("Failed to log direct download for prefix: {}", e);
                }
            }

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
        if let Ok(Some(health_info)) = redis.get_health_info(server_id, &full_path).await {
            if let Some(full_file_size) = health_info.file_size {
                // 根据range计算实际传输字节数
                let actual_bytes =
                    calculate_actual_bytes_from_range(range.as_deref(), full_file_size);

                // 使用批量更新接口同时更新资源、服务器和全局流量统计
                if let Err(e) = redis
                    .update_bandwidth_batch(BandwidthUpdateBatch {
                        resource_id: resid.clone(),
                        server_id: server_id.clone(),
                        bytes: actual_bytes,
                    })
                    .await
                {
                    warn!(
                        "Failed to update bandwidth for prefix server {}: {}",
                        server_id, e
                    );
                } else {
                    // 记录成功的调度请求（非缓存）
                    metrics.record_scheduled_request(&resid, server_id, false);
                }

                debug!(
                    "Updated prefix download bandwidth stats: actual_bytes={}, full_file_size={}, range={:?}, server_id={}, session_id={:?}",
                    actual_bytes, full_file_size, range, server_id, original_session_id
                );
            }
        }
    }

    // 如果有缓存结果，返回缓存内容
    if let Some((metadata, content)) = cached_result {
        return Ok(DownloadResponse::Cached { content, metadata });
    }

    Ok(DownloadResponse::Redirect(cdn_url))
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
async fn download_prefix_redirect(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    Extension(metrics): Extension<Arc<Metrics>>,
    Extension(version_cache): Extension<Arc<crate::modules::version_provider::VersionCache>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 获取 session 参数
    let session_id = params.get("session").map(|s| s.clone());
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match handle_prefix_download_request(
        resid, sub_path, session_id, None, config, redis, runner, client_ip, user_agent, metrics, version_cache,
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
async fn download_prefix_json(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    Extension(metrics): Extension<Arc<Metrics>>,
    Extension(version_cache): Extension<Arc<crate::modules::version_provider::VersionCache>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 提取客户端IP地址
    let client_ip = crate::modules::geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));

    // 提取 range 参数（历史客户端支持）
    let range = params.get("range").map(|s| s.clone());

    // 统一从 sid 参数获取，支持历史客户端
    let session_id = {
        let legacy_handler = LegacyClientHandler::new(config.clone(), redis.clone());

        // 检查是否是历史客户端资源
        let config_guard = config.read().await;
        let is_legacy_resource = config_guard
            .get_resource(&resid)
            .map(|r| r.legacy_client_support)
            .unwrap_or(false);
        drop(config_guard);

        if is_legacy_resource {
            // 历史客户端处理：sid 可能为空（第一次请求）
            let sid = params.get("sid").map(|s| s.as_str()).unwrap_or("");

            if sid.is_empty() {
                // 首次请求，生成challenge并创建session
                match legacy_handler
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

    match handle_prefix_download_request(
        resid, sub_path, session_id, range, config, redis, runner, client_ip, user_agent, metrics, version_cache,
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

// 辅助函数：更新会话模式的流量统计
async fn update_session_bandwidth_stats(
    redis: &DataStore,
    _session_id: &str,
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
        if let Err(e) = redis
            .update_resource_daily_bandwidth(resource_id, total_bandwidth)
            .await
        {
            warn!(
                "Failed to update resource daily bandwidth for {}: {}",
                resource_id, e
            );
        }
        if let Err(e) = redis.update_global_daily_bandwidth(total_bandwidth).await {
            warn!("Failed to update global daily bandwidth: {}", e);
        }

        // 分别更新各个服务器的流量统计
        let server_count = server_usage.len();
        for (server_id, bandwidth) in server_usage {
            if let Err(e) = redis
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

/// 获取资源的changelog
/// 优先级：版本提供者插件返回的changelog > 资源配置中的静态changelog > None
async fn get_resource_changelog(
    config: &Arc<RwLock<AppConfig>>,
    version_cache: &Arc<crate::modules::version_provider::VersionCache>,
    resource_id: &str,
) -> Option<String> {
    let config_guard = config.read().await;

    // 获取资源配置
    let resource_config = match config_guard.get_resource(resource_id) {
        Some(rc) => rc,
        None => return None,
    };

    // 优先级1: 尝试从版本提供者获取changelog
    if let Some(ref version_provider) = resource_config.version_provider {
        // 尝试从版本缓存获取VersionInfo
        if let Some(version_info) = version_cache.get_cached_version_info(resource_id).await {
            if let Some(changelog) = version_info.changelog {
                if !changelog.trim().is_empty() {
                    return Some(changelog);
                }
            }
        }
    }

    // 优先级2: 使用资源配置中的静态changelog
    if let Some(ref static_changelog) = resource_config.changelog {
        if !static_changelog.trim().is_empty() {
            return Some(static_changelog.clone());
        }
    }

    // 默认返回None
    None
}

pub fn routes() -> Router {
    Router::new()
        .route("/resource/{resid}", get(get_metadata).post(create_session))
        .route(
            "/resource/{resid}/{*sub_path}",
            get(get_prefix_metadata).post(create_prefix_session),
        )
        .route(
            "/session/{sessionid}/{resid}",
            get(get_cdn).delete(delete_session),
        )
        .route(
            "/download/{resid}",
            get(download_redirect).post(download_json),
        )
        .route(
            "/download/{resid}/{*sub_path}",
            get(download_prefix_redirect).post(download_prefix_json),
        )
}
