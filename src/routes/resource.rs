use axum::{
    Json, Router,
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::models::{CreateSessionRequest, DeleteSessionRequest, Session};
use crate::responses::{ApiResponse, ResponseData};
use crate::{
    app_state::{MAX_CHUNK_DOWNLOADS, RedisStore},
    modules::flow::runner::{FlowRunner, RunFlowParams},
    modules::thirdparty::kachina,
};

// 错误码常量定义
const E_RESOURCE_NOT_FOUND: &str = "E_RESOURCE_NOT_FOUND";
const E_VERSION_NOT_FOUND: &str = "E_VERSION_NOT_FOUND";
const E_PATH_NOT_FOUND: &str = "E_PATH_NOT_FOUND";

#[allow(unused_variables)]
async fn get_metadata(
    Path(resid): Path<String>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(runner): Extension<FlowRunner>,
    Extension(redis): Extension<RedisStore>,
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

        format!("kachina_meta:{}", path)
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
                if let Err(e) = redis.set_cached_metadata(&cache_key, &cache_value, 3600).await {
                    eprintln!("Failed to cache metadata: {}", e);
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
                if let Err(e) = redis.set_cached_metadata(&cache_key, &cache_value, 3600).await {
                    eprintln!("Failed to cache null metadata: {}", e);
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
            eprintln!("Failed to parse kachina metadata: {}", error_msg);
            let status_code = if error_msg.starts_with(E_RESOURCE_NOT_FOUND) 
                || error_msg.starts_with(E_VERSION_NOT_FOUND) {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status_code, Json(ApiResponse::error(error_msg)))
        }
    }
}

#[allow(unused_variables)]
async fn create_session(
    Extension(redis): Extension<RedisStore>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Path(resid): Path<String>,
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
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::Success(ResponseData::Challenge {
                challenge: "md5".to_string(),
                data: format!("data/{}/{}", resid, req.sid),
                sid: req.sid,
            })),
        );
    }

    let session = Session {
        path,
        chunks: req.chunks.clone(),
        cdn_records: HashMap::new(),
    };

    if let Err(e) = redis.store_session(&req.sid, &session).await {
        eprintln!("Failed to store session in Redis: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Failed to create session".to_string())),
        );
    }

    // 获取测试服务器列表
    let tries = vec![];

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
    Extension(redis): Extension<RedisStore>,
    Extension(runner): Extension<FlowRunner>,
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Path((resid, sessionid)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
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
                    eprintln!("Failed to refresh session: {}", e);
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

                if res.is_none() {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(ApiResponse::error(format!("Resource {} not found", resid))),
                    );
                }
                let res = res.unwrap();
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
                let params = RunFlowParams {
                    path: session.path.clone(),
                    ranges,
                    extras: serde_json::json!({}),
                    session_id: Some(sessionid.clone()),
                };
                let flow_res = runner.run_flow(flow_list, &params).await;
                if let Err(e) = flow_res {
                    eprintln!("Failed to run flow: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiResponse::error("Failed to process request".to_string())),
                    );
                }
                let cdn_url = flow_res.unwrap();

                // 记录CDN调度信息
                if let Err(e) = redis
                    .update_cdn_record(&sessionid, range_str, &cdn_url)
                    .await
                {
                    eprintln!("Failed to update CDN record: {}", e);
                }

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
                eprintln!("Failed to increment download count: {}", e);
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
    Extension(redis): Extension<RedisStore>,
    Path((resid, sessionid)): Path<(String, String)>,
    Json(req): Json<DeleteSessionRequest>,
) -> impl IntoResponse {
    // 在删除之前获取会话统计信息
    match redis.get_session_stats(&sessionid).await {
        Ok(Some(stats)) => {
            // 合并所有统计信息
            let complete_stats = json!({
                "session_id": sessionid,
                "resource_id": resid,
                "path": stats.path,
                "chunks": stats.chunks,
                "download_counts": stats.download_counts,
                "cdn_records": stats.cdn_records,  // 包含了CDN调度记录
                "insights": {
                    "bandwidth": req.insights.bandwidth,
                    "ttfb": req.insights.ttfb,
                }
            });

            println!("Session statistics: {}", complete_stats);

            // 删除会话
            if let Err(e) = redis.remove_session(&sessionid).await {
                eprintln!("Failed to remove session: {}", e);
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
            eprintln!("Failed to get session statistics: {}", e);
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

pub fn routes() -> Router {
    Router::new()
        .route("/resource/{resid}", get(get_metadata).post(create_session))
        .route(
            "/session/{sessionid}/{resid}",
            get(get_cdn).delete(delete_session),
        )
}
