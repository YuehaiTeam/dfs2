use axum::{
    Json, Router,
    body::Body,
    extract::{Extension, Path, Query},
    http::Request,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::config::SharedConfig;
use crate::container::AppContext;
use crate::error::{DfsError, DfsResult};
use crate::modules::external::geolocation;
use crate::modules::storage::data_store::DataStore;
use crate::responses::{ApiResponse, EmptyResponse, ErrorResponse};

/// 管理接口鉴权中间件
pub async fn mgmt_auth_middleware(
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    // 检查管理API密钥
    if let Some(mgmt_token) = std::env::var("MGMT_API_TOKEN").ok() {
        if !mgmt_token.is_empty() {
            // 检查Authorization头
            if let Some(auth_header) = headers.get("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let token = &auth_str[7..];
                        if token == mgmt_token {
                            // 鉴权通过
                            return Ok(next.run(request).await);
                        }
                    }
                }
            }

            // 鉴权失败
            warn!("Unauthorized access attempt to management API");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // 如果没有设置MGMT_API_TOKEN，允许访问（向后兼容）
    Ok(next.run(request).await)
}

/// 健康检查响应结构
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct HealthCheck {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub redis_status: String,
    pub plugin_count: usize,
    pub server_count: usize,
    pub last_check: String,
}

/// 版本刷新响应结构
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct VersionRefreshResponse {
    pub resource_id: String,
    pub old_version: Option<String>,
    pub new_version: String,
    pub updated: bool,
    pub message: String,
}

/// 简单ping检查
#[utoipa::path(
    get,
    path = "/mgmt/ping",
    tag = "Management",
    summary = "Simple ping endpoint",
    description = "Returns HTTP 200 OK status to indicate server is running",
    responses(
        (status = 200, description = "Server is responding"),
        (status = 401, description = "Unauthorized - invalid or missing management token")
    )
)]
pub async fn ping() -> impl IntoResponse {
    StatusCode::OK
}

/// 详细健康检查
#[utoipa::path(
    get,
    path = "/mgmt/health",
    tag = "Management",
    summary = "Get detailed health check information",
    description = "Returns comprehensive health information including Redis status, plugin count, server count, and system metrics",
    responses(
        (status = 200, description = "Health check completed successfully", body = HealthCheck),
        (status = 503, description = "Service degraded - some components unavailable", body = HealthCheck),
        (status = 401, description = "Unauthorized - invalid or missing management token")
    )
)]
#[tracing::instrument(skip(ctx))]
pub async fn health_check(Extension(ctx): Extension<AppContext>) -> impl IntoResponse {
    info!("Health check requested");

    // 检查Redis连接状态
    let redis_status = match test_redis_connection(&ctx.data_store).await {
        Ok(_) => "connected".to_string(),
        Err(e) => {
            warn!("Redis connection check failed: {}", e);
            "disconnected".to_string()
        }
    };

    // 读取配置信息
    let config_guard = ctx.get_config();
    let plugin_count = config_guard.plugin_code.len();
    let server_count = config_guard.servers.len();

    // 构建健康检查响应
    let health_check = HealthCheck {
        status: if redis_status == "connected" {
            "healthy"
        } else {
            "degraded"
        }
        .to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0, // TODO: 实现真实的运行时间计算
        redis_status,
        plugin_count,
        server_count,
        last_check: chrono::Utc::now().to_rfc3339(),
    };

    info!(
        "Health check completed: status={}, redis={}, plugins={}, servers={}",
        health_check.status,
        health_check.redis_status,
        health_check.plugin_count,
        health_check.server_count
    );

    (StatusCode::OK, Json(health_check))
}

/// 配置重载
#[utoipa::path(
    post,
    path = "/mgmt/reload-config",
    tag = "Management",
    summary = "Reload server configuration",
    description = "Reloads the server configuration from disk without restarting the service",
    responses(
        (status = 200, description = "Configuration reloaded successfully", body = EmptyResponse),
        (status = 500, description = "Failed to reload configuration", body = ErrorResponse),
        (status = 401, description = "Unauthorized - invalid or missing management token")
    )
)]
pub async fn reload_config(Extension(ctx): Extension<AppContext>) -> impl IntoResponse {
    info!("Configuration reload requested");

    match ctx.shared_config.reload_from_file().await {
        Ok(()) => {
            info!("Configuration reloaded successfully");
            (
                StatusCode::OK,
                Json(ApiResponse::success(crate::responses::ResponseData::Empty)),
            )
        }
        Err(e) => {
            error!("Failed to reload configuration: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(format!("加载配置文件失败: {}", e))),
            )
        }
    }
}

/// Prometheus指标端点
#[utoipa::path(
    get,
    path = "/mgmt/metrics",
    tag = "Management",
    summary = "Get Prometheus metrics",
    description = "Returns Prometheus-formatted metrics for monitoring and alerting",
    responses(
        (status = 200, description = "Metrics retrieved successfully", content_type = "text/plain"),
        (status = 401, description = "Unauthorized - invalid or missing management token")
    )
)]
#[axum::debug_handler]
pub async fn metrics_handler(Extension(ctx): Extension<AppContext>) -> impl IntoResponse {
    use axum::extract::State;
    crate::metrics::metrics_handler(State(ctx.metrics), State(ctx.data_store)).await
}

/// IP地理位置查询参数
#[derive(serde::Deserialize)]
pub struct GeoIpQuery {
    pub ip: String,
}

/// IP地理位置查询
#[utoipa::path(
    get,
    path = "/mgmt/geoip",
    tag = "Management",
    summary = "Get IP geolocation information",
    description = "Returns detailed geolocation information for the specified IP address using IPIP database",
    params(
        ("ip" = String, Query, description = "IP address to lookup")
    ),
    responses(
        (status = 200, description = "IP geolocation retrieved successfully"),
        (status = 400, description = "Invalid IP address format", body = ErrorResponse),
        (status = 404, description = "IP address not found in database", body = ErrorResponse),
        (status = 401, description = "Unauthorized - invalid or missing management token")
    )
)]
pub async fn geoip_lookup(Query(params): Query<GeoIpQuery>) -> impl IntoResponse {
    info!("GeoIP lookup requested for IP: {}", params.ip);

    // 解析IP地址
    let ip = match params.ip.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(e) => {
            warn!("Invalid IP address format: {} - {}", params.ip, e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(format!(
                    "无效的IP地址格式: {}",
                    params.ip
                ))),
            )
                .into_response();
        }
    };

    // 使用IPDB查询地理位置信息
    if let Some(ref ipdb) = *geolocation::IPDB {
        match ipdb.find(&ip.to_string(), "CN") {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => {
                warn!("Failed to lookup IP {} in IPDB: {}", ip, e);
                (
                    StatusCode::NOT_FOUND,
                    Json(ApiResponse::error(format!(
                        "在数据库中未找到IP地址 {} 的信息: {}",
                        ip, e
                    ))),
                )
                    .into_response()
            }
        }
    } else {
        error!("IPDB database not loaded");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::error("IPIP地理位置数据库未加载".to_string())),
        )
            .into_response()
    }
}

/// 测试Redis连接
async fn test_redis_connection(redis: &DataStore) -> DfsResult<()> {
    // 简单的Redis连接测试 - 尝试读取一个不存在的键
    match redis.get_string("__health_check_test__").await {
        Ok(_) => Ok(()), // 连接成功，不管返回什么
        Err(e) => {
            error!("Redis health check failed: {}", e);
            Err(DfsError::redis_error("health_check", e.to_string()))
        }
    }
}

/// 版本刷新端点 - 支持双重鉴权
#[utoipa::path(
    post,
    path = "/refresh/{resource_id}",
    tag = "Management",
    summary = "Refresh resource version",
    description = "Triggers immediate version refresh for the specified resource. Supports both resource-specific webhook tokens and global management tokens.",
    params(
        ("resource_id" = String, Path, description = "Resource identifier to refresh")
    ),
    responses(
        (status = 200, description = "Version refresh completed successfully", body = VersionRefreshResponse),
        (status = 404, description = "Resource not found or no version provider configured", body = ErrorResponse),
        (status = 401, description = "Unauthorized - invalid or missing token", body = ErrorResponse),
        (status = 500, description = "Version refresh failed", body = ErrorResponse)
    )
)]
pub async fn refresh_version(
    Path(resource_id): Path<String>,
    headers: HeaderMap,
    Extension(ctx): Extension<AppContext>,
) -> impl IntoResponse {
    info!("Version refresh requested for resource: {}", resource_id);

    // 双重鉴权检查
    if let Err(status) = validate_refresh_token(&headers, &resource_id, &ctx.shared_config).await {
        return (
            status,
            Json(ApiResponse::error("Unauthorized access".to_string())),
        )
            .into_response();
    }

    // 获取当前缓存的版本 - 使用ResourceService保持架构层次
    let old_version = ctx.resource_service.get_cached_version(&resource_id).await;

    // 执行版本刷新 - 使用ResourceService保持架构层次
    match ctx.resource_service.refresh_version(&resource_id).await {
        Ok(new_version) => {
            let updated = old_version.as_ref().map_or(true, |old| old != &new_version);

            let response = VersionRefreshResponse {
                resource_id: resource_id.clone(),
                old_version,
                new_version: new_version.clone(),
                updated,
                message: if updated {
                    format!("Version updated to {}", new_version)
                } else {
                    format!("Version {} is already current", new_version)
                },
            };

            info!(
                "Version refresh completed for {}: {}",
                resource_id,
                if updated { "updated" } else { "no change" }
            );

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            error!("Version refresh failed for {}: {}", resource_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(format!("Version refresh failed: {}", e))),
            )
                .into_response()
        }
    }
}

/// 验证版本刷新token（双重鉴权）
async fn validate_refresh_token(
    headers: &HeaderMap,
    resource_id: &str,
    config: &SharedConfig,
) -> Result<(), StatusCode> {
    // 提取Authorization头
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let config_guard = config.load();

    // 方式1: 检查全局管理token
    if let Ok(mgmt_token) = std::env::var("MGMT_API_TOKEN") {
        if !mgmt_token.is_empty() && auth_header == mgmt_token {
            info!("Version refresh authorized with global management token");
            return Ok(());
        }
    }

    // 方式2: 检查资源专属webhook token
    if let Some(resource) = config_guard.get_resource(resource_id) {
        if let Some(ref version_provider) = resource.version_provider {
            if let Some(ref webhook_token) = version_provider.webhook_token {
                if auth_header == webhook_token {
                    info!("Version refresh authorized with resource-specific webhook token");
                    return Ok(());
                }
            }
        }
    }

    warn!(
        "Unauthorized version refresh attempt for resource: {}",
        resource_id
    );
    Err(StatusCode::UNAUTHORIZED)
}

/// 创建管理路由，包含鉴权中间件
pub fn routes() -> Router {
    // 版本刷新端点 - 使用独立的双重鉴权，不经过mgmt中间件
    let version_routes = Router::new().route("/refresh/{resource_id}", post(refresh_version));

    // 其他管理端点 - 使用标准mgmt鉴权中间件
    let mgmt_routes = Router::new()
        .route("/mgmt/ping", get(ping))
        .route("/mgmt/health", get(health_check))
        .route("/mgmt/reload-config", get(reload_config))
        .route("/mgmt/metrics", get(metrics_handler))
        .route("/mgmt/geoip", get(geoip_lookup))
        .layer(middleware::from_fn(mgmt_auth_middleware));

    // 合并路由
    version_routes.merge(mgmt_routes)
}
