use axum::{
    Json, Router, extract::Extension, http::StatusCode, response::IntoResponse, routing::get,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::app_state::DataStore;
use crate::config::AppConfig;
use crate::error::{DfsError, DfsResult};

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

/// 详细健康检查
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    summary = "Get detailed health check information",
    description = "Returns comprehensive health information including Redis status, plugin count, server count, and system metrics",
    responses(
        (status = 200, description = "Health check completed successfully", body = HealthCheck),
        (status = 503, description = "Service degraded - some components unavailable", body = HealthCheck)
    )
)]
#[tracing::instrument(skip(config, redis))]
pub async fn health_check(
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
    Extension(redis): Extension<DataStore>,
) -> impl IntoResponse {
    info!("Health check requested");

    // 检查Redis连接状态
    let redis_status = match test_redis_connection(&redis).await {
        Ok(_) => "connected".to_string(),
        Err(e) => {
            warn!("Redis connection check failed: {}", e);
            "disconnected".to_string()
        }
    };

    // 读取配置信息
    let config_guard = config.read().await;
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
        health_check.status, health_check.redis_status, health_check.plugin_count, health_check.server_count
    );

    (StatusCode::OK, Json(health_check))
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

pub fn routes() -> Router {
    Router::new()
        .route("/health", get(health_check))
}