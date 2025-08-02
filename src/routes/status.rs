use axum::{
    Json, Router, extract::Extension, http::StatusCode, response::IntoResponse, routing::get,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::AppConfig;
use crate::responses::{ApiResponse, EmptyResponse, ErrorResponse};

#[utoipa::path(
    get,
    path = "/ping",
    tag = "System",
    summary = "Simple ping endpoint",
    description = "Returns HTTP 200 OK status to indicate server is running",
    responses(
        (status = 200, description = "Server is responding")
    )
)]
pub async fn ping() -> impl IntoResponse {
    StatusCode::OK
}

#[utoipa::path(
    get,
    path = "/reload-config",
    tag = "System",
    summary = "Reload server configuration",
    description = "Reloads the server configuration from disk without restarting the service",
    responses(
        (status = 200, description = "Configuration reloaded successfully", body = EmptyResponse),
        (status = 500, description = "Failed to reload configuration", body = ErrorResponse)
    )
)]
pub async fn reload_config(
    Extension(config): Extension<Arc<RwLock<AppConfig>>>,
) -> impl IntoResponse {
    match AppConfig::load().await {
        Ok(new_config) => {
            // 获取写锁并更新配置
            let mut write_lock = config.write().await;
            *write_lock = new_config;
            (
                StatusCode::OK,
                Json(ApiResponse::success(crate::responses::ResponseData::Empty)),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(format!("加载配置文件失败: {}", e))),
        ),
    }
}

pub fn routes() -> Router {
    Router::new()
        .route("/ping", get(ping))
        .route("/reload-config", get(reload_config))
}
