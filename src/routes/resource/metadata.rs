use axum::{
    Json,
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, warn};

use crate::{
    container::AppContext,
    modules::external::kachina,
    record_request_metrics,
    responses::{ApiResponse, ErrorResponse, MetadataResponse, ResponseData},
    routes::resource::{
        E_PATH_NOT_FOUND, E_RESOURCE_NOT_FOUND, E_VERSION_NOT_FOUND,
    },
};

// 查询参数结构体
#[derive(Deserialize, Debug)]
pub struct MetadataQuery {
    /// 是否返回 kachina metadata (有参数 = 是, 未设置 = 否)
    pub with_metadata: Option<String>,
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
pub async fn get_metadata(
    Path(resid): Path<String>,
    Query(query): Query<MetadataQuery>,
    Extension(ctx): Extension<AppContext>,
) -> impl IntoResponse {
    let start_time = std::time::Instant::now();

    // 检查是否请求 kachina metadata（有参数就是 true，无参数就是 false）
    let with_metadata = query.with_metadata.is_some();

    // 获取changelog（优先级：版本提供者 > 静态配置）
    let changelog = ctx.resource_service.get_resource_changelog(&resid).await;

    // 获取基本资源信息
    let config_guard = ctx.get_config();

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
                Json(ApiResponse::error(E_RESOURCE_NOT_FOUND.to_string())),
            );
        }
    };

    let resource_config = config_guard.get_resource(&validated_resid).unwrap();

    // 获取有效版本（考虑动态版本提供者）
    let effective_version = ctx.resource_service.get_effective_version(&resid).await;

    // 如果不需要 kachina metadata，直接返回基本信息
    if !with_metadata {
        // 记录成功的请求指标
        record_request_metrics!(ctx.metrics, start_time);

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
    let path = match ctx.resource_service.get_version_path(&resid, &effective_version, None, None) {
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
    if let Ok(Some(cached_data)) = ctx.data_store.get_cached_metadata(&cache_key).await {
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
    match kachina::parse_kachina_metadata(
        &ctx.shared_config,
        &ctx.flow_service,
        &resid,
        Some(&effective_version),
    )
    .await
    {
        Ok(Some(metadata)) => {
            // 返回解析后的数据
            let response_data = json!({
                "index": metadata.index,
                "metadata": metadata.metadata,
                "installer_end": metadata.installer_end
            });

            // 缓存解析结果，缓存1小时 (3600秒)
            if let Ok(cache_value) = serde_json::to_string(&response_data) {
                if let Err(e) = ctx
                    .data_store
                    .set_cached_metadata(&cache_key, &cache_value, 3600)
                    .await
                {
                    warn!("Failed to cache metadata: {}", e);
                }
            }

            // 记录成功的请求指标
            record_request_metrics!(ctx.metrics, start_time);

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
                if let Err(e) = ctx
                    .data_store
                    .set_cached_metadata(&cache_key, &cache_value, 3600)
                    .await
                {
                    warn!("Failed to cache null metadata: {}", e);
                }
            }

            // 记录成功的请求指标
            record_request_metrics!(ctx.metrics, start_time);

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
            record_request_metrics!(ctx.metrics, start_time);

            (status_code, Json(ApiResponse::error(error_msg)))
        }
    }
}

#[allow(unused_variables)]
pub async fn get_prefix_metadata(
    Path((resid, sub_path)): Path<(String, String)>,
    Extension(ctx): Extension<AppContext>,
) -> impl IntoResponse {
    // 获取changelog（优先级：版本提供者 > 静态配置）
    let changelog = ctx.resource_service.get_resource_changelog(&resid).await;

    // 读锁访问配置
    let config_guard = ctx.get_config();

    // 验证前缀资源存在性和类型
    let (validated_resid, _effective_version) = match ctx
        .resource_service
        .validate_resource_and_version(&resid, "", Some(&sub_path))
        .await
    {
        Ok(result) => result,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(e.to_string())),
            );
        }
    };

    let resource_config = config_guard.get_resource(&validated_resid).unwrap(); // 已验证存在

    // 获取完整文件路径
    let version = ctx.resource_service.get_effective_version(&resid).await;
    let full_path = match ctx.resource_service.get_version_path(&resid, &version, None, Some(&sub_path)) {
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
    if let Ok(Some(cached_data)) = ctx.data_store.get_cached_metadata(&cache_key).await {
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
    match kachina::parse_kachina_metadata(
        &ctx.shared_config,
        &ctx.flow_service,
        &resid,
        Some(&version),
    )
    .await
    {
        Ok(Some(metadata)) => {
            let response_data = json!({
                "index": metadata.index,
                "metadata": metadata.metadata,
                "installer_end": metadata.installer_end
            });

            // 缓存解析结果
            if let Ok(cache_value) = serde_json::to_string(&response_data) {
                if let Err(e) = ctx
                    .data_store
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
                if let Err(e) = ctx
                    .data_store
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
