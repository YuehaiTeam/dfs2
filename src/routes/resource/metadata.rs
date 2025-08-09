use axum::extract::{Extension, Path, Query};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, warn};

use crate::{
    container::AppContext,
    modules::external::kachina,
    record_request_metrics,
    responses::{ApiResponse, ErrorResponse, MetadataResponse, ResponseData},
};

// 查询参数结构体
#[derive(Deserialize, Debug)]
pub struct MetadataQuery {
    /// 是否返回 kachina metadata (有参数 = 是, 未设置 = 否)
    pub with_metadata: Option<String>,
}

// 统一的metadata处理函数
async fn handle_metadata_request_unified(
    resid: String,
    sub_path: Option<String>, // None=普通资源, Some=前缀资源
    with_metadata: bool,
    ctx: AppContext,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    let start_time = std::time::Instant::now();

    // 获取changelog（优先级：版本提供者 > 静态配置）
    let changelog = ctx.resource_service.get_resource_changelog(&resid).await;

    // 获取基本资源信息
    let config_guard = ctx.get_config();

    // 验证资源存在性（根据是否有sub_path区分处理）
    let (validated_resid, effective_version) = match ctx
        .resource_service
        .validate_resource_and_version(&resid, "", sub_path.as_deref())
        .await
    {
        Ok(result) => result,
        Err(e) => {
            return if sub_path.is_some() {
                Err(crate::error::DfsError::InvalidInput {
                    field: "sub_path".to_string(),
                    reason: e.to_string(),
                })
            } else {
                Err(crate::error::DfsError::ResourceNotFound {
                    resource_id: resid.clone(),
                })
            };
        }
    };

    // 生成响应中的name字段
    let response_name = if let Some(ref sub_path_val) = sub_path {
        format!("{resid}/{sub_path_val}")
    } else {
        resid.clone()
    };

    // 如果不需要 kachina metadata，直接返回基本信息
    if !with_metadata {
        // 记录成功的请求指标
        record_request_metrics!(ctx.metrics, start_time);

        return Ok(ApiResponse::success(ResponseData::Metadata {
            resource_version: effective_version,
            name: response_name,
            changelog: changelog.clone(),
            data: json!(null), // 不返回 kachina metadata
        }));
    }

    // 以下是 kachina metadata 处理逻辑
    let path = match ctx.resource_service.get_version_path(
        &validated_resid,
        &effective_version,
        None,
        sub_path.as_deref(),
    ) {
        Some(p) => p,
        None => {
            let resource_path = if let Some(ref sub_path_val) = sub_path {
                format!("{resid}/{sub_path_val}")
            } else {
                format!("{resid}:{effective_version}")
            };
            return Err(crate::error::DfsError::ResourceNotFound {
                resource_id: resource_path,
            });
        }
    };

    let cache_key = if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
        if !prefix.is_empty() {
            format!("{prefix}:kachina_meta:{path}")
        } else {
            format!("kachina_meta:{path}")
        }
    } else {
        format!("kachina_meta:{path}")
    };

    drop(config_guard); // 释放配置锁

    // 先检查缓存
    if let Ok(Some(cached_data)) = ctx.data_store.get_cached_metadata(&cache_key).await {
        if let Ok(cached_json) = serde_json::from_str::<serde_json::Value>(&cached_data) {
            return Ok(ApiResponse::success(ResponseData::Metadata {
                resource_version: effective_version.clone(),
                name: response_name,
                changelog: changelog.clone(),
                data: cached_json,
            }));
        }
    }

    // 使用 kachina 模块解析 KachinaInstaller 文件
    match kachina::parse_kachina_metadata(
        &ctx.shared_config,
        &ctx.flow_service,
        &resid,
        &effective_version,
        sub_path,
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

            Ok(ApiResponse::success(ResponseData::Metadata {
                resource_version: effective_version.clone(),
                name: response_name,
                changelog: changelog.clone(),
                data: response_data,
            }))
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

            Ok(ApiResponse::success(ResponseData::Metadata {
                resource_version: effective_version.clone(),
                name: response_name,
                changelog: changelog.clone(),
                data: null_data,
            }))
        }
        Err(e) => {
            error!("Failed to parse kachina metadata: {}", e);

            // 记录错误的请求指标
            record_request_metrics!(ctx.metrics, start_time);

            Err(e)
        }
    }
}

#[utoipa::path(
    get,
    path = "/resource/{resid}",
    tag = "Resource",
    summary = "Get resource metadata",
    description = "Retrieves metadata for a specific resource, including KachinaInstaller information if available",
    params(
        ("resid" = String, Path, description = "Resource identifier"),
        ("with_metadata" = Option<String>, Query, description = "Include kachina metadata if present (any value enables it)")
    ),
    responses(
        (status = 200, description = "Metadata retrieved successfully", body = MetadataResponse),
        (status = 404, description = "Resource not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn get_metadata(
    Path(resid): Path<String>,
    Query(query): Query<MetadataQuery>,
    Extension(ctx): Extension<AppContext>,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    // 检查是否请求 kachina metadata（有参数就是 true，无参数就是 false）
    let with_metadata = query.with_metadata.is_some();

    handle_metadata_request_unified(resid, None, with_metadata, ctx).await
}

#[utoipa::path(
    get,
    path = "/resource/{resid}/{sub_path}",
    tag = "Resource",
    summary = "Get prefix resource metadata",
    description = "Retrieves metadata for a specific file within a prefix resource, including KachinaInstaller information if available",
    params(
        ("resid" = String, Path, description = "Prefix resource identifier"),
        ("sub_path" = String, Path, description = "Sub-path within the prefix resource"),
        ("with_metadata" = Option<String>, Query, description = "Include kachina metadata if present (any value enables it)")
    ),
    responses(
        (status = 200, description = "Metadata retrieved successfully", body = MetadataResponse),
        (status = 400, description = "Invalid resource type or sub-path", body = ErrorResponse),
        (status = 404, description = "Resource or file not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn get_prefix_metadata(
    Path((resid, sub_path)): Path<(String, String)>,
    Query(query): Query<MetadataQuery>,
    Extension(ctx): Extension<AppContext>,
) -> crate::error::DfsResult<crate::responses::ApiResponse> {
    // 检查是否请求 kachina metadata（与普通资源路由行为一致）
    let with_metadata = query.with_metadata.is_some();

    handle_metadata_request_unified(resid, Some(sub_path), with_metadata, ctx).await
}
