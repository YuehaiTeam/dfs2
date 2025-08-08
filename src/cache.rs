use crate::app_state::REQWEST_CLIENT;
use crate::config::AppConfig;
use crate::data_store::{CacheMetadata, DataStoreBackend};
use std::sync::Arc;
use tracing::warn;
use xxhash_rust::xxh3::xxh3_64;

/// 生成ETag（使用xxhash）
pub fn generate_etag(content: &[u8]) -> String {
    let hash = xxh3_64(content);
    format!("\"{}\"", hash)
}

/// 下载内容并缓存到Redis
pub async fn download_and_cache(
    cdn_url: &str,
    resource_id: &str,
    version: &str,
    path: &str,
    redis: &Arc<dyn DataStoreBackend>,
    max_age: u32,
) -> Result<(CacheMetadata, Vec<u8>), String> {
    // 下载内容
    let response = REQWEST_CLIENT
        .get(cdn_url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Download failed with status: {}", response.status()));
    }

    // 提取Content-Type
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let content = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read content: {}", e))?
        .to_vec();

    // 生成ETag（使用xxhash）
    let etag = generate_etag(&content);

    // 创建元数据
    let metadata = CacheMetadata {
        cached_at: chrono::Utc::now().timestamp() as u64,
        max_age,
        content_length: content.len() as u64,
        content_type,
        etag,
    };

    // 存储到Redis（分离存储）
    let keys = redis.generate_cache_keys(resource_id, version, path);
    if let Err(e) = redis
        .set_cache_entry(&keys.metadata_key, &keys.content_key, &metadata, &content)
        .await
    {
        warn!("Failed to cache content: {}", e);
    }

    Ok((metadata, content))
}

/// 检查是否应该缓存内容
pub async fn should_cache_content(
    config: &AppConfig,
    redis: &Arc<dyn DataStoreBackend>,
    resource_id: &str,
    sub_path: Option<&str>,
    server_id: &str,
    full_path: &str,
) -> Option<(u64, u32)> {
    // 检查资源是否启用缓存
    let resource = config.get_resource(resource_id)?;
    if !resource.cache_enabled {
        return None;
    }

    // 前缀资源检查子路径模式
    if resource.resource_type == "prefix" {
        let sub = sub_path?;
        if !resource
            .cache_subpaths
            .iter()
            .any(|pattern| glob_match(pattern, sub))
        {
            return None;
        }
    }

    // 从健康检查缓存获取文件大小
    if let Ok(Some(health_info)) = redis.get_health_info(server_id, full_path).await {
        if health_info.is_alive {
            return health_info
                .file_size
                .map(|size| (size, resource.cache_max_age));
        }
    }

    None
}

/// 简单的glob模式匹配
pub fn glob_match(pattern: &str, text: &str) -> bool {
    // 简化版本的glob匹配，支持*通配符
    if pattern == "*" {
        return true;
    }

    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.is_empty() {
            return true;
        }

        let mut text_start = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if i == 0 {
                // 第一部分必须在开头匹配
                if !text[text_start..].starts_with(part) {
                    return false;
                }
                text_start += part.len();
            } else if i == parts.len() - 1 {
                // 最后一部分必须在结尾匹配
                return text[text_start..].ends_with(part);
            } else {
                // 中间部分
                if let Some(pos) = text[text_start..].find(part) {
                    text_start += pos + part.len();
                } else {
                    return false;
                }
            }
        }
        true
    } else {
        pattern == text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.json", "config.json"));
        assert!(glob_match("*.json", "data.json"));
        assert!(!glob_match("*.json", "config.txt"));
        assert!(glob_match("config/*", "config/app.yaml"));
        assert!(glob_match("config/*", "config/database.yaml"));
        assert!(!glob_match("config/*", "data/app.yaml"));
        assert!(glob_match("assets/icons/*.png", "assets/icons/logo.png"));
        assert!(!glob_match("assets/icons/*.png", "assets/images/logo.png"));
    }
}