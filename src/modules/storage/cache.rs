use crate::config::{AppConfig, ResourceConfig};
use crate::container::FETCH_CLIENT;
use crate::modules::storage::data_store::{CacheMetadata, DataStoreBackend};
use std::sync::Arc;
use tracing::{debug, warn};
use xxhash_rust::xxh3::xxh3_64;

/// 生成ETag（使用xxhash）
pub fn generate_etag(content: &[u8]) -> String {
    let hash = xxh3_64(content);
    format!("\"{hash}\"")
}

/// 下载内容并缓存到Redis
pub async fn download_and_cache(
    cdn_url: &str,
    resource_id: &str,
    version: &str,
    path: &str,
    redis: &Arc<dyn DataStoreBackend>,
    max_age: u32,
    source_server: &str,
) -> Result<(CacheMetadata, Vec<u8>), String> {
    // 下载内容
    let response = FETCH_CLIENT
        .get(cdn_url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "Download failed with status: {}",
            response.status()
        ));
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
        .map_err(|e| format!("Failed to read content: {e}"))?
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
        src: Some(source_server.to_string()),
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
    let resource = config.get_resource(resource_id)?;
    if !cache_eligible(resource, sub_path) {
        return None;
    }

    // 文件大小取自健康检查缓存，因此必须问将要供出内容的那个节点
    if let Ok(Some(health_info)) = redis.get_health_info(server_id, full_path).await
        && health_info.is_alive
    {
        return health_info
            .file_size
            .map(|size| (size, resource.cache_max_age));
    }

    debug!(
        "No usable health info for server '{}' path '{}'; cannot decide cache eligibility by size",
        server_id, full_path
    );
    None
}

/// 该资源与子路径是否在缓存范围内。
///
/// 只看配置，不看文件大小，因此可以在选点之前先用它挡掉不缓存的路径。
pub fn cache_eligible(resource: &ResourceConfig, sub_path: Option<&str>) -> bool {
    if !resource.cache_enabled {
        return false;
    }
    if resource.resource_type != "prefix" {
        return true;
    }
    sub_path.is_some_and(|sub| {
        resource
            .cache_subpaths
            .iter()
            .any(|pattern| glob_match(pattern, sub))
    })
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
    fn legacy_metadata_without_src_still_parses() {
        // 线上 Redis 里已有一批没有 src 字段的条目，反序列化失败会导致缓存全量击穿
        let legacy = r#"{"cached_at":1,"max_age":300,"content_length":10,"content_type":null,"etag":"\"x\""}"#;
        let metadata: CacheMetadata =
            serde_json::from_str(legacy).expect("legacy cache metadata must stay readable");
        assert!(metadata.src.is_none());

        let round_trip = serde_json::to_string(&metadata).expect("serialize");
        assert!(!round_trip.contains("src"));
    }

    fn resource(cache_enabled: bool, resource_type: &str, subpaths: &[&str]) -> ResourceConfig {
        ResourceConfig {
            latest: "1.0.0".to_string(),
            versions: std::collections::HashMap::new(),
            tries: vec![],
            server: vec![],
            flow: vec![],
            challenge: None,
            download: crate::config::DownloadPolicy::Enabled,
            resource_type: resource_type.to_string(),
            cache_enabled,
            cache_subpaths: subpaths.iter().map(|s| s.to_string()).collect(),
            cache_max_age: 300,
            legacy_client_support: false,
            legacy_client_full_range: false,
            changelog: None,
            version_provider: None,
            version_files: vec![],
            version_file_split_ttl: 300,
        }
    }

    #[test]
    fn cache_eligibility_depends_only_on_configuration() {
        // 普通资源：开关即结论，与子路径无关
        assert!(cache_eligible(&resource(true, "file", &[]), None));
        assert!(cache_eligible(&resource(true, "file", &[]), Some("a.json")));
        assert!(!cache_eligible(&resource(false, "file", &[]), None));

        // 前缀资源：必须有子路径且匹配某个模式
        let prefix = resource(true, "prefix", &["*.json", "images/*"]);
        assert!(cache_eligible(&prefix, Some("meta.json")));
        assert!(cache_eligible(&prefix, Some("images/logo.png")));
        assert!(!cache_eligible(&prefix, Some("bin/app.exe")));
        assert!(!cache_eligible(&prefix, None));
        assert!(!cache_eligible(
            &resource(true, "prefix", &[]),
            Some("meta.json")
        ));
        assert!(!cache_eligible(
            &resource(false, "prefix", &["*"]),
            Some("meta.json")
        ));
    }

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
