use super::*;
use crate::modules::storage::data_store::{DataStore, FileDataStore};
use std::sync::Arc;
use tokio::sync::RwLock;
use tempdir::TempDir;
use serde_json::json;

async fn create_test_data_store() -> DataStore {
    let temp_dir = TempDir::new("dfs2_test").expect("Failed to create temp directory");
    let file_store = FileDataStore::new(temp_dir.path().to_str().unwrap());
    DataStore::File(file_store)
}

fn create_test_config() -> Arc<RwLock<crate::config::AppConfig>> {
    let mut config = crate::config::AppConfig {
        servers: std::collections::HashMap::new(),
        resources: std::collections::HashMap::new(),
        plugins: std::collections::HashMap::new(),
        plugin_code: std::collections::HashMap::new(),
        debug_mode: true,
        challenge: crate::config::ChallengeConfig::default(),
        server_impl: std::collections::HashMap::new(),
    };

    // 添加测试插件 - 参数顺序匹配实际插件签名 (options, resourceId, extras)
    config.plugin_code.insert("version_provider_test".to_string(),
        "exports = async function(options, resourceId, extras) {\
            if (resourceId === \"test_resource\") {\
                return {\
                    version: \"1.0.0\",\
                    changelog: \"## Test Release v1.0.0\\n- Initial release\\n- Basic functionality\",\
                    metadata: {\
                        release_name: \"Test Release\",\
                        published_at: \"2023-01-01T00:00:00Z\"\
                    }\
                };\
            } else if (resourceId === \"error_resource\") {\
                throw new Error(\"Test error\");\
            } else {\
                return {\
                    version: \"0.0.0\",\
                    changelog: null,\
                    metadata: null\
                };\
            }\
        };".to_string());

    Arc::new(RwLock::new(config))
}

#[tokio::test]
async fn test_version_cache_basic_operations() {
    let data_store = create_test_data_store().await;
    let cache = VersionCache::new(data_store);

    let resource_id = "test_resource";
    let version = "1.2.3";
    let ttl = 300;

    // 测试设置缓存
    let result = cache.set_cached_version(resource_id, version, ttl).await;
    assert!(result.is_ok(), "Failed to set cached version: {:?}", result);

    // 测试获取缓存
    let cached = cache.get_cached_version(resource_id).await;
    assert_eq!(cached, Some(version.to_string()), "Cached version mismatch");

    // 测试TTL检查
    let should_update = cache.should_update(resource_id, ttl).await;
    assert!(!should_update, "Should not update immediately after setting");
}

#[tokio::test]
async fn test_version_cache_expiry() {
    let data_store = create_test_data_store().await;
    let cache = VersionCache::new(data_store);

    let resource_id = "expire_test";
    let version = "1.0.0";
    let ttl = 1; // 1 second TTL

    // 设置缓存
    let _ = cache.set_cached_version(resource_id, version, ttl).await;

    // 立即检查，应该不需要更新
    assert!(!cache.should_update(resource_id, ttl).await);

    // 等待过期
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // 现在应该需要更新
    assert!(cache.should_update(resource_id, ttl).await);
}

#[tokio::test]
async fn test_plugin_version_provider_success() {
    let data_store = create_test_data_store().await;
    let config = create_test_config();
    let js_runner = crate::modules::qjs::JsRunner::new(config.clone(), data_store).await;
    let provider = PluginVersionProvider::new(js_runner, config);

    let resource_id = "test_resource";
    let result = provider.fetch_version_info(resource_id).await;

    assert!(result.is_ok(), "Plugin execution should succeed");
    let version_info = result.unwrap();
    assert_eq!(version_info.version, "1.0.0");
    assert!(version_info.changelog.is_some());
    assert!(version_info.changelog.as_ref().unwrap().contains("Test Release v1.0.0"));
    assert!(version_info.metadata.is_some());
    
    let metadata = version_info.metadata.unwrap();
    assert_eq!(metadata["release_name"], "Test Release");
}

#[tokio::test]
async fn test_plugin_version_provider_error() {
    let data_store = create_test_data_store().await;
    let config = create_test_config();
    let js_runner = crate::modules::qjs::JsRunner::new(config.clone(), data_store).await;
    let provider = PluginVersionProvider::new(js_runner, config);

    let resource_id = "error_resource";
    let result = provider.fetch_version_info(resource_id).await;

    assert!(result.is_err(), "Plugin should fail for error_resource");
    assert!(result.unwrap_err().to_string().contains("Test error"));
}

#[tokio::test]
async fn test_version_updater_update_single_resource() {
    let data_store = create_test_data_store().await;
    let config = create_test_config();
    let js_runner = crate::modules::qjs::JsRunner::new(config.clone(), data_store.clone()).await;
    let provider = Arc::new(PluginVersionProvider::new(js_runner, config.clone()));
    let cache = Arc::new(VersionCache::new(data_store));
    let updater = VersionUpdater::new(provider, cache.clone(), config);

    let resource_id = "test_resource";
    let result = updater.update_resource_immediately(resource_id).await;

    assert!(result.is_ok(), "Resource update should succeed");
    let version = result.unwrap();
    assert_eq!(version, "1.0.0");

    // 验证缓存已更新
    let cached = cache.get_cached_version(resource_id).await;
    assert_eq!(cached, Some("1.0.0".to_string()));
}

#[tokio::test]
async fn test_version_info_serialization() {
    let version_info = VersionInfo {
        version: "2.0.0".to_string(),
        changelog: Some("## v2.0.0\n- New feature added\n- Bug fixes".to_string()),
        metadata: Some(json!({
            "tag_name": "v2.0.0",
            "prerelease": false,
            "published_at": "2023-12-01T00:00:00Z"
        })),
        cached_at: std::time::SystemTime::now(),
    };

    let serialized = serde_json::to_string(&version_info).unwrap();
    let deserialized: VersionInfo = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.version, "2.0.0");
    assert!(deserialized.changelog.is_some());
    assert!(deserialized.changelog.unwrap().contains("v2.0.0"));
    assert!(deserialized.metadata.is_some());
    assert_eq!(deserialized.metadata.unwrap()["tag_name"], "v2.0.0");
}

#[tokio::test]
async fn test_updater_error_handling() {
    let data_store = create_test_data_store().await;
    let config = create_test_config();
    let js_runner = crate::modules::qjs::JsRunner::new(config.clone(), data_store.clone()).await;
    let provider = Arc::new(PluginVersionProvider::new(js_runner, config.clone()));
    let cache = Arc::new(VersionCache::new(data_store));
    let updater = VersionUpdater::new(config, cache, provider);

    // 测试不存在的资源
    let result = updater.update_resource_immediately("nonexistent_resource").await;
    assert!(result.is_err(), "Should fail for nonexistent resource");

    // 测试插件错误处理
    let result = updater.update_resource_immediately("error_resource").await;
    assert!(result.is_err(), "Should fail for error-inducing resource");
}

#[tokio::test]
async fn test_cache_ttl_percentage_refresh() {
    let data_store = create_test_data_store().await;
    let cache = VersionCache::new(data_store);

    let resource_id = "ttl_test";
    let version = "1.0.0";
    let ttl = 10; // 10 seconds

    // 设置缓存
    let _ = cache.set_cached_version(resource_id, version, ttl).await;

    // 立即检查 - 不应该需要更新（0% TTL已过）
    assert!(!cache.should_update(resource_id, ttl).await);

    // 等待超过80%的TTL（8秒）
    tokio::time::sleep(tokio::time::Duration::from_secs(8)).await;

    // 现在应该需要更新（超过80% TTL）
    assert!(cache.should_update(resource_id, ttl).await);
}