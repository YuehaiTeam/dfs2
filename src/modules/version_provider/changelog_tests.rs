use super::*;
use crate::config::{AppConfig, ResourceConfig, VersionProviderConfig};
use crate::data_store::{DataStore, FileDataStore};
use crate::modules::qjs::JsRunner;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tempdir::TempDir;

async fn create_test_data_store() -> DataStore {
    let temp_dir = TempDir::new("dfs2_test").expect("Failed to create temp directory");
    let file_store = FileDataStore::new(temp_dir.path().to_str().unwrap());
    DataStore::File(file_store)
}

fn create_config_with_changelog() -> Arc<RwLock<AppConfig>> {
    let mut config = AppConfig {
        servers: HashMap::new(),
        resources: HashMap::new(),
        plugins: HashMap::new(),
        plugin_code: HashMap::new(),
        debug_mode: true,
        challenge: crate::config::ChallengeConfig::default(),
        server_impl: HashMap::new(),
    };

    // 插件代码，返回changelog
    config.plugin_code.insert("version_provider_github".to_string(), r#"
        exports = async function(options, resourceId, extras) {
            if (resourceId === "with_changelog") {
                return {
                    version: "1.5.0",
                    changelog: "## Version 1.5.0\n\n### New Features\n- Added changelog support\n- Improved error handling\n\n### Bug Fixes\n- Fixed memory leak\n- Resolved timeout issues",
                    metadata: {
                        tag_name: "v1.5.0",
                        published_at: "2023-12-01T10:30:00Z"
                    }
                };
            } else if (resourceId === "no_changelog") {
                return {
                    version: "2.0.0",
                    changelog: null,
                    metadata: {
                        tag_name: "v2.0.0",
                        published_at: "2023-12-01T15:45:00Z"
                    }
                };
            } else {
                return {
                    version: "0.1.0",
                    metadata: null
                };
            }
        };
    "#.to_string());

    // 有changelog的资源（通过插件）
    let mut versions = HashMap::new();
    versions.insert("latest".to_string(), {
        let mut version_map = HashMap::new();
        version_map.insert("default".to_string(), "/releases/latest/app.exe".to_string());
        version_map
    });

    config.resources.insert("with_changelog".to_string(), ResourceConfig {
        latest: "1.5.0".to_string(),
        versions,
        tries: vec!["server1".to_string()],
        server: vec!["server1".to_string()],
        flow: vec![],
        challenge: None,
        download: crate::config::DownloadPolicy::Enabled,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: None, // 使用插件changelog
        version_provider: Some(VersionProviderConfig {
            r#type: "plugin".to_string(),
            plugin_name: "version_provider_github".to_string(),
            cache_ttl: Some(300),
            webhook_token: None,
            options: json!({"repo": "test/repo"}),
        }),
    });

    // 静态changelog资源（无插件）
    let mut versions2 = HashMap::new();
    versions2.insert("1.2.3".to_string(), {
        let mut version_map = HashMap::new();
        version_map.insert("default".to_string(), "/releases/1.2.3/app.exe".to_string());
        version_map
    });

    config.resources.insert("static_changelog".to_string(), ResourceConfig {
        latest: "1.2.3".to_string(),
        versions: versions2,
        tries: vec!["server1".to_string()],
        server: vec!["server1".to_string()],
        flow: vec![],
        challenge: None,
        download: crate::config::DownloadPolicy::Enabled,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: Some("## Static Changelog\n- This is a static changelog\n- Configured in YAML".to_string()),
        version_provider: None,
    });

    // 同时有静态和插件changelog的资源（插件优先）
    let mut versions3 = HashMap::new();
    versions3.insert("latest".to_string(), {
        let mut version_map = HashMap::new();
        version_map.insert("default".to_string(), "/releases/latest/tool.exe".to_string());
        version_map
    });

    config.resources.insert("both_changelog".to_string(), ResourceConfig {
        latest: "2.0.0".to_string(),
        versions: versions3,
        tries: vec!["server1".to_string()],
        server: vec!["server1".to_string()],
        flow: vec![],
        challenge: None,
        download: crate::config::DownloadPolicy::Enabled,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: Some("## Static Fallback Changelog\n- This should be overridden by plugin".to_string()),
        version_provider: Some(VersionProviderConfig {
            r#type: "plugin".to_string(),
            plugin_name: "version_provider_github".to_string(),
            cache_ttl: Some(300),
            webhook_token: None,
            options: json!({"repo": "test/both"}),
        }),
    });

    // 无changelog资源
    config.resources.insert("no_changelog".to_string(), ResourceConfig {
        latest: "1.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec!["server1".to_string()],
        server: vec!["server1".to_string()],
        flow: vec![],
        challenge: None,
        download: crate::config::DownloadPolicy::Enabled,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: None,
        version_provider: None,
    });

    Arc::new(RwLock::new(config))
}

#[tokio::test]
async fn test_plugin_changelog_extraction() {
    let data_store = create_test_data_store().await;
    let config = create_config_with_changelog();
    let js_runner = JsRunner::new(config.clone(), data_store).await;
    let provider = PluginVersionProvider::new(js_runner, config);

    let result = provider.fetch_version_info("with_changelog").await;
    assert!(result.is_ok(), "Failed to fetch version info: {:?}", result);

    let version_info = result.unwrap();
    assert_eq!(version_info.version, "1.5.0");
    assert!(version_info.changelog.is_some());
    
    let changelog = version_info.changelog.unwrap();
    assert!(changelog.contains("Version 1.5.0"));
    assert!(changelog.contains("New Features"));
    assert!(changelog.contains("Bug Fixes"));
    assert!(changelog.contains("Added changelog support"));
}

#[tokio::test] 
async fn test_plugin_no_changelog() {
    let data_store = create_test_data_store().await;
    let config = create_config_with_changelog();
    let js_runner = JsRunner::new(config.clone(), data_store).await;
    let provider = PluginVersionProvider::new(js_runner, config);

    let result = provider.fetch_version_info("no_changelog").await;
    assert!(result.is_ok(), "Failed to fetch version info: {:?}", result);

    let version_info = result.unwrap();
    assert_eq!(version_info.version, "2.0.0");
    assert!(version_info.changelog.is_none());
}

#[tokio::test]
async fn test_version_info_with_changelog() {
    let changelog_text = "## Release v3.1.0\n\n### Features\n- New API endpoints\n- Enhanced security\n\n### Fixes\n- Performance improvements";
    let metadata = json!({
        "release_name": "Major Update",
        "download_count": 1500,
        "assets": ["app.exe", "installer.msi"]
    });

    let version_info = VersionInfo::new(
        "3.1.0".to_string(),
        Some(changelog_text.to_string()),
        Some(metadata.clone())
    );

    assert_eq!(version_info.version, "3.1.0");
    assert!(version_info.changelog.is_some());
    assert_eq!(version_info.changelog.as_ref().unwrap(), changelog_text);
    assert_eq!(version_info.metadata, Some(metadata));

    // 测试序列化
    let serialized = serde_json::to_string(&version_info).unwrap();
    let deserialized: VersionInfo = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.version, "3.1.0");
    assert_eq!(deserialized.changelog.as_ref().unwrap(), changelog_text);
}

#[tokio::test]
async fn test_cache_with_changelog() {
    let data_store = create_test_data_store().await;
    let cache = VersionCache::new(data_store);

    let changelog = "## Test Changelog\n- Cached with changelog\n- Version info preserved";
    let version_info = VersionInfo::new(
        "1.8.0".to_string(),
        Some(changelog.to_string()),
        Some(json!({"test": true}))
    );

    // 设置缓存
    let result = cache.set_cached_version_info("test_resource", &version_info, 300).await;
    assert!(result.is_ok(), "Failed to cache version info: {:?}", result);

    // 获取缓存
    let cached_info = cache.get_cached_version_info("test_resource").await;
    assert!(cached_info.is_some());

    let cached = cached_info.unwrap();
    assert_eq!(cached.version, "1.8.0");
    assert_eq!(cached.changelog, Some(changelog.to_string()));
    assert!(cached.metadata.is_some());
}

#[tokio::test]
async fn test_updater_with_changelog() {
    let data_store = create_test_data_store().await;
    let config = create_config_with_changelog();
    let js_runner = JsRunner::new(config.clone(), data_store.clone()).await;
    let provider = Arc::new(PluginVersionProvider::new(js_runner, config.clone()));
    let cache = Arc::new(VersionCache::new(data_store));
    let updater = VersionUpdater::new(provider, cache.clone(), config);

    // 更新具有changelog的资源
    let result = updater.update_resource_immediately("with_changelog").await;
    assert!(result.is_ok(), "Failed to update resource: {:?}", result);

    let version = result.unwrap();
    assert_eq!(version, "1.5.0");

    // 验证changelog已缓存
    let cached_info = cache.get_cached_version_info("with_changelog").await;
    assert!(cached_info.is_some());

    let info = cached_info.unwrap();
    assert!(info.changelog.is_some());
    assert!(info.changelog.unwrap().contains("Version 1.5.0"));
}

#[tokio::test]
async fn test_changelog_serialization_edge_cases() {
    // 测试空changelog
    let empty_changelog_info = VersionInfo::new("1.0.0".to_string(), None, None);
    let serialized = serde_json::to_string(&empty_changelog_info).unwrap();
    let deserialized: VersionInfo = serde_json::from_str(&serialized).unwrap();
    assert!(deserialized.changelog.is_none());

    // 测试包含特殊字符的changelog
    let special_changelog = "## Version 2.0.0 🎉\n\n### Changes\n- Fixed issue #123\n- Added support for UTF-8 文本\n- Improved performance by 50%\n\n```javascript\nconst example = 'code block';\n```\n\n> **Note**: This is a blockquote";
    let special_info = VersionInfo::new("2.0.0".to_string(), Some(special_changelog.to_string()), None);
    
    let serialized = serde_json::to_string(&special_info).unwrap();
    let deserialized: VersionInfo = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.changelog.as_ref().unwrap(), special_changelog);

    // 测试长changelog
    let long_changelog = "## Version 3.0.0\n\n".to_string() + &"### New Features\n- Feature ".repeat(100) + "\n\n### Bug Fixes\n- Bug fix ".repeat(50);
    let long_info = VersionInfo::new("3.0.0".to_string(), Some(long_changelog.clone()), None);
    
    let serialized = serde_json::to_string(&long_info).unwrap();
    let deserialized: VersionInfo = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.changelog.as_ref().unwrap(), &long_changelog);
}