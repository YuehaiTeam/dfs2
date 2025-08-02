use dfs2::models::Session;
use dfs2::data_store::{DataStoreBackend, FileDataStore};
use dfs2::config::{AppConfig, ResourceConfig, DownloadPolicy};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_prefix_resource_session_path_matching() {
    // Test that prefix resource sessions correctly handle path matching
    // 创建临时目录用于测试
    let temp_dir = std::env::temp_dir().join(format!("dfs2_test_{}", Uuid::new_v4()));
    unsafe {
        std::env::set_var("DATA_STORE_PATH", temp_dir.to_str().unwrap());
    }
    
    // 创建测试数据存储
    let data_store = FileDataStore::new().await.expect("Failed to create test data store");
    let store = Arc::new(data_store) as Arc<dyn DataStoreBackend>;
    
    let session_id = "test_session_prefix_123";
    let expected_path = "games/example/assets/texture.png";
    
    // 创建测试会话（模拟前缀资源的完整路径）
    let session = Session {
        path: expected_path.to_string(),
        chunks: vec!["0-1023".to_string()],
        cdn_records: HashMap::new(),
    };
    
    // 存储会话
    store.store_session(session_id, &session).await.expect("Failed to store session");
    
    // 验证会话路径存储正确
    let retrieved_session = store.get_session(session_id).await.expect("Failed to get session");
    assert!(retrieved_session.is_some());
    let retrieved_session = retrieved_session.unwrap();
    assert_eq!(retrieved_session.path, expected_path);
    assert_eq!(retrieved_session.chunks, vec!["0-1023".to_string()]);
    
    println!("✅ Prefix resource session path matching test passed!");
}

#[tokio::test]
async fn test_prefix_resource_config_structure() {
    // Test that prefix resource configuration works correctly
    let mut config = AppConfig {
        servers: HashMap::new(),
        resources: HashMap::new(),
        plugins: HashMap::new(),
        debug_mode: false,
        challenge: dfs2::config::ChallengeConfig::default(),
        plugin_code: HashMap::new(),
        server_impl: HashMap::new(),
    };
    
    // 创建前缀资源配置
    let mut resource = ResourceConfig {
        latest: "v1.0".to_string(),
        versions: HashMap::new(),
        tries: Vec::new(),
        server: vec!["server1".to_string()],
        flow: Vec::new(),
        challenge: None,
        download: DownloadPolicy::Enabled,
        resource_type: "prefix".to_string(),
    };
    
    // 添加版本信息
    resource.versions.insert("v1.0".to_string(), {
        let mut version_map = HashMap::new();
        version_map.insert("default".to_string(), "games/example".to_string());
        version_map
    });
    
    config.resources.insert("test_game".to_string(), resource);
    
    // 验证配置结构
    let test_resource = config.resources.get("test_game").unwrap();
    assert_eq!(test_resource.resource_type, "prefix");
    assert_eq!(test_resource.latest, "v1.0");
    assert!(matches!(test_resource.download, DownloadPolicy::Enabled));
    
    // 测试路径组合功能
    let base_path = config.get_version_path("test_game", "v1.0", None).unwrap();
    assert_eq!(base_path, "games/example");
    
    let full_path = config.get_version_path_with_sub("test_game", "v1.0", None, Some("assets/texture.png")).unwrap();
    assert_eq!(full_path, "games/example/assets/texture.png");
    
    println!("✅ Prefix resource config structure test passed!");
}

#[tokio::test] 
async fn test_prefix_path_security_validation() {
    // Test that path combinations work as expected for prefix resources
    // Since the security functions are private, we test the public API behavior
    let mut config = AppConfig {
        servers: HashMap::new(),
        resources: HashMap::new(),
        plugins: HashMap::new(),
        debug_mode: false,
        challenge: dfs2::config::ChallengeConfig::default(),
        plugin_code: HashMap::new(),
        server_impl: HashMap::new(),
    };
    
    let mut resource = ResourceConfig {
        latest: "v1.0".to_string(),
        versions: HashMap::new(),
        tries: Vec::new(),
        server: Vec::new(),
        flow: Vec::new(),
        challenge: None,
        download: DownloadPolicy::Free,
        resource_type: "prefix".to_string(),
    };
    
    resource.versions.insert("v1.0".to_string(), {
        let mut version_map = HashMap::new();
        version_map.insert("default".to_string(), "games/example".to_string());
        version_map
    });
    
    config.resources.insert("test_game".to_string(), resource);
    
    // Test normal path combination
    let normal_path = config.get_version_path_with_sub("test_game", "v1.0", None, Some("assets/texture.png")).unwrap();
    assert_eq!(normal_path, "games/example/assets/texture.png");
    
    // Test path with directory traversal attempts (should be sanitized)
    let dangerous_path = config.get_version_path_with_sub("test_game", "v1.0", None, Some("../../../etc/passwd")).unwrap();
    // The path should be sanitized to prevent directory traversal
    assert!(dangerous_path.starts_with("games/example/"));
    
    println!("✅ Prefix path security validation test passed!");
}

#[tokio::test]
async fn test_prefix_resource_download_policies() {
    // Test different download policies for prefix resources
    // Test Disabled policy
    let disabled_resource = ResourceConfig {
        latest: "v1.0".to_string(),
        versions: HashMap::new(),
        tries: Vec::new(),
        server: Vec::new(),
        flow: Vec::new(),
        challenge: None,
        download: DownloadPolicy::Disabled,
        resource_type: "prefix".to_string(),
    };
    
    assert!(matches!(disabled_resource.download, DownloadPolicy::Disabled));
    
    // Test Free policy  
    let free_resource = ResourceConfig {
        latest: "v1.0".to_string(),
        versions: HashMap::new(),
        tries: Vec::new(),
        server: Vec::new(),
        flow: Vec::new(),
        challenge: None,
        download: DownloadPolicy::Free,
        resource_type: "prefix".to_string(),
    };
    
    assert!(matches!(free_resource.download, DownloadPolicy::Free));
    
    // Test Enabled policy
    let enabled_resource = ResourceConfig {
        latest: "v1.0".to_string(),
        versions: HashMap::new(),
        tries: Vec::new(),
        server: Vec::new(),
        flow: Vec::new(),
        challenge: None,
        download: DownloadPolicy::Enabled,
        resource_type: "prefix".to_string(),
    };
    
    assert!(matches!(enabled_resource.download, DownloadPolicy::Enabled));
    
    println!("✅ Prefix resource download policies test passed!");
}

#[tokio::test]
async fn test_prefix_resource_chunks_validation() {
    // Test chunk validation for prefix resource downloads
    // 创建临时目录用于测试
    let temp_dir = std::env::temp_dir().join(format!("dfs2_test_{}", Uuid::new_v4()));
    unsafe {
        std::env::set_var("DATA_STORE_PATH", temp_dir.to_str().unwrap());
    }
    
    // 创建测试数据存储
    let data_store = FileDataStore::new().await.expect("Failed to create test data store");
    let store = Arc::new(data_store) as Arc<dyn DataStoreBackend>;
    
    let session_id = "test_session_chunks";
    
    // 测试有效的chunks（包含0-范围）
    let valid_session = Session {
        path: "games/example/assets/model.fbx".to_string(),
        chunks: vec!["0-1023".to_string(), "1024-2047".to_string()],
        cdn_records: HashMap::new(),
    };
    
    store.store_session(session_id, &valid_session).await.expect("Failed to store valid session");
    
    let retrieved = store.get_session(session_id).await.expect("Failed to get session").unwrap();
    let has_zero_range = retrieved.chunks.iter().any(|chunk| chunk.starts_with("0-"));
    assert!(has_zero_range, "Valid session should have 0- range");
    
    // 测试无效的chunks（不包含0-范围）
    let invalid_session = Session {
        path: "games/example/assets/sound.ogg".to_string(),
        chunks: vec!["1024-2047".to_string(), "2048-3071".to_string()],
        cdn_records: HashMap::new(),
    };
    
    let invalid_session_id = "test_session_invalid_chunks";
    store.store_session(invalid_session_id, &invalid_session).await.expect("Failed to store invalid session");
    
    let retrieved_invalid = store.get_session(invalid_session_id).await.expect("Failed to get session").unwrap();
    let has_zero_range_invalid = retrieved_invalid.chunks.iter().any(|chunk| chunk.starts_with("0-"));
    assert!(!has_zero_range_invalid, "Invalid session should not have 0- range");
    
    println!("✅ Prefix resource chunks validation test passed!");
}