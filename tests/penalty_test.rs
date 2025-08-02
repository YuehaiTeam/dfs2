use dfs2::models::{CdnRecord, Session};
use dfs2::data_store::{DataStoreBackend, FileDataStore};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_server_penalty_mechanism() {
    // 创建临时目录用于测试
    let temp_dir = std::env::temp_dir().join(format!("dfs2_test_{}", Uuid::new_v4()));
    unsafe {
        std::env::set_var("DATA_STORE_PATH", temp_dir.to_str().unwrap());
    }
    
    // 创建测试数据存储
    let data_store = FileDataStore::new().await.expect("Failed to create test data store");
    let store = Arc::new(data_store) as Arc<dyn DataStoreBackend>;
    
    let session_id = "test_session_123";
    let chunk_id = "0-1023";
    
    // 创建测试会话
    let session = Session {
        path: "/test/file.txt".to_string(),
        chunks: vec![chunk_id.to_string()],
        cdn_records: HashMap::new(),
    };
    
    // 存储会话
    store.store_session(session_id, &session).await.expect("Failed to store session");
    
    // 添加第一次调度记录（server_a）
    let record1 = CdnRecord {
        url: "https://server-a.com/file.txt".to_string(),
        server_id: Some("server_a".to_string()),
        skip_penalty: false,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    store.update_cdn_record_v2(session_id, chunk_id, record1).await
        .expect("Failed to update CDN record");
    
    // 添加第二次调度记录（server_b）
    let record2 = CdnRecord {
        url: "https://server-b.com/file.txt".to_string(),
        server_id: Some("server_b".to_string()),
        skip_penalty: false,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    store.update_cdn_record_v2(session_id, chunk_id, record2).await
        .expect("Failed to update CDN record");
    
    // 验证记录是否正确存储
    let records = store.get_cdn_records(session_id, chunk_id).await
        .expect("Failed to get CDN records");
    
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].server_id, Some("server_a".to_string()));
    assert_eq!(records[1].server_id, Some("server_b".to_string()));
    assert!(!records[0].skip_penalty);
    assert!(!records[1].skip_penalty);
    
    // 添加一个跳过惩罚的记录（premium server）
    let record3 = CdnRecord {
        url: "https://premium-server.com/file.txt".to_string(),
        server_id: Some("premium_server".to_string()),
        skip_penalty: true,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    store.update_cdn_record_v2(session_id, chunk_id, record3).await
        .expect("Failed to update CDN record");
    
    let records = store.get_cdn_records(session_id, chunk_id).await
        .expect("Failed to get CDN records");
    
    assert_eq!(records.len(), 3);
    assert_eq!(records[2].server_id, Some("premium_server".to_string()));
    assert!(records[2].skip_penalty);
    
    println!("✅ Server penalty mechanism test passed!");
}

#[tokio::test]
async fn test_cdn_record_serialization() {
    // 创建临时目录用于测试
    let temp_dir = std::env::temp_dir().join(format!("dfs2_test_{}", Uuid::new_v4()));
    unsafe {
        std::env::set_var("DATA_STORE_PATH", temp_dir.to_str().unwrap());
    }
    
    let record = CdnRecord {
        url: "https://test.com/file.txt".to_string(),
        server_id: Some("test_server".to_string()),
        skip_penalty: true,
        timestamp: 1640995200,
    };
    
    // 测试序列化
    let json = serde_json::to_string(&record).expect("Failed to serialize CdnRecord");
    let deserialized: CdnRecord = serde_json::from_str(&json).expect("Failed to deserialize CdnRecord");
    
    assert_eq!(record.url, deserialized.url);
    assert_eq!(record.server_id, deserialized.server_id);
    assert_eq!(record.skip_penalty, deserialized.skip_penalty);
    assert_eq!(record.timestamp, deserialized.timestamp);
    
    println!("✅ CdnRecord serialization test passed!");
}