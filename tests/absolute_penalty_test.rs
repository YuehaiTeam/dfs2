use dfs2::models::{CdnRecord, Session};
use dfs2::data_store::{DataStoreBackend, SessionStats};
use dfs2::modules::flow::runner::FlowRunner;
use dfs2::config::AppConfig;
use dfs2::modules::qjs::JsRunner;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// 创建一个简单的内存数据存储用于测试
struct MockDataStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    cdn_records: Arc<RwLock<HashMap<String, HashMap<String, Vec<CdnRecord>>>>>,
}

impl MockDataStore {
    fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            cdn_records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl DataStoreBackend for MockDataStore {
    async fn store_session(&self, session_id: &str, session: &Session) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.to_string(), session.clone());
        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<Session>, String> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    async fn remove_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    async fn update_cdn_record_v2(&self, session_id: &str, chunk_id: &str, record: CdnRecord) -> Result<(), String> {
        let mut cdn_records = self.cdn_records.write().await;
        let session_records = cdn_records.entry(session_id.to_string()).or_insert_with(HashMap::new);
        let chunk_records = session_records.entry(chunk_id.to_string()).or_insert_with(Vec::new);
        chunk_records.push(record);
        Ok(())
    }

    async fn get_cdn_records(&self, session_id: &str, chunk_key: &str) -> Result<Vec<CdnRecord>, String> {
        let cdn_records = self.cdn_records.read().await;
        if let Some(session_records) = cdn_records.get(session_id) {
            if let Some(chunk_records) = session_records.get(chunk_key) {
                return Ok(chunk_records.clone());
            }
        }
        Ok(Vec::new())
    }

    // 下面是其他必需的trait方法的空实现
    async fn get_download_counts(&self, _sid: &str) -> Result<HashMap<String, u32>, String> {
        Ok(HashMap::new())
    }

    async fn update_session_path(&self, _sid: &str, _path: &str) -> Result<bool, String> {
        Ok(true)
    }

    async fn update_session_chunks(&self, _sid: &str, _chunks: &[String]) -> Result<bool, String> {
        Ok(true)
    }

    async fn update_cdn_record(&self, _sid: &str, _chunk: &str, _cdn_url: &str) -> Result<(), String> {
        Ok(())
    }

    async fn increment_download_count(&self, _sid: &str, _chunk_id: &str) -> Result<Option<u32>, String> {
        Ok(Some(1))
    }

    async fn refresh_session(&self, _sid: &str) -> Result<(), String> {
        Ok(())
    }

    async fn set_cached_metadata(&self, _key: &str, _value: &str, _expires: u32) -> Result<(), String> {
        Ok(())
    }

    async fn get_cached_metadata(&self, _key: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn set_string(&self, _key: &str, _value: &str, _expires: Option<u32>) -> Result<(), String> {
        Ok(())
    }

    async fn get_string(&self, _key: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn set_alive_status(&self, _server_id: &str, _path: &str, _is_alive: bool) -> Result<(), String> {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> Result<(), String> {
        Ok(())
    }

    async fn get_alive_status(&self, _server_id: &str, _path: &str) -> Result<Option<bool>, String> {
        Ok(None)
    }

    async fn write_js_storage(&self, _key: String, _value: String, _expires: u32) -> bool {
        true
    }

    async fn read_js_storage(&self, _key: String) -> Option<String> {
        None
    }

    async fn store_challenge(&self, _session_id: &str, _challenge_data: &str) -> Result<(), String> {
        Ok(())
    }

    async fn remove_challenge(&self, _session_id: &str) -> Result<(), String> {
        Ok(())
    }

    async fn get_challenge(&self, _session_id: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn get_session_stats(&self, _session_id: &str) -> Result<Option<SessionStats>, String> {
        Ok(None)
    }
}

#[tokio::test]
async fn test_absolute_minimum_penalty_strategy() {
    // 创建测试数据存储
    let data_store = MockDataStore::new();
    let store = Arc::new(data_store) as Arc<dyn DataStoreBackend>;
    
    // 创建测试配置
    let config = Arc::new(RwLock::new(AppConfig {
        servers: HashMap::new(),
        resources: HashMap::new(),
        plugins: HashMap::new(),
        debug_mode: true,
        plugin_code: HashMap::new(),
        server_impl: HashMap::new(),
        challenge: dfs2::config::ChallengeConfig::default(),
    }));
    
    // 创建 JsRunner
    let js_runner = JsRunner::new(config.clone(), store.clone()).await;
    
    // 创建 FlowRunner
    let flow_runner = FlowRunner {
        config: config.clone(),
        redis: store.clone(),
        jsrunner: js_runner,
    };
    
    let session_id = "test_penalty_session";
    let chunk_key = "0-1024";
    
    // 创建会话
    let session = Session {
        path: "/test/penalty_file.txt".to_string(),
        chunks: vec![chunk_key.to_string()],
        cdn_records: HashMap::new(),
    };
    
    store.store_session(session_id, &session).await.expect("Failed to store session");
    
    // 模拟第一次调度，选择了高权重服务器（server_high_priority）
    let record_high = CdnRecord {
        url: "https://high-priority-server.com/file.txt".to_string(),
        server_id: Some("server_high_priority".to_string()),
        skip_penalty: false,  // 不跳过惩罚
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    store.update_cdn_record_v2(session_id, chunk_key, record_high).await
        .expect("Failed to update CDN record for high priority server");
    
    // 现在测试惩罚策略：创建一个权重差异很大的服务器池
    let mut server_pool = vec![
        ("server_high_priority".to_string(), 999),    // 之前选择过的高权重服务器
        ("server_medium_priority".to_string(), 50),   // 中等权重服务器  
        ("server_low_priority".to_string(), 5),       // 低权重服务器
    ];
    
    println!("Before penalty - Server pool: {:?}", server_pool);
    
    // 应用惩罚策略
    flow_runner.apply_penalty_for_repeated_requests(
        session_id, 
        &Some(vec![(0, 1024)]), 
        &mut server_pool
    ).await;
    
    println!("After penalty - Server pool: {:?}", server_pool);
    
    // 验证惩罚结果
    let high_priority_weight = server_pool.iter()
        .find(|(name, _)| name == "server_high_priority")
        .map(|(_, weight)| *weight)
        .expect("High priority server should still be in pool");
    
    let medium_priority_weight = server_pool.iter()
        .find(|(name, _)| name == "server_medium_priority")
        .map(|(_, weight)| *weight)
        .expect("Medium priority server should still be in pool");
        
    let low_priority_weight = server_pool.iter()
        .find(|(name, _)| name == "server_low_priority")
        .map(|(_, weight)| *weight)
        .expect("Low priority server should still be in pool");
    
    // 关键断言：被惩罚的高权重服务器现在应该具有最低权重
    assert_eq!(high_priority_weight, 5, 
               "High priority server should be penalized to minimum weight of 5");
    
    // 未被惩罚的服务器权重应该保持不变
    assert_eq!(medium_priority_weight, 50, 
               "Medium priority server weight should remain unchanged");
    assert_eq!(low_priority_weight, 5, 
               "Low priority server weight should remain unchanged");
    
    // 验证被惩罚服务器的权重不再是最高的
    assert!(high_priority_weight <= medium_priority_weight, 
            "Penalized server should not have higher weight than non-penalized servers");
    assert!(high_priority_weight <= low_priority_weight, 
            "Penalized server should not have higher weight than non-penalized servers");
    
    println!("✅ Absolute minimum penalty strategy test passed!");
    println!("   High priority server (999 -> {})", high_priority_weight);
    println!("   Medium priority server (50 -> {})", medium_priority_weight);
    println!("   Low priority server (5 -> {})", low_priority_weight);
}

#[tokio::test]
async fn test_multiple_servers_penalty() {
    // 测试多个服务器同时被惩罚的情况
    let data_store = MockDataStore::new();
    let store = Arc::new(data_store) as Arc<dyn DataStoreBackend>;
    
    let config = Arc::new(RwLock::new(AppConfig {
        servers: HashMap::new(),
        resources: HashMap::new(),
        plugins: HashMap::new(),
        debug_mode: true,
        plugin_code: HashMap::new(),
        server_impl: HashMap::new(),
        challenge: dfs2::config::ChallengeConfig::default(),
    }));
    
    let js_runner = JsRunner::new(config.clone(), store.clone()).await;
    let flow_runner = FlowRunner {
        config: config.clone(),
        redis: store.clone(),
        jsrunner: js_runner,
    };
    
    let session_id = "test_multiple_penalty";
    let chunk_key = "0-2048";
    
    let session = Session {
        path: "/test/multiple_penalty.txt".to_string(),
        chunks: vec![chunk_key.to_string()],
        cdn_records: HashMap::new(),
    };
    
    store.store_session(session_id, &session).await.expect("Failed to store session");
    
    // 添加两个之前使用过的服务器记录
    let record1 = CdnRecord {
        url: "https://server-a.com/file.txt".to_string(),
        server_id: Some("server_a".to_string()),
        skip_penalty: false,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    let record2 = CdnRecord {
        url: "https://server-b.com/file.txt".to_string(),
        server_id: Some("server_b".to_string()),
        skip_penalty: false,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    store.update_cdn_record_v2(session_id, chunk_key, record1).await.unwrap();
    store.update_cdn_record_v2(session_id, chunk_key, record2).await.unwrap();
    
    // 创建服务器池：两个高权重服务器之前被使用过，一个低权重服务器没有
    let mut server_pool = vec![
        ("server_a".to_string(), 800),        // 被惩罚
        ("server_b".to_string(), 900),        // 被惩罚
        ("server_c".to_string(), 10),         // 未被惩罚，最小权重
    ];
    
    println!("Before multiple penalty - Server pool: {:?}", server_pool);
    
    flow_runner.apply_penalty_for_repeated_requests(
        session_id, 
        &Some(vec![(0, 2048)]), 
        &mut server_pool
    ).await;
    
    println!("After multiple penalty - Server pool: {:?}", server_pool);
    
    // 验证：两个被惩罚的服务器都应该被设置为最小权重10
    let server_a_weight = server_pool.iter()
        .find(|(name, _)| name == "server_a")
        .map(|(_, weight)| *weight).unwrap();
    let server_b_weight = server_pool.iter()
        .find(|(name, _)| name == "server_b")
        .map(|(_, weight)| *weight).unwrap();
    let server_c_weight = server_pool.iter()
        .find(|(name, _)| name == "server_c")
        .map(|(_, weight)| *weight).unwrap();
    
    assert_eq!(server_a_weight, 10, "Server A should be penalized to minimum weight");
    assert_eq!(server_b_weight, 10, "Server B should be penalized to minimum weight");
    assert_eq!(server_c_weight, 10, "Server C weight should remain unchanged");
    
    println!("✅ Multiple servers penalty test passed!");
    println!("   Server A (800 -> {})", server_a_weight);
    println!("   Server B (900 -> {})", server_b_weight);
    println!("   Server C (10 -> {})", server_c_weight);
}