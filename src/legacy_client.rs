use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::challenge::Challenge;
use crate::config::AppConfig;
use crate::data_store::DataStore;
use crate::error::{DfsError, DfsResult};
use crate::models::Session;


pub struct LegacyClientHandler {
    config: Arc<RwLock<AppConfig>>,
    redis: DataStore,
}

impl LegacyClientHandler {
    pub fn new(config: Arc<RwLock<AppConfig>>, redis: DataStore) -> Self {
        Self { config, redis }
    }
    
    
    
    // 生成独立的 MD5 challenge 并直接创建对应的 session
    pub async fn generate_legacy_challenge(&self, resid: &str, range: Option<&str>) -> DfsResult<Challenge> {
        let client_id = Uuid::new_v4().to_string();
        let base_data = format!("legacy:{}:{}", resid, client_id);
        let challenge = Challenge::generate_md5(&base_data);
        
        // 计算预期的响应值
        let response_value = challenge.get_expected();
        
        // 根据 range 参数设置 session chunks
        let chunks = if let Some(range_str) = range {
            // 有 range 参数，使用指定的 range
            vec![range_str.to_string()]
        } else {
            // 没有 range 参数，默认完整文件下载
            vec!["0-".to_string()]
        };
        
        // 直接用响应值作为 session ID 创建 session
        let session = Session {
            resource_id: resid.to_string(),
            version: "latest".to_string(),
            chunks,
            cdn_records: HashMap::new(),
            extras: serde_json::json!({}), // 历史客户端使用空extras
        };
        
        self.redis.store_session(&response_value, &session).await
            .map_err(|e| DfsError::redis_error("create_legacy_session", e.to_string()))?;
        
        Ok(challenge)
    }
    
}