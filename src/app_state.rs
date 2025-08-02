use crate::data_store::DataStoreBackend;
use std::env;
use std::sync::Arc;

lazy_static::lazy_static! {
    pub static ref MAX_CHUNK_DOWNLOADS: u32 = env::var("MAX_CHUNK_DOWNLOADS")
        .unwrap_or_else(|_| "3".to_string())
        .parse()
        .unwrap_or(3);
}

lazy_static::lazy_static! {
    pub static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::builder()
        .user_agent("DFS2-Server/1.0")
        .read_timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| {
            // Use panic here since this is a startup critical error
            panic!("Failed to build reqwest client: {}", e);
        })
        .unwrap();
}

// 导出别名以保持向后兼容
pub type DataStore = Arc<dyn DataStoreBackend>;
pub type RedisStore = Arc<dyn DataStoreBackend>; // 保持向后兼容的别名

/// 创建数据存储后端
/// 支持通过环境变量选择存储类型：
/// - DATA_STORE_TYPE=redis: 使用Redis存储
/// - DATA_STORE_TYPE=file (默认): 使用文件存储
pub async fn create_data_store() -> Result<DataStore, String> {
    let store_type = env::var("DATA_STORE_TYPE").unwrap_or_else(|_| "file".to_string());
    
    match store_type.to_lowercase().as_str() {
        "redis" => {
            // Redis存储
            let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
            let redis_client = redis::Client::open(redis_url)
                .map_err(|e| format!("Failed to create Redis client: {}", e))?;
            
            let redis_store = crate::redis_data_store::RedisDataStore::new(redis_client);
            Ok(Arc::new(redis_store))
        }
        "file" => {
            // 文件存储
            let file_store = crate::data_store::FileDataStore::new().await?;
            Ok(Arc::new(file_store))
        }
        _ => {
            Err(format!("Unsupported data store type: {}. Supported types: redis, file", store_type))
        }
    }
}