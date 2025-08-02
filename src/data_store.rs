use crate::models::{Session, CdnRecord};
use crate::modules::server::HealthInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::info;

/// 缓存元数据，与实际内容分离存储
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub cached_at: u64,               // Unix timestamp
    pub max_age: u32,                 // 缓存时间（秒）
    pub content_length: u64,          // 内容长度
    pub content_type: Option<String>, // MIME类型
    pub etag: String,                 // xxhash ETag
}

impl CacheMetadata {
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        now > self.cached_at + self.max_age as u64
    }
    
    /// 返回真实的剩余max-age，用于Cache-Control头部
    pub fn remaining_max_age(&self) -> u32 {
        let now = chrono::Utc::now().timestamp() as u64;
        let expires_at = self.cached_at + self.max_age as u64;
        if now >= expires_at {
            0
        } else {
            (expires_at - now) as u32
        }
    }
}

/// 缓存键结构
pub struct CacheKeys {
    pub metadata_key: String,
    pub content_key: String,
}

// 数据存储后端抽象
#[async_trait::async_trait]
pub trait DataStoreBackend: Send + Sync {
    async fn store_session(&self, sid: &str, session: &Session) -> Result<(), String>;
    async fn get_session(&self, sid: &str) -> Result<Option<Session>, String>;
    async fn remove_session(&self, sid: &str) -> Result<(), String>;
    async fn increment_download_count(&self, sid: &str, chunk: &str) -> Result<Option<u32>, String>;
    async fn refresh_session(&self, sid: &str) -> Result<(), String>;
    async fn get_download_counts(&self, sid: &str) -> Result<HashMap<String, u32>, String>;
    async fn update_session_path(&self, sid: &str, path: &str) -> Result<bool, String>;
    async fn update_session_chunks(&self, sid: &str, chunks: &[String]) -> Result<bool, String>;
    async fn update_cdn_record(&self, sid: &str, chunk: &str, cdn_url: &str) -> Result<(), String>;
    async fn update_cdn_record_v2(&self, sid: &str, chunk: &str, record: CdnRecord) -> Result<(), String>;
    async fn get_cdn_records(&self, sid: &str, chunk: &str) -> Result<Vec<CdnRecord>, String>;
    async fn get_session_stats(&self, sid: &str) -> Result<Option<SessionStats>, String>;
    async fn read_js_storage(&self, key: String) -> Option<String>;
    async fn write_js_storage(&self, key: String, value: String, expires: u32) -> bool;
    async fn get_cached_metadata(&self, key: &str) -> Result<Option<String>, String>;
    async fn set_cached_metadata(&self, key: &str, value: &str, expires: u32) -> Result<(), String>;
    async fn get_string(&self, key: &str) -> Result<Option<String>, String>;
    async fn set_string(&self, key: &str, value: &str, expires: Option<u32>) -> Result<(), String>;
    async fn get_alive_status(&self, server_id: &str, path: &str) -> Result<Option<bool>, String>;
    async fn set_alive_status(&self, server_id: &str, path: &str, is_alive: bool) -> Result<(), String>;
    
    // 新增：健康信息支持
    async fn get_health_info(&self, server_id: &str, path: &str) -> Result<Option<HealthInfo>, String>;
    async fn set_health_info(&self, server_id: &str, path: &str, info: &HealthInfo) -> Result<(), String>;
    
    // 新增：分离式内容缓存接口
    async fn get_cache_metadata(&self, key: &str) -> Result<Option<CacheMetadata>, String>;
    async fn get_cache_content(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    async fn set_cache_entry(&self, meta_key: &str, content_key: &str, 
                           metadata: &CacheMetadata, content: &[u8]) -> Result<(), String>;
    
    // 便捷方法：生成缓存键
    fn generate_cache_keys(&self, resource_id: &str, version: &str, path: &str) -> CacheKeys {
        use xxhash_rust::xxh3::xxh3_64;
        let path_hash = xxh3_64(path.as_bytes());
        let base_key = format!("cache:{}:{}:{:x}", resource_id, version, path_hash);
        
        CacheKeys {
            metadata_key: format!("{}_meta", base_key),
            content_key: format!("{}_data", base_key),
        }
    }
    
    // 便捷方法：获取完整缓存内容
    async fn get_full_cached_content(&self, resource_id: &str, version: &str, path: &str) 
        -> Result<Option<(CacheMetadata, Vec<u8>)>, String> {
        let keys = self.generate_cache_keys(resource_id, version, path);
        
        // 并行获取元数据和内容
        let (meta_result, content_result) = tokio::join!(
            self.get_cache_metadata(&keys.metadata_key),
            self.get_cache_content(&keys.content_key)
        );
        
        match (meta_result?, content_result?) {
            (Some(metadata), Some(content)) if !metadata.is_expired() => {
                Ok(Some((metadata, content)))
            }
            _ => Ok(None)
        }
    }
    
    async fn store_challenge(&self, sid: &str, challenge_data: &str) -> Result<(), String>;
    async fn get_challenge(&self, sid: &str) -> Result<Option<String>, String>;
    async fn remove_challenge(&self, sid: &str) -> Result<(), String>;
    async fn delete(&self, key: &str) -> Result<(), String>;
    
    // 流量统计相关方法
    async fn update_daily_bandwidth(&self, session_id: &str, bytes: u64) -> Result<(), String>;
    async fn update_server_daily_bandwidth(&self, server_id: &str, bytes: u64) -> Result<(), String>;
    async fn get_daily_bandwidth(&self, session_id: &str) -> Result<u64, String>;
}

#[derive(Debug)]
pub struct SessionStats {
    pub path: String,
    pub chunks: Vec<String>,
    pub download_counts: HashMap<String, u32>,
    pub cdn_records: HashMap<String, Vec<CdnRecord>>,
}

// 文件数据存储实现 - 每个key对应一个文件
pub struct FileDataStore {
    base_path: PathBuf,
}

// 存储过期时间的包装结构
#[derive(Serialize, Deserialize)]
struct StoredValue<T> {
    data: T,
    expires_at: Option<u64>, // Unix timestamp
}

impl<T> StoredValue<T> {
    fn new(data: T, expires: Option<u32>) -> Self {
        let expires_at = expires.map(|secs| {
            chrono::Utc::now().timestamp() as u64 + secs as u64
        });
        Self { data, expires_at }
    }
    
    fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            chrono::Utc::now().timestamp() as u64 > expires_at
        } else {
            false
        }
    }
    
    fn into_data(self) -> Option<T> {
        if self.is_expired() {
            None
        } else {
            Some(self.data)
        }
    }
}

impl FileDataStore {
    pub async fn new() -> Result<Self, String> {
        let base_path = std::env::var("DATA_STORE_PATH")
            .unwrap_or_else(|_| "./data_store".to_string())
            .into();
        
        // 确保存储目录存在
        if let Err(e) = fs::create_dir_all(&base_path).await {
            return Err(format!("Failed to create data store directory: {}", e));
        }

        let store = Self { base_path };
        
        info!("File data store initialized at {:?}", store.base_path);
        Ok(store)
    }
    
    /// 将key转换为安全的文件名
    fn sanitize_filename(input: &str) -> String {
        let mut result = String::new();
        for c in input.chars() {
            let replacement = match c {
                ':' => "_COLON_".to_string(),
                '?' => "_QUEST_".to_string(),
                '*' => "_STAR_".to_string(),
                '<' => "_LT_".to_string(),
                '>' => "_GT_".to_string(),
                '"' => "_QUOTE_".to_string(),
                '|' => "_PIPE_".to_string(),
                '\\' => "_BSLASH_".to_string(),
                '/' => "_SLASH_".to_string(),
                ' ' => "_SPACE_".to_string(),
                c if c.is_control() => format!("_U{:04X}_", c as u32),
                c => c.to_string(),
            };
            result.push_str(&replacement);
            
            // 限制文件名长度
            if result.len() > 200 {
                break;
            }
        }
        result
    }
    
    /// 将key转换为安全的文件名（用于二进制文件）
    fn safe_filename(&self, key: &str) -> String {
        Self::sanitize_filename(key)
    }
    
    /// 将key转换为文件路径
    fn key_to_file_path(&self, key: &str) -> PathBuf {
        let safe_filename = Self::sanitize_filename(key);
        self.base_path.join(format!("{}.json", safe_filename))
    }
    
    /// 通用的JSON文件写入
    async fn write_json_file<T: Serialize>(&self, key: &str, data: &T) -> Result<(), String> {
        let file_path = self.key_to_file_path(key);
        
        // 确保父目录存在
        if let Some(parent) = file_path.parent() {
            if let Err(e) = fs::create_dir_all(parent).await {
                return Err(format!("Failed to create directory: {}", e));
            }
        }
        
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        // 使用临时文件确保原子写入
        let temp_path = file_path.with_extension("json.tmp");
        fs::write(&temp_path, json).await
            .map_err(|e| format!("Failed to write temp file: {}", e))?;
        
        fs::rename(temp_path, file_path).await
            .map_err(|e| format!("Failed to rename file: {}", e))
    }
    
    /// 通用的JSON文件读取
    async fn read_json_file<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, String> {
        let file_path = self.key_to_file_path(key);
        tracing::debug!("Reading JSON file from: {:?}", file_path);
        
        match fs::read_to_string(&file_path).await {
            Ok(content) => {
                match serde_json::from_str(&content) {
                    Ok(data) => Ok(Some(data)),
                    Err(e) => Err(format!("JSON parse error in {}: {}", file_path.display(), e))
                }
            },
            Err(_) => Ok(None) // 文件不存在
        }
    }
    
    /// 删除文件
    async fn delete_file(&self, key: &str) -> Result<(), String> {
        let file_path = self.key_to_file_path(key);
        match fs::remove_file(file_path).await {
            Ok(_) => Ok(()),
            Err(_) => Ok(()), // 文件不存在也认为是成功
        }
    }
}

#[async_trait::async_trait]
impl DataStoreBackend for FileDataStore {
    async fn store_session(&self, sid: &str, session: &Session) -> Result<(), String> {
        let key = format!("session:{}", sid);
        self.write_json_file(&key, session).await
    }

    async fn get_session(&self, sid: &str) -> Result<Option<Session>, String> {
        let key = format!("session:{}", sid);
        self.read_json_file(&key).await
    }

    async fn remove_session(&self, sid: &str) -> Result<(), String> {
        let key = format!("session:{}", sid);
        self.delete_file(&key).await
    }

    async fn increment_download_count(&self, sid: &str, chunk: &str) -> Result<Option<u32>, String> {
        let key = format!("download_count:{}:{}", sid, chunk);
        let current_count: u32 = self.read_json_file(&key).await?.unwrap_or(0);
        let new_count = current_count + 1;
        self.write_json_file(&key, &new_count).await?;
        Ok(Some(new_count))
    }

    async fn refresh_session(&self, _sid: &str) -> Result<(), String> {
        // 对于文件存储，不需要刷新过期时间
        Ok(())
    }

    async fn get_download_counts(&self, sid: &str) -> Result<HashMap<String, u32>, String> {
        // 这个方法需要扫描所有相关的下载计数文件
        // 为了简化，先返回空HashMap，后续可以通过文件系统扫描实现
        let _ = sid;
        Ok(HashMap::new())
    }

    async fn update_session_path(&self, sid: &str, path: &str) -> Result<bool, String> {
        if let Some(mut session) = self.get_session(sid).await? {
            session.path = path.to_string();
            self.store_session(sid, &session).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn update_session_chunks(&self, sid: &str, chunks: &[String]) -> Result<bool, String> {
        if let Some(mut session) = self.get_session(sid).await? {
            session.chunks = chunks.to_vec();
            self.store_session(sid, &session).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn update_cdn_record(&self, sid: &str, chunk: &str, cdn_url: &str) -> Result<(), String> {
        // 向后兼容的方法，创建简单的CdnRecord
        let record = CdnRecord {
            url: cdn_url.to_string(),
            server_id: None,
            skip_penalty: false,
            timestamp: chrono::Utc::now().timestamp() as u64,
            weight: 0,
        };
        self.update_cdn_record_v2(sid, chunk, record).await
    }

    async fn update_cdn_record_v2(&self, sid: &str, chunk: &str, record: CdnRecord) -> Result<(), String> {
        let key = format!("cdn_records:{}:{}", sid, chunk);
        let mut records: Vec<CdnRecord> = self.read_json_file(&key).await?.unwrap_or_default();
        records.push(record);
        self.write_json_file(&key, &records).await
    }

    async fn get_cdn_records(&self, sid: &str, chunk: &str) -> Result<Vec<CdnRecord>, String> {
        let key = format!("cdn_records:{}:{}", sid, chunk);
        Ok(self.read_json_file(&key).await?.unwrap_or_default())
    }

    async fn get_session_stats(&self, sid: &str) -> Result<Option<SessionStats>, String> {
        if let Some(session) = self.get_session(sid).await? {
            let download_counts = self.get_download_counts(sid).await?;
            
            // 收集所有CDN记录
            let mut cdn_records = HashMap::new();
            for chunk in &session.chunks {
                let records = self.get_cdn_records(sid, chunk).await?;
                if !records.is_empty() {
                    cdn_records.insert(chunk.clone(), records);
                }
            }
            
            Ok(Some(SessionStats {
                path: session.path,
                chunks: session.chunks,
                download_counts,
                cdn_records,
            }))
        } else {
            Ok(None)
        }
    }

    async fn read_js_storage(&self, key: String) -> Option<String> {
        let storage_key = format!("js_storage:{}", key);
        if let Ok(Some(stored_value)) = self.read_json_file::<StoredValue<String>>(&storage_key).await {
            stored_value.into_data()
        } else {
            None
        }
    }

    async fn write_js_storage(&self, key: String, value: String, expires: u32) -> bool {
        let storage_key = format!("js_storage:{}", key);
        let stored_value = StoredValue::new(value, Some(expires));
        self.write_json_file(&storage_key, &stored_value).await.is_ok()
    }

    async fn get_cached_metadata(&self, key: &str) -> Result<Option<String>, String> {
        let cache_key = format!("metadata_cache:{}", key);
        if let Some(stored_value) = self.read_json_file::<StoredValue<String>>(&cache_key).await? {
            Ok(stored_value.into_data())
        } else {
            Ok(None)
        }
    }

    async fn set_cached_metadata(&self, key: &str, value: &str, expires: u32) -> Result<(), String> {
        let cache_key = format!("metadata_cache:{}", key);
        let stored_value = StoredValue::new(value.to_string(), Some(expires));
        self.write_json_file(&cache_key, &stored_value).await
    }

    async fn get_string(&self, key: &str) -> Result<Option<String>, String> {
        let storage_key = format!("general_cache:{}", key);
        if let Some(stored_value) = self.read_json_file::<StoredValue<String>>(&storage_key).await? {
            Ok(stored_value.into_data())
        } else {
            Ok(None)
        }
    }

    async fn set_string(&self, key: &str, value: &str, expires: Option<u32>) -> Result<(), String> {
        let storage_key = format!("general_cache:{}", key);
        let stored_value = StoredValue::new(value.to_string(), expires);
        self.write_json_file(&storage_key, &stored_value).await
    }

    async fn get_alive_status(&self, server_id: &str, path: &str) -> Result<Option<bool>, String> {
        let key = format!("alive_status:{}:{}", server_id, path);
        if let Some(stored_value) = self.read_json_file::<StoredValue<bool>>(&key).await? {
            Ok(stored_value.into_data())
        } else {
            Ok(None)
        }
    }

    async fn set_alive_status(&self, server_id: &str, path: &str, is_alive: bool) -> Result<(), String> {
        let key = format!("alive_status:{}:{}", server_id, path);
        let stored_value = StoredValue::new(is_alive, Some(300)); // 5分钟过期
        self.write_json_file(&key, &stored_value).await
    }

    async fn get_health_info(&self, server_id: &str, path: &str) -> Result<Option<HealthInfo>, String> {
        let key = format!("health_info:{}:{}", server_id, path);
        if let Some(stored_value) = self.read_json_file::<StoredValue<HealthInfo>>(&key).await? {
            Ok(stored_value.into_data())
        } else {
            Ok(None)
        }
    }

    async fn set_health_info(&self, server_id: &str, path: &str, info: &HealthInfo) -> Result<(), String> {
        let key = format!("health_info:{}:{}", server_id, path);
        let stored_value = StoredValue::new(info.clone(), Some(300)); // 5分钟过期
        self.write_json_file(&key, &stored_value).await
    }

    async fn get_cache_metadata(&self, key: &str) -> Result<Option<CacheMetadata>, String> {
        if let Some(stored_value) = self.read_json_file::<StoredValue<CacheMetadata>>(key).await? {
            Ok(stored_value.into_data())
        } else {
            Ok(None)
        }
    }

    async fn get_cache_content(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let file_path = self.base_path.join(self.safe_filename(key));
        
        match fs::read(&file_path).await {
            Ok(content) => Ok(Some(content)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Failed to read cache content file: {}", e)),
        }
    }

    async fn set_cache_entry(&self, meta_key: &str, content_key: &str, 
                           metadata: &CacheMetadata, content: &[u8]) -> Result<(), String> {
        // 并行写入元数据和内容
        let meta_future = async {
            let stored_value = StoredValue::new(metadata.clone(), Some(metadata.max_age));
            self.write_json_file(meta_key, &stored_value).await
        };
        
        let content_future = async {
            let file_path = self.base_path.join(self.safe_filename(content_key));
            match fs::write(&file_path, content).await {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("Failed to write cache content file: {}", e)),
            }
        };
        
        let (meta_result, content_result) = tokio::join!(meta_future, content_future);
        meta_result?;
        content_result?;
        Ok(())
    }

    async fn store_challenge(&self, sid: &str, challenge_data: &str) -> Result<(), String> {
        let key = format!("challenge:{}", sid);
        let stored_value = StoredValue::new(challenge_data.to_string(), Some(600)); // 10分钟过期
        self.write_json_file(&key, &stored_value).await
    }

    async fn get_challenge(&self, sid: &str) -> Result<Option<String>, String> {
        let key = format!("challenge:{}", sid);
        if let Some(stored_value) = self.read_json_file::<StoredValue<String>>(&key).await? {
            Ok(stored_value.into_data())
        } else {
            Ok(None)
        }
    }

    async fn remove_challenge(&self, sid: &str) -> Result<(), String> {
        let key = format!("challenge:{}", sid);
        self.delete_file(&key).await
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        let storage_key = format!("general_cache:{}", key);
        self.delete_file(&storage_key).await
    }
    
    async fn update_daily_bandwidth(&self, session_id: &str, bytes: u64) -> Result<(), String> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let key = format!("bw_daily:{}:{}", session_id, today);
        
        // 读取当前使用量
        let current_usage: u64 = self.read_json_file(&key).await?.unwrap_or(0);
        let new_usage = current_usage + bytes;
        
        // 写入新的使用量
        self.write_json_file(&key, &new_usage).await
    }
    
    async fn update_server_daily_bandwidth(&self, server_id: &str, bytes: u64) -> Result<(), String> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let key = format!("server_bw_daily:{}:{}", server_id, today);
        
        // 读取当前使用量
        let current_usage: u64 = self.read_json_file(&key).await?.unwrap_or(0);
        let new_usage = current_usage + bytes;
        
        // 写入新的使用量
        self.write_json_file(&key, &new_usage).await
    }
    
    async fn get_daily_bandwidth(&self, session_id: &str) -> Result<u64, String> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let key = format!("bw_daily:{}:{}", session_id, today);
        
        // 读取当前使用量，如果不存在返回0
        Ok(self.read_json_file(&key).await?.unwrap_or(0))
    }
}

/// 数据存储类型枚举
pub type DataStore = Arc<dyn DataStoreBackend>;

/// 创建数据存储实例
pub async fn create_data_store() -> Result<DataStore, String> {
    use std::env;
    
    let store_type = env::var("DATA_STORE_TYPE").unwrap_or_else(|_| "file".to_string());
    
    match store_type.as_str() {
        "redis" => {
            // 创建Redis客户端
            let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
            let client = redis::Client::open(redis_url).map_err(|e| format!("Failed to create Redis client: {}", e))?;
            let redis_store = crate::redis_data_store::RedisDataStore::new(client);
            Ok(Arc::new(redis_store))
        }
        "file" | _ => {
            let file_store = FileDataStore::new().await?;
            Ok(Arc::new(file_store))
        }
    }
}