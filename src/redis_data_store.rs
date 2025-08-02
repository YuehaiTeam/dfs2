use crate::data_store::{DataStoreBackend, SessionStats, CacheMetadata};
use crate::models::{Session, CdnRecord};
use crate::modules::server::HealthInfo;
use redis::{AsyncCommands, Client};
use std::collections::HashMap;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct RedisDataStore {
    client: Client,
}

impl RedisDataStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// 生成带前缀的Redis键
    /// 格式: prefix:namespace:key 或者 namespace:key (如果没有设置前缀)
    /// 前缀通过环境变量 REDIS_PREFIX 设置
    fn redis_key(&self, namespace: &str, key: &str) -> String {
        if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
            if !prefix.is_empty() {
                return format!("{}:{}:{}", prefix, namespace, key);
            }
        }
        format!("{}:{}", namespace, key)
    }
}

#[async_trait::async_trait]
impl DataStoreBackend for RedisDataStore {
    async fn store_session(&self, sid: &str, session: &Session) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let session_key = self.redis_key("session", sid);
        let counts_key = self.redis_key("counts", sid);

        let mut pipe = redis::pipe();
        pipe.atomic()
            // 存储会话数据
            .hset(&session_key, "path", &session.path)
            .hset(
                &session_key,
                "chunks",
                serde_json::to_string(&session.chunks).map_err(|e| e.to_string())?,
            )
            .hset(
                &session_key,
                "cdn_records",
                serde_json::to_string(&session.cdn_records).map_err(|e| e.to_string())?,
            )
            .expire(&session_key, 3600);

        // 初始化所有chunk的下载计数为0
        for chunk in &session.chunks {
            debug!(
                "Setting Redis hash field for chunk: {} in {}",
                chunk, counts_key
            );
            pipe.hset(&counts_key, chunk, 0);
        }
        pipe.expire(&counts_key, 3600);

        let _: () = pipe.query_async(&mut conn).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn get_session(&self, sid: &str) -> Result<Option<Session>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("session", sid);

        // 使用Pipeline一次获取所有字段
        let (path, chunks, cdn_records): (Option<String>, Option<String>, Option<String>) =
            redis::pipe()
                .atomic()
                .hget(&key, "path")
                .hget(&key, "chunks")
                .hget(&key, "cdn_records")
                .query_async(&mut conn)
                .await
                .map_err(|e| e.to_string())?;

        match (path, chunks, cdn_records) {
            (Some(path), Some(chunks_json), Some(cdn_records_json)) => {
                let chunks: Vec<String> = serde_json::from_str(&chunks_json).unwrap_or_default();
                let cdn_records: HashMap<String, Vec<CdnRecord>> =
                    serde_json::from_str(&cdn_records_json).unwrap_or_default();
                Ok(Some(Session {
                    path,
                    chunks,
                    cdn_records,
                }))
            }
            _ => Ok(None),
        }
    }

    async fn remove_session(&self, sid: &str) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let session_key = self.redis_key("session", sid);
        let counts_key = self.redis_key("counts", sid);

        // 删除session hash和下载计数hash
        let _: () = redis::pipe()
            .atomic()
            .del(&session_key)
            .del(&counts_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    async fn increment_download_count(&self, sid: &str, chunk: &str) -> Result<Option<u32>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let counts_key = self.redis_key("counts", sid);

        // 首先检查chunk是否存在于hash中
        let exists: bool = conn.hexists(&counts_key, chunk).await.map_err(|e| e.to_string())?;
        if !exists {
            return Ok(None); // 无效的chunk
        }

        // 增加下载计数并刷新过期时间
        let count: [u32; 2] = redis::pipe()
            .atomic()
            .hincr(&counts_key, chunk, 1)
            .expire(&counts_key, 3600)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(Some(count[0]))
    }

    async fn refresh_session(&self, sid: &str) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let session_key = self.redis_key("session", sid);
        let counts_key = self.redis_key("counts", sid);

        // 同时刷新session和下载计数的过期时间
        let _: () = redis::pipe()
            .atomic()
            .expire(&session_key, 3600)
            .expire(&counts_key, 3600)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    async fn get_download_counts(&self, sid: &str) -> Result<HashMap<String, u32>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let counts_key = self.redis_key("counts", sid);

        // 获取所有下载计数
        conn.hgetall(&counts_key).await.map_err(|e| e.to_string())
    }

    async fn update_session_path(&self, sid: &str, path: &str) -> Result<bool, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("session", sid);

        let exists: bool = conn.hset(&key, "path", path).await.map_err(|e| e.to_string())?;
        if exists {
            let _: () = conn.expire(&key, 3600).await.map_err(|e| e.to_string())?;
        }
        Ok(exists)
    }

    async fn update_session_chunks(&self, sid: &str, chunks: &[String]) -> Result<bool, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("session", sid);

        let chunks_json = serde_json::to_string(chunks).map_err(|e| e.to_string())?;
        let exists: bool = conn.hset(&key, "chunks", chunks_json).await.map_err(|e| e.to_string())?;
        if exists {
            let _: () = conn.expire(&key, 3600).await.map_err(|e| e.to_string())?;
        }
        Ok(exists)
    }

    async fn update_cdn_record(&self, sid: &str, chunk: &str, cdn_url: &str) -> Result<(), String> {
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
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("session", sid);

        // 先获取现有记录
        let cdn_records: Option<String> = conn.hget(&key, "cdn_records").await.map_err(|e| e.to_string())?;
        let mut records: HashMap<String, Vec<CdnRecord>> = cdn_records
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();

        // 更新记录
        records
            .entry(chunk.to_string())
            .or_default()
            .push(record);

        // 保存更新后的记录
        let _: () = redis::pipe()
            .atomic()
            .hset(
                &key,
                "cdn_records",
                serde_json::to_string(&records).map_err(|e| e.to_string())?,
            )
            .expire(&key, 3600)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    async fn get_cdn_records(&self, sid: &str, chunk: &str) -> Result<Vec<CdnRecord>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("session", sid);

        let cdn_records: Option<String> = conn.hget(&key, "cdn_records").await.map_err(|e| e.to_string())?;
        
        if let Some(records_json) = cdn_records {
            let all_records: HashMap<String, Vec<CdnRecord>> = serde_json::from_str(&records_json)
                .unwrap_or_default();
            Ok(all_records.get(chunk).cloned().unwrap_or_default())
        } else {
            Ok(Vec::new())
        }
    }

    async fn get_session_stats(&self, sid: &str) -> Result<Option<SessionStats>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let session_key = self.redis_key("session", sid);
        let counts_key = self.redis_key("counts", sid);

        // 使用Pipeline同时获取所有信息
        let ((path, chunks, cdn_records), counts): (
            (Option<String>, Option<String>, Option<String>),
            HashMap<String, u32>,
        ) = redis::pipe()
            .atomic()
            .hget(&session_key, "path")
            .hget(&session_key, "chunks")
            .hget(&session_key, "cdn_records")
            .hgetall(&counts_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        match (path, chunks, cdn_records) {
            (Some(path), Some(chunks_json), Some(cdn_records_json)) => {
                let chunks: Vec<String> = serde_json::from_str(&chunks_json).unwrap_or_default();
                let cdn_records: HashMap<String, Vec<CdnRecord>> =
                    serde_json::from_str(&cdn_records_json).unwrap_or_default();
                Ok(Some(SessionStats {
                    path,
                    chunks,
                    download_counts: counts,
                    cdn_records,
                }))
            }
            _ => Ok(None),
        }
    }

    async fn read_js_storage(&self, key: String) -> Option<String> {
        let conn = self.client.get_multiplexed_async_connection().await;
        if conn.is_err() {
            return None;
        }
        let mut conn = match conn {
            Ok(conn) => conn,
            Err(e) => {
                warn!("Failed to get Redis connection for JS storage read: {}", e);
                return None;
            }
        };
        let redis_key = self.redis_key("js_storage", &key);
        let value = conn.get(&redis_key).await;
        match value {
            Ok(Some(value)) => Some(value),
            Ok(None) => None,
            Err(_) => None,
        }
    }

    async fn write_js_storage(&self, key: String, value: String, expires: u32) -> bool {
        let conn = self.client.get_multiplexed_async_connection().await;
        if conn.is_err() {
            return false;
        }
        let mut conn = match conn {
            Ok(conn) => conn,
            Err(e) => {
                warn!("Failed to get Redis connection for JS storage write: {}", e);
                return false;
            }
        };
        let redis_key = self.redis_key("js_storage", &key);
        let ret: Result<String, redis::RedisError> =
            conn.set_ex(redis_key, value, expires.into()).await;
        ret.is_ok()
    }

    async fn get_cached_metadata(&self, key: &str) -> Result<Option<String>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let cache_key = self.redis_key("metadata_cache", key);
        conn.get(&cache_key).await.map_err(|e| e.to_string())
    }

    async fn set_cached_metadata(&self, key: &str, value: &str, expires: u32) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let cache_key = self.redis_key("metadata_cache", key);
        conn.set_ex(cache_key, value, expires as u64).await.map_err(|e| e.to_string())
    }

    async fn get_string(&self, key: &str) -> Result<Option<String>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        conn.get(key).await.map_err(|e| e.to_string())
    }

    async fn set_string(&self, key: &str, value: &str, expires: Option<u32>) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        if let Some(expires) = expires {
            conn.set_ex(key, value, expires as u64).await.map_err(|e| e.to_string())
        } else {
            conn.set(key, value).await.map_err(|e| e.to_string())
        }
    }

    async fn get_alive_status(&self, server_id: &str, path: &str) -> Result<Option<bool>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let cache_key = self.redis_key("alive", &format!("{}:{}", server_id, path));
        let result: Option<String> = conn.get(&cache_key).await.map_err(|e| e.to_string())?;
        Ok(result.and_then(|s| s.parse::<bool>().ok()))
    }

    async fn set_alive_status(&self, server_id: &str, path: &str, is_alive: bool) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let cache_key = self.redis_key("alive", &format!("{}:{}", server_id, path));
        // Cache for 5 minutes (300 seconds)
        conn.set_ex(cache_key, is_alive.to_string(), 300).await.map_err(|e| e.to_string())
    }

    async fn get_health_info(&self, server_id: &str, path: &str) -> Result<Option<HealthInfo>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("health", &format!("{}:{}", server_id, path));
        
        let result: Option<String> = conn.get(key).await.map_err(|e| e.to_string())?;
        if let Some(json_str) = result {
            serde_json::from_str(&json_str).map_err(|e| format!("Failed to deserialize health info: {}", e))
        } else {
            Ok(None)
        }
    }

    async fn set_health_info(&self, server_id: &str, path: &str, info: &HealthInfo) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("health", &format!("{}:{}", server_id, path));
        let json_str = serde_json::to_string(info)
            .map_err(|e| format!("Failed to serialize health info: {}", e))?;
        conn.set_ex(key, json_str, 300).await.map_err(|e| e.to_string()) // 5分钟过期
    }

    async fn get_cache_metadata(&self, key: &str) -> Result<Option<CacheMetadata>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let result: Option<String> = conn.get(key).await.map_err(|e| e.to_string())?;
        if let Some(json_str) = result {
            let metadata: CacheMetadata = serde_json::from_str(&json_str)
                .map_err(|e| format!("Failed to deserialize cache metadata: {}", e))?;
            if metadata.is_expired() {
                // 过期，删除键并返回None
                let _: Result<i32, _> = conn.del(key).await;
                Ok(None)
            } else {
                Ok(Some(metadata))
            }
        } else {
            Ok(None)
        }
    }

    async fn get_cache_content(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let result: Option<Vec<u8>> = conn.get(key).await.map_err(|e| e.to_string())?;
        Ok(result)
    }

    async fn set_cache_entry(&self, meta_key: &str, content_key: &str, 
                           metadata: &CacheMetadata, content: &[u8]) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let metadata_json = serde_json::to_string(metadata)
            .map_err(|e| format!("Failed to serialize cache metadata: {}", e))?;
        
        // 使用Pipeline提高性能
        let mut pipe = redis::pipe();
        pipe.atomic()
            // 设置元数据（JSON，小）
            .set_ex(meta_key, metadata_json, metadata.max_age as u64)
            // 设置内容（二进制，直接存储）
            .set_ex(content_key, content, metadata.max_age as u64);
        
        let _: () = pipe.query_async(&mut conn).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn store_challenge(&self, sid: &str, challenge_data: &str) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("challenge", sid);
        // Store challenge for 10 minutes
        conn.set_ex(key, challenge_data, 600).await.map_err(|e| e.to_string())
    }

    async fn get_challenge(&self, sid: &str) -> Result<Option<String>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("challenge", sid);
        conn.get(&key).await.map_err(|e| e.to_string())
    }

    async fn remove_challenge(&self, sid: &str) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        let key = self.redis_key("challenge", sid);
        conn.del(key).await.map_err(|e| e.to_string())
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        conn.del(key).await.map_err(|e| e.to_string())
    }
    
    async fn update_daily_bandwidth(&self, session_id: &str, bytes: u64) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let cache_key = self.redis_key("bw_daily", &format!("{}:{}", session_id, today));
        
        // 使用 INCRBY 原子性增加计数，并设置24小时过期时间
        let _: () = redis::pipe()
            .atomic()
            .cmd("INCRBY").arg(&cache_key).arg(bytes)
            .expire(&cache_key, 86400) // 24小时过期
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
            
        Ok(())
    }
    
    async fn update_server_daily_bandwidth(&self, server_id: &str, bytes: u64) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let cache_key = self.redis_key("server_bw_daily", &format!("{}:{}", server_id, today));
        
        // 使用 INCRBY 原子性增加计数，并设置24小时过期时间
        let _: () = redis::pipe()
            .atomic()
            .cmd("INCRBY").arg(&cache_key).arg(bytes)
            .expire(&cache_key, 86400) // 24小时过期
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
            
        Ok(())
    }
    
    async fn get_daily_bandwidth(&self, session_id: &str) -> Result<u64, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let cache_key = self.redis_key("bw_daily", &format!("{}:{}", session_id, today));
        
        let result: Option<String> = conn.get(&cache_key).await.map_err(|e| e.to_string())?;
        Ok(result.and_then(|s| s.parse().ok()).unwrap_or(0))
    }
}