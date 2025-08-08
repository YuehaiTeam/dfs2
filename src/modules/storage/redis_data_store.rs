use crate::modules::storage::data_store::{DataStoreBackend, SessionStats, CacheMetadata};
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
            .hset(&session_key, "resource_id", &session.resource_id)
            .hset(&session_key, "version", &session.version)
            .hset(
                &session_key,
                "chunks",
                serde_json::to_string(&session.chunks).map_err(|e| e.to_string())?,
            )
            .hset(
                &session_key,
                "sub_path",
                serde_json::to_string(&session.sub_path).map_err(|e| e.to_string())?,
            )
            .hset(
                &session_key,
                "cdn_records",
                serde_json::to_string(&session.cdn_records).map_err(|e| e.to_string())?,
            )
            .hset(
                &session_key,
                "extras",
                serde_json::to_string(&session.extras).map_err(|e| e.to_string())?,
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
        let (resource_id, version, chunks, sub_path, cdn_records, extras): (Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>) =
            redis::pipe()
                .atomic()
                .hget(&key, "resource_id")
                .hget(&key, "version")
                .hget(&key, "chunks")
                .hget(&key, "sub_path")
                .hget(&key, "cdn_records")
                .hget(&key, "extras")
                .query_async(&mut conn)
                .await
                .map_err(|e| e.to_string())?;

        match (resource_id, version, chunks, cdn_records) {
            (Some(resource_id), Some(version), Some(chunks_json), Some(cdn_records_json)) => {
                let chunks: Vec<String> = serde_json::from_str(&chunks_json).unwrap_or_default();
                let cdn_records: HashMap<String, Vec<CdnRecord>> =
                    serde_json::from_str(&cdn_records_json).unwrap_or_default();
                let sub_path_value: Option<String> = sub_path
                    .and_then(|s| serde_json::from_str(&s).ok());
                let extras: serde_json::Value = extras
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_else(|| serde_json::json!({}));
                Ok(Some(Session {
                    resource_id,
                    version,
                    chunks,
                    sub_path: sub_path_value,
                    cdn_records,
                    extras,
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
        let (resource_id, version, chunks, cdn_records, counts): (
            Option<String>, 
            Option<String>, 
            Option<String>, 
            Option<String>,
            HashMap<String, u32>
        ) = redis::pipe()
            .atomic()
            .hget(&session_key, "resource_id")
            .hget(&session_key, "version")
            .hget(&session_key, "chunks")
            .hget(&session_key, "cdn_records")
            .hgetall(&counts_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        match (resource_id, version, chunks, cdn_records) {
            (Some(resource_id), Some(version), Some(chunks_json), Some(cdn_records_json)) => {
                let chunks: Vec<String> = serde_json::from_str(&chunks_json).unwrap_or_default();
                let cdn_records: HashMap<String, Vec<CdnRecord>> =
                    serde_json::from_str(&cdn_records_json).unwrap_or_default();
                Ok(Some(SessionStats {
                    resource_id,
                    version,
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
    
    async fn update_resource_daily_bandwidth(&self, resource_id: &str, bytes: u64) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let cache_key = self.redis_key("resource_bw_daily", &format!("{}:{}", resource_id, today));
        
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
    
    async fn update_global_daily_bandwidth(&self, bytes: u64) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let cache_key = self.redis_key("global_bw_daily", &today);
        
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
    
    async fn get_server_daily_bandwidth(&self, server_id: &str) -> Result<u64, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let cache_key = self.redis_key("server_bw_daily", &format!("{}:{}", server_id, today));
        
        let result: Option<String> = conn.get(&cache_key).await.map_err(|e| e.to_string())?;
        Ok(result.and_then(|s| s.parse().ok()).unwrap_or(0))
    }
    
    async fn get_resource_daily_bandwidth(&self, resource_id: &str) -> Result<u64, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let cache_key = self.redis_key("resource_bw_daily", &format!("{}:{}", resource_id, today));
        
        let result: Option<String> = conn.get(&cache_key).await.map_err(|e| e.to_string())?;
        Ok(result.and_then(|s| s.parse().ok()).unwrap_or(0))
    }
    
    async fn get_global_daily_bandwidth(&self) -> Result<u64, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let cache_key = self.redis_key("global_bw_daily", &today);
        
        let result: Option<String> = conn.get(&cache_key).await.map_err(|e| e.to_string())?;
        Ok(result.and_then(|s| s.parse().ok()).unwrap_or(0))
    }
    
    async fn update_bandwidth_batch(&self, batch: crate::modules::storage::data_store::BandwidthUpdateBatch) -> Result<(), String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        
        // 构建三个Redis键
        let resource_key = self.redis_key("resource_bw_daily", &format!("{}:{}", batch.resource_id, today));
        let server_key = self.redis_key("server_bw_daily", &format!("{}:{}", batch.server_id, today));
        let global_key = self.redis_key("global_bw_daily", &today);
        
        // 使用Redis MULTI/EXEC事务原子性更新所有统计
        let _: () = redis::pipe()
            .atomic()
            .cmd("INCRBY").arg(&resource_key).arg(batch.bytes)
            .expire(&resource_key, 86400)
            .cmd("INCRBY").arg(&server_key).arg(batch.bytes) 
            .expire(&server_key, 86400)
            .cmd("INCRBY").arg(&global_key).arg(batch.bytes)
            .expire(&global_key, 86400)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
            
        Ok(())
    }

    async fn scan_expired_sessions(&self, timeout_seconds: u64) -> Result<Vec<(String, String, std::net::IpAddr)>, String> {
        
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let mut expired_sessions = Vec::new();
        let mut cursor = 0u64;
        
        // 生成扫描模式，包含前缀支持
        let scan_pattern = if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
            if !prefix.is_empty() {
                format!("{}:session:*", prefix)
            } else {
                "session:*".to_string()
            }
        } else {
            "session:*".to_string()
        };
        
        loop {
            // 使用 SCAN 命令扫描匹配的键，每次返回最多100个键
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&scan_pattern)
                .arg("COUNT")
                .arg(100u64)
                .query_async(&mut conn)
                .await
                .map_err(|e| e.to_string())?;
            
            // 检查每个会话键的 TTL
            for key in keys {
                match redis::cmd("TTL").arg(&key).query_async::<i64>(&mut conn).await {
                    Ok(ttl) if ttl > 0 && ttl < 60 => {
                        // TTL > 0 表示键存在且有过期时间，TTL < 60 表示即将过期
                        if let Some(session_id) = self.extract_session_id(&key) {
                            if let Ok(Some(session_info)) = self.get_session_info(&session_id).await {
                                expired_sessions.push(session_info);
                            }
                        }
                    }
                    Ok(ttl) if ttl == -1 => {
                        // TTL = -1 表示键存在但没有设置过期时间，这是异常情况
                        // 根据创建时间判断是否应该过期
                        if let Some(session_id) = self.extract_session_id(&key) {
                            if let Ok(Some(session_info)) = self.check_session_timeout(&session_id, timeout_seconds).await {
                                expired_sessions.push(session_info);
                            }
                        }
                    }
                    _ => {
                        // TTL = -2 表示键不存在，TTL = 0 表示键已过期，忽略
                    }
                }
            }
            
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        
        Ok(expired_sessions)
    }
}

impl RedisDataStore {
    /// 从 Redis 键中提取会话 ID
    fn extract_session_id(&self, key: &str) -> Option<String> {
        // key 格式: "session:session_id" 或 "prefix:session:session_id"
        if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
            if !prefix.is_empty() {
                let expected_prefix = format!("{}:session:", prefix);
                if key.starts_with(&expected_prefix) {
                    return Some(key[expected_prefix.len()..].to_string());
                }
            }
        }
        
        if key.starts_with("session:") {
            Some(key[8..].to_string()) // "session:".len() = 8
        } else {
            None
        }
    }
    
    /// 获取会话信息（resource_id 和 client_ip）
    async fn get_session_info(&self, session_id: &str) -> Result<Option<(String, String, std::net::IpAddr)>, String> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;
        
        let session_key = self.redis_key("session", session_id);
        
        let (resource_id, extras): (Option<String>, Option<String>) = redis::pipe()
            .hget(&session_key, "resource_id")
            .hget(&session_key, "extras")
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        
        if let (Some(resource_id), Some(extras_json)) = (resource_id, extras) {
            if let Ok(extras) = serde_json::from_str::<serde_json::Value>(&extras_json) {
                if let Some(client_ip_str) = extras.get("client_ip").and_then(|v| v.as_str()) {
                    if let Ok(client_ip) = client_ip_str.parse::<std::net::IpAddr>() {
                        return Ok(Some((session_id.to_string(), resource_id, client_ip)));
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    /// 检查没有设置TTL的会话是否超时
    async fn check_session_timeout(&self, session_id: &str, _timeout_seconds: u64) -> Result<Option<(String, String, std::net::IpAddr)>, String> {
        // 这里可以根据会话的创建时间来判断是否超时
        // 但由于当前实现中没有存储创建时间，我们暂时跳过这些会话
        // 在实际生产环境中，建议所有会话都设置TTL
        warn!("Found session without TTL: {}, skipping", session_id);
        Ok(None)
    }
}