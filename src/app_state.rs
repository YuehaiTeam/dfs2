use crate::models::Session;
use redis::{AsyncCommands, Client, RedisResult};
use std::collections::HashMap;
use std::env;

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
        .unwrap();
}

#[derive(Debug)]
pub struct SessionStats {
    pub path: String,
    pub chunks: Vec<String>,
    pub download_counts: HashMap<String, u32>,
    pub cdn_records: HashMap<String, Vec<String>>,
}

#[derive(Clone)]
pub struct RedisStore {
    client: Client,
}

#[allow(dead_code)]
impl RedisStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn store_session(&self, sid: &str, session: &Session) -> RedisResult<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let session_key = format!("session:{}", sid);
        let counts_key = format!("counts:{}", sid);

        let mut pipe = redis::pipe();
        pipe.atomic()
            // 存储会话数据
            .hset(&session_key, "path", &session.path)
            .hset(
                &session_key,
                "chunks",
                serde_json::to_string(&session.chunks).unwrap(),
            )
            .hset(
                &session_key,
                "cdn_records",
                serde_json::to_string(&session.cdn_records).unwrap(),
            )
            .expire(&session_key, 3600);

        // 初始化所有chunk的下载计数为0
        for chunk in &session.chunks {
            println!("hset {} {}", counts_key, chunk);
            pipe.hset(&counts_key, chunk, 0);
        }
        pipe.expire(&counts_key, 3600);

        let _: () = pipe.query_async(&mut conn).await?;
        Ok(())
    }

    pub async fn get_session(&self, sid: &str) -> RedisResult<Option<Session>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("session:{}", sid);

        // 使用Pipeline一次获取所有字段
        let (path, chunks, cdn_records): (Option<String>, Option<String>, Option<String>) =
            redis::pipe()
                .atomic()
                .hget(&key, "path")
                .hget(&key, "chunks")
                .hget(&key, "cdn_records")
                .query_async(&mut conn)
                .await?;

        match (path, chunks, cdn_records) {
            (Some(path), Some(chunks_json), Some(cdn_records_json)) => {
                let chunks: Vec<String> = serde_json::from_str(&chunks_json).unwrap_or_default();
                let cdn_records: HashMap<String, Vec<String>> =
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

    pub async fn remove_session(&self, sid: &str) -> RedisResult<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let session_key = format!("session:{}", sid);
        let counts_key = format!("counts:{}", sid);

        // 删除session hash和下载计数hash
        let _: () = redis::pipe()
            .atomic()
            .del(&session_key)
            .del(&counts_key)
            .query_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn increment_download_count(
        &self,
        sid: &str,
        chunk: &str,
    ) -> RedisResult<Option<u32>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let counts_key = format!("counts:{}", sid);

        // 首先检查chunk是否存在于hash中
        let exists: bool = conn.hexists(&counts_key, chunk).await?;
        if !exists {
            return Ok(None); // 无效的chunk
        }

        // 增加下载计数并刷新过期时间
        let count: [u32; 2] = redis::pipe()
            .atomic()
            .hincr(&counts_key, chunk, 1)
            .expire(&counts_key, 3600)
            .query_async(&mut conn)
            .await?;

        Ok(Some(count[0]))
    }

    pub async fn refresh_session(&self, sid: &str) -> RedisResult<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let session_key = format!("session:{}", sid);
        let counts_key = format!("counts:{}", sid);

        // 同时刷新session和下载计数的过期时间
        let _: () = redis::pipe()
            .atomic()
            .expire(&session_key, 3600)
            .expire(&counts_key, 3600)
            .query_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn get_download_counts(
        &self,
        sid: &str,
    ) -> RedisResult<std::collections::HashMap<String, u32>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let counts_key = format!("counts:{}", sid);

        // 获取所有下载计数
        conn.hgetall(&counts_key).await
    }

    pub async fn update_session_path(&self, sid: &str, path: &str) -> RedisResult<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("session:{}", sid);

        let exists: bool = conn.hset(&key, "path", path).await?;
        if exists {
            let _: () = conn.expire(&key, 3600).await?;
        }
        Ok(exists)
    }

    pub async fn update_session_chunks(&self, sid: &str, chunks: &[String]) -> RedisResult<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("session:{}", sid);

        let chunks_json = serde_json::to_string(chunks).unwrap();
        let exists: bool = conn.hset(&key, "chunks", chunks_json).await?;
        if exists {
            let _: () = conn.expire(&key, 3600).await?;
        }
        Ok(exists)
    }

    pub async fn update_cdn_record(
        &self,
        sid: &str,
        chunk: &str,
        cdn_url: &str,
    ) -> RedisResult<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("session:{}", sid);

        // 先获取现有记录
        let cdn_records: Option<String> = conn.hget(&key, "cdn_records").await?;
        let mut records: HashMap<String, Vec<String>> = cdn_records
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();

        // 更新记录
        records
            .entry(chunk.to_string())
            .or_default()
            .push(cdn_url.to_string());

        // 保存更新后的记录
        let _: () = redis::pipe()
            .atomic()
            .hset(
                &key,
                "cdn_records",
                serde_json::to_string(&records).unwrap(),
            )
            .expire(&key, 3600)
            .query_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn get_session_stats(&self, sid: &str) -> RedisResult<Option<SessionStats>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let session_key = format!("session:{}", sid);
        let counts_key = format!("counts:{}", sid);

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
            .await?;

        match (path, chunks, cdn_records) {
            (Some(path), Some(chunks_json), Some(cdn_records_json)) => {
                let chunks: Vec<String> = serde_json::from_str(&chunks_json).unwrap_or_default();
                let cdn_records: HashMap<String, Vec<String>> =
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

    pub async fn read_js_storage(&self, key: String) -> Option<String> {
        let conn = self.client.get_multiplexed_async_connection().await;
        if conn.is_err() {
            return None;
        }
        let mut conn = conn.unwrap();
        let key = format!("js_storage:{}", key);
        let value = conn.get(&key).await;
        match value {
            Ok(Some(value)) => Some(value),
            Ok(None) => None,
            Err(_) => None,
        }
    }

    pub async fn write_js_storage(&self, key: String, value: String, expires: u32) -> bool {
        let conn = self.client.get_multiplexed_async_connection().await;
        if conn.is_err() {
            return false;
        }
        let mut conn = conn.unwrap();
        let key = format!("js_storage:{}", key);
        let ret: Result<String, redis::RedisError> = conn.set_ex(key, value, expires.into()).await;
        ret.is_ok()
    }

    pub async fn get_cached_metadata(&self, key: &str) -> RedisResult<Option<String>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let cache_key = format!("metadata_cache:{}", key);
        conn.get(&cache_key).await
    }

    pub async fn set_cached_metadata(&self, key: &str, value: &str, expires: u32) -> RedisResult<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let cache_key = format!("metadata_cache:{}", key);
        conn.set_ex(cache_key, value, expires as u64).await
    }
}
