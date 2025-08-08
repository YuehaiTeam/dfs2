use std::time::{SystemTime, Duration};
use tracing::{debug, error, warn};

use crate::modules::storage::data_store::DataStore;
use crate::error::{DfsError, DfsResult};
use super::VersionInfo;

/// 版本缓存管理器
#[derive(Clone)]
pub struct VersionCache {
    redis: DataStore,
}

impl VersionCache {
    pub fn new(redis: DataStore) -> Self {
        Self { redis }
    }
    
    /// 获取缓存的版本信息
    pub async fn get_cached_version(&self, resource_id: &str) -> Option<String> {
        let cache_key = format!("version_cache:{}", resource_id);
        match self.redis.get_string(&cache_key).await {
            Ok(Some(version)) => {
                debug!("Retrieved cached version for {}: {}", resource_id, version);
                Some(version)
            }
            Ok(None) => {
                debug!("No cached version found for {}", resource_id);
                None
            }
            Err(e) => {
                warn!("Failed to get cached version for {}: {}", resource_id, e);
                None
            }
        }
    }
    
    /// 设置缓存版本
    pub async fn set_cached_version(
        &self, 
        resource_id: &str, 
        version: &str, 
        ttl: u32
    ) -> DfsResult<()> {
        let cache_key = format!("version_cache:{}", resource_id);
        
        self.redis.set_string(&cache_key, version, Some(ttl)).await
            .map_err(|e| {
                error!("Failed to cache version for {}: {}", resource_id, e);
                e
            })?;
            
        debug!("Cached version for {} (TTL: {}s): {}", resource_id, ttl, version);
        Ok(())
    }
    
    /// 获取详细的版本信息（包含元数据）
    pub async fn get_cached_version_info(&self, resource_id: &str) -> Option<VersionInfo> {
        let info_key = format!("version_info:{}", resource_id);
        match self.redis.get_string(&info_key).await {
            Ok(Some(json_str)) => {
                match serde_json::from_str::<VersionInfo>(&json_str) {
                    Ok(info) => {
                        debug!("Retrieved cached version info for {}", resource_id);
                        Some(info)
                    }
                    Err(e) => {
                        warn!("Failed to parse cached version info for {}: {}", resource_id, e);
                        None
                    }
                }
            }
            Ok(None) => None,
            Err(e) => {
                warn!("Failed to get cached version info for {}: {}", resource_id, e);
                None
            }
        }
    }
    
    /// 设置详细的版本信息
    pub async fn set_cached_version_info(
        &self, 
        resource_id: &str, 
        version_info: &VersionInfo, 
        ttl: u32
    ) -> DfsResult<()> {
        let info_key = format!("version_info:{}", resource_id);
        let cache_key = format!("version_cache:{}", resource_id);
        
        // 序列化版本信息
        let json_str = serde_json::to_string(version_info)
            .map_err(|e| DfsError::internal_error(format!("Failed to serialize version info: {}", e)))?;
        
        // 同时设置详细信息和简单版本号
        self.redis.set_string(&info_key, &json_str, Some(ttl)).await?;
        self.redis.set_string(&cache_key, &version_info.version, Some(ttl)).await?;
        
        debug!("Cached version info for {} (TTL: {}s): {}", resource_id, ttl, version_info.version);
        Ok(())
    }
    
    /// 检查缓存是否应该更新
    /// 在80%过期时间点时返回true，以便提前更新
    pub async fn should_update(&self, resource_id: &str, cache_ttl: u32) -> bool {
        let update_key = format!("version_update_time:{}", resource_id);
        
        match self.redis.get_string(&update_key).await {
            Ok(Some(timestamp_str)) => {
                if let Ok(timestamp) = timestamp_str.parse::<u64>() {
                    let last_update = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
                    let threshold = Duration::from_secs((cache_ttl as f64 * 0.8) as u64);
                    
                    if let Ok(elapsed) = last_update.elapsed() {
                        let should_update = elapsed >= threshold;
                        debug!(
                            "Version update check for {}: elapsed={}s, threshold={}s, should_update={}", 
                            resource_id, elapsed.as_secs(), threshold.as_secs(), should_update
                        );
                        return should_update;
                    }
                }
            }
            Ok(None) => {
                debug!("No update timestamp found for {}, should update", resource_id);
                return true; // 没有记录说明从未更新过
            }
            Err(e) => {
                warn!("Failed to check update timestamp for {}: {}", resource_id, e);
                return true; // 出错时也尝试更新
            }
        }
        
        true
    }
    
    /// 记录最后更新时间
    pub async fn mark_updated(&self, resource_id: &str) -> DfsResult<()> {
        let update_key = format!("version_update_time:{}", resource_id);
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.redis.set_string(
            &update_key, 
            &timestamp.to_string(), 
            Some(86400) // 24小时过期
        ).await?;
        
        debug!("Marked version update time for {}: {}", resource_id, timestamp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use modules::storage::app_state::create_data_store;
    
    async fn setup_cache() -> VersionCache {
        let data_store = create_data_store().await.expect("Failed to create data store");
        VersionCache::new(data_store)
    }
    
    #[tokio::test]
    async fn test_version_cache() {
        let cache = setup_cache().await;
        let resource_id = "test_resource";
        let version = "1.2.3";
        let ttl = 300;
        
        // 测试设置和获取
        cache.set_cached_version(resource_id, version, ttl).await.unwrap();
        let cached = cache.get_cached_version(resource_id).await;
        assert_eq!(cached, Some(version.to_string()));
        
        // 测试版本信息
        let version_info = VersionInfo::new(
            version.to_string(), 
            None, // changelog
            Some(serde_json::json!({"test": "data"})) // metadata
        );
        cache.set_cached_version_info(resource_id, &version_info, ttl).await.unwrap();
        
        let cached_info = cache.get_cached_version_info(resource_id).await;
        assert!(cached_info.is_some());
        let cached_info = cached_info.unwrap();
        assert_eq!(cached_info.version, version);
        
        // 测试清除缓存
        cache.clear_cache(resource_id).await.unwrap();
        let cached_after_clear = cache.get_cached_version(resource_id).await;
        assert_eq!(cached_after_clear, None);
    }
    
    #[tokio::test]
    async fn test_should_update() {
        let cache = setup_cache().await;
        let resource_id = "test_should_update";
        let ttl = 100; // 100秒
        
        // 初始状态应该更新
        assert!(cache.should_update(resource_id, ttl).await);
        
        // 标记已更新
        cache.mark_updated(resource_id).await.unwrap();
        
        // 刚更新完不应该更新
        assert!(!cache.should_update(resource_id, ttl).await);
        
        // 模拟时间过去（实际测试中可能需要调整）
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        // 注意：实际测试中，100ms远小于80%的100s，所以仍然不应该更新
        // 这里只是测试逻辑，实际使用中时间会更长
    }
}