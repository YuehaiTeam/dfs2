use std::time::{Duration, SystemTime};
use tracing::{debug, error, warn};

use super::VersionInfo;
use crate::error::{DfsError, DfsResult};
use crate::modules::storage::data_store::DataStore;

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
        let cache_key = format!("version_cache:{resource_id}");
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

    /// 写入版本号，不设过期。
    ///
    /// 插件失败不会删掉它。下一次插件成功才会覆盖。
    pub async fn set_cached_version(&self, resource_id: &str, version: &str) -> DfsResult<()> {
        let cache_key = format!("version_cache:{resource_id}");

        self.redis
            .set_string(&cache_key, version, None)
            .await
            .map_err(|e| {
                error!("Failed to cache version for {}: {}", resource_id, e);
                e
            })?;

        debug!("Cached version for {}: {}", resource_id, version);
        Ok(())
    }

    /// 获取详细的版本信息（包含元数据）
    pub async fn get_cached_version_info(&self, resource_id: &str) -> Option<VersionInfo> {
        let info_key = format!("version_info:{resource_id}");
        match self.redis.get_string(&info_key).await {
            Ok(Some(json_str)) => match serde_json::from_str::<VersionInfo>(&json_str) {
                Ok(info) => {
                    debug!("Retrieved cached version info for {}", resource_id);
                    Some(info)
                }
                Err(e) => {
                    warn!(
                        "Failed to parse cached version info for {}: {}",
                        resource_id, e
                    );
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                warn!(
                    "Failed to get cached version info for {}: {}",
                    resource_id, e
                );
                None
            }
        }
    }

    /// 写入版本详情和版本号，两者都不设过期。
    pub async fn set_cached_version_info(
        &self,
        resource_id: &str,
        version_info: &VersionInfo,
    ) -> DfsResult<()> {
        let info_key = format!("version_info:{resource_id}");
        let cache_key = format!("version_cache:{resource_id}");

        // 序列化版本信息
        let json_str = serde_json::to_string(version_info).map_err(|e| {
            DfsError::internal_error(format!("Failed to serialize version info: {e}"))
        })?;

        // 同时设置详细信息和简单版本号
        self.redis.set_string(&info_key, &json_str, None).await?;
        self.redis
            .set_string(&cache_key, &version_info.version, None)
            .await?;

        debug!(
            "Cached version info for {}: {}",
            resource_id, version_info.version
        );
        Ok(())
    }

    /// 距上次成功更新已过 `cache_ttl` 的 80% 时返回 true。
    ///
    /// 版本值本身不过期。这个间隔只决定何时再拉插件。
    pub async fn should_update(&self, resource_id: &str, cache_ttl: u32) -> bool {
        let update_key = format!("version_update_time:{resource_id}");

        match self.redis.get_string(&update_key).await {
            Ok(Some(timestamp_str)) => {
                if let Ok(timestamp) = timestamp_str.parse::<u64>() {
                    let last_update = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
                    let threshold = Duration::from_secs((cache_ttl as f64 * 0.8) as u64);

                    if let Ok(elapsed) = last_update.elapsed() {
                        let should_update = elapsed >= threshold;
                        debug!(
                            "Version update check for {}: elapsed={}s, threshold={}s, should_update={}",
                            resource_id,
                            elapsed.as_secs(),
                            threshold.as_secs(),
                            should_update
                        );
                        return should_update;
                    }
                }
            }
            Ok(None) => {
                debug!(
                    "No update timestamp found for {}, should update",
                    resource_id
                );
                return true; // 没有记录说明从未更新过
            }
            Err(e) => {
                warn!(
                    "Failed to check update timestamp for {}: {}",
                    resource_id, e
                );
                return true; // 出错时也尝试更新
            }
        }

        true
    }

    /// 记录最后更新时间
    pub async fn mark_updated(&self, resource_id: &str) -> DfsResult<()> {
        let update_key = format!("version_update_time:{resource_id}");
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.redis
            .set_string(
                &update_key,
                &timestamp.to_string(),
                Some(86400), // 24小时过期；过期后下次检查会再拉插件，不删版本值
            )
            .await?;

        debug!(
            "Marked version update time for {}: {}",
            resource_id, timestamp
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::VersionCache;
    use crate::modules::version_provider::VersionInfo;
    use crate::tests::mocks::MockDataStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn cached_version_is_not_given_an_expiry() {
        let mock = Arc::new(MockDataStore::new());
        let cache = VersionCache::new(mock.clone());
        let info = VersionInfo::new("2.0.0".into(), Some("notes".into()), None);

        cache
            .set_cached_version_info("app", &info)
            .await
            .expect("cache version");

        assert_eq!(
            cache.get_cached_version("app").await.as_deref(),
            Some("2.0.0")
        );
        assert_eq!(
            mock.string_has_expiry("version_cache:app").await,
            Some(false)
        );
        assert_eq!(
            mock.string_has_expiry("version_info:app").await,
            Some(false)
        );
    }
}
