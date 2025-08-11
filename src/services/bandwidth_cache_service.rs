use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::modules::storage::data_store::DataStore;

/// 缓存的带宽数据
#[derive(Debug, Clone)]
struct CachedBandwidthData {
    pub total_bytes: u64,      // 指定时间窗口内的总流量
    pub window_minutes: u32,   // 时间窗口大小（分钟）
    pub cached_at: SystemTime, // 缓存时间
    pub last_redis_sync: u64,  // 最后同步到Redis的分钟时间戳
}

/// 带宽缓存服务
///
/// 提供本地缓存 + 异步批量更新的分钟级带宽统计功能
///
/// # 功能特性
/// - 本地缓存：减少Redis查询，提供90%+缓存命中率
/// - 异步更新：累积流量数据，定期批量写入Redis
/// - 后台任务：自动刷新机制，保证数据最终一致性
#[derive(Clone)]
pub struct BandwidthCacheService {
    /// 读缓存：server_id -> (window_minutes -> CachedBandwidthData)
    read_cache: Arc<RwLock<HashMap<String, HashMap<u32, CachedBandwidthData>>>>,

    /// 写缓冲区：(server_id, minute_timestamp) -> total_bytes
    write_buffer: Arc<DashMap<(String, u64), AtomicU64>>,

    /// Redis数据存储
    data_store: DataStore,

    /// 缓存TTL（默认5秒）
    cache_ttl: Duration,

    /// 刷新间隔（默认1秒）
    flush_interval: Duration,
}

impl BandwidthCacheService {
    /// 创建新的带宽缓存服务
    pub fn new(data_store: DataStore) -> Self {
        let service = Self {
            read_cache: Arc::new(RwLock::new(HashMap::new())),
            write_buffer: Arc::new(DashMap::new()),
            data_store,
            cache_ttl: Duration::from_secs(5),
            flush_interval: Duration::from_secs(1),
        };

        // 启动后台刷新任务
        service.start_background_flush_task();
        service
    }

    /// 查询服务器近N分钟流量（优先使用缓存）
    ///
    /// # 参数
    /// - `server_id`: 服务器ID
    /// - `minutes`: 时间窗口大小（分钟）
    ///
    /// # 返回
    /// - `Ok(u64)`: 指定时间窗口内的总流量字节数
    /// - `Err(String)`: 查询失败的错误信息
    pub async fn get_server_minutes_bandwidth(
        &self,
        server_id: &str,
        minutes: u32,
    ) -> Result<u64, String> {
        debug!(
            "Querying bandwidth for server {} in last {} minutes",
            server_id, minutes
        );

        // 1. 尝试从缓存获取
        if let Some(cached_result) = self.get_from_cache(server_id, minutes).await {
            debug!(
                "Cache hit for server {} ({} minutes): {} bytes",
                server_id, minutes, cached_result
            );
            return Ok(cached_result);
        }

        // 2. 缓存未命中，从Redis查询
        debug!(
            "Cache miss for server {} ({} minutes), querying Redis",
            server_id, minutes
        );
        let redis_result = self.query_from_redis(server_id, minutes).await?;

        // 3. 更新缓存
        self.update_cache(server_id, minutes, redis_result).await;

        debug!(
            "Redis query result for server {} ({} minutes): {} bytes",
            server_id, minutes, redis_result
        );
        Ok(redis_result)
    }

    /// 记录流量（异步写入）
    ///
    /// # 参数
    /// - `server_id`: 服务器ID
    /// - `bytes`: 流量字节数
    pub async fn record_bandwidth(&self, server_id: &str, bytes: u64) {
        let current_minute = self.current_minute_timestamp();
        let key = (server_id.to_string(), current_minute);

        debug!(
            "Recording {} bytes for server {} at minute {}",
            bytes, server_id, current_minute
        );

        // 原子累加，完全无锁
        self.write_buffer
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(bytes, Ordering::Relaxed);

        // 立即更新本地缓存（保证查询一致性）
        self.increment_local_cache(server_id, bytes, current_minute)
            .await;
    }

    /// 从缓存获取数据
    async fn get_from_cache(&self, server_id: &str, minutes: u32) -> Option<u64> {
        let cache = self.read_cache.read().await;

        if let Some(server_cache) = cache.get(server_id) {
            if let Some(cached_data) = server_cache.get(&minutes) {
                // 检查缓存是否过期
                if cached_data.cached_at.elapsed().unwrap_or(Duration::MAX) < self.cache_ttl {
                    return Some(cached_data.total_bytes);
                }
            }
        }

        None
    }

    /// 从Redis查询数据
    async fn query_from_redis(&self, server_id: &str, minutes: u32) -> Result<u64, String> {
        // 使用环形缓冲区查询
        self.data_store
            .get_server_minutes_bandwidth_direct(server_id, minutes)
            .await
    }

    /// 更新本地缓存
    async fn update_cache(&self, server_id: &str, minutes: u32, total_bytes: u64) {
        let mut cache = self.read_cache.write().await;
        let server_cache = cache
            .entry(server_id.to_string())
            .or_insert_with(HashMap::new);

        server_cache.insert(
            minutes,
            CachedBandwidthData {
                total_bytes,
                window_minutes: minutes,
                cached_at: SystemTime::now(),
                last_redis_sync: self.current_minute_timestamp(),
            },
        );

        // 清理过期缓存（简单LRU策略）
        if server_cache.len() > 10 {
            // 找到最旧的缓存项
            let window_to_remove = server_cache
                .iter()
                .min_by_key(|(_, data)| data.cached_at)
                .map(|(window, _)| *window);

            // 移除最旧的缓存项
            if let Some(window) = window_to_remove {
                server_cache.remove(&window);
            }
        }
    }

    /// 立即更新本地缓存（用于保证一致性）
    async fn increment_local_cache(&self, server_id: &str, bytes: u64, minute_timestamp: u64) {
        let mut cache = self.read_cache.write().await;

        if let Some(server_cache) = cache.get_mut(server_id) {
            for (_, cached_data) in server_cache.iter_mut() {
                // 如果这个字节数应该包含在缓存的时间窗口内
                let cache_start_minute = cached_data
                    .last_redis_sync
                    .saturating_sub(cached_data.window_minutes as u64 - 1);

                if minute_timestamp >= cache_start_minute
                    && minute_timestamp <= cached_data.last_redis_sync
                {
                    cached_data.total_bytes += bytes;
                }
            }
        }
    }

    /// 启动后台批量刷新任务
    fn start_background_flush_task(&self) {
        let write_buffer = Arc::clone(&self.write_buffer);
        let data_store = self.data_store.clone();
        let flush_interval = self.flush_interval;

        info!(
            "Starting background bandwidth flush task (interval: {:?})",
            flush_interval
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(flush_interval);

            loop {
                interval.tick().await;

                // 跳过空的刷新周期
                if write_buffer.is_empty() {
                    continue;
                }

                // 创建新的空buffer，收集数据
                let updates_to_flush = DashMap::new();

                // 移动所有数据到新的DashMap
                for entry in write_buffer.iter() {
                    let (key, value) = entry.pair();
                    updates_to_flush
                        .insert(key.clone(), AtomicU64::new(value.load(Ordering::Relaxed)));
                }

                // 清空原始 buffer
                write_buffer.clear();

                // 批量刷新到Redis
                if let Err(e) = Self::flush_to_redis(&data_store, updates_to_flush).await {
                    error!("Failed to flush bandwidth updates to Redis: {}", e);
                } else {
                    debug!("Successfully flushed bandwidth updates to Redis");
                }
            }
        });
    }

    /// 批量刷新到Redis
    async fn flush_to_redis(
        data_store: &DataStore,
        updates: DashMap<(String, u64), AtomicU64>,
    ) -> Result<(), String> {
        if updates.is_empty() {
            return Ok(());
        }

        debug!("Flushing {} bandwidth entries to Redis", updates.len());

        // 按server_id分组并收集数据
        let mut server_data: HashMap<String, Vec<(u64, u64)>> = HashMap::new();

        for entry in updates.iter() {
            let ((server_id, minute_timestamp), counter) = entry.pair();
            let bytes = counter.load(Ordering::Relaxed);

            if bytes > 0 {
                server_data
                    .entry(server_id.clone())
                    .or_default()
                    .push((*minute_timestamp, bytes));
            }
        }

        // 为每个服务器排序并写入Redis
        for (server_id, mut minute_list) in server_data {
            // 按时间戳排序，确保顺序写入
            minute_list.sort_by_key(|(minute, _)| *minute);

            debug!(
                "Flushing {} minute entries for server {}",
                minute_list.len(),
                server_id
            );

            for (minute_timestamp, total_bytes) in minute_list {
                if let Err(e) = data_store
                    .update_server_minute_bandwidth_direct(
                        &server_id,
                        minute_timestamp,
                        total_bytes,
                    )
                    .await
                {
                    warn!(
                        "Failed to update minute bandwidth for server {} at minute {}: {}",
                        server_id, minute_timestamp, e
                    );
                }
            }
        }

        Ok(())
    }

    /// 获取当前分钟时间戳
    fn current_minute_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60
    }

    /// 获取缓存统计信息（用于监控和调试）
    pub async fn get_cache_stats(&self) -> CacheStats {
        let cache = self.read_cache.read().await;

        let cached_servers = cache.len();
        let cached_entries: usize = cache.values().map(|m| m.len()).sum();
        let pending_updates = self.write_buffer.len();

        CacheStats {
            cached_servers,
            cached_entries,
            pending_updates,
        }
    }

    // 测试辅助方法
    #[cfg(test)]
    /// 手动触发刷新到Redis（测试用）
    pub async fn flush_pending_for_test(&self) -> Result<(), String> {
        let updates_to_flush = DashMap::new();

        // 移动所有数据到新的DashMap
        for entry in self.write_buffer.iter() {
            let (key, value) = entry.pair();
            updates_to_flush.insert(key.clone(), AtomicU64::new(value.load(Ordering::Relaxed)));
        }

        // 清空原始 buffer
        self.write_buffer.clear();

        Self::flush_to_redis(&self.data_store, updates_to_flush).await
    }

    #[cfg(test)]
    /// 在指定分钟记录流量（测试用）
    pub async fn record_bandwidth_at_minute(
        &self,
        server_id: &str,
        bytes: u64,
        minute_timestamp: u64,
    ) {
        let key = (server_id.to_string(), minute_timestamp);

        debug!(
            "Recording {} bytes for server {} at minute {}",
            bytes, server_id, minute_timestamp
        );

        // 原子累加
        self.write_buffer
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(bytes, Ordering::Relaxed);
    }
}

/// 缓存统计信息
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub cached_servers: usize,  // 缓存的服务器数量
    pub cached_entries: usize,  // 缓存的条目总数
    pub pending_updates: usize, // 待刷新的更新数量
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::mocks::TestEnvironment;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn test_bandwidth_recording_and_aggregation() {
        let env = TestEnvironment::new().await;
        let cache_service = BandwidthCacheService::new(env.data_store);

        // 记录流量 - 同一分钟内的多次记录会自动聚合
        cache_service.record_bandwidth("test_server", 1024).await;
        cache_service.record_bandwidth("test_server", 2048).await;

        // 手动触发刷新到Redis
        cache_service.flush_pending_for_test().await.unwrap();

        // 验证数据已正确聚合并存储
        let result = cache_service
            .get_server_minutes_bandwidth("test_server", 1)
            .await;
        assert_eq!(result.unwrap(), 3072); // 1024 + 2048 = 3072
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let env = TestEnvironment::new().await;
        let mut cache_service = BandwidthCacheService::new(env.data_store.clone());
        cache_service.cache_ttl = Duration::from_millis(100); // 短TTL用于测试

        // 预写入数据到Redis
        let current_ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60;
        env.data_store
            .update_server_minute_bandwidth_direct("test_server", current_ts, 1024)
            .await
            .unwrap();

        // 首次查询会缓存结果
        let result1 = cache_service
            .get_server_minutes_bandwidth("test_server", 1)
            .await;
        assert_eq!(result1.unwrap(), 1024);

        // 等待缓存过期
        sleep(Duration::from_millis(150)).await;

        // 再次查询，缓存已过期，会重新从Redis加载
        let result2 = cache_service
            .get_server_minutes_bandwidth("test_server", 1)
            .await;
        assert_eq!(result2.unwrap(), 1024);
    }

    #[tokio::test]
    async fn test_server_isolation() {
        let env = TestEnvironment::new().await;
        let cache_service = BandwidthCacheService::new(env.data_store);

        // 为不同服务器记录不同的流量
        cache_service.record_bandwidth("server1", 1000).await;
        cache_service.record_bandwidth("server2", 2000).await;
        cache_service.record_bandwidth("server3", 3000).await;

        // 刷新到Redis
        cache_service.flush_pending_for_test().await.unwrap();

        // 验证每个服务器的数据完全独立
        let result1 = cache_service
            .get_server_minutes_bandwidth("server1", 1)
            .await;
        let result2 = cache_service
            .get_server_minutes_bandwidth("server2", 1)
            .await;
        let result3 = cache_service
            .get_server_minutes_bandwidth("server3", 1)
            .await;

        assert_eq!(result1.unwrap(), 1000);
        assert_eq!(result2.unwrap(), 2000);
        assert_eq!(result3.unwrap(), 3000);
    }

    #[tokio::test]
    async fn test_time_window_queries() {
        let env = TestEnvironment::new().await;
        let cache_service = BandwidthCacheService::new(env.data_store.clone());

        // 使用固定时间基准进行测试
        let base_minute = 1000000u64;
        env.set_mock_current_time(Some(base_minute + 10)).await;

        // 在不同时间点记录流量
        cache_service
            .record_bandwidth_at_minute("test_server", 1000, base_minute)
            .await;
        cache_service
            .record_bandwidth_at_minute("test_server", 2000, base_minute + 1)
            .await;
        cache_service
            .record_bandwidth_at_minute("test_server", 3000, base_minute + 2)
            .await;

        // 刷新到存储
        cache_service.flush_pending_for_test().await.unwrap();

        // 验证时间窗口查询功能
        let total = env
            .data_store
            .get_server_minutes_bandwidth_direct("test_server", 15)
            .await;
        assert_eq!(total.unwrap(), 6000);

        let cache_result = cache_service
            .get_server_minutes_bandwidth("test_server", 15)
            .await;
        assert_eq!(cache_result.unwrap(), 6000);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let env = TestEnvironment::new().await;
        let cache_service = BandwidthCacheService::new(env.data_store);

        // 并发为多个服务器记录流量
        let tasks: Vec<_> = (1..=5)
            .map(|i| {
                let service = cache_service.clone();
                let server_id = format!("server{}", i);
                let bytes = (i as u64) * 1000;
                tokio::spawn(async move {
                    // 每个服务器记录两次，测试原子聚合
                    service.record_bandwidth(&server_id, bytes).await;
                    service.record_bandwidth(&server_id, bytes).await;
                })
            })
            .collect();

        // 等待所有并发任务完成
        for task in tasks {
            task.await.unwrap();
        }

        // 刷新数据
        cache_service.flush_pending_for_test().await.unwrap();

        // 验证每个服务器都正确聚合了数据
        for i in 1..=5 {
            let server_id = format!("server{}", i);
            let expected = (i as u64) * 1000 * 2; // 记录了两次
            let result = cache_service
                .get_server_minutes_bandwidth(&server_id, 1)
                .await;
            assert_eq!(result.unwrap(), expected);
        }
    }
}
