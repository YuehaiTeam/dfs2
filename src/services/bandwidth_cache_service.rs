use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::modules::storage::data_store::{BANDWIDTH_MINUTE_RING_SIZE, DataStore};

/// 汇总全站外部节点签发流量的内部桶键（不含进程内缓存直回 `"cache"`）。
pub const GLOBAL_BANDWIDTH_KEY: &str = "*";

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

    /// 串行化后台定时刷盘与测试手动刷盘，保证 `fetch_sub` 回扣不会并发重入
    flush_lock: Arc<tokio::sync::Mutex<()>>,

    /// 协调刷盘（写锁）与缓存未命中回源读取（读锁），消除 `HINCRBY` 与 `fetch_sub` 之间的双计窗口
    sync_lock: Arc<RwLock<()>>,

    /// 测试时钟覆盖（秒级 Unix 时间戳；`u64::MAX` 表示未启用覆盖）
    #[cfg(test)]
    mock_unix_secs: Arc<AtomicU64>,
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
            flush_lock: Arc::new(tokio::sync::Mutex::new(())),
            sync_lock: Arc::new(RwLock::new(())),
            #[cfg(test)]
            mock_unix_secs: Arc::new(AtomicU64::new(u64::MAX)),
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
        let query_minute = self.current_minute_timestamp();

        // 1. 尝试从缓存获取
        if let Some(cached_result) = self.get_from_cache(server_id, minutes, query_minute).await {
            debug!(
                "Cache hit for server {} ({} minutes): {} bytes",
                server_id, minutes, cached_result
            );
            return Ok(cached_result);
        }

        // 2. 缓存未命中：持读同步锁查询持久化层并原子收敛写缓冲区增量，避免刷盘双计与写回覆盖竞态
        debug!(
            "Cache miss for server {} ({} minutes), querying Redis",
            server_id, minutes
        );
        let clamped_minutes = minutes.min(BANDWIDTH_MINUTE_RING_SIZE);
        let _sync_guard = self.sync_lock.read().await;
        let persisted = self
            .data_store
            .get_server_minutes_bandwidth_direct(server_id, clamped_minutes)
            .await?;

        let total_bytes = {
            let mut cache = self.read_cache.write().await;
            let pending = self.sum_pending_bytes(server_id, clamped_minutes, query_minute);
            let total = persisted.saturating_add(pending);
            Self::insert_cache_entry_locked(&mut cache, server_id, minutes, total, query_minute);
            total
        };

        debug!(
            "Redis query result for server {} ({} minutes): {} bytes",
            server_id, minutes, total_bytes
        );
        Ok(total_bytes)
    }

    /// 查询用于速率判定的采样总字节与真实覆盖秒数。
    ///
    /// 采样包含过去 `window_minutes` 个完整分钟桶外加当前进行中的分钟桶（共 `window_minutes + 1`
    /// 个桶，上限截断至 [`BANDWIDTH_MINUTE_RING_SIZE`]），覆盖时长为完整分钟秒数加上当前分钟已走过的
    /// `now_secs % 60` 秒，消除跨整分时刻采样窗口缩水导致的速率周期性低估。
    pub async fn get_rate_window_stats(
        &self,
        target_id: &str,
        window_minutes: u32,
    ) -> Result<(u64, u64), String> {
        let now_secs = self.current_unix_timestamp_secs();
        let buckets = window_minutes
            .max(1)
            .saturating_add(1)
            .min(BANDWIDTH_MINUTE_RING_SIZE);
        let total_bytes = self
            .get_server_minutes_bandwidth(target_id, buckets)
            .await?;
        let elapsed_secs = (buckets.saturating_sub(1) as u64) * 60 + (now_secs % 60);
        Ok((total_bytes, elapsed_secs.max(1)))
    }

    /// 记录流量（异步写入）。非 `"cache"` 节点同步计入全局汇总桶 [`GLOBAL_BANDWIDTH_KEY`]。
    ///
    /// # 参数
    /// - `server_id`: 服务器ID
    /// - `bytes`: 流量字节数
    pub async fn record_bandwidth(&self, server_id: &str, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let current_minute = self.current_minute_timestamp();
        self.record_target_at_minute(server_id, bytes, current_minute)
            .await;
        if server_id != "cache" && server_id != GLOBAL_BANDWIDTH_KEY {
            self.record_target_at_minute(GLOBAL_BANDWIDTH_KEY, bytes, current_minute)
                .await;
        }
    }

    async fn record_target_at_minute(&self, target_id: &str, bytes: u64, minute_timestamp: u64) {
        let key = (target_id.to_string(), minute_timestamp);

        debug!(
            "Recording {} bytes for server {} at minute {}",
            bytes, target_id, minute_timestamp
        );

        let mut cache = self.read_cache.write().await;
        self.write_buffer
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(bytes, Ordering::AcqRel);
        Self::increment_local_cache_locked(&mut cache, target_id, bytes, minute_timestamp);
    }

    /// 从缓存获取数据；跨整分后旧分钟快照失效，避免漏计新分钟写入并残留过期分钟。
    async fn get_from_cache(
        &self,
        server_id: &str,
        minutes: u32,
        current_minute: u64,
    ) -> Option<u64> {
        let cache = self.read_cache.read().await;

        if let Some(server_cache) = cache.get(server_id)
            && let Some(cached_data) = server_cache.get(&minutes)
            && cached_data.last_redis_sync == current_minute
            && cached_data.cached_at.elapsed().unwrap_or(Duration::MAX) < self.cache_ttl
        {
            return Some(cached_data.total_bytes);
        }

        None
    }

    fn sum_pending_bytes(&self, server_id: &str, minutes: u32, current_minute: u64) -> u64 {
        let mut pending = 0u64;
        for i in 0..minutes {
            let target_minute = current_minute.saturating_sub(i as u64);
            if let Some(counter) = self
                .write_buffer
                .get(&(server_id.to_string(), target_minute))
            {
                pending = pending.saturating_add(counter.load(Ordering::Acquire));
            }
        }
        pending
    }

    /// 更新本地缓存（调用方已持有 `read_cache` 写锁）
    fn insert_cache_entry_locked(
        cache: &mut HashMap<String, HashMap<u32, CachedBandwidthData>>,
        server_id: &str,
        minutes: u32,
        total_bytes: u64,
        sync_minute: u64,
    ) {
        let server_cache = cache.entry(server_id.to_string()).or_default();

        server_cache.insert(
            minutes,
            CachedBandwidthData {
                total_bytes,
                window_minutes: minutes,
                cached_at: SystemTime::now(),
                last_redis_sync: sync_minute,
            },
        );

        // 清理过期缓存（简单LRU策略）
        if server_cache.len() > 10 {
            let window_to_remove = server_cache
                .iter()
                .min_by_key(|(_, data)| data.cached_at)
                .map(|(window, _)| *window);

            if let Some(window) = window_to_remove {
                server_cache.remove(&window);
            }
        }
    }

    /// 立即更新本地缓存（调用方已持有 `read_cache` 写锁）
    fn increment_local_cache_locked(
        cache: &mut HashMap<String, HashMap<u32, CachedBandwidthData>>,
        server_id: &str,
        bytes: u64,
        minute_timestamp: u64,
    ) {
        if let Some(server_cache) = cache.get_mut(server_id) {
            for cached_data in server_cache.values_mut() {
                if cached_data.window_minutes == 0 {
                    continue;
                }
                let cache_start_minute = cached_data
                    .last_redis_sync
                    .saturating_sub(cached_data.window_minutes.saturating_sub(1) as u64);

                if minute_timestamp >= cache_start_minute
                    && minute_timestamp <= cached_data.last_redis_sync
                {
                    cached_data.total_bytes = cached_data.total_bytes.saturating_add(bytes);
                }
            }
        }
    }

    /// 启动后台批量刷新任务
    fn start_background_flush_task(&self) {
        let service = self.clone();
        let flush_interval = self.flush_interval;

        info!(
            "Starting background bandwidth flush task (interval: {:?})",
            flush_interval
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(flush_interval);

            loop {
                interval.tick().await;

                if service.write_buffer.is_empty() {
                    continue;
                }

                if let Err(e) = service.flush_pending_entries().await {
                    error!("Failed to flush bandwidth updates to Redis: {}", e);
                } else {
                    debug!("Successfully flushed bandwidth updates to Redis");
                }
            }
        });
    }

    /// 将写缓冲区中的增量刷入存储，并在 `sync_lock` 写锁保护下完成持久化与 `fetch_sub` 回扣，
    /// 消除回源读取时重复计入同一批增量的竞态窗口。
    async fn flush_pending_entries(&self) -> Result<(), String> {
        let _guard = self.flush_lock.lock().await;
        if self.write_buffer.is_empty() {
            return Ok(());
        }

        let _sync_guard = self.sync_lock.write().await;

        let mut server_data: HashMap<String, Vec<(u64, u64)>> = HashMap::new();
        for entry in self.write_buffer.iter() {
            let ((server_id, minute_timestamp), counter) = entry.pair();
            let bytes = counter.load(Ordering::Acquire);
            if bytes > 0 {
                server_data
                    .entry(server_id.clone())
                    .or_default()
                    .push((*minute_timestamp, bytes));
            }
        }

        for (server_id, mut minute_list) in server_data {
            minute_list.sort_by_key(|(minute, _)| *minute);

            debug!(
                "Flushing {} minute entries for server {}",
                minute_list.len(),
                server_id
            );

            for (minute_timestamp, flushed_bytes) in minute_list {
                match self
                    .data_store
                    .update_server_minute_bandwidth_direct(
                        &server_id,
                        minute_timestamp,
                        flushed_bytes,
                    )
                    .await
                {
                    Ok(()) => {
                        if let Some(counter) = self
                            .write_buffer
                            .get(&(server_id.clone(), minute_timestamp))
                        {
                            counter.fetch_sub(flushed_bytes, Ordering::AcqRel);
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to update minute bandwidth for server {} at minute {}: {}",
                            server_id, minute_timestamp, e
                        );
                    }
                }
            }
        }

        let current_minute = self.current_minute_timestamp();
        self.write_buffer.retain(|(_, min_ts), counter| {
            *min_ts >= current_minute || counter.load(Ordering::Acquire) > 0
        });

        Ok(())
    }

    fn current_unix_timestamp_secs(&self) -> u64 {
        #[cfg(test)]
        {
            let mocked = self.mock_unix_secs.load(Ordering::Relaxed);
            if mocked != u64::MAX {
                return mocked;
            }
        }
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// 获取当前分钟时间戳
    fn current_minute_timestamp(&self) -> u64 {
        self.current_unix_timestamp_secs() / 60
    }

    #[cfg(test)]
    pub fn set_mock_unix_secs(&self, unix_secs: Option<u64>) {
        self.mock_unix_secs
            .store(unix_secs.unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// 获取缓存统计信息（用于监控和调试）
    #[allow(dead_code)]
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
        self.flush_pending_entries().await
    }

    #[cfg(test)]
    /// 在指定分钟记录流量（测试用）
    pub async fn record_bandwidth_at_minute(
        &self,
        server_id: &str,
        bytes: u64,
        minute_timestamp: u64,
    ) {
        if bytes == 0 {
            return;
        }
        self.record_target_at_minute(server_id, bytes, minute_timestamp)
            .await;
        if server_id != "cache" && server_id != GLOBAL_BANDWIDTH_KEY {
            self.record_target_at_minute(GLOBAL_BANDWIDTH_KEY, bytes, minute_timestamp)
                .await;
        }
    }
}

/// 缓存统计信息
#[derive(Debug, Clone)]
#[allow(dead_code)]
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

    #[tokio::test]
    async fn minute_bandwidth_continues_past_24_hours() {
        let env = TestEnvironment::new().await;
        let cache_service = env.app_context.bandwidth_cache_service.clone();

        let day_zero_minute = 500_000u64;
        env.set_mock_current_time(Some(day_zero_minute)).await;
        cache_service.record_bandwidth("long_lived", 4096).await;
        cache_service.flush_pending_for_test().await.unwrap();
        assert_eq!(
            cache_service
                .get_server_minutes_bandwidth("long_lived", 5)
                .await
                .unwrap(),
            4096
        );

        let after_33_hours = day_zero_minute + 2000;
        env.set_mock_current_time(Some(after_33_hours)).await;
        cache_service.record_bandwidth("long_lived", 8192).await;
        cache_service.flush_pending_for_test().await.unwrap();

        assert_eq!(
            cache_service
                .get_server_minutes_bandwidth("long_lived", 5)
                .await
                .unwrap(),
            8192
        );
    }

    #[tokio::test]
    async fn global_bandwidth_aggregates_external_servers_and_excludes_cache() {
        let env = TestEnvironment::new().await;
        let cache_service = env.app_context.bandwidth_cache_service.clone();
        env.set_mock_unix_secs(Some(700_000 * 60 + 15)).await;

        cache_service.record_bandwidth("node_a", 1_000).await;
        cache_service.record_bandwidth("node_b", 2_500).await;
        cache_service.record_bandwidth("cache", 9_999).await;

        // 未刷盘前直接查询也包含写缓冲中的增量
        assert_eq!(
            cache_service
                .get_server_minutes_bandwidth(GLOBAL_BANDWIDTH_KEY, 5)
                .await
                .unwrap(),
            3_500
        );

        cache_service.flush_pending_for_test().await.unwrap();
        assert_eq!(
            cache_service
                .get_server_minutes_bandwidth(GLOBAL_BANDWIDTH_KEY, 5)
                .await
                .unwrap(),
            3_500
        );

        // 全局桶已在本地读缓存命中期间，同分钟新增节点写入仍实时叠加且刷盘后不重计
        cache_service.record_bandwidth("node_a", 500).await;
        assert_eq!(
            cache_service
                .get_server_minutes_bandwidth(GLOBAL_BANDWIDTH_KEY, 5)
                .await
                .unwrap(),
            4_000
        );
        cache_service.flush_pending_for_test().await.unwrap();
        assert_eq!(
            cache_service
                .get_server_minutes_bandwidth(GLOBAL_BANDWIDTH_KEY, 5)
                .await
                .unwrap(),
            4_000
        );
    }

    #[tokio::test]
    async fn read_cache_invalidates_on_minute_rollover_and_rate_window_includes_partial_minute() {
        let env = TestEnvironment::new().await;
        let cache_service = env.app_context.bandwidth_cache_service.clone();

        let base_minute = 800_000u64;
        env.set_mock_unix_secs(Some(base_minute * 60 + 30)).await;
        cache_service
            .record_bandwidth_at_minute("node_a", 10_000, base_minute - 5)
            .await;
        cache_service
            .record_bandwidth_at_minute("node_a", 5_000, base_minute)
            .await;
        cache_service.flush_pending_for_test().await.unwrap();

        // 5 分钟速率窗口采样 5 个完整分钟 + 当前进行中的 30 秒，总跨度 330 秒
        let (bytes, elapsed_secs) = cache_service
            .get_rate_window_stats("node_a", 5)
            .await
            .unwrap();
        assert_eq!(bytes, 15_000);
        assert_eq!(elapsed_secs, 5 * 60 + 30);

        // 推进到 base_minute + 1（仍在本地缓存 wall-clock TTL 内），滑出窗口的旧桶不再保留
        env.set_mock_unix_secs(Some((base_minute + 1) * 60 + 10))
            .await;
        let (bytes_after, elapsed_after) = cache_service
            .get_rate_window_stats("node_a", 5)
            .await
            .unwrap();
        assert_eq!(bytes_after, 5_000);
        assert_eq!(elapsed_after, 5 * 60 + 10);
    }
}
