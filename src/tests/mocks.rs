use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// 重新导入必要的类型，因为不再有lib.rs
use crate::config::{AppConfig, SharedConfig};
use crate::container::AppContext;
use crate::metrics::Metrics;
use crate::models::{CdnRecord, Session};
use crate::modules::qjs::JsRunner;
use crate::modules::server::HealthInfo;
use crate::modules::storage::data_store::{
    BANDWIDTH_MINUTE_RING_SIZE, BandwidthUpdateBatch, CacheMetadata, DataStoreBackend, SessionStats,
};
use crate::modules::version_provider::{PluginVersionProvider, VersionCache, VersionUpdater};
use crate::services::{
    BandwidthCacheService, ChallengeService, FlowService, ResourceService, SessionService,
    VersionFileService,
};

/// 统一的测试环境，包含所有必要的服务和Mock
#[allow(dead_code)]
pub struct TestEnvironment {
    pub data_store: crate::modules::storage::data_store::DataStore,
    pub shared_config: SharedConfig,
    pub js_runner: JsRunner,
    pub services: TestServices,
    pub app_context: AppContext,             // 添加app_context字段
    pub mock_data_store: Arc<MockDataStore>, // 直接存储MockDataStore引用
}

#[allow(dead_code)]
pub struct TestServices {
    pub session_service: SessionService,
    pub flow_service: FlowService,
    pub resource_service: ResourceService,
    pub challenge_service: ChallengeService,
}

impl TestEnvironment {
    /// 创建标准测试环境
    pub async fn new() -> Self {
        let config = create_default_test_config();
        Self::with_config(config).await
    }

    /// 设置Mock的当前时间（测试用，分钟粒度）
    pub async fn set_mock_current_time(&self, minute_timestamp: Option<u64>) {
        self.mock_data_store
            .set_current_time(minute_timestamp)
            .await;
        self.app_context
            .bandwidth_cache_service
            .set_mock_unix_secs(minute_timestamp.map(|m| m * 60));
    }

    /// 设置Mock的当前时间（测试用，秒粒度）
    pub async fn set_mock_unix_secs(&self, unix_secs: Option<u64>) {
        self.mock_data_store
            .set_current_time(unix_secs.map(|s| s / 60))
            .await;
        self.app_context
            .bandwidth_cache_service
            .set_mock_unix_secs(unix_secs);
    }

    /// 使用自定义配置创建测试环境
    pub async fn with_config(config: AppConfig) -> Self {
        let mock_data_store = Arc::new(MockDataStore::new());
        let data_store: crate::modules::storage::data_store::DataStore = mock_data_store.clone();
        let shared_config = SharedConfig::new(config);
        let js_runner = JsRunner::new(shared_config.clone(), data_store.clone()).await;

        // 创建版本管理组件
        let version_cache = Arc::new(VersionCache::new(data_store.clone()));
        let plugin_provider = Arc::new(PluginVersionProvider::new(
            js_runner.clone(),
            shared_config.clone(),
        ));
        let version_updater = Arc::new(VersionUpdater::new(
            shared_config.clone(),
            version_cache.clone(),
            plugin_provider,
        ));

        // 创建服务
        let session_service = SessionService::new(data_store.clone());
        let resource_service =
            ResourceService::new(shared_config.clone(), version_cache, version_updater);
        let bandwidth_cache_service = BandwidthCacheService::new(data_store.clone());
        let metrics = Arc::new(Metrics::new(shared_config.clone()).unwrap());
        let flow_service = FlowService::new(
            shared_config.clone(),
            data_store.clone(),
            js_runner.clone(),
            bandwidth_cache_service.clone(),
            resource_service.clone(),
            Some(metrics.clone()),
        );
        let challenge_service = ChallengeService::new(
            data_store.clone(),
            js_runner.clone(),
            shared_config.clone(),
            session_service.clone(),
        );

        let version_file_service = VersionFileService::new(
            shared_config.clone(),
            data_store.clone(),
            resource_service.clone(),
            Some(metrics.clone()),
        );
        let app_context = AppContext::new(
            session_service.clone(),
            resource_service.clone(),
            flow_service.clone(),
            challenge_service.clone(),
            bandwidth_cache_service.clone(),
            js_runner.clone(),
            metrics,
            shared_config.clone(),
            data_store.clone(),
            version_file_service,
        );

        Self {
            data_store,
            shared_config: shared_config.clone(),
            js_runner: js_runner.clone(),
            services: TestServices {
                session_service,
                flow_service,
                resource_service,
                challenge_service,
            },
            app_context,
            mock_data_store, // 存储MockDataStore引用
        }
    }
}

type NestedCdnRecords = HashMap<String, HashMap<String, Vec<CdnRecord>>>;
type ExpiringValue = (String, Option<u64>);

/// Mock数据存储实现
pub struct MockDataStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    challenges: Arc<RwLock<HashMap<String, String>>>,
    cdn_records: Arc<RwLock<NestedCdnRecords>>,
    download_counts: Arc<RwLock<HashMap<String, u32>>>,
    js_storage: Arc<RwLock<HashMap<String, ExpiringValue>>>,
    health_info: Arc<RwLock<HashMap<String, HealthInfo>>>,
    cache_metadata: Arc<RwLock<HashMap<String, CacheMetadata>>>,
    cache_content: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    string_storage: Arc<RwLock<HashMap<String, ExpiringValue>>>,
    bandwidth_stats: Arc<RwLock<HashMap<String, u64>>>,
    // 分钟级流量统计存储：server_id -> (minute_timestamp -> bytes)
    minute_bandwidth: Arc<RwLock<HashMap<String, HashMap<u64, u64>>>>,
    // 时间注入机制（测试专用）
    current_time_override: Arc<RwLock<Option<u64>>>, // 注入的当前分钟时间戳
    pub scan_calls: std::sync::atomic::AtomicUsize,
}

impl MockDataStore {
    pub fn new() -> Self {
        let mut health_info = HashMap::new();
        let healthy = HealthInfo {
            is_alive: true,
            file_size: Some(1024),
            last_check: chrono::Utc::now().timestamp() as u64,
            observed_cert_hash: None,
            content_hash: None,
        };

        // 为各种测试资源路径预设健康信息
        health_info.insert("test_server_1:/test/file.bin".to_string(), healthy.clone());
        health_info.insert("test_server_2:/test/file.bin".to_string(), healthy.clone());
        health_info.insert("test_server_1:/md5/file.bin".to_string(), healthy.clone());
        health_info.insert(
            "test_server_1:/sha256/file.bin".to_string(),
            healthy.clone(),
        );
        health_info.insert("test_server_1:/web/file.bin".to_string(), healthy.clone());
        health_info.insert(
            "test_server_1:/game/v3/textures/player.png".to_string(),
            healthy.clone(),
        );
        health_info.insert(
            "test_server_1:/free/v1/a/one.bin".to_string(),
            healthy.clone(),
        );
        health_info.insert(
            "test_server_2:/free/v1/a/one.bin".to_string(),
            healthy.clone(),
        );
        health_info.insert(
            "test_server_1:/free/v1/b/two.bin".to_string(),
            healthy.clone(),
        );
        health_info.insert(
            "test_server_2:/free/v1/b/two.bin".to_string(),
            healthy.clone(),
        );

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            cdn_records: Arc::new(RwLock::new(HashMap::new())),
            download_counts: Arc::new(RwLock::new(HashMap::new())),
            js_storage: Arc::new(RwLock::new(HashMap::new())),
            health_info: Arc::new(RwLock::new(health_info)),
            cache_metadata: Arc::new(RwLock::new(HashMap::new())),
            cache_content: Arc::new(RwLock::new(HashMap::new())),
            string_storage: Arc::new(RwLock::new(HashMap::new())),
            bandwidth_stats: Arc::new(RwLock::new(HashMap::new())),
            minute_bandwidth: Arc::new(RwLock::new(HashMap::new())),
            current_time_override: Arc::new(RwLock::new(None)),
            scan_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// 获取当前时间戳
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// 检查值是否过期
    fn is_expired(expires_at: Option<u64>) -> bool {
        if let Some(expires) = expires_at {
            Self::current_timestamp() > expires
        } else {
            false
        }
    }

    /// 获取当前分钟时间戳（支持时间注入）
    async fn get_current_minute(&self) -> u64 {
        let override_time = self.current_time_override.read().await;
        if let Some(injected_time) = *override_time {
            injected_time
        } else {
            // 使用真实时间
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 60
        }
    }

    /// 设置Mock的当前时间（测试用）
    pub async fn set_current_time(&self, minute_timestamp: Option<u64>) {
        let mut override_time = self.current_time_override.write().await;
        *override_time = minute_timestamp;
    }

    /// 版本键是否带过期时间。键不存在时返回 `None`。
    pub async fn string_has_expiry(&self, key: &str) -> Option<bool> {
        self.string_storage
            .read()
            .await
            .get(key)
            .map(|(_, expires_at)| expires_at.is_some())
    }

    /// 写入一张已过期的 override 票，供认领失败测试使用。
    pub async fn seed_expired_override_ticket(&self, uuid: &str, csv: &str) {
        let mut storage = self.string_storage.write().await;
        storage.insert(format!("override:{uuid}"), (csv.to_string(), Some(1)));
    }

    /// 写入一张 override 票。生产由管理员 `SET`，测试走这条。
    pub async fn seed_override_ticket(
        &self,
        uuid: &str,
        csv: &str,
        expires: Option<u32>,
    ) -> Result<(), String> {
        self.set_string(&format!("override:{uuid}"), csv, expires)
            .await
    }
}

#[async_trait::async_trait]
impl DataStoreBackend for MockDataStore {
    async fn store_session(&self, sid: &str, session: &Session) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(sid.to_string(), session.clone());
        Ok(())
    }

    async fn get_session(&self, sid: &str) -> Result<Option<Session>, String> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(sid).cloned())
    }

    async fn remove_session(&self, sid: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(sid);
        // 同时清理相关的CDN记录和下载计数
        let mut cdn_records = self.cdn_records.write().await;
        cdn_records.remove(sid);
        Ok(())
    }

    async fn increment_download_count(
        &self,
        sid: &str,
        chunk: &str,
    ) -> Result<Option<u32>, String> {
        if self.get_session(sid).await?.is_none() {
            return Ok(None);
        }
        let key = format!("{}:{}", sid, chunk);
        let mut counts = self.download_counts.write().await;
        let current = counts.get(&key).copied().unwrap_or(0);
        let new_count = current + 1;
        counts.insert(key, new_count);
        Ok(Some(new_count))
    }

    async fn refresh_session(&self, _sid: &str) -> Result<(), String> {
        // Mock实现中不需要实际刷新
        Ok(())
    }

    async fn get_download_counts(&self, sid: &str) -> Result<HashMap<String, u32>, String> {
        let counts = self.download_counts.read().await;
        let prefix = format!("{}:", sid);
        let result = counts
            .iter()
            .filter_map(|(k, v)| {
                if k.starts_with(&prefix) {
                    k.strip_prefix(&prefix).map(|chunk| (chunk.to_string(), *v))
                } else {
                    None
                }
            })
            .collect();
        Ok(result)
    }

    async fn update_cdn_record_v2(
        &self,
        sid: &str,
        chunk: &str,
        record: CdnRecord,
    ) -> Result<(), String> {
        let mut cdn_records = self.cdn_records.write().await;
        let session_records = cdn_records.entry(sid.to_string()).or_default();
        let chunk_records = session_records.entry(chunk.to_string()).or_default();
        chunk_records.push(record);
        Ok(())
    }

    async fn get_cdn_records(&self, sid: &str, chunk: &str) -> Result<Vec<CdnRecord>, String> {
        let cdn_records = self.cdn_records.read().await;
        if let Some(session_records) = cdn_records.get(sid)
            && let Some(chunk_records) = session_records.get(chunk)
        {
            return Ok(chunk_records.clone());
        }
        Ok(Vec::new())
    }

    async fn get_session_stats(&self, sid: &str) -> Result<Option<SessionStats>, String> {
        let session = match self.get_session(sid).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        let download_counts = self.get_download_counts(sid).await?;

        let cdn_records = self.cdn_records.read().await;
        let session_cdn_records = cdn_records.get(sid).cloned().unwrap_or_default();

        Ok(Some(SessionStats {
            resource_id: session.resource_id,
            version: session.version,
            chunks: session.chunks,
            download_counts,
            cdn_records: session_cdn_records,
            created_at: session.created_at,
        }))
    }

    async fn read_js_storage(&self, key: String) -> Option<String> {
        let storage = self.js_storage.read().await;
        if let Some((value, expires_at)) = storage.get(&key) {
            if !Self::is_expired(*expires_at) {
                Some(value.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    async fn write_js_storage(&self, key: String, value: String, expires: u32) -> bool {
        let mut storage = self.js_storage.write().await;
        let expires_at = Some(Self::current_timestamp() + expires as u64);
        storage.insert(key, (value, expires_at));
        true
    }

    async fn get_cached_metadata(&self, _key: &str) -> Result<Option<String>, String> {
        // Mock实现：这里简化为返回空
        Ok(None)
    }

    async fn set_cached_metadata(
        &self,
        _key: &str,
        _value: &str,
        _expires: u32,
    ) -> Result<(), String> {
        // Mock实现：这里不做实际存储
        Ok(())
    }

    async fn get_string(&self, key: &str) -> Result<Option<String>, String> {
        let storage = self.string_storage.read().await;
        if let Some((value, expires_at)) = storage.get(key) {
            if !Self::is_expired(*expires_at) {
                Ok(Some(value.clone()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn set_string(&self, key: &str, value: &str, expires: Option<u32>) -> Result<(), String> {
        let mut storage = self.string_storage.write().await;
        let expires_at = expires.map(|e| Self::current_timestamp() + e as u64);
        storage.insert(key.to_string(), (value.to_string(), expires_at));
        Ok(())
    }

    async fn take_string(&self, key: &str) -> Result<Option<String>, String> {
        let mut storage = self.string_storage.write().await;
        Ok(storage
            .remove(key)
            .filter(|(_, expires_at)| !Self::is_expired(*expires_at))
            .map(|(value, _)| value))
    }

    async fn incr_fixed_window(&self, key: &str, window: u32) -> Result<u64, String> {
        let mut storage = self.string_storage.write().await;
        let (next, expires_at) = match storage.get(key) {
            Some((value, expires_at)) if !Self::is_expired(*expires_at) => (
                value.parse::<u64>().unwrap_or(0).saturating_add(1),
                *expires_at,
            ),
            _ => (1, Some(Self::current_timestamp() + window as u64)),
        };
        storage.insert(key.to_string(), (next.to_string(), expires_at));
        Ok(next)
    }

    async fn get_override_ticket(
        &self,
        uuid: &str,
    ) -> Result<Option<(String, Option<u32>)>, String> {
        let key = format!("override:{uuid}");
        let storage = self.string_storage.read().await;
        match storage.get(&key) {
            Some((value, expires_at)) if !Self::is_expired(*expires_at) => {
                let remaining =
                    expires_at.map(|at| at.saturating_sub(Self::current_timestamp()) as u32);
                Ok(Some((value.clone(), remaining)))
            }
            _ => Ok(None),
        }
    }

    async fn get_override_binding(&self, bind_suffix: &str) -> Result<Option<String>, String> {
        self.get_string(&format!("override:bind:{bind_suffix}"))
            .await
    }

    async fn set_override_binding(
        &self,
        bind_suffix: &str,
        json: &str,
        expires: u32,
    ) -> Result<(), String> {
        self.set_string(&format!("override:bind:{bind_suffix}"), json, Some(expires))
            .await
    }

    async fn get_health_info(
        &self,
        server_id: &str,
        path: &str,
    ) -> Result<Option<HealthInfo>, String> {
        let key = format!("{}:{}", server_id, path);
        let health = self.health_info.read().await;
        Ok(health.get(&key).cloned())
    }

    async fn set_health_info(
        &self,
        server_id: &str,
        path: &str,
        info: &HealthInfo,
    ) -> Result<(), String> {
        let key = format!("{}:{}", server_id, path);
        let mut health = self.health_info.write().await;
        health.insert(key, info.clone());
        Ok(())
    }

    async fn scan_expired_sessions(
        &self,
        _timeout_seconds: u64,
    ) -> Result<Vec<(String, String, std::net::IpAddr)>, String> {
        self.scan_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Vec::new())
    }

    async fn batch_check_and_increment_downloads(
        &self,
        _sid: &str,
        chunks: &[String],
    ) -> Result<crate::models::BatchChunkData, String> {
        // 模拟实现：大部分chunks有效，少数无效（用于测试混合场景）
        let mut valid_chunks = std::collections::HashMap::new();
        let mut invalid_chunks = Vec::new();

        for chunk in chunks {
            // 模拟逻辑：包含"invalid"的chunk被认为无效
            if chunk.contains("invalid") {
                invalid_chunks.push(chunk.clone());
            } else {
                valid_chunks.insert(chunk.clone(), 1);
            }
        }

        // 模拟一些CDN记录
        let mut cdn_records = std::collections::HashMap::new();
        if let Some(first_chunk) = chunks.first()
            && !first_chunk.contains("invalid")
        {
            cdn_records.insert(
                first_chunk.clone(),
                vec![crate::models::CdnRecord {
                    url: "https://mock-cdn.com/file".to_string(),
                    server_id: Some("mock-server".to_string()),
                    skip_penalty: false,
                    timestamp: 1234567890,
                    weight: 10,
                    size: Some(1024),
                }],
            );
        }

        Ok(crate::models::BatchChunkData {
            valid_chunks,
            invalid_chunks,
            cdn_records,
        })
    }

    async fn batch_write_cdn_and_bandwidth(
        &self,
        _sid: &str,
        _cdn_records: &[crate::modules::storage::data_store::BatchCdnRecord],
        _bandwidth_batch: &crate::modules::storage::data_store::MultiBandwidthUpdateBatch,
    ) -> Result<(), String> {
        // 模拟实现：总是成功
        Ok(())
    }

    async fn get_cache_metadata(&self, key: &str) -> Result<Option<CacheMetadata>, String> {
        let metadata = self.cache_metadata.read().await;
        Ok(metadata.get(key).cloned())
    }

    async fn get_cache_content(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let content = self.cache_content.read().await;
        Ok(content.get(key).cloned())
    }

    async fn set_cache_entry(
        &self,
        meta_key: &str,
        content_key: &str,
        metadata: &CacheMetadata,
        content: &[u8],
    ) -> Result<(), String> {
        let mut meta = self.cache_metadata.write().await;
        let mut cont = self.cache_content.write().await;
        meta.insert(meta_key.to_string(), metadata.clone());
        cont.insert(content_key.to_string(), content.to_vec());
        Ok(())
    }

    async fn store_challenge(&self, sid: &str, challenge_data: &str) -> Result<(), String> {
        let mut challenges = self.challenges.write().await;
        challenges.insert(sid.to_string(), challenge_data.to_string());
        Ok(())
    }

    async fn get_challenge(&self, sid: &str) -> Result<Option<String>, String> {
        let challenges = self.challenges.read().await;
        Ok(challenges.get(sid).cloned())
    }

    async fn remove_challenge(&self, sid: &str) -> Result<(), String> {
        let mut challenges = self.challenges.write().await;
        challenges.remove(sid);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        // Mock实现：从string_storage中删除
        let mut storage = self.string_storage.write().await;
        storage.remove(key);
        Ok(())
    }

    // 带宽统计相关Mock实现
    async fn update_server_daily_bandwidth(
        &self,
        server_id: &str,
        bytes: u64,
    ) -> Result<(), String> {
        let key = format!("server_bw:{}", server_id);
        let mut stats = self.bandwidth_stats.write().await;
        let current = stats.get(&key).copied().unwrap_or(0);
        stats.insert(key, current + bytes);
        Ok(())
    }

    async fn update_resource_daily_bandwidth(
        &self,
        resource_id: &str,
        bytes: u64,
    ) -> Result<(), String> {
        let key = format!("resource_bw:{}", resource_id);
        let mut stats = self.bandwidth_stats.write().await;
        let current = stats.get(&key).copied().unwrap_or(0);
        stats.insert(key, current + bytes);
        Ok(())
    }

    async fn update_global_daily_bandwidth(&self, bytes: u64) -> Result<(), String> {
        let key = "global_bw".to_string();
        let mut stats = self.bandwidth_stats.write().await;
        let current = stats.get(&key).copied().unwrap_or(0);
        stats.insert(key, current + bytes);
        Ok(())
    }

    async fn get_server_daily_bandwidth(&self, server_id: &str) -> Result<u64, String> {
        let key = format!("server_bw:{}", server_id);
        let stats = self.bandwidth_stats.read().await;
        Ok(stats.get(&key).copied().unwrap_or(0))
    }

    async fn get_resource_daily_bandwidth(&self, resource_id: &str) -> Result<u64, String> {
        let key = format!("resource_bw:{}", resource_id);
        let stats = self.bandwidth_stats.read().await;
        Ok(stats.get(&key).copied().unwrap_or(0))
    }

    async fn get_global_daily_bandwidth(&self) -> Result<u64, String> {
        let key = "global_bw";
        let stats = self.bandwidth_stats.read().await;
        Ok(stats.get(key).copied().unwrap_or(0))
    }

    async fn update_bandwidth_batch(&self, batch: BandwidthUpdateBatch) -> Result<(), String> {
        self.update_resource_daily_bandwidth(&batch.resource_id, batch.bytes)
            .await?;
        self.update_server_daily_bandwidth(&batch.server_id, batch.bytes)
            .await?;
        self.update_global_daily_bandwidth(batch.bytes).await?;
        Ok(())
    }

    // 分钟级带宽统计接口实现
    async fn update_server_minute_bandwidth_direct(
        &self,
        server_id: &str,
        minute_timestamp: u64,
        bytes: u64,
    ) -> Result<(), String> {
        if bytes == 0 {
            return Ok(());
        }
        let mut minute_data = self.minute_bandwidth.write().await;
        let server_data = minute_data.entry(server_id.to_string()).or_default();
        let entry = server_data.entry(minute_timestamp).or_insert(0);
        *entry = entry.saturating_add(bytes);
        Ok(())
    }

    async fn get_server_minutes_bandwidth_direct(
        &self,
        server_id: &str,
        minutes: u32,
    ) -> Result<u64, String> {
        let minutes = minutes.min(BANDWIDTH_MINUTE_RING_SIZE);
        let current_minute = self.get_current_minute().await;
        let minute_data = self.minute_bandwidth.read().await;
        let Some(data) = minute_data.get(server_id) else {
            return Ok(0);
        };

        let mut total_bytes = 0u64;
        for i in 0..minutes {
            let target_minute = current_minute.saturating_sub(i as u64);
            if let Some(&bytes) = data.get(&target_minute) {
                total_bytes = total_bytes.saturating_add(bytes);
            }
        }
        Ok(total_bytes)
    }
}

/// 创建默认的测试配置
pub fn create_default_test_config() -> AppConfig {
    use crate::config::{ChallengeConfig, DownloadPolicy, ResourceConfig, ServerConfig};
    use crate::modules::server::ServerImpl;

    let mut config = AppConfig {
        servers: HashMap::new(),
        resources: HashMap::new(),
        plugins: HashMap::new(),
        flows: HashMap::new(),
        debug_mode: true,
        challenge: ChallengeConfig::default(),
        plugin_code: HashMap::new(),
        server_impl: HashMap::new(),
        pruned_flow_server_refs: Vec::new(),
        config_yaml: String::new(),
        internal: crate::config::InternalConfig::default(),
    };

    // 添加测试用web challenge插件
    config.plugin_code.insert(
        "web_challenge_recaptcha".to_string(),
        r#"
        exports = async function(context, challengeData, options, extras) {
            if (context === "generate") {
                return {
                    url: "https://challenge.example.com/recaptcha/" + challengeData.sid,
                    challenge: "recaptcha_challenge_data"
                };
            } else if (context === "verify") {
                return {
                    success: challengeData.user_response === "correct_token"
                };
            }
            return {};
        };
        "#
        .to_string(),
    );

    config.plugin_code.insert(
        "web_challenge_math".to_string(),
        r#"
        exports = async function(context, challengeData, options, extras) {
            if (context === "generate") {
                return {
                    url: "https://challenge.example.com/math/" + challengeData.sid,
                    challenge: "math_challenge_data"
                };
            } else if (context === "verify") {
                return {
                    success: challengeData.user_response === "4"
                };
            }
            return {};
        };
        "#
        .to_string(),
    );

    // 添加一个会失败的web challenge插件（用于测试fallback）
    config.plugin_code.insert(
        "geetest".to_string(),
        r#"
        exports = async function(context, challengeData, options, extras) {
            // 这个插件故意抛出错误来测试fallback机制
            throw new Error("Plugin intentionally fails for testing");
        };
        "#
        .to_string(),
    );

    // 添加测试服务器
    config.servers.insert(
        "test_server_1".to_string(),
        ServerConfig {
            r#type: "direct".to_string(),
            url: "https://test1.example.com".to_string(),
            ..Default::default()
        },
    );

    config.servers.insert(
        "test_server_2".to_string(),
        ServerConfig {
            r#type: "direct".to_string(),
            url: "https://test2.example.com".to_string(),
            ..Default::default()
        },
    );

    // 添加测试资源
    let mut resource_config = ResourceConfig {
        latest: "1.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec![],
        server: vec![], // 已废弃，使用flow
        flow: vec![crate::modules::flow::config::FlowItem {
            insert: None,
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            tier: 0,
        }],
        challenge: None,
        download: DownloadPolicy::Enabled,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: None,
        version_provider: None,
        version_files: vec![],
        version_file_split_ttl: 300,
    };

    let mut version_map = HashMap::new();
    version_map.insert("default".to_string(), "/test/file.bin".to_string());
    resource_config
        .versions
        .insert("1.0.0".to_string(), version_map);

    config
        .resources
        .insert("test_resource".to_string(), resource_config);

    // 添加前缀资源 game_assets
    let mut prefix_resource_config = ResourceConfig {
        latest: "3.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec![],
        server: vec![], // 已废弃，使用flow
        flow: vec![crate::modules::flow::config::FlowItem {
            insert: None,
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            tier: 0,
        }],
        challenge: None,
        download: DownloadPolicy::Enabled,
        resource_type: "prefix".to_string(),
        cache_enabled: true,
        cache_subpaths: vec!["*.png".to_string(), "*.json".to_string()],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: None,
        version_provider: None,
        version_files: vec![],
        version_file_split_ttl: 300,
    };

    let mut prefix_version_map = HashMap::new();
    prefix_version_map.insert("default".to_string(), "/game/v3/".to_string());
    prefix_resource_config
        .versions
        .insert("3.0.0".to_string(), prefix_version_map);

    config
        .resources
        .insert("game_assets".to_string(), prefix_resource_config);

    // Free 前缀资源：sid 只做跨文件粘滞回退
    let mut free_prefix_config = ResourceConfig {
        latest: "1.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec![],
        server: vec![],
        flow: vec![crate::modules::flow::config::FlowItem {
            insert: None,
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![
                crate::modules::flow::config::FlowUse::Server {
                    id: "test_server_1".to_string(),
                    weight: 20,
                },
                crate::modules::flow::config::FlowUse::Server {
                    id: "test_server_2".to_string(),
                    weight: 10,
                },
            ],
            tier: 0,
        }],
        challenge: None,
        download: DownloadPolicy::Free,
        resource_type: "prefix".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: None,
        version_provider: None,
        version_files: vec![],
        version_file_split_ttl: 300,
    };
    let mut free_prefix_versions = HashMap::new();
    free_prefix_versions.insert("default".to_string(), "/free/v1/".to_string());
    free_prefix_config
        .versions
        .insert("1.0.0".to_string(), free_prefix_versions);
    config
        .resources
        .insert("free_assets".to_string(), free_prefix_config);

    let mut free_other_config = ResourceConfig {
        latest: "1.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec![],
        server: vec![],
        flow: vec![crate::modules::flow::config::FlowItem {
            insert: None,
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            tier: 0,
        }],
        challenge: None,
        download: DownloadPolicy::Free,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: None,
        version_provider: None,
        version_files: vec![],
        version_file_split_ttl: 300,
    };
    let mut free_other_versions = HashMap::new();
    free_other_versions.insert("default".to_string(), "/test/file.bin".to_string());
    free_other_config
        .versions
        .insert("1.0.0".to_string(), free_other_versions);
    config
        .resources
        .insert("free_other".to_string(), free_other_config);

    // 添加MD5挑战资源
    let mut md5_resource_config = ResourceConfig {
        latest: "1.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec![],
        server: vec![], // 已废弃，使用flow
        flow: vec![crate::modules::flow::config::FlowItem {
            insert: None,
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            tier: 0,
        }],
        challenge: Some(crate::config::ChallengeConfig {
            challenge_type: "md5".to_string(),
            sha256_difficulty: 2,
            web_plugin: "math".to_string(),
            type_weights: None,
        }),
        download: DownloadPolicy::Enabled,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: None,
        version_provider: None,
        version_files: vec![],
        version_file_split_ttl: 300,
    };

    let mut md5_version_map = HashMap::new();
    md5_version_map.insert("default".to_string(), "/md5/file.bin".to_string());
    md5_resource_config
        .versions
        .insert("1.0.0".to_string(), md5_version_map);
    config
        .resources
        .insert("md5_resource".to_string(), md5_resource_config);

    // 添加SHA256挑战资源
    let mut sha256_resource_config = ResourceConfig {
        latest: "1.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec![],
        server: vec![], // 已废弃，使用flow
        flow: vec![crate::modules::flow::config::FlowItem {
            insert: None,
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            tier: 0,
        }],
        challenge: Some(crate::config::ChallengeConfig {
            challenge_type: "sha256".to_string(),
            sha256_difficulty: 3,
            web_plugin: "math".to_string(),
            type_weights: None,
        }),
        download: DownloadPolicy::Enabled,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: None,
        version_provider: None,
        version_files: vec![],
        version_file_split_ttl: 300,
    };

    let mut sha256_version_map = HashMap::new();
    sha256_version_map.insert("default".to_string(), "/sha256/file.bin".to_string());
    sha256_resource_config
        .versions
        .insert("1.0.0".to_string(), sha256_version_map);
    config
        .resources
        .insert("sha256_resource".to_string(), sha256_resource_config);

    // 添加Web挑战资源
    let mut web_resource_config = ResourceConfig {
        latest: "1.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec![],
        server: vec![], // 已废弃，使用flow
        flow: vec![crate::modules::flow::config::FlowItem {
            insert: None,
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            tier: 0,
        }],
        challenge: Some(crate::config::ChallengeConfig {
            challenge_type: "web".to_string(),
            sha256_difficulty: 2,
            web_plugin: "web_challenge_recaptcha".to_string(),
            type_weights: None,
        }),
        download: DownloadPolicy::Enabled,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: None,
        version_provider: None,
        version_files: vec![],
        version_file_split_ttl: 300,
    };

    let mut web_version_map = HashMap::new();
    web_version_map.insert("default".to_string(), "/web/file.bin".to_string());
    web_resource_config
        .versions
        .insert("1.0.0".to_string(), web_version_map);
    config
        .resources
        .insert("web_resource".to_string(), web_resource_config);

    // 添加test_resource - 用于版本刷新测试，带有版本提供程序
    let mut test_resource_config = ResourceConfig {
        latest: "1.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec![],
        server: vec![], // 已废弃，使用flow
        flow: vec![crate::modules::flow::config::FlowItem {
            insert: None,
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            tier: 0,
        }],
        challenge: Some(crate::config::ChallengeConfig {
            challenge_type: "md5".to_string(),
            sha256_difficulty: 2,
            web_plugin: "math".to_string(),
            type_weights: None,
        }),
        download: DownloadPolicy::Enabled,
        resource_type: "file".to_string(),
        cache_enabled: false,
        cache_subpaths: vec![],
        cache_max_age: 300,
        legacy_client_support: false,
        legacy_client_full_range: false,
        changelog: Some("Test changelog for test_resource".to_string()),
        version_provider: Some(crate::config::VersionProviderConfig {
            r#type: "plugin".to_string(),
            plugin_name: "version_provider_test".to_string(),
            cache_ttl: Some(300),
            webhook_token: Some("webhook_secret_123".to_string()),
            options: serde_json::json!({
                "repo": "test/test-repo",
                "include_prerelease": false
            }),
        }),
        version_files: vec![],
        version_file_split_ttl: 300,
    };

    let mut test_version_map = HashMap::new();
    test_version_map.insert("default".to_string(), "/test/file.bin".to_string());
    test_resource_config
        .versions
        .insert("1.0.0".to_string(), test_version_map);
    config
        .resources
        .insert("test_resource".to_string(), test_resource_config);

    // 添加version_provider_test插件代码
    config.plugin_code.insert(
        "version_provider_test".to_string(),
        r#"
        exports = async function(options, resourceId, extras) {
            // 模拟版本提供程序返回最新版本
            return {
                version: "1.1.0",
                changelog: "Updated to version 1.1.0 - Test update",
                metadata: {
                    updated_at: new Date().toISOString(),
                    test: true
                }
            };
        };
        "#
        .to_string(),
    );

    // 创建ServerImpl实例（模拟配置加载时的转换过程）
    let mut server_impl = HashMap::new();
    for (id, server_config) in config.servers.iter() {
        if let Ok(server) = ServerImpl::new(server_config) {
            server_impl.insert(id.clone(), server);
        }
    }
    config.server_impl = server_impl;

    config
}
