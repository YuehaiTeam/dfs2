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
    BandwidthUpdateBatch, CacheMetadata, DataStoreBackend, RingBufferMeta, SessionStats,
};
use crate::modules::version_provider::{PluginVersionProvider, VersionCache, VersionUpdater};
use crate::services::{
    BandwidthCacheService, ChallengeService, FlowService, ResourceService, SessionService,
};

/// 统一的测试环境，包含所有必要的服务和Mock
pub struct TestEnvironment {
    pub data_store: crate::modules::storage::data_store::DataStore,
    pub shared_config: SharedConfig,
    pub js_runner: JsRunner,
    pub services: TestServices,
    pub app_context: AppContext,             // 添加app_context字段
    pub mock_data_store: Arc<MockDataStore>, // 直接存储MockDataStore引用
}

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

    /// 设置Mock的当前时间（测试用）
    pub async fn set_mock_current_time(&self, minute_timestamp: Option<u64>) {
        // 直接使用存储的MockDataStore引用
        self.mock_data_store
            .set_current_time(minute_timestamp)
            .await;
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
        let flow_service = FlowService::new(
            shared_config.clone(),
            data_store.clone(),
            js_runner.clone(),
            bandwidth_cache_service.clone(),
            resource_service.clone(),
        );
        let challenge_service = ChallengeService::new(
            data_store.clone(),
            js_runner.clone(),
            shared_config.clone(),
            session_service.clone(),
        );

        // 创建AppContext
        let metrics = Arc::new(Metrics::new(shared_config.clone()).unwrap());
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

/// Mock数据存储实现
pub struct MockDataStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    challenges: Arc<RwLock<HashMap<String, String>>>,
    cdn_records: Arc<RwLock<HashMap<String, HashMap<String, Vec<CdnRecord>>>>>,
    download_counts: Arc<RwLock<HashMap<String, u32>>>,
    js_storage: Arc<RwLock<HashMap<String, (String, Option<u64>)>>>, // (value, expires_at)
    health_info: Arc<RwLock<HashMap<String, HealthInfo>>>,
    cache_metadata: Arc<RwLock<HashMap<String, CacheMetadata>>>,
    cache_content: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    string_storage: Arc<RwLock<HashMap<String, (String, Option<u64>)>>>,
    bandwidth_stats: Arc<RwLock<HashMap<String, u64>>>,
    // 分钟级流量统计存储
    minute_bandwidth: Arc<RwLock<HashMap<String, HashMap<u32, u64>>>>, // server_id -> (minute_index -> bytes)
    ring_meta: Arc<RwLock<HashMap<String, RingBufferMeta>>>,           // ring_key -> meta
    // 时间注入机制（测试专用）
    current_time_override: Arc<RwLock<Option<u64>>>, // 注入的当前分钟时间戳
}

impl MockDataStore {
    pub fn new() -> Self {
        let mut health_info = HashMap::new();
        let healthy = HealthInfo {
            is_alive: true,
            file_size: Some(1024),
            last_check: chrono::Utc::now().timestamp() as u64,
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
            ring_meta: Arc::new(RwLock::new(HashMap::new())),
            current_time_override: Arc::new(RwLock::new(None)),
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
        if let Some(session_records) = cdn_records.get(sid) {
            if let Some(chunk_records) = session_records.get(chunk) {
                return Ok(chunk_records.clone());
            }
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

    async fn get_cached_metadata(&self, key: &str) -> Result<Option<String>, String> {
        // Mock实现：这里简化为返回空
        Ok(None)
    }

    async fn set_cached_metadata(
        &self,
        key: &str,
        value: &str,
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
        timeout_seconds: u64,
    ) -> Result<Vec<(String, String, std::net::IpAddr)>, String> {
        // Mock实现：返回空列表
        Ok(Vec::new())
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
        println!(
            "[Mock] update_server_minute_bandwidth_direct: server={}, minute={}, bytes={}",
            server_id, minute_timestamp, bytes
        );

        let ring_key = format!("server_bw_ring:{}", server_id);

        // 获取或创建环形缓冲区元数据
        let ring_size = 1440u32; // 24小时

        let mut meta_storage = self.ring_meta.write().await;
        let is_new = !meta_storage.contains_key(&ring_key);
        let meta = meta_storage.entry(ring_key.clone()).or_insert_with(|| {
            println!(
                "[Mock] 创建新环形缓冲区: server={}, start_minute={}",
                server_id, minute_timestamp
            );
            RingBufferMeta {
                start_minute: minute_timestamp, // 使用第一次写入的时间戳作为起始时间
                head_index: 0,
                ring_size,
            }
        });

        if !is_new {
            println!(
                "[Mock] 使用现有环形缓冲区: server={}, start_minute={}, head_index={}",
                server_id, meta.start_minute, meta.head_index
            );
        }

        // 计算物理索引
        if let Some(physical_index) = meta.get_physical_index(minute_timestamp) {
            println!(
                "[Mock] 物理索引计算成功: minute={}, physical_index={}",
                minute_timestamp, physical_index
            );
            let mut minute_data = self.minute_bandwidth.write().await;
            let server_data = minute_data
                .entry(server_id.to_string())
                .or_insert_with(HashMap::new);
            let current_bytes = server_data.get(&physical_index).copied().unwrap_or(0);
            server_data.insert(physical_index, current_bytes + bytes);
            println!(
                "[Mock] 更新数据: physical_index={}, old_bytes={}, new_bytes={}",
                physical_index,
                current_bytes,
                current_bytes + bytes
            );
        } else {
            println!(
                "[Mock] 物理索引计算失败: minute={}, meta.start_minute={}, ring_size={}",
                minute_timestamp, meta.start_minute, meta.ring_size
            );
        }

        Ok(())
    }

    async fn get_server_minutes_bandwidth_direct(
        &self,
        server_id: &str,
        minutes: u32,
    ) -> Result<u64, String> {
        let current_minute = self.get_current_minute().await; // 使用注入的时间
        println!(
            "[Mock] get_server_minutes_bandwidth_direct: server={}, minutes={}, current_minute={}",
            server_id, minutes, current_minute
        );

        let ring_key = format!("server_bw_ring:{}", server_id);

        // 获取环形缓冲区元数据
        let meta_storage = self.ring_meta.read().await;
        let meta = match meta_storage.get(&ring_key) {
            Some(m) => {
                println!(
                    "[Mock] 找到环形缓冲区元数据: start_minute={}, head_index={}, ring_size={}",
                    m.start_minute, m.head_index, m.ring_size
                );
                m.clone()
            }
            None => {
                println!("[Mock] 未找到环形缓冲区元数据: server={}", server_id);
                return Ok(0); // 没有数据
            }
        };

        let mut total_bytes = 0u64;
        let minute_data = self.minute_bandwidth.read().await;
        let server_data = minute_data.get(server_id);

        if let Some(data) = server_data {
            println!("[Mock] 找到服务器数据，包含 {} 个物理索引", data.len());
            // 计算需要查询的物理索引
            for i in 0..minutes {
                let target_minute = current_minute.saturating_sub(i as u64);
                if let Some(physical_index) = meta.get_physical_index(target_minute) {
                    if let Some(&bytes) = data.get(&physical_index) {
                        println!(
                            "[Mock] 查询命中: target_minute={}, physical_index={}, bytes={}",
                            target_minute, physical_index, bytes
                        );
                        total_bytes += bytes;
                    } else {
                        println!(
                            "[Mock] 查询未命中: target_minute={}, physical_index={}, 无数据",
                            target_minute, physical_index
                        );
                    }
                } else {
                    println!("[Mock] 物理索引计算失败: target_minute={}", target_minute);
                }
            }
        } else {
            println!("[Mock] 未找到服务器数据: server={}", server_id);
        }

        println!(
            "[Mock] 查询结果: server={}, total_bytes={}",
            server_id, total_bytes
        );
        Ok(total_bytes)
    }

    async fn get_ring_meta(&self, ring_key: &str) -> Result<Option<RingBufferMeta>, String> {
        let meta_storage = self.ring_meta.read().await;
        Ok(meta_storage.get(ring_key).cloned())
    }

    async fn hmget(&self, key: &str, fields: &[String]) -> Result<Vec<Option<String>>, String> {
        // Mock实现：简化为从minute_bandwidth中获取数据
        if key.starts_with("server_bw_ring:") {
            let server_id = key.strip_prefix("server_bw_ring:").unwrap_or("");
            let minute_data = self.minute_bandwidth.read().await;

            if let Some(server_data) = minute_data.get(server_id) {
                let mut results = Vec::new();
                for field in fields {
                    if let Ok(index) = field.parse::<u32>() {
                        let bytes = server_data.get(&index).copied().unwrap_or(0);
                        results.push(Some(bytes.to_string()));
                    } else {
                        results.push(None);
                    }
                }
                return Ok(results);
            }
        }

        // 默认返回空值
        Ok(vec![None; fields.len()])
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
        debug_mode: true,
        challenge: ChallengeConfig::default(),
        plugin_code: HashMap::new(),
        server_impl: HashMap::new(),
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
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            r#break: false,
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
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            r#break: false,
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
    };

    let mut prefix_version_map = HashMap::new();
    prefix_version_map.insert("default".to_string(), "/game/v3/".to_string());
    prefix_resource_config
        .versions
        .insert("3.0.0".to_string(), prefix_version_map);

    config
        .resources
        .insert("game_assets".to_string(), prefix_resource_config);

    // 添加MD5挑战资源
    let mut md5_resource_config = ResourceConfig {
        latest: "1.0.0".to_string(),
        versions: HashMap::new(),
        tries: vec![],
        server: vec![], // 已废弃，使用flow
        flow: vec![crate::modules::flow::config::FlowItem {
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            r#break: false,
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
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            r#break: false,
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
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            r#break: false,
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
            rules: vec![],
            mode: crate::modules::flow::config::FlowMode::AND,
            r#use: vec![crate::modules::flow::config::FlowUse::Server {
                id: "test_server_1".to_string(),
                weight: 10,
            }],
            r#break: false,
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
