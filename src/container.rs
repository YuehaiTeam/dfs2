use arc_swap::Guard;

use crate::{
    config::AppConfig,
    config::SharedConfig,
    error::DfsResult,
    metrics::Metrics,
    modules::storage::data_store::{DataStore, create_data_store},
    modules::{qjs::JsRunner, version_provider::{VersionCache, VersionUpdater, PluginVersionProvider}},
    services::{ChallengeService, FlowService, ResourceService, SessionService},
};

use std::sync::Arc;

lazy_static::lazy_static! {
    pub static ref MAX_CHUNK_DOWNLOADS: u32 = std::env::var("MAX_CHUNK_DOWNLOADS")
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
        .map_err(|e| {
            // Use panic here since this is a startup critical error
            panic!("Failed to build reqwest client: {}", e);
        })
        .unwrap();
}

#[derive(Clone)]
pub struct AppContext {
    pub session_service: SessionService,
    pub resource_service: ResourceService,
    pub flow_service: FlowService,
    pub challenge_service: ChallengeService,
    pub js_runner: JsRunner,
    pub metrics: Arc<Metrics>,
    pub shared_config: SharedConfig,
    pub data_store: DataStore,
}

impl AppContext {
    pub fn new(
        session_service: SessionService,
        resource_service: ResourceService,
        flow_service: FlowService,
        challenge_service: ChallengeService,
        js_runner: JsRunner,
        metrics: Arc<Metrics>,
        shared_config: SharedConfig,
        data_store: DataStore,
    ) -> Self {
        Self {
            session_service,
            resource_service,
            flow_service,
            challenge_service,
            js_runner,
            metrics,
            shared_config,
            data_store,
        }
    }

    /// 无锁获取配置
    pub fn get_config(&self) -> Guard<Arc<AppConfig>> {
        self.shared_config.load()
    }

    /// 热重载配置
    pub fn reload_config(&self, new_config: AppConfig) {
        self.shared_config.reload(new_config);
    }
}

pub struct AppContainer {
    pub data_store: DataStore,
    pub shared_config: SharedConfig,
    pub js_runner: JsRunner,
    pub metrics: Arc<Metrics>,
    pub version_cache: Arc<VersionCache>,
    pub version_updater: Arc<VersionUpdater>,
}

impl AppContainer {
    pub async fn new() -> DfsResult<Self> {
        // 1. 加载配置并创建共享配置
        let initial_config = AppConfig::load().await?;
        let shared_config = SharedConfig::new(initial_config);

        // 2. 初始化存储
        let data_store = create_data_store().await?;

        // 3. 初始化其他组件
        let js_runner = JsRunner::new(shared_config.clone(), data_store.clone()).await;
        let metrics = Arc::new(Metrics::new(shared_config.clone())?);
        let version_cache = Arc::new(VersionCache::new(data_store.clone()));
        let plugin_provider = Arc::new(PluginVersionProvider::new(js_runner.clone(), shared_config.clone()));
        let version_updater = Arc::new(VersionUpdater::new(shared_config.clone(), version_cache.clone(), plugin_provider));

        Ok(Self {
            data_store,
            shared_config,
            js_runner,
            metrics,
            version_cache,
            version_updater,
        })
    }

    pub fn create_app_context(&self) -> AppContext {
        let session_service = SessionService::new(self.data_store.clone());
        let resource_service =
            ResourceService::new(
                self.shared_config.clone(), 
                self.version_cache.clone(),
                self.version_updater.clone()
            );
        let flow_service = FlowService::new(
            self.shared_config.clone(),
            self.data_store.clone(),
            self.js_runner.clone(),
        );
        let challenge_service = ChallengeService::new(
            self.data_store.clone(),
            self.js_runner.clone(),
            self.shared_config.clone(),
            session_service.clone(),
        );

        AppContext::new(
            session_service,
            resource_service,
            flow_service,
            challenge_service,
            self.js_runner.clone(),
            self.metrics.clone(),
            self.shared_config.clone(),
            self.data_store.clone(),
        )
    }
}
