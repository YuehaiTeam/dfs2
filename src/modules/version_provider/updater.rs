use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::AppConfig;
use super::{VersionCache, PluginVersionProvider};

/// 版本更新器 - 负责后台定时更新版本缓存
pub struct VersionUpdater {
    config: Arc<RwLock<AppConfig>>,
    version_cache: Arc<VersionCache>,
    plugin_provider: Arc<PluginVersionProvider>,
}

impl VersionUpdater {
    pub fn new(
        config: Arc<RwLock<AppConfig>>,
        version_cache: Arc<VersionCache>,
        plugin_provider: Arc<PluginVersionProvider>,
    ) -> Self {
        Self {
            config,
            version_cache,
            plugin_provider,
        }
    }
    
    /// 启动后台更新任务
    pub async fn start_background_task(self: Arc<Self>) {
        info!("Starting version updater background task");
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // 1分钟间隔
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            
            loop {
                interval.tick().await;
                
                match self.update_versions().await {
                    Ok(update_count) => {
                        if update_count > 0 {
                            debug!("Version update cycle completed, updated {} resources", update_count);
                        }
                    }
                    Err(e) => {
                        error!("Version update cycle failed: {}", e);
                    }
                }
            }
        });
    }
    
    /// 执行版本更新检查
    async fn update_versions(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.read().await;
        let mut update_count = 0;
        let mut resource_index = 0;
        
        // 收集需要检查的资源
        let resources_to_check: Vec<(String, u32)> = config.resources.iter()
            .filter_map(|(resource_id, resource)| {
                resource.version_provider.as_ref().map(|vp| {
                    (resource_id.clone(), vp.cache_ttl.unwrap_or(300))
                })
            })
            .collect();
        
        let total_resources = resources_to_check.len();
        if total_resources == 0 {
            return Ok(0);
        }
        
        debug!("Checking {} resources for version updates", total_resources);
        
        for (resource_id, cache_ttl) in resources_to_check {
            // 错开检查时间，避免所有资源同时请求API
            if resource_index > 0 {
                let stagger_delay = (resource_index * 1000) / total_resources; // 在1秒内分散
                if stagger_delay > 0 {
                    tokio::time::sleep(Duration::from_millis(stagger_delay as u64)).await;
                }
            }
            
            // 检查是否需要更新
            if self.version_cache.should_update(&resource_id, cache_ttl).await {
                match self.update_resource_version(&resource_id, cache_ttl).await {
                    Ok(true) => {
                        update_count += 1;
                        debug!("Successfully updated version for {}", resource_id);
                    }
                    Ok(false) => {
                        debug!("No update needed for {} (already current)", resource_id);
                    }
                    Err(e) => {
                        warn!("Failed to update version for {}: {}", resource_id, e);
                    }
                }
            } else {
                debug!("Skipping update for {} (cache still fresh)", resource_id);
            }
            
            resource_index += 1;
        }
        
        if update_count > 0 {
            info!("Version update cycle completed: {} resources updated out of {} checked", 
                  update_count, total_resources);
        }
        
        Ok(update_count)
    }
    
    /// 更新单个资源的版本
    async fn update_resource_version(
        &self, 
        resource_id: &str, 
        cache_ttl: u32
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        debug!("Updating version for resource: {}", resource_id);
        
        // 获取当前缓存的版本（如果有的话）
        let current_cached = self.version_cache.get_cached_version(resource_id).await;
        
        // 通过插件获取最新版本
        match self.plugin_provider.fetch_version_info(resource_id).await {
            Ok(version_info) => {
                let new_version = &version_info.version;
                
                // 检查版本是否实际发生了变化
                let version_changed = current_cached.as_ref()
                    .map(|cached| cached != new_version)
                    .unwrap_or(true); // 如果没有缓存，认为是变化了
                
                if version_changed {
                    info!("Version changed for {}: {} -> {}", 
                          resource_id,
                          current_cached.unwrap_or_else(|| "none".to_string()),
                          new_version);
                } else {
                    debug!("Version unchanged for {}: {}", resource_id, new_version);
                }
                
                // 更新缓存（无论版本是否变化，都要更新时间戳）
                if let Err(e) = self.version_cache.set_cached_version_info(
                    resource_id, 
                    &version_info, 
                    cache_ttl
                ).await {
                    error!("Failed to cache version for {}: {}", resource_id, e);
                    return Err(e.into());
                }
                
                // 标记更新时间
                if let Err(e) = self.version_cache.mark_updated(resource_id).await {
                    warn!("Failed to mark update time for {}: {}", resource_id, e);
                }
                
                Ok(version_changed)
            }
            Err(e) => {
                error!("Failed to fetch version for {}: {}", resource_id, e);
                Err(e.into())
            }
        }
    }
    
    /// 立即更新指定资源的版本（用于webhook触发）
    pub async fn update_resource_immediately(&self, resource_id: &str) -> crate::error::DfsResult<String> {
        info!("Immediate version update requested for: {}", resource_id);
        
        // 获取资源配置
        let config = self.config.read().await;
        let resource = config.get_resource(resource_id)
            .ok_or_else(|| crate::error::DfsError::resource_not_found(resource_id))?;
        
        let version_provider = resource.version_provider.as_ref()
            .ok_or_else(|| crate::error::DfsError::invalid_input(
                "version_provider",
                "Resource does not have version provider configured".to_string()
            ))?;
        
        let cache_ttl = version_provider.cache_ttl.unwrap_or(300);
        
        // 获取最新版本
        let version_info = self.plugin_provider.fetch_version_info(resource_id).await?;
        
        // 更新缓存
        self.version_cache.set_cached_version_info(
            resource_id, 
            &version_info, 
            cache_ttl
        ).await?;
        
        // 标记更新时间
        self.version_cache.mark_updated(resource_id).await?;
        
        info!("Immediately updated version for {}: {}", resource_id, version_info.version);
        Ok(version_info.version)
    }
    
    /// 获取版本更新统计信息
    pub async fn get_update_stats(&self) -> UpdateStats {
        let config = self.config.read().await;
        let total_resources = config.resources.len();
        let resources_with_providers = config.resources.iter()
            .filter(|(_, resource)| resource.version_provider.is_some())
            .count();
        
        UpdateStats {
            total_resources,
            resources_with_providers,
            last_update_cycle: std::time::SystemTime::now(), // 这里应该记录实际的最后更新时间
        }
    }
}

/// 版本更新统计信息
#[derive(Debug, Clone)]
pub struct UpdateStats {
    pub total_resources: usize,
    pub resources_with_providers: usize,
    pub last_update_cycle: std::time::SystemTime,
}

/// 初始化版本缓存
pub async fn initialize_version_system(
    config: &AppConfig,
    version_cache: Arc<VersionCache>,
    plugin_provider: Arc<PluginVersionProvider>,
) -> crate::error::DfsResult<usize> {
    let mut init_count = 0;
    
    info!("Initializing version system...");
    
    for (resource_id, resource) in &config.resources {
        if let Some(version_provider) = &resource.version_provider {
            // 检查缓存是否已存在
            if version_cache.get_cached_version(resource_id).await.is_none() {
                let cache_ttl = version_provider.cache_ttl.unwrap_or(300);
                
                // 使用latest字段作为初始缓存
                if let Err(e) = version_cache.set_cached_version(
                    resource_id, 
                    &resource.latest, 
                    cache_ttl
                ).await {
                    error!("Failed to set initial cache for {}: {}", resource_id, e);
                    continue;
                }
                
                info!("Set initial version cache for {}: {}", resource_id, resource.latest);
                
                // 异步触发首次版本检查
                let resource_id = resource_id.clone();
                let plugin_provider = plugin_provider.clone();
                let version_cache = version_cache.clone();
                tokio::spawn(async move {
                    match plugin_provider.fetch_version_info(&resource_id).await {
                        Ok(version_info) => {
                            if let Err(e) = version_cache.set_cached_version_info(
                                &resource_id, 
                                &version_info, 
                                cache_ttl
                            ).await {
                                error!("Failed to initialize version cache for {}: {}", resource_id, e);
                            } else {
                                info!("Initialized version for {}: {}", resource_id, version_info.version);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to fetch initial version for {}: {}", resource_id, e);
                        }
                    }
                });
                
                init_count += 1;
            }
        }
    }
    
    info!("Version system initialized for {} resources", init_count);
    Ok(init_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::config::{ResourceConfig, VersionProviderConfig};
    use crate::config::DownloadPolicy;
    use crate::app_state::create_data_store;
    
    async fn create_test_updater() -> (Arc<VersionUpdater>, Arc<RwLock<AppConfig>>) {
        let mut resources = HashMap::new();
        
        resources.insert(
            "test_resource".to_string(),
            ResourceConfig {
                latest: "1.0.0".to_string(),
                versions: HashMap::new(),
                tries: vec![],
                server: vec![],
                flow: vec![],
                challenge: None,
                download: DownloadPolicy::Disabled,
                resource_type: "file".to_string(),
                cache_enabled: false,
                cache_subpaths: vec![],
                cache_max_age: 300,
                legacy_client_support: false,
                legacy_client_full_range: false,
                version_provider: Some(VersionProviderConfig {
                    r#type: "plugin".to_string(),
                    plugin_name: "version_provider_test".to_string(),
                    cache_ttl: Some(300),
                    webhook_token: Some("test_token".to_string()),
                    options: serde_json::json!({}),
                }),
            },
        );
        
        let config = Arc::new(RwLock::new(AppConfig {
            servers: HashMap::new(),
            resources,
            plugins: HashMap::new(),
            debug_mode: true,
            challenge: crate::config::ChallengeConfig::default(),
            plugin_code: HashMap::new(),
            server_impl: HashMap::new(),
        }));
        
        let data_store = create_data_store().await.expect("Failed to create data store");
        let version_cache = Arc::new(VersionCache::new(data_store));
        
        // 注意：在实际测试中，需要一个真实的PluginVersionProvider
        // 这里使用占位符，实际测试需要完整的JsRunner支持
        let js_runner = Arc::new(
            crate::modules::qjs::JsRunner::new(config.clone(), version_cache.clone().redis.clone()).await
        );
        let plugin_provider = Arc::new(PluginVersionProvider::new(js_runner, config.clone()));
        
        let updater = Arc::new(VersionUpdater::new(
            config.clone(),
            version_cache,
            plugin_provider,
        ));
        
        (updater, config)
    }
    
    #[tokio::test]
    async fn test_update_stats() {
        let (updater, _config) = create_test_updater().await;
        
        let stats = updater.get_update_stats().await;
        assert_eq!(stats.total_resources, 1);
        assert_eq!(stats.resources_with_providers, 1);
    }
    
    #[tokio::test]
    async fn test_version_initialization() {
        // 测试版本系统初始化
        // 注意：这个测试需要完整的插件环境
    }
}