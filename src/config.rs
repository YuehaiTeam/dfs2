use arc_swap::{ArcSwap, Guard};
use rquickjs::IntoJs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};

use crate::modules::auth::challenge::ChallengeType;
use crate::modules::{flow::FlowItem, server::ServerImpl};

/// Challenge configuration for individual resources or global settings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeConfig {
    /// Challenge type: "md5", "sha256", "web", or "random"
    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,

    /// SHA256 challenge difficulty (1-4 bytes, only used for SHA256)
    #[serde(default = "default_sha256_difficulty")]
    pub sha256_difficulty: u8,

    /// Default web challenge plugin to use
    #[serde(default = "default_web_plugin")]
    pub web_plugin: String,

    /// Type weights for random selection (percentages)
    #[serde(default)]
    pub type_weights: Option<TypeWeights>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TypeWeights {
    #[serde(default = "default_md5_weight")]
    pub md5: u32,
    #[serde(default = "default_sha256_weight")]
    pub sha256: u32,
    #[serde(default = "default_web_weight")]
    pub web: u32,
}

// Default functions for challenge configuration
fn default_challenge_type() -> String {
    "md5".to_string()
}
fn default_sha256_difficulty() -> u8 {
    2
}
fn default_web_plugin() -> String {
    "web_challenge_recaptcha".to_string()
}
fn default_md5_weight() -> u32 {
    30
}
fn default_sha256_weight() -> u32 {
    50
}
fn default_web_weight() -> u32 {
    20
}
fn default_resource_type() -> String {
    "file".to_string()
}
fn default_cache_max_age() -> u32 {
    300
} // 5分钟

/// Version provider configuration for dynamic version fetching
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersionProviderConfig {
    /// Provider type: "plugin"
    pub r#type: String,

    /// Plugin name (must start with "version_provider_")
    pub plugin_name: String,

    /// Cache TTL in seconds (default: 300)
    #[serde(default)]
    pub cache_ttl: Option<u32>,

    /// Webhook token for manual refresh (optional)
    pub webhook_token: Option<String>,

    /// Provider-specific options
    #[serde(default)]
    pub options: serde_json::Value,
}

impl<'js> IntoJs<'js> for VersionProviderConfig {
    fn into_js(self, ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Value<'js>> {
        let obj = rquickjs::Object::new(ctx.clone())?;
        obj.set("type", self.r#type)?;
        obj.set("plugin_name", self.plugin_name)?;
        obj.set("cache_ttl", self.cache_ttl)?;
        obj.set("webhook_token", self.webhook_token.clone())?;
        obj.set("options", self.options.to_string())?; // 转换为字符串以便JS处理
        Ok(obj.into())
    }
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        ChallengeConfig {
            challenge_type: default_challenge_type(),
            sha256_difficulty: default_sha256_difficulty(),
            web_plugin: default_web_plugin(),
            type_weights: Some(TypeWeights {
                md5: default_md5_weight(),
                sha256: default_sha256_weight(),
                web: default_web_weight(),
            }),
        }
    }
}

/// Download policy for resources
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DownloadPolicy {
    /// Download disabled (default)
    Disabled,
    /// Download enabled with session validation
    Enabled,
    /// Download freely available without session
    Free,
}

impl Default for DownloadPolicy {
    fn default() -> Self {
        DownloadPolicy::Disabled
    }
}

impl ChallengeConfig {
    /// Get the actual challenge type to use, considering random selection
    pub fn get_effective_type(&self) -> ChallengeType {
        match self.challenge_type.as_str() {
            "md5" => ChallengeType::Md5,
            "sha256" => ChallengeType::Sha256,
            "web" => ChallengeType::Web,
            "random" => {
                // Use weights to randomly select type
                use rand::Rng;
                let mut rng = rand::rng();

                if let Some(ref weights) = self.type_weights {
                    let total = weights.md5 + weights.sha256 + weights.web;
                    if total == 0 {
                        return ChallengeType::Md5; // fallback
                    }

                    let choice = rng.random_range(0..total);
                    if choice < weights.md5 {
                        ChallengeType::Md5
                    } else if choice < weights.md5 + weights.sha256 {
                        ChallengeType::Sha256
                    } else {
                        ChallengeType::Web
                    }
                } else {
                    // No weights specified, use equal probability
                    let choice = rng.random_range(0..3);
                    match choice {
                        0 => ChallengeType::Md5,
                        1 => ChallengeType::Sha256,
                        _ => ChallengeType::Web,
                    }
                }
            }
            _ => {
                error!(
                    "Unknown challenge type: {}, defaulting to MD5",
                    self.challenge_type
                );
                ChallengeType::Md5
            }
        }
    }

    /// Get SHA256 difficulty, clamped to valid range
    pub fn get_sha256_difficulty(&self) -> u8 {
        self.sha256_difficulty.clamp(1, 4)
    }
}

impl<'js> IntoJs<'js> for ChallengeConfig {
    fn into_js(self, ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Value<'js>> {
        let obj = rquickjs::Object::new(ctx.clone())?;
        obj.set("challenge_type", self.challenge_type)?;
        obj.set("sha256_difficulty", self.sha256_difficulty)?;
        obj.set("web_plugin", self.web_plugin)?;
        Ok(obj.into())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ServerConfig {
    pub id: String,
    pub url: String,
    pub r#type: String,
    /// 可选的健康检查路径，用于验证服务器连接性
    /// 如果未设置，则跳过该服务器的连接性检查
    #[serde(default)]
    pub health_check_path: Option<String>,
}
impl<'js> IntoJs<'js> for ServerConfig {
    fn into_js(self, ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Value<'js>> {
        let obj = rquickjs::Object::new(ctx.clone())?;
        obj.set("id", self.id)?;
        obj.set("url", self.url)?;
        obj.set("type", self.r#type)?;
        obj.set("health_check_path", self.health_check_path)?;
        Ok(obj.into())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersionPaths {
    #[serde(flatten)]
    pub paths: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceConfig {
    #[serde(default)]
    pub latest: String,
    pub versions: HashMap<String, HashMap<String, String>>,
    pub tries: Vec<String>,
    pub server: Vec<String>,
    pub flow: Vec<FlowItem>,
    /// Resource-specific challenge configuration (optional)
    #[serde(default)]
    pub challenge: Option<ChallengeConfig>,
    /// Download policy for this resource
    #[serde(default)]
    pub download: DownloadPolicy,
    /// Resource type: "file" (single file) or "prefix" (path prefix)
    #[serde(default = "default_resource_type")]
    pub resource_type: String,
    /// 是否启用内容缓存
    #[serde(default)]
    pub cache_enabled: bool,
    /// 前缀资源的可缓存子路径模式（使用glob语法）
    #[serde(default)]
    pub cache_subpaths: Vec<String>,
    /// 缓存时间（秒），用于Cache-Control max-age
    #[serde(default = "default_cache_max_age")]
    pub cache_max_age: u32,
    /// 是否启用历史客户端支持（默认 false）
    #[serde(default)]
    pub legacy_client_support: bool,
    /// 历史客户端全范围模式：虽然验证range但生成签名时始终使用整个文件（默认 false）
    #[serde(default)]
    pub legacy_client_full_range: bool,
    /// 静态changelog配置 (可选)
    #[serde(default)]
    pub changelog: Option<String>,
    /// 动态版本提供者配置 (可选)
    #[serde(default)]
    pub version_provider: Option<VersionProviderConfig>,
}
impl<'js> IntoJs<'js> for ResourceConfig {
    fn into_js(self, ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Value<'js>> {
        let obj = rquickjs::Object::new(ctx.clone())?;
        obj.set("latest", self.latest)?;
        obj.set("tries", self.tries)?;
        obj.set("server", self.server)?;
        obj.set("resource_type", self.resource_type)?;
        let versions = rquickjs::Object::new(ctx.clone())?;
        for (key, value) in self.versions {
            versions.set(key, value)?;
        }
        obj.set("versions", versions)?;
        obj.set("legacy_client_support", self.legacy_client_support)?;
        obj.set("legacy_client_full_range", self.legacy_client_full_range)?;
        if let Some(changelog) = self.changelog {
            obj.set("changelog", changelog)?;
        }
        if let Some(version_provider) = self.version_provider {
            obj.set("version_provider", version_provider)?;
        }
        Ok(obj.into())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub servers: HashMap<String, ServerConfig>,
    pub resources: HashMap<String, ResourceConfig>,
    pub plugins: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub debug_mode: bool,
    /// Global challenge configuration (can be overridden per resource)
    #[serde(default)]
    pub challenge: ChallengeConfig,
    #[serde(default, skip)]
    pub plugin_code: HashMap<String, String>,
    #[serde(default, skip)]
    pub server_impl: HashMap<String, ServerImpl>,
}

impl<'js> IntoJs<'js> for AppConfig {
    fn into_js(self, ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Value<'js>> {
        let obj = rquickjs::Object::new(ctx.clone())?;
        let servers = rquickjs::Object::new(ctx.clone())?;
        for (key, value) in self.servers {
            servers.set(key, value)?;
        }
        obj.set("servers", servers)?;

        let resources = rquickjs::Object::new(ctx.clone())?;
        for (key, value) in self.resources {
            resources.set(key, value)?;
        }
        obj.set("resources", resources)?;

        Ok(obj.into())
    }
}

impl AppConfig {
    /// Get effective challenge configuration for a specific resource
    /// Resource-specific config overrides global config
    pub fn get_challenge_config(&self, resource_id: &str) -> &ChallengeConfig {
        if let Some(resource) = self.resources.get(resource_id) {
            if let Some(ref resource_challenge) = resource.challenge {
                return resource_challenge;
            }
        }
        &self.challenge
    }

    pub async fn load() -> anyhow::Result<Self> {
        let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string());
        let plugin_path = std::env::var("PLUGIN_PATH").unwrap_or_else(|_| "plugins/".to_string());
        let content = tokio::fs::read_to_string(path).await?;
        let mut config: AppConfig = serde_yaml::from_str(&content)?;
        // loop through the plugin directory and load all .js files
        let mut plugin_code = HashMap::new();
        let mut paths = tokio::fs::read_dir(plugin_path).await?;
        loop {
            let entry = paths.next_entry().await?;
            if entry.is_none() {
                break;
            }
            let entry = entry.unwrap(); // This is safe because we checked is_none() above
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "js") {
                let file_name =
                    path.file_stem()
                        .and_then(|stem| stem.to_str())
                        .ok_or_else(|| {
                            error!("Failed to get valid filename from path: {:?}", path);
                            anyhow::anyhow!("Invalid plugin filename: {:?}", path)
                        })?;
                let content = tokio::fs::read_to_string(&path).await.map_err(|e| {
                    error!("Failed to read plugin file {:?}: {}", path, e);
                    e
                })?;
                plugin_code.insert(file_name.to_string(), content);
                info!("Loaded plugin: {}", file_name);
            }
        }
        config.plugin_code = plugin_code;

        // Set debug mode to true in debug builds if not explicitly set in config
        #[cfg(debug_assertions)]
        {
            if !config.debug_mode {
                config.debug_mode = true;
                info!("Debug mode automatically enabled in debug build");
            }
        }

        // create server implementations
        let mut server_impl = HashMap::new();
        for (id, server) in config.servers.iter() {
            let server = ServerImpl::new(server)?;
            server_impl.insert(id.clone(), server);
        }
        config.server_impl = server_impl;

        Ok(config)
    }

    pub fn get_server(&self, id: &str) -> Option<&ServerImpl> {
        self.server_impl.get(id)
    }

    pub fn get_resource(&self, id: &str) -> Option<&ResourceConfig> {
        self.resources.get(id)
    }
}

/// 使用 ArcSwap 实现的共享配置，支持热重载且无锁读取
#[derive(Clone)]
pub struct SharedConfig {
    config: Arc<ArcSwap<AppConfig>>,
}

impl SharedConfig {
    pub fn new(initial_config: AppConfig) -> Self {
        Self {
            config: Arc::new(ArcSwap::from_pointee(initial_config)),
        }
    }

    /// 无锁获取配置的引用
    pub fn load(&self) -> Guard<Arc<AppConfig>> {
        self.config.load()
    }

    /// 热重载配置（原子操作）
    pub fn reload(&self, new_config: AppConfig) {
        let old_config = self.config.swap(Arc::new(new_config));
        tracing::info!("Configuration reloaded successfully, old config dropped");
        drop(old_config); // 显式释放旧配置
    }

    /// 获取内部ArcSwap的克隆（用于传递给其他组件）
    pub fn clone_inner(&self) -> Arc<ArcSwap<AppConfig>> {
        self.config.clone()
    }

    /// 更新配置的便捷方法（用于替换config.write().await的使用场景）
    pub async fn reload_from_file(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let new_config = AppConfig::load().await?;
        self.reload(new_config);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_difficulty_clamping() {
        // 测试范围内的值不变
        let mut config = ChallengeConfig::default();
        config.sha256_difficulty = 2;
        assert_eq!(config.get_sha256_difficulty(), 2);

        config.sha256_difficulty = 1;
        assert_eq!(config.get_sha256_difficulty(), 1);

        config.sha256_difficulty = 4;
        assert_eq!(config.get_sha256_difficulty(), 4);

        // 测试超出范围的值被限制
        config.sha256_difficulty = 0;
        assert_eq!(config.get_sha256_difficulty(), 1); // 最小值1

        config.sha256_difficulty = 5;
        assert_eq!(config.get_sha256_difficulty(), 4); // 最大值4

        config.sha256_difficulty = 255;
        assert_eq!(config.get_sha256_difficulty(), 4); // 最大值4
    }

    #[test]
    fn test_challenge_config_resource_override() {
        use std::collections::HashMap;
        
        // 创建全局配置
        let global_challenge = ChallengeConfig {
            challenge_type: "md5".to_string(),
            sha256_difficulty: 2,
            web_plugin: "global_plugin".to_string(),
            type_weights: None,
        };

        // 创建资源特定配置
        let resource_challenge = ChallengeConfig {
            challenge_type: "sha256".to_string(),
            sha256_difficulty: 3,
            web_plugin: "resource_plugin".to_string(),
            type_weights: None,
        };

        let mut resources = HashMap::new();
        let resource_with_challenge = ResourceConfig {
            latest: "1.0".to_string(),
            versions: HashMap::new(),
            tries: vec![],
            server: vec![],
            flow: vec![],
            challenge: Some(resource_challenge), // 资源特定配置
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

        let resource_without_challenge = ResourceConfig {
            latest: "1.0".to_string(),
            versions: HashMap::new(),
            tries: vec![],
            server: vec![],
            flow: vec![],
            challenge: None, // 无资源特定配置
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

        resources.insert("resource_with_challenge".to_string(), resource_with_challenge);
        resources.insert("resource_without_challenge".to_string(), resource_without_challenge);

        let config = AppConfig {
            servers: HashMap::new(),
            resources,
            plugins: HashMap::new(),
            debug_mode: false,
            challenge: global_challenge,
            plugin_code: HashMap::new(),
            server_impl: HashMap::new(),
        };

        // 测试有资源特定配置的情况 - 应该使用资源配置
        let resource_config = config.get_challenge_config("resource_with_challenge");
        assert_eq!(resource_config.challenge_type, "sha256");
        assert_eq!(resource_config.sha256_difficulty, 3);
        assert_eq!(resource_config.web_plugin, "resource_plugin");

        // 测试没有资源特定配置的情况 - 应该使用全局配置
        let global_config = config.get_challenge_config("resource_without_challenge");
        assert_eq!(global_config.challenge_type, "md5");
        assert_eq!(global_config.sha256_difficulty, 2);
        assert_eq!(global_config.web_plugin, "global_plugin");

        // 测试不存在的资源 - 应该使用全局配置
        let fallback_config = config.get_challenge_config("nonexistent_resource");
        assert_eq!(fallback_config.challenge_type, "md5");
        assert_eq!(fallback_config.sha256_difficulty, 2);
        assert_eq!(fallback_config.web_plugin, "global_plugin");
    }
}
