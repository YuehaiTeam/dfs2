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
    "random".to_string()
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
    /// Create a challenge config for specific type with default settings
    pub fn new(challenge_type: ChallengeType, difficulty: Option<u8>) -> Self {
        let type_str = match challenge_type {
            ChallengeType::Md5 => "md5",
            ChallengeType::Sha256 => "sha256",
            ChallengeType::Web => "web",
        };

        ChallengeConfig {
            challenge_type: type_str.to_string(),
            sha256_difficulty: difficulty.unwrap_or(2).clamp(1, 4),
            web_plugin: default_web_plugin(),
            type_weights: Some(TypeWeights {
                md5: default_md5_weight(),
                sha256: default_sha256_weight(),
                web: default_web_weight(),
            }),
        }
    }

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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

    /// Apply environment variable overrides to challenge configuration
    pub fn apply_env_overrides(&mut self) {
        // Override global challenge config with environment variables
        if let Ok(challenge_type) = std::env::var("CHALLENGE_DEFAULT_TYPE") {
            self.challenge.challenge_type = challenge_type;
        }

        if let Ok(difficulty_str) = std::env::var("CHALLENGE_SHA256_DIFFICULTY") {
            if let Ok(difficulty) = difficulty_str.parse::<u8>() {
                self.challenge.sha256_difficulty = difficulty.clamp(1, 4);
            }
        }

        if let Ok(web_plugin) = std::env::var("CHALLENGE_WEB_PLUGIN") {
            self.challenge.web_plugin = web_plugin;
        }
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

        // Apply environment variable overrides
        config.apply_env_overrides();

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
    use std::collections::HashMap;

    fn create_test_config() -> AppConfig {
        let mut servers = HashMap::new();
        servers.insert(
            "s3_server".to_string(),
            ServerConfig {
                id: "s3_server".to_string(),
                url: "https://access:secret@s3.example.com?region=us-east-1&bucket=test"
                    .to_string(),
                r#type: "s3".to_string(),
                health_check_path: None,
            },
        );
        servers.insert(
            "direct_server".to_string(),
            ServerConfig {
                id: "direct_server".to_string(),
                url: "https://cdn.example.com".to_string(),
                r#type: "direct".to_string(),
                health_check_path: None,
            },
        );

        let mut resources = HashMap::new();
        let mut versions = HashMap::new();
        let mut version_1_0 = HashMap::new();
        version_1_0.insert("default".to_string(), "/app/v1.0/app.exe".to_string());
        version_1_0.insert(
            "s3_server".to_string(),
            "/releases/v1.0/app.exe".to_string(),
        );
        versions.insert("1.0".to_string(), version_1_0);

        resources.insert(
            "test_app".to_string(),
            ResourceConfig {
                latest: "1.0".to_string(),
                versions,
                tries: vec!["s3_server".to_string(), "direct_server".to_string()],
                server: vec!["s3_server".to_string(), "direct_server".to_string()],
                flow: vec![],    // 简单测试不需要复杂flow
                challenge: None, // 使用默认挑战配置
                download: crate::config::DownloadPolicy::Enabled, // 默认下载策略
                resource_type: "file".to_string(), // 默认文件类型
                legacy_client_support: false, // 测试中默认不支持历史客户端
                legacy_client_full_range: false, // 测试中默认不启用全范围模式
                cache_enabled: false, // 默认不启用缓存
                cache_subpaths: vec![], // 默认无缓存子路径
                cache_max_age: default_cache_max_age(), // 默认缓存时间
                changelog: None, // 测试中默认无静态changelog
                version_provider: None, // 测试中默认不使用动态版本
            },
        );

        AppConfig {
            servers,
            resources,
            plugins: HashMap::new(),
            debug_mode: false,
            plugin_code: HashMap::new(),
            server_impl: HashMap::new(),
            challenge: ChallengeConfig::default(),
        }
    }

    #[test]
    fn test_get_server() {
        let config = create_test_config();

        let server = config.get_server("s3_server");
        assert!(server.is_none()); // server_impl为空，所以返回None

        // 测试不存在的服务器
        let server = config.get_server("nonexistent");
        assert!(server.is_none());
    }

    #[test]
    fn test_get_resource() {
        let config = create_test_config();

        let resource = config.get_resource("test_app");
        assert!(resource.is_some());
        let resource = resource.unwrap();
        assert_eq!(resource.latest, "1.0");
        assert_eq!(resource.tries.len(), 2);

        // 测试不存在的资源
        let resource = config.get_resource("nonexistent");
        assert!(resource.is_none());
    }

    #[test]
    fn test_get_version_path() {
        let config = create_test_config();

        // 测试默认路径
        let path = config.get_version_path("test_app", "1.0", None, None);
        assert_eq!(path, Some("/app/v1.0/app.exe".to_string()));

        // 测试特定服务器路径
        let path = config.get_version_path("test_app", "1.0", Some("s3_server"), None);
        assert_eq!(path, Some("/releases/v1.0/app.exe".to_string()));

        // 测试不存在的版本
        let path = config.get_version_path("test_app", "2.0", None, None);
        assert!(path.is_none());

        // 测试不存在的资源
        let path = config.get_version_path("nonexistent", "1.0", None, None);
        assert!(path.is_none());

        // 测试不存在的服务器，应该回退到默认
        let path = config.get_version_path("test_app", "1.0", Some("nonexistent_server"), None);
        assert_eq!(path, Some("/app/v1.0/app.exe".to_string()));
    }

    #[test]
    fn test_version_placeholder_replacement() {
        let mut config = create_test_config();

        // 添加包含版本占位符的配置
        let mut version_with_placeholder = HashMap::new();
        version_with_placeholder.insert(
            "default".to_string(),
            "/releases/${version}/app.exe".to_string(),
        );
        version_with_placeholder.insert(
            "s3_server".to_string(),
            "/s3-bucket/${version}/installer.exe".to_string(),
        );

        if let Some(resource) = config.resources.get_mut("test_app") {
            resource
                .versions
                .insert("2.0".to_string(), version_with_placeholder);
        }

        // 测试版本占位符替换 - 默认路径
        let path = config.get_version_path("test_app", "2.0", None, None);
        assert_eq!(path, Some("/releases/2.0/app.exe".to_string()));

        // 测试版本占位符替换 - 特定服务器路径
        let path = config.get_version_path("test_app", "2.0", Some("s3_server"), None);
        assert_eq!(path, Some("/s3-bucket/2.0/installer.exe".to_string()));

        // 测试不存在占位符的路径不受影响
        let path = config.get_version_path("test_app", "1.0", None, None);
        assert_eq!(path, Some("/app/v1.0/app.exe".to_string()));

        // 测试复杂版本号的替换
        let mut complex_version = HashMap::new();
        complex_version.insert(
            "default".to_string(),
            "/apps/${version}/final/dist.zip".to_string(),
        );

        if let Some(resource) = config.resources.get_mut("test_app") {
            resource
                .versions
                .insert("1.2.3-beta".to_string(), complex_version);
        }

        let path = config.get_version_path("test_app", "1.2.3-beta", None, None);
        assert_eq!(path, Some("/apps/1.2.3-beta/final/dist.zip".to_string()));
    }

    #[test]
    fn test_versions_default_template() {
        let mut config = create_test_config();

        // 添加default模板配置
        let mut default_template = HashMap::new();
        default_template.insert(
            "default".to_string(),
            "/releases/${version}/app.exe".to_string(),
        );
        default_template.insert(
            "s3_server".to_string(),
            "/s3-releases/${version}/installer.exe".to_string(),
        );

        if let Some(resource) = config.resources.get_mut("test_app") {
            resource
                .versions
                .insert("default".to_string(), default_template);
        }

        // 测试使用default模板 - 不存在的版本应该使用default模板
        let path = config.get_version_path("test_app", "3.0.0", None, None);
        assert_eq!(path, Some("/releases/3.0.0/app.exe".to_string()));

        // 测试使用default模板 - 特定服务器
        let path = config.get_version_path("test_app", "3.0.0", Some("s3_server"), None);
        assert_eq!(path, Some("/s3-releases/3.0.0/installer.exe".to_string()));

        // 测试特定版本优先级高于default模板
        let path = config.get_version_path("test_app", "1.0", None, None);
        assert_eq!(path, Some("/app/v1.0/app.exe".to_string())); // 仍然使用特定版本配置

        // 添加一个只有部分服务器配置的版本
        let mut partial_version = HashMap::new();
        partial_version.insert(
            "direct_server".to_string(),
            "/direct/v4.0.0/app.exe".to_string(),
        );

        if let Some(resource) = config.resources.get_mut("test_app") {
            resource
                .versions
                .insert("4.0.0".to_string(), partial_version);
        }

        // 测试混合使用：特定版本有部分配置，缺失的回退到default模板
        let path = config.get_version_path("test_app", "4.0.0", Some("direct_server"), None);
        assert_eq!(path, Some("/direct/v4.0.0/app.exe".to_string())); // 使用特定配置

        let path = config.get_version_path("test_app", "4.0.0", None, None);
        assert_eq!(path, Some("/releases/4.0.0/app.exe".to_string())); // default服务器使用模板

        let path = config.get_version_path("test_app", "4.0.0", Some("s3_server"), None);
        assert_eq!(path, Some("/s3-releases/4.0.0/installer.exe".to_string())); // s3_server使用模板
    }

    #[test]
    fn test_server_config_serialization() {
        let server = ServerConfig {
            id: "test".to_string(),
            url: "https://example.com".to_string(),
            r#type: "direct".to_string(),
            health_check_path: None,
        };

        let yaml = serde_yaml::to_string(&server).unwrap();
        let deserialized: ServerConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(server.id, deserialized.id);
        assert_eq!(server.url, deserialized.url);
        assert_eq!(server.r#type, deserialized.r#type);
    }

    #[test]
    fn test_resource_config_serialization() {
        let mut versions = HashMap::new();
        let mut version_map = HashMap::new();
        version_map.insert("default".to_string(), "/path/to/file".to_string());
        versions.insert("1.0".to_string(), version_map);

        let resource = ResourceConfig {
            latest: "1.0".to_string(),
            versions,
            tries: vec!["server1".to_string()],
            server: vec!["server1".to_string(), "server2".to_string()],
            flow: vec![],
            challenge: None,
            download: DownloadPolicy::Enabled,
            resource_type: "file".to_string(),
            legacy_client_support: false,
            legacy_client_full_range: false,
            cache_enabled: false,
            cache_subpaths: vec![],
            cache_max_age: default_cache_max_age(),
            changelog: None,
            version_provider: None,
        };

        let yaml = serde_yaml::to_string(&resource).unwrap();
        let deserialized: ResourceConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(resource.latest, deserialized.latest);
        assert_eq!(resource.tries.len(), deserialized.tries.len());
        assert_eq!(resource.server.len(), deserialized.server.len());
        assert_eq!(resource.resource_type, deserialized.resource_type);
    }

    #[test]
    fn test_prefix_path_handling() {
        // 测试路径标准化
        assert_eq!(normalize_path("file.txt"), "/file.txt");
        assert_eq!(normalize_path("/file.txt"), "/file.txt");
        assert_eq!(normalize_path("../../../etc/passwd"), "/etc/passwd");
        assert_eq!(normalize_path("dir\\file.txt"), "/dir/file.txt");

        // 测试前缀路径组合
        assert_eq!(
            combine_prefix_path("/app/v1.0/", "bin/app.exe"),
            "/app/v1.0/bin/app.exe"
        );
        assert_eq!(
            combine_prefix_path("/app/v1.0", "/bin/app.exe"),
            "/app/v1.0/bin/app.exe"
        );
        assert_eq!(
            combine_prefix_path("/app/v1.0/", "../../../etc/passwd"),
            "/app/v1.0/etc/passwd"
        );
    }

    #[test]
    fn test_get_version_path_with_sub() {
        let mut config = create_test_config();

        // 添加前缀资源
        let mut prefix_versions = HashMap::new();
        let mut prefix_version_1_0 = HashMap::new();
        prefix_version_1_0.insert("default".to_string(), "/releases/v1.0/".to_string());
        prefix_versions.insert("1.0".to_string(), prefix_version_1_0);

        config.resources.insert(
            "app_suite".to_string(),
            ResourceConfig {
                latest: "1.0".to_string(),
                versions: prefix_versions,
                tries: vec!["s3_server".to_string()],
                server: vec!["s3_server".to_string()],
                flow: vec![],
                challenge: None,
                download: DownloadPolicy::Enabled,
                resource_type: "prefix".to_string(),
                legacy_client_support: false,
                legacy_client_full_range: false,
                cache_enabled: false,
                cache_subpaths: vec![],
                cache_max_age: default_cache_max_age(),
                changelog: None,
                version_provider: None,
            },
        );

        // 测试文件资源（忽略子路径）
        let path = config.get_version_path("test_app", "1.0", None, Some("ignored"));
        assert_eq!(path, Some("/app/v1.0/app.exe".to_string()));

        // 测试前缀资源（需要子路径）
        let path = config.get_version_path("app_suite", "1.0", None, None);
        assert!(path.is_none()); // 前缀资源必须提供子路径

        let path = config.get_version_path("app_suite", "1.0", None, Some("windows/app.exe"));
        assert_eq!(path, Some("/releases/v1.0/windows/app.exe".to_string()));

        // 测试不存在的资源
        let path = config.get_version_path("nonexistent", "1.0", None, Some("file"));
        assert!(path.is_none());
    }
}
