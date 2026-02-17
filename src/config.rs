use arc_swap::{ArcSwap, Guard};
use rquickjs::IntoJs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tracing::{error, info, warn};

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

/// Validated certificate hash policy for HTTP/3 only nodes.
///
/// Determines how the certificate of an h3_only server is verified:
/// - `ValidCert`: require a valid (CA-signed) certificate (default when cert_hash is None/empty)
/// - `Trust`: skip cert verification; fetch and cache the cert hash during health check
/// - `PinnedHex`: pin to a specific leaf certificate hash (SHA-256 of DER bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertHashPolicy {
    /// Require valid certificate (empty/None cert_hash)
    ValidCert,
    /// Skip cert verification, must fetch cert hash during health check
    Trust,
    /// Pin to specific leaf cert hash (SHA-256 of DER), stored as 32 bytes
    PinnedHex([u8; 32]),
}

impl CertHashPolicy {
    /// Parse and validate a cert_hash string into a CertHashPolicy.
    ///
    /// Valid inputs:
    /// - `None` or empty string → `ValidCert`
    /// - `"trust"` (case-insensitive) → `Trust`
    /// - 64 hex characters → `PinnedHex` (normalized to lowercase)
    pub fn from_option(cert_hash: &Option<String>) -> Result<Self, String> {
        match cert_hash {
            None => Ok(CertHashPolicy::ValidCert),
            Some(s) if s.is_empty() => Ok(CertHashPolicy::ValidCert),
            Some(s) if s.eq_ignore_ascii_case("trust") => Ok(CertHashPolicy::Trust),
            Some(s) => {
                let s = s.trim();
                if s.len() != 64 {
                    return Err(format!(
                        "cert_hash must be exactly 64 hex characters, got {} characters: '{}'",
                        s.len(),
                        s
                    ));
                }
                if !s.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!("cert_hash contains non-hex characters: '{}'", s));
                }
                let mut bytes = [0u8; 32];
                for i in 0..32 {
                    bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                        .map_err(|e| format!("failed to parse hex at position {}: {}", i * 2, e))?;
                }
                Ok(CertHashPolicy::PinnedHex(bytes))
            }
        }
    }

    /// Return the normalized lowercase hex string for PinnedHex, or None for other variants.
    #[allow(dead_code)]
    pub fn as_hex_string(&self) -> Option<String> {
        match self {
            CertHashPolicy::PinnedHex(bytes) => {
                Some(bytes.iter().map(|b| format!("{:02x}", b)).collect())
            }
            _ => None,
        }
    }
}

impl fmt::Display for CertHashPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertHashPolicy::ValidCert => write!(f, "valid_cert"),
            CertHashPolicy::Trust => write!(f, "trust"),
            CertHashPolicy::PinnedHex(bytes) => {
                for b in bytes {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
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
#[derive(Default)]
pub enum DownloadPolicy {
    /// Download disabled (default)
    #[default]
    Disabled,
    /// Download enabled with session validation
    Enabled,
    /// Download freely available without session
    Free,
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
    /// 服务器配置文件，用于区分具体实现类型（如minio、aws等）
    #[serde(default)]
    pub profile: Option<String>,
    /// 是否跳过特定的配置文件生成步骤
    #[serde(default)]
    pub generation_skip: Vec<String>,
    /// Whether this server is HTTP/3 only
    #[serde(default)]
    pub h3_only: bool,
    /// Certificate hash policy for h3_only nodes:
    /// - None/empty: require valid certificate
    /// - "trust": skip cert verification, fetch cert hash during health check
    /// - 64-char hex: pin to specific leaf cert SHA-256 hash
    #[serde(default)]
    pub cert_hash: Option<String>,
}
impl ServerConfig {
    /// Validate h3_only and cert_hash configuration.
    /// Returns a list of errors and warnings for this server.
    pub fn validate_h3(&self, server_id: &str) -> (Vec<String>, Vec<String>) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if !self.h3_only {
            // When h3_only=false, warn if cert_hash is set but don't fail
            if self.cert_hash.is_some() && !self.cert_hash.as_ref().is_none_or(|s| s.is_empty()) {
                warnings.push(format!(
                    "Server '{}': cert_hash is set but h3_only is false; cert_hash will be ignored",
                    server_id
                ));
            }
            return (errors, warnings);
        }

        // h3_only=true: validate URL scheme is https
        if !self.url.starts_with("https://") {
            errors.push(format!(
                "Server '{}': h3_only=true requires https:// URL scheme, got '{}'",
                server_id, self.url
            ));
        }

        // Validate cert_hash value
        if let Err(e) = CertHashPolicy::from_option(&self.cert_hash) {
            errors.push(format!("Server '{}': invalid cert_hash: {}", server_id, e));
        }

        (errors, warnings)
    }

    /// Parse and return the validated CertHashPolicy for this server.
    /// Returns ValidCert if h3_only is false.
    pub fn cert_hash_policy(&self) -> Result<CertHashPolicy, String> {
        if !self.h3_only {
            return Ok(CertHashPolicy::ValidCert);
        }
        CertHashPolicy::from_option(&self.cert_hash)
    }

    /// Return the normalized cert_hash string (lowercase hex) for storage/URLs.
    /// Returns None if not h3_only or if policy is ValidCert/Trust.
    #[allow(dead_code)]
    pub fn normalized_cert_hash(&self) -> Option<String> {
        if !self.h3_only {
            return None;
        }
        match &self.cert_hash {
            Some(s) if s.eq_ignore_ascii_case("trust") => Some("trust".to_string()),
            Some(s) if s.len() == 64 => Some(s.to_ascii_lowercase()),
            _ => None,
        }
    }
}

impl<'js> IntoJs<'js> for ServerConfig {
    fn into_js(self, ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Value<'js>> {
        let obj = rquickjs::Object::new(ctx.clone())?;
        obj.set("id", self.id)?;
        obj.set("url", self.url)?;
        obj.set("type", self.r#type)?;
        obj.set("health_check_path", self.health_check_path)?;
        obj.set("profile", self.profile)?;
        obj.set("h3_only", self.h3_only)?;
        obj.set("cert_hash", self.cert_hash)?;
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

    /// Validate all server h3_only/cert_hash configurations.
    /// Returns (errors, warnings).
    pub fn validate_servers_h3(&self) -> (Vec<String>, Vec<String>) {
        let mut all_errors = Vec::new();
        let mut all_warnings = Vec::new();
        for (server_id, server_config) in &self.servers {
            let (errors, warnings) = server_config.validate_h3(server_id);
            all_errors.extend(errors);
            all_warnings.extend(warnings);
        }
        (all_errors, all_warnings)
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

        // Validate h3_only/cert_hash server configurations
        let (h3_errors, h3_warnings) = config.validate_servers_h3();
        for w in &h3_warnings {
            warn!("{}", w);
        }
        if !h3_errors.is_empty() {
            for e in &h3_errors {
                error!("{}", e);
            }
            return Err(anyhow::anyhow!(
                "Server h3_only/cert_hash validation failed:\n{}",
                h3_errors.join("\n")
            ));
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
    fn test_cert_hash_policy_valid_cert() {
        // None -> ValidCert
        assert_eq!(
            CertHashPolicy::from_option(&None).unwrap(),
            CertHashPolicy::ValidCert
        );
        // Empty string -> ValidCert
        assert_eq!(
            CertHashPolicy::from_option(&Some("".to_string())).unwrap(),
            CertHashPolicy::ValidCert
        );
    }

    #[test]
    fn test_cert_hash_policy_trust() {
        assert_eq!(
            CertHashPolicy::from_option(&Some("trust".to_string())).unwrap(),
            CertHashPolicy::Trust
        );
        // Case insensitive
        assert_eq!(
            CertHashPolicy::from_option(&Some("TRUST".to_string())).unwrap(),
            CertHashPolicy::Trust
        );
        assert_eq!(
            CertHashPolicy::from_option(&Some("Trust".to_string())).unwrap(),
            CertHashPolicy::Trust
        );
    }

    #[test]
    fn test_cert_hash_policy_pinned_hex() {
        let hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let policy = CertHashPolicy::from_option(&Some(hex.to_string())).unwrap();
        match &policy {
            CertHashPolicy::PinnedHex(bytes) => {
                assert_eq!(bytes[0], 0xa1);
                assert_eq!(bytes[1], 0xb2);
                assert_eq!(bytes[31], 0xb2);
            }
            _ => panic!("Expected PinnedHex"),
        }
        // Display should emit lowercase hex
        assert_eq!(policy.to_string(), hex);
        // as_hex_string should match
        assert_eq!(policy.as_hex_string().unwrap(), hex);
    }

    #[test]
    fn test_cert_hash_policy_pinned_hex_uppercase_normalized() {
        let hex_upper = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        let policy = CertHashPolicy::from_option(&Some(hex_upper.to_string())).unwrap();
        // Should be normalized to lowercase
        let hex_lower = hex_upper.to_ascii_lowercase();
        assert_eq!(policy.to_string(), hex_lower);
        assert_eq!(policy.as_hex_string().unwrap(), hex_lower);
    }

    #[test]
    fn test_cert_hash_policy_invalid_length() {
        let result = CertHashPolicy::from_option(&Some("abcdef".to_string()));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("64 hex characters"));
    }

    #[test]
    fn test_cert_hash_policy_invalid_hex_chars() {
        // 64 chars but not all hex
        let bad = "g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let result = CertHashPolicy::from_option(&Some(bad.to_string()));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-hex"));
    }

    #[test]
    fn test_cert_hash_policy_display() {
        assert_eq!(CertHashPolicy::ValidCert.to_string(), "valid_cert");
        assert_eq!(CertHashPolicy::Trust.to_string(), "trust");
    }

    #[test]
    fn test_server_config_validate_h3_disabled() {
        let server = ServerConfig {
            id: "test".to_string(),
            url: "http://example.com".to_string(),
            r#type: "direct".to_string(),
            h3_only: false,
            cert_hash: None,
            ..Default::default()
        };
        let (errors, warnings) = server.validate_h3("test");
        assert!(errors.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_server_config_validate_h3_disabled_with_cert_hash_warns() {
        let server = ServerConfig {
            id: "test".to_string(),
            url: "http://example.com".to_string(),
            r#type: "direct".to_string(),
            h3_only: false,
            cert_hash: Some("trust".to_string()),
            ..Default::default()
        };
        let (errors, warnings) = server.validate_h3("test");
        assert!(errors.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("ignored"));
    }

    #[test]
    fn test_server_config_validate_h3_enabled_https_ok() {
        let server = ServerConfig {
            id: "test".to_string(),
            url: "https://cdn.example.com".to_string(),
            r#type: "direct".to_string(),
            h3_only: true,
            cert_hash: Some("trust".to_string()),
            ..Default::default()
        };
        let (errors, warnings) = server.validate_h3("test");
        assert!(errors.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_server_config_validate_h3_enabled_http_fails() {
        let server = ServerConfig {
            id: "test".to_string(),
            url: "http://cdn.example.com".to_string(),
            r#type: "direct".to_string(),
            h3_only: true,
            cert_hash: None,
            ..Default::default()
        };
        let (errors, _warnings) = server.validate_h3("test");
        assert!(!errors.is_empty());
        assert!(errors[0].contains("https://"));
    }

    #[test]
    fn test_server_config_validate_h3_enabled_bad_cert_hash() {
        let server = ServerConfig {
            id: "test".to_string(),
            url: "https://cdn.example.com".to_string(),
            r#type: "direct".to_string(),
            h3_only: true,
            cert_hash: Some("invalid_value".to_string()),
            ..Default::default()
        };
        let (errors, _warnings) = server.validate_h3("test");
        assert!(!errors.is_empty());
        assert!(errors[0].contains("cert_hash"));
    }

    #[test]
    fn test_server_config_cert_hash_policy_non_h3() {
        let server = ServerConfig {
            id: "test".to_string(),
            url: "http://example.com".to_string(),
            r#type: "direct".to_string(),
            h3_only: false,
            cert_hash: Some("trust".to_string()),
            ..Default::default()
        };
        // Non-h3 always returns ValidCert
        assert_eq!(
            server.cert_hash_policy().unwrap(),
            CertHashPolicy::ValidCert
        );
    }

    #[test]
    fn test_server_config_cert_hash_policy_h3() {
        let server = ServerConfig {
            id: "test".to_string(),
            url: "https://cdn.example.com".to_string(),
            r#type: "direct".to_string(),
            h3_only: true,
            cert_hash: Some("trust".to_string()),
            ..Default::default()
        };
        assert_eq!(server.cert_hash_policy().unwrap(), CertHashPolicy::Trust);
    }

    #[test]
    fn test_server_config_serde_backward_compat() {
        // Old config without h3_only/cert_hash should parse fine
        let yaml = r#"
id: "old_server"
url: "https://cdn.example.com"
type: "direct"
"#;
        let config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.h3_only);
        assert!(config.cert_hash.is_none());
    }

    #[test]
    fn test_server_config_serde_with_h3_fields() {
        let yaml = r#"
id: "h3_server"
url: "https://cdn.example.com"
type: "direct"
h3_only: true
cert_hash: "trust"
"#;
        let config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.h3_only);
        assert_eq!(config.cert_hash, Some("trust".to_string()));
    }

    #[test]
    fn test_app_config_validate_servers_h3() {
        let mut servers = HashMap::new();
        servers.insert(
            "good".to_string(),
            ServerConfig {
                id: "good".to_string(),
                url: "https://cdn.example.com".to_string(),
                r#type: "direct".to_string(),
                h3_only: true,
                cert_hash: Some("trust".to_string()),
                ..Default::default()
            },
        );
        servers.insert(
            "bad".to_string(),
            ServerConfig {
                id: "bad".to_string(),
                url: "http://cdn.example.com".to_string(),
                r#type: "direct".to_string(),
                h3_only: true,
                cert_hash: None,
                ..Default::default()
            },
        );
        let config = AppConfig {
            servers,
            resources: HashMap::new(),
            plugins: HashMap::new(),
            debug_mode: false,
            challenge: ChallengeConfig::default(),
            plugin_code: HashMap::new(),
            server_impl: HashMap::new(),
        };
        let (errors, _warnings) = config.validate_servers_h3();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("bad")));
    }

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

        resources.insert(
            "resource_with_challenge".to_string(),
            resource_with_challenge,
        );
        resources.insert(
            "resource_without_challenge".to_string(),
            resource_without_challenge,
        );

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
