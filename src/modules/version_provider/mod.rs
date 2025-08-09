pub mod cache;
pub mod plugin_provider;
pub mod updater;

pub use cache::VersionCache;
pub use plugin_provider::PluginVersionProvider;
pub use updater::VersionUpdater;

/// 版本信息结构
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub changelog: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub cached_at: std::time::SystemTime,
}

impl VersionInfo {
    pub fn new(
        version: String,
        changelog: Option<String>,
        metadata: Option<serde_json::Value>,
    ) -> Self {
        Self {
            version,
            changelog,
            metadata,
            cached_at: std::time::SystemTime::now(),
        }
    }
}
