pub mod plugin_provider;
pub mod cache;
pub mod updater;

pub use plugin_provider::PluginVersionProvider;
pub use cache::VersionCache;
pub use updater::VersionUpdater;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod changelog_tests;

use crate::error::DfsError;

/// 版本提供者 trait
#[async_trait::async_trait]
pub trait VersionProvider {
    /// 获取资源的最新版本
    async fn get_latest_version(&self, resource_id: &str) -> Result<String, DfsError>;
}

/// 版本信息结构
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub changelog: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub cached_at: std::time::SystemTime,
}

impl VersionInfo {
    pub fn new(version: String, changelog: Option<String>, metadata: Option<serde_json::Value>) -> Self {
        Self {
            version,
            changelog,
            metadata,
            cached_at: std::time::SystemTime::now(),
        }
    }
    
    pub fn age(&self) -> std::time::Duration {
        self.cached_at.elapsed().unwrap_or_default()
    }
}