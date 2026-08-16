use crate::{
    config::SharedConfig,
    error::{DfsError, DfsResult},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ResourceService {
    shared_config: SharedConfig,
    pub version_cache: Arc<crate::modules::version_provider::VersionCache>,
    pub version_updater: Arc<crate::modules::version_provider::VersionUpdater>,
}

impl ResourceService {
    pub fn new(
        shared_config: SharedConfig,
        version_cache: Arc<crate::modules::version_provider::VersionCache>,
        version_updater: Arc<crate::modules::version_provider::VersionUpdater>,
    ) -> Self {
        Self {
            shared_config,
            version_cache,
            version_updater,
        }
    }

    /// 统一资源验证逻辑，支持前缀资源验证
    /// sub_path: None = 常规资源，Some = 前缀资源（必须验证resource_type == "prefix"）
    pub async fn validate_resource_and_version(
        &self,
        resource_id: &str,
        version: &str,
        sub_path: Option<&str>,
    ) -> DfsResult<(String, String)> {
        let config = self.shared_config.load();
        let resource_config = config
            .resources
            .get(resource_id)
            .ok_or_else(|| DfsError::resource_not_found(resource_id))?;

        // 前缀资源类型验证
        if sub_path.is_some() && resource_config.resource_type != "prefix" {
            return Err(DfsError::download_not_allowed(
                resource_id,
                "resource is not a prefix type",
            ));
        }

        let effective_version = if version.is_empty() {
            self.get_effective_version(resource_id).await?
        } else {
            version.to_string()
        };

        // 验证版本存在性
        if !resource_config.versions.contains_key(&effective_version)
            && !resource_config.versions.contains_key("default")
        {
            return Err(DfsError::version_not_found(resource_id, &effective_version));
        }

        Ok((resource_id.to_string(), effective_version))
    }

    pub async fn get_effective_version(&self, resource_id: &str) -> Result<String, DfsError> {
        // 集成版本缓存逻辑
        if let Some(cached_version) = self.version_cache.get_cached_version(resource_id).await {
            Ok(cached_version)
        } else {
            let config = self.shared_config.load();
            if let Some(resource) = config.resources.get(resource_id) {
                if !resource.latest.is_empty() {
                    Ok(resource.latest.clone())
                } else {
                    Err(DfsError::version_not_found(
                        resource_id,
                        "no latest version configured and no cached version available",
                    ))
                }
            } else {
                Err(DfsError::resource_not_found(resource_id))
            }
        }
    }

    pub fn get_version_path(
        &self,
        resource_id: &str,
        version: &str,
        server_id: Option<&str>,
        sub_path: Option<&str>,
    ) -> Option<String> {
        let config = self.shared_config.load();
        let resource = config.get_resource(resource_id)?;
        version_path_for_resource(resource, version, server_id, sub_path)
    }

    pub fn resolve_version_file_path(
        &self,
        resource_id: &str,
        version: &str,
        server_id: Option<&str>,
        version_file: &str,
    ) -> Option<String> {
        let config = self.shared_config.load();
        let resource = config.get_resource(resource_id)?;
        version_file_path_for_resource(resource, version, server_id, version_file)
    }

    /// 获取资源changelog，优先使用版本提供者的结果
    pub async fn get_resource_changelog(&self, resource_id: &str) -> Option<String> {
        // 先尝试从版本缓存获取
        if let Some(version_info) = self
            .version_cache
            .get_cached_version_info(resource_id)
            .await
        {
            if let Some(changelog) = version_info.changelog {
                return Some(changelog);
            }
        }

        // 回退到静态配置
        let config = self.shared_config.load();
        config
            .resources
            .get(resource_id)
            .and_then(|resource| resource.changelog.clone())
    }

    /// Get currently cached version for a resource
    pub async fn get_cached_version(&self, resource_id: &str) -> Option<String> {
        self.version_cache.get_cached_version(resource_id).await
    }

    /// Refresh version cache for a specific resource
    pub async fn refresh_version(&self, resource_id: &str) -> crate::error::DfsResult<String> {
        self.version_updater
            .update_resource_immediately(resource_id)
            .await
    }
}

pub fn version_base_path_for_resource(
    resource: &crate::config::ResourceConfig,
    version: &str,
    server_id: Option<&str>,
) -> Option<String> {
    let path = if let Some(version_map) = resource.versions.get(version) {
        if let Some(server_id) = server_id {
            version_map
                .get(server_id)
                .or_else(|| version_map.get("default"))
        } else {
            version_map.get("default")
        }
    } else {
        None
    };

    let path = path.or_else(|| {
        let default_template = resource.versions.get("default")?;
        if let Some(server_id) = server_id {
            default_template
                .get(server_id)
                .or_else(|| default_template.get("default"))
        } else {
            default_template.get("default")
        }
    })?;

    Some(path.replace("${version}", version))
}

pub fn version_path_for_resource(
    resource: &crate::config::ResourceConfig,
    version: &str,
    server_id: Option<&str>,
    sub_path: Option<&str>,
) -> Option<String> {
    let base_path = version_base_path_for_resource(resource, version, server_id)?;
    match (resource.resource_type.as_str(), sub_path) {
        ("prefix", Some(sub)) => Some(combine_prefix_path(&base_path, sub)),
        ("prefix", None) => None,
        (_, _) => Some(base_path),
    }
}

pub fn version_file_path_for_resource(
    resource: &crate::config::ResourceConfig,
    version: &str,
    server_id: Option<&str>,
    version_file: &str,
) -> Option<String> {
    let base_path = version_base_path_for_resource(resource, version, server_id)?;
    let prefix = if resource.resource_type == "prefix" {
        base_path
    } else if let Some((parent, _)) = base_path.rsplit_once('/') {
        if parent.is_empty() {
            "/".to_string()
        } else {
            parent.to_string()
        }
    } else {
        base_path
    };
    Some(combine_prefix_path(&prefix, version_file))
}

pub fn collect_resource_server_ids(resource: &crate::config::ResourceConfig) -> Vec<String> {
    let mut ids = resource.server.clone();
    for item in &resource.flow {
        for flow_use in &item.r#use {
            if let crate::modules::flow::config::FlowUse::Server { id, .. } = flow_use {
                if !ids.iter().any(|existing| existing == id) {
                    ids.push(id.clone());
                }
            }
        }
    }
    ids
}

/// 安全地组合前缀路径和子路径
fn combine_prefix_path(prefix: &str, sub_path: &str) -> String {
    let normalized_sub = normalize_path(sub_path);
    let clean_prefix = prefix.trim_end_matches('/');
    format!("{clean_prefix}{normalized_sub}")
}

/// 标准化和验证路径安全性
fn normalize_path(path: &str) -> String {
    // 防止目录遍历攻击
    let cleaned = path
        .replace("../", "")
        .replace("..\\", "")
        .replace("\\", "/");

    // 确保以斜杠开头
    if !cleaned.starts_with('/') {
        format!("/{cleaned}")
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_normalize_path_security() {
        // 测试路径遍历攻击防护
        assert_eq!(normalize_path("../../../etc/passwd"), "/etc/passwd");
        assert_eq!(
            normalize_path("..\\..\\windows\\system32"),
            "/windows/system32"
        );
        assert_eq!(normalize_path("normal/path"), "/normal/path");
        assert_eq!(normalize_path("/already/absolute"), "/already/absolute");
    }

    #[tokio::test]
    async fn test_combine_prefix_path() {
        // 测试前缀路径组合
        assert_eq!(
            combine_prefix_path("/games/base", "assets/texture.png"),
            "/games/base/assets/texture.png"
        );
        assert_eq!(
            combine_prefix_path("/games/base/", "/assets/model.obj"),
            "/games/base/assets/model.obj"
        );
        assert_eq!(
            combine_prefix_path("/games/base", "../../../hack"),
            "/games/base/hack"
        );
    }

    #[test]
    fn test_version_file_path_for_prefix_resource() {
        let mut resource = crate::config::ResourceConfig {
            latest: "1.0.0".to_string(),
            versions: std::collections::HashMap::new(),
            tries: vec![],
            server: vec![],
            flow: vec![],
            challenge: None,
            download: crate::config::DownloadPolicy::Free,
            resource_type: "prefix".to_string(),
            cache_enabled: false,
            cache_subpaths: vec![],
            cache_max_age: 300,
            legacy_client_support: false,
            legacy_client_full_range: false,
            changelog: None,
            version_provider: None,
            version_files: vec!["version.json".to_string()],
            version_file_split_ttl: 300,
        };
        let mut version_map = std::collections::HashMap::new();
        version_map.insert("default".to_string(), "/game/v3/".to_string());
        resource.versions.insert("1.0.0".to_string(), version_map);

        assert_eq!(
            version_file_path_for_resource(&resource, "1.0.0", None, "version.json").as_deref(),
            Some("/game/v3/version.json")
        );
    }
}
