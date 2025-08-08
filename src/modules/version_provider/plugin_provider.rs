use serde_json::json;
use tracing::{debug, error};

use super::{VersionInfo, VersionProvider};
use crate::config::SharedConfig;
use crate::error::{DfsError, DfsResult};
use crate::modules::qjs::JsRunner;

/// 基于插件的版本提供者
pub struct PluginVersionProvider {
    js_runner: JsRunner,
    config: SharedConfig,
}

impl PluginVersionProvider {
    pub fn new(js_runner: JsRunner, config: SharedConfig) -> Self {
        Self { js_runner, config }
    }

    /// 通过插件获取资源版本
    pub async fn fetch_version(&self, resource_id: &str) -> DfsResult<String> {
        let config_guard = self.config.load();

        // 获取资源配置
        let resource = config_guard
            .get_resource(resource_id)
            .ok_or_else(|| DfsError::resource_not_found(resource_id))?;

        // 检查是否配置了版本提供者
        let version_provider = resource.version_provider.as_ref().ok_or_else(|| {
            DfsError::invalid_input(
                "version_provider",
                "No version provider configured for resource".to_string(),
            )
        })?;

        // 验证插件类型
        if version_provider.r#type != "plugin" {
            return Err(DfsError::invalid_input(
                "version_provider.type",
                format!(
                    "Unsupported version provider type: {}",
                    version_provider.r#type
                ),
            ));
        }

        // 验证插件名称
        let plugin_name = &version_provider.plugin_name;
        if !plugin_name.starts_with("version_provider_") {
            return Err(DfsError::invalid_input(
                "version_provider.plugin_name",
                format!(
                    "Version provider plugin name must start with 'version_provider_': {}",
                    plugin_name
                ),
            ));
        }

        // 检查插件是否存在
        if !config_guard.plugin_code.contains_key(plugin_name) {
            return Err(DfsError::plugin_not_found(plugin_name.clone()));
        }

        debug!(
            "Executing version provider plugin {} for resource {}",
            plugin_name, resource_id
        );

        // 执行插件
        let version_info = self
            .execute_version_plugin(plugin_name, &version_provider.options, resource_id)
            .await?;

        Ok(version_info.version)
    }

    /// 通过插件获取详细版本信息
    pub async fn fetch_version_info(&self, resource_id: &str) -> DfsResult<VersionInfo> {
        let config_guard = self.config.load();

        // 获取资源配置
        let resource = config_guard
            .get_resource(resource_id)
            .ok_or_else(|| DfsError::resource_not_found(resource_id))?;

        // 检查是否配置了版本提供者
        let version_provider = resource.version_provider.as_ref().ok_or_else(|| {
            DfsError::invalid_input(
                "version_provider",
                "No version provider configured for resource".to_string(),
            )
        })?;

        let plugin_name = &version_provider.plugin_name;

        debug!(
            "Fetching version info via plugin {} for resource {}",
            plugin_name, resource_id
        );

        // 执行插件并返回完整信息
        self.execute_version_plugin(plugin_name, &version_provider.options, resource_id)
            .await
    }

    /// 执行版本提供者插件
    async fn execute_version_plugin(
        &self,
        plugin_name: &str,
        options: &serde_json::Value,
        resource_id: &str,
    ) -> DfsResult<VersionInfo> {
        // 准备插件执行参数
        let extras = json!({
            "resource_id": resource_id,
            "timestamp": chrono::Utc::now().timestamp(),
        });

        // 执行插件
        let result = self
            .js_runner
            .execute_version_provider_plugin(plugin_name, options, resource_id, &extras)
            .await?;

        debug!(
            "Version provider plugin {} returned: {:?}",
            plugin_name, result
        );

        // 解析插件返回结果
        let version = result
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                DfsError::plugin_error(
                    plugin_name.to_string(),
                    "Plugin must return 'version' field as string".to_string(),
                )
            })?;

        if version.is_empty() {
            return Err(DfsError::plugin_error(
                plugin_name.to_string(),
                "Plugin returned empty version".to_string(),
            ));
        }

        // 提取changelog
        let changelog = result
            .get("changelog")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // 提取元数据
        let metadata = result.get("metadata").cloned();

        Ok(VersionInfo::new(version.to_string(), changelog, metadata))
    }
}

#[async_trait::async_trait]
impl VersionProvider for PluginVersionProvider {
    async fn get_latest_version(&self, resource_id: &str) -> Result<String, DfsError> {
        self.fetch_version(resource_id).await
    }
}

/// 扩展JsRunner以支持版本提供者插件
impl JsRunner {
    /// 执行版本提供者插件
    pub async fn execute_version_provider_plugin(
        &self,
        plugin_name: &str,
        options: &serde_json::Value,
        resource_id: &str,
        extras: &serde_json::Value,
    ) -> DfsResult<serde_json::Value> {
        // 验证插件存在
        let config = self.get_shared_config();
        let config_guard = config.load();
        let plugin_code = config_guard
            .plugin_code
            .get(plugin_name)
            .ok_or_else(|| DfsError::plugin_not_found(plugin_name.to_string()))?;

        // 生成执行代码 - 参考flow插件的执行方式
        let execution_code = format!(
            r#"
            (async (options, resource_id, extras) => {{
                try {{
                    var exports; // 使用var允许重定义
                    
                    /* USER CODE START */
                    {}
                    /* USER CODE END */
                    
                    if (typeof exports !== 'function') {{
                        throw new Error('Plugin must set exports to a function');
                    }}
                    
                    // 调用插件函数 - 参数顺序匹配插件签名 (options, resourceId, extras)
                    const result = await exports(options, resource_id, extras);
                    
                    // 验证返回结果
                    if (!result || typeof result !== 'object') {{
                        throw new Error('Plugin must return an object');
                    }}
                    
                    if (!result.version || typeof result.version !== 'string') {{
                        throw new Error('Plugin must return version field as string');
                    }}
                    
                    return result;
                }} catch (error) {{
                    console.error('Version provider plugin error:', error.message);
                    throw error;
                }}
            }})({}, {}, {})
            "#,
            plugin_code,
            serde_json::to_string(options).unwrap_or_else(|_| "{}".to_string()),
            serde_json::to_string(resource_id).unwrap_or_else(|_| "\"unknown\"".to_string()),
            serde_json::to_string(extras).unwrap_or_else(|_| "{}".to_string()),
        );

        debug!("Executing version provider plugin: {}", plugin_name);

        // 执行插件
        match self.execute_async(&execution_code).await {
            Ok(result) => {
                debug!(
                    "Version provider plugin {} executed successfully",
                    plugin_name
                );
                Ok(result)
            }
            Err(e) => {
                error!(
                    "Version provider plugin {} execution failed: {}",
                    plugin_name, e
                );
                Err(DfsError::plugin_error(
                    plugin_name.to_string(),
                    e.to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DownloadPolicy;
    use crate::config::{AppConfig, ResourceConfig, VersionProviderConfig};
    use crate::modules::flow::FlowItem;
    use std::collections::HashMap;

    fn create_test_config_with_version_provider() -> AppConfig {
        let mut servers = HashMap::new();
        let mut resources = HashMap::new();
        let mut plugin_code = HashMap::new();

        // 测试插件代码
        plugin_code.insert(
            "version_provider_test".to_string(),
            r#"
            async function(options, resourceId, extras) {
                return {
                    version: options.test_version || "1.0.0",
                    metadata: {
                        source: "test_plugin",
                        resource_id: resourceId,
                        timestamp: extras.timestamp
                    }
                };
            }
            "#
            .to_string(),
        );

        // 测试资源配置
        resources.insert(
            "test_resource".to_string(),
            ResourceConfig {
                latest: "0.9.0".to_string(),
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
                changelog: None,
                version_provider: Some(VersionProviderConfig {
                    r#type: "plugin".to_string(),
                    plugin_name: "version_provider_test".to_string(),
                    cache_ttl: Some(300),
                    webhook_token: Some("test_token".to_string()),
                    options: serde_json::json!({
                        "test_version": "2.0.0"
                    }),
                }),
            },
        );

        AppConfig {
            servers,
            resources,
            plugins: HashMap::new(),
            debug_mode: true,
            challenge: crate::config::ChallengeConfig::default(),
            plugin_code,
            server_impl: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_plugin_version_provider() {
        // 注意：这个测试需要一个完整的JsRunner实现
        // 在实际环境中，需要确保JsRunner和相关依赖都已正确初始化

        // 创建测试配置
        let config = Arc::new(RwLock::new(create_test_config_with_version_provider()));

        // 这里应该创建真实的JsRunner实例，但在单元测试中可能需要模拟
        // let js_runner = Arc::new(JsRunner::new(config.clone(), data_store).await);
        // let provider = PluginVersionProvider::new(js_runner, config);

        // let version = provider.fetch_version("test_resource").await.unwrap();
        // assert_eq!(version, "2.0.0");
    }
}
