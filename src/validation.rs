use crate::{
    config::{AppConfig, SharedConfig},
    error::DfsResult,
    modules::{
        qjs::JsRunner, server::ping_servers, storage::data_store::DataStore,
        version_file::PROBE_CONCURRENCY,
    },
};
use std::collections::HashSet;
use tracing::info;

/// 验证报告结构
#[derive(Debug)]
pub struct ValidationReport {
    pub config_valid: bool,
    pub plugins_valid: bool,
    pub servers_valid: bool,
    pub redis_valid: bool,
    pub version_providers_valid: bool,
    pub version_files_valid: bool,
    pub env_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationReport {
    pub fn new() -> Self {
        Self {
            config_valid: true,
            plugins_valid: true,
            servers_valid: true,
            redis_valid: true,
            version_providers_valid: true,
            version_files_valid: true,
            env_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, message: String) {
        self.errors.push(message);
    }

    pub fn add_warning(&mut self, message: String) {
        self.warnings.push(message);
    }

    pub fn is_valid(&self) -> bool {
        self.config_valid
            && self.plugins_valid
            && self.servers_valid
            && self.redis_valid
            && self.version_providers_valid
            && self.version_files_valid
            && self.env_valid
    }

    pub fn print_report(&self) {
        println!("=== DFS2 配置验证报告 ===\n");

        // 打印各组件状态
        println!(
            "📋 配置文件: {}",
            if self.config_valid {
                "✅ 有效"
            } else {
                "❌ 无效"
            }
        );
        println!(
            "🔌 插件系统: {}",
            if self.plugins_valid {
                "✅ 有效"
            } else {
                "❌ 无效"
            }
        );
        println!(
            "🌐 服务器连接: {}",
            if self.servers_valid {
                "✅ 有效"
            } else {
                "❌ 无效"
            }
        );
        println!(
            "🗃️  Redis连接: {}",
            if self.redis_valid {
                "✅ 有效"
            } else {
                "❌ 无效"
            }
        );
        println!(
            "🔄 版本提供者: {}",
            if self.version_providers_valid {
                "✅ 有效"
            } else {
                "❌ 无效"
            }
        );
        println!(
            "📄 版本文件: {}",
            if self.version_files_valid {
                "✅ 有效"
            } else {
                "❌ 无效"
            }
        );
        println!(
            "🔧 环境变量: {}",
            if self.env_valid {
                "✅ 有效"
            } else {
                "❌ 无效"
            }
        );

        // 打印错误
        if !self.errors.is_empty() {
            println!("\n❌ 错误 ({}):", self.errors.len());
            for (i, error) in self.errors.iter().enumerate() {
                println!("  {}. {}", i + 1, error);
            }
        }

        // 打印警告
        if !self.warnings.is_empty() {
            println!("\n⚠️  警告 ({}):", self.warnings.len());
            for (i, warning) in self.warnings.iter().enumerate() {
                println!("  {}. {}", i + 1, warning);
            }
        }

        // 打印总结
        println!("\n=== 验证结果 ===");
        if self.is_valid() {
            println!("✅ 配置验证通过，可以安全启动服务器");
        } else {
            println!("❌ 配置验证失败，请修复上述错误后重试");
        }

        if !self.warnings.is_empty() {
            println!("⚠️  存在 {} 个警告，建议检查", self.warnings.len());
        }
    }
}

/// 验证器结构
pub struct ConfigValidator;

impl ConfigValidator {
    /// 执行完整的配置验证
    pub async fn validate_full(
        config: &AppConfig,
        data_store: &DataStore,
    ) -> DfsResult<ValidationReport> {
        let mut report = ValidationReport::new();

        info!("开始配置验证...");

        // 1. 验证配置文件完整性
        Self::validate_config_completeness(config, &mut report).await;

        // 2. 验证插件JS语法
        Self::validate_plugins_syntax(config, data_store, &mut report).await;

        // 3. 验证服务器连接性
        let ping_failed = Self::validate_server_connectivity(config, data_store, &mut report).await;

        // 4. 验证Redis连接
        Self::validate_redis_connection(data_store, &mut report).await;

        // 5. 验证版本提供者配置和功能
        Self::validate_version_providers(config, data_store, &mut report).await;

        // 6. 验证版本文件跨节点一致性（配置了 version_files 时）
        Self::validate_version_files(config, data_store, &mut report, &ping_failed).await;

        // 7. 验证环境变量配置
        Self::validate_environment_variables(&mut report).await;

        info!("配置验证完成");
        Ok(report)
    }

    /// 验证配置文件完整性
    async fn validate_config_completeness(config: &AppConfig, report: &mut ValidationReport) {
        info!("验证配置文件完整性...");

        // 检查是否有服务器定义
        if config.servers.is_empty() {
            report.add_error("配置文件中未定义任何服务器".to_string());
            report.config_valid = false;
        } else {
            info!("找到 {} 个服务器配置", config.servers.len());
        }

        // 验证服务器h3_only/cert_hash配置
        let (h3_errors, h3_warnings) = config.validate_servers_transport();
        for e in &h3_errors {
            report.add_error(e.clone());
            report.config_valid = false;
        }
        for w in &h3_warnings {
            report.add_warning(w.clone());
        }

        // 检查是否有资源定义
        if config.resources.is_empty() {
            report.add_warning("配置文件中未定义任何资源".to_string());
        } else {
            info!("找到 {} 个资源配置", config.resources.len());
        }

        // 验证资源是否引用了有效的服务器
        for (resource_id, resource) in &config.resources {
            // 检查默认服务器列表
            for server_id in &resource.server {
                if !config.servers.contains_key(server_id) {
                    report.add_error(format!(
                        "资源 '{resource_id}' 引用了不存在的服务器 '{server_id}'"
                    ));
                    report.config_valid = false;
                }
            }

            // 检查tries列表中的服务器
            for server_id in &resource.tries {
                if !config.servers.contains_key(server_id) {
                    report.add_error(format!(
                        "资源 '{resource_id}' 的tries列表中引用了不存在的服务器 '{server_id}'"
                    ));
                    report.config_valid = false;
                }
            }

            // 验证版本配置：每个资源必须配置版本（静态或动态）
            let has_static_version = !resource.latest.is_empty();
            let has_dynamic_version = resource.version_provider.is_some();

            if !has_static_version && !has_dynamic_version {
                report.add_error(format!(
                    "资源 '{resource_id}' 缺少版本配置：必须配置 'latest' 字段或 'version_provider'"
                ));
                report.config_valid = false;
            }

            for version_file in &resource.version_files {
                if version_file.trim().is_empty() {
                    report.add_error(format!("资源 '{resource_id}' 的 version_files 包含空路径"));
                    report.config_valid = false;
                }
                if version_file.contains("..") {
                    report.add_error(format!(
                        "资源 '{resource_id}' 的 version_files 路径 '{version_file}' 非法"
                    ));
                    report.config_valid = false;
                }
            }
        }

        // flow 的节点引用与 resource.server / resource.tries 不同，不影响配置有效性：加载时已经
        // 摘除，运行时不会看到它们。这里只报告，让死引用能在部署前被发现而不阻断部署。
        for (resource_id, server_id) in &config.pruned_flow_server_refs {
            report.add_warning(format!(
                "资源 '{resource_id}' 的 flow 引用了未定义的服务器 '{server_id}'，该引用已被忽略"
            ));
        }

        // 检查插件配置
        if !config.plugins.is_empty() {
            info!("找到 {} 个插件配置", config.plugins.len());
        }

        // 验证版本提供者配置格式
        let mut resources_with_providers = 0;
        for (resource_id, resource) in &config.resources {
            if let Some(ref version_provider) = resource.version_provider {
                resources_with_providers += 1;

                // 验证类型字段
                if version_provider.r#type != "plugin" {
                    report.add_error(format!(
                        "资源 '{}' 的版本提供者类型 '{}' 不支持，目前只支持 'plugin'",
                        resource_id, version_provider.r#type
                    ));
                    report.config_valid = false;
                }

                // 验证插件名称格式
                if !version_provider
                    .plugin_name
                    .starts_with("version_provider_")
                {
                    report.add_error(format!(
                        "资源 '{}' 的版本提供者插件名称 '{}' 必须以 'version_provider_' 开头",
                        resource_id, version_provider.plugin_name
                    ));
                    report.config_valid = false;
                }

                // 验证插件是否存在
                if !config
                    .plugin_code
                    .contains_key(&version_provider.plugin_name)
                {
                    report.add_error(format!(
                        "资源 '{}' 引用的版本提供者插件 '{}' 不存在",
                        resource_id, version_provider.plugin_name
                    ));
                    report.config_valid = false;
                }

                // cache_ttl 是再次拉取插件的间隔，不是版本值的过期时间
                if let Some(cache_ttl) = version_provider.cache_ttl {
                    if cache_ttl < 60 {
                        report.add_warning(format!(
                            "资源 '{resource_id}' 的 cache_ttl ({cache_ttl}) 小于60秒，版本插件会过于频繁地请求上游"
                        ));
                    } else if cache_ttl > 86400 {
                        report.add_warning(format!(
                            "资源 '{resource_id}' 的 cache_ttl ({cache_ttl}) 大于24小时，版本要过很久才会再拉"
                        ));
                    }
                }

                // 验证webhook token长度
                if let Some(ref webhook_token) = version_provider.webhook_token
                    && webhook_token.len() < 16
                {
                    report.add_warning(format!(
                            "资源 '{resource_id}' 的webhook token 长度过短，建议至少16个字符以确保安全性"
                        ));
                }
            }
        }

        if resources_with_providers > 0 {
            info!("找到 {} 个配置了版本提供者的资源", resources_with_providers);
        }
    }

    /// 验证插件JS语法
    async fn validate_plugins_syntax(
        config: &AppConfig,
        data_store: &DataStore,
        report: &mut ValidationReport,
    ) {
        info!("验证插件JS语法...");

        if config.plugin_code.is_empty() {
            report.add_warning("未找到任何插件代码".to_string());
            return;
        }

        // 创建JS运行时进行语法检查
        let shared_config = SharedConfig::new(config.clone());
        let js_runner = JsRunner::new(shared_config, data_store.clone()).await;

        let mut valid_plugins = 0;

        for (plugin_id, plugin_code) in &config.plugin_code {
            info!("检查插件: {}", plugin_id);

            // 创建测试代码来验证语法，模拟真实的插件执行环境
            let test_code = format!(
                r#"
                (async () => {{
                    try {{
                        // 模拟插件运行环境的全局作用域
                        var exports; // 使用var允许重定义
                        
                        /* USER CODE START */
                        {plugin_code}
                        /* USER CODE END */
                        
                        // 检查是否正确设置了exports
                        if (typeof exports === 'function') {{
                            return {{ success: true, exports_type: "function" }};
                        }} else if (exports !== undefined) {{
                            return {{ success: true, exports_type: typeof exports }};
                        }} else {{
                            return {{ success: false, error: "插件未设置exports" }};
                        }}
                    }} catch (e) {{
                        return {{ success: false, error: e.message }};
                    }}
                }})()
                "#
            );

            match js_runner.eval(test_code).await {
                Ok(result) => {
                    // 尝试解析结果
                    if let Ok(test_result) = serde_json::from_value::<serde_json::Value>(result) {
                        if let Some(success) = test_result.get("success").and_then(|v| v.as_bool())
                        {
                            if success {
                                valid_plugins += 1;
                                info!("插件 '{}' 语法检查通过", plugin_id);
                            } else {
                                let error_msg = test_result
                                    .get("error")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("未知错误");
                                report
                                    .add_error(format!("插件 '{plugin_id}' 语法错误: {error_msg}"));
                                report.plugins_valid = false;
                            }
                        } else {
                            report.add_error(format!("插件 '{plugin_id}' 语法检查结果格式错误"));
                            report.plugins_valid = false;
                        }
                    } else {
                        report.add_error(format!("插件 '{plugin_id}' 语法检查结果无法解析"));
                        report.plugins_valid = false;
                    }
                }
                Err(e) => {
                    report.add_error(format!("插件 '{plugin_id}' 执行失败: {e}"));
                    report.plugins_valid = false;
                }
            }
        }

        info!(
            "插件语法检查完成: {}/{} 个插件通过",
            valid_plugins,
            config.plugin_code.len()
        );
    }

    /// 验证服务器连接性
    async fn validate_server_connectivity(
        config: &AppConfig,
        _data_store: &DataStore,
        report: &mut ValidationReport,
    ) -> HashSet<String> {
        info!("验证服务器连接性...");

        for (server_id, server_config) in &config.servers {
            if server_config.health_check_path.is_none() {
                info!(
                    "跳过服务器 '{}' 的连接性测试（未配置健康检查路径）",
                    server_id
                );
            }
        }

        // 与运行时普查共用同一套探测逻辑，避免 validate 通过而普查跳过的节点集合不一致
        let ping = ping_servers(config, PROBE_CONCURRENCY).await;

        for server_id in &ping.implementation_missing {
            // 服务器配置错误是致命问题
            report.add_error(format!("服务器 '{server_id}' 配置错误，无法创建服务器实现"));
            report.servers_valid = false;
        }

        let tested_servers = ping.probed.len();
        let valid_servers = ping.alive_count();
        let ping_failed = ping.unreachable();

        for result in &ping.probed {
            if result.is_alive {
                info!("服务器 '{}' 连接正常", result.server_id);
            } else {
                // 服务器连接失败只是警告，不影响配置验证结果
                report.add_warning(format!(
                    "服务器 '{}' 连接失败或不可用 (测试路径: {})",
                    result.server_id, result.health_check_path
                ));
            }
        }

        if tested_servers > 0 {
            info!(
                "服务器连接性检查完成: {}/{} 个测试服务器可用",
                valid_servers, tested_servers
            );
        } else {
            info!("未配置任何服务器的健康检查路径，跳过连接性测试");
        }

        // 注意：即使所有服务器都连接失败，也不设为错误，只记录警告
        // 因为这可能是临时网络问题，不应该阻止配置验证通过
        if tested_servers > 0 && valid_servers == 0 {
            report
                .add_warning("所有配置了健康检查的服务器当前都不可用，请检查网络连接".to_string());
        }

        ping_failed
    }

    /// 验证Redis连接
    async fn validate_redis_connection(data_store: &DataStore, report: &mut ValidationReport) {
        info!("验证Redis连接...");

        let store_type = std::env::var("DATA_STORE_TYPE").unwrap_or_else(|_| "file".to_string());

        if store_type == "redis" {
            // 尝试一个简单的Redis操作来测试连接
            let test_key = "dfs2_validation_test";
            let test_value = "test_connection";

            match data_store.set_string(test_key, test_value, Some(10)).await {
                Ok(()) => {
                    // 尝试读取
                    match data_store.get_string(test_key).await {
                        Ok(Some(value)) if value == test_value => {
                            info!("Redis连接测试成功");
                            // 清理测试数据
                            let _ = data_store.delete(test_key).await;
                        }
                        Ok(Some(_)) => {
                            report.add_error("Redis连接测试失败：读取的值不匹配".to_string());
                            report.redis_valid = false;
                        }
                        Ok(None) => {
                            report.add_error("Redis连接测试失败：无法读取写入的值".to_string());
                            report.redis_valid = false;
                        }
                        Err(e) => {
                            report.add_error(format!("Redis连接测试失败：读取失败 - {e}"));
                            report.redis_valid = false;
                        }
                    }
                }
                Err(e) => {
                    report.add_error(format!("Redis连接测试失败：写入失败 - {e}"));
                    report.redis_valid = false;
                }
            }
        } else {
            info!("使用文件存储后端，跳过Redis连接测试");
        }
    }

    /// 验证版本提供者配置和功能
    async fn validate_version_providers(
        config: &AppConfig,
        data_store: &DataStore,
        report: &mut ValidationReport,
    ) {
        info!("验证版本提供者功能...");

        // 找到所有配置了版本提供者的资源
        let resources_with_providers: Vec<(&String, &crate::config::ResourceConfig)> = config
            .resources
            .iter()
            .filter(|(_, resource)| resource.version_provider.is_some())
            .collect();

        if resources_with_providers.is_empty() {
            info!("未发现配置版本提供者的资源，跳过版本提供者功能验证");
            return;
        }

        info!(
            "发现 {} 个配置了版本提供者的资源，开始功能验证",
            resources_with_providers.len()
        );

        // 创建JS运行时和版本提供者系统
        let shared_config = SharedConfig::new(config.clone());
        let js_runner = JsRunner::new(shared_config.clone(), data_store.clone()).await;
        let plugin_provider = crate::modules::version_provider::PluginVersionProvider::new(
            js_runner,
            shared_config.clone(),
        );

        let mut successful_validations = 0;

        let total_resources = resources_with_providers.len();

        for (resource_id, resource) in &resources_with_providers {
            if let Some(ref version_provider) = resource.version_provider {
                info!(
                    "测试版本提供者插件: {} (资源: {})",
                    version_provider.plugin_name, resource_id
                );

                // 测试版本获取功能
                match plugin_provider.fetch_version_info(resource_id).await {
                    Ok(version_info) => {
                        // 验证返回的版本信息
                        if version_info.version.is_empty() {
                            report.add_error(format!(
                                "资源 '{}' 的版本提供者插件 '{}' 返回了空版本",
                                resource_id, version_provider.plugin_name
                            ));
                            report.version_providers_valid = false;
                        } else {
                            successful_validations += 1;
                            info!(
                                "版本提供者测试成功: {} -> 版本 '{}'",
                                resource_id, version_info.version
                            );

                            // 如果有元数据，记录一下
                            if let Some(ref metadata) = version_info.metadata {
                                info!(
                                    "版本元数据: {}",
                                    serde_json::to_string(metadata).unwrap_or_default()
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // 检查是否是API限制或网络问题（这些应该是警告而不是错误）
                        let error_msg = e.to_string().to_lowercase();
                        if error_msg.contains("rate limit")
                            || error_msg.contains("api limit")
                            || error_msg.contains("quota")
                        {
                            report.add_warning(format!(
                                "资源 '{}' 的版本提供者插件 '{}' 触发API限制: {}",
                                resource_id, version_provider.plugin_name, e
                            ));
                        } else if error_msg.contains("network")
                            || error_msg.contains("timeout")
                            || error_msg.contains("connection")
                        {
                            report.add_warning(format!(
                                "资源 '{}' 的版本提供者插件 '{}' 网络连接问题: {}",
                                resource_id, version_provider.plugin_name, e
                            ));
                        } else {
                            // 插件逻辑错误或配置错误应该是致命问题
                            report.add_error(format!(
                                "资源 '{}' 的版本提供者插件 '{}' 执行失败: {}",
                                resource_id, version_provider.plugin_name, e
                            ));
                            report.version_providers_valid = false;
                        }
                    }
                }

                // 稍微延迟以避免API限制
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        info!(
            "版本提供者功能验证完成: {}/{} 个成功",
            successful_validations, total_resources
        );

        if successful_validations == 0 && !resources_with_providers.is_empty() {
            report.add_warning("所有版本提供者测试都失败了，请检查插件配置和网络连接".to_string());
        }
    }

    /// Compare configured version files across replicas. No majority is a hard failure.
    async fn validate_version_files(
        config: &AppConfig,
        data_store: &DataStore,
        report: &mut ValidationReport,
        ping_failed: &HashSet<String>,
    ) {
        let has_version_files = config
            .resources
            .values()
            .any(|resource| !resource.version_files.is_empty());
        if !has_version_files {
            info!("未配置 version_files，跳过版本文件一致性检查");
            return;
        }

        info!("验证版本文件跨节点一致性...");
        let shared_config = SharedConfig::new(config.clone());
        let version_cache = std::sync::Arc::new(
            crate::modules::version_provider::VersionCache::new(data_store.clone()),
        );
        let js_runner = JsRunner::new(shared_config.clone(), data_store.clone()).await;
        let plugin_provider = std::sync::Arc::new(
            crate::modules::version_provider::PluginVersionProvider::new(
                js_runner,
                shared_config.clone(),
            ),
        );
        let version_updater =
            std::sync::Arc::new(crate::modules::version_provider::VersionUpdater::new(
                shared_config.clone(),
                version_cache.clone(),
                plugin_provider,
            ));
        let resource_service = crate::services::ResourceService::new(
            shared_config.clone(),
            version_cache,
            version_updater,
        );
        let version_file_service = crate::services::VersionFileService::new(
            shared_config,
            data_store.clone(),
            resource_service,
            None,
        );

        match version_file_service.census_all(true, ping_failed).await {
            Ok(census) => {
                for warning in census.warnings {
                    report.add_warning(warning);
                }
                if census.errors.is_empty() {
                    info!("版本文件一致性检查通过");
                } else {
                    for error in census.errors {
                        report.add_error(error);
                    }
                    report.version_files_valid = false;
                }
            }
            Err(e) => {
                report.add_error(format!("版本文件一致性检查失败: {e}"));
                report.version_files_valid = false;
            }
        }
    }

    /// 验证环境变量配置
    async fn validate_environment_variables(report: &mut ValidationReport) {
        info!("验证环境变量配置...");

        // 检查关键环境变量
        let important_vars = vec![
            ("RUST_LOG", false, "日志级别配置"),
            ("DATA_STORE_TYPE", false, "数据存储类型"),
            ("REDIS_URL", false, "Redis连接URL（如果使用Redis）"),
            ("CONFIG_PATH", false, "配置文件路径"),
            ("BIND_ADDRESS", false, "服务器绑定地址"),
        ];

        for (var_name, required, description) in important_vars {
            match std::env::var(var_name) {
                Ok(value) if !value.is_empty() => {
                    info!("环境变量 {} = {}", var_name, value);
                }
                Ok(_) => {
                    if required {
                        report.add_error(format!("环境变量 {var_name} 为空"));
                    } else {
                        report.add_warning(format!("环境变量 {var_name} 为空，将使用默认值"));
                    }
                }
                Err(_) => {
                    if required {
                        report.add_error(format!("缺少必需的环境变量 {var_name} ({description})"));
                    } else {
                        info!(
                            "环境变量 {} 未设置，将使用默认值 ({})",
                            var_name, description
                        );
                    }
                }
            }
        }

        // 特殊检查：如果使用Redis，确保REDIS_URL已设置
        let store_type = std::env::var("DATA_STORE_TYPE").unwrap_or_else(|_| "file".to_string());
        if store_type == "redis" && std::env::var("REDIS_URL").is_err() {
            report.add_warning("使用Redis存储但未设置REDIS_URL，将使用默认值".to_string());
        }

        if let Err(errors) = crate::modules::mcp::settings::validate_env() {
            for error in errors {
                report.add_error(error);
            }
            report.env_valid = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一份自身完整的配置，`flow` 留空——死引用的信息来自 `pruned_flow_server_refs`，
    /// 因为加载时已经把引用摘掉了，`flow` 里再也看不到它们。
    fn complete_config() -> AppConfig {
        let yaml = r#"
servers:
  real:
    id: real
    url: "https://real.example.com/"
    type: direct
plugins: {}
resources:
  app:
    latest: "1.0.0"
    versions:
      default:
        default: "path/${version}"
    tries: []
    server: []
    flow: []
"#;
        serde_yaml::from_str(yaml).expect("test config should parse")
    }

    #[tokio::test]
    async fn pruned_flow_refs_are_reported_without_failing_validation() {
        let mut config = complete_config();
        config.pruned_flow_server_refs = vec![("app".to_string(), "ghost".to_string())];
        let mut report = ValidationReport::new();

        ConfigValidator::validate_config_completeness(&config, &mut report).await;

        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("app") && w.contains("ghost") && w.contains("已被忽略")),
            "死引用应当报为警告并说明已被忽略，实际警告：{:?}",
            report.warnings
        );
        // 部署链路按退出码判断是否放行，死引用不能阻断部署。
        assert!(report.config_valid);
        assert!(report.is_valid());
    }

    #[tokio::test]
    async fn a_config_without_dead_refs_reports_no_such_warning() {
        let config = complete_config();
        let mut report = ValidationReport::new();

        ConfigValidator::validate_config_completeness(&config, &mut report).await;

        assert!(!report.warnings.iter().any(|w| w.contains("已被忽略")));
        assert!(report.is_valid());
    }

    #[tokio::test]
    async fn validate_does_not_publish_health_entries() {
        let mut config = crate::tests::mocks::create_default_test_config();
        for (id, server) in config.servers.iter_mut() {
            server.url = "http://127.0.0.1:1".into();
            server.health_check_path = Some(format!("/validate-health-{id}"));
        }
        config.server_impl.clear();
        for (id, server_config) in config.servers.iter() {
            if let Ok(server) = crate::modules::server::ServerImpl::new(server_config) {
                config.server_impl.insert(id.clone(), server);
            }
        }
        let env = crate::tests::mocks::TestEnvironment::with_config(config.clone()).await;
        let paths: Vec<(String, String)> = config
            .servers
            .iter()
            .filter_map(|(id, s)| {
                s.health_check_path
                    .as_ref()
                    .map(|p| (id.clone(), p.clone()))
            })
            .collect();
        ConfigValidator::validate_full(&config, &env.data_store)
            .await
            .unwrap();
        for (id, path) in paths {
            assert!(
                env.data_store
                    .get_health_info(&id, &path)
                    .await
                    .unwrap()
                    .is_none(),
                "validate must not write health:{id}:{path}"
            );
        }
    }
}
