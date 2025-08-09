use crate::{
    config::SharedConfig,
    error::{DfsError, DfsResult},
    models::{FlowContext, FlowOptions, FlowResult, FlowTarget, PluginMetadata},
    modules::{
        external::geolocation,
        flow::{FlowComp, FlowCond, FlowItem, FlowMode, FlowUse, ResourcePattern},
        qjs::JsRunner,
        storage::data_store::DataStore,
    },
};
use rand::Rng;
use std::collections::HashMap;
use tracing::info;

#[derive(Clone)]
pub struct FlowService {
    shared_config: SharedConfig,
    data_store: DataStore,
    js_runner: JsRunner,
}

impl FlowService {
    pub fn new(shared_config: SharedConfig, data_store: DataStore, js_runner: JsRunner) -> Self {
        Self {
            shared_config,
            data_store,
            js_runner,
        }
    }

    /// 纯函数式Flow执行，完全移除RunFlowParams依赖
    /// Flow只负责服务器选择决策，不处理CDN记录和惩罚查询
    pub async fn execute_flow(
        &self,
        target: &FlowTarget,
        context: &FlowContext,
        options: &FlowOptions,
        flow_items: &[FlowItem],
        penalty_servers: Vec<String>, // 外部传入惩罚服务器列表
    ) -> DfsResult<FlowResult> {
        let mut server_pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selected_server_id = None;
        let mut selected_server_weight = None;

        // 执行Flow pipeline
        for item in flow_items {
            let should_break = self
                .execute_flow_item(
                    &mut server_pool,
                    item,
                    target,
                    context,
                    options,
                    &mut plugin_server_mapping,
                    &penalty_servers,
                    &mut selected_server_id,
                    &mut selected_server_weight,
                )
                .await?;

            if should_break {
                break;
            }
        }

        // 最终poolize（如果需要）
        if server_pool.len() > 1
            || (server_pool.len() == 1 && !server_pool[0].0.starts_with("http"))
        {
            if let Some((server_id, weight)) = self
                .poolize_from_pool(
                    &mut server_pool,
                    target,
                    context,
                    options,
                    &plugin_server_mapping,
                    &penalty_servers,
                )
                .await?
            {
                selected_server_id = Some(server_id);
                selected_server_weight = Some(weight);
            }
        }

        if server_pool.is_empty() {
            return Err(DfsError::internal_error("NO_RES_AVAILABLE"));
        }

        Ok(FlowResult {
            url: server_pool[0].0.clone(),
            selected_server_id,
            selected_server_weight,
            plugin_server_mapping,
        })
    }

    /// 执行单个Flow项目
    async fn execute_flow_item(
        &self,
        pool: &mut Vec<(String, u32)>,
        item: &FlowItem,
        target: &FlowTarget,
        context: &FlowContext,
        options: &FlowOptions,
        plugin_server_mapping: &mut HashMap<String, (Option<String>, bool)>,
        penalty_servers: &[String],
        selected_server_id: &mut Option<String>,
        selected_server_weight: &mut Option<u32>,
    ) -> DfsResult<bool> {
        // 评估规则
        let should_exec = if !item.rules.is_empty() {
            self.evaluate_flow_rules(&item.rules, &item.mode, target, context)
                .await?
        } else {
            true
        };

        if should_exec {
            for operation in &item.r#use {
                match operation {
                    FlowUse::Clear => pool.clear(),
                    FlowUse::Server { id, weight } => {
                        // 检查服务器是否在惩罚列表中
                        if !penalty_servers.contains(id) {
                            pool.push((id.clone(), *weight));
                        }
                    }
                    FlowUse::Plugin { id, indirect } => {
                        let result = self
                            .execute_plugin(id, indirect, pool.clone(), &context.extras)
                            .await?;
                        self.process_plugin_result(result, pool, plugin_server_mapping)?;
                    }
                    FlowUse::Poolize => {
                        if let Some((server_id, weight)) = self
                            .poolize_from_pool(
                                pool,
                                target,
                                context,
                                options,
                                plugin_server_mapping,
                                penalty_servers,
                            )
                            .await?
                        {
                            // Poolize成功，保存服务器选择信息
                            *selected_server_id = Some(server_id);
                            *selected_server_weight = Some(weight);
                        }
                    }
                }
            }
        }

        Ok(item.r#break)
    }

    /// 从pool中选择服务器并生成URL（不涉及CDN记录）
    async fn poolize_from_pool(
        &self,
        pool: &mut Vec<(String, u32)>,
        target: &FlowTarget,
        context: &FlowContext,
        options: &FlowOptions,
        plugin_server_mapping: &HashMap<String, (Option<String>, bool)>,
        penalty_servers: &[String],
    ) -> DfsResult<Option<(String, u32)>> {
        // 应用惩罚：降低惩罚服务器的权重
        self.apply_penalty_to_pool(pool, penalty_servers);

        // 权重随机选择
        let selected_server = self.weighted_random_selection(pool)?;

        // 健康检查
        if self.is_server_healthy(&selected_server, target).await? {
            // 生成URL
            let url = self
                .generate_server_url(&selected_server, target, context, options)
                .await?;
            pool.clear();
            pool.push((url, selected_server.1));
            Ok(Some(selected_server))
        } else {
            // 服务器不健康，从pool中移除并重试
            pool.retain(|x| x.0 != selected_server.0);
            if !pool.is_empty() {
                Box::pin(self.poolize_from_pool(
                    pool,
                    target,
                    context,
                    options,
                    plugin_server_mapping,
                    penalty_servers,
                ))
                .await
            } else {
                Ok(None)
            }
        }
    }

    /// 评估Flow规则（只使用必要的参数）
    async fn evaluate_flow_rules(
        &self,
        rules: &[FlowCond],
        mode: &FlowMode,
        target: &FlowTarget,
        context: &FlowContext,
    ) -> DfsResult<bool> {
        if rules.is_empty() {
            return Ok(true);
        }

        match mode {
            FlowMode::AND => {
                for rule in rules {
                    if !self.evaluate_condition(rule, target, context).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            FlowMode::OR => {
                for rule in rules {
                    if self.evaluate_condition(rule, target, context).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    /// 评估单个条件
    async fn evaluate_condition(
        &self,
        condition: &FlowCond,
        target: &FlowTarget,
        context: &FlowContext,
    ) -> DfsResult<bool> {
        match condition {
            FlowCond::CnIp(expected_is_cn) => {
                if let Some(client_ip) = context.client_ip {
                    let is_global = geolocation::is_global_ip(client_ip);
                    let is_cn = !is_global;
                    Ok(*expected_is_cn == is_cn)
                } else {
                    Ok(false)
                }
            }
            FlowCond::IpVersion(expected_version) => {
                if let Some(client_ip) = context.client_ip {
                    let actual_version = if geolocation::is_ipv6(client_ip) {
                        6
                    } else {
                        4
                    };
                    Ok(actual_version == *expected_version)
                } else {
                    Ok(false)
                }
            }
            FlowCond::Cidr(cidr) => {
                if let Some(client_ip) = context.client_ip {
                    Ok(cidr.contains(&client_ip))
                } else {
                    Ok(false)
                }
            }
            FlowCond::Extras(key) => {
                // 检查extras中是否存在指定的key（不管值是什么）
                Ok(context.extras.get(key).is_some())
            }
            FlowCond::GeoIp(keyword) => {
                // 检查IP地址的位置信息是否包含指定关键词（不区分大小写）
                if let Some(client_ip) = context.client_ip {
                    if let Some(location_data) = geolocation::get_ip_location_data(client_ip) {
                        Ok(location_data
                            .to_lowercase()
                            .contains(&keyword.to_lowercase()))
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            FlowCond::Size(comp, expected_size) => {
                if let Some(file_size) = target.file_size {
                    let expected_bytes = expected_size.bytes() as u64;
                    let result = match comp {
                        FlowComp::Eq => file_size == expected_bytes,
                        FlowComp::Ne => file_size != expected_bytes,
                        FlowComp::Gt => file_size > expected_bytes,
                        FlowComp::Ge => file_size >= expected_bytes,
                        FlowComp::Lt => file_size < expected_bytes,
                        FlowComp::Le => file_size <= expected_bytes,
                    };
                    Ok(result)
                } else {
                    Ok(false)
                }
            }
            FlowCond::ResourceBwDaily(pattern, comp, limit) => {
                // 资源级别的带宽限制检查
                let current_usage = match pattern {
                    ResourcePattern::Global => {
                        // 全局流量统计
                        self.data_store
                            .get_global_daily_bandwidth()
                            .await
                            .unwrap_or(0)
                    }
                    ResourcePattern::Current => {
                        // 当前资源流量统计
                        self.data_store
                            .get_resource_daily_bandwidth(&target.resource_id)
                            .await
                            .unwrap_or(0)
                    }
                    ResourcePattern::Specific(resource_id) => {
                        // 指定资源流量统计
                        self.data_store
                            .get_resource_daily_bandwidth(resource_id)
                            .await
                            .unwrap_or(0)
                    }
                };

                let limit_bytes = limit.bytes() as u64;
                Ok(match comp {
                    FlowComp::Eq => current_usage == limit_bytes,
                    FlowComp::Ne => current_usage != limit_bytes,
                    FlowComp::Gt => current_usage > limit_bytes,
                    FlowComp::Ge => current_usage >= limit_bytes,
                    FlowComp::Lt => current_usage < limit_bytes,
                    FlowComp::Le => current_usage <= limit_bytes,
                })
            }
            FlowCond::ServerBwDaily(server_id, comp, limit) => {
                // 服务器级别的带宽限制检查：使用指定的server_id
                let today = chrono::Local::now().format("%Y-%m-%d").to_string();
                let cache_key = if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
                    if !prefix.is_empty() {
                        format!("{prefix}:server_bw_daily:{server_id}:{today}")
                    } else {
                        format!("server_bw_daily:{server_id}:{today}")
                    }
                } else {
                    format!("server_bw_daily:{server_id}:{today}")
                };

                if let Ok(Some(usage_str)) = self.data_store.get_string(&cache_key).await {
                    if let Ok(current_usage) = usage_str.parse::<u64>() {
                        let limit_bytes = limit.bytes() as u64;
                        return Ok(match comp {
                            FlowComp::Eq => current_usage == limit_bytes,
                            FlowComp::Ne => current_usage != limit_bytes,
                            FlowComp::Gt => current_usage > limit_bytes,
                            FlowComp::Ge => current_usage >= limit_bytes,
                            FlowComp::Lt => current_usage < limit_bytes,
                            FlowComp::Le => current_usage <= limit_bytes,
                        });
                    }
                }
                // 如果没有使用量数据，假设使用量为0
                let limit_bytes = limit.bytes() as u64;
                Ok(match comp {
                    FlowComp::Eq => 0 == limit_bytes,
                    FlowComp::Ne => 0 != limit_bytes,
                    FlowComp::Gt => false, // 0不可能大于正数
                    FlowComp::Ge => limit_bytes == 0,
                    FlowComp::Lt => limit_bytes > 0,
                    FlowComp::Le => true, // 0总是小于等于任何数
                })
            }
            FlowCond::Time(comp, expected_time) => {
                let current_time = chrono::Local::now().time();
                Ok(match comp {
                    FlowComp::Eq => current_time == *expected_time,
                    FlowComp::Ne => current_time != *expected_time,
                    FlowComp::Gt => current_time > *expected_time,
                    FlowComp::Ge => current_time >= *expected_time,
                    FlowComp::Lt => current_time < *expected_time,
                    FlowComp::Le => current_time <= *expected_time,
                })
            }
        }
    }

    /// 执行插件
    async fn execute_plugin(
        &self,
        id: &str,
        indirect: &str,
        pool: Vec<(String, u32)>,
        extras: &serde_json::Value,
    ) -> DfsResult<serde_json::Value> {
        let config = self.shared_config.load();
        let plugin_options = config.plugins.get(id);

        if let Some(code) = config.plugin_code.get(id) {
            let js_code = format!(
                r#"
                (async (pool, indirect, options, extras, exports) => {{
                    /* USER CODE START */
                    {}
                    /* USER CODE END */
                    let ret = await exports?.(pool, indirect, options, extras) || false;
                    return [ret, pool];
                }})({}, {}, {}, {})
                "#,
                code,
                serde_json::to_string(&pool).unwrap_or_else(|_| "[]".to_string()),
                serde_json::to_string(indirect).unwrap_or_else(|_| "false".to_string()),
                serde_json::to_string(&plugin_options.unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_else(|_| "null".to_string()),
                serde_json::to_string(extras).unwrap_or_else(|_| "{}".to_string()),
            );

            let result =
                self.js_runner.eval(js_code).await.map_err(|e| {
                    DfsError::internal_error(format!("Plugin execution failed: {e}"))
                })?;
            Ok(result)
        } else {
            Err(DfsError::internal_error(format!("Plugin {id} not found")))
        }
    }

    /// 处理插件结果
    fn process_plugin_result(
        &self,
        result: serde_json::Value,
        pool: &mut Vec<(String, u32)>,
        plugin_server_mapping: &mut HashMap<String, (Option<String>, bool)>,
    ) -> DfsResult<()> {
        // 尝试解析增强格式
        if let Ok((_should_break, enhanced_pool)) = serde_json::from_value::<(
            bool,
            Vec<(String, u32, Option<PluginMetadata>)>,
        )>(result.clone())
        {
            pool.clear();
            for (url, weight, metadata) in enhanced_pool {
                pool.push((url.clone(), weight));

                if let Some(metadata) = metadata {
                    plugin_server_mapping.insert(
                        url,
                        (metadata.server_id, metadata.skip_penalty.unwrap_or(false)),
                    );
                }
            }
        } else {
            // 兼容旧格式
            let (_should_break, basic_pool): (bool, Vec<(String, u32)>) =
                serde_json::from_value(result).map_err(|e| {
                    DfsError::internal_error(format!("Failed to parse plugin result: {e}"))
                })?;
            pool.clear();
            pool.extend(basic_pool);
        }
        Ok(())
    }

    /// 应用惩罚到pool（降低权重而不是移除）
    fn apply_penalty_to_pool(&self, pool: &mut [(String, u32)], penalty_servers: &[String]) {
        if penalty_servers.is_empty() {
            return;
        }

        let mut non_penalized_min_weight = u32::MAX;
        for (server_name, weight) in pool.iter() {
            if !penalty_servers.contains(server_name) {
                non_penalized_min_weight = non_penalized_min_weight.min(*weight);
            }
        }

        if non_penalized_min_weight != u32::MAX {
            for (server_name, weight) in pool.iter_mut() {
                if penalty_servers.contains(server_name) {
                    info!(
                        "Applied penalty to server {} for repeated request: {} -> {}",
                        server_name, *weight, non_penalized_min_weight
                    );
                    *weight = non_penalized_min_weight;
                }
            }
        }
    }

    /// 权重随机选择
    fn weighted_random_selection(&self, pool: &[(String, u32)]) -> DfsResult<(String, u32)> {
        let total_weight: u32 = pool.iter().map(|(_, weight)| *weight).sum();
        if total_weight == 0 {
            return Err(DfsError::internal_error(
                "No valid servers with positive weight",
            ));
        }

        let mut rng = rand::rng();
        let mut random_weight = rng.random_range(0..total_weight);

        for (server_id, weight) in pool.iter() {
            if random_weight <= *weight {
                return Ok((server_id.clone(), *weight));
            }
            random_weight -= weight;
        }

        // 不应该到达这里
        Err(DfsError::internal_error("Weighted selection failed"))
    }

    /// 检查服务器健康状态
    async fn is_server_healthy(
        &self,
        server: &(String, u32),
        target: &FlowTarget,
    ) -> DfsResult<bool> {
        let config = self.shared_config.load();
        if let Some(server_impl) = config.get_server(&server.0) {
            let resource = config
                .get_resource(&target.resource_id)
                .ok_or_else(|| DfsError::resource_not_found(&target.resource_id))?;

            // 获取版本路径
            let path = if let Some(version_map) = resource.versions.get(&target.version) {
                if let Some(server_id) = Some(&server.0) {
                    version_map
                        .get(server_id)
                        .or_else(|| version_map.get("default"))
                } else {
                    version_map.get("default")
                }
            } else {
                resource
                    .versions
                    .get("default")
                    .and_then(|default_template| {
                        default_template
                            .get(&server.0)
                            .or_else(|| default_template.get("default"))
                    })
            };

            let health_check_path = path
                .map(|p| p.replace("${version}", &target.version))
                .ok_or_else(|| DfsError::path_not_found(&target.resource_id, &target.version))?;

            Ok(server_impl
                .is_alive(&server.0, &health_check_path, Some(&self.data_store))
                .await)
        } else {
            Ok(false)
        }
    }

    /// 生成服务器URL
    async fn generate_server_url(
        &self,
        server: &(String, u32),
        target: &FlowTarget,
        context: &FlowContext,
        options: &FlowOptions,
    ) -> DfsResult<String> {
        let config = self.shared_config.load();
        if let Some(server_impl) = config.get_server(&server.0) {
            // 简化版路径获取，直接访问配置
            let resource = config
                .get_resource(&target.resource_id)
                .ok_or_else(|| DfsError::resource_not_found(&target.resource_id))?;

            // 获取版本路径
            let path = if let Some(version_map) = resource.versions.get(&target.version) {
                version_map
                    .get(&server.0)
                    .or_else(|| version_map.get("default"))
            } else {
                resource
                    .versions
                    .get("default")
                    .and_then(|default_template| {
                        default_template
                            .get(&server.0)
                            .or_else(|| default_template.get("default"))
                    })
            };

            let base_path = path
                .map(|p| p.replace("${version}", &target.version))
                .ok_or_else(|| DfsError::path_not_found(&target.resource_id, &target.version))?;

            // 处理前缀路径
            let url_path = match (resource.resource_type.as_str(), &target.sub_path) {
                ("prefix", Some(sub)) => {
                    let normalized_sub = normalize_path_simple(sub);
                    let clean_prefix = base_path.trim_end_matches('/');
                    format!("{clean_prefix}{normalized_sub}")
                }
                ("prefix", None) => {
                    return Err(DfsError::path_not_found(
                        &target.resource_id,
                        &target.version,
                    ));
                }
                (_, _) => base_path,
            };

            let url_ranges = if options.cdn_full_range {
                None
            } else {
                target.ranges.clone()
            };

            server_impl
                .url(
                    &url_path,
                    url_ranges,
                    context.session_id.as_deref(),
                    Some(&self.data_store),
                )
                .await
                .map_err(|e| DfsError::internal_error(format!("URL generation failed: {e}")))
        } else {
            Err(DfsError::server_unavailable(&server.0))
        }
    }
}

/// 简化版路径标准化函数（用于FlowService内部）
fn normalize_path_simple(path: &str) -> String {
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
