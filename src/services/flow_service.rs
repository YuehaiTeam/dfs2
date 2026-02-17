use crate::{
    config::{CertHashPolicy, ServerConfig, SharedConfig},
    error::{DfsError, DfsResult},
    models::{FlowContext, FlowJsContext, FlowOptions, FlowResult, FlowTarget, PluginMetadata},
    modules::{
        external::geolocation,
        flow::{FlowComp, FlowCond, FlowItem, FlowMode, FlowUse, ResourcePattern},
        qjs::JsRunner,
        server::HealthInfo,
        storage::data_store::DataStore,
    },
};
use rand::Rng;
use std::collections::HashMap;
use tracing::{debug, info};
use url::Url;

#[derive(Clone)]
pub struct FlowService {
    shared_config: SharedConfig,
    data_store: DataStore,
    js_runner: JsRunner,
    bandwidth_cache: crate::services::BandwidthCacheService,
    resource_service: crate::services::ResourceService,
}

impl FlowService {
    pub fn new(
        shared_config: SharedConfig,
        data_store: DataStore,
        js_runner: JsRunner,
        bandwidth_cache: crate::services::BandwidthCacheService,
        resource_service: crate::services::ResourceService,
    ) -> Self {
        Self {
            shared_config,
            data_store,
            js_runner,
            bandwidth_cache,
            resource_service,
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
        session: Option<&crate::models::Session>,
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
                    session,
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

        // Post-pipeline h3_only URL rewrite: catch plugin literal URLs
        let mut final_url = server_pool[0].0.clone();
        if let Some(ref server_id) = selected_server_id {
            let config = self.shared_config.load();
            if let Some(server_config) = config.servers.get(server_id)
                && server_config.h3_only
            {
                let health_info = self.get_health_info_for_server(server_id, target).await;
                final_url = rewrite_h3_url(final_url, server_config, health_info.as_ref())?;
            }
        }

        Ok(FlowResult {
            url: final_url,
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
        session: Option<&crate::models::Session>,
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
                        if penalty_servers.contains(id) {
                            continue;
                        }

                        // h3_only gate: skip h3_only servers when client is not h3-capable
                        let config = self.shared_config.load();
                        if let Some(server_config) = config.servers.get(id)
                            && server_config.h3_only
                            && !context.h3_capable
                        {
                            debug!(
                                server = %id,
                                "Skipping h3_only server: client is not h3-capable"
                            );
                            continue;
                        }

                        pool.push((id.clone(), *weight));
                    }
                    FlowUse::Plugin { id, indirect } => {
                        let flow_context = FlowJsContext {
                            target: target.clone(),
                            context: context.clone(),
                            options: options.clone(),
                            session: session.cloned(),
                        };
                        let result = self
                            .execute_plugin(id, indirect, pool.clone(), &flow_context)
                            .await?;
                        self.process_plugin_result(result, pool, plugin_server_mapping)?;

                        // h3_only gate for plugin-returned entries that resolve to a server_id
                        if !context.h3_capable {
                            let config = self.shared_config.load();
                            pool.retain(|(url, _weight)| {
                                if let Some((Some(server_id), _)) = plugin_server_mapping.get(url)
                                    && let Some(server_config) = config.servers.get(server_id)
                                    && server_config.h3_only
                                {
                                    debug!(
                                        server = %server_id,
                                        url = %url,
                                        "Skipping h3_only plugin server: client is not h3-capable"
                                    );
                                    return false;
                                }
                                true
                            });
                        }
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
            FlowCond::ServerBwMinutes(server_id, minutes, comp, limit) => {
                // 服务器分钟级流量限制检查：使用缓存服务
                let current_usage = self
                    .bandwidth_cache
                    .get_server_minutes_bandwidth(server_id, *minutes)
                    .await
                    .unwrap_or(0);

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
        flow_context: &FlowJsContext,
    ) -> DfsResult<serde_json::Value> {
        let config = self.shared_config.load();
        let plugin_options = config.plugins.get(id);

        if let Some(code) = config.plugin_code.get(id) {
            let js_code = format!(
                r#"
                (async (pool, indirect, options, flowContext, exports) => {{
                    /* USER CODE START */
                    {}
                    /* USER CODE END */
                    let ret = await exports?.(pool, indirect, options, flowContext) || false;
                    return [ret, pool];
                }})({}, {}, {}, {})
                "#,
                code,
                serde_json::to_string(&pool).unwrap_or_else(|_| "[]".to_string()),
                serde_json::to_string(indirect).unwrap_or_else(|_| "false".to_string()),
                serde_json::to_string(&plugin_options.unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_else(|_| "null".to_string()),
                serde_json::to_string(flow_context).unwrap_or_else(|_| "{}".to_string()),
            );

            let result =
                self.js_runner.eval(js_code).await.map_err(|e| {
                    DfsError::internal_error(format!("Plugin execution failed: {}", e))
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
        if let (Some(server_impl), Some(server_config)) =
            (config.get_server(&server.0), config.servers.get(&server.0))
        {
            // 首先验证资源和版本，获取有效版本
            let (validated_resource_id, effective_version) = self
                .resource_service
                .validate_resource_and_version(
                    &target.resource_id,
                    &target.version,
                    target.sub_path.as_deref(),
                )
                .await?;

            // 使用统一的路径获取函数，支持前缀资源和子路径
            let health_check_path = self
                .resource_service
                .get_version_path(
                    &validated_resource_id,
                    &effective_version,
                    Some(&server.0),
                    target.sub_path.as_deref(),
                )
                .ok_or_else(|| {
                    DfsError::path_not_found(&validated_resource_id, &effective_version)
                })?;

            Ok(server_impl
                .is_alive(
                    &server.0,
                    server_config,
                    &health_check_path,
                    Some(&self.data_store),
                )
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

            let url = server_impl
                .url(
                    &url_path,
                    url_ranges,
                    context.session_id.as_deref(),
                    Some(&self.data_store),
                )
                .await
                .map_err(|e| DfsError::internal_error(format!("URL generation failed: {e}")))?;

            // Apply h3_only URL rewrite if applicable
            if let Some(server_config) = config.servers.get(&server.0)
                && server_config.h3_only
            {
                let health_info = self.get_health_info_for_server(&server.0, target).await;
                return rewrite_h3_url(url, server_config, health_info.as_ref());
            }

            Ok(url)
        } else {
            Err(DfsError::server_unavailable(&server.0))
        }
    }

    /// Retrieve cached HealthInfo for a server, used for h3_only cert hash resolution.
    async fn get_health_info_for_server(
        &self,
        server_id: &str,
        target: &FlowTarget,
    ) -> Option<HealthInfo> {
        // Try to resolve the health check path for this resource/version
        let path = self.resource_service.get_version_path(
            &target.resource_id,
            &target.version,
            Some(server_id),
            target.sub_path.as_deref(),
        );
        if let Some(health_check_path) = path {
            self.data_store
                .get_health_info(server_id, &health_check_path)
                .await
                .ok()
                .flatten()
        } else {
            None
        }
    }
}

/// Rewrite a URL for h3_only servers: change scheme from https to http3
/// and optionally append #cert={hash} fragment based on the server's cert hash policy.
///
/// Only rewrites URLs with "https" scheme. Non-https URLs are returned unchanged.
fn rewrite_h3_url(
    original_url: String,
    server_config: &ServerConfig,
    health_info: Option<&HealthInfo>,
) -> DfsResult<String> {
    let url = Url::parse(&original_url).map_err(|e| {
        DfsError::internal_error(format!("Failed to parse URL for h3 rewrite: {e}"))
    })?;

    // Only rewrite https URLs
    if url.scheme() != "https" {
        return Ok(original_url);
    }

    // Determine cert fragment based on policy
    let fragment = match server_config.cert_hash_policy() {
        Ok(CertHashPolicy::ValidCert) => {
            // No fragment needed
            None
        }
        Ok(CertHashPolicy::Trust) => {
            // Need observed_cert_hash from health_info
            if let Some(hash) = health_info.and_then(|h| h.observed_cert_hash.as_ref()) {
                let normalized = hash.to_ascii_lowercase();
                Some(format!("cert={}", normalized))
            } else {
                return Err(DfsError::internal_error(
                    "h3_only server with cert_hash=trust but no observed cert hash available",
                ));
            }
        }
        Ok(CertHashPolicy::PinnedHex(bytes)) => {
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            Some(format!("cert={}", hex))
        }
        Err(e) => {
            return Err(DfsError::internal_error(format!(
                "Invalid cert_hash policy: {e}"
            )));
        }
    };

    // Build the rewritten URL by replacing the scheme via string manipulation.
    // url::Url::set_scheme() rejects transitions from special schemes (https) to
    // non-special schemes (http3), so we construct the result manually.
    // We strip the existing fragment (url crate separates it) and append ours.
    let without_fragment = {
        let s = url.as_str();
        // url.fragment() returns the part after '#', or None
        if url.fragment().is_some() {
            // Remove the trailing #fragment
            &s[..s.rfind('#').unwrap_or(s.len())]
        } else {
            s
        }
    };

    // Replace "https://" prefix with "http3://"
    let rewritten = format!("http3://{}", &without_fragment["https://".len()..]);

    // Append fragment if needed
    match fragment {
        Some(frag) => Ok(format!("{}#{}", rewritten, frag)),
        None => Ok(rewritten),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::common::TestEnvironment;
    use serde_json::json;
    use size::Size;
    use std::collections::HashMap;

    /// 创建标准测试上下文
    fn create_test_context() -> (FlowTarget, FlowContext, FlowOptions) {
        let target = FlowTarget {
            resource_id: "test_resource".to_string(),
            version: "1.0.0".to_string(),
            file_size: Some(1024 * 1024), // 1MB
            sub_path: None,
            ranges: None,
        };

        let context = FlowContext {
            client_ip: Some("192.168.1.100".parse().unwrap()), // 私有IP，模拟中国用户
            session_id: Some("test_session".to_string()),
            extras: json!({"test_flag": true}),
            h3_capable: false,
        };

        let options = FlowOptions {
            cdn_full_range: false,
        };

        (target, context, options)
    }

    /// 创建测试FlowService
    async fn create_test_flow_service() -> FlowService {
        let env = TestEnvironment::new().await;
        env.services.flow_service
    }

    #[tokio::test]
    async fn test_evaluate_condition() {
        let service = create_test_flow_service().await;
        let (target, mut context, _options) = create_test_context();

        // 测试 CnIp 条件
        // 在测试环境中，没有IPIP数据库，is_global_ip默认返回true
        // 因此所有IP都被认为是全球IP (!is_global_ip = false)
        context.client_ip = Some("192.168.1.100".parse().unwrap());
        let result = service
            .evaluate_condition(&FlowCond::CnIp(true), &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            false,
            "Without IPDB, all IPs are considered global (non-CN)"
        );

        // 测试cnip false条件 - 应该返回true（因为所有IP都是全球IP）
        let result = service
            .evaluate_condition(&FlowCond::CnIp(false), &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "Without IPDB, cnip false should return true"
        );

        // 测试不同IP地址 - 在没有IPDB的情况下结果应该相同
        context.client_ip = Some("8.8.8.8".parse().unwrap());
        let result = service
            .evaluate_condition(&FlowCond::CnIp(false), &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "All IPs should be treated as global without IPDB"
        );

        // 无IP情况
        context.client_ip = None;
        let result = service
            .evaluate_condition(&FlowCond::CnIp(true), &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false, "No IP should return false");

        // 测试 IpVersion 条件
        context.client_ip = Some("192.168.1.100".parse().unwrap()); // IPv4
        let result = service
            .evaluate_condition(&FlowCond::IpVersion(4), &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true, "IPv4 address should match version 4");

        context.client_ip = Some("::1".parse().unwrap()); // IPv6
        let result = service
            .evaluate_condition(&FlowCond::IpVersion(6), &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true, "IPv6 address should match version 6");

        // 测试 Size 条件
        let mut sized_target = target.clone();
        sized_target.file_size = Some(1048576); // 精确的1MB = 1024*1024字节

        // size > 500KB (500*1024 = 512000字节)
        let size_500kb = Size::from_str("500KB").unwrap();
        let result = service
            .evaluate_condition(
                &FlowCond::Size(FlowComp::Gt, size_500kb),
                &sized_target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "1048576 bytes should be greater than 500KB"
        );

        // size < 2MB (2*1024*1024 = 2097152字节)
        let size_2mb = Size::from_str("2MB").unwrap();
        let result = service
            .evaluate_condition(
                &FlowCond::Size(FlowComp::Lt, size_2mb),
                &sized_target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "1048576 bytes should be less than 2MB"
        );

        // size >= 1MB - 使用>=比较来避免精度问题
        let size_1mb = Size::from_str("1MB").unwrap();
        let result = service
            .evaluate_condition(
                &FlowCond::Size(FlowComp::Ge, size_1mb),
                &sized_target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true, "1048576 bytes should be >= 1MB");

        // 测试精确相等 - 使用已知的字节数
        sized_target.file_size = Some(size_1mb.bytes() as u64);
        let result = service
            .evaluate_condition(
                &FlowCond::Size(FlowComp::Eq, size_1mb.clone()),
                &sized_target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true, "Exact bytes should equal");

        // 无文件大小情况
        sized_target.file_size = None;
        let result = service
            .evaluate_condition(
                &FlowCond::Size(FlowComp::Gt, size_500kb),
                &sized_target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false, "No file size should return false");

        // 测试 Extras 条件
        let result = service
            .evaluate_condition(
                &FlowCond::Extras("test_flag".to_string()),
                &target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "Existing extra field should return true"
        );

        let result = service
            .evaluate_condition(
                &FlowCond::Extras("nonexistent".to_string()),
                &target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            false,
            "Non-existing extra field should return false"
        );

        // 测试 Time 条件 (使用固定时间进行测试)
        let earlier_time = chrono::NaiveTime::from_hms_opt(9, 0, 0).unwrap();

        // 由于time条件使用当前时间，我们主要测试逻辑结构
        let result = service
            .evaluate_condition(
                &FlowCond::Time(FlowComp::Ge, earlier_time),
                &target,
                &context,
            )
            .await;
        assert!(result.is_ok(), "Time condition should not error");

        println!("✅ All condition evaluation tests passed");
    }

    #[tokio::test]
    async fn test_evaluate_flow_rules() {
        let service = create_test_flow_service().await;
        let (target, mut context, _options) = create_test_context();

        // 测试空规则 - 应该返回true
        let result = service
            .evaluate_flow_rules(&[], &FlowMode::AND, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true, "Empty rules should return true");

        // 测试AND模式 - 所有条件必须满足
        // 在测试环境中使用cnip false（全球IP）和文件大小条件
        context.client_ip = Some("192.168.1.100".parse().unwrap()); // 任意IP
        let mut sized_target = target.clone();
        sized_target.file_size = Some(2 * 1024 * 1024); // 2MB

        let and_rules = vec![
            FlowCond::CnIp(false), // 全球IP (在测试环境中总是true)
            FlowCond::Size(FlowComp::Gt, Size::from_str("1MB").unwrap()), // 大于1MB
        ];

        // 全球IP + 2MB文件 -> 两个条件都满足 -> true
        let result = service
            .evaluate_flow_rules(&and_rules, &FlowMode::AND, &sized_target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "AND mode: both conditions true should return true"
        );

        // 全球IP + 500KB文件 -> 大小条件不满足 -> false
        sized_target.file_size = Some(500 * 1024); // 500KB
        let result = service
            .evaluate_flow_rules(&and_rules, &FlowMode::AND, &sized_target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            false,
            "AND mode: one condition false should return false"
        );

        // 测试使用cnip true的场景 - 应该总是失败
        let cn_ip_rules = vec![FlowCond::CnIp(true)]; // 中国IP条件
        let result = service
            .evaluate_flow_rules(&cn_ip_rules, &FlowMode::AND, &sized_target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            false,
            "Without IPDB, cnip true should always be false"
        );

        // 测试OR模式 - 任一条件满足即可
        let or_rules = vec![
            FlowCond::CnIp(false), // 全球IP (总是true)
            FlowCond::Size(FlowComp::Gt, Size::from_str("1MB").unwrap()), // 大于1MB
        ];

        // 全球IP + 500KB文件 -> IP条件满足 -> true
        context.client_ip = Some("192.168.1.100".parse().unwrap());
        sized_target.file_size = Some(500 * 1024); // 500KB
        let result = service
            .evaluate_flow_rules(&or_rules, &FlowMode::OR, &sized_target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "OR mode: one condition true should return true"
        );

        // 测试都不满足的OR情况
        let impossible_or_rules = vec![
            FlowCond::CnIp(true), // 中国IP (总是false)
            FlowCond::Size(FlowComp::Gt, Size::from_str("10MB").unwrap()), // 大于10MB (当前2MB不满足)
        ];

        sized_target.file_size = Some(2 * 1024 * 1024); // 2MB
        let result = service
            .evaluate_flow_rules(&impossible_or_rules, &FlowMode::OR, &sized_target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            false,
            "OR mode: all conditions false should return false"
        );

        // 测试复杂条件组合 - 使用在测试环境中可以满足的条件
        let complex_rules = vec![
            FlowCond::CnIp(false), // 全球IP (总是true)
            FlowCond::Size(FlowComp::Ge, Size::from_str("1MB").unwrap()), // 大于等于1MB
            FlowCond::Extras("test_flag".to_string()), // extras包含test_flag
            FlowCond::IpVersion(4), // IPv4
        ];

        // 设置满足所有条件的上下文
        context.client_ip = Some("192.168.1.100".parse().unwrap()); // IPv4地址
        sized_target.file_size = Some(1024 * 1024); // 1MB，满足>=1MB条件
        // extras已经包含test_flag

        let result = service
            .evaluate_flow_rules(&complex_rules, &FlowMode::AND, &sized_target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "Complex AND rules: all conditions true should return true"
        );

        println!("✅ All rule combination tests passed");
    }

    #[tokio::test]
    async fn test_weighted_random_selection() {
        let service = create_test_flow_service().await;

        // 测试空服务器池 - 应该返回错误
        let empty_pool: Vec<(String, u32)> = vec![];
        let result = service.weighted_random_selection(&empty_pool);
        assert!(result.is_err(), "Empty pool should return error");

        // 测试全零权重 - 应该返回错误
        let zero_weight_pool = vec![("server1".to_string(), 0), ("server2".to_string(), 0)];
        let result = service.weighted_random_selection(&zero_weight_pool);
        assert!(result.is_err(), "Zero weight pool should return error");

        // 测试单个服务器 - 应该100%选中该服务器
        let single_server_pool = vec![("server1".to_string(), 10)];
        let result = service.weighted_random_selection(&single_server_pool);
        assert!(result.is_ok(), "Single server should succeed");
        assert_eq!(
            result.unwrap().0,
            "server1",
            "Single server should be selected"
        );

        // 测试权重分布 - 使用统计验证
        let test_pool = vec![
            ("server1".to_string(), 70), // 期望约70%
            ("server2".to_string(), 30), // 期望约30%
        ];

        let mut server1_count = 0;
        let mut server2_count = 0;
        let total_runs = 1000;

        for _ in 0..total_runs {
            let result = service.weighted_random_selection(&test_pool);
            assert!(result.is_ok(), "Selection should not fail");

            match result.unwrap().0.as_str() {
                "server1" => server1_count += 1,
                "server2" => server2_count += 1,
                _ => panic!("Unexpected server selected"),
            }
        }

        // 验证分布 (允许±10%的误差)
        let server1_ratio = server1_count as f64 / total_runs as f64;
        let server2_ratio = server2_count as f64 / total_runs as f64;

        println!(
            "Server1 ratio: {:.2}% (expected ~70%)",
            server1_ratio * 100.0
        );
        println!(
            "Server2 ratio: {:.2}% (expected ~30%)",
            server2_ratio * 100.0
        );

        assert!(
            server1_ratio > 0.60 && server1_ratio < 0.80,
            "Server1 should be selected ~70% of time, got {:.1}%",
            server1_ratio * 100.0
        );
        assert!(
            server2_ratio > 0.20 && server2_ratio < 0.40,
            "Server2 should be selected ~30% of time, got {:.1}%",
            server2_ratio * 100.0
        );

        // 测试0权重服务器不被选中
        let mixed_weight_pool = vec![
            ("server1".to_string(), 10),
            ("server2".to_string(), 0),
            ("server3".to_string(), 5),
        ];

        let mut server2_selected = false;
        for _ in 0..100 {
            let result = service.weighted_random_selection(&mixed_weight_pool);
            assert!(result.is_ok(), "Selection should not fail");
            if result.unwrap().0 == "server2" {
                server2_selected = true;
                break;
            }
        }
        assert!(
            !server2_selected,
            "Zero weight server should never be selected"
        );

        // 测试不同权重比例
        let unequal_pool = vec![("high".to_string(), 90), ("low".to_string(), 10)];

        let mut high_count = 0;
        for _ in 0..200 {
            let result = service.weighted_random_selection(&unequal_pool);
            if result.unwrap().0 == "high" {
                high_count += 1;
            }
        }

        let high_ratio = high_count as f64 / 200.0;
        assert!(
            high_ratio > 0.80,
            "High weight server should be selected most of the time"
        );

        println!("✅ All weighted random selection tests passed");
    }

    #[tokio::test]
    async fn test_apply_penalty_to_pool() {
        let service = create_test_flow_service().await;

        // 测试空惩罚列表 - 权重应该不变
        let mut pool = vec![
            ("server1".to_string(), 10),
            ("server2".to_string(), 5),
            ("server3".to_string(), 8),
        ];
        let original_pool = pool.clone();
        service.apply_penalty_to_pool(&mut pool, &[]);
        assert_eq!(
            pool, original_pool,
            "Empty penalty list should not change weights"
        );

        // 测试标准惩罚 - 惩罚服务器权重被调整到最低非惩罚权重
        let mut pool = vec![
            ("server1".to_string(), 10),
            ("server2".to_string(), 5), // 最低非惩罚权重
            ("server3".to_string(), 8),
        ];
        let penalty_servers = vec!["server1".to_string(), "server3".to_string()];
        service.apply_penalty_to_pool(&mut pool, &penalty_servers);

        // server1 和 server3 应该被调整到 5 (最低非惩罚权重)
        // server2 保持 5 不变
        assert_eq!(
            pool[0].1, 5,
            "Penalized server1 should have weight reduced to min non-penalized"
        );
        assert_eq!(
            pool[1].1, 5,
            "Non-penalized server2 should keep original weight"
        );
        assert_eq!(
            pool[2].1, 5,
            "Penalized server3 should have weight reduced to min non-penalized"
        );

        // 测试全部服务器被惩罚 - 权重应该保持不变
        let mut pool = vec![
            ("server1".to_string(), 10),
            ("server2".to_string(), 5),
            ("server3".to_string(), 8),
        ];
        let original_pool = pool.clone();
        let all_penalty = vec![
            "server1".to_string(),
            "server2".to_string(),
            "server3".to_string(),
        ];
        service.apply_penalty_to_pool(&mut pool, &all_penalty);
        assert_eq!(
            pool, original_pool,
            "All penalized servers should keep original weights"
        );

        // 测试惩罚不存在的服务器 - 应该没有影响
        let mut pool = vec![("server1".to_string(), 10), ("server2".to_string(), 5)];
        let original_pool = pool.clone();
        let nonexistent_penalty = vec!["nonexistent_server".to_string()];
        service.apply_penalty_to_pool(&mut pool, &nonexistent_penalty);
        assert_eq!(
            pool, original_pool,
            "Non-existent penalty servers should have no effect"
        );

        // 测试部分惩罚 - 只有被惩罚的服务器权重改变
        let mut pool = vec![
            ("server1".to_string(), 20),
            ("server2".to_string(), 15),
            ("server3".to_string(), 10), // 最低非惩罚权重
            ("server4".to_string(), 25),
        ];
        let partial_penalty = vec!["server1".to_string(), "server4".to_string()];
        service.apply_penalty_to_pool(&mut pool, &partial_penalty);

        assert_eq!(
            pool[0].1, 10,
            "Penalized server1 should be reduced to min non-penalized (10)"
        );
        assert_eq!(
            pool[1].1, 15,
            "Non-penalized server2 should keep weight (15)"
        );
        assert_eq!(
            pool[2].1, 10,
            "Non-penalized server3 should keep weight (10)"
        );
        assert_eq!(
            pool[3].1, 10,
            "Penalized server4 should be reduced to min non-penalized (10)"
        );

        // 测试边界情况：只有一个非惩罚服务器
        let mut pool = vec![
            ("server1".to_string(), 10),
            ("server2".to_string(), 5), // 唯一非惩罚服务器
            ("server3".to_string(), 8),
        ];
        let single_non_penalty = vec!["server1".to_string(), "server3".to_string()];
        service.apply_penalty_to_pool(&mut pool, &single_non_penalty);

        assert_eq!(
            pool[0].1, 5,
            "Penalized server should match single non-penalized weight"
        );
        assert_eq!(
            pool[1].1, 5,
            "Non-penalized server should keep original weight"
        );
        assert_eq!(
            pool[2].1, 5,
            "Penalized server should match single non-penalized weight"
        );

        println!("✅ All penalty application tests passed");
    }

    #[tokio::test]
    async fn test_server_bandwidth_minutes_condition() {
        let service = create_test_flow_service().await;
        let (target, context, _options) = create_test_context();

        // 获取bandwidth cache service来记录流量数据
        let bandwidth_service = &service.bandwidth_cache;

        // 测试场景：记录不同服务器的流量数据
        let server_id = "test_cdn";

        // 记录一些流量数据
        bandwidth_service
            .record_bandwidth(server_id, 500_000_000)
            .await; // 500MB
        bandwidth_service
            .record_bandwidth(server_id, 300_000_000)
            .await; // 300MB

        // 手动刷新到存储
        bandwidth_service.flush_pending_for_test().await.unwrap();

        // 测试小于条件：800MB < 1GB -> true
        let size_1gb = Size::from_str("1GB").unwrap();
        let condition = FlowCond::ServerBwMinutes(
            server_id.to_string(),
            30, // 30分钟窗口
            FlowComp::Lt,
            size_1gb.clone(),
        );

        let result = service
            .evaluate_condition(&condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true, "800MB should be less than 1GB");

        // 测试大于条件：800MB > 500MB -> true
        let size_500mb = Size::from_str("500MB").unwrap();
        let condition =
            FlowCond::ServerBwMinutes(server_id.to_string(), 30, FlowComp::Gt, size_500mb);

        let result = service
            .evaluate_condition(&condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true, "800MB should be greater than 500MB");

        // 测试等于条件（使用确切值）
        let size_800mb = Size::from_str("800MB").unwrap();
        let condition =
            FlowCond::ServerBwMinutes(server_id.to_string(), 30, FlowComp::Eq, size_800mb);

        let result = service
            .evaluate_condition(&condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true, "800MB should equal 800MB");

        // 测试不存在的服务器 - 应该返回0流量
        let nonexistent_condition = FlowCond::ServerBwMinutes(
            "nonexistent_server".to_string(),
            30,
            FlowComp::Lt,
            Size::from_str("100MB").unwrap(),
        );

        let result = service
            .evaluate_condition(&nonexistent_condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "Non-existent server should have 0 bandwidth, thus < 100MB"
        );

        // 测试不同时间窗口的流量查询
        let smaller_window_condition = FlowCond::ServerBwMinutes(
            server_id.to_string(),
            1, // 1分钟窗口（应该包含所有当前分钟的流量）
            FlowComp::Eq,
            size_800mb.clone(),
        );

        let result = service
            .evaluate_condition(&smaller_window_condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "Current minute should contain all recorded bandwidth"
        );

        println!("✅ Server bandwidth minutes condition tests passed");
    }

    #[tokio::test]
    async fn test_server_bandwidth_minutes_in_flow_rules() {
        let service = create_test_flow_service().await;
        let (target, context, _options) = create_test_context();

        let bandwidth_service = &service.bandwidth_cache;
        let high_traffic_server = "high_traffic_cdn";
        let low_traffic_server = "low_traffic_cdn";

        // 为高流量服务器记录大量数据
        bandwidth_service
            .record_bandwidth(high_traffic_server, 1_500_000_000)
            .await; // 1.5GB

        // 为低流量服务器记录少量数据
        bandwidth_service
            .record_bandwidth(low_traffic_server, 200_000_000)
            .await; // 200MB

        // 刷新到存储
        bandwidth_service.flush_pending_for_test().await.unwrap();

        // 测试复合流量控制规则：只有低流量服务器可以处理新请求
        let bandwidth_limit_rules = vec![
            FlowCond::ServerBwMinutes(
                high_traffic_server.to_string(),
                60, // 60分钟窗口
                FlowComp::Lt,
                Size::from_str("1GB").unwrap(),
            ),
            FlowCond::CnIp(false), // 全球用户
        ];

        // 高流量服务器应该不满足条件（1.5GB不小于1GB）
        let result = service
            .evaluate_flow_rules(&bandwidth_limit_rules, &FlowMode::AND, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            false,
            "High traffic server should fail bandwidth limit check"
        );

        // 测试低流量服务器满足条件的规则
        let low_bandwidth_rules = vec![
            FlowCond::ServerBwMinutes(
                low_traffic_server.to_string(),
                60,
                FlowComp::Lt,
                Size::from_str("1GB").unwrap(),
            ),
            FlowCond::CnIp(false), // 全球用户
        ];

        let result = service
            .evaluate_flow_rules(&low_bandwidth_rules, &FlowMode::AND, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "Low traffic server should pass bandwidth limit check"
        );

        // 测试OR模式下的带宽条件
        let or_bandwidth_rules = vec![
            FlowCond::ServerBwMinutes(
                high_traffic_server.to_string(),
                60,
                FlowComp::Lt,
                Size::from_str("1GB").unwrap(), // 不满足
            ),
            FlowCond::ServerBwMinutes(
                low_traffic_server.to_string(),
                60,
                FlowComp::Lt,
                Size::from_str("1GB").unwrap(), // 满足
            ),
        ];

        let result = service
            .evaluate_flow_rules(&or_bandwidth_rules, &FlowMode::OR, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "OR mode should pass when one bandwidth condition is met"
        );

        // 测试复杂场景：文件大小 + 服务器带宽限制
        let mut sized_target = target.clone();
        sized_target.file_size = Some(100 * 1024 * 1024); // 100MB文件

        let complex_rules = vec![
            FlowCond::Size(FlowComp::Gt, Size::from_str("50MB").unwrap()), // 文件大于50MB
            FlowCond::ServerBwMinutes(
                low_traffic_server.to_string(),
                30,
                FlowComp::Lt,
                Size::from_str("500MB").unwrap(), // 服务器30分钟流量小于500MB
            ),
        ];

        let result = service
            .evaluate_flow_rules(&complex_rules, &FlowMode::AND, &sized_target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "Large files should be allowed on low-bandwidth servers"
        );

        println!("✅ Server bandwidth minutes flow rules tests passed");
    }

    #[tokio::test]
    async fn test_bandwidth_condition_time_windows() {
        let service = create_test_flow_service().await;
        let (target, context, _options) = create_test_context();

        let bandwidth_service = &service.bandwidth_cache;
        let server_id = "time_test_server";

        // 记录流量数据
        bandwidth_service
            .record_bandwidth(server_id, 400_000_000)
            .await; // 400MB
        bandwidth_service.flush_pending_for_test().await.unwrap();

        // 测试不同时间窗口
        let time_windows = vec![1, 5, 15, 30, 60, 120];

        for minutes in time_windows {
            let condition = FlowCond::ServerBwMinutes(
                server_id.to_string(),
                minutes,
                FlowComp::Ge, // 大于等于
                Size::from_str("400MB").unwrap(),
            );

            let result = service
                .evaluate_condition(&condition, &target, &context)
                .await;
            assert!(result.is_ok());
            assert_eq!(
                result.unwrap(),
                true,
                "All time windows should contain the recorded 400MB"
            );
        }

        // 测试时间窗口边界：记录的数据应该在所有合理的时间窗口内都能查到
        let large_window_condition = FlowCond::ServerBwMinutes(
            server_id.to_string(),
            1440, // 24小时 = 1440分钟
            FlowComp::Eq,
            Size::from_str("400MB").unwrap(),
        );

        let result = service
            .evaluate_condition(&large_window_condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            true,
            "Large time window should still contain recorded data"
        );

        println!("✅ Bandwidth condition time window tests passed");
    }

    #[tokio::test]
    async fn test_process_plugin_result() {
        let service = create_test_flow_service().await;

        // 测试增强格式解析 - 包含元数据
        let enhanced_result = json!([
            false, // should_break
            [
                ["http://server1.example.com/file", 10, {
                    "server_id": "srv1",
                    "skip_penalty": true
                }],
                ["http://server2.example.com/file", 5, {
                    "server_id": "srv2",
                    "skip_penalty": false
                }],
                ["http://server3.example.com/file", 8, null]
            ]
        ]);

        let mut pool = vec![];
        let mut plugin_server_mapping = HashMap::new();

        let result =
            service.process_plugin_result(enhanced_result, &mut pool, &mut plugin_server_mapping);
        assert!(
            result.is_ok(),
            "Enhanced format should be parsed successfully"
        );

        // 验证服务器池
        assert_eq!(pool.len(), 3, "Pool should contain 3 servers");
        assert_eq!(pool[0], ("http://server1.example.com/file".to_string(), 10));
        assert_eq!(pool[1], ("http://server2.example.com/file".to_string(), 5));
        assert_eq!(pool[2], ("http://server3.example.com/file".to_string(), 8));

        // 验证元数据映射
        assert_eq!(
            plugin_server_mapping.len(),
            2,
            "Should have 2 server mappings with metadata"
        );
        assert_eq!(
            plugin_server_mapping.get("http://server1.example.com/file"),
            Some(&(Some("srv1".to_string()), true))
        );
        assert_eq!(
            plugin_server_mapping.get("http://server2.example.com/file"),
            Some(&(Some("srv2".to_string()), false))
        );
        assert!(
            !plugin_server_mapping.contains_key("http://server3.example.com/file"),
            "Server with null metadata should not be in mapping"
        );

        // 测试兼容格式解析 - 旧格式
        let compatible_result = json!([
            false, // should_break
            [
                ["http://legacy1.example.com/file", 15],
                ["http://legacy2.example.com/file", 20]
            ]
        ]);

        let mut pool = vec![];
        let mut plugin_server_mapping = HashMap::new();

        let result =
            service.process_plugin_result(compatible_result, &mut pool, &mut plugin_server_mapping);
        assert!(
            result.is_ok(),
            "Compatible format should be parsed successfully"
        );

        // 验证服务器池
        assert_eq!(pool.len(), 2, "Pool should contain 2 servers");
        assert_eq!(pool[0], ("http://legacy1.example.com/file".to_string(), 15));
        assert_eq!(pool[1], ("http://legacy2.example.com/file".to_string(), 20));

        // 兼容格式应该没有元数据映射
        assert_eq!(
            plugin_server_mapping.len(),
            0,
            "Compatible format should not have metadata"
        );

        // 测试错误格式处理
        let invalid_result = json!("invalid_format");
        let mut pool = vec![];
        let mut plugin_server_mapping = HashMap::new();

        let result =
            service.process_plugin_result(invalid_result, &mut pool, &mut plugin_server_mapping);
        assert!(result.is_err(), "Invalid format should return error");

        // 测试部分无效数据 - 缺少必要字段
        let partial_invalid_result = json!([
            false,
            [
                ["http://server1.example.com/file"] // 缺少权重
            ]
        ]);

        let mut pool = vec![];
        let mut plugin_server_mapping = HashMap::new();

        let result = service.process_plugin_result(
            partial_invalid_result,
            &mut pool,
            &mut plugin_server_mapping,
        );
        assert!(
            result.is_err(),
            "Partial invalid format should return error"
        );

        // 测试空结果
        let empty_result = json!([false, []]);
        let mut pool = vec![("existing".to_string(), 1)]; // 预存在的数据
        let mut plugin_server_mapping = HashMap::new();

        let result =
            service.process_plugin_result(empty_result, &mut pool, &mut plugin_server_mapping);
        assert!(result.is_ok(), "Empty result should be valid");
        assert_eq!(
            pool.len(),
            0,
            "Pool should be cleared even for empty result"
        );

        // 测试带有skip_penalty的元数据应用
        let skip_penalty_result = json!([
            false,
            [
                ["http://penalty-skip.example.com/file", 10, {
                    "server_id": "penalty-skip",
                    "skip_penalty": true
                }],
                ["http://penalty-normal.example.com/file", 10, {
                    "server_id": "penalty-normal"
                    // skip_penalty 省略，应该默认为false
                }]
            ]
        ]);

        let mut pool = vec![];
        let mut plugin_server_mapping = HashMap::new();

        let result = service.process_plugin_result(
            skip_penalty_result,
            &mut pool,
            &mut plugin_server_mapping,
        );
        assert!(result.is_ok(), "Skip penalty result should be valid");

        // 验证skip_penalty处理
        assert_eq!(
            plugin_server_mapping.get("http://penalty-skip.example.com/file"),
            Some(&(Some("penalty-skip".to_string()), true)),
            "skip_penalty: true should be preserved"
        );
        assert_eq!(
            plugin_server_mapping.get("http://penalty-normal.example.com/file"),
            Some(&(Some("penalty-normal".to_string()), false)),
            "missing skip_penalty should default to false"
        );

        println!("✅ All plugin result processing tests passed");
    }

    /// Helper: create test config with h3_only servers for h3 gate tests
    fn create_h3_test_config() -> crate::config::AppConfig {
        use crate::config::ServerConfig;

        let mut config = crate::tests::mocks::create_default_test_config();

        // Add an h3_only server
        config.servers.insert(
            "h3_server".to_string(),
            ServerConfig {
                id: "h3_server".to_string(),
                r#type: "direct".to_string(),
                url: "https://h3.example.com".to_string(),
                h3_only: true,
                cert_hash: Some("trust".to_string()),
                ..Default::default()
            },
        );

        // Add a normal (non-h3_only) server
        config.servers.insert(
            "normal_server".to_string(),
            ServerConfig {
                id: "normal_server".to_string(),
                r#type: "direct".to_string(),
                url: "https://normal.example.com".to_string(),
                h3_only: false,
                cert_hash: None,
                ..Default::default()
            },
        );

        // Create ServerImpl for new servers
        for id in ["h3_server", "normal_server"] {
            if let Some(server_config) = config.servers.get(id) {
                if let Ok(server) = crate::modules::server::ServerImpl::new(server_config) {
                    config.server_impl.insert(id.to_string(), server);
                }
            }
        }

        config
    }

    /// Helper: create FlowService with h3 test config
    async fn create_h3_test_flow_service() -> FlowService {
        let env = TestEnvironment::with_config(create_h3_test_config()).await;
        env.services.flow_service
    }

    #[tokio::test]
    async fn test_h3_only_server_skipped_when_not_h3_capable() {
        let service = create_h3_test_flow_service().await;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selected_server_id = None;
        let mut selected_server_weight = None;

        let (target, mut context, options) = create_test_context();
        context.h3_capable = false;

        // Flow item with h3_only server
        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "h3_server".to_string(),
                weight: 10,
            }],
            r#break: false,
        };

        let _should_break = service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &[],
                &mut selected_server_id,
                &mut selected_server_weight,
            )
            .await
            .unwrap();

        assert!(
            pool.is_empty(),
            "h3_only server should NOT be in pool when client is not h3-capable"
        );

        println!("✅ h3_only server skipped when not h3_capable");
    }

    #[tokio::test]
    async fn test_h3_only_server_added_when_h3_capable() {
        let service = create_h3_test_flow_service().await;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selected_server_id = None;
        let mut selected_server_weight = None;

        let (target, mut context, options) = create_test_context();
        context.h3_capable = true;

        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "h3_server".to_string(),
                weight: 10,
            }],
            r#break: false,
        };

        let _should_break = service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &[],
                &mut selected_server_id,
                &mut selected_server_weight,
            )
            .await
            .unwrap();

        assert_eq!(
            pool.len(),
            1,
            "h3_only server SHOULD be in pool when client is h3-capable"
        );
        assert_eq!(pool[0].0, "h3_server");
        assert_eq!(pool[0].1, 10);

        println!("✅ h3_only server added when h3_capable");
    }

    #[tokio::test]
    async fn test_non_h3_only_server_added_regardless_of_h3_capable() {
        let service = create_h3_test_flow_service().await;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selected_server_id = None;
        let mut selected_server_weight = None;

        let (target, mut context, options) = create_test_context();
        context.h3_capable = false;

        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "normal_server".to_string(),
                weight: 5,
            }],
            r#break: false,
        };

        let _should_break = service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &[],
                &mut selected_server_id,
                &mut selected_server_weight,
            )
            .await
            .unwrap();

        assert_eq!(
            pool.len(),
            1,
            "non-h3_only server should be in pool regardless of h3_capable"
        );
        assert_eq!(pool[0].0, "normal_server");

        println!("✅ non-h3_only server added regardless of h3_capable");
    }

    #[tokio::test]
    async fn test_h3_only_mixed_pool_filtering() {
        let service = create_h3_test_flow_service().await;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selected_server_id = None;
        let mut selected_server_weight = None;

        let (target, mut context, options) = create_test_context();
        context.h3_capable = false;

        // Flow item with both h3_only and normal servers
        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![
                FlowUse::Server {
                    id: "h3_server".to_string(),
                    weight: 10,
                },
                FlowUse::Server {
                    id: "normal_server".to_string(),
                    weight: 5,
                },
            ],
            r#break: false,
        };

        let _should_break = service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &[],
                &mut selected_server_id,
                &mut selected_server_weight,
            )
            .await
            .unwrap();

        // Only normal_server should be in pool
        assert_eq!(
            pool.len(),
            1,
            "Only non-h3_only server should remain in pool"
        );
        assert_eq!(pool[0].0, "normal_server");
        assert_eq!(pool[0].1, 5);

        // Now test with h3_capable = true
        pool.clear();
        context.h3_capable = true;

        let _should_break = service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &[],
                &mut selected_server_id,
                &mut selected_server_weight,
            )
            .await
            .unwrap();

        // Both servers should be in pool
        assert_eq!(
            pool.len(),
            2,
            "Both servers should be in pool when h3_capable"
        );

        println!("✅ h3_only mixed pool filtering works correctly");
    }

    #[tokio::test]
    async fn test_h3_only_with_penalty_interaction() {
        let service = create_h3_test_flow_service().await;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selected_server_id = None;
        let mut selected_server_weight = None;

        let (target, mut context, options) = create_test_context();
        context.h3_capable = true;

        // h3_server is both h3_only AND penalized
        let penalty_servers = vec!["h3_server".to_string()];

        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![
                FlowUse::Server {
                    id: "h3_server".to_string(),
                    weight: 10,
                },
                FlowUse::Server {
                    id: "normal_server".to_string(),
                    weight: 5,
                },
            ],
            r#break: false,
        };

        let _should_break = service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &penalty_servers,
                &mut selected_server_id,
                &mut selected_server_weight,
            )
            .await
            .unwrap();

        // h3_server should be skipped due to penalty (checked first),
        // even though h3_capable is true
        assert_eq!(pool.len(), 1, "Penalized h3_server should be skipped");
        assert_eq!(pool[0].0, "normal_server");

        println!("✅ h3_only + penalty interaction works correctly");
    }

    #[tokio::test]
    async fn test_h3_only_unknown_server_not_filtered() {
        // Server not in config should still be added (no ServerConfig to check)
        let service = create_h3_test_flow_service().await;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selected_server_id = None;
        let mut selected_server_weight = None;

        let (target, mut context, options) = create_test_context();
        context.h3_capable = false;

        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "unknown_server".to_string(),
                weight: 7,
            }],
            r#break: false,
        };

        let _should_break = service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &[],
                &mut selected_server_id,
                &mut selected_server_weight,
            )
            .await
            .unwrap();

        assert_eq!(
            pool.len(),
            1,
            "Unknown server (not in config) should still be added to pool"
        );
        assert_eq!(pool[0].0, "unknown_server");

        println!("✅ Unknown server not filtered by h3_only gate");
    }

    // ======================== rewrite_h3_url tests ========================

    /// Helper to create a ServerConfig for rewrite tests
    fn make_server_config(h3_only: bool, cert_hash: Option<&str>) -> crate::config::ServerConfig {
        crate::config::ServerConfig {
            id: "test_h3".to_string(),
            url: "https://cdn.example.com".to_string(),
            r#type: "direct".to_string(),
            h3_only,
            cert_hash: cert_hash.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    /// Helper to create a HealthInfo with optional observed cert hash
    fn make_health_info(observed_cert_hash: Option<&str>) -> HealthInfo {
        HealthInfo {
            is_alive: true,
            file_size: Some(1024),
            last_check: 1000,
            observed_cert_hash: observed_cert_hash.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_rewrite_h3_url_https_to_http3_with_query_params() {
        let server = make_server_config(true, None); // ValidCert → no fragment
        let url = "https://cdn.example.com/path/to/file.zip?token=abc&expires=123".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert_eq!(
            result, "http3://cdn.example.com/path/to/file.zip?token=abc&expires=123",
            "Query params should be preserved and scheme changed to http3"
        );
    }

    #[test]
    fn test_rewrite_h3_url_existing_fragment_replaced() {
        let hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let server = make_server_config(true, Some(hex));
        let url = "https://cdn.example.com/file.zip#old-fragment".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert!(
            result.starts_with("http3://cdn.example.com/file.zip#cert="),
            "Existing fragment should be replaced, got: {}",
            result
        );
        assert!(
            !result.contains("old-fragment"),
            "Old fragment should be gone"
        );
        assert!(
            result.ends_with(&format!("#cert={}", hex)),
            "Should end with #cert={{hex}}, got: {}",
            result
        );
    }

    #[test]
    fn test_rewrite_h3_url_non_https_not_rewritten() {
        let server = make_server_config(true, None);
        let url = "http://cdn.example.com/file.zip".to_string();
        let result = rewrite_h3_url(url.clone(), &server, None).unwrap();
        assert_eq!(result, url, "Non-https URLs should not be rewritten");
    }

    #[test]
    fn test_rewrite_h3_url_cert_hash_empty_no_fragment() {
        // cert_hash = None → ValidCert → no fragment
        let server = make_server_config(true, None);
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert_eq!(result, "http3://cdn.example.com/file.zip");
        assert!(!result.contains('#'), "No fragment when cert_hash is empty");
    }

    #[test]
    fn test_rewrite_h3_url_cert_hash_empty_string_no_fragment() {
        // cert_hash = Some("") → ValidCert → no fragment
        let server = make_server_config(true, Some(""));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert_eq!(result, "http3://cdn.example.com/file.zip");
    }

    #[test]
    fn test_rewrite_h3_url_trust_with_observed_hash() {
        let server = make_server_config(true, Some("trust"));
        let observed = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let health = make_health_info(Some(observed));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_h3_url(url, &server, Some(&health)).unwrap();
        assert_eq!(
            result,
            format!("http3://cdn.example.com/file.zip#cert={}", observed),
            "Trust mode should use observed cert hash"
        );
    }

    #[test]
    fn test_rewrite_h3_url_trust_normalizes_hash_to_lowercase() {
        let server = make_server_config(true, Some("trust"));
        let observed_upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        let health = make_health_info(Some(observed_upper));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_h3_url(url, &server, Some(&health)).unwrap();
        assert!(
            result.ends_with(&format!("#cert={}", observed_upper.to_ascii_lowercase())),
            "Hash should be normalized to lowercase"
        );
    }

    #[test]
    fn test_rewrite_h3_url_trust_without_observed_hash_errors() {
        let server = make_server_config(true, Some("trust"));
        let health = make_health_info(None); // no observed hash
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_h3_url(url, &server, Some(&health));
        assert!(
            result.is_err(),
            "Trust mode without observed hash should return error"
        );
    }

    #[test]
    fn test_rewrite_h3_url_trust_no_health_info_errors() {
        let server = make_server_config(true, Some("trust"));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_h3_url(url, &server, None);
        assert!(
            result.is_err(),
            "Trust mode without health_info should return error"
        );
    }

    #[test]
    fn test_rewrite_h3_url_pinned_hex() {
        let hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let server = make_server_config(true, Some(hex));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert_eq!(
            result,
            format!("http3://cdn.example.com/file.zip#cert={}", hex),
            "Pinned hex should be used as cert fragment"
        );
    }

    #[test]
    fn test_rewrite_h3_url_pinned_hex_uppercase_normalized() {
        let hex_upper = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        let hex_lower = hex_upper.to_ascii_lowercase();
        let server = make_server_config(true, Some(hex_upper));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert_eq!(
            result,
            format!("http3://cdn.example.com/file.zip#cert={}", hex_lower),
            "Pinned hex should be normalized to lowercase"
        );
    }

    #[test]
    fn test_rewrite_h3_url_preserves_port() {
        let server = make_server_config(true, None);
        let url = "https://cdn.example.com:8443/file.zip".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert_eq!(
            result, "http3://cdn.example.com:8443/file.zip",
            "Port should be preserved"
        );
    }

    #[test]
    fn test_rewrite_h3_url_preserves_complex_url() {
        let hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let server = make_server_config(true, Some(hex));
        // Use non-default port (8443) to test port preservation.
        // Note: port 443 is the default for https and gets normalized away by url::Url.
        let url = "https://cdn.example.com:8443/path/to/file.zip?token=abc&sig=xyz".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert_eq!(
            result,
            format!(
                "http3://cdn.example.com:8443/path/to/file.zip?token=abc&sig=xyz#cert={}",
                hex
            ),
            "Complex URL with port, path, and query should be fully preserved"
        );
    }

    #[test]
    fn test_rewrite_h3_url_non_h3_server_valid_cert() {
        // Non-h3_only server: cert_hash_policy returns ValidCert regardless
        let server = make_server_config(false, Some("trust"));
        let url = "https://cdn.example.com/file.zip".to_string();
        // Note: rewrite_h3_url doesn't check h3_only itself - that's done by callers.
        // But cert_hash_policy() returns ValidCert when h3_only=false.
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert_eq!(
            result, "http3://cdn.example.com/file.zip",
            "Non-h3 server gets ValidCert policy, so no fragment"
        );
    }

    // ======================== Integration-style tests ========================
    // These test the full flow pipeline with h3_only servers and verify URL output.

    /// Helper: create config with h3_only server using pinned cert hash and a resource that uses it
    fn create_h3_integration_config() -> crate::config::AppConfig {
        use crate::config::{DownloadPolicy, ResourceConfig, ServerConfig};

        let mut config = crate::tests::mocks::create_default_test_config();

        let hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

        // h3_only server with pinned cert hash
        config.servers.insert(
            "h3_pinned".to_string(),
            ServerConfig {
                id: "h3_pinned".to_string(),
                r#type: "direct".to_string(),
                url: "https://h3-pinned.example.com".to_string(),
                h3_only: true,
                cert_hash: Some(hex.to_string()),
                ..Default::default()
            },
        );

        // h3_only server with ValidCert (no cert_hash)
        config.servers.insert(
            "h3_valid".to_string(),
            ServerConfig {
                id: "h3_valid".to_string(),
                r#type: "direct".to_string(),
                url: "https://h3-valid.example.com".to_string(),
                h3_only: true,
                cert_hash: None,
                ..Default::default()
            },
        );

        // Non-h3 server (for mixed pool)
        config.servers.insert(
            "regular_cdn".to_string(),
            ServerConfig {
                id: "regular_cdn".to_string(),
                r#type: "direct".to_string(),
                url: "https://regular.example.com".to_string(),
                h3_only: false,
                cert_hash: None,
                ..Default::default()
            },
        );

        // Create ServerImpl for new servers
        for id in ["h3_pinned", "h3_valid", "regular_cdn"] {
            if let Some(sc) = config.servers.get(id) {
                if let Ok(si) = crate::modules::server::ServerImpl::new(sc) {
                    config.server_impl.insert(id.to_string(), si);
                }
            }
        }

        // Resource using h3_pinned server
        let mut h3_resource = ResourceConfig {
            latest: "1.0.0".to_string(),
            versions: HashMap::new(),
            tries: vec![],
            server: vec![],
            flow: vec![FlowItem {
                rules: vec![],
                mode: FlowMode::AND,
                r#use: vec![FlowUse::Server {
                    id: "h3_pinned".to_string(),
                    weight: 10,
                }],
                r#break: false,
            }],
            challenge: None,
            download: DownloadPolicy::Free,
            resource_type: "file".to_string(),
            cache_enabled: false,
            cache_subpaths: vec![],
            cache_max_age: 300,
            legacy_client_support: false,
            legacy_client_full_range: false,
            changelog: None,
            version_provider: None,
        };
        let mut ver_map = HashMap::new();
        ver_map.insert("h3_pinned".to_string(), "/files/app.zip".to_string());
        ver_map.insert("default".to_string(), "/files/app.zip".to_string());
        h3_resource.versions.insert("1.0.0".to_string(), ver_map);
        config.resources.insert("h3_app".to_string(), h3_resource);

        // Resource using mixed pool (h3 + regular)
        let mut mixed_resource = ResourceConfig {
            latest: "1.0.0".to_string(),
            versions: HashMap::new(),
            tries: vec![],
            server: vec![],
            flow: vec![FlowItem {
                rules: vec![],
                mode: FlowMode::AND,
                r#use: vec![
                    FlowUse::Server {
                        id: "h3_pinned".to_string(),
                        weight: 10,
                    },
                    FlowUse::Server {
                        id: "regular_cdn".to_string(),
                        weight: 10,
                    },
                ],
                r#break: false,
            }],
            challenge: None,
            download: DownloadPolicy::Free,
            resource_type: "file".to_string(),
            cache_enabled: false,
            cache_subpaths: vec![],
            cache_max_age: 300,
            legacy_client_support: false,
            legacy_client_full_range: false,
            changelog: None,
            version_provider: None,
        };
        let mut ver_map2 = HashMap::new();
        ver_map2.insert("default".to_string(), "/files/app.zip".to_string());
        mixed_resource
            .versions
            .insert("1.0.0".to_string(), ver_map2);
        config
            .resources
            .insert("mixed_app".to_string(), mixed_resource);

        config
    }

    #[tokio::test]
    async fn test_integration_h3_only_pool_non_capable_client() {
        // Full flow: config with h3_only server, non-h3 client → pool should be empty
        let config = create_h3_integration_config();
        let env = TestEnvironment::with_config(config).await;
        let service = env.services.flow_service;

        let target = FlowTarget {
            resource_id: "h3_app".to_string(),
            version: "1.0.0".to_string(),
            file_size: Some(1024),
            sub_path: None,
            ranges: None,
        };
        let context = FlowContext {
            client_ip: Some("10.0.0.1".parse().unwrap()),
            session_id: Some("test_sid".to_string()),
            extras: json!({}),
            h3_capable: false, // Client does NOT support h3
        };
        let options = FlowOptions {
            cdn_full_range: false,
        };

        let flow_items = vec![FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "h3_pinned".to_string(),
                weight: 10,
            }],
            r#break: false,
        }];

        let result = service
            .execute_flow(&target, &context, &options, &flow_items, vec![], None)
            .await;

        // Should fail: no servers available (h3_only filtered out for non-capable client)
        assert!(
            result.is_err(),
            "Should error when only h3_only servers available and client is not h3-capable"
        );
    }

    #[tokio::test]
    async fn test_integration_mixed_pool_non_capable_client_gets_regular() {
        // Full flow: mixed pool (h3 + regular), non-h3 client → only regular server remains
        let config = create_h3_integration_config();
        let env = TestEnvironment::with_config(config).await;

        // Set up health info for the regular server
        let health = HealthInfo {
            is_alive: true,
            file_size: Some(1024),
            last_check: chrono::Utc::now().timestamp() as u64,
            observed_cert_hash: None,
        };
        env.data_store
            .set_health_info("regular_cdn", "/files/app.zip", &health)
            .await
            .unwrap();

        let service = env.services.flow_service;

        let target = FlowTarget {
            resource_id: "mixed_app".to_string(),
            version: "1.0.0".to_string(),
            file_size: Some(1024),
            sub_path: None,
            ranges: None,
        };
        let context = FlowContext {
            client_ip: Some("10.0.0.1".parse().unwrap()),
            session_id: Some("test_sid".to_string()),
            extras: json!({}),
            h3_capable: false,
        };
        let options = FlowOptions {
            cdn_full_range: false,
        };

        let flow_items = vec![FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![
                FlowUse::Server {
                    id: "h3_pinned".to_string(),
                    weight: 10,
                },
                FlowUse::Server {
                    id: "regular_cdn".to_string(),
                    weight: 10,
                },
            ],
            r#break: false,
        }];

        let result = service
            .execute_flow(&target, &context, &options, &flow_items, vec![], None)
            .await;

        assert!(
            result.is_ok(),
            "Should succeed with regular server available"
        );
        let flow_result = result.unwrap();

        // URL should be from regular server, not http3://
        assert!(
            !flow_result.url.starts_with("http3://"),
            "Non-h3 client should NOT get http3:// URL, got: {}",
            flow_result.url
        );
        assert_eq!(
            flow_result.selected_server_id,
            Some("regular_cdn".to_string()),
            "Should select the regular (non-h3) server"
        );
    }

    #[test]
    fn test_rewrite_h3_url_invalid_url() {
        let server = make_server_config(true, None);
        let result = rewrite_h3_url("not a valid url".to_string(), &server, None);
        assert!(result.is_err(), "Invalid URL should return error");
    }

    #[test]
    fn test_rewrite_h3_url_empty_path() {
        let server = make_server_config(true, None);
        let url = "https://cdn.example.com".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert_eq!(
            result, "http3://cdn.example.com/",
            "URL with no path should still get a trailing slash from url crate normalization"
        );
    }

    #[test]
    fn test_rewrite_h3_url_with_auth_and_query() {
        let server = make_server_config(true, None);
        let url = "https://cdn.example.com/path?Signature=abc123&Expires=999".to_string();
        let result = rewrite_h3_url(url, &server, None).unwrap();
        assert!(result.starts_with("http3://"), "Should rewrite to http3://");
        assert!(
            result.contains("Signature=abc123"),
            "Query params should be preserved"
        );
        assert!(
            result.contains("Expires=999"),
            "All query params should be preserved"
        );
    }

    #[test]
    fn test_rewrite_h3_url_pinned_and_trust_both_produce_cert_fragment() {
        let hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let url = "https://cdn.example.com/file.zip".to_string();

        // Pinned: always has cert fragment
        let pinned_server = make_server_config(true, Some(hex));
        let pinned_result = rewrite_h3_url(url.clone(), &pinned_server, None).unwrap();
        assert!(
            pinned_result.contains("#cert="),
            "PinnedHex should produce #cert= fragment"
        );

        // Trust: has cert fragment when health info has observed hash
        let trust_server = make_server_config(true, Some("trust"));
        let health = make_health_info(Some(hex));
        let trust_result = rewrite_h3_url(url, &trust_server, Some(&health)).unwrap();
        assert!(
            trust_result.contains("#cert="),
            "Trust mode with observed hash should produce #cert= fragment"
        );

        // Both should produce the same cert value
        assert_eq!(
            pinned_result, trust_result,
            "Same cert hash should produce same URL regardless of policy type"
        );
    }
}
