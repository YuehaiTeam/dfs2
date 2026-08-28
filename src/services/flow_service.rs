use crate::{
    config::{AppConfig, SharedConfig},
    error::{DfsError, DfsResult},
    models::{
        ClientCapabilities, FlowContext, FlowJsContext, FlowOptions, FlowPenalties, FlowResult,
        FlowTarget, PluginMetadata,
    },
    modules::{
        external::geolocation,
        flow::{FlowComp, FlowCond, FlowItem, FlowMode, FlowUse, ResourcePattern},
        network::capabilities,
        qjs::JsRunner,
        server::HealthInfo,
        storage::data_store::DataStore,
        version_file::VersionFileDecision,
    },
    services::VersionFileService,
};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

/// 一个 flow 项执行完后对管道的处置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemControl {
    /// 继续执行后续项
    Proceed,
    /// 本层到此为止：后续属于同一层的项一概跳过，其它层照常执行
    EndTier,
    /// 整条 flow 到此为止
    EndFlow,
}

/// 一次选点的结果，含选自哪一层。
///
/// 层信息只随结果返回，不进池子：池条目的形状 `(名字, 权重)` 会原样序列化给插件。
#[derive(Debug, Clone)]
struct Poolized {
    server_id: String,
    weight: u32,
    tier: u32,
}

#[derive(Clone)]
pub struct FlowService {
    shared_config: SharedConfig,
    data_store: DataStore,
    js_runner: JsRunner,
    bandwidth_cache: crate::services::BandwidthCacheService,
    resource_service: crate::services::ResourceService,
    version_file_service: VersionFileService,
}

impl FlowService {
    pub fn new(
        shared_config: SharedConfig,
        data_store: DataStore,
        js_runner: JsRunner,
        bandwidth_cache: crate::services::BandwidthCacheService,
        resource_service: crate::services::ResourceService,
    ) -> Self {
        // 只用于读取普查结论，不跑普查，因此不需要 metrics
        let version_file_service = VersionFileService::new(
            shared_config.clone(),
            data_store.clone(),
            resource_service.clone(),
            None,
        );
        Self {
            shared_config,
            data_store,
            js_runner,
            bandwidth_cache,
            resource_service,
            version_file_service,
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
        penalties: FlowPenalties,
        session: Option<&crate::models::Session>,
    ) -> DfsResult<FlowResult> {
        let mut server_pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();
        let mut selection: Option<Poolized> = None;

        // 执行Flow pipeline
        let mut ended_tiers: HashSet<u32> = HashSet::new();
        for item in flow_items {
            if ended_tiers.contains(&item.tier) {
                continue;
            }

            let control = self
                .execute_flow_item(
                    &mut server_pool,
                    item,
                    target,
                    context,
                    options,
                    session,
                    &mut plugin_server_mapping,
                    &penalties,
                    &mut selection,
                    &mut tier_mapping,
                )
                .await?;

            match control {
                ItemControl::Proceed => {}
                ItemControl::EndTier => {
                    ended_tiers.insert(item.tier);
                }
                ItemControl::EndFlow => break,
            }
        }

        // 最终poolize（如果需要）
        if (server_pool.len() > 1
            || (server_pool.len() == 1 && !server_pool[0].0.starts_with("http")))
            && let Some(poolized) = self
                .poolize_from_pool(
                    &mut server_pool,
                    target,
                    context,
                    options,
                    &plugin_server_mapping,
                    &penalties,
                    &tier_mapping,
                )
                .await?
        {
            selection = Some(poolized);
        }

        if server_pool.is_empty() {
            return Err(DfsError::internal_error("NO_RES_AVAILABLE"));
        }

        // Post-pipeline URL rewrite: catch plugin literal URLs
        let mut final_url = server_pool[0].0.clone();
        if let Some(selected) = &selection {
            let config = self.shared_config.load();
            if let Some(server_config) = config.servers.get(&selected.server_id) {
                let health_info = self
                    .get_health_info_for_server(&selected.server_id, target)
                    .await;
                final_url = capabilities::rewrite_url(
                    &final_url,
                    server_config,
                    health_info.as_ref(),
                    &context.capabilities,
                )?;
            }
        }

        Ok(FlowResult {
            url: final_url,
            selected_server_id: selection.as_ref().map(|s| s.server_id.clone()),
            selected_server_weight: selection.as_ref().map(|s| s.weight),
            selected_tier: selection.as_ref().map(|s| s.tier),
            plugin_server_mapping,
        })
    }

    /// 执行单个Flow项目
    #[allow(clippy::too_many_arguments)]
    async fn execute_flow_item(
        &self,
        pool: &mut Vec<(String, u32)>,
        item: &FlowItem,
        target: &FlowTarget,
        context: &FlowContext,
        options: &FlowOptions,
        session: Option<&crate::models::Session>,
        plugin_server_mapping: &mut HashMap<String, (Option<String>, bool)>,
        penalties: &FlowPenalties,
        selection: &mut Option<Poolized>,
        tier_mapping: &mut HashMap<String, u32>,
    ) -> DfsResult<ItemControl> {
        // 评估规则
        let should_exec = if !item.rules.is_empty() {
            self.evaluate_flow_rules(&item.rules, &item.mode, target, context)
                .await?
        } else {
            true
        };

        // 规则不命中的项不执行任何命令，也就无从截断——后续各项照常参与选点。
        let mut control = ItemControl::Proceed;

        if should_exec {
            for operation in &item.r#use {
                match operation {
                    FlowUse::Break => {
                        control = ItemControl::EndFlow;
                        break;
                    }
                    FlowUse::Continue => {
                        control = ItemControl::EndTier;
                        break;
                    }
                    FlowUse::Clear => pool.clear(),
                    FlowUse::Server { id, weight } => {
                        if penalties.banned.iter().any(|server_id| server_id == id) {
                            continue;
                        }

                        let config = self.shared_config.load();
                        if let Some(server_config) = config.servers.get(id)
                            && !capabilities::server_transport_is_usable(
                                server_config,
                                &context.capabilities,
                            )
                        {
                            debug!(
                                server = %id,
                                "Skipping server: client cannot speak the transport it requires"
                            );
                            continue;
                        }

                        Self::record_pool_entry_tier(tier_mapping, id, item.tier);
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
                        self.process_plugin_result(
                            result,
                            pool,
                            plugin_server_mapping,
                            &context.capabilities,
                        )?;

                        // 插件可以整体替换池子，因此按"尚未归属"补记而不是记录新增项
                        for (name, _) in pool.iter() {
                            Self::record_pool_entry_tier(tier_mapping, name, item.tier);
                        }
                    }
                    FlowUse::Poolize => {
                        if let Some(poolized) = self
                            .poolize_from_pool(
                                pool,
                                target,
                                context,
                                options,
                                plugin_server_mapping,
                                penalties,
                                tier_mapping,
                            )
                            .await?
                        {
                            *selection = Some(poolized);
                        }
                    }
                }
            }
        }

        Ok(control)
    }

    /// 从pool中选择服务器并生成URL（不涉及CDN记录）
    ///
    /// 按层从最优先向下尝试：只有一层内所有节点都不可用（权重全零、健康检查失败）时才降到
    /// 下一层。层内的取舍仍是加权随机，权重因此只表达同层内的流量配比。
    #[allow(clippy::too_many_arguments)]
    async fn poolize_from_pool(
        &self,
        pool: &mut Vec<(String, u32)>,
        target: &FlowTarget,
        context: &FlowContext,
        options: &FlowOptions,
        plugin_server_mapping: &HashMap<String, (Option<String>, bool)>,
        penalties: &FlowPenalties,
        tier_mapping: &HashMap<String, u32>,
    ) -> DfsResult<Option<Poolized>> {
        pool.retain(|(name, _)| {
            let server_id = Self::pool_entry_server_id(name, plugin_server_mapping);
            !penalties.banned.iter().any(|banned| banned == server_id)
        });
        self.apply_penalty_to_pool(pool, &penalties.demoted, plugin_server_mapping);

        let mut tiers: Vec<u32> = pool
            .iter()
            .map(|(name, _)| Self::pool_entry_tier(name, tier_mapping))
            .collect();
        tiers.sort_unstable();
        tiers.dedup();

        for tier in &tiers {
            let mut tier_pool: Vec<(String, u32)> = pool
                .iter()
                .filter(|(name, _)| Self::pool_entry_tier(name, tier_mapping) == *tier)
                .cloned()
                .collect();

            if let Some((server_id, weight)) = self
                .select_healthy_from_pool(&mut tier_pool, target, context, options)
                .await?
            {
                debug!(server = %server_id, tier, "Selected server from tier");
                // tier_pool 此时只剩最终 URL，由它替换整个池子
                *pool = tier_pool;
                return Ok(Some(Poolized {
                    server_id,
                    weight,
                    tier: *tier,
                }));
            }

            // 降级本身值得注意：它意味着一整层当前没有可用节点
            warn!(
                "Tier {} has no usable server; falling through (tiers in pool: {:?})",
                tier, tiers
            );
        }

        // 调用方以空池判定 NO_RES_AVAILABLE，池里若留着未解析的节点名会被当成 URL 返回
        pool.clear();
        Ok(None)
    }

    /// 在给定池子内做加权随机并健康检查，不健康的节点就地剔除后重试。
    ///
    /// 成功时池子被换成只含最终 URL 的单条目；失败时池子为空。
    async fn select_healthy_from_pool(
        &self,
        pool: &mut Vec<(String, u32)>,
        target: &FlowTarget,
        context: &FlowContext,
        options: &FlowOptions,
    ) -> DfsResult<Option<(String, u32)>> {
        while !pool.is_empty() {
            let selected_server = match self.weighted_random_selection(pool) {
                Ok(selected) => selected,
                Err(e) => {
                    // 权重全零属于配置意图（整层禁用），不是错误
                    debug!("No selectable server in this tier: {}", e);
                    pool.clear();
                    return Ok(None);
                }
            };

            if self.is_server_healthy(&selected_server, target).await? {
                let url = self
                    .generate_server_url(&selected_server, target, context, options)
                    .await?;
                pool.clear();
                pool.push((url, selected_server.1));
                return Ok(Some(selected_server));
            }

            pool.retain(|x| x.0 != selected_server.0);
        }

        Ok(None)
    }

    /// 池条目所属的层，未记录的条目视为最优先层
    fn pool_entry_tier(name: &str, tier_mapping: &HashMap<String, u32>) -> u32 {
        tier_mapping.get(name).copied().unwrap_or(0)
    }

    /// 记录池条目的层。同一条目被多层引用时以最优先的那层为准。
    fn record_pool_entry_tier(tier_mapping: &mut HashMap<String, u32>, name: &str, tier: u32) {
        tier_mapping
            .entry(name.to_string())
            .and_modify(|existing| *existing = (*existing).min(tier))
            .or_insert(tier);
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
                // 内部取件按配置的出口栈判定：调度器配了哪个栈的出口，就能从那个栈的节点取件。
                // context.client_ip 里只有为地理求值挑出的那一个（双栈时取 v4），拿它判 ipversion
                // 会把 v6-only 层对双栈调度器也关掉。
                if context.internal {
                    let config = self.shared_config.load();
                    return Ok(match expected_version {
                        4 => config.internal.ip4.is_some(),
                        6 => config.internal.ip6.is_some(),
                        _ => false,
                    });
                }
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

                if let Ok(Some(usage_str)) = self.data_store.get_string(&cache_key).await
                    && let Ok(current_usage) = usage_str.parse::<u64>()
                {
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
            FlowCond::Internal(expected) => Ok(*expected == context.internal),
            FlowCond::Not(inner) => {
                // 取反的是内层的求值结果，不是"内层为真的补集"：内层因信息缺失而为 false 时，
                // 取反给出 true。判定失败（Err）不参与取反，照原样上抛。
                let inner_result =
                    Box::pin(self.evaluate_condition(inner, target, context)).await?;
                Ok(!inner_result)
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
    ///
    /// 条目在压入池子之前逐条过门禁：客户端用不了的传输、指向未定义节点的归属声明都在这里丢弃，
    /// 池里剩下的因此都是可交付的，加权随机的分母也才是对的。
    fn process_plugin_result(
        &self,
        result: serde_json::Value,
        pool: &mut Vec<(String, u32)>,
        plugin_server_mapping: &mut HashMap<String, (Option<String>, bool)>,
        capabilities: &ClientCapabilities,
    ) -> DfsResult<()> {
        let config = self.shared_config.load();

        // 尝试解析增强格式
        if let Ok((_should_break, enhanced_pool)) = serde_json::from_value::<(
            bool,
            Vec<(String, u32, Option<PluginMetadata>)>,
        )>(result.clone())
        {
            pool.clear();
            for (url, weight, metadata) in enhanced_pool {
                let server_id = metadata
                    .as_ref()
                    .and_then(|metadata| metadata.server_id.as_deref());
                if !Self::plugin_entry_is_usable(&config, &url, server_id, capabilities) {
                    continue;
                }

                pool.push((url.clone(), weight));

                if let Some(metadata) = metadata {
                    plugin_server_mapping.insert(
                        url,
                        (metadata.server_id, metadata.skip_penalty.unwrap_or(false)),
                    );
                }
            }
        } else {
            // 兼容旧格式：没有 metadata 层，归属无从得知，只能按 URL 自身的 scheme 判定
            let (_should_break, basic_pool): (bool, Vec<(String, u32)>) =
                serde_json::from_value(result).map_err(|e| {
                    DfsError::internal_error(format!("Failed to parse plugin result: {e}"))
                })?;
            pool.clear();
            pool.extend(basic_pool.into_iter().filter(|(url, _weight)| {
                Self::plugin_entry_is_usable(&config, url, None, capabilities)
            }));
        }
        Ok(())
    }

    /// 插件返回的一条池条目能否交给这个客户端。
    ///
    /// 声明了归属时以节点配置为准：插件用内置签名函数生成的 URL 是 `http(s)://`，scheme 上看不
    /// 出传输要求，节点配置是更精确的判据。声明的节点不存在则丢弃——它解析不成任何真实节点，留在
    /// 池里只会占着权重份额等健康检查剔除。未声明归属的条目只剩 scheme 可依据。
    fn plugin_entry_is_usable(
        config: &AppConfig,
        url: &str,
        server_id: Option<&str>,
        capabilities: &ClientCapabilities,
    ) -> bool {
        if let Some(server_id) = server_id {
            let Some(server_config) = config.servers.get(server_id) else {
                debug!(
                    server = %server_id,
                    url = %url,
                    "Dropping plugin entry: it claims a server that is not defined"
                );
                return false;
            };

            if !capabilities::server_transport_is_usable(server_config, capabilities) {
                debug!(
                    server = %server_id,
                    url = %url,
                    "Dropping plugin entry: client cannot speak the transport its server requires"
                );
                return false;
            }
        }

        if !capabilities::url_transport_is_usable(url, capabilities) {
            debug!(
                url = %url,
                "Dropping plugin entry: client cannot speak the transport its scheme requires"
            );
            return false;
        }

        true
    }

    fn pool_entry_server_id<'a>(
        name: &'a str,
        plugin_server_mapping: &'a HashMap<String, (Option<String>, bool)>,
    ) -> &'a str {
        plugin_server_mapping
            .get(name)
            .and_then(|(server_id, _)| server_id.as_deref())
            .unwrap_or(name)
    }

    /// 已签过的节点降权摊开：减半，下限 1。
    fn apply_penalty_to_pool(
        &self,
        pool: &mut [(String, u32)],
        demoted: &[String],
        plugin_server_mapping: &HashMap<String, (Option<String>, bool)>,
    ) {
        if demoted.is_empty() {
            return;
        }

        for (server_name, weight) in pool.iter_mut() {
            let server_id = Self::pool_entry_server_id(server_name, plugin_server_mapping);
            if demoted.iter().any(|id| id == server_id) {
                let new_weight = (*weight / 2).max(1);
                if new_weight != *weight {
                    info!(
                        "Demoted server {} for reuse: {} -> {}",
                        server_id, *weight, new_weight
                    );
                }
                *weight = new_weight;
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

        // 抽样区间是半开的 [0, total)，比较必须同为严格小于：写成 `<=` 会让每个条目多占一格，
        // 权重 0 的条目变得可选（`server x 0` 本意是禁用），且靠前的条目被系统性偏向。
        for (server_id, weight) in pool.iter() {
            if random_weight < *weight {
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

            if self
                .version_file_service
                .is_version_file_request(
                    &validated_resource_id,
                    &effective_version,
                    &health_check_path,
                )
                .await
            {
                match self
                    .version_file_service
                    .evaluate_path(&validated_resource_id, &health_check_path, &server.0)
                    .await
                {
                    VersionFileDecision::SplitFailed | VersionFileDecision::Mismatch => {
                        return Ok(false);
                    }
                    VersionFileDecision::Match | VersionFileDecision::Unknown => {}
                }
            }

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

            // Apply transport URL rewrite if applicable
            if let Some(server_config) = config.servers.get(&server.0) {
                let health_info = self.get_health_info_for_server(&server.0, target).await;
                return capabilities::rewrite_url(
                    &url,
                    server_config,
                    health_info.as_ref(),
                    &context.capabilities,
                );
            }

            Ok(url)
        } else {
            Err(DfsError::server_unavailable(&server.0))
        }
    }

    /// Retrieve cached HealthInfo for a server, used for transport cert hash resolution.
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
    use crate::modules::network::capabilities::{ClientCapabilities, rewrite_url};
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
            capabilities: Default::default(),
            internal: false,
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

    /// `not` 取反的是内层的求值结果。这与"内层为真的补集"在信息缺失时不同：
    /// 没有客户端 IP 时 `cnip true` 与 `cnip false` 同为 false，`not` 把两者都翻成 true。
    #[tokio::test]
    async fn not_inverts_the_evaluated_result_including_missing_information() {
        let service = create_test_flow_service().await;
        let (target, mut context, _options) = create_test_context();

        context.client_ip = Some("8.8.8.8".parse().unwrap());
        let inner = FlowCond::CnIp(false);
        let inner_result = service
            .evaluate_condition(&inner, &target, &context)
            .await
            .expect("inner condition evaluates");
        let negated = service
            .evaluate_condition(&FlowCond::Not(Box::new(inner)), &target, &context)
            .await
            .expect("negated condition evaluates");
        assert_eq!(negated, !inner_result);

        // 无 IP 时两个方向都为 false，取反后都为 true
        context.client_ip = None;
        for expected_is_cn in [true, false] {
            assert!(
                !service
                    .evaluate_condition(&FlowCond::CnIp(expected_is_cn), &target, &context)
                    .await
                    .expect("cnip evaluates without an IP"),
                "cnip {expected_is_cn} should be false without a client IP"
            );
            assert!(
                service
                    .evaluate_condition(
                        &FlowCond::Not(Box::new(FlowCond::CnIp(expected_is_cn))),
                        &target,
                        &context
                    )
                    .await
                    .expect("negated cnip evaluates without an IP"),
                "not cnip {expected_is_cn} is true without a client IP"
            );
        }

        // 嵌套取反回到原值
        context.client_ip = Some("8.8.8.8".parse().unwrap());
        let double = FlowCond::Not(Box::new(FlowCond::Not(Box::new(FlowCond::CnIp(false)))));
        assert_eq!(
            service
                .evaluate_condition(&double, &target, &context)
                .await
                .expect("nested negation evaluates"),
            inner_result
        );
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
        assert!(
            !result.unwrap(),
            "Without IPDB, all IPs are considered global (non-CN)"
        );

        // 测试cnip false条件 - 应该返回true（因为所有IP都是全球IP）
        let result = service
            .evaluate_condition(&FlowCond::CnIp(false), &target, &context)
            .await;
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "Without IPDB, cnip false should return true"
        );

        // 测试不同IP地址 - 在没有IPDB的情况下结果应该相同
        context.client_ip = Some("8.8.8.8".parse().unwrap());
        let result = service
            .evaluate_condition(&FlowCond::CnIp(false), &target, &context)
            .await;
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "All IPs should be treated as global without IPDB"
        );

        // 无IP情况
        context.client_ip = None;
        let result = service
            .evaluate_condition(&FlowCond::CnIp(true), &target, &context)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "No IP should return false");

        // 测试 IpVersion 条件
        context.client_ip = Some("192.168.1.100".parse().unwrap()); // IPv4
        let result = service
            .evaluate_condition(&FlowCond::IpVersion(4), &target, &context)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "IPv4 address should match version 4");

        context.client_ip = Some("::1".parse().unwrap()); // IPv6
        let result = service
            .evaluate_condition(&FlowCond::IpVersion(6), &target, &context)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "IPv6 address should match version 6");

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
        assert!(
            result.unwrap(),
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
        assert!(result.unwrap(), "1048576 bytes should be less than 2MB");

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
        assert!(result.unwrap(), "1048576 bytes should be >= 1MB");

        // 测试精确相等 - 使用已知的字节数
        sized_target.file_size = Some(size_1mb.bytes() as u64);
        let result = service
            .evaluate_condition(
                &FlowCond::Size(FlowComp::Eq, size_1mb),
                &sized_target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "Exact bytes should equal");

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
        assert!(!result.unwrap(), "No file size should return false");

        // 测试 Extras 条件
        let result = service
            .evaluate_condition(
                &FlowCond::Extras("test_flag".to_string()),
                &target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "Existing extra field should return true");

        let result = service
            .evaluate_condition(
                &FlowCond::Extras("nonexistent".to_string()),
                &target,
                &context,
            )
            .await;
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
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
        assert!(result.unwrap(), "Empty rules should return true");

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
        assert!(
            result.unwrap(),
            "AND mode: both conditions true should return true"
        );

        // 全球IP + 500KB文件 -> 大小条件不满足 -> false
        sized_target.file_size = Some(500 * 1024); // 500KB
        let result = service
            .evaluate_flow_rules(&and_rules, &FlowMode::AND, &sized_target, &context)
            .await;
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "AND mode: one condition false should return false"
        );

        // 测试使用cnip true的场景 - 应该总是失败
        let cn_ip_rules = vec![FlowCond::CnIp(true)]; // 中国IP条件
        let result = service
            .evaluate_flow_rules(&cn_ip_rules, &FlowMode::AND, &sized_target, &context)
            .await;
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
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
        assert!(
            result.unwrap(),
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
        assert!(
            !result.unwrap(),
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
        assert!(
            result.unwrap(),
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

    /// 权重语义的精确边界。上面那个分布测试的 ±10% 容差盖不住这些情况：
    /// 等权时末位可达、首位 0 权重不可选、小权重下的配比不偏。
    #[tokio::test]
    async fn weighted_selection_respects_exact_weights() {
        let service = create_test_flow_service().await;

        // 等权两节点：末位必须可达。区间半开而比较取闭时，(1,1) 的第二个节点永远选不到。
        let equal_pool = vec![("first".to_string(), 1), ("second".to_string(), 1)];
        let mut seen_second = false;
        let mut first_count = 0;
        for _ in 0..400 {
            let (selected, _) = service
                .weighted_random_selection(&equal_pool)
                .expect("equal pool selects");
            if selected == "second" {
                seen_second = true;
            } else {
                first_count += 1;
            }
        }
        assert!(
            seen_second,
            "second entry of an equal-weight pool is unreachable"
        );
        let first_ratio = f64::from(first_count) / 400.0;
        assert!(
            (0.40..=0.60).contains(&first_ratio),
            "equal weights should split evenly, first got {:.1}%",
            first_ratio * 100.0
        );

        // 首位 0 权重：`server x 0` 表示禁用，不能因为落在区间端点而被选中
        let leading_zero_pool = vec![
            ("disabled".to_string(), 0),
            ("alpha".to_string(), 1),
            ("beta".to_string(), 1),
        ];
        for _ in 0..400 {
            let (selected, weight) = service
                .weighted_random_selection(&leading_zero_pool)
                .expect("pool with positive total selects");
            assert_ne!(
                selected, "disabled",
                "zero-weight entry must stay unselected"
            );
            assert!(weight > 0);
        }
    }

    #[tokio::test]
    async fn test_apply_penalty_to_pool() {
        let service = create_test_flow_service().await;
        let mapping = HashMap::new();

        let mut pool = vec![
            ("server1".to_string(), 10),
            ("server2".to_string(), 5),
            ("server3".to_string(), 8),
        ];
        let original_pool = pool.clone();
        service.apply_penalty_to_pool(&mut pool, &[], &mapping);
        assert_eq!(
            pool, original_pool,
            "Empty demoted list should not change weights"
        );

        let mut pool = vec![
            ("server1".to_string(), 10),
            ("server2".to_string(), 5),
            ("server3".to_string(), 8),
        ];
        let demoted = vec!["server1".to_string(), "server3".to_string()];
        service.apply_penalty_to_pool(&mut pool, &demoted, &mapping);
        assert_eq!(pool[0].1, 5, "server1 10 should halve to 5");
        assert_eq!(pool[1].1, 5, "untouched server should keep weight");
        assert_eq!(pool[2].1, 4, "server3 8 should halve to 4");

        let mut pool = vec![
            ("server1".to_string(), 10),
            ("server2".to_string(), 5),
            ("server3".to_string(), 8),
        ];
        let all_demoted = vec![
            "server1".to_string(),
            "server2".to_string(),
            "server3".to_string(),
        ];
        service.apply_penalty_to_pool(&mut pool, &all_demoted, &mapping);
        assert_eq!(pool[0].1, 5);
        assert_eq!(pool[1].1, 2);
        assert_eq!(pool[2].1, 4);

        let mut pool = vec![("server1".to_string(), 1), ("server2".to_string(), 6)];
        service.apply_penalty_to_pool(&mut pool, &["server1".to_string()], &mapping);
        assert_eq!(pool[0].1, 1, "weight 1 must stay at least 1");
        assert_eq!(pool[1].1, 6);

        let mut pool = vec![("server1".to_string(), 10), ("server2".to_string(), 5)];
        let original_pool = pool.clone();
        service.apply_penalty_to_pool(&mut pool, &["missing".to_string()], &mapping);
        assert_eq!(pool, original_pool);
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
            size_1gb,
        );

        let result = service
            .evaluate_condition(&condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "800MB should be less than 1GB");

        // 测试大于条件：800MB > 500MB -> true
        let size_500mb = Size::from_str("500MB").unwrap();
        let condition =
            FlowCond::ServerBwMinutes(server_id.to_string(), 30, FlowComp::Gt, size_500mb);

        let result = service
            .evaluate_condition(&condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "800MB should be greater than 500MB");

        // 测试等于条件（使用确切值）
        let size_800mb = Size::from_str("800MB").unwrap();
        let condition =
            FlowCond::ServerBwMinutes(server_id.to_string(), 30, FlowComp::Eq, size_800mb);

        let result = service
            .evaluate_condition(&condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "800MB should equal 800MB");

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
        assert!(
            result.unwrap(),
            "Non-existent server should have 0 bandwidth, thus < 100MB"
        );

        // 测试不同时间窗口的流量查询
        let smaller_window_condition = FlowCond::ServerBwMinutes(
            server_id.to_string(),
            1, // 1分钟窗口（应该包含所有当前分钟的流量）
            FlowComp::Eq,
            size_800mb,
        );

        let result = service
            .evaluate_condition(&smaller_window_condition, &target, &context)
            .await;
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
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
        assert!(
            !result.unwrap(),
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
        assert!(
            result.unwrap(),
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
        assert!(
            result.unwrap(),
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
        assert!(
            result.unwrap(),
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
            assert!(
                result.unwrap(),
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
        assert!(
            result.unwrap(),
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
                    "server_id": "test_server_1",
                    "skip_penalty": true
                }],
                ["http://server2.example.com/file", 5, {
                    "server_id": "test_server_2",
                    "skip_penalty": false
                }],
                ["http://server3.example.com/file", 8, null]
            ]
        ]);

        let mut pool = vec![];
        let mut plugin_server_mapping = HashMap::new();

        let result = service.process_plugin_result(
            enhanced_result,
            &mut pool,
            &mut plugin_server_mapping,
            &ClientCapabilities::default(),
        );
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
            Some(&(Some("test_server_1".to_string()), true))
        );
        assert_eq!(
            plugin_server_mapping.get("http://server2.example.com/file"),
            Some(&(Some("test_server_2".to_string()), false))
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

        let result = service.process_plugin_result(
            compatible_result,
            &mut pool,
            &mut plugin_server_mapping,
            &ClientCapabilities::default(),
        );
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

        let result = service.process_plugin_result(
            invalid_result,
            &mut pool,
            &mut plugin_server_mapping,
            &ClientCapabilities::default(),
        );
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
            &ClientCapabilities::default(),
        );
        assert!(
            result.is_err(),
            "Partial invalid format should return error"
        );

        // 测试空结果
        let empty_result = json!([false, []]);
        let mut pool = vec![("existing".to_string(), 1)]; // 预存在的数据
        let mut plugin_server_mapping = HashMap::new();

        let result = service.process_plugin_result(
            empty_result,
            &mut pool,
            &mut plugin_server_mapping,
            &ClientCapabilities::default(),
        );
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
                    "server_id": "test_server_1",
                    "skip_penalty": true
                }],
                ["http://penalty-normal.example.com/file", 10, {
                    "server_id": "test_server_2"
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
            &ClientCapabilities::default(),
        );
        assert!(result.is_ok(), "Skip penalty result should be valid");

        // 验证skip_penalty处理
        assert_eq!(
            plugin_server_mapping.get("http://penalty-skip.example.com/file"),
            Some(&(Some("test_server_1".to_string()), true)),
            "skip_penalty: true should be preserved"
        );
        assert_eq!(
            plugin_server_mapping.get("http://penalty-normal.example.com/file"),
            Some(&(Some("test_server_2".to_string()), false)),
            "missing skip_penalty should default to false"
        );

        println!("✅ All plugin result processing tests passed");
    }

    /// 带 `h3_server`（h3_only）与 `test_server_1`（direct）的服务，用来分别观察两条门禁判据。
    async fn plugin_gate_service() -> FlowService {
        let env = TestEnvironment::with_config(create_h3_test_config()).await;
        env.services.flow_service
    }

    fn gate_plugin_result(entries: serde_json::Value) -> serde_json::Value {
        json!([false, entries])
    }

    async fn pool_after_plugin(
        service: &FlowService,
        entries: serde_json::Value,
        capabilities: &ClientCapabilities,
    ) -> Vec<(String, u32)> {
        let mut pool = vec![];
        let mut plugin_server_mapping = HashMap::new();
        service
            .process_plugin_result(
                gate_plugin_result(entries),
                &mut pool,
                &mut plugin_server_mapping,
                capabilities,
            )
            .expect("plugin result should parse");
        pool
    }

    #[tokio::test]
    async fn a_plugin_entry_claiming_an_undefined_server_is_dropped() {
        let service = plugin_gate_service().await;

        let pool = pool_after_plugin(
            &service,
            json!([
                ["https://ghost.example.com/f", 10, {"server_id": "ghost"}],
                ["https://real.example.com/f", 7, {"server_id": "test_server_1"}]
            ]),
            &ClientCapabilities::default(),
        )
        .await;

        assert_eq!(pool, vec![("https://real.example.com/f".to_string(), 7)]);
    }

    /// 归属声明比 scheme 更精确：URL 是 `https://`，只有节点配置能说出它要 HTTP/3。
    #[tokio::test]
    async fn a_plugin_entry_is_gated_by_the_server_it_claims() {
        let service = plugin_gate_service().await;
        let entries = json!([["https://h3.example.com/f", 10, {"server_id": "h3_server"}]]);

        let without_h3 =
            pool_after_plugin(&service, entries.clone(), &ClientCapabilities::default()).await;
        assert!(without_h3.is_empty());

        let with_h3 = pool_after_plugin(
            &service,
            entries,
            &ClientCapabilities {
                h3: true,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(with_h3.len(), 1);
    }

    /// 没有归属声明时只剩 scheme 可依据。
    #[tokio::test]
    async fn a_plugin_entry_is_gated_by_its_own_scheme() {
        let service = plugin_gate_service().await;
        let entries = json!([
            ["http3://cdn.example.com/f", 10, null],
            ["https://plain.example.com/f", 5, null]
        ]);

        let without_h3 =
            pool_after_plugin(&service, entries.clone(), &ClientCapabilities::default()).await;
        assert_eq!(
            without_h3,
            vec![("https://plain.example.com/f".to_string(), 5)]
        );

        let with_h3 = pool_after_plugin(
            &service,
            entries,
            &ClientCapabilities {
                h3: true,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(with_h3.len(), 2);
    }

    /// 旧格式没有 metadata 层，若不逐条过 scheme 门禁就会整批绕过。
    #[tokio::test]
    async fn legacy_format_entries_are_gated_by_scheme_too() {
        let service = plugin_gate_service().await;

        let pool = pool_after_plugin(
            &service,
            json!([
                ["sftp://node.example.com:22/f", 10],
                ["https://plain.example.com/f", 5]
            ]),
            &ClientCapabilities::default(),
        )
        .await;

        assert_eq!(pool, vec![("https://plain.example.com/f".to_string(), 5)]);
    }

    /// 门禁丢弃的条目不进 `plugin_server_mapping`，否则惩罚与层归属会挂在不存在的池条目上。
    #[tokio::test]
    async fn dropped_entries_leave_no_mapping_behind() {
        let service = plugin_gate_service().await;
        let mut pool = vec![];
        let mut plugin_server_mapping = HashMap::new();

        service
            .process_plugin_result(
                gate_plugin_result(json!([
                    ["https://h3.example.com/f", 10, {"server_id": "h3_server"}],
                    ["https://ghost.example.com/f", 10, {"server_id": "ghost"}]
                ])),
                &mut pool,
                &mut plugin_server_mapping,
                &ClientCapabilities::default(),
            )
            .expect("plugin result should parse");

        assert!(pool.is_empty());
        assert!(plugin_server_mapping.is_empty());
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
            if let Some(server_config) = config.servers.get(id)
                && let Ok(server) = crate::modules::server::ServerImpl::new(server_config)
            {
                config.server_impl.insert(id.to_string(), server);
            }
        }

        config
    }

    /// Helper: create FlowService with h3 test config
    async fn create_h3_test_flow_service() -> FlowService {
        let env = TestEnvironment::with_config(create_h3_test_config()).await;
        env.services.flow_service
    }

    /// 内部取件的能力面取自本进程的 fetch 客户端，而不是"什么都不支持"。
    /// 用全 false 的 `Default` 时，h3_only 节点对内部取件永远不可选。
    #[tokio::test]
    async fn internal_fetch_can_use_h3_only_servers() {
        let service = create_h3_test_flow_service().await;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        let (target, _client_context, options) = create_test_context();
        let context = FlowContext::internal(None);
        assert!(context.internal);
        assert!(context.capabilities.h3, "内部取件走 H3 middleware");
        assert!(!context.capabilities.wt, "本进程不做 WebTransport 客户端");

        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "h3_server".to_string(),
                weight: 10,
            }],
            tier: 0,
        };

        service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &FlowPenalties::default(),
                &mut selection,
                &mut tier_mapping,
            )
            .await
            .expect("flow item executes for an internal fetch");

        assert_eq!(
            pool,
            vec![("h3_server".to_string(), 10)],
            "h3_only server should be selectable for an internal fetch"
        );
    }

    /// `internal` 条件区分的是"谁发起的取件"，不是"客户端 IP 是否已知"。
    #[tokio::test]
    async fn internal_condition_distinguishes_the_originator() {
        let service = create_test_flow_service().await;
        let (target, mut client_context, _options) = create_test_context();

        let internal_context = FlowContext::internal(None);
        assert!(
            service
                .evaluate_condition(&FlowCond::Internal(true), &target, &internal_context)
                .await
                .expect("internal condition evaluates")
        );

        // 客户端 IP 缺失的客户端请求仍然不是内部取件
        client_context.client_ip = None;
        assert!(
            !service
                .evaluate_condition(&FlowCond::Internal(true), &target, &client_context)
                .await
                .expect("internal condition evaluates"),
            "a client request without a resolved IP is not an internal fetch"
        );
        assert!(
            service
                .evaluate_condition(&FlowCond::Internal(false), &target, &client_context)
                .await
                .expect("internal condition evaluates")
        );
    }

    /// 配置了出口 IP 的内部上下文按该 IP 参与地理条件求值；`internal` 条件只看标志、与 IP 无关。
    #[tokio::test]
    async fn an_egress_ip_lets_geo_conditions_route_internal_fetches() {
        let service = create_test_flow_service().await;
        let (target, _client_context, _options) = create_test_context();

        // 无 IP 时 cnip 两个方向都不命中，带 IP 后（测试环境无 IPDB，一律判全球）cnip false 命中
        let without_ip = FlowContext::internal(None);
        assert!(
            !service
                .evaluate_condition(&FlowCond::CnIp(false), &target, &without_ip)
                .await
                .expect("cnip evaluates")
        );

        let with_ip = FlowContext::internal(Some("203.0.113.0".parse().unwrap()));
        assert!(
            service
                .evaluate_condition(&FlowCond::CnIp(false), &target, &with_ip)
                .await
                .expect("cnip evaluates"),
            "an internal context carrying an egress IP must be routable by geo conditions"
        );

        // cidr 同样按出口 IP 判定
        let cidr: FlowCond = serde_yaml::from_str("cidr 203.0.113.0/24").expect("cidr parses");
        assert!(
            service
                .evaluate_condition(&cidr, &target, &with_ip)
                .await
                .expect("cidr evaluates")
        );

        // internal 条件的判定与 IP 无关
        for context in [&without_ip, &with_ip] {
            assert!(
                service
                    .evaluate_condition(&FlowCond::Internal(true), &target, context)
                    .await
                    .expect("internal condition evaluates"),
                "the internal flag must not depend on the egress IP"
            );
        }
    }

    /// `ipversion` 对内部取件按配置的出口栈判定，不看 `client_ip` 里为地理求值挑出的那一个：
    /// 双栈调度器的 v6-only 层必须可达，尽管地理求值用的是 v4。
    #[tokio::test]
    async fn internal_ipversion_follows_the_configured_egress_stacks() {
        let mut config = crate::tests::mocks::create_default_test_config();
        config.internal = crate::config::InternalConfig {
            ip4: Some("203.0.113.0".parse().unwrap()),
            ip6: Some("2001:db8:1234::".parse().unwrap()),
        };
        let env = TestEnvironment::with_config(config).await;
        let service = env.services.flow_service.clone();
        let (target, _client_context, _options) = create_test_context();

        let internal_context = FlowContext::internal(Some("203.0.113.0".parse().unwrap()));
        for version in [4, 6] {
            assert!(
                service
                    .evaluate_condition(&FlowCond::IpVersion(version), &target, &internal_context)
                    .await
                    .expect("ipversion evaluates"),
                "a dual-stack scheduler must match ipversion {version}"
            );
        }

        // 只配 v4 的调度器够不到 v6-only 层
        let mut v4_only = crate::tests::mocks::create_default_test_config();
        v4_only.internal = crate::config::InternalConfig {
            ip4: Some("203.0.113.0".parse().unwrap()),
            ip6: None,
        };
        let env = TestEnvironment::with_config(v4_only).await;
        let service = env.services.flow_service.clone();
        assert!(
            !service
                .evaluate_condition(&FlowCond::IpVersion(6), &target, &internal_context)
                .await
                .expect("ipversion evaluates"),
            "a v4-only scheduler must not match ipversion 6"
        );

        // 未配置 internal 段时行为与配置引入前一致：两个版本都不命中
        let env = TestEnvironment::new().await;
        let service = env.services.flow_service.clone();
        let unconfigured_context = FlowContext::internal(None);
        for version in [4, 6] {
            assert!(
                !service
                    .evaluate_condition(
                        &FlowCond::IpVersion(version),
                        &target,
                        &unconfigured_context
                    )
                    .await
                    .expect("ipversion evaluates"),
                "an unconfigured scheduler matches no ipversion"
            );
        }
    }

    #[tokio::test]
    async fn test_h3_only_server_skipped_when_not_h3_capable() {
        let service = create_h3_test_flow_service().await;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        let (target, mut context, options) = create_test_context();
        context.capabilities.h3 = false;

        // Flow item with h3_only server
        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "h3_server".to_string(),
                weight: 10,
            }],
            tier: 0,
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
                &FlowPenalties::default(),
                &mut selection,
                &mut tier_mapping,
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
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        let (target, mut context, options) = create_test_context();
        context.capabilities.h3 = true;

        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "h3_server".to_string(),
                weight: 10,
            }],
            tier: 0,
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
                &FlowPenalties::default(),
                &mut selection,
                &mut tier_mapping,
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
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        let (target, mut context, options) = create_test_context();
        context.capabilities.h3 = false;

        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "normal_server".to_string(),
                weight: 5,
            }],
            tier: 0,
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
                &FlowPenalties::default(),
                &mut selection,
                &mut tier_mapping,
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
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        let (target, mut context, options) = create_test_context();
        context.capabilities.h3 = false;

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
            tier: 0,
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
                &FlowPenalties::default(),
                &mut selection,
                &mut tier_mapping,
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
        context.capabilities.h3 = true;

        let _should_break = service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &FlowPenalties::default(),
                &mut selection,
                &mut tier_mapping,
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
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        let (target, mut context, options) = create_test_context();
        context.capabilities.h3 = true;

        // h3_server is both h3_only AND banned after a retry
        let penalties = FlowPenalties {
            banned: vec!["h3_server".to_string()],
            demoted: Vec::new(),
        };

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
            tier: 0,
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
                &penalties,
                &mut selection,
                &mut tier_mapping,
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
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        let (target, mut context, options) = create_test_context();
        context.capabilities.h3 = false;

        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Server {
                id: "unknown_server".to_string(),
                weight: 7,
            }],
            tier: 0,
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
                &FlowPenalties::default(),
                &mut selection,
                &mut tier_mapping,
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

    /// 同层内权重仍然只表达流量配比，不表达优先级。
    #[tokio::test]
    async fn weights_within_a_tier_still_split_traffic() {
        let service = create_h3_test_flow_service().await;
        let (target, mut context, options) = create_test_context();
        context.capabilities.h3 = true;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        let item = FlowItem {
            rules: vec![],
            mode: FlowMode::AND,
            r#use: vec![
                FlowUse::Server {
                    id: "normal_server".to_string(),
                    weight: 3,
                },
                FlowUse::Server {
                    id: "h3_server".to_string(),
                    weight: 7,
                },
            ],
            tier: 2,
        };

        service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &FlowPenalties::default(),
                &mut selection,
                &mut tier_mapping,
            )
            .await
            .expect("flow item executes");

        // 同一项贡献的节点同层，权重原样保留
        assert_eq!(
            pool,
            vec![
                ("normal_server".to_string(), 3),
                ("h3_server".to_string(), 7)
            ]
        );
        assert_eq!(tier_mapping.get("normal_server"), Some(&2));
        assert_eq!(tier_mapping.get("h3_server"), Some(&2));
    }

    /// 同一节点被多层引用时按最优先的那层处理，否则层归属取决于配置书写顺序。
    #[tokio::test]
    async fn a_server_referenced_by_several_tiers_takes_the_highest() {
        let service = create_h3_test_flow_service().await;
        let (target, mut context, options) = create_test_context();
        context.capabilities.h3 = true;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        for tier in [3, 1, 4] {
            let item = FlowItem {
                rules: vec![],
                mode: FlowMode::AND,
                r#use: vec![FlowUse::Server {
                    id: "normal_server".to_string(),
                    weight: 5,
                }],
                tier,
            };
            service
                .execute_flow_item(
                    &mut pool,
                    &item,
                    &target,
                    &context,
                    &options,
                    None,
                    &mut plugin_server_mapping,
                    &FlowPenalties::default(),
                    &mut selection,
                    &mut tier_mapping,
                )
                .await
                .expect("flow item executes");
        }

        assert_eq!(tier_mapping.get("normal_server"), Some(&1));
    }

    /// `break` 与 `continue` 作为命令，位置决定它们截断到哪里。
    #[tokio::test]
    async fn break_and_continue_commands_stop_at_their_position() {
        let service = create_test_flow_service().await;
        let (target, context, options) = create_test_context();

        let cases = [
            (FlowUse::Break, ItemControl::EndFlow, "break"),
            (FlowUse::Continue, ItemControl::EndTier, "continue"),
        ];

        for (command, expected_control, name) in cases {
            let item = FlowItem {
                rules: vec![],
                mode: FlowMode::AND,
                r#use: vec![
                    FlowUse::Server {
                        id: "before".to_string(),
                        weight: 3,
                    },
                    command,
                    FlowUse::Server {
                        id: "after".to_string(),
                        weight: 4,
                    },
                ],
                tier: 0,
            };

            let mut pool = Vec::new();
            let mut plugin_server_mapping = HashMap::new();
            let mut selection: Option<Poolized> = None;
            let mut tier_mapping: HashMap<String, u32> = HashMap::new();

            let control = service
                .execute_flow_item(
                    &mut pool,
                    &item,
                    &target,
                    &context,
                    &options,
                    None,
                    &mut plugin_server_mapping,
                    &FlowPenalties::default(),
                    &mut selection,
                    &mut tier_mapping,
                )
                .await
                .expect("flow item executes");

            assert_eq!(control, expected_control, "{name} controls the flow");
            assert_eq!(
                pool,
                vec![("before".to_string(), 3)],
                "commands after {name} in the same use list must not run"
            );
        }
    }

    /// 规则不命中时，`break` / `continue` 命令都不执行——它们在 `use` 里，与其它命令同权。
    #[tokio::test]
    async fn control_commands_do_not_run_when_rules_miss() {
        let service = create_test_flow_service().await;
        let (target, mut context, options) = create_test_context();
        context.client_ip = Some("8.8.8.8".parse().unwrap());

        let item = FlowItem {
            rules: vec![FlowCond::CnIp(true)],
            mode: FlowMode::AND,
            r#use: vec![FlowUse::Break],
            tier: 0,
        };

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();

        let control = service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &FlowPenalties::default(),
                &mut selection,
                &mut tier_mapping,
            )
            .await
            .expect("flow item executes");

        assert_eq!(
            control,
            ItemControl::Proceed,
            "a break command in an unmatched item is inert"
        );
    }

    #[tokio::test]
    async fn test_demoted_servers_stay_in_pool_with_half_weight() {
        let service = create_h3_test_flow_service().await;

        let mut pool = Vec::new();
        let mut plugin_server_mapping = HashMap::new();
        let mut selection: Option<Poolized> = None;
        let mut tier_mapping: HashMap<String, u32> = HashMap::new();
        let (target, mut context, options) = create_test_context();
        context.capabilities.h3 = true;
        let penalties = FlowPenalties {
            banned: Vec::new(),
            demoted: vec!["normal_server".to_string()],
        };
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
                    weight: 6,
                },
            ],
            tier: 0,
        };

        service
            .execute_flow_item(
                &mut pool,
                &item,
                &target,
                &context,
                &options,
                None,
                &mut plugin_server_mapping,
                &penalties,
                &mut selection,
                &mut tier_mapping,
            )
            .await
            .unwrap();

        assert_eq!(pool.len(), 2, "demoted servers must still enter the pool");
        service.apply_penalty_to_pool(&mut pool, &penalties.demoted, &plugin_server_mapping);
        assert_eq!(pool[0].1, 10);
        assert_eq!(pool[1].1, 3);
    }

    // ======================== rewrite_h3_url tests ========================

    /// Helper to create ClientCapabilities with h3 enabled (for rewrite tests)
    fn h3_caps() -> ClientCapabilities {
        ClientCapabilities {
            h3: true,
            ..Default::default()
        }
    }

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
            content_hash: None,
        }
    }

    #[test]
    fn test_rewrite_h3_url_https_to_http3_with_query_params() {
        let server = make_server_config(true, None); // ValidCert → no fragment
        let url = "https://cdn.example.com/path/to/file.zip?token=abc&expires=123".to_string();
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
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
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
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
        let result = rewrite_url(&url.clone(), &server, None, &h3_caps()).unwrap();
        assert_eq!(result, url, "Non-https URLs should not be rewritten");
    }

    #[test]
    fn test_rewrite_h3_url_cert_hash_empty_no_fragment() {
        // cert_hash = None → ValidCert → no fragment
        let server = make_server_config(true, None);
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
        assert_eq!(result, "http3://cdn.example.com/file.zip");
        assert!(!result.contains('#'), "No fragment when cert_hash is empty");
    }

    #[test]
    fn test_rewrite_h3_url_cert_hash_empty_string_no_fragment() {
        // cert_hash = Some("") → ValidCert → no fragment
        let server = make_server_config(true, Some(""));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
        assert_eq!(result, "http3://cdn.example.com/file.zip");
    }

    #[test]
    fn test_rewrite_h3_url_trust_with_observed_hash() {
        let server = make_server_config(true, Some("trust"));
        let observed = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let health = make_health_info(Some(observed));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_url(&url, &server, Some(&health), &h3_caps()).unwrap();
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
        let result = rewrite_url(&url, &server, Some(&health), &h3_caps()).unwrap();
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
        let result = rewrite_url(&url, &server, Some(&health), &h3_caps());
        assert!(
            result.is_err(),
            "Trust mode without observed hash should return error"
        );
    }

    #[test]
    fn test_rewrite_h3_url_trust_no_health_info_errors() {
        let server = make_server_config(true, Some("trust"));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_url(&url, &server, None, &h3_caps());
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
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
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
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
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
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
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
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
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
    fn test_rewrite_url_non_h3_server_passthrough() {
        // Non-h3_only server with type=direct: rewrite_url should passthrough
        let server = make_server_config(false, Some("trust"));
        let url = "https://cdn.example.com/file.zip".to_string();
        let result = rewrite_url(&url, &server, None, &ClientCapabilities::default()).unwrap();
        assert_eq!(
            result, "https://cdn.example.com/file.zip",
            "Non-h3 direct server should passthrough unchanged"
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
            if let Some(sc) = config.servers.get(id)
                && let Ok(si) = crate::modules::server::ServerImpl::new(sc)
            {
                config.server_impl.insert(id.to_string(), si);
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
                tier: 0,
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
            version_files: vec![],
            version_file_split_ttl: 300,
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
                tier: 0,
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
            version_files: vec![],
            version_file_split_ttl: 300,
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

    const TIER_TEST_PATH: &str = "/files/tier.bin";

    /// 分层选点用的配置：两个普通 direct 节点，节点可用性完全由健康缓存决定，
    /// 因此测试不必接触网络。
    fn create_tier_integration_config() -> crate::config::AppConfig {
        use crate::config::{DownloadPolicy, ResourceConfig, ServerConfig};

        let mut config = crate::tests::mocks::create_default_test_config();

        for id in ["tier_primary", "tier_secondary", "tier_backup"] {
            config.servers.insert(
                id.to_string(),
                ServerConfig {
                    id: id.to_string(),
                    r#type: "direct".to_string(),
                    url: format!("https://{id}.example.com"),
                    h3_only: false,
                    cert_hash: None,
                    ..Default::default()
                },
            );
            if let Some(server_config) = config.servers.get(id)
                && let Ok(server_impl) = crate::modules::server::ServerImpl::new(server_config)
            {
                config.server_impl.insert(id.to_string(), server_impl);
            }
        }

        let mut resource = ResourceConfig {
            latest: "1.0.0".to_string(),
            versions: HashMap::new(),
            tries: vec![],
            server: vec![],
            flow: vec![],
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
            version_files: vec![],
            version_file_split_ttl: 300,
        };
        let mut versions = HashMap::new();
        versions.insert("default".to_string(), TIER_TEST_PATH.to_string());
        resource.versions.insert("1.0.0".to_string(), versions);
        config.resources.insert("tier_app".to_string(), resource);

        config
    }

    async fn set_tier_server_alive(env: &TestEnvironment, server_id: &str, is_alive: bool) {
        let health = HealthInfo {
            is_alive,
            file_size: Some(1024),
            last_check: chrono::Utc::now().timestamp() as u64,
            observed_cert_hash: None,
            content_hash: None,
        };
        env.data_store
            .set_health_info(server_id, TIER_TEST_PATH, &health)
            .await
            .expect("seed health info");
    }

    fn tier_flow_target() -> FlowTarget {
        FlowTarget {
            resource_id: "tier_app".to_string(),
            version: "1.0.0".to_string(),
            file_size: Some(1024),
            sub_path: None,
            ranges: None,
        }
    }

    fn tier_flow_items() -> Vec<FlowItem> {
        vec![
            FlowItem {
                rules: vec![],
                mode: FlowMode::AND,
                r#use: vec![FlowUse::Server {
                    id: "tier_primary".to_string(),
                    weight: 5,
                }],
                tier: 0,
            },
            FlowItem {
                rules: vec![],
                mode: FlowMode::AND,
                r#use: vec![FlowUse::Server {
                    id: "tier_backup".to_string(),
                    weight: 100,
                }],
                tier: 1,
            },
        ]
    }

    /// 优先层可用时不降级，即使低优先层权重高出 20 倍——这正是权重做不到的那件事。
    #[tokio::test]
    async fn a_usable_top_tier_is_never_bypassed_by_a_heavier_lower_tier() {
        let env = TestEnvironment::with_config(create_tier_integration_config()).await;
        set_tier_server_alive(&env, "tier_primary", true).await;
        set_tier_server_alive(&env, "tier_backup", true).await;

        let service = env.services.flow_service.clone();
        let (_unused_target, context, options) = create_test_context();
        let target = tier_flow_target();
        let flow_items = tier_flow_items();

        for _ in 0..30 {
            let result = service
                .execute_flow(
                    &target,
                    &context,
                    &options,
                    &flow_items,
                    FlowPenalties::default(),
                    None,
                )
                .await
                .expect("top tier is healthy");
            assert_eq!(
                result.selected_server_id.as_deref(),
                Some("tier_primary"),
                "a usable top tier must not fall through"
            );
            assert_eq!(result.selected_tier, Some(0));
        }
    }

    /// 同层三项：第一项以 `continue` 结束本层，第二项（同层）应被跳过，第三项（下一层）照常执行。
    ///
    /// 判据落在选点结果上：`tier_primary` 不健康，若同层的 `tier_secondary` 也进了池，层 0 就
    /// 是可用的、绝不会降级。选中 `tier_backup` 才说明本层确实在 `continue` 处结束了。
    fn tier_items_with_control_command(command: FlowUse) -> Vec<FlowItem> {
        vec![
            FlowItem {
                rules: vec![],
                mode: FlowMode::AND,
                r#use: vec![
                    FlowUse::Server {
                        id: "tier_primary".to_string(),
                        weight: 5,
                    },
                    command,
                ],
                tier: 0,
            },
            FlowItem {
                rules: vec![],
                mode: FlowMode::AND,
                r#use: vec![FlowUse::Server {
                    id: "tier_secondary".to_string(),
                    weight: 5,
                }],
                tier: 0,
            },
            FlowItem {
                rules: vec![],
                mode: FlowMode::AND,
                r#use: vec![FlowUse::Server {
                    id: "tier_backup".to_string(),
                    weight: 100,
                }],
                tier: 1,
            },
        ]
    }

    #[tokio::test]
    async fn continue_ends_its_own_tier_and_leaves_the_others() {
        let env = TestEnvironment::with_config(create_tier_integration_config()).await;
        set_tier_server_alive(&env, "tier_primary", false).await;
        set_tier_server_alive(&env, "tier_secondary", true).await;
        set_tier_server_alive(&env, "tier_backup", true).await;

        let service = env.services.flow_service.clone();
        let (_unused_target, context, options) = create_test_context();

        let result = service
            .execute_flow(
                &tier_flow_target(),
                &context,
                &options,
                &tier_items_with_control_command(FlowUse::Continue),
                FlowPenalties::default(),
                None,
            )
            .await
            .expect("the lower tier is still built");

        assert_eq!(
            result.selected_server_id.as_deref(),
            Some("tier_backup"),
            "the rest of tier 0 must be skipped while tier 1 still runs"
        );
        assert_eq!(result.selected_tier, Some(1));
    }

    /// 同一组配置换成 `break`：下一层也不再构建，池子空到报 NO_RES_AVAILABLE。
    #[tokio::test]
    async fn break_ends_every_tier_not_just_its_own() {
        let env = TestEnvironment::with_config(create_tier_integration_config()).await;
        set_tier_server_alive(&env, "tier_primary", false).await;
        set_tier_server_alive(&env, "tier_secondary", true).await;
        set_tier_server_alive(&env, "tier_backup", true).await;

        let service = env.services.flow_service.clone();
        let (_unused_target, context, options) = create_test_context();

        let error = service
            .execute_flow(
                &tier_flow_target(),
                &context,
                &options,
                &tier_items_with_control_command(FlowUse::Break),
                FlowPenalties::default(),
                None,
            )
            .await
            .expect_err("break stops the pipeline before any other tier is built");

        assert!(
            format!("{error:?}").contains("NO_RES_AVAILABLE"),
            "expected NO_RES_AVAILABLE, got {error:?}"
        );
    }

    /// 优先层内节点全部不可用时降到下一层。
    #[tokio::test]
    async fn an_exhausted_tier_falls_through_to_the_next() {
        let env = TestEnvironment::with_config(create_tier_integration_config()).await;
        set_tier_server_alive(&env, "tier_primary", false).await;
        set_tier_server_alive(&env, "tier_backup", true).await;

        let service = env.services.flow_service.clone();
        let (_unused_target, context, options) = create_test_context();

        let result = service
            .execute_flow(
                &tier_flow_target(),
                &context,
                &options,
                &tier_flow_items(),
                FlowPenalties::default(),
                None,
            )
            .await
            .expect("tier 1 is healthy");

        assert_eq!(result.selected_server_id.as_deref(), Some("tier_backup"));
        assert_eq!(result.selected_tier, Some(1));
    }

    /// 所有层都无可用节点时报 NO_RES_AVAILABLE，而不是把节点名当 URL 返回。
    #[tokio::test]
    async fn all_tiers_exhausted_reports_no_resource() {
        let env = TestEnvironment::with_config(create_tier_integration_config()).await;
        set_tier_server_alive(&env, "tier_primary", false).await;
        set_tier_server_alive(&env, "tier_backup", false).await;

        let service = env.services.flow_service.clone();
        let (_unused_target, context, options) = create_test_context();

        let error = service
            .execute_flow(
                &tier_flow_target(),
                &context,
                &options,
                &tier_flow_items(),
                FlowPenalties::default(),
                None,
            )
            .await
            .expect_err("no tier has a healthy server");

        assert!(
            format!("{error:?}").contains("NO_RES_AVAILABLE"),
            "expected NO_RES_AVAILABLE, got {error:?}"
        );
    }

    /// 不写 tier 的配置全部落在同一层，两个分开书写的节点仍然按权重竞争。
    #[tokio::test]
    async fn items_without_tiers_compete_in_one_tier() {
        let env = TestEnvironment::with_config(create_tier_integration_config()).await;
        set_tier_server_alive(&env, "tier_primary", true).await;
        set_tier_server_alive(&env, "tier_backup", true).await;

        let service = env.services.flow_service.clone();
        let (_unused_target, context, options) = create_test_context();
        let target = tier_flow_target();

        // 等权而非沿用 tier_flow_items 的 5 对 100：那个悬殊权重下弱者每轮只有 4.8% 的机会，
        // 80 轮全部落空的概率约 2%，测试会偶发失败。同层竞争与权重配比是两件事，后者由
        // weights_within_a_tier_still_split_traffic 覆盖。
        let flow_items: Vec<FlowItem> = tier_flow_items()
            .into_iter()
            .map(|item| FlowItem {
                tier: 0,
                r#use: item
                    .r#use
                    .into_iter()
                    .map(|operation| match operation {
                        FlowUse::Server { id, .. } => FlowUse::Server { id, weight: 10 },
                        other => other,
                    })
                    .collect(),
                ..item
            })
            .collect();

        let mut seen = std::collections::HashSet::new();
        for _ in 0..80 {
            let result = service
                .execute_flow(
                    &target,
                    &context,
                    &options,
                    &flow_items,
                    FlowPenalties::default(),
                    None,
                )
                .await
                .expect("one tier with two healthy servers selects");
            assert_eq!(result.selected_tier, Some(0));
            if let Some(id) = result.selected_server_id {
                seen.insert(id);
            }
        }

        assert_eq!(
            seen.len(),
            2,
            "servers in separate items without tiers must compete together, saw {seen:?}"
        );
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
            capabilities: Default::default(), // Client does NOT support h3
            internal: false,
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
            tier: 0,
        }];
        let result = service
            .execute_flow(
                &target,
                &context,
                &options,
                &flow_items,
                FlowPenalties::default(),
                None,
            )
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
            content_hash: None,
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
            capabilities: Default::default(),
            internal: false,
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
            tier: 0,
        }];
        let result = service
            .execute_flow(
                &target,
                &context,
                &options,
                &flow_items,
                FlowPenalties::default(),
                None,
            )
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
        let result = rewrite_url("not a valid url", &server, None, &h3_caps());
        assert!(result.is_err(), "Invalid URL should return error");
    }

    #[test]
    fn test_rewrite_h3_url_empty_path() {
        let server = make_server_config(true, None);
        let url = "https://cdn.example.com".to_string();
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
        assert_eq!(
            result, "http3://cdn.example.com/",
            "URL with no path should still get a trailing slash from url crate normalization"
        );
    }

    #[test]
    fn test_rewrite_h3_url_with_auth_and_query() {
        let server = make_server_config(true, None);
        let url = "https://cdn.example.com/path?Signature=abc123&Expires=999".to_string();
        let result = rewrite_url(&url, &server, None, &h3_caps()).unwrap();
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
        let pinned_result = rewrite_url(&url.clone(), &pinned_server, None, &h3_caps()).unwrap();
        assert!(
            pinned_result.contains("#cert="),
            "PinnedHex should produce #cert= fragment"
        );

        // Trust: has cert fragment when health info has observed hash
        let trust_server = make_server_config(true, Some("trust"));
        let health = make_health_info(Some(hex));
        let trust_result = rewrite_url(&url, &trust_server, Some(&health), &h3_caps()).unwrap();
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
