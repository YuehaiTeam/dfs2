use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::modules::{flow::FlowItem, geolocation, qjs::JsRunner};
use crate::{app_state::DataStore, config::AppConfig};

use super::{FlowComp, FlowCond, FlowMode, FlowUse};

pub struct RunFlowParams {
    pub path: String,
    pub ranges: Option<Vec<(u32, u32)>>,
    pub extras: serde_json::Value,
    pub session_id: Option<String>,
    pub client_ip: Option<IpAddr>,
    pub file_size: Option<u64>,
    pub plugin_server_mapping: HashMap<String, (Option<String>, bool)>, // url -> (server_id, skip_penalty)
    pub resource_id: String,          // 新增：资源ID
    pub sub_path: Option<String>,     // 新增：子路径（仅前缀资源使用）
    pub selected_server_id: Option<String>, // 新增：记录被选择的服务器ID
    pub selected_server_weight: Option<u32>, // 新增：记录被选择的服务器权重
}

#[derive(Clone)]
pub struct FlowRunner {
    pub config: std::sync::Arc<RwLock<AppConfig>>,
    pub redis: DataStore,
    pub jsrunner: JsRunner,
}

impl FlowRunner {
    /// 应用重复调度惩罚 - 使用绝对最小值策略
    pub async fn apply_penalty_for_repeated_requests(
        &self,
        session_id: &str,
        ranges: &Option<Vec<(u32, u32)>>,
        pool: &mut Vec<(String, u32)>
    ) {
        let chunk_key = self.format_chunk_key(ranges);
        if let Ok(previous_records) = self.redis.get_cdn_records(session_id, &chunk_key).await {
            // 第一步：识别哪些服务器需要被惩罚
            let mut penalized_servers = Vec::new();
            let mut non_penalized_min_weight = u32::MAX;
            
            for (server_name, weight) in pool.iter() {
                let should_penalize = previous_records.iter().any(|record| {
                    record.server_id.as_ref() == Some(server_name) && !record.skip_penalty
                });
                
                if should_penalize {
                    penalized_servers.push(server_name.clone());
                } else {
                    // 记录未被惩罚服务器的最小权重
                    non_penalized_min_weight = non_penalized_min_weight.min(*weight);
                }
            }
            
            // 第二步：应用绝对最小值惩罚
            if !penalized_servers.is_empty() && non_penalized_min_weight != u32::MAX {
                for (server_name, weight) in pool.iter_mut() {
                    if penalized_servers.contains(server_name) {
                        let original_weight = *weight;
                        *weight = non_penalized_min_weight;
                        info!("Applied absolute minimum penalty to server {} for repeated request: {} -> {}", 
                              server_name, original_weight, *weight);
                    }
                }
            }
        }
    }
    
    /// 将ranges转换为chunk key字符串
    fn format_chunk_key(&self, ranges: &Option<Vec<(u32, u32)>>) -> String {
        match ranges {
            Some(ranges) if !ranges.is_empty() => {
                ranges.iter()
                    .map(|(start, end)| format!("{}-{}", start, end))
                    .collect::<Vec<_>>()
                    .join(",")
            }
            _ => "0-".to_string() // 默认的完整文件下载key
        }
    }

    /// 评估单个流条件
    async fn evaluate_condition(&self, condition: &FlowCond, params: &RunFlowParams) -> bool {
        match condition {
            FlowCond::CnIp(expected_is_cn) => {
                if let Some(client_ip) = params.client_ip {
                    let is_global = geolocation::is_global_ip(client_ip);
                    let is_cn = !is_global;
                    *expected_is_cn == is_cn
                } else {
                    // 没有客户端IP信息，默认为false（条件不满足）
                    false
                }
            }
            FlowCond::IpVersion(expected_version) => {
                if let Some(client_ip) = params.client_ip {
                    let actual_version = if geolocation::is_ipv6(client_ip) {
                        6
                    } else {
                        4
                    };
                    actual_version == *expected_version
                } else {
                    // 没有客户端IP信息，默认为false（条件不满足）
                    false
                }
            }
            FlowCond::Cidr(cidr) => {
                if let Some(client_ip) = params.client_ip {
                    cidr.contains(&client_ip)
                } else {
                    false
                }
            }
            FlowCond::Extras(key) => {
                // 检查extras中是否存在指定的key且值为true
                params
                    .extras
                    .get(key)
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            }
            FlowCond::Size(comp, expected_size) => {
                if let Some(file_size) = params.file_size {
                    let expected_bytes = expected_size.bytes() as u64;
                    match comp {
                        FlowComp::Eq => file_size == expected_bytes,
                        FlowComp::Ne => file_size != expected_bytes,
                        FlowComp::Gt => file_size > expected_bytes,
                        FlowComp::Ge => file_size >= expected_bytes,
                        FlowComp::Lt => file_size < expected_bytes,
                        FlowComp::Le => file_size <= expected_bytes,
                    }
                } else {
                    false
                }
            }
            FlowCond::BwDaily(comp, limit) => {
                // 带宽限制检查：需要从Redis获取今日使用量
                if let Some(session_id) = &params.session_id {
                    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    let cache_key = if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
                        if !prefix.is_empty() {
                            format!("{}:bw_daily:{}:{}", prefix, session_id, today)
                        } else {
                            format!("bw_daily:{}:{}", session_id, today)
                        }
                    } else {
                        format!("bw_daily:{}:{}", session_id, today)
                    };

                    if let Ok(Some(usage_str)) = self.redis.get_string(&cache_key).await {
                        if let Ok(current_usage) = usage_str.parse::<u64>() {
                            let limit_bytes = limit.bytes() as u64;
                            return match comp {
                                FlowComp::Eq => current_usage == limit_bytes,
                                FlowComp::Ne => current_usage != limit_bytes,
                                FlowComp::Gt => current_usage > limit_bytes,
                                FlowComp::Ge => current_usage >= limit_bytes,
                                FlowComp::Lt => current_usage < limit_bytes,
                                FlowComp::Le => current_usage <= limit_bytes,
                            };
                        }
                    }
                }
                // 如果没有使用量数据，假设使用量为0
                let limit_bytes = limit.bytes() as u64;
                match comp {
                    FlowComp::Eq => 0 == limit_bytes,
                    FlowComp::Ne => 0 != limit_bytes,
                    FlowComp::Gt => false, // 0不可能大于正数
                    FlowComp::Ge => limit_bytes == 0,
                    FlowComp::Lt => limit_bytes > 0,
                    FlowComp::Le => true, // 0总是小于等于任何数
                }
            }
            FlowCond::ServerBwDaily(comp, limit) => {
                // 服务器级别的带宽限制检查：需要从params中获取选中的server_id
                if let Some(server_id) = &params.selected_server_id {
                    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    let cache_key = if let Ok(prefix) = std::env::var("REDIS_PREFIX") {
                        if !prefix.is_empty() {
                            format!("{}:server_bw_daily:{}:{}", prefix, server_id, today)
                        } else {
                            format!("server_bw_daily:{}:{}", server_id, today)
                        }
                    } else {
                        format!("server_bw_daily:{}:{}", server_id, today)
                    };

                    if let Ok(Some(usage_str)) = self.redis.get_string(&cache_key).await {
                        if let Ok(current_usage) = usage_str.parse::<u64>() {
                            let limit_bytes = limit.bytes() as u64;
                            return match comp {
                                FlowComp::Eq => current_usage == limit_bytes,
                                FlowComp::Ne => current_usage != limit_bytes,
                                FlowComp::Gt => current_usage > limit_bytes,
                                FlowComp::Ge => current_usage >= limit_bytes,
                                FlowComp::Lt => current_usage < limit_bytes,
                                FlowComp::Le => current_usage <= limit_bytes,
                            };
                        }
                    }
                }
                // 如果没有选中的服务器ID或没有使用量数据，假设使用量为0
                let limit_bytes = limit.bytes() as u64;
                match comp {
                    FlowComp::Eq => 0 == limit_bytes,
                    FlowComp::Ne => 0 != limit_bytes,
                    FlowComp::Gt => false, // 0不可能大于正数
                    FlowComp::Ge => limit_bytes == 0,
                    FlowComp::Lt => limit_bytes > 0,
                    FlowComp::Le => true, // 0总是小于等于任何数
                }
            }
            FlowCond::Time(comp, expected_time) => {
                let current_time = chrono::Local::now().time();
                match comp {
                    FlowComp::Eq => current_time == *expected_time,
                    FlowComp::Ne => current_time != *expected_time,
                    FlowComp::Gt => current_time > *expected_time,
                    FlowComp::Ge => current_time >= *expected_time,
                    FlowComp::Lt => current_time < *expected_time,
                    FlowComp::Le => current_time <= *expected_time,
                }
            }
        }
    }

    /// 评估规则列表
    async fn evaluate_rules(
        &self,
        rules: &[FlowCond],
        mode: &FlowMode,
        params: &RunFlowParams,
    ) -> bool {
        if rules.is_empty() {
            return true; // 没有规则时默认通过
        }

        match mode {
            FlowMode::AND => {
                // AND模式：所有规则都必须满足
                for rule in rules {
                    if !self.evaluate_condition(rule, params).await {
                        return false;
                    }
                }
                true
            }
            FlowMode::OR => {
                // OR模式：任意规则满足即可
                for rule in rules {
                    if self.evaluate_condition(rule, params).await {
                        return true;
                    }
                }
                false
            }
        }
    }
    pub async fn poolize(
        &self,
        pool: &mut Vec<(String, u32)>,
        path: &str,
        ranges: Option<Vec<(u32, u32)>>,
        session_id: Option<&str>,
        plugin_mappings: &HashMap<String, (Option<String>, bool)>
    ) -> Option<(String, u32)> {
        // 1. 应用重复调度惩罚
        if let Some(session_id) = session_id {
            self.apply_penalty_for_repeated_requests(session_id, &ranges, pool).await;
        }
        
        // 2. 原有的服务器选择逻辑
        loop {
            let selected_index = {
                let total = pool.iter().map(|x: &(String, u32)| x.1).sum::<u32>();
                let mut rng = rand::rng();
                let mut weight = if total > 0 {
                    rng.random_range(0..total)
                } else {
                    0
                };
                let mut selected_index = String::new();
                for item in pool.iter() {
                    if weight <= item.1 {
                        selected_index = item.0.clone();
                        break;
                    }
                    weight -= item.1;
                }
                selected_index
            };
            // already execed, just use it
            if selected_index.starts_with("http:") || selected_index.starts_with("https:") {
                // URL case: 记录并返回
                pool.retain(|x| x.0 == selected_index);
                
                // 记录CDN调度结果
                if let Some(session_id) = session_id {
                    let (server_id, skip_penalty) = plugin_mappings
                        .get(&selected_index)
                        .unwrap_or(&(None, false));
                    
                    let record = crate::models::CdnRecord {
                        url: selected_index.clone(),
                        server_id: server_id.clone(),
                        skip_penalty: *skip_penalty,
                        timestamp: chrono::Utc::now().timestamp() as u64,
                        weight: pool.iter().find(|x| x.0 == selected_index).map(|x| x.1).unwrap_or(0),
                    };
                    
                    let chunk_key = self.format_chunk_key(&ranges);
                    let _ = self.redis.update_cdn_record_v2(session_id, &chunk_key, record).await;
                }
                
                // 返回选中的服务器ID和权重（从插件映射中获取）
                let selected_server_id = if let Some((server_id, _)) = plugin_mappings.get(&selected_index) {
                    server_id.clone()
                } else {
                    Some("plugin".to_string())
                };
                let weight = pool.iter().find(|x| x.0 == selected_index).map(|x| x.1).unwrap_or(0);
                
                return selected_server_id.map(|id| (id, weight));
            } else if selected_index.is_empty() {
                pool.clear();
                return None;
            } else {
                // exec selected one, check if it is alive
                let is_alive = {
                    let config = self.config.read().await;
                    let server_impl = config.get_server(&selected_index);
                    if let Some(server_impl) = server_impl {
                        server_impl
                            .is_alive(&selected_index, path, Some(&self.redis))
                            .await
                    } else {
                        false
                    }
                };
                if is_alive {
                    // get url
                    let url = {
                        let config = self.config.read().await;
                        let server_impl = config.get_server(&selected_index);
                        if let Some(server_impl) = server_impl {
                            server_impl.url(path, ranges.clone(), session_id, Some(&self.redis)).await
                        } else {
                            Err(anyhow::anyhow!("Server not found"))
                        }
                    };
                    if url.is_err() {
                        if let Err(e) = url {
                            error!("URL generation failed for server {}: {}", selected_index, e);
                        }
                        pool.retain(|x| x.0 != selected_index);
                        continue;
                    } else {
                        let orig_weight = pool
                            .iter()
                            .find(|x| x.0 == selected_index)
                            .unwrap_or(&(String::new(), 0))
                            .1;
                        pool.clear();
                        if let Ok(url_str) = url {
                            // 记录服务器选择结果
                            if let Some(session_id) = session_id {
                                let record = crate::models::CdnRecord {
                                    url: url_str.clone(),
                                    server_id: Some(selected_index.clone()),
                                    skip_penalty: false,
                                    timestamp: chrono::Utc::now().timestamp() as u64,
                                    weight: orig_weight,
                                };
                                
                                let chunk_key = self.format_chunk_key(&ranges);
                                let _ = self.redis.update_cdn_record_v2(session_id, &chunk_key, record).await;
                            }
                            
                            pool.push((url_str, orig_weight));
                            
                            // 返回选中的服务器ID和权重  
                            return Some((selected_index.clone(), orig_weight));
                        }
                    }
                    return None;
                } else {
                    warn!("Server {} is not alive for path {}", selected_index, path);
                    // remove it
                    pool.retain(|x| x.0 != selected_index);
                    // rerun poolize
                    if !pool.is_empty() {
                        continue;
                    } else {
                        return None;
                    }
                }
            }
        }
    }

    pub async fn run_flow_item(
        &self,
        pool: &mut Vec<(String, u32)>,
        item: &FlowItem,
        params: &mut RunFlowParams,
    ) -> anyhow::Result<bool> {
        let mut should_break = false;
        let mut should_exec = true;
        if !item.r#use.is_empty() {
            if !item.rules.is_empty() {
                // 评估所有规则，根据模式决定是否执行
                should_exec = self.evaluate_rules(&item.rules, &item.mode, params).await;
            }
            if should_exec {
                for exec in item.r#use.iter() {
                    match exec {
                        FlowUse::Clear => {
                            pool.clear();
                        }
                        FlowUse::Poolize => {
                            let selected_server_info = self.poolize(
                                pool,
                                &params.path,
                                params.ranges.clone(),
                                params.session_id.as_deref(),
                                &params.plugin_server_mapping
                            )
                            .await;
                            if let Some((server_id, weight)) = selected_server_info {
                                params.selected_server_id = Some(server_id);
                                params.selected_server_weight = Some(weight);
                            }
                        }
                        FlowUse::Server { id, weight } => {
                            pool.push((id.clone(), *weight));
                        }
                        FlowUse::Plugin { id, indirect } => {
                            let code = self
                                .get_plugin_code(id, indirect, pool.clone(), params.extras.clone())
                                .await;
                            let run = self.jsrunner.eval(code.unwrap_or_default()).await?;
                            
                            // 尝试解析增强格式：(bool, Vec<(String, u32, Option<PluginMetadata>)>)
                            if let Ok((should_break_enhanced, enhanced_pool)) = 
                                serde_json::from_value::<(bool, Vec<(String, u32, Option<crate::models::PluginMetadata>)>)>(run.clone()) {
                                
                                pool.clear();
                                for (url, weight, metadata) in enhanced_pool {
                                    pool.push((url.clone(), weight));
                                    
                                    if let Some(metadata) = metadata {
                                        // 存储插件元数据到params中
                                        params.plugin_server_mapping.insert(
                                            url,
                                            (metadata.server_id, metadata.skip_penalty.unwrap_or(false))
                                        );
                                    }
                                }
                                should_break = should_break_enhanced;
                            } else {
                                // 兼容旧格式：(bool, Vec<(String, u32)>)
                                let res: (bool, Vec<(String, u32)>) = serde_json::from_value(run)?;
                                pool.clear();
                                pool.extend(res.1);
                                should_break = res.0;
                            }
                        }
                    }
                }
            }
        }
        Ok(should_break)
    }

    pub async fn run_flow(
        &self,
        list: &Vec<FlowItem>,
        params: &mut RunFlowParams,
    ) -> anyhow::Result<String> {
        let mut pool = Vec::new();
        for item in list {
            let result = self.run_flow_item(&mut pool, item, params).await;
            match result {
                Ok(res) => {
                    if res {
                        break;
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        if pool.len() > 1
            || (pool.len() == 1
                && !pool[0].0.starts_with("http:")
                && !pool[0].0.starts_with("https:"))
        {
            let selected_server_info = self.poolize(
                &mut pool,
                &params.path,
                params.ranges.clone(),
                params.session_id.as_deref(),
                &params.plugin_server_mapping
            )
            .await;
            if let Some((server_id, weight)) = selected_server_info {
                params.selected_server_id = Some(server_id);
                params.selected_server_weight = Some(weight);
            }
        }
        if pool.is_empty() {
            return Err(anyhow::anyhow!("NO_RES_AVAILABLE"));
        }
        
        // 输出最终的调度结果到 stdout
        let chunk_info = if let Some(ref ranges) = params.ranges {
            if ranges.len() == 1 {
                format!("{}:{}-{}", params.resource_id, ranges[0].0, ranges[0].1)
            } else {
                format!("{}:{}chunks", params.resource_id, ranges.len())
            }
        } else {
            format!("{}:full", params.resource_id)
        };
        
        let client_ip = params.client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        // 使用选中的服务器ID
        let server_name = params.selected_server_id
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        
        info!("CDN_DISPATCH {} {} -> {} weight:{}", 
              chunk_info, client_ip, server_name, pool[0].1);
        
        Ok(pool[0].0.clone())
    }

    pub async fn get_plugin_code(
        &self,
        id: &str,
        indirect: &str,
        pool: Vec<(String, u32)>,
        extras: serde_json::Value,
    ) -> Option<String> {
        let config = self.config.read().await;
        let plugin_options = config.plugins.get(id);
        if let Some(code) = config.plugin_code.get(id) {
            return Some(format!(
                r#"
            (async (pool, indirect, options, extras, exports) => {{
                /* USER CODE START */
                {}
                /* USER CODE END */
                let ret = await exports?.(pool, indirect, options, extras) || false;
                return [ret, pool];
            }})({}, {}, {}, {})"#,
                code,
                serde_json::to_string(&pool)
                    .map_err(|e| {
                        error!("Failed to serialize pool: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "[]".to_string()),
                serde_json::to_string(indirect)
                    .map_err(|e| {
                        error!("Failed to serialize indirect: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "false".to_string()),
                serde_json::to_string(&plugin_options.unwrap_or(&serde_json::Value::Null))
                    .map_err(|e| {
                        error!("Failed to serialize plugin options: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "null".to_string()),
                serde_json::to_string(&extras)
                    .map_err(|e| {
                        error!("Failed to serialize extras: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "{}".to_string()),
            ));
        }
        warn!("Plugin {} not found", id);
        None
    }

    pub async fn get_challenge_plugin_code(
        &self,
        id: &str,
        context: &str, // "generate" or "verify"
        challenge_data: serde_json::Value,
        extras: serde_json::Value,
    ) -> Option<String> {
        let config = self.config.read().await;
        let plugin_options = config.plugins.get(id);
        if let Some(code) = config.plugin_code.get(id) {
            return Some(format!(
                r#"
            (async (context, challengeData, options, extras, exports) => {{
                /* USER CODE START */
                {}
                /* USER CODE END */
                let ret = await exports?.(context, challengeData, options, extras);
                return ret;
            }})({}, {}, {}, {})"#,
                code,
                serde_json::to_string(context)
                    .map_err(|e| {
                        error!("Failed to serialize context: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "\"\"".to_string()),
                serde_json::to_string(&challenge_data)
                    .map_err(|e| {
                        error!("Failed to serialize challenge data: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "null".to_string()),
                serde_json::to_string(&plugin_options.unwrap_or(&serde_json::Value::Null))
                    .map_err(|e| {
                        error!("Failed to serialize plugin options: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "null".to_string()),
                serde_json::to_string(&extras)
                    .map_err(|e| {
                        error!("Failed to serialize extras: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "{}".to_string()),
            ));
        }
        warn!("Challenge plugin {} not found", id);
        None
    }

    pub async fn run_challenge_plugin(
        &self,
        plugin_id: &str,
        context: &str,
        challenge_data: serde_json::Value,
        extras: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        if let Some(code) = self
            .get_challenge_plugin_code(plugin_id, context, challenge_data, extras)
            .await
        {
            let result = self.jsrunner.eval(code).await?;
            Ok(result)
        } else {
            Err(anyhow::anyhow!("Challenge plugin {} not found", plugin_id))
        }
    }
}
