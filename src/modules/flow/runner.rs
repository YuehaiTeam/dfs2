use rand::Rng;
use tokio::sync::RwLock;

use crate::{app_state::RedisStore, config::AppConfig};

use crate::modules::{flow::FlowItem, qjs::JsRunner};

use super::FlowUse;

pub struct RunFlowParams {
    pub path: String,
    pub ranges: Option<Vec<(u32, u32)>>,
    pub extras: serde_json::Value,
    pub session_id: Option<String>,
}

#[derive(Clone)]
pub struct FlowRunner {
    pub config: std::sync::Arc<RwLock<AppConfig>>,
    pub redis: RedisStore,
    pub jsrunner: JsRunner,
}

impl FlowRunner {
    pub async fn poolize(
        &self,
        pool: &mut Vec<(String, u32)>,
        path: &str,
        ranges: Option<Vec<(u32, u32)>>,
        session_id: Option<&str>,
    ) {
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
                pool.retain(|x| x.0 == selected_index);
                return;
            } else if selected_index.is_empty() {
                pool.clear();
                return;
            } else {
                // exec selected one, check if it is alive
                let is_alive = {
                    let config = self.config.read().await;
                    let server_impl = config.get_server(&selected_index);
                    if let Some(server_impl) = server_impl {
                        server_impl.is_alive(path).await
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
                            server_impl.url(path, ranges.clone(), session_id)
                        } else {
                            Err(anyhow::anyhow!("Server not found"))
                        }
                    };
                    if url.is_err() {
                        println!("Error: {}", url.err().unwrap());
                        pool.retain(|x| x.0 != selected_index);
                        continue;
                    } else {
                        let orig_weight = pool
                            .iter()
                            .find(|x| x.0 == selected_index)
                            .unwrap_or(&(String::new(), 0))
                            .1;
                        pool.clear();
                        pool.push((url.unwrap(), orig_weight));
                    }
                    return;
                } else {
                    println!("Error: {} {} is not alive", selected_index, path);
                    // remove it
                    pool.retain(|x| x.0 != selected_index);
                    // rerun poolize
                    if !pool.is_empty() {
                        continue;
                    } else {
                        return;
                    }
                }
            }
        }
    }

    pub async fn run_flow_item(
        &self,
        pool: &mut Vec<(String, u32)>,
        item: &FlowItem,
        params: &RunFlowParams,
    ) -> anyhow::Result<bool> {
        let mut should_break = false;
        let mut should_exec = true;
        if !item.r#use.is_empty() {
            if !item.rules.is_empty() {
                should_exec = false;
                for _rule in item.rules.iter() {}
            }
            if should_exec {
                for exec in item.r#use.iter() {
                    match exec {
                        FlowUse::Clear => {
                            pool.clear();
                        }
                        FlowUse::Poolize => {
                            self.poolize(pool, &params.path, params.ranges.clone(), params.session_id.as_deref()).await;
                        }
                        FlowUse::Server { id, weight } => {
                            pool.push((id.clone(), *weight));
                        }
                        FlowUse::Plugin { id, indirect } => {
                            let code = self
                                .get_plugin_code(id, indirect, pool.clone(), params.extras.clone())
                                .await;
                            let run = self.jsrunner.eval(code.unwrap_or_default()).await?;
                            // cast serde_json::Value to (bool, Vec<(String, u32)>)
                            let res: (bool, Vec<(String, u32)>) = serde_json::from_value(run)?;
                            // replace pool with the new one
                            pool.clear();
                            pool.extend(res.1);
                            should_break = res.0;
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
        params: &RunFlowParams,
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
            self.poolize(&mut pool, &params.path, params.ranges.clone(), params.session_id.as_deref()).await;
        }
        if pool.is_empty() {
            return Err(anyhow::anyhow!("NO_RES_AVAILABLE"));
        }
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
                serde_json::to_string(&pool).unwrap(),
                serde_json::to_string(indirect).unwrap(),
                serde_json::to_string(&plugin_options.unwrap_or(&serde_json::Value::Null)).unwrap(),
                serde_json::to_string(&extras).unwrap(),
            ));
        }
        println!("Plugin {} not found", id);
        None
    }
}
