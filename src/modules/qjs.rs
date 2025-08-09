use rquickjs::{AsyncContext, AsyncRuntime, Context, FromJs, Promise, Runtime, Value, async_with};
use tracing::{error, warn};

use llrt_modules::module_builder::ModuleBuilder;

use crate::{config::SharedConfig, modules::storage::data_store::DataStore};
thread_local! {
    static JS_CONTEXT: Context = {
        let runtime = Runtime::new()
            .map_err(|e| {
                error!("Failed to create JS runtime: {}", e);
                std::process::exit(1);
            })
            .unwrap();
        Context::full(&runtime)
            .map_err(|e| {
                error!("Failed to create JS context: {}", e);
                std::process::exit(1);
            })
            .unwrap()
    };
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct JsRunner {
    config: SharedConfig,
    redis: DataStore,
    context: AsyncContext,
}

#[rquickjs::function]
pub async fn js_s3sign(
    url: String,
    path: String,
    headers: Option<std::collections::BTreeMap<String, String>>,
) -> String {
    let signer: Result<super::server::s3::S3Signer, anyhow::Error> =
        super::server::s3::S3Signer::from_url(&url);
    let signer = match signer {
        Ok(signer) => signer,
        Err(e) => {
            warn!("S3 signer creation failed: {}", e);
            return String::new();
        }
    };
    let ret = signer.generate_presigned_url(&path, headers);
    match ret {
        Ok(url) => url,
        Err(e) => {
            warn!("S3 presigned URL generation failed: {}", e);
            String::new()
        }
    }
}

#[rquickjs::function]
pub async fn js_dfsnodesign(
    url: String,
    path: String,
    uuid: String,
    ranges: Option<Vec<Vec<u32>>>,
) -> String {
    let signer: Result<super::server::dfs_node::DfsNodeSigner, anyhow::Error> =
        super::server::dfs_node::DfsNodeSigner::from_url(&url);
    let signer = match signer {
        Ok(signer) => signer,
        Err(e) => {
            warn!("DFS node signer creation failed: {}", e);
            return String::new();
        }
    };

    // Convert Vec<Vec<u32>> to Vec<(u32, u32)>
    let converted_ranges = ranges.map(|r| {
        r.into_iter()
            .filter(|range| range.len() >= 2)
            .map(|range| (range[0], range[1]))
            .collect::<Vec<(u32, u32)>>()
    });

    let ret = signer.generate_presigned_url(&path, &uuid, converted_ranges);
    match ret {
        Ok(url) => url,
        Err(e) => {
            warn!("DFS node presigned URL generation failed: {}", e);
            String::new()
        }
    }
}

impl JsRunner {
    pub async fn new(config: SharedConfig, redis: DataStore) -> Self {
        let runtime = AsyncRuntime::new()
            .map_err(|e| {
                error!("Failed to create async JS runtime: {}", e);
                std::process::exit(1);
            })
            .unwrap();
        let context = AsyncContext::full(&runtime)
            .await
            .map_err(|e| {
                error!("Failed to create async JS context: {}", e);
                std::process::exit(1);
            })
            .unwrap();
        let module_builder = ModuleBuilder::default();
        let (module_resolver, module_loader, global_attachment) = module_builder.build();
        context
            .runtime()
            .set_loader((module_resolver,), (module_loader,))
            .await;
        let redis1 = redis.clone();
        async_with!(context => |ctx| {
            let redis2 = redis1.clone();
            let redis_read = rquickjs::Function::new(
                ctx.clone(),
                rquickjs::prelude::Async(move |_ctx: rquickjs::Ctx, key: String| {
                    let redis = redis2.clone();
                    async move { redis.read_js_storage(key).await }
                }),
            );
            let redis3 = redis1.clone();
            let redis_write = rquickjs::Function::new(
                ctx.clone(),
                rquickjs::prelude::Async(move |_ctx: rquickjs::Ctx, key: String, value: String, expires: u32| {
                    let redis = redis3.clone();
                    async move { redis.write_js_storage(key, value, expires).await }
                }),
            );
            let s3sign_func = rquickjs::Function::new(
                ctx.clone(),
                rquickjs::prelude::Async(js_s3sign),
            );
            let dfsnodesign_func = rquickjs::Function::new(
                ctx.clone(),
                rquickjs::prelude::Async(js_dfsnodesign),
            );
            global_attachment.attach(&ctx)?;
            let globals = ctx.globals();
            globals.set("_dfs_s3sign", s3sign_func)?;
            globals.set("_dfs_dfsnodesign", dfsnodesign_func)?;
            globals.set("_dfs_storage_read", redis_read)?;
            globals.set("_dfs_storage_write", redis_write)?;
            Ok::<_, rquickjs::Error>(())
        })
        .await
        .map_err(|e| {
            error!("Failed to initialize JavaScript context: {}", e);
            std::process::exit(1);
        })
        .unwrap();
        Self {
            config,
            context,
            redis,
        }
    }
    pub fn get_shared_config(&self) -> SharedConfig {
        self.config.clone()
    }

    pub async fn execute_async(&self, code: &str) -> anyhow::Result<serde_json::Value> {
        self.eval(code.to_string()).await
    }

    pub async fn eval(&self, code: String) -> anyhow::Result<serde_json::Value> {
        let config = (**self.config.load()).clone(); // 双重解包：Arc<AppConfig> -> AppConfig
        let ret = async_with!(self.context => |ctx| {
            let globals = ctx.globals();
            globals.set("_dfs_config", config)?;
            let promise = ctx.eval::<Promise,String>(code);
            match promise {
                Ok(promise) => {
                    let fut: rquickjs::promise::PromiseFuture<'_, Value> =
                    promise.into_future();
                    let result = fut.await;
                    match result {
                        Ok(result) => {
                            return Ok(JsonValue::from_js(&ctx, result)?.into());
                        }
                        Err(_) => {
                            let catch = ctx.catch();
                            return Err(anyhow::anyhow!("Error: {:?}", catch));
                        }
                    }
                },
                Err(_) => {
                    let catch = ctx.catch();
                    return Err(anyhow::anyhow!("Error: {:?}", catch));
                }
            }
        })
        .await?;
        Ok(ret)
    }

    /// 运行挑战验证插件
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
            let result = self.eval(code).await?;
            Ok(result)
        } else {
            Err(anyhow::anyhow!("Challenge plugin {} not found", plugin_id))
        }
    }

    /// 获取挑战插件代码
    async fn get_challenge_plugin_code(
        &self,
        id: &str,
        context: &str, // "generate" or "verify"
        challenge_data: serde_json::Value,
        extras: serde_json::Value,
    ) -> Option<String> {
        let config = self.config.load();
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
                        tracing::error!("Failed to serialize context: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "\"\"".to_string()),
                serde_json::to_string(&challenge_data)
                    .map_err(|e| {
                        tracing::error!("Failed to serialize challenge data: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "{}".to_string()),
                serde_json::to_string(&plugin_options.unwrap_or(&serde_json::Value::Null))
                    .map_err(|e| {
                        tracing::error!("Failed to serialize plugin options: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "null".to_string()),
                serde_json::to_string(&extras)
                    .map_err(|e| {
                        tracing::error!("Failed to serialize extras: {}", e);
                        e
                    })
                    .unwrap_or_else(|_| "{}".to_string()),
            ));
        }
        tracing::warn!("Challenge plugin {} not found", id);
        None
    }
}

struct JsonValue(serde_json::Value);

impl<'js> rquickjs::FromJs<'js> for JsonValue {
    fn from_js(ctx: &rquickjs::Ctx<'js>, v: Value<'js>) -> rquickjs::Result<Self> {
        rquickjs::Result::Ok(JsonValue(match v.type_of() {
            rquickjs::Type::Uninitialized => serde_json::json!("undefined"),
            rquickjs::Type::Undefined => serde_json::json!("undefined"),
            rquickjs::Type::Null => serde_json::json!("null"),
            rquickjs::Type::Bool => serde_json::json!(v.as_bool().unwrap_or(false)),
            rquickjs::Type::Int => serde_json::json!(v.as_int().unwrap_or(0)),
            rquickjs::Type::Float => serde_json::json!(v.as_float().unwrap_or(0.0)),
            rquickjs::Type::String => {
                serde_json::json!(
                    v.as_string()
                        .unwrap_or(&rquickjs::String::from_str(ctx.clone(), "")?)
                        .to_string()
                        .unwrap_or(String::from(""))
                )
            }
            rquickjs::Type::Symbol => serde_json::json!("[symbol]"),
            rquickjs::Type::Array => {
                let empty = &rquickjs::Array::new(ctx.clone())?;
                let arr = v.as_array().unwrap_or(empty);
                let mut values = Vec::new();
                for item in arr.iter::<Value>() {
                    if let Ok(val) = item {
                        values.push(val);
                    }
                }
                let mut result = Vec::new();
                for value in values.iter() {
                    if let Ok(converted) = JsonValue::from_js(ctx, value.clone()) {
                        result.push(converted.into());
                    }
                }
                serde_json::Value::Array(result)
            }
            rquickjs::Type::Function => serde_json::json!("[function]"),
            rquickjs::Type::Object => {
                let mut value = serde_json::Map::<String, serde_json::Value>::new();
                let inner = rquickjs::Object::new(ctx.clone())?;
                let object = v.as_object().unwrap_or(&inner);
                let mut keys = Vec::new();
                for key in object.keys::<String>() {
                    if let Ok(k) = key {
                        keys.push(k);
                    }
                }
                for key in keys {
                    if let Ok(val) = object.get::<String, Value>(key.clone()) {
                        if let Ok(converted) = JsonValue::from_js(ctx, val) {
                            value.insert(key, converted.into());
                        }
                    }
                }
                serde_json::Value::Object(value)
            }
            rquickjs::Type::Module => serde_json::json!("[module]"),
            rquickjs::Type::Promise => serde_json::json!("[promise]"),
            rquickjs::Type::Constructor => serde_json::json!("[constructor]"),
            rquickjs::Type::Exception => serde_json::json!("[Exception]"),
            rquickjs::Type::Unknown => serde_json::json!("[Unknown]"),
            rquickjs::Type::BigInt => serde_json::json!("[BigInt]"),
        }))
    }
}

impl From<JsonValue> for serde_json::Value {
    fn from(val: JsonValue) -> Self {
        val.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::storage::data_store::DataStore;
    use std::collections::HashMap;

    async fn create_test_js_runner() -> JsRunner {
        let app_config = crate::config::AppConfig {
            servers: HashMap::new(),
            resources: HashMap::new(),
            plugins: HashMap::new(),
            debug_mode: true,
            plugin_code: HashMap::new(),
            server_impl: HashMap::new(),
            challenge: crate::config::ChallengeConfig::default(),
        };

        let config = crate::config::SharedConfig::new(app_config);

        let redis_store = crate::modules::storage::data_store::FileDataStore::new()
            .await
            .expect("Failed to create test data store");
        let data_store = std::sync::Arc::new(redis_store) as DataStore;

        JsRunner::new(config, data_store).await
    }

    #[tokio::test]
    async fn test_javascript_basic_execution() {
        let js_runner = create_test_js_runner().await;

        // Test basic JavaScript execution
        let result = js_runner.eval("Promise.resolve(42)".to_string()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::json!(42));
    }

    #[tokio::test]
    async fn test_javascript_redis_integration() {
        let js_runner = create_test_js_runner().await;

        // Test Redis storage functions are available - if Redis is not available, functions should still exist
        let test_code = r#"
            (async function() {
                // Test that Redis functions exist
                const functions_exist = {
                    write_exists: typeof _dfs_storage_write === "function",
                    read_exists: typeof _dfs_storage_read === "function"
                };
                
                if (!functions_exist.write_exists || !functions_exist.read_exists) {
                    return { error: "Redis functions not available", functions_exist };
                }
                
                // Try writing to Redis (may fail if Redis is not running)
                const writeResult = await _dfs_storage_write("test_key_js", "test_value", 60);
                
                // If write failed, that's ok for testing - we just want to verify the functions are exposed
                if (!writeResult) {
                    return { 
                        success: true, 
                        redis_available: false,
                        functions_exist: true,
                        message: "Redis functions available but Redis server not connected"
                    };
                }
                
                // If write succeeded, test reading
                const readResult = await _dfs_storage_read("test_key_js");
                if (readResult !== "test_value") {
                    return { error: "Read failed", got: readResult };
                }
                
                return { 
                    success: true, 
                    redis_available: true,
                    functions_exist: true,
                    value: readResult 
                };
            })()
        "#;

        let result = js_runner.eval(test_code.to_string()).await;
        assert!(result.is_ok());

        let json_result = result.unwrap();
        if let Some(error) = json_result.get("error") {
            panic!("Redis integration test failed: {}", error);
        }

        // The test should succeed whether Redis is available or not
        assert_eq!(json_result["success"], true);
        assert_eq!(json_result["functions_exist"], true);
    }

    #[tokio::test]
    async fn test_plugin_function_signature() {
        let js_runner = create_test_js_runner().await;

        // Test plugin function signature with proper async/await
        let plugin_code = r#"
            async function test_plugin(pool, indirect, options, extras) {
                // Test that all parameters are accessible
                const result = {
                    pool_length: pool ? pool.length : 0,
                    indirect_type: typeof indirect,
                    options_type: typeof options,
                    extras_type: typeof extras,
                    redis_functions_available: {
                        read: typeof _dfs_storage_read,
                        write: typeof _dfs_storage_write
                    }
                };
                
                return [false, result];
            }
            
            test_plugin(
                [["http://example.com", 1], ["http://test.com", 2]], 
                "test_indirect", 
                {}, 
                {}
            )
        "#;

        let result = js_runner.eval(plugin_code.to_string()).await;
        assert!(result.is_ok());

        let json_result = result.unwrap();
        // The result should be an array with [false, result_object]
        assert!(json_result.is_array());
        let result_array = json_result.as_array().unwrap();
        assert_eq!(result_array.len(), 2);
        assert_eq!(result_array[0], serde_json::json!(false));

        let result_obj = &result_array[1];
        assert_eq!(result_obj["pool_length"], 2);
        assert_eq!(result_obj["indirect_type"], "string");
        assert_eq!(result_obj["redis_functions_available"]["read"], "function");
        assert_eq!(result_obj["redis_functions_available"]["write"], "function");
    }

    #[tokio::test]
    async fn test_s3_signing_function() {
        let js_runner = create_test_js_runner().await;

        // Test S3 signing function availability (should return empty string for invalid URL)
        let s3_test_code = r#"
            (async function() {
                const result = await _dfs_s3sign("invalid-url", "/test/path", {});
                return { 
                    function_exists: typeof _dfs_s3sign === "function",
                    result_type: typeof result,
                    result_value: result
                };
            })()
        "#;

        let result = js_runner.eval(s3_test_code.to_string()).await;
        assert!(result.is_ok());

        let json_result = result.unwrap();
        assert_eq!(json_result["function_exists"], true);
        assert_eq!(json_result["result_type"], "string");
    }

    #[tokio::test]
    async fn test_dfs_node_signing_function() {
        let js_runner = create_test_js_runner().await;

        // Test DFS node signing function availability
        let dfs_test_code = r#"
            (async function() {
                const result = await _dfs_dfsnodesign("invalid-url", "/test/path", "test-uuid", null);
                return { 
                    function_exists: typeof _dfs_dfsnodesign === "function",
                    result_type: typeof result,
                    result_value: result
                };
            })()
        "#;

        let result = js_runner.eval(dfs_test_code.to_string()).await;
        assert!(result.is_ok());

        let json_result = result.unwrap();
        assert_eq!(json_result["function_exists"], true);
        assert_eq!(json_result["result_type"], "string");
    }
}
