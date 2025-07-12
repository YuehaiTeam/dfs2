use std::sync::Arc;

use rquickjs::{AsyncContext, AsyncRuntime, Context, FromJs, Promise, Runtime, Value, async_with};
use tokio::sync::RwLock;

use crate::{app_state::RedisStore, config::AppConfig};
use llrt_modules::module_builder::ModuleBuilder;
thread_local! {
    static JS_CONTEXT: Context = Context::full(&Runtime::new().unwrap()).unwrap();
}

#[derive(Clone)]
pub struct JsRunner {
    config: Arc<RwLock<AppConfig>>,
    redis: RedisStore,
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
    if signer.is_err() {
        return "".to_string();
    }
    let signer = signer.unwrap();
    let ret = signer.generate_presigned_url(&path, headers);
    if ret.is_err() {
        return "".to_string();
    }
    ret.unwrap()
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
    if signer.is_err() {
        return "".to_string();
    }
    let signer = signer.unwrap();
    
    // Convert Vec<Vec<u32>> to Vec<(u32, u32)>
    let converted_ranges = ranges.map(|r| {
        r.into_iter()
            .filter(|range| range.len() >= 2)
            .map(|range| (range[0], range[1]))
            .collect::<Vec<(u32, u32)>>()
    });
    
    let ret = signer.generate_presigned_url(&path, &uuid, converted_ranges);
    if ret.is_err() {
        return "".to_string();
    }
    ret.unwrap()
}

impl JsRunner {
    pub async fn new(config: Arc<RwLock<AppConfig>>, redis: RedisStore) -> Self {
        let context = AsyncContext::full(&AsyncRuntime::new().unwrap())
            .await
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
        .expect("Failed to initialize JavaScript context");
        Self {
            config,
            context,
            redis,
        }
    }
    pub async fn eval(&self, code: String) -> anyhow::Result<serde_json::Value> {
        let config = self.config.read().await.clone();
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
