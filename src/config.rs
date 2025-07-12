use rquickjs::IntoJs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::modules::{flow::FlowItem, server::ServerImpl};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub id: String,
    pub url: String,
    pub r#type: String,
}
impl<'js> IntoJs<'js> for ServerConfig {
    fn into_js(self, ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Value<'js>> {
        let obj = rquickjs::Object::new(ctx.clone()).unwrap();
        obj.set("id", self.id).unwrap();
        obj.set("url", self.url).unwrap();
        obj.set("type", self.r#type).unwrap();
        Ok(obj.into())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersionPaths {
    #[serde(flatten)]
    pub paths: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceConfig {
    #[serde(default)]
    pub latest: String,
    pub versions: HashMap<String, HashMap<String, String>>,
    pub tries: Vec<String>,
    pub server: Vec<String>,
    pub flow: Vec<FlowItem>,
}
impl<'js> IntoJs<'js> for ResourceConfig {
    fn into_js(self, ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Value<'js>> {
        let obj = rquickjs::Object::new(ctx.clone()).unwrap();
        obj.set("latest", self.latest).unwrap();
        obj.set("tries", self.tries).unwrap();
        obj.set("server", self.server).unwrap();
        let versions = rquickjs::Object::new(ctx.clone()).unwrap();
        for (key, value) in self.versions {
            versions.set(key, value).unwrap();
        }
        obj.set("versions", versions).unwrap();
        Ok(obj.into())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub servers: HashMap<String, ServerConfig>,
    pub resources: HashMap<String, ResourceConfig>,
    pub plugins: HashMap<String, serde_json::Value>,
    #[serde(default, skip)]
    pub plugin_code: HashMap<String, String>,
    #[serde(default, skip)]
    pub server_impl: HashMap<String, ServerImpl>,
}

impl<'js> IntoJs<'js> for AppConfig {
    fn into_js(self, ctx: &rquickjs::Ctx<'js>) -> rquickjs::Result<rquickjs::Value<'js>> {
        let obj = rquickjs::Object::new(ctx.clone()).unwrap();
        let servers = rquickjs::Object::new(ctx.clone()).unwrap();
        for (key, value) in self.servers {
            servers.set(key, value).unwrap();
        }
        obj.set("servers", servers).unwrap();

        let resources = rquickjs::Object::new(ctx.clone()).unwrap();
        for (key, value) in self.resources {
            resources.set(key, value).unwrap();
        }
        obj.set("resources", resources).unwrap();

        Ok(obj.into())
    }
}

impl AppConfig {
    pub async fn load() -> anyhow::Result<Self> {
        let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string());
        let plugin_path = std::env::var("PLUGIN_PATH").unwrap_or_else(|_| "plugins/".to_string());
        let content = tokio::fs::read_to_string(path).await?;
        let mut config: AppConfig = serde_yaml::from_str(&content)?;
        // loop through the plugin directory and load all .js files
        let mut plugin_code = HashMap::new();
        let mut paths = tokio::fs::read_dir(plugin_path).await?;
        loop {
            let entry = paths.next_entry().await?;
            if entry.is_none() {
                break;
            }
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "js") {
                let file_name = path.file_stem().unwrap().to_str().unwrap();
                let content = tokio::fs::read_to_string(path.clone()).await?;
                plugin_code.insert(file_name.to_string(), content);
            }
        }
        config.plugin_code = plugin_code;
        // create server implementations
        let mut server_impl = HashMap::new();
        for (id, server) in config.servers.iter() {
            let server = ServerImpl::new(server)?;
            server_impl.insert(id.clone(), server);
        }
        config.server_impl = server_impl;
        Ok(config)
    }

    pub fn get_server(&self, id: &str) -> Option<&ServerImpl> {
        self.server_impl.get(id)
    }

    pub fn get_resource(&self, id: &str) -> Option<&ResourceConfig> {
        self.resources.get(id)
    }

    pub fn get_version_path(
        &self,
        resid: &str,
        version: &str,
        server_id: Option<&str>,
    ) -> Option<String> {
        let resource = self.get_resource(resid)?;

        let version_map = resource.versions.get(version)?;

        // 如果指定了特定服务器，尝试获取该服务器的路径
        if let Some(server_id) = server_id {
            if let Some(path) = version_map.get(server_id) {
                return Some(path.clone());
            }
        }

        // 否则返回默认路径
        version_map.get("default").cloned()
    }
}
