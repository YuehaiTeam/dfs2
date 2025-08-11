use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;

pub mod profiles;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusJob {
    pub job_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    pub static_configs: Vec<StaticConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relabel_configs: Option<Vec<RelabelConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticConfig {
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelabelConfig {
    pub target_label: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global: Option<GlobalConfig>,
    pub scrape_configs: Vec<PrometheusJob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub scrape_interval: String,
}

pub fn generate_prometheus_config(
    config: &AppConfig,
    profile_filter: Option<&str>,
    scrape_interval: &str,
) -> Result<String> {
    let mut jobs = Vec::new();

    for (server_id, server_config) in &config.servers {
        // 如果指定了profile过滤器，则只处理匹配的服务器
        if let Some(filter) = profile_filter {
            match &server_config.profile {
                Some(profile) if profile == filter => {}
                _ => continue,
            }
        }

        // 根据profile生成相应的配置
        if let Some(ref profile) = server_config.profile {
            match profile.as_str() {
                "minio" => {
                    if let Ok(job) = profiles::minio::generate_minio_job(server_id, server_config) {
                        jobs.push(job);
                    }
                }
                _ => {
                    tracing::warn!("Unsupported profile: {} for server: {}", profile, server_id);
                }
            }
        }
    }

    let prometheus_config = PrometheusConfig {
        global: Some(GlobalConfig {
            scrape_interval: scrape_interval.to_string(),
        }),
        scrape_configs: jobs,
    };

    // 序列化为YAML
    serde_yaml::to_string(&prometheus_config)
        .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))
}
