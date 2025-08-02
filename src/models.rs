use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CdnRecord {
    pub url: String,
    pub server_id: Option<String>,  // 服务器ID
    pub skip_penalty: bool,         // 是否跳过惩罚机制
    pub timestamp: u64,             // 调度时间戳
    pub weight: u32,                // 实际使用的权重
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Session {
    pub path: String,
    pub chunks: Vec<String>,
    pub cdn_records: HashMap<String, Vec<CdnRecord>>, // chunk_id -> Vec<CdnRecord>
}

#[derive(Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    #[serde(default)]
    pub chunks: Vec<String>,
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub challenge: String,
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_version() -> String {
    "latest".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Challenge {
    pub challenge_type: String,
    pub data: String,
    pub sid: String,
}

#[derive(Clone, Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct InsightData {
    pub bandwidth: HashMap<String, String>,
    pub ttfb: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub server_id: Option<String>,
    pub skip_penalty: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct DeleteSessionRequest {
    #[serde(default)]
    pub insights: Option<InsightData>,
}
