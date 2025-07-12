use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub path: String,
    pub chunks: Vec<String>,
    pub cdn_records: HashMap<String, Vec<String>>, // chunk_id -> Vec<cdn_url>
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct InsightData {
    pub bandwidth: HashMap<String, String>,
    pub ttfb: HashMap<String, String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct DeleteSessionRequest {
    pub insights: InsightData,
}
