use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country: String,
    pub city: Option<String>,
    pub is_china_ip: bool,
    pub ip_version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatsLog {
    pub created_at: String, // ISO 8601 format
    pub completed_at: Option<String>,
    pub timeout_at: Option<String>,
    pub duration_ms: u64,
    pub total_chunks: u32,
    pub successful_downloads: u32,
    pub failed_downloads: u32,
    pub success_rate: f64,
    pub completion_reason: String, // "client_terminated", "timeout", "direct_download"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnRecordLog {
    pub url: String,
    pub server_id: String,
    pub server_weight: u32,
    pub timestamp: String, // ISO 8601 format
    pub skip_penalty: bool,
    pub selection_reason: String, // "highest_weight", "retry_fallback", "flow_selected"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkLog {
    pub range: String,
    pub download_attempts: u32,
    pub cdn_records: Vec<CdnRecordLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInsightsLog {
    pub bandwidth_stats: Option<HashMap<String, String>>,
    pub ttfb_stats: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLog {
    pub timestamp: String, // ISO 8601 format
    pub log_type: String, // "session_completed", "session_timeout", "direct_download"
    pub session_id: Option<String>,
    pub resource_id: String,
    pub version: String,
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub geo_info: GeoInfo,
    pub download_policy: String, // "enabled", "free", "disabled"
    pub session_stats: SessionStatsLog,
    pub chunks: Vec<ChunkLog>,
    pub server_usage_summary: HashMap<String, u32>,
    pub client_insights: Option<ClientInsightsLog>,
}

impl GeoInfo {
    pub fn from_ip(ip: IpAddr) -> Self {
        // 使用IPIP数据库进行地理位置信息解析
        let is_global_ip = crate::modules::geolocation::is_global_ip(ip);
        let is_china_ip = !is_global_ip; // 非全球IP视为中国IP
        let ip_version = match ip {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        };

        GeoInfo {
            country: if is_china_ip { "CN".to_string() } else { "Unknown".to_string() },
            city: None, // 暂时不实现城市解析
            is_china_ip,
            ip_version,
        }
    }
}

impl SessionStatsLog {
    pub fn calculate_success_rate(successful: u32, total: u32) -> f64 {
        if total == 0 {
            0.0
        } else {
            successful as f64 / total as f64
        }
    }
}

impl Default for ClientInsightsLog {
    fn default() -> Self {
        Self {
            bandwidth_stats: None,
            ttfb_stats: None,
        }
    }
}