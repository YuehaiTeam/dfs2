use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnRecordLog {
    pub url: String,
    pub srv: Option<String>,  // server_id
    pub wgt: Option<u32>,     // server_weight
    pub ts: u64,              // timestamp (Unix时间戳)
    pub pen: Option<bool>,    // skip_penalty
    pub rsn: Option<String>,  // selection_reason
    pub ttfb: Option<u32>,    // client_ttfb
    pub time: Option<u32>,    // client_time
    pub size: Option<u32>,    // client_size
    pub err: Option<String>,  // client_error
    pub mode: Option<String>, // client_mode
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkLog {
    pub rng: String,             // range
    pub att: u32,                // download_attempts
    pub cdns: Vec<CdnRecordLog>, // cdn_records
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLog {
    pub start: u64, // session创建时间
    pub end: u64,   // session结束时间
    #[serde(rename = "type")]
    pub log_type: String, // 日志类型
    pub sid: Option<String>, // session ID
    pub rid: String, // resource ID
    pub ver: String, // 版本
    pub ua: Option<String>, // user agent
    pub ip: (String, Option<String>), // (IP地址, 地理信息) tuple
    pub chunks: Vec<ChunkLog>,
}
