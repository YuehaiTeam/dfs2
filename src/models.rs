use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CdnRecord {
    pub url: String,
    pub server_id: Option<String>, // 服务器ID
    pub skip_penalty: bool,        // 是否跳过惩罚机制
    pub timestamp: u64,            // 调度时间戳
    pub weight: u32,               // 实际使用的权重
    pub size: Option<u64>,         // 实际下载的字节数
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Session {
    pub resource_id: String,
    pub version: String,
    pub chunks: Vec<String>,
    pub sub_path: Option<String>, // 新增：前缀资源的子路径
    pub cdn_records: HashMap<String, Vec<CdnRecord>>, // chunk_id -> Vec<CdnRecord>
    #[serde(default = "default_empty_json")]
    pub extras: serde_json::Value, // 额外的用户自定义数据
    pub created_at: u64,          // session创建时间戳
}

#[derive(Deserialize, ToSchema, Debug)]
pub struct CreateSessionRequest {
    #[serde(default)]
    pub chunks: Vec<String>,
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub challenge: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_empty_json")]
    pub extras: serde_json::Value,
}

fn default_version() -> String {
    "".to_string()
}

fn default_empty_json() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Challenge {
    pub challenge_type: String,
    pub data: String,
    pub sid: String,
}

#[derive(Clone, Deserialize, ToSchema)]
pub struct InsightItem {
    pub url: String,
    pub ttfb: u32,
    pub time: u32,
    pub size: u32,
    pub error: Option<String>,
    #[serde(default)]
    pub range: Vec<(u32, u32)>,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Clone, Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct InsightData {
    pub servers: Vec<InsightItem>,
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

// Flow上下文结构体 (从domain/flow_context.rs合并)
use std::net::IpAddr;

/// 目标资源信息 - "我要访问什么"
#[derive(Debug, Clone, Serialize)]
pub struct FlowTarget {
    pub resource_id: String,
    pub version: String,
    pub sub_path: Option<String>,        // 前缀资源的子路径
    pub file_size: Option<u64>,          // 由外部传入的文件大小
    pub ranges: Option<Vec<(u32, u32)>>, // 目标字节范围（由外部解析）
}

/// 请求上下文信息 - "在什么情况下访问"
#[derive(Debug, Clone, Serialize)]
pub struct FlowContext {
    pub client_ip: Option<IpAddr>,
    pub session_id: Option<String>,
    pub extras: serde_json::Value,
}

/// 执行选项 - "如何访问"
#[derive(Debug, Clone, Serialize)]
pub struct FlowOptions {
    pub cdn_full_range: bool,
}

/// Flow执行结果
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FlowResult {
    pub url: String, // 主要返回值：最终URL
    pub selected_server_id: Option<String>,
    pub selected_server_weight: Option<u32>,
    pub plugin_server_mapping: HashMap<String, (Option<String>, bool)>, // 插件元数据映射
}

/// 批量chunk请求结构
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BatchChunkRequest {
    /// 要获取CDN地址的chunk列表，格式如 ["0-1023", "1024-2047", "2048-4095"]
    pub chunks: Vec<String>,
}

/// 批量Redis操作结果结构
#[derive(Debug)]
pub struct BatchChunkData {
    /// 有效chunks及其下载计数
    pub valid_chunks: HashMap<String, u32>,
    /// 无效的chunk列表
    pub invalid_chunks: Vec<String>,
    /// 每个chunk的CDN记录（用于penalty服务器）
    pub cdn_records: HashMap<String, Vec<CdnRecord>>,
}

/// 单个chunk处理结果
#[derive(Debug)]
pub struct ChunkProcessResult {
    pub chunk_id: String,
    pub url: Option<String>,
    pub error: Option<String>,
    pub bandwidth_info: Option<BandwidthInfo>,
    pub cdn_record: Option<CdnRecord>,
}

/// 带宽信息结构
#[derive(Debug)]
pub struct BandwidthInfo {
    pub server_id: Option<String>,
    pub bytes: u64,
    pub chunk_id: String,
}

/// JavaScript插件上下文结构
#[derive(Debug, Clone, Serialize)]
pub struct FlowJsContext {
    pub target: FlowTarget,
    pub context: FlowContext,
    pub options: FlowOptions,
    pub session: Option<Session>,
}
