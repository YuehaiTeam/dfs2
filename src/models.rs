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
    #[serde(default)]
    pub kind: SessionKind,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    #[default]
    Chunk,
    Direct,
}

impl Session {
    pub const DIRECT_TTL_SECONDS: u64 = 300;

    pub fn make_direct(&mut self) {
        self.kind = SessionKind::Direct;
        self.expires_at = Some(chrono::Utc::now().timestamp() as u64 + Self::DIRECT_TTL_SECONDS);
    }

    pub fn is_direct_expired(&self, now: u64) -> bool {
        self.kind == SessionKind::Direct
            && self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
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
#[allow(dead_code)]
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

pub use crate::modules::network::capabilities::ClientCapabilities;

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
    /// Client transport capabilities (HTTP/3, WebRTC, WebTransport).
    /// Derived from UA markers + X-DFS-Override header.
    #[serde(default)]
    pub capabilities: ClientCapabilities,
    /// 本次取件由调度器自身发起，而非代表某个客户端。
    ///
    /// 需要单独一位而不能靠 `client_ip.is_none()` 推断：客户端 IP 也会因取不到而缺失，
    /// 两种情况下该往哪些节点调度并不相同。
    #[serde(default)]
    pub internal: bool,
}

impl FlowContext {
    /// 调度器自身发起的取件：没有客户端，能力取本进程 fetch 客户端的实际支持面。
    pub fn internal() -> Self {
        Self {
            client_ip: None,
            session_id: None,
            extras: serde_json::json!({}),
            capabilities: ClientCapabilities::internal_fetcher(),
            internal: true,
        }
    }
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
    /// 选中的节点来自哪一层。发生降级时它大于最优先层的序号。
    ///
    /// 插件在管道中途 `poolize` 选出的节点无法归属到层，此时为 `None`。
    pub selected_tier: Option<u32>,
    pub plugin_server_mapping: HashMap<String, (Option<String>, bool)>, // 插件元数据映射
}

/// 调度惩罚：重试才硬剔除，仅签过则降权摊开。
#[derive(Debug, Clone, Default)]
pub struct FlowPenalties {
    /// 该客户端已经拿过这些节点后又要新 URL，加池时跳过。
    pub banned: Vec<String>,
    /// 这个 sid 已经签过、尚未被换掉。仍进池，权重 / 2（下限 1）。
    pub demoted: Vec<String>,
}

/// 批量chunk请求结构
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BatchChunkRequest {
    /// 要获取CDN地址的chunk列表，格式如 ["0-1023", "1024-2047", "2048-4095"]
    pub chunks: Vec<String>,
}

/// 批量Redis操作结果结构
#[derive(Debug)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct ChunkProcessResult {
    pub chunk_id: String,
    pub url: Option<String>,
    pub error: Option<String>,
    pub bandwidth_info: Option<BandwidthInfo>,
    pub cdn_record: Option<CdnRecord>,
}

/// 带宽信息结构
#[derive(Debug)]
#[allow(dead_code)]
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
