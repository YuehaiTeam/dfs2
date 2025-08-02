use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum ApiResponse {
    Success(ResponseData),
    Error { 
        message: String 
    },
}

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum ResponseData {
    Metadata {
        #[serde(rename = "_dfs_version")]
        dfs_version: String,
        name: String,
        data: Value,
    },
    Challenge {
        challenge: String,
        data: String,
        sid: String,
    },
    Session {
        tries: Vec<String>,
        sid: String,
    },
    Cdn {
        url: String,
    },
    Download {
        url: String,
    },
    Json(Value),
    Raw(Value),
    Empty,
}

// Additional response types for OpenAPI documentation

#[derive(Serialize, ToSchema)]
pub struct SessionResponse {
    pub tries: Vec<String>,
    pub sid: String,
}

#[derive(Serialize, ToSchema)]  
pub struct CdnResponse {
    pub url: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct StatusResponse {
    pub status: String,
    pub version: String,
    pub plugins: u32,
    pub servers: u32,
}

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub services: ServiceHealth,
    pub metrics: HealthMetrics,
}

#[derive(Serialize, ToSchema)]
pub struct ServiceHealth {
    pub redis: ConnectionStatus,
    pub servers: ServerHealth,
    pub plugins: PluginStatus,
}

#[derive(Serialize, ToSchema)]
pub struct ConnectionStatus {
    pub status: String,
    pub latency_ms: u64,
}

#[derive(Serialize, ToSchema)]
pub struct ServerHealth {
    pub healthy: u32,
    pub total: u32,
}

#[derive(Serialize, ToSchema)]
pub struct PluginStatus {
    pub loaded: u32,
    pub errors: u32,
}

#[derive(Serialize, ToSchema)]
pub struct HealthMetrics {
    pub active_sessions: u64,
    pub requests_per_second: f64,
    pub error_rate: f64,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    pub message: String,
}

// Additional request types

use serde::Deserialize;

#[derive(Deserialize, ToSchema)]
pub struct GetCdnRequest {
    pub chunk: String,
}

#[derive(Deserialize, ToSchema)]
pub struct VerifyRequest {
    pub response: String,
}

impl ApiResponse {
    pub fn success(data: ResponseData) -> Self {
        Self::Success(data)
    }

    pub fn error(message: String) -> Self {
        Self::Error { message }
    }
}
