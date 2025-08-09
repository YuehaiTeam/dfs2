use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum ApiResponse {
    Success(ResponseData),
    Error { message: String },
}

#[allow(dead_code)]
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum ResponseData {
    Metadata {
        resource_version: String,
        name: String,
        changelog: Option<String>,
        data: Value,
    },
    Challenge {
        challenge: String,
        data: String,
        sid: String,
    },
    LegacyChallengeResponse {
        challenge: String, // 直接存储 "hash/source" 格式
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
    Raw(String),
    Empty,
}

// Specific response types for better OpenAPI documentation

#[derive(Serialize, ToSchema)]
pub struct SessionCreatedResponse {
    pub tries: Vec<String>,
    pub sid: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub data: String,
    pub sid: String,
}

#[derive(Serialize, ToSchema)]
pub struct MetadataResponse {
    pub resource_version: String,
    pub name: String,
    pub changelog: Option<String>,
    pub data: Value,
}

#[derive(Serialize, ToSchema)]
pub struct CdnUrlResponse {
    pub url: String,
}

#[derive(Serialize, ToSchema)]
pub struct DownloadUrlResponse {
    pub url: String,
}

#[derive(Serialize, ToSchema)]
pub struct CachedContentResponse {
    pub cached: bool,
    pub content: String, // base64 encoded
    pub content_type: Option<String>,
    pub etag: String,
    pub max_age: u32,
    pub size: u64,
}

#[derive(Serialize, ToSchema)]
pub struct EmptyResponse {
    pub success: bool,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    pub message: String,
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

// Additional request types


impl ApiResponse {
    pub fn success(data: ResponseData) -> Self {
        Self::Success(data)
    }

    pub fn error(message: String) -> Self {
        Self::Error { message }
    }
}
