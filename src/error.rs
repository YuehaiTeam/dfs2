use crate::responses::ApiResponse;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

/// DFS2 统一错误类型系统
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum DfsError {
    /// 资源未找到错误
    #[error("Resource not found: {resource_id}")]
    ResourceNotFound { resource_id: String },

    /// 版本未找到错误
    #[error("Version '{version}' not found for resource '{resource_id}'")]
    VersionNotFound {
        resource_id: String,
        version: String,
    },

    /// 服务器不可用错误
    #[error("Server unavailable: {server_id}")]
    ServerUnavailable { server_id: String },

    /// 服务器未找到错误
    #[error("Server configuration not found: {server_id}")]
    ServerNotFound { server_id: String },

    /// 路径未找到错误
    #[error("Path not found for resource '{resource_id}' version '{version}'")]
    PathNotFound {
        resource_id: String,
        version: String,
    },

    /// 会话未找到错误
    #[error("Session not found: {session_id}")]
    SessionNotFound { session_id: String },

    /// 会话创建失败错误
    #[error("Failed to create session: {reason}")]
    SessionCreationFailed { reason: String },

    /// 挑战验证失败错误
    #[error("Challenge verification failed: {reason}")]
    ChallengeVerificationFailed { reason: String },

    /// 挑战未找到错误
    #[error("Challenge not found for session: {session_id}")]
    ChallengeNotFound { session_id: String },

    /// 插件执行错误
    #[error("Plugin execution failed: {plugin_id} - {reason}")]
    PluginExecutionFailed { plugin_id: String, reason: String },

    /// 插件未找到错误
    #[error("Plugin not found: {plugin_id}")]
    PluginNotFound { plugin_id: String },

    /// 配置加载错误
    #[error("Configuration loading failed: {reason}")]
    ConfigLoadFailed { reason: String },

    /// 配置验证错误
    #[error("Configuration validation failed: {field} - {reason}")]
    ConfigValidationFailed { field: String, reason: String },

    /// Redis 连接错误
    #[error("Redis operation failed: {operation} - {reason}")]
    RedisError { operation: String, reason: String },

    /// 序列化/反序列化错误
    #[error("Serialization error: {reason}")]
    SerializationError { reason: String },

    /// 网络请求错误
    #[error("Network request failed: {reason}")]
    NetworkError { reason: String },

    /// IO 错误
    #[error("IO operation failed: {operation} - {reason}")]
    IoError { operation: String, reason: String },

    /// 内部服务器错误
    #[error("Internal server error: {reason}")]
    InternalError { reason: String },

    /// 认证失败错误
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    /// 权限错误
    #[error("Permission denied: {resource}")]
    PermissionDenied { resource: String },

    /// 无效输入错误
    #[error("Invalid input: {field} - {reason}")]
    InvalidInput { field: String, reason: String },

    /// 无效配置错误
    #[error("Invalid configuration:  {reason}")]
    InvalidConfig { reason: String },

    /// 超时错误
    #[error("Operation timeout: {operation} after {timeout_ms}ms")]
    Timeout { operation: String, timeout_ms: u64 },

    /// 下载不被允许错误
    #[error("Download not allowed for resource '{resource_id}': {reason}")]
    DownloadNotAllowed { resource_id: String, reason: String },
}

/// 便捷的结果类型别名
pub type DfsResult<T> = Result<T, DfsError>;

#[allow(dead_code)]
impl DfsError {
    /// 创建资源未找到错误
    pub fn resource_not_found<S: Into<String>>(resource_id: S) -> Self {
        Self::ResourceNotFound {
            resource_id: resource_id.into(),
        }
    }

    /// 创建版本未找到错误
    pub fn version_not_found<S1: Into<String>, S2: Into<String>>(
        resource_id: S1,
        version: S2,
    ) -> Self {
        Self::VersionNotFound {
            resource_id: resource_id.into(),
            version: version.into(),
        }
    }

    /// 创建服务器不可用错误
    pub fn server_unavailable<S: Into<String>>(server_id: S) -> Self {
        Self::ServerUnavailable {
            server_id: server_id.into(),
        }
    }

    /// 创建路径未找到错误
    pub fn path_not_found<S1: Into<String>, S2: Into<String>>(
        resource_id: S1,
        version: S2,
    ) -> Self {
        Self::PathNotFound {
            resource_id: resource_id.into(),
            version: version.into(),
        }
    }

    /// 创建配置加载错误
    pub fn config_load_failed<S: Into<String>>(reason: S) -> Self {
        Self::ConfigLoadFailed {
            reason: reason.into(),
        }
    }

    /// 创建Redis错误
    pub fn redis_error<S1: Into<String>, S2: Into<String>>(operation: S1, reason: S2) -> Self {
        Self::RedisError {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    /// 创建插件执行错误
    pub fn plugin_execution_failed<S1: Into<String>, S2: Into<String>>(
        plugin_id: S1,
        reason: S2,
    ) -> Self {
        Self::PluginExecutionFailed {
            plugin_id: plugin_id.into(),
            reason: reason.into(),
        }
    }

    /// 创建插件未找到错误
    pub fn plugin_not_found<S: Into<String>>(plugin_id: S) -> Self {
        Self::PluginNotFound {
            plugin_id: plugin_id.into(),
        }
    }

    /// 创建插件错误（别名，兼容性）
    pub fn plugin_error<S1: Into<String>, S2: Into<String>>(plugin_id: S1, reason: S2) -> Self {
        Self::PluginExecutionFailed {
            plugin_id: plugin_id.into(),
            reason: reason.into(),
        }
    }

    /// 创建认证失败错误
    pub fn authentication_failed<S: Into<String>>(reason: S) -> Self {
        Self::AuthenticationFailed {
            reason: reason.into(),
        }
    }

    /// 创建内部错误
    pub fn internal_error<S: Into<String>>(reason: S) -> Self {
        Self::InternalError {
            reason: reason.into(),
        }
    }

    /// 创建无效输入错误
    pub fn invalid_input<S1: Into<String>, S2: Into<String>>(field: S1, reason: S2) -> Self {
        Self::InvalidInput {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// 创建无效配置错误
    pub fn invalid_config<S: Into<String>>(reason: S) -> Self {
        Self::InvalidConfig {
            reason: reason.into(),
        }
    }

    /// 创建IO错误
    pub fn io_error<S1: Into<String>, S2: Into<String>>(operation: S1, reason: S2) -> Self {
        Self::IoError {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    /// 创建下载不允许错误
    pub fn download_not_allowed<S1: Into<String>, S2: Into<String>>(
        resource_id: S1,
        reason: S2,
    ) -> Self {
        Self::DownloadNotAllowed {
            resource_id: resource_id.into(),
            reason: reason.into(),
        }
    }

    /// 获取错误的 HTTP 状态码
    pub fn http_status_code(&self) -> u16 {
        match self {
            Self::ResourceNotFound { .. }
            | Self::VersionNotFound { .. }
            | Self::PathNotFound { .. }
            | Self::SessionNotFound { .. }
            | Self::ChallengeNotFound { .. }
            | Self::PluginNotFound { .. } => 404,

            Self::AuthenticationFailed { .. } => 401,

            Self::PermissionDenied { .. } => 403,

            Self::DownloadNotAllowed { .. } => 403,

            Self::InvalidInput { .. } => 400,
            Self::InvalidConfig { .. } => 400,

            Self::ChallengeVerificationFailed { .. } => 402,

            Self::Timeout { .. } => 408,

            Self::ServerUnavailable { .. }
            | Self::ServerNotFound { .. }
            | Self::RedisError { .. }
            | Self::NetworkError { .. }
            | Self::IoError { .. }
            | Self::InternalError { .. }
            | Self::SerializationError { .. }
            | Self::ConfigLoadFailed { .. }
            | Self::ConfigValidationFailed { .. }
            | Self::SessionCreationFailed { .. }
            | Self::PluginExecutionFailed { .. } => 500,
        }
    }

    /// 检查错误是否为可重试类型
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ServerUnavailable { .. }
                | Self::NetworkError { .. }
                | Self::Timeout { .. }
                | Self::RedisError { .. }
        )
    }

    /// 获取错误类别（用于指标统计）
    pub fn category(&self) -> &'static str {
        match self {
            Self::ResourceNotFound { .. }
            | Self::VersionNotFound { .. }
            | Self::PathNotFound { .. } => "resource",

            Self::SessionNotFound { .. } | Self::SessionCreationFailed { .. } => "session",

            Self::ChallengeVerificationFailed { .. } | Self::ChallengeNotFound { .. } => {
                "challenge"
            }

            Self::PluginExecutionFailed { .. } | Self::PluginNotFound { .. } => "plugin",

            Self::ConfigLoadFailed { .. } | Self::ConfigValidationFailed { .. } => "config",

            Self::RedisError { .. } => "redis",

            Self::ServerUnavailable { .. } | Self::ServerNotFound { .. } => "server",

            Self::NetworkError { .. } => "network",

            Self::IoError { .. } => "io",

            Self::SerializationError { .. } => "serialization",

            Self::AuthenticationFailed { .. } => "authentication",

            Self::PermissionDenied { .. } => "permission",

            Self::DownloadNotAllowed { .. } => "download",

            Self::InvalidInput { .. } => "input",

            Self::InvalidConfig { .. } => "config",

            Self::Timeout { .. } => "timeout",

            Self::InternalError { .. } => "internal",
        }
    }
}

// 从标准库错误类型转换
impl From<std::io::Error> for DfsError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            operation: "file_operation".to_string(),
            reason: err.to_string(),
        }
    }
}

impl From<serde_json::Error> for DfsError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError {
            reason: err.to_string(),
        }
    }
}

impl From<serde_yaml::Error> for DfsError {
    fn from(err: serde_yaml::Error) -> Self {
        Self::SerializationError {
            reason: err.to_string(),
        }
    }
}

impl From<anyhow::Error> for DfsError {
    fn from(err: anyhow::Error) -> Self {
        Self::InternalError {
            reason: err.to_string(),
        }
    }
}

impl From<String> for DfsError {
    fn from(reason: String) -> Self {
        Self::InternalError { reason }
    }
}

impl From<&str> for DfsError {
    fn from(reason: &str) -> Self {
        Self::InternalError {
            reason: reason.to_string(),
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for DfsError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::InternalError {
            reason: err.to_string(),
        }
    }
}

/// Axum IntoResponse implementation for DfsError
impl IntoResponse for DfsError {
    fn into_response(self) -> Response {
        let status_code = StatusCode::from_u16(self.http_status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let error_response = ApiResponse::error(self.to_string());
        (status_code, Json(error_response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = DfsError::resource_not_found("test_resource");
        assert_eq!(err.http_status_code(), 404);
        assert_eq!(err.category(), "resource");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_server_error() {
        let err = DfsError::server_unavailable("test_server");
        assert_eq!(err.http_status_code(), 500);
        assert_eq!(err.category(), "server");
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_display() {
        let err = DfsError::version_not_found("app", "1.0");
        assert!(
            err.to_string()
                .contains("Version '1.0' not found for resource 'app'")
        );
    }

    #[test]
    fn test_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let dfs_err: DfsError = io_err.into();
        assert_eq!(dfs_err.category(), "io");
    }
}
