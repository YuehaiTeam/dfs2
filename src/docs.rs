use utoipa::OpenApi;
use axum::Router;
use utoipa_swagger_ui::SwaggerUi;

// Import response types for documentation
use crate::responses::*;
use crate::models::*;

/// DFS2 API Documentation
#[derive(OpenApi)]
#[openapi(
    info(
        title = "DFS2 - Distributed File System API",
        version = "0.2.0",
        description = "DFS2 is a Rust-based distributed file system server with JavaScript plugin support. It acts as middleware for file distribution across multiple storage backends (S3, direct URLs, DFS nodes) with configurable routing flows and CDN optimization.",
        license(name = "MIT", url = "https://opensource.org/licenses/MIT"),
        contact(name = "DFS2 Team", email = "support@example.com")
    ),
    paths(
        // Management endpoints
        crate::routes::mgmt::ping,
        crate::routes::mgmt::health_check,
        crate::routes::mgmt::reload_config,
        crate::routes::mgmt::metrics_handler,
        
        // Resource management endpoints
        crate::routes::resource::get_metadata,
        crate::routes::resource::create_session,
        crate::routes::resource::get_cdn,
        crate::routes::resource::delete_session,
        crate::routes::resource::download_redirect,
        crate::routes::resource::download_json,
        crate::routes::resource::get_prefix_metadata,
        crate::routes::resource::create_prefix_session,
        crate::routes::resource::download_prefix_redirect,
        crate::routes::resource::download_prefix_json,
        
        // Static file and challenge endpoints
        crate::routes::static_files::serve_static_file,
        crate::routes::static_files::serve_challenge_page,
    ),
    components(
        schemas(
            CreateSessionRequest,
            SessionCreatedResponse,
            ChallengeResponse,
            MetadataResponse,
            CdnUrlResponse,
            DownloadUrlResponse,
            CachedContentResponse,
            EmptyResponse,
            ErrorResponse,
            GetCdnRequest,
            VerifyRequest,
            VerifyResponse,
            StatusResponse,
            HealthResponse,
            Session,
            Challenge,
            ApiResponse,
            ResponseData,
            crate::routes::mgmt::HealthCheck,
            crate::models::DeleteSessionRequest,
            crate::models::InsightData,
        )
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server"),
        (url = "https://dfs2.example.com", description = "Production server")
    ),
    tags(
        (name = "Resource", description = "File resource and session management"),
        (name = "Management", description = "Server management and monitoring endpoints"),
        (name = "Challenge", description = "Authentication challenges"),
        (name = "Static", description = "Static file serving")
    ),
)]
pub struct ApiDoc;

// Swagger UI is now handled by utoipa-swagger-ui crate

/// Check if OpenAPI docs are enabled via environment variable
pub fn is_openapi_docs_enabled() -> bool {
    std::env::var("ENABLE_OPENAPI_DOCS")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false)
}

/// Create API documentation router (only if enabled)
pub fn create_docs_router() -> Router {
    if is_openapi_docs_enabled() {
        Router::new()
            .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
    } else {
        Router::new() // Return empty router when disabled
    }
}

