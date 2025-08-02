use utoipa::OpenApi;
use axum::{Router, routing::get, Json, response::Html};

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
    components(
        schemas(
            CreateSessionRequest,
            SessionResponse,
            GetCdnRequest,
            CdnResponse,
            VerifyRequest,
            VerifyResponse,
            StatusResponse,
            HealthResponse,
            Session,
            Challenge,
            ErrorResponse,
        )
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server"),
        (url = "https://dfs2.example.com", description = "Production server")
    ),
    tags(
        (name = "Resource", description = "File resource and session management"),
        (name = "Health", description = "Server health and status monitoring"),
        (name = "System", description = "System configuration and metrics"),
        (name = "Challenge", description = "Authentication challenges")
    )
)]
pub struct ApiDoc;

/// OpenAPI JSON handler
async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Simple Swagger UI HTML page
async fn swagger_ui() -> Html<String> {
    let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>DFS2 API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api-docs/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>
    "#;
    Html(html.to_string())
}

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
            .route("/api-docs/openapi.json", get(openapi_json))
            .route("/docs", get(swagger_ui))
    } else {
        Router::new() // Return empty router when disabled
    }
}

/// Get OpenAPI specification
pub fn get_openapi_spec() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}