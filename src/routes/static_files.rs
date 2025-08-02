use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::get,
};
use std::fs;
use std::path::PathBuf;

/// 静态HTML文件服务路由
/// 用于托管挑战验证页面和其他静态资源
pub fn routes() -> Router {
    Router::new()
        .route("/static/{*path}", get(serve_static_file))
        .route("/challenge/{challenge_type}", get(serve_challenge_page))
}

/// 服务静态文件
async fn serve_static_file(Path(file_path): Path<String>) -> impl IntoResponse {
    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "static".to_string());
    let full_path = PathBuf::from(&static_dir).join(&file_path);

    // 安全检查：确保路径不会越出静态目录
    if !full_path.starts_with(&static_dir) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    match fs::read(&full_path) {
        Ok(contents) => {
            let content_type = get_content_type(&file_path);
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                contents,
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "File not found").into_response(),
    }
}

/// 服务挑战页面
async fn serve_challenge_page(Path(challenge_type): Path<String>) -> impl IntoResponse {
    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "static".to_string());
    let template_path = PathBuf::from(&static_dir)
        .join("challenge")
        .join(format!("{}.html", challenge_type));

    match fs::read_to_string(&template_path) {
        Ok(template) => {
            // 直接返回HTML文件，不进行模板替换
            Html(template).into_response()
        }
        Err(_) => {
            // 如果找不到特定的模板，返回通用错误页面
            let error_html = format!(
                r#"
<!DOCTYPE html>
<html>
<head>
    <title>Challenge Not Available</title>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
        .error {{ color: #d32f2f; }}
    </style>
</head>
<body>
    <h1 class="error">Challenge Type Not Supported</h1>
    <p>The requested challenge type '{}' is not available.</p>
    <p>Please contact the administrator if this error persists.</p>
</body>
</html>
                "#,
                challenge_type
            );
            (StatusCode::NOT_FOUND, Html(error_html)).into_response()
        }
    }
}

/// 根据文件扩展名确定Content-Type
fn get_content_type(file_path: &str) -> &'static str {
    let extension = file_path.split('.').last().unwrap_or("");
    match extension {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}
