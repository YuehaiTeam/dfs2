mod app_state;
mod analytics;
mod cache;
mod challenge;
mod config;
mod data_store;
mod docs;
mod error;
mod metrics;
mod models;
mod modules;
mod redis_data_store;
mod responses;
mod routes;

use app_state::create_data_store;
use axum::{Router, routing::get, http::Request, middleware::{self, Next}, response::Response, extract::ConnectInfo, body::Body};
use config::AppConfig;
use docs::{create_docs_router, is_openapi_docs_enabled};
use metrics::Metrics;
use dotenv::dotenv;
use error::{DfsError, DfsResult};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn init_tracing() -> DfsResult<()> {
    // 设置默认日志级别
    let default_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Tracing initialized successfully");
    Ok(())
}

use dfs2::RealConnectInfo;

// 中间件函数来处理真实IP提取
async fn real_ip_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    // 从请求头中提取真实IP
    let real_connect_info = RealConnectInfo::from_headers_and_addr(req.headers(), addr);
    
    // 将真实连接信息添加到请求扩展中
    req.extensions_mut().insert(real_connect_info);
    
    next.run(req).await
}

#[tokio::main]
async fn main() -> DfsResult<()> {
    dotenv().ok();

    // 初始化日志系统
    init_tracing()?;

    info!("Starting DFS2 server...");

    // 加载配置
    let config = match AppConfig::load().await {
        Ok(config) => {
            info!("Configuration loaded successfully");
            Arc::new(RwLock::new(config))
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return Err(DfsError::config_load_failed(e.to_string()));
        }
    };

    // 初始化数据存储后端
    let data_store = match create_data_store().await {
        Ok(store) => {
            info!("Data store backend initialized successfully");
            store
        }
        Err(e) => {
            error!("Failed to initialize data store backend: {}", e);
            return Err(DfsError::internal_error(format!("Data store initialization failed: {}", e)));
        }
    };

    // 创建JavaScript运行时
    let jsrunner = modules::qjs::JsRunner::new(config.clone(), data_store.clone()).await;
    info!("JavaScript runtime initialized");

    // 创建流程运行器
    let flowrunner = modules::flow::runner::FlowRunner {
        redis: data_store.clone(),
        jsrunner: jsrunner.clone(),
        config: config.clone(),
    };
    info!("Flow runner initialized");

    // 初始化Prometheus指标
    let metrics = match Metrics::new() {
        Ok(metrics) => {
            info!("Prometheus metrics initialized");
            Arc::new(metrics)
        }
        Err(e) => {
            error!("Failed to initialize metrics: {}", e);
            return Err(DfsError::internal_error(format!("Metrics initialization failed: {}", e)));
        }
    };

    // 更新初始指标
    {
        let config_read = config.read().await;
        metrics.set_plugins_loaded(config_read.plugins.len() as u64);
        metrics.set_server_health(config_read.servers.len() as u64, config_read.servers.len() as u64);
    }

    // 启动会话清理任务
    let cleanup_task = Arc::new(analytics::SessionCleanupTask::new(config.clone(), data_store.clone()));
    cleanup_task.clone().start_background_task().await;
    info!("Session cleanup task started");

    // 构建路由
    let metrics_route = Router::new()
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(metrics.clone());

    let app = Router::new()
        .merge(routes::resource::routes())
        .merge(routes::status::routes())
        .merge(routes::health::routes())
        .merge(routes::static_files::routes())
        .merge(create_docs_router())
        .merge(metrics_route)
        .layer(middleware::from_fn(real_ip_middleware))
        .layer(axum::Extension(data_store))
        .layer(axum::Extension(jsrunner))
        .layer(axum::Extension(flowrunner))
        .layer(axum::Extension(config));

    // 获取绑定地址
    let bind_addr = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let addr: SocketAddr = bind_addr.parse().map_err(|e: std::net::AddrParseError| {
        DfsError::invalid_input("BIND_ADDRESS", e.to_string())
    })?;

    info!("Starting HTTP server on {}", addr);
    
    // 记录OpenAPI文档状态
    if is_openapi_docs_enabled() {
        info!("OpenAPI documentation enabled at /docs and /api-docs/openapi.json");
    } else {
        info!("OpenAPI documentation disabled (set ENABLE_OPENAPI_DOCS=true to enable)");
    }

    // 启动服务器
    match axum::serve(
        tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| DfsError::io_error("bind_socket", e.to_string()))?,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        Ok(_) => {
            info!("Server shutdown gracefully");
            Ok(())
        }
        Err(e) => {
            error!("Server error: {}", e);
            Err(DfsError::internal_error(format!("Server error: {}", e)))
        }
    }
}
