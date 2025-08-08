mod config;
mod container;
mod error;
mod metrics;
mod models;
mod modules;
mod responses;
mod routes;
mod services;
mod validation;

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::Request,
    middleware::{self, Next},
    response::Response,
};
use clap::Parser;
use container::AppContainer;
use dotenv::dotenv;
use error::{DfsError, DfsResult};
use std::net::SocketAddr;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use validation::ConfigValidator;

use crate::modules::{analytics, network::RealConnectInfo};

/// DFS2 - Distributed File System Server
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Validate configuration and plugins only, then exit
    #[arg(
        long,
        help = "Validate configuration and plugins, then exit without starting the server"
    )]
    validate_only: bool,
}

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

    // 解析命令行参数
    let args = Args::parse();

    // 初始化日志系统
    init_tracing()?;

    if args.validate_only {
        info!("运行配置验证模式...");
    } else {
        info!("Starting DFS2 server...");
    }

    // 使用AppContainer初始化所有组件
    let app_container = match AppContainer::new().await {
        Ok(container) => {
            info!("Application container initialized successfully");
            container
        }
        Err(e) => {
            error!("Failed to initialize application container: {}", e);
            return Err(e);
        }
    };

    // 如果是验证模式，执行验证后退出
    if args.validate_only {
        let config_guard = app_container.shared_config.load();
        match ConfigValidator::validate_full(&config_guard, &app_container.data_store).await {
            Ok(report) => {
                report.print_report();
                std::process::exit(if report.is_valid() { 0 } else { 1 });
            }
            Err(e) => {
                error!("配置验证失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // 创建统一的AppContext
    let app_context = app_container.create_app_context();
    info!("Application context created");

    // 更新初始指标
    {
        let config_guard = app_container.shared_config.load();
        app_container
            .metrics
            .set_plugins_loaded(config_guard.plugins.len() as u64);
        app_container.metrics.set_server_health(
            config_guard.servers.len() as u64,
            config_guard.servers.len() as u64,
        );
    }

    // 初始化版本缓存
    {
        let config_guard = app_container.shared_config.load();
        match modules::version_provider::updater::initialize_version_system(
            &config_guard,
            app_container.version_cache.clone(),
            std::sync::Arc::new(modules::version_provider::PluginVersionProvider::new(
                app_container.js_runner.clone(),
                app_container.shared_config.clone(),
            )),
        )
        .await
        {
            Ok(init_count) => {
                info!(
                    "Version provider system initialized for {} resources",
                    init_count
                );
            }
            Err(e) => {
                warn!("Failed to initialize version provider system: {}", e);
            }
        }
    }

    // 启动后台任务
    let version_updater = modules::version_provider::VersionUpdater::new(
        app_container.shared_config.clone(),
        app_container.version_cache.clone(),
        std::sync::Arc::new(modules::version_provider::PluginVersionProvider::new(
            app_container.js_runner.clone(),
            app_container.shared_config.clone(),
        )),
    );
    std::sync::Arc::new(version_updater)
        .start_background_task()
        .await;
    info!("Version updater background task started");

    // 启动会话清理任务
    let cleanup_task = std::sync::Arc::new(analytics::SessionCleanupTask::new(
        app_container.shared_config.clone(),
        app_container.data_store.clone(),
    ));
    cleanup_task.start_background_task().await;
    info!("Session cleanup task started");

    // 构建路由 - 使用统一的AppContext
    let app = Router::new()
        .merge(routes::resource::routes())
        .merge(routes::static_files::routes())
        .merge(routes::mgmt::routes())
        .layer(middleware::from_fn(real_ip_middleware))
        .layer(axum::Extension(app_context));

    // 获取绑定地址
    let bind_addr = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let addr: SocketAddr = bind_addr.parse().map_err(|e: std::net::AddrParseError| {
        DfsError::invalid_input("BIND_ADDRESS", e.to_string())
    })?;

    info!("Starting HTTP server on {}", addr);

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
