mod app_state;
mod config;
mod models;
mod modules;
mod responses;
mod routes;

use app_state::RedisStore;
use axum::Router;
use config::AppConfig;
use dotenv::dotenv;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let config = Arc::new(RwLock::new(AppConfig::load().await?));
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).unwrap();
    let redis_store = RedisStore::new(redis_client);
    let jsrunner = modules::qjs::JsRunner::new(config.clone(), redis_store.clone()).await;
    let flowrunner = modules::flow::runner::FlowRunner {
        redis: redis_store.clone(),
        jsrunner: jsrunner.clone(),
        config: config.clone(),
    };

    let app = Router::new()
        .merge(routes::resource::routes())
        .merge(routes::status::routes())
        .layer(axum::Extension(redis_store))
        .layer(axum::Extension(jsrunner))
        .layer(axum::Extension(flowrunner))
        .layer(axum::Extension(config));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("http://{}", addr);
    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app.into_make_service(),
    )
    .await
    .unwrap();

    Ok(())
}
