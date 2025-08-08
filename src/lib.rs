pub mod models;
pub mod data_store;
pub mod redis_data_store;
pub mod config;
pub mod error;
pub mod challenge;
pub mod responses;
pub mod app_state;
pub mod metrics;
pub mod modules;
pub mod routes;
pub mod docs;
pub mod analytics;
pub mod cache;
pub mod legacy_client;

use axum::http::HeaderMap;
use std::net::{SocketAddr, IpAddr};

// 自定义连接信息结构体，支持从 X-Real-IP 头提取IP地址
#[derive(Clone, Debug)]
pub struct RealConnectInfo {
    pub remote_addr: SocketAddr,
}

impl RealConnectInfo {
    pub fn from_headers_and_addr(headers: &HeaderMap, fallback_addr: SocketAddr) -> Self {
        // 尝试从 X-Real-IP 头获取真实IP
        let real_ip = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|ip_str| ip_str.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, fallback_addr.port()));

        Self {
            remote_addr: real_ip.unwrap_or(fallback_addr),
        }
    }
}