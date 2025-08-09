use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
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
            .or_else(|| {
                // 如果没有 X-Real-IP，尝试从 X-Forwarded-For 头获取
                headers
                    .get("x-forwarded-for")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|forwarded_for| {
                        // X-Forwarded-For 可能包含多个IP，取第一个
                        forwarded_for.split(',').next()
                    })
                    .and_then(|ip_str| ip_str.trim().parse::<IpAddr>().ok())
            })
            .unwrap_or_else(|| fallback_addr.ip());

        Self {
            remote_addr: SocketAddr::new(real_ip, fallback_addr.port()),
        }
    }
}
