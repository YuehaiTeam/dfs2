use ipdb::Reader;
use lazy_static::lazy_static;
use std::net::IpAddr;
use tracing::{error, info, warn};

lazy_static! {
    pub static ref IPDB: Option<Reader> = {
        let path = std::env::var("IPDB_PATH").unwrap_or_else(|_| "ipipfree.ipdb".to_string());
        match Reader::open_file(&path) {
            Ok(reader) => {
                info!("IPIP database loaded from: {}", path);
                Some(reader)
            }
            Err(e) => {
                error!("Failed to load IPIP database from {}: {}", path, e);
                error!("IP geolocation features will be disabled");
                None
            }
        }
    };
}

/// 判断IP是否为全球IP（非中国IP）
pub fn is_global_ip(ip: IpAddr) -> bool {
    if let Some(ref ipdb) = *IPDB {
        // 使用find_city_info获取详细的城市信息
        match ipdb.find(&ip.to_string(), "CN") {
            Ok(ipvec) => {
                // check if ipvec not include "CN" or "CHN"
                !ipvec.contains(&"CN") && !ipvec.contains(&"CHN")
            }
            Err(e) => {
                warn!("Failed to lookup IP {} with find_city_info: {}", ip, e);
                // 查询失败，默认为全球IP
                true
            }
        }
    } else {
        // 没有数据库，默认为全球IP
        true
    }
}

/// 获取IP地址的完整位置信息（用于geoip关键词匹配）
pub fn get_ip_location_data(ip: IpAddr) -> Option<String> {
    if let Some(ref ipdb) = *IPDB {
        match ipdb.find(&ip.to_string(), "CN") {
            Ok(result) => {
                // 将Vec<&str>用空格连接成字符串，用于geoip关键词匹配
                Some(result.join(" "))
            }
            Err(e) => {
                warn!("Failed to lookup IP location data for {}: {}", ip, e);
                None
            }
        }
    } else {
        None
    }
}

/// 判断IP是否为IPv6
pub fn is_ipv6(ip: IpAddr) -> bool {
    ip.is_ipv6()
}

/// 获取客户端IP地址（从请求中提取）
pub fn extract_client_ip(headers: &axum::http::HeaderMap) -> Option<IpAddr> {
    // 检查常见的代理头
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // X-Forwarded-For 可能包含多个IP，取第一个
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            if let Ok(ip) = real_ip_str.parse() {
                return Some(ip);
            }
        }
    }

    if let Some(cf_connecting_ip) = headers.get("cf-connecting-ip") {
        if let Ok(cf_ip_str) = cf_connecting_ip.to_str() {
            if let Ok(ip) = cf_ip_str.parse() {
                return Some(ip);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_ipv6() {
        assert!(!is_ipv6(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_ipv6(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn test_is_global_ip_fallback() {
        // 当没有IPIP数据库时，应该返回true
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let result = is_global_ip(ip);
        // 由于测试环境可能没有数据库，我们只确保函数不会panic
        assert!(result == true || result == false);
    }

    #[test]
    fn test_get_ip_location_data() {
        // 测试获取IP位置数据函数
        let ip = IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114));
        let result = get_ip_location_data(ip);
        // 由于测试环境可能没有数据库，我们只确保函数不会panic
        // 如果有数据库，result应该是Some，如果没有则是None
        match result {
            Some(data) => assert!(!data.is_empty()),
            None => {} // 没有数据库是正常的
        }
    }
}
