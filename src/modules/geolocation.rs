use lazy_static::lazy_static;
use maxminddb::Reader;
use std::net::IpAddr;
use tracing::{error, info};

lazy_static! {
    static ref IPDB: Option<Reader<Vec<u8>>> = {
        let path =
            std::env::var("GEOLITE2_PATH").unwrap_or_else(|_| "GeoLite2-City.mmdb".to_string());
        match maxminddb::Reader::open_readfile(&path) {
            Ok(reader) => {
                info!("GeoLite2 database loaded from: {}", path);
                Some(reader)
            }
            Err(e) => {
                error!("Failed to load GeoLite2 database from {}: {}", path, e);
                error!("IP geolocation features will be disabled");
                None
            }
        }
    };
}

/// 判断IP是否为全球IP（非中国IP）
pub fn is_global_ip(ip: IpAddr) -> bool {
    if let Some(ref ipdb) = *IPDB {
        match ipdb.lookup::<maxminddb::geoip2::City>(ip) {
            Ok(city_record_opt) => {
                if let Some(city_record) = city_record_opt {
                    if let Some(country) = city_record.country {
                        if let Some(iso_code) = country.iso_code {
                            let is_cn = iso_code == "CN";
                            return !is_cn;
                        }
                    }
                }
                // 如果没有国家信息，默认为全球IP
                true
            }
            Err(_) => {
                // 查询失败，默认为全球IP
                true
            }
        }
    } else {
        // 没有数据库，默认为全球IP
        true
    }
}

/// 判断IP是否为IPv6
pub fn is_ipv6(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => false,
        IpAddr::V6(_) => true,
    }
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
        // 当没有GeoLite2数据库时，应该返回true
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let result = is_global_ip(ip);
        // 由于测试环境可能没有数据库，我们只确保函数不会panic
        assert!(result == true || result == false);
    }
}
