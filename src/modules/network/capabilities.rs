//! Client capability detection and URL scheme rewriting.
//!
//! This module consolidates all transport capability detection (HTTP/3, WebRTC, WebTransport)
//! and URL scheme rewriting logic into a single module.
//!
//! ## Capabilities
//!
//! Capabilities are detected from two sources:
//! 1. `X-DFS-Override` header (explicit override, e.g. `h3=1&wrtc=0&wt=1`)
//! 2. User-Agent string analysis (browser/marker detection)
//!
//! ## URL Rewriting
//!
//! After URL signing, the `rewrite_url()` function rewrites the URL scheme
//! based on the server type/config:
//! - `h3_only` → `https://` → `http3://` (+ optional `#cert=` fragment)
//! - `dfs_rtc` → `http(s)://` → `wrtc://`
//! - `dfs_webtransport` → `http(s)://` → `h3wt://` (+ optional `#cert=` fragment)
//! - `ssh_only` → `http://` → `ssh+http://` (+ `#user/pass/fingerprint` fragment)
//! - `dfs_sftp` → URL generated directly by DfsSftpSigner (no rewrite needed)

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use url::Url;

use crate::config::{CertHashPolicy, ServerConfig};
use crate::error::{DfsError, DfsResult};
use crate::modules::server::HealthInfo;

// ─────────────────────────────────────────────────────────────────────────────
// RequestOverride
// ─────────────────────────────────────────────────────────────────────────────

/// Request override parameters from X-DFS-Override header.
///
/// Parses querystring-formatted override values like `h3=1&wrtc=0&wt=1`.
/// Each field controls a specific transport capability:
/// - `Some(0)` = force disable
/// - `Some(1)` = force enable
/// - `None` = no override, use auto-detection
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RequestOverride {
    /// HTTP/3 override
    pub h3: Option<u8>,
    /// WebRTC override
    pub wrtc: Option<u8>,
    /// WebTransport override
    pub wt: Option<u8>,
    /// SSH tunnel override
    pub ssh: Option<u8>,
    /// SFTP override
    pub sftp: Option<u8>,
    /// Extra parameters for future extensibility
    #[serde(flatten)]
    #[allow(dead_code)]
    pub extra: HashMap<String, String>,
}

impl RequestOverride {
    /// Parse override string from X-DFS-Override header.
    ///
    /// Returns `None` if the string is empty or malformed.
    pub fn parse(header_value: &str) -> Option<Self> {
        if header_value.is_empty() {
            return None;
        }
        serde_urlencoded::from_str(header_value).ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClientCapabilities
// ─────────────────────────────────────────────────────────────────────────────

/// Client transport capabilities detected from request headers.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClientCapabilities {
    /// HTTP/3 capable (for h3_only servers)
    pub h3: bool,
    /// WebRTC capable (for dfs_rtc servers)
    pub wrtc: bool,
    /// WebTransport capable (for dfs_webtransport servers)
    pub wt: bool,
    /// SSH tunnel capable (for ssh_only servers)
    pub ssh: bool,
    /// SFTP capable (for dfs_sftp servers)
    pub sftp: bool,
}

impl ClientCapabilities {
    /// 本进程 fetch 客户端的能力面。
    ///
    /// 与 `Default`（全 false，表示"未从请求中识别出任何能力"）不同，这是一份确定的声明，
    /// 取自 `FETCH_CLIENT` 实际挂载的 middleware：H3、SSH、SFTP 三者可用；
    /// WebTransport 与 WebRTC 是浏览器侧协议，本进程作为客户端不具备。
    pub fn internal_fetcher() -> Self {
        Self {
            h3: true,
            wrtc: false,
            wt: false,
            ssh: true,
            sftp: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability detection
// ─────────────────────────────────────────────────────────────────────────────

/// Get the compiled regex for Chrome version detection.
///
/// Matches both `Chrome/<major>` (desktop) and `CriOS/<major>` (Chrome on iOS).
fn get_chrome_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?:Chrome|CriOS)/(\d+)").expect("Invalid Chrome regex pattern")
    })
}

/// Check if Chrome major version > 100.
fn is_chrome_above_100(ua: &str) -> bool {
    if let Some(caps) = get_chrome_regex().captures(ua)
        && let Some(major_match) = caps.get(1)
        && let Ok(major_version) = major_match.as_str().parse::<u32>()
    {
        return major_version > 100;
    }
    false
}

/// Detect a single capability from override + UA.
///
/// - `override_val`: the override field value (e.g. `h3=0` → `Some(0)`)
/// - `marker`: the UA marker to look for (e.g. `"h3/enabled"`)
/// - `chrome_fallback`: whether to fall back to Chrome>100 detection
fn detect_capability(
    override_val: Option<u8>,
    ua: Option<&str>,
    marker: &str,
    chrome_fallback: bool,
) -> bool {
    // Step 1 & 2: Override
    match override_val {
        Some(0) => return false,
        Some(1) => return true,
        _ => {}
    }

    // Step 3+: UA analysis
    let ua = match ua {
        Some(ua) if !ua.is_empty() => ua,
        _ => return false,
    };

    // Check marker
    if ua.contains(marker) {
        return true;
    }

    // Chrome fallback (if enabled for this capability)
    if chrome_fallback && is_chrome_above_100(ua) {
        return true;
    }

    false
}

/// Compute all client capabilities from request headers.
///
/// # Arguments
///
/// * `override_header` - Optional value of X-DFS-Override header
/// * `user_agent` - Optional User-Agent string
pub fn compute_capabilities(
    override_header: Option<&str>,
    user_agent: Option<&str>,
) -> ClientCapabilities {
    let overrides = override_header
        .and_then(RequestOverride::parse)
        .unwrap_or_default();

    ClientCapabilities {
        h3: detect_capability(overrides.h3, user_agent, "h3/enabled", false),
        wrtc: detect_capability(overrides.wrtc, user_agent, "wrtc/enabled", true),
        wt: detect_capability(overrides.wt, user_agent, "wt/enabled", true),
        ssh: detect_capability(overrides.ssh, user_agent, "ssh/enabled", false),
        sftp: detect_capability(overrides.sftp, user_agent, "sftp/enabled", false),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// URL rewriting
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrite a URL's scheme and optionally append a `#cert=` fragment,
/// based on the server's type/configuration and client capabilities.
///
/// When a server has both `h3_only` AND `type = "dfs_webtransport"`,
/// the client capabilities determine which scheme to use (h3 preferred):
/// - Client supports h3 → `http3://`
/// - Client supports wt (but not h3) → `h3wt://`
///
/// Otherwise:
/// - `h3_only` → `https://` → `http3://` (+ cert fragment)
/// - `dfs_rtc` type → `http(s)://` → `wrtc://`
/// - `dfs_webtransport` type → `http(s)://` → `h3wt://` (+ cert fragment)
/// - All other servers → passthrough (unchanged)
pub fn rewrite_url(
    url: &str,
    server_config: &ServerConfig,
    health_info: Option<&HealthInfo>,
    capabilities: &ClientCapabilities,
) -> DfsResult<String> {
    // ── SSH-only rewrite ──
    // http://ssh_host:22/path?$=sig → ssh+http://ssh_host:22/path?$=sig#user=...&pass=...&fingerprint=...
    if server_config.ssh_only {
        return rewrite_to_ssh(url, server_config);
    }

    // dfs_sftp URLs are generated directly by DfsSftpSigner — no rewrite needed
    if server_config.r#type == "dfs_sftp" {
        return Ok(url.to_string());
    }

    let is_wt = server_config.r#type == "dfs_webtransport";

    if server_config.h3_only && is_wt {
        // Dual mode: h3 preferred, wt fallback
        if capabilities.h3 {
            return rewrite_to_scheme_with_cert(url, "http3", server_config, health_info);
        }
        if capabilities.wt {
            return rewrite_to_scheme_with_cert(url, "h3wt", server_config, health_info);
        }
        // Neither — gate should have filtered. Default to h3 so the client
        // gets a fast-fail (unrecognised scheme) instead of silently falling
        // back to an h2 connection that will time out.
        return rewrite_to_scheme_with_cert(url, "http3", server_config, health_info);
    }

    if server_config.h3_only {
        return rewrite_to_scheme_with_cert(url, "http3", server_config, health_info);
    }

    match server_config.r#type.as_str() {
        "dfs_rtc" => Ok(rewrite_to_scheme(url, "wrtc")),
        "dfs_webtransport" => rewrite_to_scheme_with_cert(url, "h3wt", server_config, health_info),
        _ => Ok(url.to_string()),
    }
}

/// Simple scheme replacement: `http(s)://` → `{scheme}://`.
///
/// Non-http(s) URLs are returned unchanged.
fn rewrite_to_scheme(url: &str, scheme: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        return format!("{scheme}://{rest}");
    }
    if let Some(rest) = url.strip_prefix("http://") {
        return format!("{scheme}://{rest}");
    }
    url.to_string()
}

/// Rewrite an HTTP URL to ssh+http:// with credentials in fragment.
///
/// For dfs_node type servers, the DFS signature is used as password:
/// - user = hex-encoded path
/// - pass = the `?$=` signature value
/// Format a host string for URL output, adding brackets for IPv6 addresses.
pub fn format_host_for_url(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

///
/// For other server types, none-auth is used:
/// - user = "" (empty, triggers authenticate_none in SSH middleware)
/// - pass = ""
fn rewrite_to_ssh(url: &str, server_config: &ServerConfig) -> DfsResult<String> {
    let parsed = Url::parse(url).map_err(|e| {
        DfsError::internal_error(format!("Failed to parse URL for ssh rewrite: {e}"))
    })?;

    // Only rewrite http:// URLs
    if parsed.scheme() != "http" {
        return Ok(url.to_string());
    }

    let fingerprint = server_config
        .ssh_fingerprint
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();

    // Determine user/pass based on server type
    let (ssh_user, ssh_pass) = if server_config.r#type == "dfs_node" {
        // DFS node auth: user = hex(path), pass = DFS signature
        let path = parsed.path();
        let user = hex::encode(path.as_bytes());
        // Extract signature from ?$= query parameter
        let sig = parsed
            .query_pairs()
            .find(|(k, _)| k == "$")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        (user, sig)
    } else {
        // None-auth: empty user + empty pass triggers authenticate_none in SSH middleware
        (String::new(), String::new())
    };

    // Build the ssh+http URL preserving path and query
    let host_raw = parsed.host_str().unwrap_or("localhost");
    let host = format_host_for_url(host_raw);
    let port = parsed.port().unwrap_or(22);
    let path_and_query = match parsed.query() {
        Some(q) => format!("{}?{}", parsed.path(), q),
        None => parsed.path().to_string(),
    };

    let mut fragment = format!(
        "user={}&pass={}&fingerprint={}",
        percent_encode(&ssh_user),
        percent_encode(&ssh_pass),
        &fingerprint,
    );

    // Append optional internal_host and internal_port
    if let Some(ref ih) = server_config.ssh_internal_host {
        fragment.push_str(&format!("&internal_host={}", percent_encode(ih)));
    }
    if let Some(ip) = server_config.ssh_internal_port {
        fragment.push_str(&format!("&internal_port={}", ip));
    }

    Ok(format!(
        "ssh+http://{host}:{port}{path_and_query}#{fragment}",
    ))
}

/// Minimal percent-encoding for URL fragment values.
pub fn percent_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            // unreserved characters
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Scheme replacement + `#cert={hash}` fragment based on cert hash policy.
///
/// Only rewrites `https://` URLs. Non-https URLs are returned unchanged.
fn rewrite_to_scheme_with_cert(
    original_url: &str,
    scheme: &str,
    server_config: &ServerConfig,
    health_info: Option<&HealthInfo>,
) -> DfsResult<String> {
    let url = Url::parse(original_url).map_err(|e| {
        DfsError::internal_error(format!("Failed to parse URL for {scheme} rewrite: {e}"))
    })?;

    // Only rewrite https URLs
    if url.scheme() != "https" {
        return Ok(original_url.to_string());
    }

    // Determine cert fragment based on policy
    let fragment = match server_config.cert_hash_policy() {
        Ok(CertHashPolicy::ValidCert) => None,
        Ok(CertHashPolicy::Trust) => {
            if let Some(hash) = health_info.and_then(|h| h.observed_cert_hash.as_ref()) {
                let normalized = hash.to_ascii_lowercase();
                Some(format!("cert={normalized}"))
            } else {
                return Err(DfsError::internal_error(format!(
                    "{scheme} server with cert_hash=trust but no observed cert hash available"
                )));
            }
        }
        Ok(CertHashPolicy::PinnedHex(bytes)) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            Some(format!("cert={hex}"))
        }
        Err(e) => {
            return Err(DfsError::internal_error(format!(
                "Invalid cert_hash policy: {e}"
            )));
        }
    };

    // Build the rewritten URL: strip fragment, replace scheme, append new fragment.
    // url::Url::set_scheme() rejects special→non-special transitions, so we do it manually.
    let without_fragment = {
        let s = url.as_str();
        if url.fragment().is_some() {
            &s[..s.rfind('#').unwrap_or(s.len())]
        } else {
            s
        }
    };

    let rewritten = format!("{scheme}://{}", &without_fragment["https://".len()..]);

    match fragment {
        Some(frag) => Ok(format!("{rewritten}#{frag}")),
        None => Ok(rewritten),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ===== RequestOverride Parsing Tests =====

    #[test]
    fn test_parse_override_all_fields() {
        let parsed = RequestOverride::parse("h3=1&wrtc=0&wt=1").unwrap();
        assert_eq!(parsed.h3, Some(1));
        assert_eq!(parsed.wrtc, Some(0));
        assert_eq!(parsed.wt, Some(1));
    }

    #[test]
    fn test_parse_override_partial() {
        let parsed = RequestOverride::parse("h3=1&a=1").unwrap();
        assert_eq!(parsed.h3, Some(1));
        assert_eq!(parsed.wrtc, None);
        assert_eq!(parsed.wt, None);
        assert_eq!(parsed.extra.get("a"), Some(&"1".to_string()));
    }

    #[test]
    fn test_parse_override_empty() {
        assert!(RequestOverride::parse("").is_none());
    }

    #[test]
    fn test_parse_override_no_known_fields() {
        let parsed = RequestOverride::parse("a=1&b=2").unwrap();
        assert_eq!(parsed.h3, None);
        assert_eq!(parsed.wrtc, None);
        assert_eq!(parsed.wt, None);
    }

    // ===== h3 Capability Tests (NO Chrome fallback) =====

    #[test]
    fn test_h3_override_enable() {
        let caps = compute_capabilities(Some("h3=1"), Some("Firefox/100"));
        assert!(caps.h3);
    }

    #[test]
    fn test_h3_override_disable() {
        let caps = compute_capabilities(Some("h3=0"), Some("h3/enabled"));
        assert!(!caps.h3);
    }

    #[test]
    fn test_h3_marker() {
        let caps = compute_capabilities(None, Some("MyApp/1.0 h3/enabled"));
        assert!(caps.h3);
    }

    #[test]
    fn test_h3_no_chrome_fallback() {
        // Chrome 120 should NOT enable h3 (Chrome fallback removed)
        let ua = "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36";
        let caps = compute_capabilities(None, Some(ua));
        assert!(!caps.h3);
    }

    #[test]
    fn test_h3_no_headers() {
        let caps = compute_capabilities(None, None);
        assert!(!caps.h3);
    }

    // ===== wrtc Capability Tests (HAS Chrome fallback) =====

    #[test]
    fn test_wrtc_override_enable() {
        let caps = compute_capabilities(Some("wrtc=1"), Some("Firefox/100"));
        assert!(caps.wrtc);
    }

    #[test]
    fn test_wrtc_override_disable() {
        let caps = compute_capabilities(Some("wrtc=0"), Some("Chrome/120"));
        assert!(!caps.wrtc);
    }

    #[test]
    fn test_wrtc_marker() {
        let caps = compute_capabilities(None, Some("MyApp/1.0 wrtc/enabled"));
        assert!(caps.wrtc);
    }

    #[test]
    fn test_wrtc_chrome_fallback() {
        let ua = "Mozilla/5.0 Chrome/101.0.0.0 Safari/537.36";
        let caps = compute_capabilities(None, Some(ua));
        assert!(caps.wrtc);
    }

    #[test]
    fn test_wrtc_chrome_100_not_capable() {
        let ua = "Mozilla/5.0 Chrome/100.0.0.0 Safari/537.36";
        let caps = compute_capabilities(None, Some(ua));
        assert!(!caps.wrtc);
    }

    #[test]
    fn test_wrtc_no_headers() {
        let caps = compute_capabilities(None, None);
        assert!(!caps.wrtc);
    }

    // ===== wt Capability Tests (HAS Chrome fallback) =====

    #[test]
    fn test_wt_override_enable() {
        let caps = compute_capabilities(Some("wt=1"), Some("Firefox/100"));
        assert!(caps.wt);
    }

    #[test]
    fn test_wt_override_disable() {
        let caps = compute_capabilities(Some("wt=0"), Some("Chrome/120"));
        assert!(!caps.wt);
    }

    #[test]
    fn test_wt_marker() {
        let caps = compute_capabilities(None, Some("MyApp/1.0 wt/enabled"));
        assert!(caps.wt);
    }

    #[test]
    fn test_wt_chrome_fallback() {
        let ua = "Mozilla/5.0 Chrome/101.0.0.0 Safari/537.36";
        let caps = compute_capabilities(None, Some(ua));
        assert!(caps.wt);
    }

    #[test]
    fn test_wt_chrome_100_not_capable() {
        let ua = "Mozilla/5.0 Chrome/100.0.0.0 Safari/537.36";
        let caps = compute_capabilities(None, Some(ua));
        assert!(!caps.wt);
    }

    // ===== Combined Override Tests =====

    #[test]
    fn test_combined_overrides() {
        let caps = compute_capabilities(Some("h3=1&wrtc=0&wt=1"), Some("Firefox/50"));
        assert!(caps.h3);
        assert!(!caps.wrtc);
        assert!(caps.wt);
    }

    #[test]
    fn test_chrome_enables_wrtc_and_wt_but_not_h3() {
        let ua = "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36";
        let caps = compute_capabilities(None, Some(ua));
        assert!(!caps.h3); // no Chrome fallback for h3
        assert!(caps.wrtc); // Chrome fallback for wrtc
        assert!(caps.wt); // Chrome fallback for wt
    }

    // ===== CriOS Tests =====

    #[test]
    fn test_crios_105() {
        let ua = "Mozilla/5.0 (iPhone) CriOS/105.0.0.0 Mobile Safari/604.1";
        let caps = compute_capabilities(None, Some(ua));
        assert!(!caps.h3); // no Chrome fallback
        assert!(caps.wrtc); // CriOS 105 > 100
        assert!(caps.wt); // CriOS 105 > 100
    }

    #[test]
    fn test_crios_100() {
        let ua = "Mozilla/5.0 (iPhone) CriOS/100.0.0.0 Mobile Safari/604.1";
        let caps = compute_capabilities(None, Some(ua));
        assert!(!caps.wrtc);
        assert!(!caps.wt);
    }

    // ===== Override Precedence Tests =====

    #[test]
    fn test_override_precedence() {
        // Override disable beats Chrome fallback
        let caps = compute_capabilities(Some("wrtc=0&wt=0"), Some("Chrome/120"));
        assert!(!caps.wrtc);
        assert!(!caps.wt);

        // Override enable beats no UA
        let caps = compute_capabilities(Some("h3=1&wrtc=1&wt=1"), None);
        assert!(caps.h3);
        assert!(caps.wrtc);
        assert!(caps.wt);
    }

    // ===== Edge Cases =====

    #[test]
    fn test_empty_ua() {
        let caps = compute_capabilities(None, Some(""));
        assert!(!caps.h3);
        assert!(!caps.wrtc);
        assert!(!caps.wt);
    }

    #[test]
    fn test_firefox_no_capabilities() {
        let ua = "Mozilla/5.0 Gecko/20100101 Firefox/120.0";
        let caps = compute_capabilities(None, Some(ua));
        assert!(!caps.h3);
        assert!(!caps.wrtc);
        assert!(!caps.wt);
    }

    #[test]
    fn test_malformed_override_falls_through() {
        // "malformed" parses but has no known fields → UA analysis
        let caps = compute_capabilities(Some("malformed"), Some("Chrome/120"));
        assert!(!caps.h3); // no Chrome fallback
        assert!(caps.wrtc); // Chrome fallback
        assert!(caps.wt); // Chrome fallback
    }

    // ===== URL Rewrite Tests =====

    fn caps_h3() -> ClientCapabilities {
        ClientCapabilities {
            h3: true,
            ..Default::default()
        }
    }

    fn caps_wt() -> ClientCapabilities {
        ClientCapabilities {
            wt: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_rewrite_wrtc() {
        let config = ServerConfig {
            id: "test".into(),
            url: "https://example.com".into(),
            r#type: "dfs_rtc".into(),
            h3_only: false,
            ..Default::default()
        };
        let result = rewrite_url(
            "https://example.com/path?$=sig",
            &config,
            None,
            &Default::default(),
        )
        .unwrap();
        assert_eq!(result, "wrtc://example.com/path?$=sig");
    }

    #[test]
    fn test_rewrite_wrtc_http() {
        let config = ServerConfig {
            id: "test".into(),
            url: "http://example.com".into(),
            r#type: "dfs_rtc".into(),
            h3_only: false,
            ..Default::default()
        };
        let result = rewrite_url(
            "http://example.com/path?$=sig",
            &config,
            None,
            &Default::default(),
        )
        .unwrap();
        assert_eq!(result, "wrtc://example.com/path?$=sig");
    }

    #[test]
    fn test_rewrite_h3_only_valid_cert() {
        let config = ServerConfig {
            id: "test".into(),
            url: "https://example.com".into(),
            r#type: "direct".into(),
            h3_only: true,
            // No cert_hash → ValidCert policy
            ..Default::default()
        };
        let result = rewrite_url("https://example.com/path", &config, None, &caps_h3()).unwrap();
        assert_eq!(result, "http3://example.com/path");
    }

    #[test]
    fn test_rewrite_h3_only_trust() {
        let config = ServerConfig {
            id: "test".into(),
            url: "https://example.com".into(),
            r#type: "direct".into(),
            h3_only: true,
            cert_hash: Some("trust".into()),
            ..Default::default()
        };
        let health = HealthInfo {
            is_alive: true,
            file_size: None,
            last_check: 0,
            observed_cert_hash: Some("AABB".into()),
            content_hash: None,
        };
        let result = rewrite_url(
            "https://example.com/path",
            &config,
            Some(&health),
            &caps_h3(),
        )
        .unwrap();
        assert_eq!(result, "http3://example.com/path#cert=aabb");
    }

    #[test]
    fn test_rewrite_h3wt_valid_cert() {
        let config = ServerConfig {
            id: "test".into(),
            url: "https://wt.example.com".into(),
            r#type: "dfs_webtransport".into(),
            h3_only: false,
            ..Default::default()
        };
        let result = rewrite_url(
            "https://wt.example.com/path?$=sig",
            &config,
            None,
            &caps_wt(),
        )
        .unwrap();
        assert_eq!(result, "h3wt://wt.example.com/path?$=sig");
    }

    #[test]
    fn test_rewrite_h3wt_trust() {
        let config = ServerConfig {
            id: "test".into(),
            url: "https://wt.example.com".into(),
            r#type: "dfs_webtransport".into(),
            h3_only: false,
            cert_hash: Some("trust".into()),
            ..Default::default()
        };
        let health = HealthInfo {
            is_alive: true,
            file_size: None,
            last_check: 0,
            observed_cert_hash: Some("CCDD".into()),
            content_hash: None,
        };
        let result = rewrite_url(
            "https://wt.example.com/path?$=sig",
            &config,
            Some(&health),
            &caps_wt(),
        )
        .unwrap();
        assert_eq!(result, "h3wt://wt.example.com/path?$=sig#cert=ccdd");
    }

    #[test]
    fn test_rewrite_passthrough() {
        let config = ServerConfig {
            id: "test".into(),
            url: "https://cdn.example.com".into(),
            r#type: "direct".into(),
            h3_only: false,
            ..Default::default()
        };
        let result = rewrite_url(
            "https://cdn.example.com/path",
            &config,
            None,
            &Default::default(),
        )
        .unwrap();
        assert_eq!(result, "https://cdn.example.com/path");
    }

    #[test]
    fn test_rewrite_non_https_passthrough() {
        // h3_only but http:// URL → no rewrite
        let config = ServerConfig {
            id: "test".into(),
            url: "http://example.com".into(),
            r#type: "direct".into(),
            h3_only: true,
            ..Default::default()
        };
        let result = rewrite_url("http://example.com/path", &config, None, &caps_h3()).unwrap();
        assert_eq!(result, "http://example.com/path");
    }

    #[test]
    fn test_rewrite_dual_h3_wt_prefers_h3() {
        let config = ServerConfig {
            id: "test".into(),
            url: "https://dual.example.com".into(),
            r#type: "dfs_webtransport".into(),
            h3_only: true,
            ..Default::default()
        };
        // Client supports both h3 and wt → h3 preferred
        let caps = ClientCapabilities {
            h3: true,
            wt: true,
            ..Default::default()
        };
        let result = rewrite_url("https://dual.example.com/path", &config, None, &caps).unwrap();
        assert_eq!(result, "http3://dual.example.com/path");
    }

    #[test]
    fn test_rewrite_dual_h3_wt_fallback_to_wt() {
        let config = ServerConfig {
            id: "test".into(),
            url: "https://dual.example.com".into(),
            r#type: "dfs_webtransport".into(),
            h3_only: true,
            ..Default::default()
        };
        // Client supports only wt → wt used
        let caps = ClientCapabilities {
            h3: false,
            wt: true,
            ..Default::default()
        };
        let result = rewrite_url("https://dual.example.com/path", &config, None, &caps).unwrap();
        assert_eq!(result, "h3wt://dual.example.com/path");
    }
}
