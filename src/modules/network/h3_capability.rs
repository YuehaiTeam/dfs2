//! HTTP/3 capability detection based on request overrides and User-Agent analysis.
//!
//! This module provides functionality to detect whether a client supports HTTP/3
//! based on:
//! 1. X-DFS-Override header (explicit override)
//! 2. User-Agent string analysis (browser capability detection)

use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Request override parameters from X-DFS-Override header.
///
/// This struct parses querystring-formatted override values like `h3=1&other=value`.
/// The `h3` field controls HTTP/3 capability:
/// - `Some(0)` = force disable HTTP/3
/// - `Some(1)` = force enable HTTP/3
/// - `None` = no override, use auto-detection
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RequestOverride {
    /// HTTP/3 override: 0 = force disable, 1 = force enable
    pub h3: Option<u8>,

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

/// Get the compiled regex for Chrome version detection.
///
/// Matches both:
/// - `Chrome/<major>.<minor>.<patch>.<build>` (desktop Chrome)
/// - `CriOS/<major>.<minor>.<patch>.<build>` (Chrome on iOS)
fn get_chrome_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?:Chrome|CriOS)/(\d+)").expect("Invalid Chrome regex pattern")
    })
}

/// Compute whether the client is capable of HTTP/3.
///
/// This function checks override header first, then falls back to User-Agent analysis:
///
/// 1. If `X-DFS-Override` header has `h3=0` → return `false`
/// 2. If `X-DFS-Override` header has `h3=1` → return `true`
/// 3. If User-Agent contains `h3/enabled` → return `true`
/// 4. Parse Chrome major version from UA (handle both `Chrome/<n>` and `CriOS/<n>` for iOS)
///    - Return `true` if major version > 100
/// 5. Otherwise return `false`
///
/// # Arguments
///
/// * `override_header` - Optional value of X-DFS-Override header
/// * `user_agent` - Optional User-Agent string
///
/// # Examples
///
/// ```
/// use dfs2::modules::network::h3_capability::compute_h3_capable;
///
/// // Override header takes precedence
/// assert_eq!(compute_h3_capable(Some("h3=1"), Some("Firefox/100")), true);
/// assert_eq!(compute_h3_capable(Some("h3=0"), Some("Chrome/120")), false);
///
/// // Chrome version detection
/// assert_eq!(compute_h3_capable(None, Some("Chrome/101")), true);
/// assert_eq!(compute_h3_capable(None, Some("Chrome/100")), false);
///
/// // h3/enabled marker
/// assert_eq!(compute_h3_capable(None, Some("MyApp/1.0 h3/enabled")), true);
/// ```
pub fn compute_h3_capable(override_header: Option<&str>, user_agent: Option<&str>) -> bool {
    // Step 1 & 2: Check override header first
    if let Some(header) = override_header
        && let Some(override_config) = RequestOverride::parse(header)
    {
        match override_config.h3 {
            Some(0) => return false,
            Some(1) => return true,
            _ => {} // Continue to UA analysis
        }
        // If parsing fails, continue to UA analysis (don't fail open or closed)
    }

    // Step 3-5: User-Agent analysis
    let ua = match user_agent {
        Some(ua) if !ua.is_empty() => ua,
        _ => return false,
    };

    // Step 3: Check for h3/enabled marker
    if ua.contains("h3/enabled") {
        return true;
    }

    // Step 4: Parse Chrome version
    if let Some(caps) = get_chrome_regex().captures(ua)
        && let Some(major_match) = caps.get(1)
        && let Ok(major_version) = major_match.as_str().parse::<u32>()
    {
        return major_version > 100;
    }

    // Step 5: Default to false
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== RequestOverride Parsing Tests =====

    #[test]
    fn test_parse_override_h3_only() {
        let parsed = RequestOverride::parse("h3=1").unwrap();
        assert_eq!(parsed.h3, Some(1));
        assert!(parsed.extra.is_empty());
    }

    #[test]
    fn test_parse_override_h3_disable() {
        let parsed = RequestOverride::parse("h3=0").unwrap();
        assert_eq!(parsed.h3, Some(0));
    }

    #[test]
    fn test_parse_override_with_extra_params() {
        let parsed = RequestOverride::parse("h3=1&a=1&b=2").unwrap();
        assert_eq!(parsed.h3, Some(1));
        assert_eq!(parsed.extra.get("a"), Some(&"1".to_string()));
        assert_eq!(parsed.extra.get("b"), Some(&"2".to_string()));
    }

    #[test]
    fn test_parse_override_disable_with_extra() {
        let parsed = RequestOverride::parse("h3=0&foo=bar").unwrap();
        assert_eq!(parsed.h3, Some(0));
        assert_eq!(parsed.extra.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_parse_override_empty() {
        assert!(RequestOverride::parse("").is_none());
    }

    #[test]
    fn test_parse_override_malformed() {
        // serde_urlencoded is lenient - keys without values go to extra
        // Only truly invalid querystrings return None
        let parsed = RequestOverride::parse("h3=1&malformed").unwrap();
        assert_eq!(parsed.h3, Some(1));
        // "malformed" without = goes to extra as key with empty value
        assert_eq!(parsed.extra.get("malformed"), Some(&"".to_string()));
    }

    #[test]
    fn test_parse_override_no_h3() {
        let parsed = RequestOverride::parse("a=1&b=2").unwrap();
        assert_eq!(parsed.h3, None);
        assert_eq!(parsed.extra.get("a"), Some(&"1".to_string()));
    }

    // ===== h3_capable Override Tests =====

    #[test]
    fn test_h3_capable_override_enable() {
        assert_eq!(compute_h3_capable(Some("h3=1"), None), true);
        assert_eq!(compute_h3_capable(Some("h3=1"), Some("Firefox/100")), true);
        assert_eq!(compute_h3_capable(Some("h3=1"), Some("Chrome/50")), true);
    }

    #[test]
    fn test_h3_capable_override_disable() {
        assert_eq!(compute_h3_capable(Some("h3=0"), None), false);
        assert_eq!(compute_h3_capable(Some("h3=0"), Some("Chrome/120")), false);
        assert_eq!(compute_h3_capable(Some("h3=0"), Some("h3/enabled")), false);
    }

    #[test]
    fn test_h3_capable_override_enable_with_extra() {
        assert_eq!(
            compute_h3_capable(Some("h3=1&a=1"), Some("Firefox/100")),
            true
        );
        assert_eq!(
            compute_h3_capable(Some("h3=1&b=2"), Some("Chrome/50")),
            true
        );
    }

    #[test]
    fn test_h3_capable_override_disable_with_extra() {
        assert_eq!(
            compute_h3_capable(Some("h3=0&a=1"), Some("Chrome/120")),
            false
        );
        assert_eq!(
            compute_h3_capable(Some("h3=0&b=2"), Some("h3/enabled")),
            false
        );
    }

    #[test]
    fn test_h3_capable_malformed_override_ignored() {
        // "malformed" alone parses as key with no value in extra, h3=None
        // So it falls through to UA analysis
        assert_eq!(
            compute_h3_capable(Some("malformed"), Some("Chrome/120")),
            true
        );
        // "h3=1&malformed" parses successfully with h3=1
        assert_eq!(
            compute_h3_capable(Some("h3=1&malformed"), Some("Firefox/100")),
            true
        );
        // "h3=0&malformed" parses successfully with h3=0
        assert_eq!(
            compute_h3_capable(Some("h3=0&malformed"), Some("Chrome/120")),
            false
        );
    }

    // ===== Chrome Version Detection Tests =====

    #[test]
    fn test_h3_capable_chrome_101() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36";
        assert_eq!(compute_h3_capable(None, Some(ua)), true);
    }

    #[test]
    fn test_h3_capable_chrome_100() {
        // Edge case: exactly 100 should return false
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36";
        assert_eq!(compute_h3_capable(None, Some(ua)), false);
    }

    #[test]
    fn test_h3_capable_chrome_99() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36";
        assert_eq!(compute_h3_capable(None, Some(ua)), false);
    }

    #[test]
    fn test_h3_capable_chrome_120() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(compute_h3_capable(None, Some(ua)), true);
    }

    // ===== Chrome iOS (CriOS) Tests =====

    #[test]
    fn test_h3_capable_crios_105() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/105.0.0.0 Mobile/15E148 Safari/604.1";
        assert_eq!(compute_h3_capable(None, Some(ua)), true);
    }

    #[test]
    fn test_h3_capable_crios_100() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/100.0.0.0 Mobile/15E148 Safari/604.1";
        assert_eq!(compute_h3_capable(None, Some(ua)), false);
    }

    #[test]
    fn test_h3_capable_crios_99() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/99.0.0.0 Mobile/15E148 Safari/604.1";
        assert_eq!(compute_h3_capable(None, Some(ua)), false);
    }

    // ===== h3/enabled Marker Tests =====

    #[test]
    fn test_h3_capable_marker_enabled() {
        assert_eq!(compute_h3_capable(None, Some("MyApp/1.0 h3/enabled")), true);
        assert_eq!(compute_h3_capable(None, Some("h3/enabled")), true);
        assert_eq!(
            compute_h3_capable(None, Some("Mozilla/5.0 h3/enabled (Custom)")),
            true
        );
    }

    #[test]
    fn test_h3_capable_marker_not_present() {
        assert_eq!(compute_h3_capable(None, Some("MyApp/1.0")), false);
        assert_eq!(compute_h3_capable(None, Some("h3/disabled")), false);
        assert_eq!(compute_h3_capable(None, Some("h3/enable")), false); // partial match
    }

    // ===== Firefox/Other Browser Tests =====

    #[test]
    fn test_h3_capable_firefox() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0";
        assert_eq!(compute_h3_capable(None, Some(ua)), false);
    }

    #[test]
    fn test_h3_capable_safari() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        assert_eq!(compute_h3_capable(None, Some(ua)), false);
    }

    #[test]
    fn test_h3_capable_edge() {
        // Edge uses Chrome/ in its UA, so it should be detected
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.0 Edg/120.0.0.0";
        assert_eq!(compute_h3_capable(None, Some(ua)), true);
    }

    // ===== Missing/Empty Input Tests =====

    #[test]
    fn test_h3_capable_no_headers() {
        assert_eq!(compute_h3_capable(None, None), false);
        assert_eq!(compute_h3_capable(None, Some("")), false);
    }

    #[test]
    fn test_h3_capable_override_only() {
        assert_eq!(compute_h3_capable(Some("h3=1"), None), true);
        assert_eq!(compute_h3_capable(Some("h3=0"), None), false);
    }

    // ===== Override Precedence Tests =====

    #[test]
    fn test_override_precedence_over_ua() {
        // Override should take precedence over UA detection
        assert_eq!(compute_h3_capable(Some("h3=0"), Some("Chrome/120")), false);
        assert_eq!(compute_h3_capable(Some("h3=1"), Some("Firefox/100")), true);
        assert_eq!(compute_h3_capable(Some("h3=0"), Some("h3/enabled")), false);
    }

    // ===== Edge Cases =====

    #[test]
    fn test_h3_capable_chrome_version_edge_cases() {
        // Very high version
        let ua = "Mozilla/5.0 Chrome/999.0.0.0 Safari/537.36";
        assert_eq!(compute_h3_capable(None, Some(ua)), true);

        // Version 101 (threshold + 1)
        let ua = "Mozilla/5.0 Chrome/101.0.0.0 Safari/537.36";
        assert_eq!(compute_h3_capable(None, Some(ua)), true);

        // Version with only major
        let ua = "Mozilla/5.0 Chrome/101 Safari/537.36";
        assert_eq!(compute_h3_capable(None, Some(ua)), true);
    }

    #[test]
    fn test_h3_capable_invalid_version() {
        // Invalid version number should fall through to false
        let ua = "Mozilla/5.0 Chrome/abc.0.0.0 Safari/537.36";
        assert_eq!(compute_h3_capable(None, Some(ua)), false);
    }

    #[test]
    fn test_chrome_regex_multiple_matches() {
        // If multiple Chrome versions appear (unlikely but test anyway), first match wins
        let ua = "Mozilla/5.0 Chrome/50.0.0.0 Chrome/120.0.0.0 Safari/537.36";
        // The regex will match the first Chrome/50
        assert_eq!(compute_h3_capable(None, Some(ua)), false);
    }
}
