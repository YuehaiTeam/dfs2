//! WebDAV PROPFIND probe for health checking dfs_rtc backends.
//!
//! Uses PROPFIND method with Depth:0 to check server availability and
//! extract file size from the `getcontentlength` property in the response.

use regex::Regex;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::warn;

/// Result of a WebDAV PROPFIND health check probe.
#[derive(Debug, Clone)]
pub struct WebDavProbeResult {
    pub is_alive: bool,
    pub file_size: Option<u64>,
}

/// Get the compiled regex for extracting getcontentlength from WebDAV XML response.
///
/// Matches both namespaced and non-namespaced forms:
/// - `<D:getcontentlength>123</D:getcontentlength>`
/// - `<getcontentlength>123</getcontentlength>`
/// - `<d:getcontentlength>123</d:getcontentlength>`
fn get_content_length_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?is)<(?:\w+:)?getcontentlength>\s*(\d+)\s*</")
            .expect("Invalid getcontentlength regex pattern")
    })
}

/// Extract file size from WebDAV PROPFIND XML response body.
fn extract_file_size_from_propfind(body: &str) -> Option<u64> {
    get_content_length_regex()
        .captures(body)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse::<u64>().ok())
}

/// Perform a WebDAV PROPFIND probe against a signed URL.
///
/// The URL should already include the dfs_node signature query parameter (`?$=...`).
/// Returns `WebDavProbeResult` with alive status and optional file size.
///
/// # Arguments
///
/// * `signed_url` - The fully signed URL to probe (with `?$=` signature)
/// * `timeout_secs` - Timeout in seconds for the probe request
pub async fn probe_propfind(signed_url: &str, timeout_secs: u64) -> WebDavProbeResult {
    let method = match reqwest::Method::from_bytes(b"PROPFIND") {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to create PROPFIND method: {:?}", e);
            return WebDavProbeResult {
                is_alive: false,
                file_size: None,
            };
        }
    };

    let propfind_body = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:getcontentlength/>
  </D:prop>
</D:propfind>"#;

    let resp = crate::container::REQWEST_CLIENT
        .request(method, signed_url)
        .header("Depth", "0")
        .header("Content-Type", "application/xml; charset=utf-8")
        .timeout(Duration::from_secs(timeout_secs))
        .body(propfind_body)
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!("WebDAV PROPFIND request failed for {}: {:?}", signed_url, e);
            return WebDavProbeResult {
                is_alive: false,
                file_size: None,
            };
        }
    };

    // 207 Multi-Status is the standard WebDAV success response,
    // but any 2xx is acceptable
    let is_alive = resp.status().is_success();

    if !is_alive {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        warn!(
            "WebDAV PROPFIND check failed for {}: status {} / {}",
            signed_url, status, body
        );
        return WebDavProbeResult {
            is_alive: false,
            file_size: None,
        };
    }

    let body = resp.text().await.unwrap_or_default();
    let file_size = extract_file_size_from_propfind(&body);

    WebDavProbeResult {
        is_alive: true,
        file_size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_file_size_standard() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/path/to/file.txt</D:href>
    <D:propstat>
      <D:prop>
        <D:getcontentlength>1048576</D:getcontentlength>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        assert_eq!(extract_file_size_from_propfind(xml), Some(1048576));
    }

    #[test]
    fn test_extract_file_size_lowercase_namespace() {
        let xml = r#"<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:propstat>
      <d:prop>
        <d:getcontentlength>2048</d:getcontentlength>
      </d:prop>
    </d:propstat>
  </d:response>
</d:multistatus>"#;
        assert_eq!(extract_file_size_from_propfind(xml), Some(2048));
    }

    #[test]
    fn test_extract_file_size_no_namespace() {
        let xml = r#"<multistatus>
  <response>
    <propstat>
      <prop>
        <getcontentlength>512</getcontentlength>
      </prop>
    </propstat>
  </response>
</multistatus>"#;
        assert_eq!(extract_file_size_from_propfind(xml), Some(512));
    }

    #[test]
    fn test_extract_file_size_with_whitespace() {
        let xml = r#"<D:prop><D:getcontentlength>
          99999
        </D:getcontentlength></D:prop>"#;
        assert_eq!(extract_file_size_from_propfind(xml), Some(99999));
    }

    #[test]
    fn test_extract_file_size_missing() {
        let xml = r#"<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:propstat>
      <D:prop/>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        assert_eq!(extract_file_size_from_propfind(xml), None);
    }

    #[test]
    fn test_extract_file_size_empty_body() {
        assert_eq!(extract_file_size_from_propfind(""), None);
    }

    #[test]
    fn test_extract_file_size_zero() {
        let xml = "<D:getcontentlength>0</D:getcontentlength>";
        assert_eq!(extract_file_size_from_propfind(xml), Some(0));
    }
}
