use anyhow::Result;

use crate::modules::server::dfs_node::DfsNodeSigner;

/// DFS RTC backend signer that reuses dfs_node's HMAC-SHA256 signing
/// but outputs wrtc:// protocol URLs and uses WebDAV PROPFIND for health checks.
#[derive(Clone, Debug)]
pub struct DfsRtcSigner {
    /// Reuse dfs_node's signing logic
    inner: DfsNodeSigner,
}

impl DfsRtcSigner {
    pub fn from_url(url_str: &str) -> Result<Self> {
        Ok(Self {
            inner: DfsNodeSigner::from_url(url_str)?,
        })
    }

    /// Generate a signed HTTP URL for PROPFIND health check probing.
    ///
    /// This produces a standard http(s) URL with dfs_node signature (`?$=...`)
    /// that can be used with reqwest for PROPFIND requests.
    pub fn generate_probe_url_http(&self, path: &str, uuid: &str) -> String {
        // Health check probe: no ranges needed
        self.inner.generate_signed_url(path, uuid, None, None)
    }

    /// Generate a presigned URL with wrtc:// protocol for client download.
    ///
    /// Uses dfs_node's HMAC-SHA256 signing, then rewrites the scheme to wrtc://.
    pub fn generate_presigned_url_wrtc(
        &self,
        path: &str,
        uuid: &str,
        ranges: Option<Vec<(u32, u32)>>,
    ) -> Result<String> {
        let http_url = self.inner.generate_presigned_url(path, uuid, ranges)?;
        Ok(rewrite_to_wrtc_scheme(&http_url))
    }
}

/// Rewrite an http(s):// URL to wrtc:// protocol.
///
/// Both http:// and https:// are rewritten to wrtc:// (no wrtcs:// variant).
/// Non-http(s) URLs are returned unchanged.
fn rewrite_to_wrtc_scheme(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        return format!("wrtc://{rest}");
    }
    if let Some(rest) = url.strip_prefix("http://") {
        return format!("wrtc://{rest}");
    }
    // Non-http(s) URLs pass through unchanged (defensive)
    url.to_string()
}

/// Rewrite a URL to wrtc:// protocol (public, for flow_service URL rewrite).
pub fn rewrite_url_to_wrtc(url: &str) -> String {
    rewrite_to_wrtc_scheme(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_http_to_wrtc() {
        assert_eq!(
            rewrite_to_wrtc_scheme("http://example.com/path?$=sig"),
            "wrtc://example.com/path?$=sig"
        );
    }

    #[test]
    fn test_rewrite_https_to_wrtc() {
        assert_eq!(
            rewrite_to_wrtc_scheme("https://example.com:8080/path?$=sig"),
            "wrtc://example.com:8080/path?$=sig"
        );
    }

    #[test]
    fn test_rewrite_non_http_passthrough() {
        assert_eq!(
            rewrite_to_wrtc_scheme("wrtc://example.com/path"),
            "wrtc://example.com/path"
        );
    }

    #[test]
    fn test_from_url() {
        let url = "http://example.com:secret_token@dfs.example.com:8080/path?expire_seconds=7200";
        let signer = DfsRtcSigner::from_url(url).unwrap();
        // Verify it can generate URLs
        let probe_url =
            signer.generate_probe_url_http("/test.txt", "00000000000000000000000000000000");
        assert!(probe_url.contains("/test.txt?$="));

        let wrtc_url = signer
            .generate_presigned_url_wrtc("/test.txt", "00000000000000000000000000000000", None)
            .unwrap();
        assert!(wrtc_url.starts_with("wrtc://"));
        assert!(wrtc_url.contains("/test.txt?$="));
    }
}
