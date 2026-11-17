use anyhow::Result;

use crate::modules::server::dfs_node::DfsNodeSigner;

/// DFS WebTransport backend signer that reuses dfs_node's HMAC-SHA256 signing
/// but outputs h3wt:// protocol URLs and uses HTTP/3 QUIC probes for health checks.
#[derive(Clone, Debug)]
pub struct DfsWtSigner {
    /// Reuse dfs_node's signing logic
    inner: DfsNodeSigner,
}

impl DfsWtSigner {
    pub fn from_url(url_str: &str) -> Result<Self> {
        Ok(Self {
            inner: DfsNodeSigner::from_url(url_str)?,
        })
    }

    /// Generate a signed HTTP URL for health check probing.
    ///
    /// This produces a standard http(s) URL with dfs_node signature (`?$=...`)
    /// that can be used with HTTP/3 QUIC probe for health checks.
    #[allow(dead_code)]
    pub fn generate_probe_url_http(&self, path: &str, uuid: &str) -> String {
        // Health check probe: no ranges needed
        self.inner.generate_signed_url(path, uuid, None, None)
    }

    /// Generate a presigned URL for client download.
    ///
    /// Uses dfs_node's HMAC-SHA256 signing. The scheme rewrite to h3wt://
    /// and cert fragment appending is handled by `capabilities::rewrite_url()`.
    pub fn generate_presigned_url(
        &self,
        path: &str,
        uuid: &str,
        ranges: Option<Vec<(u32, u32)>>,
    ) -> Result<String> {
        Ok(self
            .inner
            .generate_presigned_url_expiring(path, uuid, ranges.as_deref(), None))
    }

    pub fn generate_presigned_url_expiring(
        &self,
        path: &str,
        uuid: &str,
        ranges: Option<&[(u32, u32)]>,
        expire_seconds: Option<u32>,
    ) -> String {
        self.inner
            .generate_presigned_url_expiring(path, uuid, ranges, expire_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_url() {
        let url = "http://example.com:secret_token@dfs.example.com:8080/path?expire_seconds=7200";
        let signer = DfsWtSigner::from_url(url).unwrap();
        // Verify it can generate URLs
        let probe_url =
            signer.generate_probe_url_http("/test.txt", "00000000000000000000000000000000");
        assert!(probe_url.contains("/test.txt?$="));

        let signed_url = signer
            .generate_presigned_url("/test.txt", "00000000000000000000000000000000", None)
            .unwrap();
        // URL is still http(s) — scheme rewrite is done externally by capabilities::rewrite_url
        assert!(signed_url.contains("/test.txt?$="));
    }
}
