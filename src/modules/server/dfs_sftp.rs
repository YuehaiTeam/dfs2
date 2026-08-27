use anyhow::Result;
use url::Url;

use crate::modules::network::capabilities::{format_host_for_url, percent_encode};
use crate::modules::server::dfs_node::DfsNodeSigner;

/// DFS SFTP backend signer.
///
/// Wraps a DfsNodeSigner for HMAC-SHA256 signing and generates `sftp://` URLs
/// directly (no scheme rewrite needed).
///
/// Config URL format:
///   `sftp://user:token@host:port/path_prefix?expire_seconds=N`
///
/// Generated download URL format:
///   `sftp://host:port/prefix/path#user={hex(path)}&pass={sig}&fingerprint={fp}`
#[derive(Clone, Debug)]
pub struct DfsSftpSigner {
    /// Reuse dfs_node's HMAC-SHA256 signing logic
    inner: DfsNodeSigner,
    /// SFTP host (parsed from sftp:// URL)
    sftp_host: String,
    /// SFTP port (parsed from sftp:// URL, default 22)
    sftp_port: u16,
    /// Path prefix on the SFTP server
    path_prefix: String,
    /// SSH host key fingerprint (SHA-256, 64 hex lowercase)
    fingerprint: String,
}

impl DfsSftpSigner {
    /// Parse an `sftp://user:token@host:port/path_prefix?expire_seconds=N` URL.
    ///
    /// The `user` field is used for display/reference only; actual SSH user is
    /// derived at signing time (hex-encoded path for dfs_node auth).
    /// The `token` (password) field is the HMAC signing secret.
    pub fn from_url(url_str: &str, fingerprint: &str) -> Result<Self> {
        let url = Url::parse(url_str)?;
        anyhow::ensure!(
            url.scheme() == "sftp",
            "DfsSftpSigner requires sftp:// URL, got '{}'",
            url.scheme()
        );

        let sftp_host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("sftp URL missing host"))?
            .to_string();
        let sftp_port = url.port().unwrap_or(22);

        let path_prefix = url.path().trim_end_matches('/').to_string();

        // Build a fake http:// URL for DfsNodeSigner::from_url
        // DfsNodeSigner expects: http://user:token@host:port/path?expire_seconds=N
        let signature_token = url.password().map(|p| p.to_string());
        let mut expire_seconds = 3600u32;
        for (key, value) in url.query_pairs() {
            if key.as_ref() == "expire_seconds" {
                expire_seconds = value.parse().unwrap_or(3600);
            }
        }

        // DfsNodeSigner base_url is just a prefix; for sftp signer we don't use it
        // for URL output, but we need it for signing. Use a placeholder http URL.
        let inner = DfsNodeSigner::new(
            format!("http://{sftp_host}:{sftp_port}{path_prefix}"),
            signature_token,
            expire_seconds,
        );

        let fp_norm = fingerprint
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_ascii_lowercase();

        Ok(Self {
            inner,
            sftp_host,
            sftp_port,
            path_prefix,
            fingerprint: fp_norm,
        })
    }

    /// Generate a signed sftp:// URL for client download.
    ///
    /// Output format:
    ///   `sftp://host:port/prefix/path#user={hex(path)}&pass={sig}&fingerprint={fp}`
    pub fn generate_presigned_url(
        &self,
        path: &str,
        uuid: &str,
        ranges: Option<Vec<(u32, u32)>>,
    ) -> Result<String> {
        let full_path = format!("{}{}", self.path_prefix, path);

        // Generate the DFS signature using the inner signer
        let ranges_slice = ranges.as_deref();
        let signed_url = self
            .inner
            .generate_signed_url(path, uuid, None, ranges_slice);

        // Extract signature from ?$= parameter
        let sig = if let Some(sig_start) = signed_url.find("?$=") {
            &signed_url[sig_start + 3..]
        } else {
            ""
        };

        // user = hex-encoded path (same as ssh_only dfs_node auth)
        let ssh_user = hex::encode(path.as_bytes());

        // Build the sftp URL with credentials in fragment
        let fragment = format!(
            "user={}&pass={}&fingerprint={}",
            percent_encode(&ssh_user),
            percent_encode(sig),
            self.fingerprint,
        );

        let host_str = format_host_for_url(&self.sftp_host);
        Ok(format!(
            "sftp://{}:{}{full_path}#{fragment}",
            host_str, self.sftp_port
        ))
    }

    /// Generate a probe URL for health checking.
    ///
    /// Returns an sftp:// URL that can be used with FETCH_CLIENT
    /// (which has SftpMiddleware mounted).
    #[allow(dead_code)]
    pub fn generate_probe_url(&self, path: &str, uuid: &str) -> String {
        // For health check, generate a signed sftp URL
        self.generate_presigned_url(path, uuid, None)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_url() {
        let url = "sftp://example.com:secret_token@sftp.example.com:2222/data?expire_seconds=7200";
        let fp = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let signer = DfsSftpSigner::from_url(url, fp).unwrap();

        assert_eq!(signer.sftp_host, "sftp.example.com");
        assert_eq!(signer.sftp_port, 2222);
        assert_eq!(signer.path_prefix, "/data");
        assert_eq!(signer.fingerprint, fp);
    }

    #[test]
    fn test_generate_presigned_url() {
        let url = "sftp://user:secret@sftp.example.com:22/data?expire_seconds=3600";
        let fp = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let signer = DfsSftpSigner::from_url(url, fp).unwrap();

        let result = signer
            .generate_presigned_url("/test.txt", "00000000000000000000000000000000", None)
            .unwrap();

        // Should be sftp:// URL with host:port, path, and fragment
        assert!(result.starts_with("sftp://sftp.example.com:22/data/test.txt#"));
        assert!(result.contains("user="));
        assert!(result.contains("pass="));
        assert!(result.contains("fingerprint="));
    }
}
