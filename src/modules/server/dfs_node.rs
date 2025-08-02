use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;
use url::Url;

#[derive(Clone, Debug)]
pub struct DfsNodeSigner {
    /// The base URL of the DFS node
    base_url: String,
    /// Optional signing token for authenticated requests
    signature_token: Option<String>,
    /// Default expiration time in seconds
    expire_seconds: u32,
}

impl DfsNodeSigner {
    pub fn new(base_url: String, signature_token: Option<String>, expire_seconds: u32) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            signature_token,
            expire_seconds,
        }
    }

    /// Create a signature string for a given path, expiration time and optional ranges
    ///
    /// # Arguments
    /// * uuid - The UUID string to include in the signature
    /// * path - The file path to sign
    /// * expire_time - Unix timestamp when the signature expires
    /// * sign_token - The signing key
    /// * ranges - Optional list of (start, end) byte ranges
    ///
    /// # Returns
    /// Returns a signature string in the format: {uuid}{expire_time}{hmac}{ranges...}
    pub fn create_signature(
        uuid: &str,
        path: &str,
        expire_time: u32,
        sign_token: &str,
        ranges: Option<&[(u32, u32)]>,
    ) -> String {
        // Build HMAC message: {uuid}\n/path/to/file\n{4byte hex unix过期时间}\n{ranges...}
        let mut message = format!("{}\n{}\n{:08x}\n", uuid, path, expire_time);

        // Add ranges if provided
        if let Some(ranges) = ranges {
            for (start, end) in ranges {
                message.push_str(&format!("{}-{}\n", start, end));
            }
        }

        // Create HMAC-SHA256 signature
        let mac = Hmac::<Sha256>::new_from_slice(sign_token.as_bytes());
        let mut mac = match mac {
            Ok(mac) => mac,
            Err(e) => {
                error!("Failed to create HMAC: {}", e);
                return format!("error_hmac_creation");
            }
        };
        mac.update(message.as_bytes());
        let result = mac.finalize();
        let hmac_bytes = result.into_bytes();

        // Convert to hex string
        let hmac_hex = hex::encode(hmac_bytes);

        // Build final signature: {uuid}{expire_time}{hmac}{ranges...}
        let mut signature = format!("{}{:08x}{}", uuid, expire_time, hmac_hex);

        // Append ranges to signature
        if let Some(ranges) = ranges {
            for (start, end) in ranges {
                signature.push_str(&format!("{}-{}", start, end));
            }
        }

        signature
    }

    fn get_expire_time(&self, expire_seconds: u32) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                error!("System time error: {}", e);
                e
            })
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs() as u32;
        now + expire_seconds
    }

    pub fn generate_signed_url(
        &self,
        path: &str,
        uuid: &str,
        request_expire_time: Option<u32>,
        ranges: Option<&[(u32, u32)]>,
    ) -> String {
        match &self.signature_token {
            Some(token) => {
                // Use the passed expire time if available, otherwise calculate new one
                let expire_time = request_expire_time
                    .unwrap_or_else(|| self.get_expire_time(self.expire_seconds));

                let signature = Self::create_signature(uuid, path, expire_time, token, ranges);
                format!("{}{}?$={}", self.base_url, path, signature)
            }
            None => format!("{}{}", self.base_url, path),
        }
    }

    /// Generate a presigned URL for accessing a file with multiple ranges
    ///
    /// # Arguments
    /// * path - The file path to access
    /// * uuid - The UUID (session ID) to use for signing
    /// * ranges - Optional vector of (start, end) byte ranges
    ///
    /// # Returns
    /// Returns a signed URL string
    pub fn generate_presigned_url(
        &self,
        path: &str,
        uuid: &str,
        ranges: Option<Vec<(u32, u32)>>,
    ) -> Result<String> {
        let ranges_slice = ranges.as_ref().map(|v| v.as_slice());
        let url = self.generate_signed_url(path, uuid, None, ranges_slice);
        Ok(url)
    }

    pub fn from_url(url_str: &str) -> Result<Self> {
        let url = Url::parse(url_str)?;

        // Extract signature token from password field (if present)
        let signature_token = url.password().map(|p| p.to_string());

        // Parse query parameters
        let mut expire_seconds = 3600; // Default 1 hour

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "expire_seconds" => {
                    expire_seconds = value.parse().unwrap_or(3600);
                }
                _ => {}
            }
        }

        // Build base URL without credentials and query parameters
        let mut base_url = url.clone();
        base_url.set_username("").ok();
        base_url.set_password(None).ok();
        base_url.set_query(None);

        Ok(Self::new(
            base_url.to_string(),
            signature_token,
            expire_seconds,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_signature() {
        let uuid = "12345678901234567890123456789012";
        let path = "/test/file.txt";
        let expire_time = 0x12345678;
        let sign_token = "test_token";

        let signature = DfsNodeSigner::create_signature(uuid, path, expire_time, sign_token, None);

        // The signature should start with uuid + expire_time
        assert!(signature.starts_with("1234567890123456789012345678901212345678"));
    }

    #[test]
    fn test_create_signature_with_ranges() {
        let uuid = "12345678901234567890123456789012";
        let path = "/test/file.txt";
        let expire_time = 0x12345678;
        let sign_token = "test_token";
        let ranges = vec![(0, 255), (256, 511)];

        let signature =
            DfsNodeSigner::create_signature(uuid, path, expire_time, sign_token, Some(&ranges));

        // The signature should end with the ranges
        assert!(signature.ends_with("0-255256-511"));
    }

    #[test]
    fn test_from_url() {
        let url = "http://example.com:secret_token@dfs.example.com:8080/path?expire_seconds=7200";
        let signer = DfsNodeSigner::from_url(url).unwrap();

        assert_eq!(signer.base_url, "http://dfs.example.com:8080/path");
        assert_eq!(signer.signature_token, Some("secret_token".to_string()));
        assert_eq!(signer.expire_seconds, 7200);
    }
}
