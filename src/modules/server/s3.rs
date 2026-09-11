use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::error;
use url::Url;

#[derive(Clone, Debug)]
pub struct S3Signer {
    access_key: String,
    secret_key: String,
    region: String,
    service: String,
    endpoint: String,
    path_mode: bool,
    bucket: String,
    expires: u32,
}

impl S3Signer {
    pub fn new(
        access_key: String,
        secret_key: String,
        region: String,
        bucket: String,
        endpoint: String,
        path_mode: bool,
        expires: u32,
    ) -> Self {
        Self {
            access_key,
            secret_key,
            region,
            bucket,
            service: "s3".to_string(),
            endpoint,
            path_mode,
            expires,
        }
    }

    pub fn generate_presigned_url(
        &self,
        key: &str,
        headers: Option<BTreeMap<String, String>>,
    ) -> Result<String> {
        self.presign("GET", key, headers, chrono::Utc::now(), self.expires)
    }

    /// Presigned PUT. `UNSIGNED-PAYLOAD` matches the existing GET signer.
    pub fn generate_presigned_put_url(&self, key: &str) -> Result<String> {
        self.presign_put_at(key, chrono::Utc::now())
    }

    fn presign_put_at(&self, key: &str, now: chrono::DateTime<chrono::Utc>) -> Result<String> {
        let mut headers = BTreeMap::new();
        headers.insert(
            "x-amz-content-sha256".to_string(),
            "UNSIGNED-PAYLOAD".to_string(),
        );
        self.presign("PUT", key, Some(headers), now, 3600)
    }

    /// Upload `body` with a presigned PUT. Errors do not include the signed URL.
    pub async fn put_object(&self, key: &str, body: &[u8]) -> Result<()> {
        let url = self.generate_presigned_put_url(key)?;
        let response = put_client()
            .put(url)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header(reqwest::header::CONTENT_LENGTH, body.len())
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("S3 PUT transport failed: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!("S3 PUT failed: {status}"));
        }
        Ok(())
    }

    fn presign(
        &self,
        method: &str,
        key: &str,
        headers: Option<BTreeMap<String, String>>,
        now: chrono::DateTime<chrono::Utc>,
        expires: u32,
    ) -> Result<String> {
        let date_stamp = now.format("%Y%m%d").to_string();
        let date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let bucket = &self.bucket;

        let mut query_params = BTreeMap::new();
        query_params.insert(
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        );
        let cred = format!(
            "{}/{}/{}/{}/aws4_request",
            self.access_key, date_stamp, self.region, self.service
        );
        query_params.insert("X-Amz-Credential".to_string(), cred);
        query_params.insert("X-Amz-Date".to_string(), date.to_string());
        query_params.insert("X-Amz-Expires".to_string(), expires.to_string());

        let parsed_url = Url::parse(&self.endpoint)?;
        let mut host = parsed_url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid host in endpoint"))?
            .to_string();
        if let Some(port) = parsed_url.port() {
            host.push_str(&format!(":{port}"));
        }

        let mut header_values = BTreeMap::new();
        header_values.insert("host".to_string(), host.clone());

        if let Some(custom_headers) = headers {
            for (key, value) in custom_headers {
                header_values.insert(key.to_lowercase(), value);
            }
        }

        let mut signed_headers: Vec<String> = header_values.keys().cloned().collect();
        signed_headers.sort();
        let signed_headers_str = signed_headers.join(";");

        let mut canonical_headers = String::new();
        for name in &signed_headers {
            canonical_headers.push_str(name);
            canonical_headers.push(':');
            canonical_headers.push_str(&header_values[name]);
            canonical_headers.push('\n');
        }

        query_params.insert(
            "X-Amz-SignedHeaders".to_string(),
            signed_headers_str.clone(),
        );
        let key_without_first_slash = key.trim_start_matches('/');
        let canonical_uri = if self.path_mode {
            format!("/{bucket}/{key_without_first_slash}")
        } else {
            format!("/{key_without_first_slash}")
        };

        let mut canonical_query_string = String::new();
        for (key, value) in &query_params {
            if !canonical_query_string.is_empty() {
                canonical_query_string.push('&');
            }
            canonical_query_string.push_str(&format!(
                "{}={}",
                urlencoding::encode(key),
                urlencoding::encode(value)
            ));
        }

        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers_str}\nUNSIGNED-PAYLOAD"
        );

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}/{}/{}/aws4_request\n{}",
            date,
            date_stamp,
            self.region,
            self.service,
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let k_date = self.sign(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = self.sign(&k_date, self.region.as_bytes());
        let k_service = self.sign(&k_region, self.service.as_bytes());
        let signing_key = self.sign(&k_service, b"aws4_request");

        let signature = hex::encode(self.sign(&signing_key, string_to_sign.as_bytes()));
        canonical_query_string.push_str(&format!("&X-Amz-Signature={signature}"));

        let endpoint_without_last_slash = self.endpoint.trim_end_matches('/');
        let mut url = Url::parse(&format!("{endpoint_without_last_slash}{canonical_uri}"))?;
        url.set_query(Some(&canonical_query_string));

        Ok(url.to_string())
    }

    fn sign(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mac = Hmac::<Sha256>::new_from_slice(key);
        let mut mac = match mac {
            Ok(mac) => mac,
            Err(e) => {
                error!("Failed to create HMAC for S3 signing: {}", e);
                return vec![]; // Return empty vec on error
            }
        };
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    // Getter methods for Prometheus configuration generation
    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn from_url(url_str: &str) -> Result<Self> {
        let url = Url::parse(url_str)?;

        // 获取认证信息
        let access_key = url.username().to_string();
        if access_key.is_empty() {
            return Err(anyhow::anyhow!("Missing access_key in {}", url_str));
        }
        let secret_key = url
            .password()
            .ok_or_else(|| anyhow::anyhow!("Missing secret_key in {}", url_str))?
            .to_string();

        // 解析查询参数
        let mut region = String::new();
        let mut bucket = String::new();
        let mut path_mode = false;
        let mut expires: u32 = 600;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "region" => region = value.to_string(),
                "bucket" => bucket = value.to_string(),
                "path_mode" => path_mode = value.parse().unwrap_or(false),
                "expires" => expires = value.parse().unwrap_or(600),
                _ => {}
            }
        }

        if region.is_empty() {
            return Err(anyhow::anyhow!("Missing region parameter in URL"));
        }

        // 构建endpoint
        let mut endpoint_url = url.clone();
        endpoint_url.set_username("").ok();
        endpoint_url.set_password(None).ok();
        endpoint_url.set_query(None);
        let endpoint = endpoint_url.to_string();

        // 移除末尾的斜杠
        let endpoint = endpoint.trim_end_matches('/').to_string();

        Ok(Self::new(
            access_key, secret_key, region, bucket, endpoint, path_mode, expires,
        ))
    }
}

fn put_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent("DFS2-SessionLog/1.0")
            .timeout(Duration::from_secs(300))
            .build()
            .expect("session log S3 PUT client")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn test_signer() -> S3Signer {
        S3Signer::new(
            "AKIDEXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            "us-east-1".to_string(),
            "archive".to_string(),
            "https://s3.example.com".to_string(),
            true,
            600,
        )
    }

    #[test]
    fn presigned_put_is_put_with_unsigned_payload_and_stable_signature() {
        let now = chrono::Utc
            .with_ymd_and_hms(2026, 9, 11, 1, 2, 3)
            .single()
            .expect("fixed timestamp");
        let url = test_signer()
            .presign_put_at("sessions.2026-09-11.log.zst", now)
            .unwrap();

        assert!(url.starts_with("https://s3.example.com/archive/sessions.2026-09-11.log.zst?"));
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains("X-Amz-SignedHeaders=host%3Bx-amz-content-sha256"));
        assert!(url.contains("X-Amz-Expires=3600"));
        assert!(url.contains("X-Amz-Signature="));
        assert_eq!(
            url,
            test_signer()
                .presign_put_at("sessions.2026-09-11.log.zst", now)
                .unwrap()
        );
    }

    #[test]
    fn put_object_error_omits_url() {
        let err = anyhow::anyhow!("S3 PUT failed: 403 Forbidden");
        let msg = err.to_string();
        assert!(!msg.contains("X-Amz-"));
        assert!(!msg.contains("s3.example.com"));
    }
}
