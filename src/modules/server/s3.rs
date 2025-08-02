use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
        let now = chrono::Utc::now();
        // yyyyMMdd
        let date_stamp = now.format("%Y%m%d").to_string();
        // X-Amz-Date must be in the ISO8601 Long Format "yyyyMMdd'T'HHmmss'Z'"
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
        query_params.insert("X-Amz-Credential".to_string(), cred.clone());
        query_params.insert("X-Amz-Date".to_string(), date.to_string());
        query_params.insert("X-Amz-Expires".to_string(), self.expires.to_string());

        let parsed_url = Url::parse(&self.endpoint)?;
        let mut host = parsed_url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid host in endpoint"))?
            .to_string();
        // append port
        if let Some(port) = parsed_url.port() {
            host.push_str(&format!(":{}", port));
        }

        let mut canonical_headers = String::from("host:");
        canonical_headers.push_str(&host);
        canonical_headers.push('\n');

        let mut signed_headers = vec!["host".to_string()];
        let mut header_values = BTreeMap::new();
        header_values.insert("host".to_string(), host.to_string());

        if let Some(custom_headers) = headers {
            for (key, value) in custom_headers {
                let header_key = key.to_lowercase();
                canonical_headers.push_str(&format!("{}:{}\n", &header_key, value));
                signed_headers.push(header_key.clone());
                header_values.insert(header_key, value);
            }
        }

        signed_headers.sort();
        let signed_headers_str = signed_headers.join(";");
        query_params.insert(
            "X-Amz-SignedHeaders".to_string(),
            signed_headers_str.clone(),
        );
        let key_without_first_slash = key.trim_start_matches('/');
        let canonical_uri = if self.path_mode {
            format!("/{}/{}", bucket, key_without_first_slash)
        } else {
            format!("/{}", key_without_first_slash)
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
            "GET\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
            canonical_uri, canonical_query_string, canonical_headers, signed_headers_str
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
        canonical_query_string.push_str(&format!("&X-Amz-Signature={}", signature));

        let endpoint_without_last_slash = self.endpoint.trim_end_matches('/').to_string();

        let mut url = Url::parse(&format!("{}{}", endpoint_without_last_slash, canonical_uri))?;
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
