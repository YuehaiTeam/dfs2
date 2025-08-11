use anyhow::Result;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use url::Url;

use super::super::{PrometheusJob, RelabelConfig, StaticConfig};
use crate::config::ServerConfig;
use crate::modules::server::s3::S3Signer;

#[derive(Debug, Serialize, Deserialize)]
struct MinioJwtClaims {
    sub: String,
    iss: String,
}

fn generate_minio_jwt(access_key: &str, secret_key: &str) -> Result<String> {
    let claims = MinioJwtClaims {
        sub: access_key.to_string(),
        iss: "prometheus".to_string(),
    };

    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(secret_key.as_bytes());

    encode(&header, &claims, &encoding_key)
        .map_err(|e| anyhow::anyhow!("Failed to generate JWT: {}", e))
}

fn extract_target_from_endpoint(endpoint: &str) -> Result<String> {
    let parsed_url = Url::parse(endpoint)?;
    let host = parsed_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid host in endpoint"))?;

    match parsed_url.port() {
        Some(port) => Ok(format!("{}:{}", host, port)),
        None => Ok(host.to_string()), // 不强制添加默认端口，让Prometheus处理
    }
}

pub fn generate_minio_job(server_id: &str, server_config: &ServerConfig) -> Result<PrometheusJob> {
    // 确保这是S3类型的服务器
    if server_config.r#type != "s3" {
        return Err(anyhow::anyhow!("Server {} is not S3 type", server_id));
    }

    // 使用现有的S3Signer解析URL获取认证信息
    let s3_signer = S3Signer::from_url(&server_config.url)?;

    // 生成JWT token
    let jwt_token = generate_minio_jwt(s3_signer.access_key(), s3_signer.secret_key())?;

    // 提取target地址
    let target = extract_target_from_endpoint(s3_signer.endpoint())?;

    // 获取bucket名称
    let bucket = s3_signer.bucket();

    // 构建MinIO Prometheus job配置
    let job = PrometheusJob {
        job_name: format!("minio-{}", server_id),
        bearer_token: Some(jwt_token),
        metrics_path: Some(format!("/minio/metrics/v3/bucket/api/{}", bucket)),
        scheme: Some("http".to_string()), // 默认HTTP，可根据URL scheme调整
        static_configs: vec![StaticConfig {
            targets: vec![target],
        }],
        relabel_configs: Some(vec![
            RelabelConfig {
                target_label: "instance".to_string(),
                replacement: server_id.to_string(),
            },
            RelabelConfig {
                target_label: "server".to_string(),
                replacement: server_id.to_string(),
            },
        ]),
    };

    Ok(job)
}
