use std::collections::BTreeMap;

use crate::config::ServerConfig;

pub mod s3;
pub mod dfs_node;

#[derive(Clone, Debug)]
pub enum ServerImpl {
    Direct(String),
    S3(s3::S3Signer),
    DfsNode(dfs_node::DfsNodeSigner),
}

impl ServerImpl {
    pub fn new(config: &ServerConfig) -> anyhow::Result<Self> {
        match config.r#type.as_str() {
            "s3" => {
                let signer = s3::S3Signer::from_url(&config.url)?;
                Ok(ServerImpl::S3(signer))
            }
            "dfs_node" => {
                let signer = dfs_node::DfsNodeSigner::from_url(&config.url)?;
                Ok(ServerImpl::DfsNode(signer))
            }
            "direct" => Ok(ServerImpl::Direct(config.url.clone())),
            _ => Err(anyhow::anyhow!(
                "Unsupported server type: {}",
                config.r#type
            )),
        }
    }
    pub fn url(&self, path: &str, ranges: Option<Vec<(u32, u32)>>, session_id: Option<&str>) -> anyhow::Result<String> {
        match self {
            ServerImpl::Direct(url) => Ok(format!(
                "{}{}",
                url,
                path.strip_prefix('/').unwrap_or(path).replace('\\', "/")
            )),
            ServerImpl::S3(signer) => {
                let mut headers = BTreeMap::new();
                if let Some(ranges_vec) = ranges {
                    if !ranges_vec.is_empty() {
                        // S3 supports multiple ranges in a single Range header
                        let range_specs: Vec<String> = ranges_vec
                            .iter()
                            .map(|(start, end)| format!("{}-{}", start, end))
                            .collect();
                        let range_header = format!("bytes={}", range_specs.join(","));
                        headers.insert("range".to_string(), range_header);
                    }
                }
                signer.generate_presigned_url(path, Some(headers))
            }
            ServerImpl::DfsNode(signer) => {
                let session_id = session_id.unwrap_or("00000000000000000000000000000000");
                signer.generate_presigned_url(path, session_id, ranges)
            }
        }
    }
    
    pub async fn is_alive(&self, path: &str) -> bool {
        let check_url = self.url(path, Some(vec![(0, 255)]), None);
        if check_url.is_err() {
            println!("Keepalive Error: {} {:?}", path, check_url);
            return false;
        }
        let check_url = check_url.unwrap();
        let ret = crate::app_state::REQWEST_CLIENT
            .get(check_url.clone())
            .header("range", "bytes=0-255")
            .send()
            .await;
        if ret.is_err() {
            println!("Keepalive Error: {} {:?}", check_url, ret);
            return false;
        }
        let ret = ret.unwrap();
        if ret.status().is_success() {
            return true;
        }
        false
    }
}
