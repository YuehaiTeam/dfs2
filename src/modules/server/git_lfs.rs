use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, warn};
use url::Url;

#[derive(Clone, Debug)]
pub struct GitLfsSigner {
    repo_url: String,            // https://github.com/user/repo.git
    lfs_endpoint: String,        // https://github.com/user/repo.git/info/lfs
    raw_url_prefix: String,      // https://raw.githubusercontent.com/user/repo/branch/
    file_cache_ttl: u32,         // 文件→SHA256缓存时间
    url_cache_ttl: u32,          // SHA256→URL缓存时间
}

#[derive(Debug, Deserialize)]
struct LfsPointer {
    version: String,
    oid: String,      // sha256:hash格式
    size: u64,
}

#[derive(Serialize)]
struct LfsBatchRequest {
    operation: String,
    transfers: Vec<String>,
    objects: Vec<LfsObject>,
}

#[derive(Serialize, Deserialize)]
struct LfsObject {
    oid: String,
    size: u64,
}

#[derive(Deserialize)]
struct LfsBatchResponse {
    objects: Vec<LfsObjectResponse>,
}

#[derive(Deserialize)]
struct LfsObjectResponse {
    oid: String,
    size: u64,
    actions: Option<HashMap<String, LfsAction>>,
}

#[derive(Deserialize)]
struct LfsAction {
    href: String,
    expires_at: Option<String>,
}

impl GitLfsSigner {
    pub fn from_url(url_str: &str) -> Result<Self> {
        let url = Url::parse(url_str)?;
        
        // 主URL作为repo地址
        let repo_url = format!("{}://{}{}", 
            url.scheme(), 
            url.host_str().ok_or_else(|| anyhow::anyhow!("Invalid host in URL"))?, 
            url.path()
        );
        
        // 自动拼接LFS端点
        let lfs_endpoint = format!("{}/info/lfs", repo_url);
        
        // 解析查询参数
        let mut raw_url_prefix = String::new();
        let mut file_cache_ttl = 3600u32;
        let mut url_cache_ttl = 600u32;
        
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "raw" => raw_url_prefix = value.to_string(),
                "file_cache" => file_cache_ttl = value.parse().unwrap_or(3600),
                "url_cache" => url_cache_ttl = value.parse().unwrap_or(600),
                _ => {}
            }
        }
        
        if raw_url_prefix.is_empty() {
            return Err(anyhow::anyhow!("Missing 'raw' parameter in Git LFS URL"));
        }
        
        debug!("Created GitLfsSigner: repo={}, lfs={}, raw={}", 
               repo_url, lfs_endpoint, raw_url_prefix);
        
        Ok(Self {
            repo_url,
            lfs_endpoint,
            raw_url_prefix,
            file_cache_ttl,
            url_cache_ttl,
        })
    }
    
    pub async fn generate_url(
        &self, 
        path: &str, 
        data_store: &crate::data_store::DataStore
    ) -> Result<String> {
        let cache_key_file = format!("git_lfs_file:{}:{}", self.repo_url, path);
        
        // 第一步：尝试从缓存获取SHA256
        let (sha256, size) = if let Ok(Some(cached)) = data_store.get_string(&cache_key_file).await {
            let parts: Vec<&str> = cached.split(':').collect();
            if parts.len() == 2 {
                let sha256 = parts[0].to_string();
                let size = parts[1].parse().unwrap_or(0);
                debug!("Found cached file info: {} -> {}:{}", path, sha256, size);
                (sha256, size)
            } else {
                self.fetch_lfs_pointer_and_cache(path, &cache_key_file, data_store).await?
            }
        } else {
            self.fetch_lfs_pointer_and_cache(path, &cache_key_file, data_store).await?
        };
        
        // 第二步：获取下载URL
        let cache_key_url = format!("git_lfs_url:{}:{}", self.repo_url, sha256);
        if let Ok(Some(cached_url)) = data_store.get_string(&cache_key_url).await {
            debug!("Found cached download URL for SHA256: {}", sha256);
            return Ok(cached_url);
        }
        
        // 调用LFS API获取下载URL
        let download_url = self.resolve_lfs_download_url(&sha256, size).await?;
        
        // 缓存下载URL
        let _ = data_store.set_string(&cache_key_url, &download_url, Some(self.url_cache_ttl)).await;
        debug!("Cached download URL for SHA256: {} -> {}", sha256, download_url);
        
        Ok(download_url)
    }
    
    async fn fetch_lfs_pointer_and_cache(
        &self,
        path: &str,
        cache_key: &str,
        data_store: &crate::data_store::DataStore
    ) -> Result<(String, u64)> {
        let raw_url = format!("{}{}", self.raw_url_prefix, path.trim_start_matches('/'));
        debug!("Fetching LFS pointer from: {}", raw_url);
        
        let response = crate::app_state::REQWEST_CLIENT
            .get(&raw_url)
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to fetch LFS pointer from {}: {}", raw_url, response.status()));
        }
        
        let content = response.text().await?;
        let pointer = self.parse_lfs_pointer(&content)?;
        
        // 提取SHA256 (移除"sha256:"前缀)
        let sha256 = pointer.oid.strip_prefix("sha256:").unwrap_or(&pointer.oid).to_string();
        
        // 缓存文件→SHA256映射
        let cache_value = format!("{}:{}", sha256, pointer.size);
        let _ = data_store.set_string(cache_key, &cache_value, Some(self.file_cache_ttl)).await;
        debug!("Cached file info: {} -> {}:{}", path, sha256, pointer.size);
        
        Ok((sha256, pointer.size))
    }
    
    fn parse_lfs_pointer(&self, content: &str) -> Result<LfsPointer> {
        let mut version = String::new();
        let mut oid = String::new();
        let mut size = 0u64;
        
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("version ") {
                version = line.split_whitespace().nth(1).unwrap_or("").to_string();
            } else if line.starts_with("oid ") {
                oid = line.split_whitespace().nth(1).unwrap_or("").to_string();
            } else if line.starts_with("size ") {
                if let Some(size_str) = line.split_whitespace().nth(1) {
                    size = size_str.parse().unwrap_or(0);
                }
            }
        }
        
        if oid.is_empty() || size == 0 {
            return Err(anyhow::anyhow!("Invalid LFS pointer format: missing oid or size"));
        }
        
        debug!("Parsed LFS pointer: oid={}, size={}", oid, size);
        Ok(LfsPointer { version, oid, size })
    }
    
    async fn resolve_lfs_download_url(&self, sha256: &str, size: u64) -> Result<String> {
        let batch_request = LfsBatchRequest {
            operation: "download".to_string(),
            transfers: vec!["basic".to_string()],
            objects: vec![LfsObject {
                oid: sha256.to_string(),
                size,
            }],
        };
        
        debug!("Making LFS batch request to: {}", self.lfs_endpoint);
        
        let response = crate::app_state::REQWEST_CLIENT
            .post(&format!("{}/objects/batch", self.lfs_endpoint))
            .header("Accept", "application/vnd.git-lfs+json")
            .header("Content-Type", "application/vnd.git-lfs+json")
            .json(&batch_request)
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("LFS API request failed: {} - {}", 
                response.status(), response.text().await.unwrap_or_default()));
        }
        
        let batch_response: LfsBatchResponse = response.json().await?;
        
        if let Some(object) = batch_response.objects.first() {
            if let Some(actions) = &object.actions {
                if let Some(download_action) = actions.get("download") {
                    debug!("Resolved LFS download URL: {}", download_action.href);
                    return Ok(download_action.href.clone());
                }
            }
        }
        
        Err(anyhow::anyhow!("No download URL found in LFS response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_git_lfs_url_parsing() {
        let url = "https://github.com/user/repo.git?raw=https://raw.githubusercontent.com/user/repo/main/&file_cache=7200&url_cache=300";
        let signer = GitLfsSigner::from_url(url).unwrap();
        
        assert_eq!(signer.repo_url, "https://github.com/user/repo.git");
        assert_eq!(signer.lfs_endpoint, "https://github.com/user/repo.git/info/lfs");
        assert_eq!(signer.raw_url_prefix, "https://raw.githubusercontent.com/user/repo/main/");
        assert_eq!(signer.file_cache_ttl, 7200);
        assert_eq!(signer.url_cache_ttl, 300);
    }
    
    #[test]
    fn test_git_lfs_url_parsing_defaults() {
        let url = "https://github.com/user/repo.git?raw=https://raw.githubusercontent.com/user/repo/main/";
        let signer = GitLfsSigner::from_url(url).unwrap();
        
        assert_eq!(signer.file_cache_ttl, 3600);
        assert_eq!(signer.url_cache_ttl, 600);
    }
    
    #[test]
    fn test_git_lfs_url_parsing_missing_raw() {
        let url = "https://github.com/user/repo.git?file_cache=7200";
        let result = GitLfsSigner::from_url(url);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing 'raw' parameter"));
    }
    
    #[test]  
    fn test_lfs_pointer_parsing() {
        let content = r#"version https://git-lfs.github.com/spec/v1
oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393
size 12345"#;
        
        let signer = GitLfsSigner::from_url("https://github.com/test/test.git?raw=https://example.com/").unwrap();
        let pointer = signer.parse_lfs_pointer(content).unwrap();
        
        assert_eq!(pointer.oid, "sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393");
        assert_eq!(pointer.size, 12345);
    }
    
    #[test]
    fn test_lfs_pointer_parsing_invalid() {
        let content = "invalid content";
        
        let signer = GitLfsSigner::from_url("https://github.com/test/test.git?raw=https://example.com/").unwrap();
        let result = signer.parse_lfs_pointer(content);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid LFS pointer format"));
    }
    
    #[test]
    fn test_lfs_pointer_parsing_missing_size() {
        let content = r#"version https://git-lfs.github.com/spec/v1
oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393"#;
        
        let signer = GitLfsSigner::from_url("https://github.com/test/test.git?raw=https://example.com/").unwrap();
        let result = signer.parse_lfs_pointer(content);
        
        assert!(result.is_err());
    }
}