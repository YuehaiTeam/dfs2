use serde_json::json;
use std::collections::HashMap;

use crate::models::{CdnRecord, Session};

/// Session构建器
pub struct SessionBuilder {
    resource_id: String,
    version: String,
    chunks: Vec<String>,
    sub_path: Option<String>,
    cdn_records: HashMap<String, Vec<CdnRecord>>,
    extras: serde_json::Value,
}

impl SessionBuilder {
    pub fn new() -> Self {
        Self {
            resource_id: "test_resource".to_string(),
            version: "1.0.0".to_string(),
            chunks: vec!["0-1023".to_string()],
            sub_path: None,
            cdn_records: HashMap::new(),
            extras: json!({}),
        }
    }

    pub fn with_resource_id(mut self, resource_id: &str) -> Self {
        self.resource_id = resource_id.to_string();
        self
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    pub fn with_chunks(mut self, chunks: Vec<&str>) -> Self {
        self.chunks = chunks.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_sub_path(mut self, sub_path: Option<&str>) -> Self {
        self.sub_path = sub_path.map(|s| s.to_string());
        self
    }

    pub fn build(self) -> Session {
        Session {
            resource_id: self.resource_id,
            version: self.version,
            chunks: self.chunks,
            sub_path: self.sub_path,
            cdn_records: self.cdn_records,
            extras: self.extras,
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }
}

/// 批量测试构建器
pub struct BatchTestBuilder {
    session_id: String,
    valid_chunks: Vec<String>,
    invalid_chunks: Vec<String>,
    cdn_records: HashMap<String, Vec<CdnRecord>>,
    resource_id: String,
}

impl BatchTestBuilder {
    pub fn new() -> Self {
        Self {
            session_id: "test_batch_session".to_string(),
            valid_chunks: vec!["0-1023".to_string(), "1024-2047".to_string()],
            invalid_chunks: vec![],
            cdn_records: HashMap::new(),
            resource_id: "test_resource".to_string(),
        }
    }

    pub fn with_session_id(mut self, session_id: &str) -> Self {
        self.session_id = session_id.to_string();
        self
    }

    pub fn with_valid_chunks(mut self, chunks: Vec<&str>) -> Self {
        self.valid_chunks = chunks.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_invalid_chunks(mut self, chunks: Vec<&str>) -> Self {
        self.invalid_chunks = chunks.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_cdn_records(mut self, chunk_id: &str, records: Vec<CdnRecord>) -> Self {
        self.cdn_records.insert(chunk_id.to_string(), records);
        self
    }

    pub fn with_resource_id(mut self, resource_id: &str) -> Self {
        self.resource_id = resource_id.to_string();
        self
    }

    pub fn build(self) -> (String, Session, Vec<String>) {
        let all_chunks = [self.valid_chunks.clone(), self.invalid_chunks.clone()].concat();

        let session = Session {
            resource_id: self.resource_id,
            version: "1.0.0".to_string(),
            chunks: self.valid_chunks, // session只包含有效chunks
            sub_path: None,
            cdn_records: self.cdn_records,
            extras: json!({}),
            created_at: chrono::Utc::now().timestamp() as u64,
        };

        (self.session_id, session, all_chunks)
    }
}

/// 批量CDN请求构建器
pub struct BatchChunkRequestBuilder {
    chunks: Vec<String>,
}

impl BatchChunkRequestBuilder {
    pub fn new() -> Self {
        Self {
            chunks: vec!["0-1023".to_string(), "1024-2047".to_string()],
        }
    }

    pub fn with_chunks(mut self, chunks: Vec<&str>) -> Self {
        self.chunks = chunks.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn empty(mut self) -> Self {
        self.chunks = vec![];
        self
    }

    pub fn too_many_chunks(mut self) -> Self {
        // 生成超过100个chunks来测试限制
        self.chunks = (0..101)
            .map(|i| format!("{}-{}", i * 1024, (i + 1) * 1024 - 1))
            .collect();
        self
    }

    pub fn build(self) -> crate::models::BatchChunkRequest {
        crate::models::BatchChunkRequest {
            chunks: self.chunks,
        }
    }
}

/// CDN记录构建器
pub struct CdnRecordBuilder {
    url: String,
    server_id: Option<String>,
    skip_penalty: bool,
    timestamp: u64,
    weight: u32,
    size: Option<u64>,
}

impl CdnRecordBuilder {
    pub fn new() -> Self {
        Self {
            url: "https://test-cdn.com/file".to_string(),
            server_id: Some("test-server".to_string()),
            skip_penalty: false,
            timestamp: chrono::Utc::now().timestamp() as u64,
            weight: 10,
            size: Some(1024),
        }
    }

    pub fn with_url(mut self, url: &str) -> Self {
        self.url = url.to_string();
        self
    }

    pub fn with_server_id(mut self, server_id: Option<&str>) -> Self {
        self.server_id = server_id.map(|s| s.to_string());
        self
    }

    pub fn with_skip_penalty(mut self, skip_penalty: bool) -> Self {
        self.skip_penalty = skip_penalty;
        self
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    pub fn with_size(mut self, size: Option<u64>) -> Self {
        self.size = size;
        self
    }

    pub fn build(self) -> CdnRecord {
        CdnRecord {
            url: self.url,
            server_id: self.server_id,
            skip_penalty: self.skip_penalty,
            timestamp: self.timestamp,
            weight: self.weight,
            size: self.size,
        }
    }
}

/// Challenge数据构建器 - 生成符合ChallengeService期望格式的数据
pub struct ChallengeDataBuilder {
    challenge_type: String,
    hash: String,
    partial_data: String,
    missing_bytes: u8,
    original_data: String,
}

impl ChallengeDataBuilder {
    pub fn new() -> Self {
        Self {
            challenge_type: "md5".to_string(),
            hash: "d41d8cd98f00b204e9800998ecf8427e".to_string(), // MD5 of empty string (for testing)
            partial_data: "d41d8cd98f00b204e9800998ecf842".to_string(), // Missing last 2 chars
            missing_bytes: 1,
            original_data: "74657374".to_string(), // "test" in hex
        }
    }

    pub fn with_challenge_type(mut self, challenge_type: &str) -> Self {
        self.challenge_type = challenge_type.to_string();
        self
    }

    pub fn build(self) -> String {
        // 返回符合ChallengeService期望的JSON格式
        serde_json::json!({
            "type": self.challenge_type,
            "hash": self.hash,
            "partial_data": self.partial_data,
            "missing_bytes": self.missing_bytes,
            "original_data": self.original_data
        })
        .to_string()
    }
}

impl Default for ChallengeDataBuilder {
    fn default() -> Self {
        Self::new()
    }
}
