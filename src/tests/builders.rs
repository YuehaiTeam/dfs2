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
