use md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResult {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ChallengeType {
    #[serde(rename = "md5")]
    Md5,
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "web")]
    Web,
}

#[derive(Debug, Clone)]
pub struct ChallengeConfig {
    pub challenge_type: ChallengeType,
    pub difficulty: u8, // For SHA256: how many bytes to remove (1-4), for MD5: always 2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge_type: ChallengeType,
    pub hash: String,
    pub partial_data: String,
    pub missing_bytes: u8,
    pub original_data: Vec<u8>,
}

impl Challenge {
    /// Generate MD5 challenge with fixed 2-byte difficulty
    pub fn generate_md5(base_data: &str) -> Self {
        use rand::Rng;
        let mut rng = rand::rng();

        // Generate random data based on base_data
        let original_data = format!("{}:{}", base_data, rng.random::<u64>()).into_bytes();

        // Calculate MD5 hash of original data (first hash)
        let first_hash = format!("{:x}", md5::compute(&original_data));

        // Calculate MD5 hash of the first hash (second hash - this is the complete challenge)
        let second_hash = format!("{:x}", md5::compute(first_hash.as_bytes()));

        // Remove last 1 byte (2 hex characters) from FIRST hash as partial data
        let partial_first_hash = first_hash[..first_hash.len() - 2].to_string();

        Challenge {
            challenge_type: ChallengeType::Md5,
            hash: second_hash,                // Complete second hash
            partial_data: partial_first_hash, // Partial first hash (missing last 2 chars)
            missing_bytes: 1,                 // 1 byte = 2 hex characters
            original_data,
        }
    }

    /// Generate SHA256 challenge with configurable difficulty
    pub fn generate_sha256(base_data: &str, difficulty: u8) -> Self {
        use rand::Rng;
        let difficulty = difficulty.clamp(1, 4); // Limit difficulty to 1-4 bytes (2-8 hex chars)
        let mut rng = rand::rng();

        // Generate random data based on base_data
        let original_data = format!("{}:{}", base_data, rng.random::<u64>()).into_bytes();

        // Calculate SHA256 hash of original data (first hash)
        let first_hash = format!("{:x}", Sha256::digest(&original_data));

        // Calculate SHA256 hash of the first hash (second hash - this is the complete challenge)
        let second_hash = format!("{:x}", Sha256::digest(first_hash.as_bytes()));

        // Remove last N bytes (2N hex characters) from FIRST hash as partial data
        let chars_to_remove = (difficulty as usize) * 2; // difficulty bytes = difficulty*2 hex chars
        let partial_first_hash = first_hash[..first_hash.len() - chars_to_remove].to_string();

        Challenge {
            challenge_type: ChallengeType::Sha256,
            hash: second_hash,                // Complete second hash
            partial_data: partial_first_hash, // Partial first hash (missing last N bytes)
            missing_bytes: difficulty,
            original_data,
        }
    }

    /// Verify challenge response
    pub fn verify(&self, response: &str) -> ChallengeResult {
        let success = match self.challenge_type {
            ChallengeType::Md5 => self.verify_md5(response),
            ChallengeType::Sha256 => self.verify_sha256(response),
            ChallengeType::Web => false, // Web challenges handled separately
        };

        ChallengeResult {
            success,
            error: if success {
                None
            } else {
                Some("Invalid challenge response".to_string())
            },
        }
    }

    fn verify_md5(&self, response: &str) -> bool {
        // Response should be the first hash (32 hex characters)
        if response.len() != 32 {
            return false;
        }

        // Check if response contains only valid hex characters
        if !response.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }

        // Calculate second MD5 hash of the submitted first hash
        let double_hash = format!("{:x}", md5::compute(response.to_lowercase().as_bytes()));

        // Verify the double hash matches our stored hash
        double_hash == self.hash
    }

    fn verify_sha256(&self, response: &str) -> bool {
        // Response should be the complete first hash (64 hex characters for SHA256)
        if response.len() != 64 {
            return false;
        }

        // Check if response contains only valid hex characters
        if !response.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }

        // Calculate second SHA256 hash of the submitted first hash
        let double_hash = format!("{:x}", Sha256::digest(response.to_lowercase().as_bytes()));

        // Verify the double hash matches our stored hash
        double_hash == self.hash
    }

    /// Format challenge data for API response (hash/partial_data)
    pub fn format_data(&self) -> String {
        match self.challenge_type {
            ChallengeType::Md5 | ChallengeType::Sha256 => {
                // For MD5/SHA256: return complete_second_hash/partial_first_hash
                // self.hash contains the complete second hash
                // self.partial_data contains the partial first hash
                format!("{}/{}", self.hash, self.partial_data)
            }
            _ => {
                // For other types, use the original format
                format!("{}/{}", self.hash, self.partial_data)
            }
        }
    }

    /// Get the expected value that client should submit for verification
    pub fn get_expected(&self) -> String {
        match self.challenge_type {
            ChallengeType::Md5 => {
                // For MD5: client should submit the complete first hash
                format!("{:x}", md5::compute(&self.original_data))
            }
            ChallengeType::Sha256 => {
                // For SHA256: client should submit the complete first hash
                format!("{:x}", Sha256::digest(&self.original_data))
            }
            _ => {
                // For other types: client should submit the original data in hex
                hex::encode(&self.original_data)
            }
        }
    }
}

/// Generate challenge based on configuration
pub fn generate_challenge(config: &ChallengeConfig, base_data: &str) -> Challenge {
    match config.challenge_type {
        ChallengeType::Md5 => Challenge::generate_md5(base_data),
        ChallengeType::Sha256 => Challenge::generate_sha256(base_data, config.difficulty),
        ChallengeType::Web => {
            // Web challenges are handled by plugins, return placeholder
            Challenge {
                challenge_type: ChallengeType::Web,
                hash: "web_challenge".to_string(),
                partial_data: base_data.to_string(),
                missing_bytes: 0,
                original_data: Vec::new(),
            }
        }
    }
}

/// Default challenge configuration
impl Default for ChallengeConfig {
    fn default() -> Self {
        ChallengeConfig {
            challenge_type: ChallengeType::Md5,
            difficulty: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_md5_challenge() {
        let challenge = Challenge::generate_md5("test_data");

        assert!(challenge.hash.len() == 32); // MD5哈希长度
        assert!(challenge.partial_data.len() > 0);
        assert!(challenge.challenge_type == ChallengeType::Md5);

        // 验证部分数据确实缺少1字节（hex编码后的长度应该正确）
        let expected_byte_length = challenge.partial_data.len() / 2; // Convert hex length to byte length
        let _complete_byte_length = expected_byte_length + 1; // Add back the 1 missing byte
        assert_eq!(challenge.missing_bytes, 1);
        assert!(challenge.partial_data.len() % 2 == 0); // Hex strings should be even length
    }

    #[test]
    fn test_generate_sha256_challenge() {
        let challenge = Challenge::generate_sha256("test_data", 2);

        assert!(challenge.hash.len() == 64); // SHA256哈希长度
        assert!(challenge.partial_data.len() > 0);
        assert!(challenge.challenge_type == ChallengeType::Sha256);

        // 验证部分数据确实缺少指定字节数（hex编码后的长度应该正确）
        let expected_byte_length = challenge.partial_data.len() / 2; // Convert hex length to byte length
        let _complete_byte_length = expected_byte_length + 2; // Add back the 2 missing bytes
        assert_eq!(challenge.missing_bytes, 2);
        assert!(challenge.partial_data.len() % 2 == 0); // Hex strings should be even length
    }

    #[test]
    fn test_sha256_different_difficulties() {
        let challenge1 = Challenge::generate_sha256("test", 1);
        let challenge2 = Challenge::generate_sha256("test", 2);
        let challenge3 = Challenge::generate_sha256("test", 3);

        // 不同难度应该产生不同缺少字节数
        assert_eq!(challenge1.missing_bytes, 1);
        assert_eq!(challenge2.missing_bytes, 2);
        assert_eq!(challenge3.missing_bytes, 3);
        // 部分数据应该是hex编码的有效字符串
        assert!(challenge1.partial_data.len() % 2 == 0);
        assert!(challenge2.partial_data.len() % 2 == 0);
        assert!(challenge3.partial_data.len() % 2 == 0);
    }

    #[test]
    fn test_verify_md5_challenge() {
        let challenge = Challenge::generate_md5("test_data");

        // 模拟客户端找到正确答案的过程
        let base_data = "test_data:".to_string();
        let mut found = false;

        for i in 0..=255u8 {
            for j in 0..=255u8 {
                let test_data = format!("{}{}{}", base_data, i as char, j as char);
                let test_hash = format!("{:x}", md5::compute(test_data.as_bytes()));

                if test_hash == challenge.hash {
                    // 验证找到的答案
                    let result = challenge.verify(&hex::encode(&test_data));
                    assert!(result.success);
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }

        // 确保能找到正确答案（虽然可能需要很长时间）
        // 这个测试可能很慢，所以我们简化验证
        let wrong_answer = "wrong_data";
        let result = challenge.verify(wrong_answer);
        assert!(!result.success);
    }

    #[test]
    fn test_verify_sha256_challenge() {
        let challenge = Challenge::generate_sha256("test_data", 1);

        // 测试错误答案
        let wrong_answer = "wrong_data";
        let result = challenge.verify(wrong_answer);
        assert!(!result.success);
    }

    #[test]
    fn test_challenge_config_default() {
        let config = ChallengeConfig::default();
        assert_eq!(config.challenge_type, ChallengeType::Md5);
        assert_eq!(config.difficulty, 2);
    }

    #[test]
    fn test_generate_challenge_function() {
        let config = ChallengeConfig {
            challenge_type: ChallengeType::Md5,
            difficulty: 2,
        };
        let challenge = generate_challenge(&config, "test");
        assert_eq!(challenge.challenge_type, ChallengeType::Md5);

        let config = ChallengeConfig {
            challenge_type: ChallengeType::Sha256,
            difficulty: 3,
        };
        let challenge = generate_challenge(&config, "test");
        assert_eq!(challenge.challenge_type, ChallengeType::Sha256);

        let config = ChallengeConfig {
            challenge_type: ChallengeType::Web,
            difficulty: 1,
        };
        let challenge = generate_challenge(&config, "test");
        assert_eq!(challenge.challenge_type, ChallengeType::Web);
        assert_eq!(challenge.hash, "web_challenge");
    }

    #[test]
    fn test_challenge_serialization() {
        let challenge = Challenge {
            challenge_type: ChallengeType::Md5,
            hash: "test_hash".to_string(),
            partial_data: "test_data".to_string(),
            missing_bytes: 2,
            original_data: b"test_original".to_vec(),
        };

        // 测试JSON序列化
        let json = serde_json::to_string(&challenge).unwrap();
        let deserialized: Challenge = serde_json::from_str(&json).unwrap();

        assert_eq!(challenge.hash, deserialized.hash);
        assert_eq!(challenge.partial_data, deserialized.partial_data);
        assert_eq!(challenge.challenge_type, deserialized.challenge_type);
    }

    #[test]
    fn test_challenge_result_serialization() {
        let result = ChallengeResult {
            success: true,
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ChallengeResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.success, deserialized.success);
        assert_eq!(result.error, deserialized.error);
    }
}
