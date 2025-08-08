use crate::{
    modules::auth::challenge::{generate_challenge, Challenge, ChallengeConfig, ChallengeType},
    config::SharedConfig,
    modules::storage::data_store::DataStore,
    error::{DfsError, DfsResult},
    modules::qjs::JsRunner, responses::ChallengeResponse,
};
use serde_json::json;
use tracing::{debug, error, warn};

#[derive(Clone)]
pub struct ChallengeService {
    data_store: DataStore,
    js_runner: JsRunner,
    shared_config: SharedConfig,
    session_service: crate::services::SessionService,
}

impl ChallengeService {
    pub fn new(data_store: DataStore, js_runner: JsRunner, shared_config: SharedConfig, session_service: crate::services::SessionService) -> Self {
        Self {
            data_store,
            js_runner,
            shared_config,
            session_service,
        }
    }

    /// 存储challenge到数据存储
    pub async fn store_challenge(&self, sid: &str, challenge_data: &str) -> DfsResult<()> {
        self.data_store
            .store_challenge(sid, challenge_data)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to store challenge: {}", e)))
    }

    /// 获取challenge数据
    pub async fn get_challenge(&self, sid: &str) -> DfsResult<Option<String>> {
        self.data_store
            .get_challenge(sid)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to get challenge: {}", e)))
    }

    /// 移除challenge数据
    pub async fn remove_challenge(&self, sid: &str) -> DfsResult<()> {
        self.data_store
            .remove_challenge(sid)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to remove challenge: {}", e)))
    }

    /// 生成并存储challenge，统一处理所有类型的challenge
    pub async fn generate_and_store_challenge(
        &self,
        sid: &str,
        resource_id: &str,
        sub_path: Option<&str>,
    ) -> DfsResult<ChallengeResponse> {
        let config_guard = self.shared_config.load();
        let challenge_config = config_guard.get_challenge_config(resource_id);

        // 构造base_data
        let base_data = if let Some(sub_path) = sub_path {
            format!("data/{}/{}/{}", resource_id, sub_path, sid)
        } else {
            format!("data/{}/{}", resource_id, sid)
        };

        let challenge_type = challenge_config.get_effective_type();

        // Handle Web challenges differently using the plugin system
        if challenge_type == ChallengeType::Web {
            return self
                .generate_web_challenge(
                    sid,
                    resource_id,
                    sub_path,
                    &challenge_config.web_plugin,
                    &base_data,
                )
                .await;
        }

        // Handle MD5/SHA256 challenges
        let generation_config = ChallengeConfig {
            challenge_type,
            difficulty: if challenge_type == ChallengeType::Sha256 {
                challenge_config.get_sha256_difficulty()
            } else {
                2 // MD5 always uses 2
            },
        };

        let challenge = generate_challenge(&generation_config, &base_data);

        // Store challenge in data store
        let challenge_json = json!({
            "type": match challenge.challenge_type {
                ChallengeType::Md5 => "md5",
                ChallengeType::Sha256 => "sha256",
                ChallengeType::Web => "web",
            },
            "hash": challenge.hash,
            "partial_data": challenge.partial_data,
            "missing_bytes": challenge.missing_bytes,
            "original_data": hex::encode(&challenge.original_data),
        });

        self.store_challenge(sid, &challenge_json.to_string())
            .await?;

        Ok(ChallengeResponse {
            challenge: match challenge.challenge_type {
                ChallengeType::Md5 => "md5".to_string(),
                ChallengeType::Sha256 => "sha256".to_string(),
                ChallengeType::Web => "web".to_string(),
            },
            data: challenge.format_data(),
            sid: sid.to_string(),
        })
    }

    /// 生成Web challenge
    async fn generate_web_challenge(
        &self,
        sid: &str,
        resource_id: &str,
        sub_path: Option<&str>,
        web_plugin_id: &str,
        base_data: &str,
    ) -> DfsResult<ChallengeResponse> {
        let mut challenge_data = json!({
            "sid": sid,
            "resource_id": resource_id,
            "base_data": base_data,
        });

        // Add sub_path if present (for prefix resources)
        if let Some(sub_path) = sub_path {
            challenge_data["sub_path"] = json!(sub_path);
        }

        match self
            .js_runner
            .run_challenge_plugin(web_plugin_id, "generate", challenge_data, json!({}))
            .await
        {
            Ok(plugin_result) => {
                if let Some(verification_url) = plugin_result.get("url").and_then(|v| v.as_str()) {
                    let web_challenge_json = json!({
                        "type": "web",
                        "plugin_id": web_plugin_id,
                        "plugin_result": plugin_result,
                        "verification_url": verification_url,
                    });

                    self.store_challenge(sid, &web_challenge_json.to_string())
                        .await?;

                    Ok(ChallengeResponse {
                        challenge: "web".to_string(),
                        data: verification_url.to_string(),
                        sid: sid.to_string(),
                    })
                } else {
                    warn!(
                        "Web challenge plugin {} did not return a valid URL",
                        web_plugin_id
                    );
                    // Fall back to MD5 challenge
                    self.generate_fallback_challenge(sid, base_data)
                        .await
                }
            }
            Err(e) => {
                error!(
                    "Failed to run web challenge plugin {}: {}",
                    web_plugin_id, e
                );
                // Fall back to MD5 challenge
                self.generate_fallback_challenge(sid, base_data)
                    .await
            }
        }
    }

    /// 生成fallback MD5 challenge
    async fn generate_fallback_challenge(
        &self,
        sid: &str,
        base_data: &str,
    ) -> DfsResult<ChallengeResponse> {
        let fallback_config = ChallengeConfig {
            challenge_type: ChallengeType::Md5,
            difficulty: 2,
        };
        let fallback_challenge = generate_challenge(&fallback_config, base_data);

        let challenge_json = json!({
            "type": "md5",
            "hash": fallback_challenge.hash,
            "partial_data": fallback_challenge.partial_data,
            "missing_bytes": fallback_challenge.missing_bytes,
            "original_data": hex::encode(&fallback_challenge.original_data),
        });

        self.store_challenge(sid, &challenge_json.to_string())
            .await?;

        Ok(ChallengeResponse {
            challenge: "md5".to_string(),
            data: fallback_challenge.format_data(),
            sid: sid.to_string(),
        })
    }

    /// 验证challenge响应
    pub async fn verify_challenge_response(
        &self,
        sid: &str,
        user_response: &str,
        resource_id: &str,
        sub_path: Option<&str>,
        debug_mode: bool,
    ) -> DfsResult<bool> {
        let challenge_data = self.get_challenge(sid).await?.ok_or_else(|| {
            DfsError::invalid_input("challenge", "Challenge not found or expired")
        })?;

        let challenge_json: serde_json::Value =
            serde_json::from_str(&challenge_data).map_err(|e| {
                DfsError::internal_error(format!("Failed to parse challenge data: {}", e))
            })?;

        let challenge_str = challenge_json["type"].as_str().unwrap_or("md5");

        let verification_success = match challenge_str {
            "web" => {
                self.verify_web_challenge(
                    sid,
                    user_response,
                    resource_id,
                    sub_path,
                    &challenge_json,
                    debug_mode,
                )
                .await?
            }
            _ => self.verify_hash_challenge(
                user_response,
                &challenge_json,
                challenge_str,
                debug_mode,
            )?,
        };

        // Remove challenge after verification (successful or debug skip)
        let _ = self.remove_challenge(sid).await;

        Ok(verification_success)
    }

    /// 验证Web challenge
    async fn verify_web_challenge(
        &self,
        sid: &str,
        user_response: &str,
        resource_id: &str,
        sub_path: Option<&str>,
        challenge_json: &serde_json::Value,
        debug_mode: bool,
    ) -> DfsResult<bool> {
        if let (Some(plugin_id), Some(plugin_result)) = (
            challenge_json["plugin_id"].as_str(),
            challenge_json["plugin_result"].as_object(),
        ) {
            let mut verify_data = json!({
                "sid": sid,
                "resource_id": resource_id,
                "user_response": user_response,
                "original_result": plugin_result,
            });

            if let Some(sub_path) = sub_path {
                verify_data["sub_path"] = json!(sub_path);
            }

            match self
                .js_runner
                .run_challenge_plugin(plugin_id, "verify", verify_data, json!({}))
                .await
            {
                Ok(verification_result) => {
                    let verification_success = verification_result
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    if !verification_success && debug_mode {
                        debug!("Web challenge failed but allowing in debug mode");
                        debug!("Plugin ID: {}", plugin_id);
                        debug!("User Response: {}", user_response);
                        debug!("Verification Result: {}", verification_result);
                    }

                    Ok(verification_success || debug_mode)
                }
                Err(e) => {
                    error!(
                        "Failed to verify web challenge with plugin {}: {}",
                        plugin_id, e
                    );
                    if debug_mode {
                        debug!(
                            "Web challenge verification error but allowing in debug mode: {}",
                            e
                        );
                        Ok(true)
                    } else {
                        Err(DfsError::internal_error("Web challenge verification error"))
                    }
                }
            }
        } else {
            Err(DfsError::internal_error("Invalid web challenge data"))
        }
    }

    /// 验证MD5/SHA256 challenge
    fn verify_hash_challenge(
        &self,
        user_response: &str,
        challenge_json: &serde_json::Value,
        challenge_str: &str,
        debug_mode: bool,
    ) -> DfsResult<bool> {
        if let (Some(hash), Some(partial_data), Some(original_data_hex)) = (
            challenge_json["hash"].as_str(),
            challenge_json["partial_data"].as_str(),
            challenge_json["original_data"].as_str(),
        ) {
            let challenge_type = match challenge_str {
                "md5" => ChallengeType::Md5,
                "sha256" => ChallengeType::Sha256,
                _ => ChallengeType::Md5,
            };

            let original_data = hex::decode(original_data_hex).unwrap_or_default();
            let stored_challenge = Challenge {
                challenge_type,
                hash: hash.to_string(),
                partial_data: partial_data.to_string(),
                missing_bytes: challenge_json["missing_bytes"].as_u64().unwrap_or(2) as u8,
                original_data,
            };

            let verification_result = stored_challenge.verify(user_response);

            if !verification_result.success && debug_mode {
                debug!("Challenge failed but allowing in debug mode");
                debug!("Challenge Type: {}", challenge_str);
                debug!("Submitted: {}", user_response);
                debug!("Expected: {}", stored_challenge.get_expected());
                debug!("Hash: {}", stored_challenge.hash);
                debug!("Partial Data: {}", stored_challenge.partial_data);
            }

            Ok(verification_result.success || debug_mode)
        } else {
            Err(DfsError::internal_error("Invalid challenge data"))
        }
    }

    /// Legacy客户端的challenge生成和session创建
    /// 集成了原LegacyClientHandler的功能
    pub async fn generate_legacy_challenge(&self, resid: &str, range: Option<&str>) -> DfsResult<Challenge> {
        use uuid::Uuid;
        use std::collections::HashMap;
        use crate::models::Session;

        let client_id = Uuid::new_v4().to_string();
        let base_data = format!("legacy:{}:{}", resid, client_id);
        let challenge = Challenge::generate_md5(&base_data);
        
        // 计算预期的响应值
        let response_value = challenge.get_expected();
        
        // 根据 range 参数设置 session chunks
        let chunks = if let Some(range_str) = range {
            // 有 range 参数，使用指定的 range
            vec![range_str.to_string()]
        } else {
            // 没有 range 参数，默认完整文件下载
            vec!["0-".to_string()]
        };
        
        // 直接用响应值作为 session ID 创建 session
        let session = Session {
            resource_id: resid.to_string(),
            version: "latest".to_string(),
            chunks,
            sub_path: None, // 历史客户端不支持sub_path
            cdn_records: HashMap::new(),
            extras: serde_json::json!({}), // 历史客户端使用空extras
        };
        
        // 使用SessionService创建session
        self.session_service.store_session(&response_value, &session).await?;
        
        Ok(challenge)
    }
}
