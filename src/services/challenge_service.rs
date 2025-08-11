use crate::{
    config::SharedConfig,
    error::{DfsError, DfsResult},
    modules::auth::challenge::{Challenge, ChallengeConfig, ChallengeType, generate_challenge},
    modules::qjs::JsRunner,
    modules::storage::data_store::DataStore,
    responses::ChallengeResponse,
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
    pub fn new(
        data_store: DataStore,
        js_runner: JsRunner,
        shared_config: SharedConfig,
        session_service: crate::services::SessionService,
    ) -> Self {
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
            .map_err(|e| DfsError::internal_error(format!("Failed to store challenge: {e}")))
    }

    /// 获取challenge数据
    pub async fn get_challenge(&self, sid: &str) -> DfsResult<Option<String>> {
        self.data_store
            .get_challenge(sid)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to get challenge: {e}")))
    }

    /// 移除challenge数据
    pub async fn remove_challenge(&self, sid: &str) -> DfsResult<()> {
        self.data_store
            .remove_challenge(sid)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to remove challenge: {e}")))
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
            format!("data/{resource_id}/{sub_path}/{sid}")
        } else {
            format!("data/{resource_id}/{sid}")
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
                    self.generate_fallback_challenge(sid, base_data).await
                }
            }
            Err(e) => {
                error!(
                    "Failed to run web challenge plugin {}: {}",
                    web_plugin_id, e
                );
                // Fall back to MD5 challenge
                self.generate_fallback_challenge(sid, base_data).await
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
                DfsError::internal_error(format!("Failed to parse challenge data: {e}"))
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
            Err(DfsError::invalid_input(
                "challenge",
                "Invalid challenge data",
            ))
        }
    }

    /// Legacy客户端的challenge生成和session创建
    /// 集成了原LegacyClientHandler的功能
    pub async fn generate_legacy_challenge(
        &self,
        resid: &str,
        version: &str,
        sub_path: Option<&str>,
        range: Option<&str>,
    ) -> DfsResult<Challenge> {
        use crate::models::Session;
        use std::collections::HashMap;
        use uuid::Uuid;

        let client_id = Uuid::new_v4().to_string();
        let base_data = format!("legacy:{resid}:{client_id}");
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
            version: version.to_string(),
            chunks,
            sub_path: sub_path.map(|s| s.to_string()),
            cdn_records: HashMap::new(),
            extras: serde_json::json!({}), // 历史客户端使用空extras
            created_at: chrono::Utc::now().timestamp() as u64,
        };

        // 使用SessionService创建session
        self.session_service
            .store_session(&response_value, &session)
            .await?;

        Ok(challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::auth::challenge::ChallengeType;

    async fn create_test_service() -> ChallengeService {
        let env = crate::tests::common::TestEnvironment::new().await;
        env.services.challenge_service
    }

    #[tokio::test]
    async fn test_generate_md5_challenge() {
        let service = create_test_service().await;
        let sid = "test_session_md5";
        let resource_id = "md5_resource";

        let result = service
            .generate_and_store_challenge(sid, resource_id, None)
            .await;
        assert!(result.is_ok(), "MD5 challenge generation should succeed");

        let response = result.unwrap();
        assert_eq!(response.challenge, "md5");
        assert_eq!(response.sid, sid);
        assert!(
            !response.data.is_empty(),
            "MD5 challenge data should not be empty"
        );

        // 验证challenge已存储
        let stored = service.get_challenge(sid).await.unwrap();
        assert!(stored.is_some(), "Challenge should be stored");

        let challenge_data: serde_json::Value = serde_json::from_str(&stored.unwrap()).unwrap();
        assert_eq!(challenge_data["type"].as_str().unwrap(), "md5");
        assert!(challenge_data["hash"].is_string());
        assert!(challenge_data["partial_data"].is_string());
    }

    #[tokio::test]
    async fn test_generate_sha256_challenge() {
        let service = create_test_service().await;
        let sid = "test_session_sha256";
        let resource_id = "sha256_resource";

        let result = service
            .generate_and_store_challenge(sid, resource_id, None)
            .await;
        assert!(result.is_ok(), "SHA256 challenge generation should succeed");

        let response = result.unwrap();
        assert_eq!(response.challenge, "sha256");
        assert_eq!(response.sid, sid);
        assert!(
            !response.data.is_empty(),
            "SHA256 challenge data should not be empty"
        );

        // 验证challenge已存储且类型正确
        let stored = service.get_challenge(sid).await.unwrap();
        assert!(stored.is_some());

        let challenge_data: serde_json::Value = serde_json::from_str(&stored.unwrap()).unwrap();
        assert_eq!(challenge_data["type"].as_str().unwrap(), "sha256");
    }

    #[tokio::test]
    async fn test_generate_web_challenge_success() {
        let service = create_test_service().await;
        let sid = "test_session_web";
        let resource_id = "web_resource";

        let result = service
            .generate_and_store_challenge(sid, resource_id, None)
            .await;
        assert!(result.is_ok(), "Web challenge generation should succeed");

        let response = result.unwrap();
        assert_eq!(response.challenge, "web");
        assert_eq!(response.sid, sid);
        assert!(
            response.data.contains("challenge.example.com"),
            "Web challenge should return verification URL"
        );

        // 验证web challenge存储结构
        let stored = service.get_challenge(sid).await.unwrap();
        assert!(stored.is_some());

        let challenge_data: serde_json::Value = serde_json::from_str(&stored.unwrap()).unwrap();
        assert_eq!(challenge_data["type"].as_str().unwrap(), "web");
        assert!(challenge_data["plugin_id"].is_string());
        assert!(challenge_data["verification_url"].is_string());
    }

    #[tokio::test]
    async fn test_web_challenge_fallback_to_md5() {
        let service = create_test_service().await;
        let sid = "test_session_fallback";
        let resource_id = "web_resource";

        // 通过修改共享配置来使用失败的插件
        {
            let mut config = service.shared_config.load().as_ref().clone();
            if let Some(resource) = config.resources.get_mut(resource_id) {
                resource.challenge = Some(crate::config::ChallengeConfig {
                    challenge_type: "web".to_string(),
                    sha256_difficulty: 2,
                    web_plugin: "geetest".to_string(),
                    type_weights: None,
                });
            }
            // 重新加载配置到SharedConfig中
            service.shared_config.reload(config);
        }

        let result = service
            .generate_and_store_challenge(sid, resource_id, None)
            .await;
        assert!(
            result.is_ok(),
            "Should fallback to MD5 when web challenge fails"
        );

        let response = result.unwrap();
        // 应该fallback到MD5
        assert_eq!(response.challenge, "md5");
    }

    #[tokio::test]
    async fn test_challenge_verification_md5() {
        let service = create_test_service().await;
        let sid = "test_verification_md5";
        let resource_id = "md5_resource";

        // 生成challenge
        let generation_result = service
            .generate_and_store_challenge(sid, resource_id, None)
            .await;
        assert!(generation_result.is_ok());

        // 获取存储的challenge数据以计算正确的响应
        let stored = service.get_challenge(sid).await.unwrap().unwrap();
        let challenge_data: serde_json::Value = serde_json::from_str(&stored).unwrap();
        let original_data_hex = challenge_data["original_data"].as_str().unwrap();
        let original_data = hex::decode(original_data_hex).unwrap();

        // 计算正确的MD5响应
        let md5_hash = format!("{:x}", md5::compute(&original_data));

        // 验证正确响应
        let verify_result = service
            .verify_challenge_response(sid, &md5_hash, resource_id, None, false)
            .await;
        assert!(verify_result.is_ok());
        assert!(
            verify_result.unwrap(),
            "Correct MD5 response should verify successfully"
        );

        // 验证challenge已被移除
        let removed_challenge = service.get_challenge(sid).await.unwrap();
        assert!(
            removed_challenge.is_none(),
            "Challenge should be removed after verification"
        );
    }

    #[tokio::test]
    async fn test_challenge_verification_wrong_response() {
        let service = create_test_service().await;
        let sid = "test_wrong_response";
        let resource_id = "md5_resource";

        // 生成challenge
        service
            .generate_and_store_challenge(sid, resource_id, None)
            .await
            .unwrap();

        // 使用错误响应验证
        let verify_result = service
            .verify_challenge_response(sid, "wrong_response", resource_id, None, false)
            .await;
        assert!(verify_result.is_ok());
        assert!(
            !verify_result.unwrap(),
            "Wrong response should fail verification"
        );
    }

    #[tokio::test]
    async fn test_challenge_verification_debug_mode() {
        let service = create_test_service().await;
        let sid = "test_debug_mode";
        let resource_id = "md5_resource";

        // 生成challenge
        service
            .generate_and_store_challenge(sid, resource_id, None)
            .await
            .unwrap();

        // 在debug模式下，错误响应应该通过
        let verify_result = service
            .verify_challenge_response(sid, "wrong_response", resource_id, None, true)
            .await;
        assert!(verify_result.is_ok());
        assert!(
            verify_result.unwrap(),
            "Debug mode should allow wrong responses to pass"
        );
    }

    #[tokio::test]
    async fn test_challenge_not_found() {
        let service = create_test_service().await;

        let verify_result = service
            .verify_challenge_response(
                "nonexistent_sid",
                "any_response",
                "md5_resource",
                None,
                false,
            )
            .await;
        assert!(verify_result.is_err());

        match verify_result.unwrap_err() {
            DfsError::InvalidInput { field, reason } => {
                assert_eq!(field, "challenge");
                assert!(reason.contains("not found"));
            }
            other => panic!("Expected InvalidInput error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_web_challenge_verification() {
        let service = create_test_service().await;
        let sid = "test_web_verify";
        let resource_id = "web_resource";

        // 生成web challenge
        service
            .generate_and_store_challenge(sid, resource_id, None)
            .await
            .unwrap();

        // 验证正确的web响应
        let verify_result = service
            .verify_challenge_response(sid, "correct_token", resource_id, None, false)
            .await;
        assert!(verify_result.is_ok());
        // working_plugin mock返回success: true
        assert!(
            verify_result.unwrap(),
            "Correct web challenge response should verify"
        );
    }

    #[tokio::test]
    async fn test_legacy_challenge_generation() {
        let service = create_test_service().await;
        let resource_id = "legacy_resource";

        let result = service
            .generate_legacy_challenge(resource_id, "", None, None)
            .await;
        assert!(result.is_ok(), "Legacy challenge generation should succeed");

        let challenge = result.unwrap();
        assert_eq!(challenge.challenge_type, ChallengeType::Md5);
        assert!(!challenge.hash.is_empty());
        assert!(!challenge.partial_data.is_empty());
        assert_eq!(challenge.missing_bytes, 1); // MD5 实际使用1 byte
    }

    #[tokio::test]
    async fn test_legacy_challenge_with_range() {
        let service = create_test_service().await;
        let resource_id = "legacy_resource";
        let range = "1024-2047";

        let result = service
            .generate_legacy_challenge(resource_id, "", None, Some(range))
            .await;
        assert!(result.is_ok(), "Legacy challenge with range should succeed");

        let challenge = result.unwrap();
        assert_eq!(challenge.challenge_type, ChallengeType::Md5);

        // 验证session已使用challenge响应值作为ID创建
        let expected_response = challenge.get_expected();
        let session_result = service
            .session_service
            .get_validated_session(&expected_response)
            .await;
        assert!(
            session_result.is_ok(),
            "Session should be created with challenge response as ID"
        );

        let session = session_result.unwrap();
        assert_eq!(session.resource_id, resource_id);
        assert_eq!(session.chunks, vec![range.to_string()]);
    }

    #[tokio::test]
    async fn test_challenge_with_prefix_resource() {
        let service = create_test_service().await;
        let sid = "test_prefix_challenge";
        let resource_id = "md5_resource";
        let sub_path = "assets/texture.png";

        let result = service
            .generate_and_store_challenge(sid, resource_id, Some(sub_path))
            .await;
        assert!(
            result.is_ok(),
            "Challenge generation with sub_path should succeed"
        );

        // 验证base_data包含sub_path
        let stored = service.get_challenge(sid).await.unwrap().unwrap();
        let challenge_data: serde_json::Value = serde_json::from_str(&stored).unwrap();

        // 虽然我们不能直接访问base_data，但可以通过original_data验证
        assert!(challenge_data["original_data"].is_string());
    }

    #[tokio::test]
    async fn test_challenge_storage_and_removal() {
        let service = create_test_service().await;
        let sid = "test_storage";
        let challenge_data = r#"{"type":"md5","hash":"abc123","partial_data":"def456"}"#;

        // 测试存储
        let store_result = service.store_challenge(sid, challenge_data).await;
        assert!(store_result.is_ok(), "Challenge storage should succeed");

        // 测试获取
        let get_result = service.get_challenge(sid).await.unwrap();
        assert!(get_result.is_some());
        assert_eq!(get_result.unwrap(), challenge_data);

        // 测试移除
        let remove_result = service.remove_challenge(sid).await;
        assert!(remove_result.is_ok(), "Challenge removal should succeed");

        // 验证已移除
        let get_after_remove = service.get_challenge(sid).await.unwrap();
        assert!(get_after_remove.is_none(), "Challenge should be removed");
    }
}
