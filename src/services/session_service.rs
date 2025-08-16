use crate::{
    container::MAX_CHUNK_DOWNLOADS,
    error::{DfsError, DfsResult},
    models::{CdnRecord, Session},
    models::{FlowContext, FlowOptions, FlowResult, FlowTarget},
    modules::flow::FlowItem,
    modules::storage::data_store::DataStore,
    services::FlowService,
};
use std::net::IpAddr;

#[derive(Clone)]
pub struct SessionService {
    data_store: DataStore,
}

impl SessionService {
    pub fn new(data_store: DataStore) -> Self {
        Self { data_store }
    }

    /// 替换所有重复的 get_session 逻辑
    pub async fn get_validated_session(&self, session_id: &str) -> DfsResult<Session> {
        match self.data_store.get_session(session_id).await? {
            Some(session) => {
                // 自动刷新session过期时间
                if let Err(e) = self.refresh_session(session_id).await {
                    tracing::warn!("Failed to refresh session {}: {}", session_id, e);
                }
                Ok(session)
            }
            None => Err(DfsError::SessionNotFound {
                session_id: session_id.to_string(),
            }),
        }
    }

    /// 使用指定session_id存储session（用于用户提供session_id的场景）
    pub async fn store_session(&self, session_id: &str, session: &Session) -> DfsResult<()> {
        self.data_store
            .store_session(session_id, session)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to store session: {e}")))
    }

    /// 统一的下载次数检查逻辑
    pub async fn check_download_limit(&self, session_id: &str, range: &str) -> DfsResult<u32> {
        match self
            .data_store
            .increment_download_count(session_id, range)
            .await?
        {
            Some(count) => {
                // 自动刷新session过期时间
                if let Err(e) = self.refresh_session(session_id).await {
                    tracing::warn!(
                        "Failed to refresh session during download limit check: {}",
                        e
                    );
                }

                if count > *MAX_CHUNK_DOWNLOADS {
                    return Err(DfsError::invalid_input(
                        "download_count",
                        "Too many download attempts",
                    ));
                }
                Ok(count)
            }
            None => Err(DfsError::SessionNotFound {
                session_id: session_id.to_string(),
            }),
        }
    }

    /// 从ranges生成chunk_key
    pub fn generate_chunk_key_from_ranges(&self, ranges: &[(u32, u32)]) -> String {
        if ranges.is_empty() {
            "0-".to_string() // 默认为整个文件
        } else {
            ranges
                .iter()
                .map(|(start, end)| {
                    if *end == u32::MAX {
                        format!("{start}-")
                    } else {
                        format!("{start}-{end}")
                    }
                })
                .collect::<Vec<_>>()
                .join(",")
        }
    }

    /// 验证ranges是否在session.chunks中
    pub fn validate_ranges_against_session(
        &self,
        requested_ranges: &[(u32, u32)],
        allowed_chunks: &[String],
    ) -> DfsResult<()> {
        // 为每个range生成字符串，检查是否在allowed_chunks中
        for (start, end) in requested_ranges {
            let range_str = if *end == u32::MAX {
                format!("{start}-")
            } else {
                format!("{start}-{end}")
            };

            if !allowed_chunks.contains(&range_str) {
                return Err(DfsError::invalid_input(
                    "range",
                    format!("Range '{range_str}' not allowed in session"),
                ));
            }
        }
        Ok(())
    }

    /// 获取需要惩罚的服务器列表
    pub async fn get_penalty_servers(
        &self,
        session_id: &str,
        chunk_key: &str,
    ) -> DfsResult<Vec<String>> {
        match self.data_store.get_cdn_records(session_id, chunk_key).await {
            Ok(previous_records) => {
                let penalty_servers: Vec<String> = previous_records
                    .iter()
                    .filter_map(|record| {
                        if !record.skip_penalty {
                            record.server_id.clone()
                        } else {
                            None
                        }
                    })
                    .collect();
                Ok(penalty_servers)
            }
            Err(_) => Ok(Vec::new()), // 没有历史记录，不进行惩罚
        }
    }

    /// 记录最终CDN选择结果
    pub async fn record_final_cdn_selection(
        &self,
        session_id: &str,
        chunk_key: &str,
        record: CdnRecord,
    ) -> DfsResult<()> {
        self.data_store
            .update_cdn_record_v2(session_id, chunk_key, record)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to record CDN selection: {e}")))
    }

    /// 删除session，统一封装删除逻辑
    pub async fn remove_session(&self, session_id: &str) -> DfsResult<()> {
        self.data_store
            .remove_session(session_id)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to remove session: {e}")))
    }

    /// 刷新session过期时间
    pub async fn refresh_session(&self, session_id: &str) -> DfsResult<()> {
        self.data_store
            .refresh_session(session_id)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to refresh session: {e}")))
    }

    /// 获取session统计信息
    pub async fn get_session_stats(
        &self,
        session_id: &str,
    ) -> DfsResult<Option<crate::modules::storage::data_store::SessionStats>> {
        self.data_store
            .get_session_stats(session_id)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to get session stats: {e}")))
    }

    /// Session场景的Flow执行包装函数
    /// 处理CDN记录、惩罚查询等复杂逻辑（调用方需要先获取session）
    pub async fn run_flow_for_session(
        &self,
        session: &Session,
        session_id: &str, // 仍需要session_id用于CDN记录和penalty查询
        requested_ranges: Vec<(u32, u32)>, // 解析后的ranges
        flow_service: &FlowService,
        client_ip: Option<IpAddr>,
        file_size: Option<u64>,
        flow_items: &[FlowItem],
        options: &FlowOptions,
    ) -> DfsResult<FlowResult> {
        // 1. 直接使用传入的session（无需重复获取）

        // 2. 从ranges生成chunk_key（用于CDN记录）
        let chunk_key = self.generate_chunk_key_from_ranges(&requested_ranges);

        // 3. 验证ranges是否在session.chunks中
        self.validate_ranges_against_session(&requested_ranges, &session.chunks)?;

        // 4. 获取需要惩罚的服务器列表
        let penalty_servers = self.get_penalty_servers(session_id, &chunk_key).await?;

        // 5. 构建Flow参数
        let target = FlowTarget {
            resource_id: session.resource_id.clone(),
            version: session.version.clone(),
            sub_path: session.sub_path.clone(), // 从session读取
            ranges: if requested_ranges.is_empty() {
                None
            } else {
                Some(requested_ranges)
            },
            file_size,
        };

        let context = FlowContext {
            client_ip,
            session_id: Some(session_id.to_string()),
            extras: session.extras.clone(),
        };

        // 6. 执行Flow（纯函数）
        let flow_result = flow_service
            .execute_flow(&target, &context, options, flow_items, penalty_servers)
            .await?;

        // 7. 记录最终CDN结果
        if !flow_result.url.is_empty() {
            let cdn_record = CdnRecord {
                url: flow_result.url.clone(),
                server_id: flow_result.selected_server_id.clone(),
                skip_penalty: false, // 默认不跳过惩罚
                timestamp: chrono::Utc::now().timestamp() as u64,
                weight: flow_result.selected_server_weight.unwrap_or(0),
                size: file_size,
            };

            self.record_final_cdn_selection(session_id, &chunk_key, cdn_record)
                .await?;
        }

        Ok(flow_result)
    }
}

pub fn generate_session_id() -> String {
    use rand::RngCore;
    let mut rng = rand::rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::mocks::MockDataStore;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn create_test_session() -> Session {
        Session {
            resource_id: "test_resource".to_string(),
            version: "1.0.0".to_string(),
            chunks: vec!["0-1023".to_string(), "1024-2047".to_string()],
            sub_path: None,
            cdn_records: HashMap::new(),
            extras: json!({
                "client_ip": "192.168.1.100"
            }),
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    #[tokio::test]
    async fn test_session_storage_and_retrieval() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store);

        let session_id = "test_session_123";
        let session = create_test_session();

        // 测试存储会话
        let result = service.store_session(session_id, &session).await;
        assert!(result.is_ok(), "Failed to store session: {:?}", result);

        // 测试获取会话
        let retrieved = service.get_validated_session(session_id).await;
        assert!(
            retrieved.is_ok(),
            "Failed to retrieve session: {:?}",
            retrieved
        );

        let retrieved_session = retrieved.unwrap();
        assert_eq!(retrieved_session.resource_id, "test_resource");
        assert_eq!(retrieved_session.version, "1.0.0");
        assert_eq!(retrieved_session.chunks.len(), 2);
    }

    #[tokio::test]
    async fn test_session_not_found() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store);

        let result = service.get_validated_session("nonexistent_session").await;
        assert!(result.is_err());

        match result.unwrap_err() {
            DfsError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "nonexistent_session");
            }
            other => panic!("Expected SessionNotFound error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_download_limit_check() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store.clone());

        let session_id = "download_limit_test";
        let session = create_test_session();

        // 存储会话
        service.store_session(session_id, &session).await.unwrap();

        // 测试正常的下载次数增加
        for i in 1..=3 {
            let result = service.check_download_limit(session_id, "0-1023").await;
            assert!(
                result.is_ok(),
                "Download count check failed at iteration {}: {:?}",
                i,
                result
            );
            assert_eq!(result.unwrap(), i);
        }

        // 测试超过限制（MAX_CHUNK_DOWNLOADS = 3）
        let result = service.check_download_limit(session_id, "0-1023").await;
        assert!(result.is_err(), "Should fail when exceeding download limit");

        match result.unwrap_err() {
            DfsError::InvalidInput { field, reason } => {
                assert_eq!(field, "download_count");
                assert!(reason.contains("Too many download attempts"));
            }
            other => panic!("Expected InvalidInput error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_chunk_key_generation() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store);

        // 测试单个范围
        let ranges = vec![(0, 1023)];
        let chunk_key = service.generate_chunk_key_from_ranges(&ranges);
        assert_eq!(chunk_key, "0-1023");

        // 测试多个范围
        let ranges = vec![(0, 1023), (1024, 2047)];
        let chunk_key = service.generate_chunk_key_from_ranges(&ranges);
        assert_eq!(chunk_key, "0-1023,1024-2047");

        // 测试开放范围
        let ranges = vec![(1024, u32::MAX)];
        let chunk_key = service.generate_chunk_key_from_ranges(&ranges);
        assert_eq!(chunk_key, "1024-");

        // 测试空范围
        let ranges = vec![];
        let chunk_key = service.generate_chunk_key_from_ranges(&ranges);
        assert_eq!(chunk_key, "0-");
    }

    #[tokio::test]
    async fn test_ranges_validation() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store);

        let allowed_chunks = vec!["0-1023".to_string(), "1024-2047".to_string()];

        // 测试有效范围
        let valid_ranges = vec![(0, 1023), (1024, 2047)];
        let result = service.validate_ranges_against_session(&valid_ranges, &allowed_chunks);
        assert!(result.is_ok(), "Valid ranges should pass validation");

        // 测试无效范围
        let invalid_ranges = vec![(0, 1023), (2048, 4095)]; // 2048-4095 不在允许列表中
        let result = service.validate_ranges_against_session(&invalid_ranges, &allowed_chunks);
        assert!(result.is_err(), "Invalid ranges should fail validation");
    }

    #[tokio::test]
    async fn test_penalty_servers_retrieval() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store.clone());

        let session_id = "penalty_test";

        // 添加CDN记录（一个会被惩罚，一个跳过惩罚）
        let penalty_record = CdnRecord {
            url: "https://penalty-server.com/file".to_string(),
            server_id: Some("penalty_server".to_string()),
            skip_penalty: false,
            timestamp: chrono::Utc::now().timestamp() as u64,
            weight: 800,
            size: Some(1024),
        };

        let skip_penalty_record = CdnRecord {
            url: "https://skip-server.com/file".to_string(),
            server_id: Some("skip_server".to_string()),
            skip_penalty: true, // 跳过惩罚
            timestamp: chrono::Utc::now().timestamp() as u64,
            weight: 600,
            size: Some(1024),
        };

        data_store
            .update_cdn_record_v2(session_id, "0-1023", penalty_record)
            .await
            .unwrap();
        data_store
            .update_cdn_record_v2(session_id, "0-1023", skip_penalty_record)
            .await
            .unwrap();

        // 获取惩罚服务器列表
        let penalty_servers = service
            .get_penalty_servers(session_id, "0-1023")
            .await
            .unwrap();

        // 应该只包含不跳过惩罚的服务器
        assert_eq!(penalty_servers.len(), 1);
        assert_eq!(penalty_servers[0], "penalty_server");
    }

    #[tokio::test]
    async fn test_session_id_generation() {
        // 测试生成的session ID格式
        let session_id1 = generate_session_id();
        let session_id2 = generate_session_id();

        // 应该是32个字符的十六进制字符串
        assert_eq!(session_id1.len(), 32);
        assert_eq!(session_id2.len(), 32);

        // 两次生成应该不同
        assert_ne!(session_id1, session_id2);

        // 应该只包含十六进制字符
        for c in session_id1.chars() {
            assert!(
                c.is_ascii_hexdigit(),
                "Session ID should only contain hex characters"
            );
        }
    }

    #[tokio::test]
    async fn test_final_cdn_recording() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store.clone());

        let session_id = "cdn_record_test";
        let chunk_key = "0-1023";

        let cdn_record = CdnRecord {
            url: "https://final-server.com/file".to_string(),
            server_id: Some("final_server".to_string()),
            skip_penalty: false,
            timestamp: chrono::Utc::now().timestamp() as u64,
            weight: 900,
            size: Some(1024),
        };

        // 记录最终CDN选择
        let result = service
            .record_final_cdn_selection(session_id, chunk_key, cdn_record.clone())
            .await;
        assert!(
            result.is_ok(),
            "Failed to record final CDN selection: {:?}",
            result
        );

        // 验证记录已保存
        let records = data_store
            .get_cdn_records(session_id, chunk_key)
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].url, cdn_record.url);
        assert_eq!(records[0].server_id, cdn_record.server_id);
    }
}
