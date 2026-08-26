use crate::{
    container::MAX_CHUNK_DOWNLOADS,
    error::{DfsError, DfsResult},
    models::{CdnRecord, FlowPenalties, Session},
    models::{FlowContext, FlowOptions, FlowResult, FlowTarget},
    modules::flow::FlowItem,
    modules::network::ClientCapabilities,
    modules::storage::data_store::DataStore,
    services::FlowService,
};
use std::collections::HashMap;
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
                if session.is_direct_expired(chrono::Utc::now().timestamp() as u64) {
                    if let Err(e) = self.remove_session(session_id).await {
                        tracing::warn!(
                            "Failed to remove expired direct session {}: {}",
                            session_id,
                            e
                        );
                    }
                    return Err(DfsError::SessionNotFound {
                        session_id: session_id.to_string(),
                    });
                }

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

    /// 记录一次下载尝试。`None` 只表示会话不存在，不表示计数键未预注册。
    pub async fn record_download_attempt(&self, session_id: &str, range: &str) -> DfsResult<u32> {
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

                Ok(count)
            }
            None => Err(DfsError::SessionNotFound {
                session_id: session_id.to_string(),
            }),
        }
    }

    /// 记录并限制分块或受保护下载的重试次数。
    pub async fn check_download_limit(&self, session_id: &str, range: &str) -> DfsResult<u32> {
        let count = self.record_download_attempt(session_id, range).await?;
        if count > *MAX_CHUNK_DOWNLOADS {
            return Err(DfsError::invalid_input(
                "download_count",
                "Too many download attempts",
            ));
        }
        Ok(count)
    }

    /// 下载次数按文件+range 隔离，避免同 sid 下多个文件共享 `0-` 计数。
    pub fn scoped_download_key(sub_path: Option<&str>, range: &str) -> String {
        match sub_path {
            Some(path) if !path.is_empty() => format!("{path}:{range}"),
            _ => range.to_string(),
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

    /// 当前 chunk 再要 URL 时，这些节点应被硬剔除。
    pub async fn get_penalty_servers(
        &self,
        session_id: &str,
        chunk_key: &str,
    ) -> DfsResult<Vec<String>> {
        match self.data_store.get_cdn_records(session_id, chunk_key).await {
            Ok(previous_records) => {
                let mut records = HashMap::new();
                records.insert(chunk_key.to_string(), previous_records);
                Ok(schedule_penalties_from_records(&records, Some(chunk_key)).banned)
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// 按 sid 汇总：重试换掉的节点硬 ban，仅签过的降权。
    pub async fn get_schedule_penalties(
        &self,
        session_id: &str,
        current_chunk_key: Option<&str>,
    ) -> DfsResult<FlowPenalties> {
        match self.data_store.get_session_stats(session_id).await {
            Ok(Some(stats)) => Ok(schedule_penalties_from_records(
                &stats.cdn_records,
                current_chunk_key,
            )),
            Ok(None) => Ok(FlowPenalties::default()),
            Err(e) => {
                tracing::warn!(
                    "Failed to load schedule penalties for {}: {}",
                    session_id,
                    e
                );
                Ok(FlowPenalties::default())
            }
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
        capabilities: ClientCapabilities,
    ) -> DfsResult<FlowResult> {
        // 1. 直接使用传入的session（无需重复获取）

        // 2. 从ranges生成chunk_key（用于CDN记录；前缀资源按文件隔离）
        let chunk_key = Self::scoped_download_key(
            session.sub_path.as_deref(),
            &self.generate_chunk_key_from_ranges(&requested_ranges),
        );

        // 3. 验证ranges是否在session.chunks中
        self.validate_ranges_against_session(&requested_ranges, &session.chunks)?;

        // 4. 重试才 ban；仅签过的节点降权摊开
        let penalties = self
            .get_schedule_penalties(session_id, Some(&chunk_key))
            .await?;

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
            capabilities,
            internal: false,
        };

        // 6. 执行Flow（纯函数）
        let flow_result = flow_service
            .execute_flow(
                &target,
                &context,
                options,
                flow_items,
                penalties,
                Some(session),
            )
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

    /// Free 下载：文件身份来自请求，惩罚按 sid 跨文件累计。
    pub async fn run_flow_for_sticky_download(
        &self,
        session: &Session,
        session_id: &str,
        target: &crate::models::FlowTarget,
        flow_service: &FlowService,
        context: &FlowContext,
        options: &FlowOptions,
        flow_items: &[FlowItem],
    ) -> DfsResult<FlowResult> {
        let chunk_key = Self::scoped_download_key(
            target.sub_path.as_deref(),
            &self.generate_chunk_key_from_ranges(target.ranges.as_deref().unwrap_or(&[])),
        );
        let penalties = self
            .get_schedule_penalties(session_id, Some(&chunk_key))
            .await?;
        let flow_result = flow_service
            .execute_flow(
                target,
                context,
                options,
                flow_items,
                penalties,
                Some(session),
            )
            .await?;

        if !flow_result.url.is_empty() {
            let cdn_record = CdnRecord {
                url: flow_result.url.clone(),
                server_id: flow_result.selected_server_id.clone(),
                skip_penalty: false,
                timestamp: chrono::Utc::now().timestamp() as u64,
                weight: flow_result.selected_server_weight.unwrap_or(0),
                size: target.file_size,
            };
            self.record_final_cdn_selection(session_id, &chunk_key, cdn_record)
                .await?;
        }

        Ok(flow_result)
    }
}

fn push_unique(servers: &mut Vec<String>, server_id: String) {
    if !servers.contains(&server_id) {
        servers.push(server_id);
    }
}

fn record_server_ids(records: &[CdnRecord]) -> Vec<String> {
    let mut servers = Vec::new();
    for record in records {
        if record.skip_penalty {
            continue;
        }
        if let Some(server_id) = &record.server_id {
            servers.push(server_id.clone());
        }
    }
    servers
}

/// 重试才进 banned；其它 chunk 上只签过一次的进 demoted。
fn schedule_penalties_from_records(
    records_by_chunk: &HashMap<String, Vec<CdnRecord>>,
    current_chunk_key: Option<&str>,
) -> FlowPenalties {
    let mut banned = Vec::new();
    let mut demoted = Vec::new();

    for (chunk_key, records) in records_by_chunk {
        let servers = record_server_ids(records);
        if servers.is_empty() {
            continue;
        }

        if current_chunk_key == Some(chunk_key.as_str()) {
            for server_id in servers {
                push_unique(&mut banned, server_id);
            }
            continue;
        }

        if servers.len() >= 2 {
            for server_id in &servers[..servers.len() - 1] {
                push_unique(&mut banned, server_id.clone());
            }
            push_unique(&mut demoted, servers[servers.len() - 1].clone());
        } else {
            push_unique(&mut demoted, servers[0].clone());
        }
    }

    demoted.retain(|server_id| !banned.contains(server_id));
    FlowPenalties { banned, demoted }
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
            kind: crate::models::SessionKind::Chunk,
            expires_at: None,
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
    async fn test_record_download_attempt_missing_session() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store);

        let err = service
            .record_download_attempt("missing-sid", "0-")
            .await
            .expect_err("missing session must not look like a count-key miss");
        match err {
            DfsError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "missing-sid");
            }
            other => panic!("Expected SessionNotFound, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_record_download_attempt_accepts_unregistered_scoped_key() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store);

        let session_id = "sticky-free-sid";
        let mut session = create_test_session();
        session.chunks = vec!["0-".to_string()];
        service.store_session(session_id, &session).await.unwrap();

        let count = service
            .record_download_attempt(session_id, "a/one.bin:0-")
            .await
            .expect("session exists, so a new scoped count key must be created");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_scoped_download_key_isolates_files() {
        assert_eq!(SessionService::scoped_download_key(None, "0-"), "0-");
        assert_eq!(
            SessionService::scoped_download_key(Some("a/one.bin"), "0-"),
            "a/one.bin:0-"
        );
        assert_ne!(
            SessionService::scoped_download_key(Some("a/one.bin"), "0-"),
            SessionService::scoped_download_key(Some("b/two.bin"), "0-")
        );
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

    #[tokio::test]
    async fn test_sticky_penalty_servers_across_files() {
        let data_store =
            Arc::new(MockDataStore::new()) as crate::modules::storage::data_store::DataStore;
        let service = SessionService::new(data_store.clone());
        let session_id = "sticky_penalty_sid";

        service
            .store_session(session_id, &create_test_session())
            .await
            .unwrap();

        let file1_record = CdnRecord {
            url: "https://a.example.com/file1".to_string(),
            server_id: Some("server_a".to_string()),
            skip_penalty: false,
            timestamp: chrono::Utc::now().timestamp() as u64,
            weight: 20,
            size: Some(100),
        };
        let file2_skip = CdnRecord {
            url: "https://b.example.com/file2".to_string(),
            server_id: Some("server_b".to_string()),
            skip_penalty: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
            weight: 10,
            size: Some(100),
        };

        service
            .record_final_cdn_selection(session_id, "file1:0-", file1_record)
            .await
            .unwrap();
        service
            .record_final_cdn_selection(session_id, "file2:0-", file2_skip)
            .await
            .unwrap();

        let by_chunk = service
            .get_penalty_servers(session_id, "file2:0-")
            .await
            .unwrap();
        assert!(
            by_chunk.is_empty(),
            "per-chunk lookup should not see file1's server"
        );

        let other_file = service
            .get_schedule_penalties(session_id, Some("file2:0-"))
            .await
            .unwrap();
        assert!(
            other_file.banned.is_empty(),
            "first assignment on another file is not a retry"
        );
        assert_eq!(other_file.demoted, vec!["server_a".to_string()]);

        let current_retry = service
            .get_schedule_penalties(session_id, Some("file1:0-"))
            .await
            .unwrap();
        assert_eq!(current_retry.banned, vec!["server_a".to_string()]);
        assert!(current_retry.demoted.is_empty());
    }

    fn test_record(server_id: &str, skip_penalty: bool) -> CdnRecord {
        CdnRecord {
            url: format!("https://{server_id}.example.com/file"),
            server_id: Some(server_id.to_string()),
            skip_penalty,
            timestamp: 1,
            weight: 8,
            size: Some(100),
        }
    }

    #[test]
    fn first_assignments_are_demoted_not_banned() {
        let mut records = HashMap::new();
        for i in 0..23 {
            records.insert(
                format!("{i}-{i}"),
                vec![test_record(&format!("srv{i}"), false)],
            );
        }

        let penalties = schedule_penalties_from_records(&records, Some("new-range"));
        assert!(
            penalties.banned.is_empty(),
            "concurrent first hits must not empty the pool"
        );
        assert_eq!(penalties.demoted.len(), 23);
    }

    #[test]
    fn retry_of_current_chunk_bans_previous_servers() {
        let mut records = HashMap::new();
        records.insert("0-100".to_string(), vec![test_record("telecom", false)]);

        let penalties = schedule_penalties_from_records(&records, Some("0-100"));
        assert_eq!(penalties.banned, vec!["telecom".to_string()]);
        assert!(penalties.demoted.is_empty());
    }

    #[test]
    fn other_chunk_retry_bans_superseded_and_demotes_current() {
        let mut records = HashMap::new();
        records.insert(
            "0-100".to_string(),
            vec![test_record("A", false), test_record("B", false)],
        );

        let penalties = schedule_penalties_from_records(&records, Some("200-300"));
        assert_eq!(penalties.banned, vec!["A".to_string()]);
        assert_eq!(penalties.demoted, vec!["B".to_string()]);
    }

    #[test]
    fn skip_penalty_records_are_ignored() {
        let mut records = HashMap::new();
        records.insert("0-100".to_string(), vec![test_record("skip", true)]);

        let penalties = schedule_penalties_from_records(&records, Some("0-100"));
        assert!(penalties.banned.is_empty());
        assert!(penalties.demoted.is_empty());
    }

    #[test]
    fn banned_wins_over_demoted() {
        let mut records = HashMap::new();
        records.insert(
            "0-100".to_string(),
            vec![test_record("shared", false), test_record("other", false)],
        );
        records.insert("200-300".to_string(), vec![test_record("shared", false)]);

        let penalties = schedule_penalties_from_records(&records, Some("400-500"));
        assert_eq!(penalties.banned, vec!["shared".to_string()]);
        assert_eq!(penalties.demoted, vec!["other".to_string()]);
    }
}
