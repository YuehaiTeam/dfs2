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
            .map_err(|e| DfsError::internal_error(format!("Failed to store session: {}", e)))
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
                        format!("{}-", start)
                    } else {
                        format!("{}-{}", start, end)
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
                format!("{}-", start)
            } else {
                format!("{}-{}", start, end)
            };

            if !allowed_chunks.contains(&range_str) {
                return Err(DfsError::invalid_input(
                    "range",
                    format!("Range '{}' not allowed in session", range_str),
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
            .map_err(|e| DfsError::internal_error(format!("Failed to record CDN selection: {}", e)))
    }

    /// 删除session，统一封装删除逻辑
    pub async fn remove_session(&self, session_id: &str) -> DfsResult<()> {
        self.data_store
            .remove_session(session_id)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to remove session: {}", e)))
    }

    /// 刷新session过期时间
    pub async fn refresh_session(&self, session_id: &str) -> DfsResult<()> {
        self.data_store
            .refresh_session(session_id)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to refresh session: {}", e)))
    }

    /// 获取session统计信息
    pub async fn get_session_stats(
        &self,
        session_id: &str,
    ) -> DfsResult<Option<crate::modules::storage::data_store::SessionStats>> {
        self.data_store
            .get_session_stats(session_id)
            .await
            .map_err(|e| DfsError::internal_error(format!("Failed to get session stats: {}", e)))
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

        let options = FlowOptions {
            cdn_full_range: false, // Session场景一般不使用full_range
        };

        // 6. 执行Flow（纯函数）
        let flow_result = flow_service
            .execute_flow(&target, &context, &options, flow_items, penalty_servers)
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
