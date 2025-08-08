use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use tokio::fs::{OpenOptions, create_dir_all};
use tokio::io::AsyncWriteExt;
use tracing::{error, warn};

use crate::config::SharedConfig;
use crate::models::InsightData;
use crate::modules::analytics::models::*;
use crate::modules::storage::data_store::DataStore;
use crate::modules::storage::data_store::SessionStats;

pub struct SessionLogger {
    config: SharedConfig,
    redis: DataStore,
    log_path: String,
}

impl SessionLogger {
    pub fn new(config: SharedConfig, redis: DataStore) -> Self {
        let log_path =
            std::env::var("SESSION_LOG_PATH").unwrap_or_else(|_| "logs/sessions".to_string());

        Self {
            config,
            redis,
            log_path,
        }
    }

    /// 记录正常完成的 Session
    pub async fn log_session_completed(
        &self,
        session_id: &str,
        resource_id: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
        insights: Option<InsightData>,
    ) -> Result<(), String> {
        let session_stats = self
            .redis
            .get_session_stats(session_id)
            .await
            .map_err(|e| format!("Failed to get session stats: {}", e))?;

        if let Some(stats) = session_stats {
            let session_log = self
                .build_session_log(
                    "session_completed",
                    Some(session_id.to_string()),
                    resource_id,
                    client_ip,
                    user_agent,
                    &stats,
                    insights,
                    "client_terminated",
                )
                .await?;

            self.write_log(&session_log).await
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    /// 记录超时的 Session
    pub async fn log_session_timeout(
        &self,
        session_id: &str,
        resource_id: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
    ) -> Result<(), String> {
        let session_stats = self
            .redis
            .get_session_stats(session_id)
            .await
            .map_err(|e| format!("Failed to get session stats: {}", e))?;

        if let Some(stats) = session_stats {
            let session_log = self
                .build_session_log(
                    "session_timeout",
                    Some(session_id.to_string()),
                    resource_id,
                    client_ip,
                    user_agent,
                    &stats,
                    None,
                    "timeout",
                )
                .await?;

            self.write_log(&session_log).await
        } else {
            warn!(
                "Session {} not found when trying to log timeout",
                session_id
            );
            Ok(())
        }
    }

    /// 记录直接下载
    pub async fn log_direct_download(
        &self,
        resource_id: &str,
        version: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
        cdn_url: &str,
        server_id: &str,
        server_weight: u32,
    ) -> Result<(), String> {
        let now = Utc::now();

        // 构建直接下载的会话统计
        let session_stats = SessionStatsLog {
            created_at: now.to_rfc3339(),
            completed_at: Some(now.to_rfc3339()),
            timeout_at: None,
            duration_ms: 0,
            total_chunks: 1,
            successful_downloads: 1,
            failed_downloads: 0,
            success_rate: 1.0,
            completion_reason: "direct_download".to_string(),
        };

        // 构建CDN记录
        let cdn_record = CdnRecordLog {
            url: cdn_url.to_string(),
            server_id: server_id.to_string(),
            server_weight,
            timestamp: now.to_rfc3339(),
            skip_penalty: false,
            selection_reason: "flow_selected".to_string(),
        };

        let chunk = ChunkLog {
            range: "full_file".to_string(),
            download_attempts: 1,
            cdn_records: vec![cdn_record],
        };

        let mut server_usage = HashMap::new();
        server_usage.insert(server_id.to_string(), 1u32);

        let session_log = SessionLog {
            timestamp: now.to_rfc3339(),
            log_type: "direct_download".to_string(),
            session_id: None,
            resource_id: resource_id.to_string(),
            version: version.to_string(),
            client_ip: client_ip.to_string(),
            user_agent,
            geo_info: GeoInfo::from_ip(client_ip),
            download_policy: "free".to_string(),
            session_stats,
            chunks: vec![chunk],
            server_usage_summary: server_usage,
            client_insights: None,
        };

        self.write_log(&session_log).await
    }

    /// 记录缓存命中的下载
    pub async fn log_cached_download(
        &self,
        resource_id: &str,
        version: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
        _file_size: u64,
        _cache_max_age: u32,
        _etag: &str,
    ) -> Result<(), String> {
        let now = Utc::now();

        // 构建缓存下载的会话统计
        let session_stats = SessionStatsLog {
            created_at: now.to_rfc3339(),
            completed_at: Some(now.to_rfc3339()),
            timeout_at: None,
            duration_ms: 0,
            total_chunks: 1,
            successful_downloads: 1,
            failed_downloads: 0,
            success_rate: 1.0,
            completion_reason: "cached_download".to_string(),
        };

        // 缓存命中不记录CDN记录，创建空的chunk信息
        let chunk = ChunkLog {
            range: "full_file".to_string(),
            download_attempts: 0, // 缓存命中无需下载尝试
            cdn_records: vec![],  // 缓存命中不记录CDN记录
        };

        let session_log = SessionLog {
            timestamp: now.to_rfc3339(),
            log_type: "cached_download".to_string(),
            session_id: None,
            resource_id: resource_id.to_string(),
            version: version.to_string(),
            client_ip: client_ip.to_string(),
            user_agent,
            geo_info: GeoInfo::from_ip(client_ip),
            download_policy: "free".to_string(), // 缓存下载通常是free模式
            session_stats,
            chunks: vec![chunk],
            server_usage_summary: HashMap::new(), // 缓存命中无服务器使用
            client_insights: None,
        };

        self.write_log(&session_log).await
    }

    /// 构建 Session 日志
    async fn build_session_log(
        &self,
        log_type: &str,
        session_id: Option<String>,
        resource_id: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
        stats: &SessionStats,
        insights: Option<InsightData>,
        completion_reason: &str,
    ) -> Result<SessionLog, String> {
        let config_guard = self.config.load();
        let resource_config = config_guard
            .get_resource(resource_id)
            .ok_or_else(|| format!("Resource {} not found", resource_id))?;

        let now = Utc::now();
        let created_at = now.to_rfc3339(); // 暂时使用当前时间，后续可以从 Redis 获取创建时间

        // 构建会话统计
        let total_chunks = stats.chunks.len() as u32;
        let successful_downloads = stats.download_counts.len() as u32;
        let failed_downloads = if total_chunks >= successful_downloads {
            total_chunks - successful_downloads
        } else {
            0
        };

        let session_stats = SessionStatsLog {
            created_at: created_at.clone(),
            completed_at: if log_type == "session_timeout" {
                None
            } else {
                Some(now.to_rfc3339())
            },
            timeout_at: if log_type == "session_timeout" {
                Some(now.to_rfc3339())
            } else {
                None
            },
            duration_ms: 0, // 暂时设为0，后续可以计算实际时长
            total_chunks,
            successful_downloads,
            failed_downloads,
            success_rate: SessionStatsLog::calculate_success_rate(
                successful_downloads,
                total_chunks,
            ),
            completion_reason: completion_reason.to_string(),
        };

        // 构建分块信息
        let mut chunks = Vec::new();
        let mut server_usage = HashMap::new();

        for chunk_id in &stats.chunks {
            let download_attempts = stats.download_counts.get(chunk_id).unwrap_or(&0);
            let empty_records = Vec::new();
            let cdn_records = stats.cdn_records.get(chunk_id).unwrap_or(&empty_records);

            let cdn_record_logs: Vec<CdnRecordLog> = cdn_records
                .iter()
                .map(|record| {
                    // 统计服务器使用
                    if let Some(server_id) = &record.server_id {
                        *server_usage.entry(server_id.clone()).or_insert(0) += 1;
                    }

                    CdnRecordLog {
                        url: record.url.clone(),
                        server_id: record
                            .server_id
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                        server_weight: record.weight,
                        timestamp: DateTime::from_timestamp(record.timestamp as i64, 0)
                            .unwrap_or_else(|| Utc::now())
                            .to_rfc3339(),
                        skip_penalty: record.skip_penalty,
                        selection_reason: if record.skip_penalty {
                            "retry_fallback"
                        } else {
                            "flow_selected"
                        }
                        .to_string(),
                    }
                })
                .collect();

            chunks.push(ChunkLog {
                range: chunk_id.clone(),
                download_attempts: *download_attempts,
                cdn_records: cdn_record_logs,
            });
        }

        // 构建客户端洞察数据
        let client_insights = insights.map(|data| ClientInsightsLog {
            bandwidth_stats: Some(data.bandwidth),
            ttfb_stats: Some(data.ttfb),
        });

        // 确定下载策略
        let download_policy = match resource_config.download {
            crate::config::DownloadPolicy::Enabled => "enabled",
            crate::config::DownloadPolicy::Free => "free",
            crate::config::DownloadPolicy::Disabled => "disabled",
        }
        .to_string();

        Ok(SessionLog {
            timestamp: now.to_rfc3339(),
            log_type: log_type.to_string(),
            session_id,
            resource_id: resource_id.to_string(),
            version: resource_config.latest.clone(),
            client_ip: client_ip.to_string(),
            user_agent,
            geo_info: GeoInfo::from_ip(client_ip),
            download_policy,
            session_stats,
            chunks,
            server_usage_summary: server_usage,
            client_insights,
        })
    }

    /// 写入日志文件
    async fn write_log(&self, session_log: &SessionLog) -> Result<(), String> {
        if !self.is_enabled() {
            return Ok(());
        }

        // 创建日志目录
        if let Err(e) = create_dir_all(&self.log_path).await {
            error!("Failed to create log directory {}: {}", self.log_path, e);
            return Err(format!("Failed to create log directory: {}", e));
        }

        // 生成日志文件名（按日期分割）
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let log_file = Path::new(&self.log_path).join(format!("sessions.{}.log", date));

        // 序列化为 JSON
        let log_json = match serde_json::to_string(session_log) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize session log: {}", e);
                return Err(format!("Failed to serialize log: {}", e));
            }
        };

        // 写入文件（追加模式）
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .await
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(format!("{}\n", log_json).as_bytes()).await {
                    error!("Failed to write to log file {:?}: {}", log_file, e);
                    return Err(format!("Failed to write to log file: {}", e));
                }
                if let Err(e) = file.sync_all().await {
                    warn!("Failed to sync log file {:?}: {}", log_file, e);
                }
            }
            Err(e) => {
                error!("Failed to open log file {:?}: {}", log_file, e);
                return Err(format!("Failed to open log file: {}", e));
            }
        }

        Ok(())
    }

    /// 检查是否启用日志记录
    pub fn is_enabled(&self) -> bool {
        std::env::var("SESSION_LOG_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true)
    }
}
