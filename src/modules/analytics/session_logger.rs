use chrono::Utc;
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
            .map_err(|e| format!("Failed to get session stats: {e}"))?;

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
                )
                .await?;

            self.write_log(&session_log).await
        } else {
            Err(format!("Session {session_id} not found"))
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
            .map_err(|e| format!("Failed to get session stats: {e}"))?;

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

        // 构建CDN记录
        let cdn_record = CdnRecordLog {
            url: cdn_url.to_string(),
            srv: Some(server_id.to_string()),
            wgt: Some(server_weight),
            ts: now.timestamp() as u64,
            pen: Some(false),
            rsn: Some("flow_selected".to_string()),
            ttfb: None,
            time: None,
            size: None,
            err: None,
            mode: None,
        };

        let chunk = ChunkLog {
            rng: "full_file".to_string(),
            att: 1,
            cdns: vec![cdn_record],
        };

        let session_log = SessionLog {
            start: now.timestamp() as u64, // direct download没有真正的session创建时间
            end: now.timestamp() as u64,
            log_type: "direct_download".to_string(),
            sid: None,
            rid: resource_id.to_string(),
            ver: version.to_string(),
            ua: user_agent,
            ip: (
                client_ip.to_string(),
                crate::modules::external::geolocation::get_ip_location_data(client_ip),
            ),
            chunks: vec![chunk],
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

        // 缓存命中不记录CDN记录，创建空的chunk信息
        let chunk = ChunkLog {
            rng: "full_file".to_string(),
            att: 0,       // 缓存命中无需下载尝试
            cdns: vec![], // 缓存命中不记录CDN记录
        };

        let session_log = SessionLog {
            start: now.timestamp() as u64, // cached download没有真正的session创建时间
            end: now.timestamp() as u64,
            log_type: "cached_download".to_string(),
            sid: None,
            rid: resource_id.to_string(),
            ver: version.to_string(),
            ua: user_agent,
            ip: (
                client_ip.to_string(),
                crate::modules::external::geolocation::get_ip_location_data(client_ip),
            ),
            chunks: vec![chunk],
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
    ) -> Result<SessionLog, String> {
        let config_guard = self.config.load();
        let resource_config = config_guard
            .get_resource(resource_id)
            .ok_or_else(|| format!("Resource {resource_id} not found"))?;

        let now = Utc::now();

        // 构建分块信息和客户端数据匹配
        let mut chunks = Vec::new();
        let mut unmatched_insights = Vec::new();

        // 收集所有未匹配的客户端数据
        if let Some(insight_data) = &insights {
            unmatched_insights.extend(insight_data.servers.clone());
        }

        for chunk_id in &stats.chunks {
            let download_attempts = stats.download_counts.get(chunk_id).unwrap_or(&0);
            let empty_records = Vec::new();
            let cdn_records = stats.cdn_records.get(chunk_id).unwrap_or(&empty_records);

            let mut cdn_record_logs: Vec<CdnRecordLog> = cdn_records
                .iter()
                .map(|record| {
                    // 尝试匹配客户端数据
                    let mut matched_insight: Option<crate::models::InsightItem> = None;
                    if let Some(insight_data) = &insights {
                        for insight in insight_data.servers.iter() {
                            // 通过URL和range匹配
                            if Self::urls_match(&insight.url, &record.url)
                                && Self::ranges_match(&insight.range, chunk_id)
                            {
                                matched_insight = Some(insight.clone());
                                // 从未匹配列表中移除
                                if let Some(pos) = unmatched_insights
                                    .iter()
                                    .position(|x| x.url == insight.url && x.range == insight.range)
                                {
                                    unmatched_insights.remove(pos);
                                }
                                break;
                            }
                        }
                    }

                    CdnRecordLog {
                        url: record.url.clone(),
                        srv: record.server_id.clone(),
                        wgt: Some(record.weight),
                        ts: record.timestamp,
                        pen: Some(record.skip_penalty),
                        rsn: Some(
                            if record.skip_penalty {
                                "retry_fallback"
                            } else {
                                "flow_selected"
                            }
                            .to_string(),
                        ),
                        ttfb: matched_insight.as_ref().map(|i| i.ttfb),
                        time: matched_insight.as_ref().map(|i| i.time),
                        size: matched_insight.as_ref().map(|i| i.size),
                        err: matched_insight.as_ref().and_then(|i| i.error.clone()),
                        mode: matched_insight.as_ref().and_then(|i| i.mode.clone()),
                    }
                })
                .collect();

            // 为当前chunk添加未匹配的客户端记录
            for insight in unmatched_insights.iter() {
                if Self::ranges_match(&insight.range, chunk_id) {
                    cdn_record_logs.push(CdnRecordLog {
                        url: insight.url.clone(),
                        srv: None, // 客户端记录没有服务器信息
                        wgt: None,
                        ts: now.timestamp() as u64, // 使用当前时间
                        pen: None,
                        rsn: None,
                        ttfb: Some(insight.ttfb),
                        time: Some(insight.time),
                        size: Some(insight.size),
                        err: insight.error.clone(),
                        mode: insight.mode.clone(),
                    });
                }
            }

            // 从未匹配列表中移除已处理的项
            unmatched_insights.retain(|insight| !Self::ranges_match(&insight.range, chunk_id));

            chunks.push(ChunkLog {
                rng: chunk_id.clone(),
                att: *download_attempts,
                cdns: cdn_record_logs,
            });
        }

        // 处理剩余未匹配的客户端数据（创建新的chunk）
        let mut additional_chunks = HashMap::<String, Vec<crate::models::InsightItem>>::new();
        for insight in unmatched_insights {
            for (start, end) in &insight.range {
                let range_str = format!("{}-{}", start, end);
                additional_chunks
                    .entry(range_str)
                    .or_insert_with(Vec::new)
                    .push(insight.clone());
            }
        }

        for (range_str, insight_items) in additional_chunks {
            let cdn_records: Vec<CdnRecordLog> = insight_items
                .into_iter()
                .map(|insight| CdnRecordLog {
                    url: insight.url,
                    srv: None,
                    wgt: None,
                    ts: now.timestamp() as u64,
                    pen: None,
                    rsn: None,
                    ttfb: Some(insight.ttfb),
                    time: Some(insight.time),
                    size: Some(insight.size),
                    err: insight.error,
                    mode: insight.mode,
                })
                .collect();

            chunks.push(ChunkLog {
                rng: range_str,
                att: 0, // 客户端记录没有服务端下载尝试
                cdns: cdn_records,
            });
        }

        Ok(SessionLog {
            start: stats.created_at,
            end: now.timestamp() as u64,
            log_type: log_type.to_string(),
            sid: session_id,
            rid: resource_id.to_string(),
            ver: resource_config.latest.clone(),
            ua: user_agent,
            ip: (
                client_ip.to_string(),
                crate::modules::external::geolocation::get_ip_location_data(client_ip),
            ),
            chunks,
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
            return Err(format!("Failed to create log directory: {e}"));
        }

        // 生成日志文件名（按日期分割）
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let log_file = Path::new(&self.log_path).join(format!("sessions.{date}.log"));

        // 序列化为 JSON
        let log_json = match serde_json::to_string(session_log) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize session log: {}", e);
                return Err(format!("Failed to serialize log: {e}"));
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
                if let Err(e) = file.write_all(format!("{log_json}\n").as_bytes()).await {
                    error!("Failed to write to log file {:?}: {}", log_file, e);
                    return Err(format!("Failed to write to log file: {e}"));
                }
                if let Err(e) = file.sync_all().await {
                    warn!("Failed to sync log file {:?}: {}", log_file, e);
                }
            }
            Err(e) => {
                error!("Failed to open log file {:?}: {}", log_file, e);
                return Err(format!("Failed to open log file: {e}"));
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

    /// 检查两个URL是否匹配（忽略签名参数等差异）
    fn urls_match(insight_url: &str, cdn_url: &str) -> bool {
        // 简单的URL匹配，可以根据需要增强
        // 目前只做基本的字符串匹配，将来可以添加更智能的匹配逻辑
        insight_url == cdn_url
            || Self::extract_base_url(insight_url) == Self::extract_base_url(cdn_url)
    }

    /// 提取URL的基础部分（去除查询参数）
    fn extract_base_url(url: &str) -> &str {
        if let Some(pos) = url.find('?') {
            &url[..pos]
        } else {
            url
        }
    }

    /// 检查客户端range是否与chunk_id完全匹配
    fn ranges_match(client_ranges: &[(u32, u32)], chunk_id: &str) -> bool {
        // 将客户端ranges转换为标准化的字符串格式
        let client_range_str = Self::ranges_to_string(client_ranges);

        // 直接比较字符串
        client_range_str == chunk_id
    }

    /// 将range列表转换为标准字符串格式
    fn ranges_to_string(ranges: &[(u32, u32)]) -> String {
        if ranges.is_empty() {
            return String::new();
        }

        // 按起始位置排序
        let mut sorted_ranges = ranges.to_vec();
        sorted_ranges.sort_by_key(|&(start, _)| start);

        // 转换为字符串格式
        if sorted_ranges.len() == 1 {
            // 单个range: "start-end"
            format!("{}-{}", sorted_ranges[0].0, sorted_ranges[0].1)
        } else {
            // 多个range: "start1-end1,start2-end2,..."
            sorted_ranges
                .iter()
                .map(|(start, end)| format!("{}-{}", start, end))
                .collect::<Vec<_>>()
                .join(",")
        }
    }
}
