use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
// use tokio::time::sleep;
use tracing::{error, info};

use crate::app_state::DataStore;
use crate::config::AppConfig;
use crate::analytics::SessionLogger;

pub struct SessionCleanupTask {
    config: Arc<RwLock<AppConfig>>,
    redis: DataStore,
    logger: SessionLogger,
}

impl SessionCleanupTask {
    pub fn new(config: Arc<RwLock<AppConfig>>, redis: DataStore) -> Self {
        let logger = SessionLogger::new(config.clone(), redis.clone());
        
        Self {
            config,
            redis,
            logger,
        }
    }

    /// 启动清理任务（后台运行）
    pub async fn start_background_task(self: Arc<Self>) {
        if !self.is_enabled() {
            info!("Session cleanup task is disabled");
            return;
        }

        let interval_minutes = self.get_cleanup_interval();
        info!("Starting session cleanup task with interval: {} minutes", interval_minutes);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_minutes * 60));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = self.run_cleanup().await {
                    error!("Session cleanup task failed: {}", e);
                } else {
                    info!("Session cleanup task completed successfully");
                }
            }
        });
    }

    /// 执行一次清理任务
    pub async fn run_cleanup(&self) -> Result<(), String> {
        info!("Running session cleanup task");

        // 获取所有过期的会话ID
        let expired_sessions = self.find_expired_sessions().await?;
        
        if expired_sessions.is_empty() {
            info!("No expired sessions found");
            return Ok(());
        }

        info!("Found {} expired sessions", expired_sessions.len());

        // 处理每个过期的会话
        for (session_id, resource_id, client_ip) in expired_sessions {
            if let Err(e) = self.process_expired_session(&session_id, &resource_id, client_ip).await {
                error!("Failed to process expired session {}: {}", session_id, e);
            } else {
                info!("Processed expired session: {}", session_id);
            }
        }

        Ok(())
    }

    /// 查找过期的会话
    async fn find_expired_sessions(&self) -> Result<Vec<(String, String, IpAddr)>, String> {
        let timeout_hours = self._get_session_timeout_hours();
        let timeout_seconds = timeout_hours * 3600;
        
        info!("Scanning for expired sessions with timeout: {} hours ({} seconds)", timeout_hours, timeout_seconds);
        
        // 使用数据存储后端的扫描方法
        match self.redis.scan_expired_sessions(timeout_seconds).await {
            Ok(sessions) => {
                info!("Found {} potentially expired sessions", sessions.len());
                Ok(sessions)
            }
            Err(e) => {
                error!("Failed to scan expired sessions: {}", e);
                Err(e)
            }
        }
    }

    /// 处理单个过期的会话
    async fn process_expired_session(
        &self,
        session_id: &str,
        resource_id: &str,
        client_ip: IpAddr,
    ) -> Result<(), String> {
        // 记录超时日志
        if let Err(e) = self.logger.log_session_timeout(session_id, resource_id, client_ip, None).await {
            error!("Failed to log timeout for session {}: {}", session_id, e);
        }

        // 清理会话数据
        if let Err(e) = self.redis.remove_session(session_id).await {
            error!("Failed to remove expired session {}: {}", session_id, e);
        }

        Ok(())
    }

    /// 检查是否启用清理任务
    fn is_enabled(&self) -> bool {
        std::env::var("SESSION_CLEANUP_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true)
    }

    /// 获取清理任务间隔（分钟）
    fn get_cleanup_interval(&self) -> u64 {
        std::env::var("SESSION_CLEANUP_INTERVAL_MIN")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u64>()
            .unwrap_or(5)
    }

    /// 获取会话超时时间（小时）
    fn _get_session_timeout_hours(&self) -> u64 {
        std::env::var("SESSION_TIMEOUT_HOURS")
            .unwrap_or_else(|_| "2".to_string())
            .parse::<u64>()
            .unwrap_or(2)
    }
}