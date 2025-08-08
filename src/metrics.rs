use prometheus::{Counter, CounterVec, Gauge, GaugeVec, Histogram, Opts, Registry, TextEncoder};
use std::sync::Arc;
use tokio::sync::RwLock;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::{error, debug};
use chrono;
use crate::config::AppConfig;
use crate::data_store::DataStore;

/// DFS2 Prometheus Metrics
#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,
    
    // Request metrics
    pub requests_total: Counter,
    pub request_duration: Histogram,
    
    // Session metrics  
    pub active_sessions: Gauge,
    pub sessions_created_total: Counter,
    
    // Redis metrics
    pub redis_operations_total: Counter,
    pub redis_errors_total: Counter,
    
    // Server health metrics
    pub healthy_servers: Gauge,
    pub total_servers: Gauge,
    
    // Plugin metrics
    pub plugins_loaded: Gauge,
    pub plugin_executions_total: Counter,
    pub plugin_errors_total: Counter,
    
    // Flow runner metrics
    pub flow_executions_total: Counter,
    pub flow_failures_total: Counter,
    
    // 流量指标（3个独立指标）
    pub bandwidth_bytes_today: Gauge,                    // 全局流量
    pub bandwidth_bytes_today_per_resource: GaugeVec,   // 资源流量
    pub bandwidth_bytes_today_per_server: GaugeVec,     // 服务器流量
    
    // 总请求数指标（3个，包含缓存的和非缓存的）
    pub scheduled_requests_total: Counter,               // 全局总请求数
    pub scheduled_requests_per_server: CounterVec,      // 服务器总请求数
    pub scheduled_requests_per_resource: CounterVec,    // 资源总请求数
    
    // 缓存请求数指标（3个）
    pub cached_requests_total: Counter,                  // 全局缓存请求数
    pub cached_requests_per_server: CounterVec,         // 服务器缓存请求数
    pub cached_requests_per_resource: CounterVec,       // 资源缓存请求数
    
    // 配置引用（用于实时获取ID列表）
    pub config: Arc<RwLock<AppConfig>>,
}

impl Metrics {
    pub fn new(config: Arc<RwLock<AppConfig>>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let registry = Arc::new(Registry::new());
        
        // Request metrics
        let requests_total = Counter::new(
            "dfs_requests_total", 
            "Total number of HTTP requests"
        )?;
        registry.register(Box::new(requests_total.clone()))?;
        
        let request_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "dfs_request_duration_seconds",
                "HTTP request duration in seconds"
            ).buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
        )?;
        registry.register(Box::new(request_duration.clone()))?;
        
        // Session metrics
        let active_sessions = Gauge::new(
            "dfs_active_sessions",
            "Number of currently active sessions"
        )?;
        registry.register(Box::new(active_sessions.clone()))?;
        
        let sessions_created_total = Counter::new(
            "dfs_sessions_created_total",
            "Total number of sessions created"
        )?;
        registry.register(Box::new(sessions_created_total.clone()))?;
        
        // Redis metrics
        let redis_operations_total = Counter::new(
            "dfs_redis_operations_total",
            "Total number of Redis operations"
        )?;
        registry.register(Box::new(redis_operations_total.clone()))?;
        
        let redis_errors_total = Counter::new(
            "dfs_redis_errors_total",
            "Total number of Redis errors"
        )?;
        registry.register(Box::new(redis_errors_total.clone()))?;
        
        // Server health metrics
        let healthy_servers = Gauge::new(
            "dfs_healthy_servers",
            "Number of healthy storage servers"
        )?;
        registry.register(Box::new(healthy_servers.clone()))?;
        
        let total_servers = Gauge::new(
            "dfs_total_servers",
            "Total number of configured storage servers"
        )?;
        registry.register(Box::new(total_servers.clone()))?;
        
        // Plugin metrics
        let plugins_loaded = Gauge::new(
            "dfs_plugins_loaded",
            "Number of loaded JavaScript plugins"
        )?;
        registry.register(Box::new(plugins_loaded.clone()))?;
        
        let plugin_executions_total = Counter::new(
            "dfs_plugin_executions_total",
            "Total number of plugin executions"
        )?;
        registry.register(Box::new(plugin_executions_total.clone()))?;
        
        let plugin_errors_total = Counter::new(
            "dfs_plugin_errors_total",
            "Total number of plugin execution errors"
        )?;
        registry.register(Box::new(plugin_errors_total.clone()))?;
        
        // Flow runner metrics
        let flow_executions_total = Counter::new(
            "dfs_flow_executions_total",
            "Total number of flow executions"
        )?;
        registry.register(Box::new(flow_executions_total.clone()))?;
        
        let flow_failures_total = Counter::new(
            "dfs_flow_failures_total",
            "Total number of flow execution failures"
        )?;
        registry.register(Box::new(flow_failures_total.clone()))?;
        
        // 流量指标
        let bandwidth_bytes_today = Gauge::new(
            "dfs_bandwidth_bytes_today", 
            "Total daily bandwidth usage in bytes"
        )?;
        registry.register(Box::new(bandwidth_bytes_today.clone()))?;

        let bandwidth_bytes_today_per_resource = GaugeVec::new(
            Opts::new("dfs_bandwidth_bytes_today_per_resource", "Daily bandwidth usage per resource in bytes"),
            &["resource_id"]
        )?;
        registry.register(Box::new(bandwidth_bytes_today_per_resource.clone()))?;

        let bandwidth_bytes_today_per_server = GaugeVec::new(
            Opts::new("dfs_bandwidth_bytes_today_per_server", "Daily bandwidth usage per server in bytes"),
            &["server_id"]
        )?;
        registry.register(Box::new(bandwidth_bytes_today_per_server.clone()))?;

        // 总请求数指标
        let scheduled_requests_total = Counter::new(
            "dfs_scheduled_requests_total",
            "Total number of scheduled requests (cached and non-cached)"
        )?;
        registry.register(Box::new(scheduled_requests_total.clone()))?;

        let scheduled_requests_per_server = CounterVec::new(
            Opts::new("dfs_scheduled_requests_per_server", "Total number of scheduled requests per server (cached and non-cached)"),
            &["server_id"]
        )?;
        registry.register(Box::new(scheduled_requests_per_server.clone()))?;

        let scheduled_requests_per_resource = CounterVec::new(
            Opts::new("dfs_scheduled_requests_per_resource", "Total number of scheduled requests per resource (cached and non-cached)"),
            &["resource_id"]
        )?;
        registry.register(Box::new(scheduled_requests_per_resource.clone()))?;

        // 缓存请求数指标
        let cached_requests_total = Counter::new(
            "dfs_cached_requests_total",
            "Total number of cached requests"
        )?;
        registry.register(Box::new(cached_requests_total.clone()))?;

        let cached_requests_per_server = CounterVec::new(
            Opts::new("dfs_cached_requests_per_server", "Total number of cached requests per server"),
            &["server_id"]
        )?;
        registry.register(Box::new(cached_requests_per_server.clone()))?;

        let cached_requests_per_resource = CounterVec::new(
            Opts::new("dfs_cached_requests_per_resource", "Total number of cached requests per resource"),
            &["resource_id"]
        )?;
        registry.register(Box::new(cached_requests_per_resource.clone()))?;
        
        Ok(Self {
            registry,
            requests_total,
            request_duration,
            active_sessions,
            sessions_created_total,
            redis_operations_total,
            redis_errors_total,
            healthy_servers,
            total_servers,
            plugins_loaded,
            plugin_executions_total,
            plugin_errors_total,
            flow_executions_total,
            flow_failures_total,
            bandwidth_bytes_today,
            bandwidth_bytes_today_per_resource,
            bandwidth_bytes_today_per_server,
            scheduled_requests_total,
            scheduled_requests_per_server,
            scheduled_requests_per_resource,
            cached_requests_total,
            cached_requests_per_server,
            cached_requests_per_resource,
            config,
        })
    }
    
    /// Record an HTTP request
    pub fn record_request(&self) {
        self.requests_total.inc();
        debug!("Metrics: HTTP request recorded");
    }
    
    /// Record request duration
    pub fn record_request_duration(&self, duration: f64) {
        self.request_duration.observe(duration);
        debug!("Metrics: Request duration recorded: {:.3}s", duration);
    }
    
    /// Update session count
    pub fn set_active_sessions(&self, count: u64) {
        self.active_sessions.set(count as f64);
        debug!("Metrics: Active sessions updated: {}", count);
    }
    
    /// Record session creation
    pub fn record_session_created(&self) {
        self.sessions_created_total.inc();
        debug!("Metrics: Session creation recorded");
    }
    
    /// Record Redis operation
    pub fn record_redis_operation(&self) {
        self.redis_operations_total.inc();
    }
    
    /// Record Redis error
    pub fn record_redis_error(&self) {
        self.redis_errors_total.inc();
    }
    
    /// Update server health counts
    pub fn set_server_health(&self, healthy: u64, total: u64) {
        self.healthy_servers.set(healthy as f64);
        self.total_servers.set(total as f64);
        debug!("Metrics: Server health updated: {}/{}", healthy, total);
    }
    
    /// Update plugin count
    pub fn set_plugins_loaded(&self, count: u64) {
        self.plugins_loaded.set(count as f64);
        debug!("Metrics: Plugins loaded updated: {}", count);
    }
    
    /// Record plugin execution
    pub fn record_plugin_execution(&self) {
        self.plugin_executions_total.inc();
    }
    
    /// Record plugin error
    pub fn record_plugin_error(&self) {
        self.plugin_errors_total.inc();
    }
    
    /// Record flow execution
    pub fn record_flow_execution(&self) {
        self.flow_executions_total.inc();
    }
    
    /// Record flow failure
    pub fn record_flow_failure(&self) {
        self.flow_failures_total.inc();
    }
    
    /// Record scheduled request (区分缓存状态)
    pub fn record_scheduled_request(&self, resource_id: &str, server_id: &str, is_cached: bool) {
        // 总请求数（包含缓存和非缓存）
        self.scheduled_requests_total.inc();
        self.scheduled_requests_per_server
            .with_label_values(&[server_id]).inc();
        self.scheduled_requests_per_resource
            .with_label_values(&[resource_id]).inc();
        
        // 如果是缓存请求，额外记录到缓存指标
        if is_cached {
            self.cached_requests_total.inc();
            self.cached_requests_per_server
                .with_label_values(&[server_id]).inc();
            self.cached_requests_per_resource
                .with_label_values(&[resource_id]).inc();
        }
    }
    
    /// Update bandwidth metrics (在/metrics端点处理时调用)
    pub async fn update_bandwidth_metrics(&self, redis: &DataStore) {
        // 更新全局流量
        if let Ok(global_bw) = redis.get_global_daily_bandwidth().await {
            self.bandwidth_bytes_today.set(global_bw as f64);
        }
        
        // 实时从配置获取资源ID并更新流量
        let resource_ids: Vec<String> = {
            let config = self.config.read().await;
            config.resources.keys().cloned().collect()
        };
        
        for resource_id in &resource_ids {
            if let Ok(resource_bw) = redis.get_resource_daily_bandwidth(resource_id).await {
                self.bandwidth_bytes_today_per_resource
                    .with_label_values(&[resource_id])
                    .set(resource_bw as f64);
            }
        }
        
        // 实时从配置获取服务器ID并更新流量
        let server_ids: Vec<String> = {
            let config = self.config.read().await;
            config.servers.keys().cloned().collect()
        };
        
        for server_id in &server_ids {
            if let Ok(server_bw) = redis.get_server_daily_bandwidth(server_id).await {
                self.bandwidth_bytes_today_per_server
                    .with_label_values(&[server_id])
                    .set(server_bw as f64);
            }
        }
    }
}

/// Handler for /metrics endpoint
pub async fn metrics_handler(
    State(metrics): State<Arc<Metrics>>,
    State(redis): State<DataStore>
) -> Response {
    // 实时更新流量指标
    metrics.update_bandwidth_metrics(&redis).await;
    
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry.gather();
    
    match encoder.encode_to_string(&metric_families) {
        Ok(output) => {
            debug!("Metrics endpoint served successfully");
            (
                StatusCode::OK,
                [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
                output
            ).into_response()
        }
        Err(e) => {
            error!("Failed to encode metrics: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to encode metrics").into_response()
        }
    }
}