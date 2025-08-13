use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Analysis result structure for JSON output
#[derive(Debug, Serialize)]
pub struct AnalysisResult {
    pub analysis_info: AnalysisInfo,
    pub session_duration: SessionDurationAnalysis,
    pub server_performance: ServerPerformanceAnalysis,
    pub retry_analysis: RetryAnalysis,
    pub issues_summary: IssuesSummary,
    pub data_quality: DataQuality,
}

#[derive(Debug, Serialize)]
pub struct AnalysisInfo {
    pub analysis_period: AnalysisPeriod,
    pub log_file: String,
    pub total_records: usize,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AnalysisPeriod {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SessionDurationAnalysis {
    pub statistics: DurationStatistics,
    pub distribution: DurationDistribution,
    pub by_type: HashMap<String, DurationStatistics>,
    pub by_resource: HashMap<String, DurationStatistics>,
}

#[derive(Debug, Serialize)]
pub struct DurationStatistics {
    pub average_seconds: f64,
    pub median_seconds: f64,
    pub p95_seconds: f64,
    pub p99_seconds: f64,
    pub max_seconds: f64,
    pub min_seconds: f64,
}

#[derive(Debug, Serialize)]
pub struct DurationDistribution {
    pub fast_lt_2min: CountAndPercentage,
    pub normal_2_5min: CountAndPercentage,
    pub slow_5_10min: CountAndPercentage,
    pub very_slow_10_20min: CountAndPercentage,
    pub extremely_slow_gt_20min: CountAndPercentage,
}

#[derive(Debug, Serialize)]
pub struct CountAndPercentage {
    pub count: usize,
    pub percentage: f64,
}

#[derive(Debug, Serialize)]
pub struct ServerPerformanceAnalysis {
    pub ttfb_analysis: TtfbAnalysis,
    pub speed_analysis: SpeedAnalysis,
    pub reliability_analysis: ReliabilityAnalysis,
}

#[derive(Debug, Serialize)]
pub struct TtfbAnalysis {
    pub worst_servers: Vec<ServerTtfbStats>,
    pub best_servers: Vec<ServerTtfbStats>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ServerTtfbStats {
    pub server_id: String,
    pub avg_ttfb_ms: f64,
    pub data_coverage: DataCoverage,
    pub severity: String,
    pub recommendation: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct DataCoverage {
    pub valid_records: usize,
    pub total_requests: usize,
    pub coverage_percentage: f64,
}

#[derive(Debug, Serialize)]
pub struct SpeedAnalysis {
    pub slowest_servers: Vec<ServerSpeedStats>,
    pub fastest_servers: Vec<ServerSpeedStats>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ServerSpeedStats {
    pub server_id: String,
    pub avg_speed_mbps: f64,
    pub data_coverage: DataCoverage,
    pub severity: String,
    pub recommendation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReliabilityAnalysis {
    pub highest_retry_servers: Vec<ServerReliabilityStats>,
    pub most_reliable_servers: Vec<ServerReliabilityStats>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ServerReliabilityStats {
    pub server_id: String,
    pub total_requests: usize,
    pub avg_retries: f64,
    pub penalty_rate_percentage: f64,
    pub retry_success_rate_percentage: f64,
    pub severity: String,
    pub recommendation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RetryAnalysis {
    pub global_statistics: GlobalRetryStats,
    pub retry_distribution: RetryDistribution,
    pub time_impact: TimeImpact,
    pub by_server: HashMap<String, ServerRetryStats>,
}

#[derive(Debug, Serialize)]
pub struct GlobalRetryStats {
    pub total_sessions: usize,
    pub sessions_with_retries: usize,
    pub retry_rate_percentage: f64,
    pub avg_retries: f64,
}

#[derive(Debug, Serialize)]
pub struct RetryDistribution {
    pub zero_retries: CountAndPercentage,
    pub one_retry: CountAndPercentage,
    pub two_retries: CountAndPercentage,
    pub three_retries: CountAndPercentage,
    pub four_plus_retries: CountAndPercentage,
}

#[derive(Debug, Serialize)]
pub struct TimeImpact {
    pub zero_retries_avg_seconds: f64,
    pub one_retry_avg_seconds: f64,
    pub two_retries_avg_seconds: f64,
    pub three_plus_retries_avg_seconds: f64,
}

#[derive(Debug, Serialize)]
pub struct ServerRetryStats {
    pub server_id: String,
    pub total_requests: usize,
    pub avg_retries: f64,
    pub penalty_rate: f64,
    pub retry_reasons: HashMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct IssuesSummary {
    pub critical_servers: Vec<CriticalServer>,
    pub experience_issues: ExperienceIssues,
    pub excellent_performers: Vec<ExcellentPerformer>,
}

#[derive(Debug, Serialize)]
pub struct CriticalServer {
    pub server_id: String,
    pub issue_type: String,
    pub value: String,
    pub severity: String,
    pub recommendation: String,
}

#[derive(Debug, Serialize)]
pub struct ExperienceIssues {
    pub users_over_5min_percentage: f64,
    pub users_over_10min_percentage: f64,
    pub users_over_20min_percentage: f64,
    pub requests_requiring_retry_percentage: f64,
}

#[derive(Debug, Serialize)]
pub struct ExcellentPerformer {
    pub server_id: String,
    pub description: String,
    pub metrics: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct DataQuality {
    pub session_duration_coverage: f64,
    pub retry_statistics_coverage: f64,
    pub server_id_coverage: f64,
    pub ttfb_data_coverage: f64,
    pub speed_data_coverage: f64,
    pub recommendation: String,
}

/// Raw session log structure (matches the optimized format)
#[derive(Debug, Deserialize, Clone)]
pub struct SessionLog {
    pub start: u64,
    pub end: u64,
    #[serde(rename = "type")]
    pub log_type: String,
    pub sid: Option<String>,
    pub rid: String,
    pub ver: String,
    pub ua: Option<String>,
    pub ip: (String, Option<String>),
    pub chunks: Vec<ChunkLog>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChunkLog {
    pub rng: String,
    pub att: u32,
    pub cdns: Vec<CdnRecordLog>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CdnRecordLog {
    pub url: String,
    pub srv: Option<String>,
    pub wgt: Option<u32>,
    pub ts: u64,
    pub pen: Option<bool>,
    pub rsn: Option<String>,
    pub ttfb: Option<u32>,
    pub time: Option<u32>,
    pub size: Option<u32>,
    pub err: Option<String>,
    pub mode: Option<String>,
}
