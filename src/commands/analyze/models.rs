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
    pub error_analysis: ErrorAnalysis,
    pub detailed_server_stats: Vec<ServerDetailedStats>,
    pub chunk_allocation_analysis: ChunkAllocationAnalysis,
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

#[derive(Debug, Serialize)]
pub struct ErrorAnalysis {
    pub highest_error_servers: Vec<ServerErrorStats>,
    pub most_reliable_servers: Vec<ServerErrorStats>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ServerErrorStats {
    pub server_id: String,
    pub total_requests: usize,
    pub error_count: usize,
    pub error_rate_percentage: f64,
    pub success_rate_percentage: f64,
    pub error_types: HashMap<String, usize>,
    pub severity: String,
    pub recommendation: Option<String>,
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

/// Detailed statistics for server performance analysis
#[derive(Debug, Serialize, Clone)]
pub struct ServerDetailedStats {
    pub server_id: String,
    pub ttfb_stats: Option<DetailedStatistics>,
    pub speed_stats: Option<DetailedStatistics>,
    pub request_count: usize,
    pub coverage_percentage: f64,
    // New enhanced fields
    pub impact_stats: Option<ServerImpactStatistics>,
    pub file_size_stats: Option<FileSizePerformance>,
}

/// Server impact statistics with CPI v5 concurrency context-aware performance assessment  
#[derive(Debug, Serialize, Clone)]
pub struct ServerImpactStatistics {
    /// Comprehensive Performance Index v5 (0-100, higher is better)
    pub cpi_score: f64,
    /// Performance grade based on CPI (S/A/B/C/D/F)
    pub grade: String,

    // === Core CPI v5 Components (Concurrency Context-Aware) ===
    /// File size distribution and performance stats (for reference)
    pub file_size_stats: FileSizeDistribution,
    /// Percentage of times this server appears in session tail
    pub tail_appearance_rate: f64,

    // === CPI v5 Primary Metrics ===
    /// Average concurrency level when this server was active
    pub avg_concurrency_level: f64,
    /// Performance in low concurrency scenarios (<4 threads) - most reliable
    pub low_concurrency_speed: f64,
    /// Performance in tail phase (last 10% of session) - most critical
    pub tail_performance_score: f64,
    /// Critical path reliability - performance when it matters most
    pub critical_path_reliability: f64,
    /// Adaptability across different concurrency levels  
    pub adaptability_score: f64,

    // === Legacy Metrics (for compatibility) ===
    /// Performance variance coefficient - stability component
    pub performance_cv: f64,
    /// TTFB P95 in milliseconds
    pub ttfb_p95: f64,
    /// Error rate (0-1)
    pub error_rate: f64,
    /// Usage rate - fraction of sessions this server participated in
    pub usage_rate: f64,
    /// Average file size processed by this server in bytes
    pub avg_file_size: f64,
    /// Total data processed by this server in bytes
    pub data_processed: u64,
    /// Number of sessions this server participated in
    pub affected_sessions: usize,
}

/// File size distribution statistics for server performance analysis
#[derive(Debug, Serialize, Clone)]
pub struct FileSizeDistribution {
    /// Number of small files (<100KB)
    pub small_files: usize,
    /// Number of medium files (100KB-10MB)
    pub medium_files: usize,
    /// Number of large files (>10MB)
    pub large_files: usize,
    /// Average efficiency for small files
    pub small_file_efficiency: f64,
    /// Average speed for medium files (MB/s)
    pub medium_file_speed: f64,
    /// Average speed for large files (MB/s)
    pub large_file_speed: f64,
}

/// Global performance statistics for dynamic baseline calculation
#[derive(Debug, Clone)]
pub struct GlobalPerformanceStats {
    /// Median efficiency for small files across all servers
    pub small_file_median_efficiency: f64,
    /// Median speed for medium files across all servers (MB/s)
    pub medium_file_median_speed: f64,
    /// Median speed for large files across all servers (MB/s)
    pub large_file_median_speed: f64,
    /// Total data processed by all servers
    pub total_data_processed: u64,
    /// Average tail appearance rate across all servers
    pub global_avg_tail_rate: f64,
}

impl Default for GlobalPerformanceStats {
    fn default() -> Self {
        Self {
            small_file_median_efficiency: 1.0,
            medium_file_median_speed: 2.0,
            large_file_median_speed: 5.0,
            total_data_processed: 0,
            global_avg_tail_rate: 50.0,
        }
    }
}

/// Performance analysis categorized by file size
#[derive(Debug, Serialize, Clone)]
pub struct FileSizePerformance {
    /// <1MB files - TTFB focused analysis
    pub tiny_files: FileSizeStats,
    /// 1-4MB files - Mixed TTFB and speed analysis
    pub small_files: FileSizeStats,
    /// 4-20MB files - Speed focused analysis
    pub medium_files: FileSizeStats,
    /// >20MB files - Speed only analysis
    pub large_files: FileSizeStats,
}

/// Statistics for a specific file size category
#[derive(Debug, Serialize, Clone)]
pub struct FileSizeStats {
    /// Number of files in this category
    pub count: usize,
    /// TTFB statistics (None for large files where TTFB is less relevant)
    pub ttfb_stats: Option<DetailedStatistics>,
    /// Speed statistics (None for tiny files where speed calculation is unreliable)
    pub speed_stats: Option<DetailedStatistics>,
    /// Download duration statistics
    pub duration_stats: DetailedStatistics,
}

/// Detailed statistical measurements
#[derive(Debug, Serialize, Clone)]
pub struct DetailedStatistics {
    pub mean: f64,
    pub median: f64,
    pub min: f64,
    pub max: f64,
    pub std_dev: f64,
    pub p95: f64,
    pub p99: f64,
    pub sample_count: usize,
}

/// Chunk allocation analysis for detecting large files assigned to slow servers
#[derive(Debug, Serialize)]
pub struct ChunkAllocationAnalysis {
    pub misallocated_chunks: Vec<MisallocatedChunk>,
    pub server_chunk_distribution: HashMap<String, ServerChunkStats>,
    pub total_impact: ChunkAllocationImpact,
}

/// A chunk that was suboptimally allocated to a slow server
#[derive(Debug, Serialize, Clone)]
pub struct MisallocatedChunk {
    pub server_id: String,
    pub chunk_size_mb: f64,
    pub download_speed_mbps: f64,
    pub actual_time_seconds: f64,
    pub optimal_time_seconds: f64,
    pub time_penalty_seconds: f64,
    pub session_id: Option<String>,
}

/// Statistics about how chunks are distributed across a server
#[derive(Debug, Serialize)]
pub struct ServerChunkStats {
    pub server_id: String,
    pub total_chunks: usize,
    pub large_chunks: usize,
    pub avg_chunk_size_mb: f64,
    pub avg_speed_mbps: f64,
}

/// Overall impact assessment of chunk allocation issues
#[derive(Debug, Serialize)]
pub struct ChunkAllocationImpact {
    pub total_misallocated_chunks: usize,
    pub total_time_penalty_seconds: f64,
    pub affected_sessions: usize,
    pub worst_misallocation: Option<MisallocatedChunk>,
}

/// Server session performance data for bottleneck analysis
#[derive(Debug, Clone)]
pub struct ServerSessionPerformance {
    pub server_id: String,
    pub total_bytes: u64,
    pub total_duration: f64,     // From first start to last completion
    pub actual_speed: f64,       // Average MB/s
    pub session_time_usage: f64, // Fraction of session time used
    pub data_contribution: f64,  // Fraction of total session data
    pub efficiency_score: f64,   // Relative efficiency (0-1)
    pub bottleneck_score: f64,   // Bottleneck tendency (0-1)
    pub workload_rank: f64,      // Workload ranking in session (0-1, higher=more workload)
}

/// Bottleneck analysis result for a server in a session
#[derive(Debug, Clone)]
pub struct BottleneckAnalysis {
    pub efficiency_score: f64,
    pub time_burden_score: f64,
    pub data_contribution: f64,
    pub bottleneck_score: f64,
    pub bottleneck_type: BottleneckType,
    pub is_bottleneck: bool,
}

/// Types of server behavior in session analysis
#[derive(Debug, Clone, PartialEq)]
pub enum BottleneckType {
    TrueBottleneck,       // Low efficiency, high time usage, drags session
    Workhorse,            // High efficiency, high usage, carries session
    EfficiencyBottleneck, // Medium efficiency but unreasonable time usage
    Normal,               // Regular performance
    Underutilized,        // Good efficiency but low usage
}

impl BottleneckType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BottleneckType::TrueBottleneck => "true_bottleneck",
            BottleneckType::Workhorse => "workhorse",
            BottleneckType::EfficiencyBottleneck => "efficiency_bottleneck",
            BottleneckType::Normal => "normal",
            BottleneckType::Underutilized => "underutilized",
        }
    }
}
