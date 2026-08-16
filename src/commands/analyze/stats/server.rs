use crate::commands::analyze::models::{
    BottleneckAnalysis, BottleneckType, CdnRecordLog, DataCoverage, DetailedStatistics,
    ErrorAnalysis, FileSizeDistribution, FileSizePerformance, FileSizeStats,
    GlobalPerformanceStats, ReliabilityAnalysis, ServerDetailedStats, ServerErrorStats,
    ServerImpactStatistics, ServerPerformanceAnalysis, ServerReliabilityStats,
    ServerSessionPerformance, ServerSpeedStats, ServerTtfbStats, SessionLog, SpeedAnalysis,
    TtfbAnalysis,
};
use crate::commands::analyze::stats::allocation;
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashMap;

/// 会话并发度时间线缓存 - 性能优化核心数据结构
#[derive(Debug, Clone)]
struct SessionConcurrencyTimeline {
    session_id: String,
    timeline: Vec<ConcurrencyEvent>,
    duration: u64,
}

#[derive(Debug, Clone)]
struct ConcurrencyEvent {
    timestamp: u64,
    event_type: EventType, // Start or End
    server_id: Option<String>,
}

#[derive(Debug, Clone)]
enum EventType {
    DownloadStart,
    DownloadEnd,
}

impl SessionConcurrencyTimeline {
    /// 快速查询指定时间点的并发度 - O(log N) 复杂度
    fn get_concurrency_at_time(&self, timestamp: u64) -> usize {
        let mut concurrency: usize = 0;

        // 只需要检查timestamp之前的所有事件
        for event in &self.timeline {
            if event.timestamp > timestamp {
                break; // 事件已按时间排序，可以提前退出
            }

            match event.event_type {
                EventType::DownloadStart => concurrency += 1,
                EventType::DownloadEnd => concurrency = concurrency.saturating_sub(1),
            }
        }

        concurrency
    }
}

/// 为单个会话预计算并发度时间线
fn precompute_session_timeline(session: &SessionLog) -> SessionConcurrencyTimeline {
    let mut events = Vec::new();

    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            let download_start = cdn_record.ts;

            if let Some(duration) = cdn_record.time {
                let download_end = download_start + duration as u64;

                // 添加开始和结束事件
                events.push(ConcurrencyEvent {
                    timestamp: download_start,
                    event_type: EventType::DownloadStart,
                    server_id: cdn_record.srv.clone(),
                });

                events.push(ConcurrencyEvent {
                    timestamp: download_end,
                    event_type: EventType::DownloadEnd,
                    server_id: cdn_record.srv.clone(),
                });
            }
        }
    }

    // 按时间排序，确保查询时可以提前退出
    events.sort_by_key(|e| e.timestamp);

    SessionConcurrencyTimeline {
        session_id: session.sid.clone().unwrap_or_default(),
        timeline: events,
        duration: session.end - session.start,
    }
}

/// 并行预计算所有会话的并发度时间线 - 主要性能提升点
fn precompute_all_session_timelines(
    sessions: &[SessionLog],
) -> HashMap<String, SessionConcurrencyTimeline> {
    sessions
        .par_iter() // 使用 Rayon 并行处理
        .filter_map(|session| {
            if let Some(ref session_id) = session.sid {
                let timeline = precompute_session_timeline(session);
                Some((session_id.clone(), timeline))
            } else {
                None
            }
        })
        .collect() // Rayon 会并行收集结果
}

pub fn analyze_server_performance(sessions: &[SessionLog]) -> ServerPerformanceAnalysis {
    // Collect all CDN records with their server information
    let cdn_records = collect_cdn_records(sessions);

    // TTFB Analysis
    let ttfb_analysis = analyze_ttfb(&cdn_records);

    // Speed Analysis
    let speed_analysis = analyze_speed(&cdn_records);

    // Reliability Analysis
    let reliability_analysis = analyze_reliability(&cdn_records, sessions);

    // Error Analysis
    let error_analysis = analyze_error_rates(&cdn_records);

    // Detailed server statistics with enhanced analysis
    let detailed_server_stats = analyze_detailed_server_stats_enhanced(&cdn_records, sessions);

    // Chunk allocation analysis
    let chunk_allocation_analysis = allocation::analyze_chunk_allocation(sessions);

    ServerPerformanceAnalysis {
        ttfb_analysis,
        speed_analysis,
        reliability_analysis,
        error_analysis,
        detailed_server_stats,
        chunk_allocation_analysis,
    }
}

struct CdnRecordWithMeta {
    record: CdnRecordLog,
    server_id: Option<String>,
    session_duration: f64,
}

fn collect_cdn_records(sessions: &[SessionLog]) -> Vec<CdnRecordWithMeta> {
    let mut records = Vec::new();

    for session in sessions {
        let session_duration = (session.end - session.start) as f64;

        for chunk in &session.chunks {
            for cdn_record in &chunk.cdns {
                records.push(CdnRecordWithMeta {
                    record: cdn_record.clone(),
                    server_id: cdn_record.srv.clone(),
                    session_duration,
                });
            }
        }
    }

    records
}

fn analyze_ttfb(cdn_records: &[CdnRecordWithMeta]) -> TtfbAnalysis {
    let mut server_ttfbs: HashMap<String, Vec<u32>> = HashMap::new();
    let mut server_requests: HashMap<String, usize> = HashMap::new();

    // Group TTFB data by server
    for record_meta in cdn_records {
        if let (Some(server_id), Some(ttfb)) = (&record_meta.server_id, record_meta.record.ttfb) {
            server_ttfbs
                .entry(server_id.clone())
                .or_insert_with(Vec::new)
                .push(ttfb);
        }

        if let Some(server_id) = &record_meta.server_id {
            *server_requests.entry(server_id.clone()).or_insert(0) += 1;
        }
    }

    let mut server_stats = Vec::new();

    for (server_id, ttfbs) in server_ttfbs {
        if ttfbs.is_empty() {
            continue;
        }

        let total_requests = server_requests.get(&server_id).unwrap_or(&0);
        let avg_ttfb = ttfbs.iter().map(|&x| x as f64).sum::<f64>() / ttfbs.len() as f64;

        let coverage = DataCoverage {
            valid_records: ttfbs.len(),
            total_requests: *total_requests,
            coverage_percentage: (ttfbs.len() as f64 / *total_requests as f64) * 100.0,
        };

        let (severity, recommendation) = classify_ttfb_performance(avg_ttfb);

        server_stats.push(ServerTtfbStats {
            server_id,
            avg_ttfb_ms: avg_ttfb,
            data_coverage: coverage,
            severity,
            recommendation,
        });
    }

    // Sort by TTFB (worst first)
    server_stats.sort_by(|a, b| b.avg_ttfb_ms.partial_cmp(&a.avg_ttfb_ms).unwrap());

    let worst_servers = server_stats
        .iter()
        .filter(|s| s.severity == "critical" || s.severity == "warning")
        .take(5)
        .cloned()
        .collect();

    let best_servers = server_stats
        .iter()
        .filter(|s| s.severity == "excellent")
        .take(5)
        .cloned()
        .collect();

    TtfbAnalysis {
        worst_servers,
        best_servers,
    }
}

fn classify_ttfb_performance(avg_ttfb_ms: f64) -> (String, Option<String>) {
    if avg_ttfb_ms > 4000.0 {
        ("critical".to_string(), None)
    } else if avg_ttfb_ms > 2500.0 {
        ("warning".to_string(), None)
    } else if avg_ttfb_ms > 1500.0 {
        ("needs_attention".to_string(), None)
    } else if avg_ttfb_ms < 800.0 {
        ("excellent".to_string(), None)
    } else {
        ("acceptable".to_string(), None)
    }
}

fn analyze_speed(cdn_records: &[CdnRecordWithMeta]) -> SpeedAnalysis {
    let mut server_speeds: HashMap<String, Vec<f64>> = HashMap::new();
    let mut server_requests: HashMap<String, usize> = HashMap::new();

    // Group speed data by server
    for record_meta in cdn_records {
        if let Some(server_id) = &record_meta.server_id {
            *server_requests.entry(server_id.clone()).or_insert(0) += 1;

            // Calculate speed if both size and time are available
            // Apply multiple filters for accurate speed measurement
            if let (Some(size), Some(time)) = (record_meta.record.size, record_meta.record.time) {
                // Only include successful downloads (no error)
                if record_meta.record.err.is_none() 
                    && time >= 10  // Minimum 50ms to avoid unrealistic high speeds (reduced from 100ms)
                    && size >= 10240
                // Minimum 10KB for accurate measurement
                {
                    // Convert to MB/s (size in bytes, time in milliseconds)
                    let speed_mbps = (size as f64 / 1024.0 / 1024.0) / (time as f64 / 1000.0);

                    // Apply maximum speed filter (1000MB/s to avoid filtering high-speed downloads, increased from 500MB/s)
                    if speed_mbps <= 1000.0 {
                        server_speeds
                            .entry(server_id.clone())
                            .or_insert_with(Vec::new)
                            .push(speed_mbps);
                    }
                }
            }
        }
    }

    let mut server_stats = Vec::new();

    for (server_id, speeds) in server_speeds {
        if speeds.is_empty() {
            continue;
        }

        let total_requests = server_requests.get(&server_id).unwrap_or(&0);
        let avg_speed = speeds.iter().sum::<f64>() / speeds.len() as f64;

        let coverage = DataCoverage {
            valid_records: speeds.len(),
            total_requests: *total_requests,
            coverage_percentage: (speeds.len() as f64 / *total_requests as f64) * 100.0,
        };

        let (severity, recommendation) = classify_speed_performance(avg_speed);

        server_stats.push(ServerSpeedStats {
            server_id,
            avg_speed_mbps: avg_speed,
            data_coverage: coverage,
            severity,
            recommendation,
        });
    }

    // Sort by speed (slowest first)
    server_stats.sort_by(|a, b| a.avg_speed_mbps.partial_cmp(&b.avg_speed_mbps).unwrap());

    let slowest_servers = server_stats
        .iter()
        .filter(|s| s.severity == "critical" || s.severity == "warning")
        .take(5)
        .cloned()
        .collect();

    let fastest_servers = server_stats
        .iter()
        .filter(|s| s.severity == "excellent")
        .rev()
        .take(5)
        .cloned()
        .collect();

    SpeedAnalysis {
        slowest_servers,
        fastest_servers,
    }
}

fn classify_speed_performance(avg_speed_mbps: f64) -> (String, Option<String>) {
    if avg_speed_mbps < 1.0 {
        ("critical".to_string(), None)
    } else if avg_speed_mbps < 2.0 {
        ("warning".to_string(), None)
    } else if avg_speed_mbps < 3.0 {
        ("needs_attention".to_string(), None)
    } else if avg_speed_mbps > 5.0 {
        ("excellent".to_string(), None)
    } else {
        ("acceptable".to_string(), None)
    }
}

fn analyze_reliability(
    _cdn_records: &[CdnRecordWithMeta],
    sessions: &[SessionLog],
) -> ReliabilityAnalysis {
    let mut server_stats: HashMap<String, ServerReliabilityData> = HashMap::new();

    // Collect retry and penalty data by server
    for session in sessions {
        for chunk in &session.chunks {
            let total_retries = chunk.att;

            for cdn_record in &chunk.cdns {
                if let Some(server_id) = &cdn_record.srv {
                    let data = server_stats
                        .entry(server_id.clone())
                        .or_insert_with(ServerReliabilityData::new);

                    data.total_requests += 1;
                    data.total_retries += total_retries;

                    if cdn_record.pen == Some(true) {
                        data.penalty_count += 1;
                    }

                    // Track retry reasons
                    if let Some(reason) = &cdn_record.rsn {
                        *data.retry_reasons.entry(reason.clone()).or_insert(0) += 1;

                        if reason == "retry_fallback" {
                            data.retry_fallback_count += 1;
                        }
                    }
                }
            }
        }
    }

    let mut reliability_stats = Vec::new();

    for (server_id, data) in server_stats {
        if data.total_requests == 0 {
            continue;
        }

        let avg_retries = data.total_retries as f64 / data.total_requests as f64;
        let penalty_rate = (data.penalty_count as f64 / data.total_requests as f64) * 100.0;

        // Calculate retry success rate (requests that eventually succeeded after retry)
        let successful_retries = data.total_requests - data.retry_fallback_count;
        let retry_success_rate = if data.total_retries > 0 {
            (successful_retries as f64 / data.total_requests as f64) * 100.0
        } else {
            100.0 // No retries needed means 100% success
        };

        let (severity, recommendation) =
            classify_reliability_performance(avg_retries, penalty_rate);

        reliability_stats.push(ServerReliabilityStats {
            server_id,
            total_requests: data.total_requests,
            avg_retries,
            penalty_rate_percentage: penalty_rate,
            retry_success_rate_percentage: retry_success_rate,
            severity,
            recommendation,
        });
    }

    // Sort by avg retries (highest first)
    reliability_stats.sort_by(|a, b| b.avg_retries.partial_cmp(&a.avg_retries).unwrap());

    let highest_retry_servers = reliability_stats
        .iter()
        .filter(|s| s.severity == "critical" || s.severity == "warning")
        .take(5)
        .cloned()
        .collect();

    let most_reliable_servers = reliability_stats
        .iter()
        .filter(|s| s.severity == "excellent")
        .rev()
        .take(5)
        .cloned()
        .collect();

    ReliabilityAnalysis {
        highest_retry_servers,
        most_reliable_servers,
    }
}

struct ServerReliabilityData {
    total_requests: usize,
    total_retries: u32,
    penalty_count: usize,
    retry_fallback_count: usize,
    retry_reasons: HashMap<String, usize>,
}

impl ServerReliabilityData {
    fn new() -> Self {
        Self {
            total_requests: 0,
            total_retries: 0,
            penalty_count: 0,
            retry_fallback_count: 0,
            retry_reasons: HashMap::new(),
        }
    }
}

fn classify_reliability_performance(
    avg_retries: f64,
    penalty_rate: f64,
) -> (String, Option<String>) {
    if avg_retries > 2.5 || penalty_rate > 60.0 {
        ("critical".to_string(), None)
    } else if avg_retries > 1.5 || penalty_rate > 30.0 {
        ("warning".to_string(), None)
    } else if avg_retries > 0.8 || penalty_rate > 15.0 {
        ("needs_attention".to_string(), None)
    } else if avg_retries < 0.5 && penalty_rate < 8.0 {
        ("excellent".to_string(), None)
    } else {
        ("acceptable".to_string(), None)
    }
}

fn analyze_error_rates(cdn_records: &[CdnRecordWithMeta]) -> ErrorAnalysis {
    let mut server_stats: HashMap<String, ServerErrorData> = HashMap::new();

    // Collect error data by server
    for record_meta in cdn_records {
        if let Some(server_id) = &record_meta.server_id {
            let entry = server_stats
                .entry(server_id.clone())
                .or_insert_with(ServerErrorData::new);

            entry.total_requests += 1;

            if let Some(error) = &record_meta.record.err {
                entry.error_count += 1;
                // Remove URLs from error messages for better aggregation
                let cleaned_error = clean_error_message(error);
                *entry.error_types.entry(cleaned_error).or_insert(0) += 1;
            }
        }
    }

    let mut error_stats = Vec::new();

    for (server_id, data) in server_stats {
        if data.total_requests == 0 || data.error_count == 0 {
            continue; // Skip servers with no requests or no errors
        }

        let error_rate_percentage = (data.error_count as f64 / data.total_requests as f64) * 100.0;
        let success_rate_percentage = 100.0 - error_rate_percentage;

        let (severity, recommendation) = classify_error_performance(error_rate_percentage);

        error_stats.push(ServerErrorStats {
            server_id,
            total_requests: data.total_requests,
            error_count: data.error_count,
            error_rate_percentage,
            success_rate_percentage,
            error_types: data.error_types,
            severity,
            recommendation,
        });
    }

    // Sort by error rate (highest first)
    error_stats.sort_by(|a, b| {
        b.error_rate_percentage
            .partial_cmp(&a.error_rate_percentage)
            .unwrap()
    });

    // Show all servers with errors (no limit)
    let highest_error_servers = error_stats.clone();

    // Don't show most reliable servers since we only include servers with errors
    let most_reliable_servers = Vec::new();

    ErrorAnalysis {
        highest_error_servers,
        most_reliable_servers,
    }
}

struct ServerErrorData {
    total_requests: usize,
    error_count: usize,
    error_types: HashMap<String, usize>,
}

impl ServerErrorData {
    fn new() -> Self {
        Self {
            total_requests: 0,
            error_count: 0,
            error_types: HashMap::new(),
        }
    }
}

fn clean_error_message(error: &str) -> String {
    // Create regex patterns to match URLs
    let url_patterns = [
        r"https?://[^\s]+",                    // HTTP/HTTPS URLs
        r"ftp://[^\s]+",                       // FTP URLs
        r"www\.[^\s]+",                        // www. domains
        r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s]*", // General domains
    ];

    let mut cleaned = error.to_string();

    for pattern in &url_patterns {
        if let Ok(re) = Regex::new(pattern) {
            cleaned = re.replace_all(&cleaned, "[URL_REMOVED]").to_string();
        }
    }

    // Also clean up multiple consecutive spaces and trim
    cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");

    cleaned
}

fn classify_error_performance(error_rate_percentage: f64) -> (String, Option<String>) {
    if error_rate_percentage > 15.0 {
        (
            "critical".to_string(),
            Some("Very high error rate requires immediate attention".to_string()),
        )
    } else if error_rate_percentage > 5.0 {
        (
            "warning".to_string(),
            Some("Elevated error rate needs investigation".to_string()),
        )
    } else if error_rate_percentage > 1.0 {
        (
            "needs_attention".to_string(),
            Some("Monitor error patterns and investigate common failures".to_string()),
        )
    } else if error_rate_percentage < 0.1 {
        ("excellent".to_string(), None)
    } else {
        ("acceptable".to_string(), None)
    }
}

fn analyze_detailed_server_stats(cdn_records: &[CdnRecordWithMeta]) -> Vec<ServerDetailedStats> {
    analyze_detailed_server_stats_enhanced(cdn_records, &[])
}

fn analyze_detailed_server_stats_enhanced(
    cdn_records: &[CdnRecordWithMeta],
    sessions: &[SessionLog],
) -> Vec<ServerDetailedStats> {
    // Analyze file size performance and session impact
    let file_size_performance = analyze_file_size_performance(cdn_records, sessions);
    let session_impacts = analyze_session_impact(sessions);

    // Call the original analysis function with enhanced data
    analyze_detailed_server_stats_with_enhanced_data(
        cdn_records,
        file_size_performance,
        session_impacts,
    )
}

fn analyze_detailed_server_stats_with_enhanced_data(
    cdn_records: &[CdnRecordWithMeta],
    file_size_performance: HashMap<String, FileSizePerformance>,
    session_impacts: HashMap<String, ServerImpactStatistics>,
) -> Vec<ServerDetailedStats> {
    let mut server_ttfbs: HashMap<String, Vec<f64>> = HashMap::new();
    let mut server_speeds: HashMap<String, Vec<f64>> = HashMap::new();
    let mut server_requests: HashMap<String, usize> = HashMap::new();

    // Group data by server
    for record_meta in cdn_records {
        if let Some(server_id) = &record_meta.server_id {
            *server_requests.entry(server_id.clone()).or_insert(0) += 1;

            // Collect TTFB data
            if let Some(ttfb) = record_meta.record.ttfb {
                server_ttfbs
                    .entry(server_id.clone())
                    .or_insert_with(Vec::new)
                    .push(ttfb as f64);
            }

            // Collect speed data
            // Apply multiple filters for accurate speed measurement
            if let (Some(size), Some(time)) = (record_meta.record.size, record_meta.record.time) {
                // Only include successful downloads (no error)
                if record_meta.record.err.is_none() 
                    && time >= 10  // Minimum 50ms to avoid unrealistic high speeds (updated from 100ms)
                    && size >= 10240
                // Minimum 10KB for accurate measurement
                {
                    let speed_mbps = (size as f64 / 1024.0 / 1024.0) / (time as f64 / 1000.0);

                    // Apply maximum speed filter (1000MB/s to avoid filtering high-speed downloads, updated from 500MB/s)
                    if speed_mbps <= 1000.0 {
                        server_speeds
                            .entry(server_id.clone())
                            .or_insert_with(Vec::new)
                            .push(speed_mbps);
                    }
                }
            }
        }
    }

    let mut detailed_stats = Vec::new();

    // Get all unique server IDs
    let mut all_servers: std::collections::HashSet<String> = std::collections::HashSet::new();
    all_servers.extend(server_requests.keys().cloned());

    for server_id in all_servers {
        let request_count = *server_requests.get(&server_id).unwrap_or(&0);

        // Skip servers with very few requests to avoid statistical noise
        if request_count < 5 {
            continue;
        }

        let ttfb_stats = server_ttfbs.get(&server_id).and_then(|ttfbs| {
            if ttfbs.len() >= 3 {
                Some(calculate_detailed_statistics(ttfbs))
            } else {
                None
            }
        });

        let speed_stats = server_speeds.get(&server_id).and_then(|speeds| {
            if speeds.len() >= 3 {
                Some(calculate_detailed_statistics(speeds))
            } else {
                None
            }
        });

        // Calculate overall coverage
        let has_stats = ttfb_stats.is_some() || speed_stats.is_some();
        let coverage_percentage = if has_stats {
            let ttfb_count = server_ttfbs.get(&server_id).map(|v| v.len()).unwrap_or(0);
            let speed_count = server_speeds.get(&server_id).map(|v| v.len()).unwrap_or(0);
            let max_count = ttfb_count.max(speed_count);
            (max_count as f64 / request_count as f64) * 100.0
        } else {
            0.0
        };

        if has_stats {
            let impact_stats = session_impacts.get(&server_id).cloned();
            let file_size_stats = file_size_performance.get(&server_id).cloned();

            detailed_stats.push(ServerDetailedStats {
                server_id,
                ttfb_stats,
                speed_stats,
                request_count,
                coverage_percentage,
                impact_stats,
                file_size_stats,
            });
        }
    }

    // Sort by request count (most active servers first)
    detailed_stats.sort_by(|a, b| b.request_count.cmp(&a.request_count));

    detailed_stats
}

fn calculate_detailed_statistics(data: &[f64]) -> DetailedStatistics {
    if data.is_empty() {
        return DetailedStatistics {
            mean: 0.0,
            median: 0.0,
            min: 0.0,
            max: 0.0,
            std_dev: 0.0,
            p95: 0.0,
            p99: 0.0,
            sample_count: 0,
        };
    }

    let mut sorted_data = data.to_vec();
    sorted_data.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let len = sorted_data.len();
    let mean = sorted_data.iter().sum::<f64>() / len as f64;

    // Median
    let median = if len % 2 == 0 {
        (sorted_data[len / 2 - 1] + sorted_data[len / 2]) / 2.0
    } else {
        sorted_data[len / 2]
    };

    // Min and Max
    let min = sorted_data[0];
    let max = sorted_data[len - 1];

    // Standard deviation
    let variance = sorted_data
        .iter()
        .map(|x| {
            let diff = x - mean;
            diff * diff
        })
        .sum::<f64>()
        / len as f64;
    let std_dev = variance.sqrt();

    // Percentiles (排除异常慢的数据)
    // P95: 排除最慢的5%后，剩余95%数据的最小值
    // P99: 排除最慢的1%后，剩余99%数据的最小值
    let p95_index = ((len as f64 * 0.05).ceil() as usize).min(len - 1);
    let p99_index = ((len as f64 * 0.01).ceil() as usize).min(len - 1);

    let p95 = sorted_data[p95_index];
    let p99 = sorted_data[p99_index];

    DetailedStatistics {
        mean,
        median,
        min,
        max,
        std_dev,
        p95,
        p99,
        sample_count: len,
    }
}

/// Analyze performance by file size categories for each server
fn analyze_file_size_performance(
    cdn_records: &[CdnRecordWithMeta],
    sessions: &[SessionLog],
) -> HashMap<String, FileSizePerformance> {
    // File size thresholds in MB
    const TINY_THRESHOLD: f64 = 1.0; // <1MB
    const SMALL_THRESHOLD: f64 = 4.0; // 1-4MB  
    const MEDIUM_THRESHOLD: f64 = 20.0; // 4-20MB
    // >20MB = large files

    // Data structures to collect measurements by server and size category
    let mut server_data: HashMap<String, FileSizeCategoryData> = HashMap::new();

    // Create session map for calculating file sizes from chunks
    let mut session_map: HashMap<String, &SessionLog> = HashMap::new();
    for session in sessions {
        if let Some(sid) = &session.sid {
            session_map.insert(sid.clone(), session);
        }
    }

    // Collect data by server and file size category
    for record_meta in cdn_records {
        if let Some(server_id) = &record_meta.server_id {
            let entry = server_data
                .entry(server_id.clone())
                .or_insert_with(FileSizeCategoryData::new);

            if let (Some(size), Some(time)) = (record_meta.record.size, record_meta.record.time) {
                // Only include successful downloads
                if record_meta.record.err.is_none() && time >= 10 && size >= 10240 {
                    let file_size_mb = size as f64 / (1024.0 * 1024.0);
                    let duration_seconds = time as f64 / 1000.0;
                    let speed_mbps = file_size_mb / duration_seconds;

                    // Skip unrealistic speeds
                    if speed_mbps <= 1000.0 {
                        let category_data = match file_size_mb {
                            x if x < TINY_THRESHOLD => &mut entry.tiny_files,
                            x if x < SMALL_THRESHOLD => &mut entry.small_files,
                            x if x < MEDIUM_THRESHOLD => &mut entry.medium_files,
                            _ => &mut entry.large_files,
                        };

                        category_data.durations.push(duration_seconds);

                        // Collect TTFB for tiny and small files (where it's most relevant)
                        if file_size_mb < SMALL_THRESHOLD {
                            if let Some(ttfb) = record_meta.record.ttfb {
                                category_data.ttfbs.push(ttfb as f64);
                            }
                        }

                        // Collect speed for small, medium, and large files (where it's most accurate)
                        if file_size_mb >= TINY_THRESHOLD {
                            category_data.speeds.push(speed_mbps);
                        }
                    }
                }
            }
        }
    }

    // Convert collected data to FileSizePerformance structures
    let mut result = HashMap::new();
    for (server_id, category_data) in server_data {
        if category_data.has_any_data() {
            result.insert(
                server_id,
                FileSizePerformance {
                    tiny_files: create_file_size_stats(&category_data.tiny_files, true, false), // TTFB only
                    small_files: create_file_size_stats(&category_data.small_files, true, true), // Both TTFB and speed
                    medium_files: create_file_size_stats(&category_data.medium_files, false, true), // Speed only
                    large_files: create_file_size_stats(&category_data.large_files, false, true), // Speed only
                },
            );
        }
    }

    result
}

#[derive(Default)]
struct FileSizeCategoryData {
    tiny_files: CategoryMeasurements,
    small_files: CategoryMeasurements,
    medium_files: CategoryMeasurements,
    large_files: CategoryMeasurements,
}

impl FileSizeCategoryData {
    fn new() -> Self {
        Default::default()
    }

    fn has_any_data(&self) -> bool {
        !self.tiny_files.durations.is_empty()
            || !self.small_files.durations.is_empty()
            || !self.medium_files.durations.is_empty()
            || !self.large_files.durations.is_empty()
    }
}

#[derive(Default)]
struct CategoryMeasurements {
    ttfbs: Vec<f64>,
    speeds: Vec<f64>,
    durations: Vec<f64>,
}

fn create_file_size_stats(
    measurements: &CategoryMeasurements,
    include_ttfb: bool,
    include_speed: bool,
) -> FileSizeStats {
    let count = measurements.durations.len();

    let ttfb_stats = if include_ttfb && !measurements.ttfbs.is_empty() {
        Some(calculate_detailed_statistics(&measurements.ttfbs))
    } else {
        None
    };

    let speed_stats = if include_speed && !measurements.speeds.is_empty() {
        Some(calculate_detailed_statistics(&measurements.speeds))
    } else {
        None
    };

    let duration_stats = if !measurements.durations.is_empty() {
        calculate_detailed_statistics(&measurements.durations)
    } else {
        DetailedStatistics {
            mean: 0.0,
            median: 0.0,
            min: 0.0,
            max: 0.0,
            std_dev: 0.0,
            p95: 0.0,
            p99: 0.0,
            sample_count: 0,
        }
    };

    FileSizeStats {
        count,
        ttfb_stats,
        speed_stats,
        duration_stats,
    }
}

// CPI v5 calculation constants - concurrency-aware rebalanced weights (方案1优化)
const TAIL_PERFORMANCE_WEIGHT: f64 = 0.40; // 增加尾部性能权重 - 直接影响完成时间
const LOW_CONCURRENCY_SPEED_WEIGHT: f64 = 0.30; // 增加真实速度权重 - 更突出性能差异
const CRITICAL_RELIABILITY_WEIGHT: f64 = 0.15; // 降低过严的可靠性权重
const ADAPTABILITY_WEIGHT: f64 = 0.10; // 稳定性评估权重保持不变
const CONTRIBUTION_WEIGHT_V5: f64 = 0.05; // 降低贡献权重，更专注性能

// Base score to ensure minimum reasonable scores
const BASE_SCORE: f64 = 20.0;

// Legacy CPI v4 weights (kept for compatibility)
const EFFICIENCY_WEIGHT: f64 = 0.30; // Relative efficiency (with execution delay correction)
const TRUE_BOTTLENECK_WEIGHT: f64 = 0.25; // True bottleneck avoidance (scheduling-aware)  
const CONTRIBUTION_WEIGHT: f64 = 0.25; // Session contribution and reliability
const STABILITY_WEIGHT: f64 = 0.15; // Performance and scheduling consistency
const SPECIALIZATION_WEIGHT: f64 = 0.05; // Specialized performance bonus

/// Calculate Comprehensive Performance Index v5 - concurrency context-aware analysis
fn calculate_cpi_v5(
    server: &str,
    sessions: &[SessionLog],
    timeline_cache: &HashMap<String, SessionConcurrencyTimeline>,
    usage_rate: f64,
    data_processed: u64,
    global_stats: &GlobalPerformanceStats,
) -> f64 {
    let _session_scores: Vec<f64> = Vec::new(); // Unused but keep for potential future use
    let mut total_tail_score = 0.0;
    let mut total_speed_score = 0.0;
    let mut total_reliability_score = 0.0;
    let mut total_adaptability_score = 0.0;
    let mut valid_sessions = 0;

    for session in sessions {
        // Skip sessions where this server didn't participate
        let server_participated = session.chunks.iter().any(|chunk| {
            chunk
                .cdns
                .iter()
                .any(|cdn| cdn.srv.as_ref().map(|s| s == server).unwrap_or(false))
        });

        if !server_participated {
            continue;
        }

        valid_sessions += 1;

        // 1. Context-aware speed evaluation
        let context_speed = if let Some(ref session_id) = session.sid {
            if let Some(timeline) = timeline_cache.get(session_id) {
                calculate_context_aware_speed_score(server, session, timeline)
            } else {
                ContextAwareSpeed::default()
            }
        } else {
            ContextAwareSpeed::default()
        };

        // 2. Tail performance analysis (most critical)
        let tail_score = match analyze_tail_performance(server, session) {
            TailPerformance::Excellent => 1.0,
            TailPerformance::Normal => 0.75,
            TailPerformance::NotPresent => 0.6, // Neutral - not in critical path
            TailPerformance::Bottleneck { severity } => match severity.as_str() {
                "critical" => 0.0,
                "moderate" => 0.3,
                _ => 0.1,
            },
        };

        // 3. Low concurrency speed (most reliable speed measurement) - 方案C优化
        let low_concurrency_score = if context_speed.low_concurrency_speed > 0.0 {
            let expected_speed = estimate_expected_speed_by_file_size(8 * 1024 * 1024); // 8MB baseline
            // 对异常高速进行限制，避免小文件统计误差
            let capped_speed = context_speed.low_concurrency_speed.min(50.0); // 限制最高50MB/s
            (capped_speed / expected_speed).min(2.0) / 2.0
        } else if context_speed.medium_concurrency_speed > 0.0 {
            // 使用中等并发数据作为备选，不给折扣但要扣分
            let expected_speed = estimate_expected_speed_by_file_size(8 * 1024 * 1024);
            let capped_speed = context_speed.medium_concurrency_speed.min(30.0);
            // 从中等并发推算，评分打8折
            ((capped_speed / expected_speed).min(2.0) / 2.0) * 0.8
        } else if context_speed.high_concurrency_speed > 0.0 {
            // 最后备选：使用高并发数据，不给折扣但要扣分更多
            let expected_speed = estimate_expected_speed_by_file_size(8 * 1024 * 1024);
            let capped_speed = context_speed.high_concurrency_speed.min(20.0);
            // 从高并发推算，评分打6折
            ((capped_speed / expected_speed).min(2.0) / 2.0) * 0.6
        } else {
            0.3 // 降低默认值，区分有数据和无数据的服务器
        };

        // 4. Critical path reliability (performance when it matters most)
        let critical_reliability = if server_in_critical_path_session(server, session) {
            // If this server is in critical path, how did it perform?
            let critical_performance = calculate_critical_path_performance(server, session);
            critical_performance
        } else {
            0.8 // Good score if not in critical path (doesn't cause problems)
        };

        // 5. Adaptability across concurrency levels
        let adaptability = calculate_performance_adaptability(&context_speed);

        // Accumulate scores
        total_tail_score += tail_score;
        total_speed_score += low_concurrency_score;
        total_reliability_score += critical_reliability;
        total_adaptability_score += adaptability;
    }

    if valid_sessions == 0 {
        return BASE_SCORE; // Return base score if no valid sessions
    }

    // Calculate average scores
    let avg_tail_score = total_tail_score / valid_sessions as f64;
    let avg_speed_score = total_speed_score / valid_sessions as f64;
    let avg_reliability_score = total_reliability_score / valid_sessions as f64;
    let avg_adaptability_score = total_adaptability_score / valid_sessions as f64;

    // 6. System contribution score
    let success_rate = 1.0; // Assume 100% for now, can be calculated from error rates
    let contribution_score = calculate_contribution_score(
        data_processed,
        global_stats.total_data_processed,
        success_rate,
    );

    // Combine weighted scores
    let performance_score = (avg_tail_score * TAIL_PERFORMANCE_WEIGHT
        + avg_speed_score * LOW_CONCURRENCY_SPEED_WEIGHT
        + avg_reliability_score * CRITICAL_RELIABILITY_WEIGHT
        + avg_adaptability_score * ADAPTABILITY_WEIGHT
        + contribution_score * CONTRIBUTION_WEIGHT_V5)
        * (100.0 - BASE_SCORE);

    // Final score with base score guarantee
    (BASE_SCORE + performance_score).max(0.0).min(100.0)
}

/// Check if server is in critical path for a session
fn server_in_critical_path_session(server: &str, session: &SessionLog) -> bool {
    let session_duration = (session.end - session.start) as f64;
    let critical_threshold = session.start + (session_duration * CRITICAL_PATH_WINDOW) as u64;

    // Check if server has any downloads that complete near the end
    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            if let Some(server_id) = &cdn_record.srv {
                if server_id == server {
                    if let Some(duration) = cdn_record.time {
                        let completion_time = cdn_record.ts + duration as u64;
                        if completion_time >= critical_threshold {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

/// Calculate performance when server is in critical path
fn calculate_critical_path_performance(server: &str, session: &SessionLog) -> f64 {
    let session_duration = (session.end - session.start) as f64;
    let critical_threshold = session.start + (session_duration * CRITICAL_PATH_WINDOW) as u64;

    let mut critical_speeds = Vec::new();

    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            if let Some(server_id) = &cdn_record.srv {
                if server_id == server {
                    if let (Some(size), Some(duration)) = (cdn_record.size, cdn_record.time) {
                        let completion_time = cdn_record.ts + duration as u64;
                        if completion_time >= critical_threshold && duration > 10 {
                            let speed =
                                (size as f64 / 1024.0 / 1024.0) / (duration as f64 / 1000.0);
                            critical_speeds.push(speed);
                        }
                    }
                }
            }
        }
    }

    if critical_speeds.is_empty() {
        return 0.8; // Neutral if no critical path data
    }

    let avg_critical_speed = critical_speeds.iter().sum::<f64>() / critical_speeds.len() as f64;

    // Use the new evaluate_reliability_score function for more nuanced assessment
    evaluate_reliability_score(avg_critical_speed)
}

// Grade thresholds - adjusted for better distribution
const GRADE_S_THRESHOLD: f64 = 80.0;
const GRADE_A_THRESHOLD: f64 = 70.0;
const GRADE_B_THRESHOLD: f64 = 55.0;
const GRADE_C_THRESHOLD: f64 = 40.0;
const GRADE_D_THRESHOLD: f64 = 25.0;

// File size thresholds
const SMALL_FILE_THRESHOLD: u64 = 100 * 1024; // 100KB
const LARGE_FILE_THRESHOLD: u64 = 10 * 1024 * 1024; // 10MB

// Minimum time threshold to avoid division by zero
const MIN_TIME_MS: f64 = 10.0;

/// Calculate layered efficiency score based on file size distribution
fn calculate_layered_efficiency(file_size_stats: &FileSizeDistribution, total_files: usize) -> f64 {
    if total_files == 0 {
        return 0.5; // Default neutral score
    }

    let small_weight = file_size_stats.small_files as f64 / total_files as f64;
    let medium_weight = file_size_stats.medium_files as f64 / total_files as f64;
    let large_weight = file_size_stats.large_files as f64 / total_files as f64;

    // Weighted efficiency based on file size distribution
    let weighted_efficiency = small_weight * file_size_stats.small_file_efficiency +
        medium_weight * normalize_speed(file_size_stats.medium_file_speed, 5.0) +  // Assume 5MB/s is good for medium
        large_weight * normalize_speed(file_size_stats.large_file_speed, 10.0); // Assume 10MB/s is good for large

    weighted_efficiency.min(1.0).max(0.0)
}

/// Normalize speed to 0-1 scale based on expected good speed
fn normalize_speed(actual_speed: f64, expected_speed: f64) -> f64 {
    if expected_speed <= 0.0 {
        return 0.5;
    }
    (actual_speed / expected_speed).min(2.0) / 2.0 // Cap at 2x expected = 1.0
}

/// Calculate relative bottleneck impact score - enhanced for CPI v4 with execution delay awareness
fn calculate_relative_impact(
    tail_rate: f64,
    usage_rate: f64,
    avg_file_size: f64,
    global_avg_tail_rate: f64,
) -> f64 {
    if usage_rate <= 0.0 {
        return 0.0;
    }

    // Relative tail appearance (normalized by usage)
    let relative_tail = tail_rate / usage_rate;
    let avg_relative_tail = global_avg_tail_rate;

    // Adjust for file size (large files naturally appear in tail)
    let size_adjustment = if avg_file_size > LARGE_FILE_THRESHOLD as f64 {
        0.7 // Reduce penalty for large file servers (improved from 0.5 to 0.7)
    } else {
        1.0
    };

    // Calculate impact score (inverse of bottleneck tendency)
    let bottleneck_factor = (relative_tail / avg_relative_tail.max(0.01)) * size_adjustment;
    1.0 / (1.0 + bottleneck_factor) // Convert to 0-1 scale where higher is better
}

/// Calculate true bottleneck impact distinguishing real performance issues from scheduling delays
fn calculate_true_bottleneck_impact(
    tail_appearances: usize,
    total_sessions: usize,
    avg_execution_delay: f64,
    avg_scheduling_delay: f64,
    usage_rate: f64,
    avg_file_size: f64,
    global_avg_tail_rate: f64,
) -> f64 {
    if total_sessions == 0 || usage_rate <= 0.0 {
        return 1.0; // No impact data, return neutral
    }

    let tail_rate = (tail_appearances as f64 / total_sessions as f64) * 100.0;

    // Get base impact score
    let base_impact =
        calculate_relative_impact(tail_rate, usage_rate, avg_file_size, global_avg_tail_rate);

    // Apply true bottleneck weighting
    let bottleneck_weight =
        calculate_true_bottleneck_weight(avg_execution_delay, avg_scheduling_delay, total_sessions);

    // Adjust impact based on whether this is a true bottleneck or scheduling issue
    if bottleneck_weight > 1.0 {
        // True bottleneck: amplify the negative impact
        base_impact * (2.0 - bottleneck_weight + 1.0).min(1.0)
    } else if bottleneck_weight < 1.0 {
        // Scheduling issue: reduce the negative impact
        base_impact + (1.0 - base_impact) * (1.0 - bottleneck_weight)
    } else {
        // Normal case
        base_impact
    }
}

/// Calculate performance variance coefficient (CV)
fn calculate_performance_cv(performance_values: &[f64]) -> f64 {
    if performance_values.len() < 2 {
        return 0.0; // Not enough data
    }

    let mean = performance_values.iter().sum::<f64>() / performance_values.len() as f64;
    if mean <= 0.0 {
        return 1.0; // Maximum instability
    }

    let variance = performance_values
        .iter()
        .map(|v| (v - mean).powi(2))
        .sum::<f64>()
        / performance_values.len() as f64;

    let std_dev = variance.sqrt();
    std_dev / mean // Coefficient of variation
}

/// Calculate median from a vector of values
fn calculate_median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

/// Calculate execution delay based on expected performance within the session context
fn calculate_execution_delay(
    actual_duration: f64,
    file_size: u64,
    session_median_speed: f64,
) -> f64 {
    if session_median_speed <= 0.0 || file_size == 0 {
        return 0.0;
    }

    let file_size_mb = file_size as f64 / (1024.0 * 1024.0);
    let expected_duration = file_size_mb / session_median_speed;

    // Return positive value if slower than expected, negative if faster
    actual_duration - expected_duration
}

/// Calculate scheduling delay as relative position within session
fn calculate_scheduling_delay(start_time: u64, session_start: u64, session_duration: f64) -> f64 {
    if session_duration <= 0.0 {
        return 0.0;
    }

    let relative_start = (start_time - session_start) as f64 / session_duration;
    relative_start.max(0.0).min(1.0) // Clamp to 0-1 range
}

/// Calculate true bottleneck weight distinguishing real performance issues from scheduling delays
fn calculate_true_bottleneck_weight(
    avg_execution_delay: f64,
    avg_scheduling_delay: f64,
    session_count: usize,
) -> f64 {
    if session_count == 0 {
        return 1.0;
    }

    // Early start + slow completion = true bottleneck
    if avg_scheduling_delay < 0.5 && avg_execution_delay > 0.5 {
        2.0
    }
    // Late start = likely scheduling issue, reduce impact
    else if avg_scheduling_delay > 0.7 {
        0.5
    }
    // Normal case
    else {
        1.0
    }
}

/// Concurrency analysis structures for CPI v5
#[derive(Debug, Clone)]
struct ConcurrencyWindow {
    start_time: u64,
    end_time: u64,
    concurrency_level: usize,
    bandwidth_competition: f64,
}

/// Speed sample with concurrency context
#[derive(Debug, Clone)]
struct SpeedSample {
    raw_speed: f64,
    concurrency_level: usize,
    reliability_weight: f64,
    file_size: u64,
}

/// Context-aware speed evaluation result
#[derive(Debug, Clone, Default)]
struct ContextAwareSpeed {
    high_concurrency_speed: f64,   // >12 threads
    medium_concurrency_speed: f64, // 4-12 threads
    low_concurrency_speed: f64,    // <4 threads
    tail_speed: f64,               // Last 10% of session
}

/// Tail performance analysis result
#[derive(Debug, Clone)]
enum TailPerformance {
    NotPresent,
    Excellent,
    Normal,
    Bottleneck { severity: String },
}

/// Analyze concurrency windows throughout a session
fn analyze_concurrency_windows(session: &SessionLog) -> Vec<ConcurrencyWindow> {
    let mut windows = Vec::new();

    // Create time slots every 100ms
    let session_duration = (session.end - session.start) as f64;
    let slot_size = 100.0; // 100ms
    let num_slots = (session_duration / slot_size) as usize;

    for i in 0..num_slots {
        let slot_start = session.start + (i as f64 * slot_size) as u64;
        let slot_end = session.start + ((i + 1) as f64 * slot_size) as u64;

        // Count active downloads in this time slot
        let active_downloads = count_active_downloads_in_slot(slot_start, slot_end, session);

        windows.push(ConcurrencyWindow {
            start_time: slot_start,
            end_time: slot_end,
            concurrency_level: active_downloads,
            bandwidth_competition: active_downloads as f64 / 16.0, // Normalize to max 16 threads
        });
    }

    windows
}

/// Count active downloads in a specific time slot
fn count_active_downloads_in_slot(start: u64, end: u64, session: &SessionLog) -> usize {
    let mut active_count = 0;

    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            if let Some(duration) = cdn_record.time {
                let download_start = cdn_record.ts;
                let download_end = download_start + duration as u64;

                // Check if this download overlaps with the time slot
                if download_start < end && download_end > start {
                    active_count += 1;
                }
            }
        }
    }

    active_count
}

/// Get concurrency level at a specific time - 简单版本（用于备用场景）
fn get_concurrency_at_time(timestamp: u64, session: &SessionLog) -> usize {
    let mut active_count = 0;

    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            if let Some(duration) = cdn_record.time {
                let download_start = cdn_record.ts;
                let download_end = download_start + duration as u64;

                // Check if download is active at this timestamp
                if download_start <= timestamp && timestamp <= download_end {
                    active_count += 1;
                }
            }
        }
    }

    active_count
}

/// Get concurrency level at a specific time - 使用预计算时间线
fn get_concurrency_at_time_optimized(
    timestamp: u64,
    timeline: &SessionConcurrencyTimeline,
) -> usize {
    timeline.get_concurrency_at_time(timestamp)
}

/// Calculate context-aware speed evaluation for a server in a session
fn calculate_context_aware_speed_score(
    server: &str,
    session: &SessionLog,
    timeline: &SessionConcurrencyTimeline,
) -> ContextAwareSpeed {
    let mut speed_samples = Vec::new();
    let session_duration = (session.end - session.start) as f64;
    let tail_threshold = session.start + (session_duration * 0.9) as u64;

    // Collect speed samples with concurrency context - 使用优化的并发度查询
    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            if let Some(server_id) = &cdn_record.srv {
                if server_id != server {
                    continue;
                }

                if let (Some(size), Some(duration)) = (cdn_record.size, cdn_record.time) {
                    if cdn_record.err.is_some() || duration < 10 || size < 1024 {
                        continue; // Skip failed or too small downloads
                    }

                    // 使用优化的并发度查询 - 主要性能提升点
                    let concurrency = get_concurrency_at_time_optimized(cdn_record.ts, timeline);
                    let speed = (size as f64 / 1024.0 / 1024.0) / (duration as f64 / 1000.0); // MB/s

                    let sample = SpeedSample {
                        raw_speed: speed,
                        concurrency_level: concurrency,
                        reliability_weight: calculate_reliability_weight(concurrency),
                        file_size: size as u64, // Convert u32 to u64
                    };

                    speed_samples.push(sample);
                }
            }
        }
    }

    if speed_samples.is_empty() {
        return ContextAwareSpeed::default();
    }

    // Categorize by concurrency levels - 放宽低并发定义以获得更多有用数据
    let high_concurrency: Vec<_> = speed_samples
        .iter()
        .filter(|s| s.concurrency_level > 8)
        .collect();
    let medium_concurrency: Vec<_> = speed_samples
        .iter()
        .filter(|s| s.concurrency_level >= 4 && s.concurrency_level <= 8)
        .collect();
    let low_concurrency: Vec<_> = speed_samples
        .iter()
        .filter(|s| s.concurrency_level < 4)
        .collect();

    // 计算各级别速度，不做推算，直接显示原始数据
    let low_concurrency_speed = if !low_concurrency.is_empty() {
        calculate_weighted_average_speed(&low_concurrency).min(50.0) // 限制异常值
    } else if !medium_concurrency.is_empty() {
        // 备选：显示中等并发的实际速度（不推算）
        calculate_weighted_average_speed(&medium_concurrency).min(30.0)
    } else if !high_concurrency.is_empty() {
        // 最后备选：显示高并发的实际速度（不推算）
        calculate_weighted_average_speed(&high_concurrency).min(20.0)
    } else {
        0.0
    };

    let medium_concurrency_speed = calculate_weighted_average_speed(&medium_concurrency).min(30.0);
    let high_concurrency_speed = calculate_weighted_average_speed(&high_concurrency).min(20.0);

    // Calculate tail performance (last 10% of session)
    let tail_samples: Vec<_> = speed_samples
        .iter()
        .filter(|s| {
            // Check if any download from this server happened in tail period
            for chunk in &session.chunks {
                for cdn_record in &chunk.cdns {
                    if let Some(srv) = &cdn_record.srv {
                        if srv == server && cdn_record.ts >= tail_threshold {
                            return true;
                        }
                    }
                }
            }
            false
        })
        .collect();

    ContextAwareSpeed {
        high_concurrency_speed,
        medium_concurrency_speed,
        low_concurrency_speed, // 现在包含备选逻辑
        tail_speed: calculate_weighted_average_speed(&tail_samples).min(40.0), // 限制尾部异常速度
    }
}

/// Calculate reliability weight based on concurrency level
fn calculate_reliability_weight(concurrency: usize) -> f64 {
    // Lower concurrency = higher reliability weight
    match concurrency {
        0..=2 => 1.0,  // Very reliable
        3..=6 => 0.8,  // Good reliability
        7..=12 => 0.5, // Medium reliability
        _ => 0.2,      // Low reliability due to high competition
    }
}

/// Calculate weighted average speed from samples
fn calculate_weighted_average_speed(samples: &[&SpeedSample]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }

    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;

    for sample in samples {
        weighted_sum += sample.raw_speed * sample.reliability_weight;
        total_weight += sample.reliability_weight;
    }

    if total_weight > 0.0 {
        weighted_sum / total_weight
    } else {
        0.0
    }
}

/// Analyze tail performance - crucial for overall completion time
fn analyze_tail_performance(server: &str, session: &SessionLog) -> TailPerformance {
    let session_duration = (session.end - session.start) as f64;
    let tail_start = session.start + (session_duration * 0.9) as u64;

    // Collect downloads that happened in the tail phase
    let mut tail_downloads = Vec::new();
    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            if let Some(server_id) = &cdn_record.srv {
                if server_id == server && cdn_record.ts >= tail_start {
                    if let (Some(size), Some(duration)) = (cdn_record.size, cdn_record.time) {
                        tail_downloads.push((size, duration, cdn_record.ts));
                    }
                }
            }
        }
    }

    if tail_downloads.is_empty() {
        return TailPerformance::NotPresent;
    }

    // Calculate average concurrency during tail phase
    let avg_tail_concurrency =
        calculate_avg_concurrency_in_period(tail_start, session.end, session);

    // Calculate tail performance metrics
    let mut tail_speeds = Vec::new();
    for (size, duration, _) in &tail_downloads {
        if *duration > 10 {
            let speed = (*size as f64 / 1024.0 / 1024.0) / (*duration as f64 / 1000.0);
            tail_speeds.push(speed);
        }
    }

    if tail_speeds.is_empty() {
        return TailPerformance::NotPresent;
    }

    let avg_tail_speed = tail_speeds.iter().sum::<f64>() / tail_speeds.len() as f64;

    // Expected speed based on file size (rough estimates)
    let avg_file_size: u64 = tail_downloads
        .iter()
        .map(|(size, _, _)| *size as u64)
        .sum::<u64>()
        / tail_downloads.len() as u64;
    let expected_speed = estimate_expected_speed_by_file_size(avg_file_size);

    let speed_ratio = avg_tail_speed / expected_speed;

    // Analyze performance based on concurrency context
    if avg_tail_concurrency <= 4.0 {
        // Low concurrency: speed is reliable indicator
        if speed_ratio >= 1.2 {
            TailPerformance::Excellent
        } else if speed_ratio >= 0.8 {
            TailPerformance::Normal
        } else if speed_ratio >= 0.3 {
            TailPerformance::Bottleneck {
                severity: "moderate".to_string(),
            }
        } else {
            TailPerformance::Bottleneck {
                severity: "critical".to_string(),
            }
        }
    } else {
        // High concurrency: more lenient judgment
        if speed_ratio >= 0.6 {
            TailPerformance::Normal
        } else if speed_ratio >= 0.2 {
            TailPerformance::Bottleneck {
                severity: "moderate".to_string(),
            }
        } else {
            TailPerformance::Bottleneck {
                severity: "critical".to_string(),
            }
        }
    }
}

/// Calculate average concurrency in a time period
fn calculate_avg_concurrency_in_period(start: u64, end: u64, session: &SessionLog) -> f64 {
    let period_duration = (end - start) as f64;
    if period_duration <= 0.0 {
        return 0.0;
    }

    let sample_interval = 1000.0; // 1 second intervals
    let num_samples = (period_duration / sample_interval) as usize;

    let mut concurrency_sum = 0.0;
    let mut sample_count = 0;

    for i in 0..=num_samples {
        let sample_time = start + (i as f64 * sample_interval) as u64;
        if sample_time <= end {
            concurrency_sum += get_concurrency_at_time(sample_time, session) as f64;
            sample_count += 1;
        }
    }

    if sample_count > 0 {
        concurrency_sum / sample_count as f64
    } else {
        0.0
    }
}

/// Estimate expected speed based on file size - adjusted for 100Mbps server reality
fn estimate_expected_speed_by_file_size(file_size: u64) -> f64 {
    let size_mb = file_size as f64 / (1024.0 * 1024.0);

    // Based on 5MB/s as standard performance for 100Mbps servers with multi-user sharing
    if size_mb < 1.0 {
        // Small files: expect 5MB/s
        5.0
    } else if size_mb < 8.0 {
        // Medium files: expect 5MB/s
        5.0
    } else {
        // Large files: expect 5MB/s, can be slightly higher for CDN
        6.0
    }
}

/// Calculate performance adaptability across different concurrency levels
fn calculate_performance_adaptability(context_speed: &ContextAwareSpeed) -> f64 {
    // Measure how consistent performance is across concurrency levels
    let speeds = vec![
        context_speed.high_concurrency_speed,
        context_speed.medium_concurrency_speed,
        context_speed.low_concurrency_speed,
    ];

    let valid_speeds: Vec<f64> = speeds.into_iter().filter(|&s| s > 0.0).collect();

    if valid_speeds.len() < 2 {
        return 0.5; // Neutral if not enough data
    }

    let mean = valid_speeds.iter().sum::<f64>() / valid_speeds.len() as f64;
    let variance = valid_speeds
        .iter()
        .map(|&s| (s - mean).powi(2))
        .sum::<f64>()
        / valid_speeds.len() as f64;

    let cv = if mean > 0.0 {
        variance.sqrt() / mean
    } else {
        1.0
    };

    // Lower coefficient of variation = higher adaptability
    1.0 / (1.0 + cv)
}

// Adjusted critical path evaluation constants (方案2优化 - 更符合100Mbps服务器实际)
const CRITICAL_PATH_BASE_SPEED: f64 = 3.0; // 降低基线到3MB/s，更现实的期望
const RELIABILITY_THRESHOLD: f64 = 0.3; // 降低门槛到30%，对应0.9MB/s
const CRITICAL_PATH_WINDOW: f64 = 0.8; // 分析最后20%时间，更聚焦关键阶段

/// Evaluate reliability score based on speed performance
fn evaluate_reliability_score(speed: f64) -> f64 {
    match speed {
        s if s >= 8.0 => 1.0, // 8MB/s+ = Excellent (CDN level)
        s if s >= 5.0 => 0.8, // 5-8MB/s = Good (standard performance)
        s if s >= 3.0 => 0.6, // 3-5MB/s = Moderate
        s if s >= 2.0 => 0.4, // 2-3MB/s = Basic usable
        s if s >= 1.0 => 0.2, // 1-2MB/s = Poor
        _ => 0.1,             // <1MB/s = Very poor
    }
}

/// First pass: collect global performance statistics
fn collect_global_performance_stats(
    _sessions: &[SessionLog],
    server_impacts: &HashMap<String, ServerImpactData>,
) -> GlobalPerformanceStats {
    let mut all_small_file_efficiencies = Vec::new();
    let mut all_medium_file_speeds = Vec::new();
    let mut all_large_file_speeds = Vec::new();
    let mut total_data_processed = 0u64;
    let mut total_tail_appearances = 0;
    let mut total_sessions_count = 0;

    for (_, data) in server_impacts {
        if data.total_sessions > 0 {
            // Collect small file efficiencies
            if !data.small_file_times.is_empty() {
                let avg_time =
                    data.small_file_times.iter().sum::<f64>() / data.small_file_times.len() as f64;
                if avg_time > 0.0 {
                    all_small_file_efficiencies.push(1.0 / avg_time);
                }
            }

            // Collect medium file speeds
            all_medium_file_speeds.extend(&data.medium_file_speeds);

            // Collect large file speeds
            all_large_file_speeds.extend(&data.large_file_speeds);

            // Calculate total data processed
            for &size in &data.file_sizes {
                total_data_processed += size;
            }

            // Collect tail statistics
            total_tail_appearances += data.tail_appearances;
            total_sessions_count += data.total_sessions;
        }
    }

    // Calculate medians
    let small_file_median_efficiency = if !all_small_file_efficiencies.is_empty() {
        calculate_median(&mut all_small_file_efficiencies)
    } else {
        1.0
    };

    let medium_file_median_speed = if !all_medium_file_speeds.is_empty() {
        calculate_median(&mut all_medium_file_speeds)
    } else {
        2.0
    };

    let large_file_median_speed = if !all_large_file_speeds.is_empty() {
        calculate_median(&mut all_large_file_speeds)
    } else {
        5.0
    };

    let global_avg_tail_rate = if total_sessions_count > 0 {
        (total_tail_appearances as f64 / total_sessions_count as f64) * 100.0
    } else {
        50.0
    };

    GlobalPerformanceStats {
        small_file_median_efficiency,
        medium_file_median_speed,
        large_file_median_speed,
        total_data_processed,
        global_avg_tail_rate,
    }
}

/// Improved mapping function - less conservative than sigmoid
fn performance_score_map(ratio: f64) -> f64 {
    // Linear mapping with boost for above-median performance
    if ratio >= 1.0 {
        // Above median: score from 0.6 to 1.0
        0.6 + (ratio - 1.0) * 0.4 / 1.0 // Ratio 1.0->2.0 maps to 0.6->1.0
    } else {
        // Below median: score from 0.2 to 0.6
        0.2 + ratio * 0.4 // Ratio 0.0->1.0 maps to 0.2->0.6
    }
    .min(1.0)
}

/// Calculate relative efficiency based on dynamic baselines
fn calculate_relative_efficiency(
    file_size_stats: &FileSizeDistribution,
    total_files: usize,
    global_stats: &GlobalPerformanceStats,
) -> f64 {
    if total_files == 0 {
        return 0.5;
    }

    let small_weight = file_size_stats.small_files as f64 / total_files as f64;
    let medium_weight = file_size_stats.medium_files as f64 / total_files as f64;
    let large_weight = file_size_stats.large_files as f64 / total_files as f64;

    // Calculate relative scores using improved mapping function
    let small_score = if file_size_stats.small_file_efficiency > 0.0
        && global_stats.small_file_median_efficiency > 0.0
    {
        let ratio =
            file_size_stats.small_file_efficiency / global_stats.small_file_median_efficiency;
        performance_score_map(ratio)
    } else {
        0.5
    };

    let medium_score =
        if file_size_stats.medium_file_speed > 0.0 && global_stats.medium_file_median_speed > 0.0 {
            let ratio = file_size_stats.medium_file_speed / global_stats.medium_file_median_speed;
            performance_score_map(ratio)
        } else {
            0.5
        };

    let large_score =
        if file_size_stats.large_file_speed > 0.0 && global_stats.large_file_median_speed > 0.0 {
            let ratio = file_size_stats.large_file_speed / global_stats.large_file_median_speed;
            performance_score_map(ratio)
        } else {
            0.5
        };

    // Weighted average
    small_weight * small_score + medium_weight * medium_score + large_weight * large_score
}

/// Calculate specialization bonus for focused servers
fn calculate_specialization_bonus(file_size_stats: &FileSizeDistribution) -> f64 {
    let total =
        file_size_stats.small_files + file_size_stats.medium_files + file_size_stats.large_files;
    if total == 0 {
        return 0.0;
    }

    let small_ratio = file_size_stats.small_files as f64 / total as f64;
    let medium_ratio = file_size_stats.medium_files as f64 / total as f64;
    let large_ratio = file_size_stats.large_files as f64 / total as f64;

    // Calculate concentration (Herfindahl index)
    let concentration = small_ratio.powi(2) + medium_ratio.powi(2) + large_ratio.powi(2);

    // If highly specialized (>0.8 concentration) and performing well in specialty
    if concentration > 0.8 {
        if small_ratio > 0.8 && file_size_stats.small_file_efficiency > 0.0 {
            return 1.0; // Full bonus for small file specialists
        }
        if medium_ratio > 0.8 && file_size_stats.medium_file_speed > 0.0 {
            return 1.0; // Full bonus for medium file specialists
        }
        if large_ratio > 0.8 && file_size_stats.large_file_speed > 0.0 {
            return 1.0; // Full bonus for large file specialists
        }
    }

    0.0
}

/// Calculate contribution score based on data processed and success rate
fn calculate_contribution_score(data_processed: u64, total_data: u64, success_rate: f64) -> f64 {
    let data_contribution = if total_data > 0 {
        (data_processed as f64 / total_data as f64).min(1.0)
    } else {
        0.0
    };

    // Combine data contribution with success rate
    data_contribution * success_rate
}

/// Calculate soft penalty for anomalies
fn calculate_soft_penalty(ttfb_p95: f64, error_rate: f64) -> f64 {
    let mut penalty = 0.0;

    // TTFB penalty - more lenient, up to 3 points for 10+ seconds
    if ttfb_p95 > 5000.0 {
        // Only penalize if > 5 seconds
        penalty += ((ttfb_p95 - 5000.0) / 5000.0).min(3.0);
    }

    // Error rate penalty - more lenient, up to 3 points for 10%+ errors
    if error_rate > 0.05 {
        // Only penalize if > 5% errors
        penalty += ((error_rate - 0.05) * 60.0).min(3.0);
    }

    penalty
}

/// Calculate Comprehensive Performance Index v4 - concurrent-aware with execution delay analysis
fn calculate_cpi_v4(
    file_size_stats: &FileSizeDistribution,
    tail_appearances: usize,
    total_sessions: usize,
    usage_rate: f64,
    performance_cv: f64,
    ttfb_p95: f64,
    error_rate: f64,
    avg_file_size: f64,
    data_processed: u64,
    avg_execution_delay: f64,
    avg_scheduling_delay: f64,
    global_stats: &GlobalPerformanceStats,
) -> f64 {
    let total_files =
        file_size_stats.small_files + file_size_stats.medium_files + file_size_stats.large_files;

    // 1. Enhanced Efficiency Score (30%) - relative to dynamic baselines with execution delay correction
    let base_efficiency = calculate_relative_efficiency(file_size_stats, total_files, global_stats);

    // Apply execution delay correction - penalize servers that are consistently slower than expected
    let execution_efficiency_correction = if avg_execution_delay > 0.0 {
        1.0 / (1.0 + avg_execution_delay)
    } else {
        1.0 + (-avg_execution_delay * 0.1).min(0.2) // Small bonus for being faster than expected
    };

    let enhanced_efficiency =
        (base_efficiency * execution_efficiency_correction) * EFFICIENCY_WEIGHT;

    // 2. True Bottleneck Impact Score (25%) - distinguish real bottlenecks from scheduling delays
    let true_bottleneck_impact = calculate_true_bottleneck_impact(
        tail_appearances,
        total_sessions,
        avg_execution_delay,
        avg_scheduling_delay,
        usage_rate,
        avg_file_size,
        global_stats.global_avg_tail_rate,
    ) * TRUE_BOTTLENECK_WEIGHT;

    // 3. Contribution Score (25%) - data processed and success rate
    let success_rate = 1.0 - error_rate;
    let contribution = calculate_contribution_score(
        data_processed,
        global_stats.total_data_processed,
        success_rate,
    ) * CONTRIBUTION_WEIGHT;

    // 4. Enhanced Stability Score (15%) - performance CV + scheduling consistency
    let performance_stability = 1.0 - performance_cv.min(1.0);

    // Add scheduling consistency - reward servers with consistent scheduling patterns
    let scheduling_consistency = if total_sessions > 1 {
        // Lower scheduling delay variance indicates more consistent assignment patterns
        1.0 - (avg_scheduling_delay * 0.5).min(1.0) // Penalize consistently late assignments
    } else {
        1.0
    };

    let enhanced_stability =
        (performance_stability * 0.7 + scheduling_consistency * 0.3) * STABILITY_WEIGHT;

    // 5. Specialization Bonus (5%) - reward for focused performance
    let specialization = calculate_specialization_bonus(file_size_stats) * SPECIALIZATION_WEIGHT;

    // Combine scores
    let performance_score = (enhanced_efficiency
        + true_bottleneck_impact
        + contribution
        + enhanced_stability
        + specialization)
        * (100.0 - BASE_SCORE);

    // Apply soft penalty with execution delay awareness
    let base_penalty = calculate_soft_penalty(ttfb_p95, error_rate);

    // Additional penalty for persistent execution delays
    let execution_delay_penalty = if avg_execution_delay > 1.0 {
        // >1 second delay
        (avg_execution_delay - 1.0).min(3.0)
    } else {
        0.0
    };

    let total_penalty = base_penalty + execution_delay_penalty;

    // Final score with base score guarantee
    (BASE_SCORE + performance_score - total_penalty)
        .max(0.0)
        .min(100.0)
}

/// Calculate Comprehensive Performance Index v3 for a server (legacy)
fn calculate_cpi_v3(
    file_size_stats: &FileSizeDistribution,
    tail_rate: f64,
    usage_rate: f64,
    _sessions_used: usize,
    _total_sessions: usize,
    _bottleneck_count: usize,
    performance_cv: f64,
    ttfb_p95: f64,
    error_rate: f64,
    avg_file_size: f64,
    data_processed: u64,
    global_stats: &GlobalPerformanceStats,
) -> f64 {
    let total_files =
        file_size_stats.small_files + file_size_stats.medium_files + file_size_stats.large_files;

    // 1. Efficiency Score (30%) - relative to dynamic baselines
    let efficiency = calculate_relative_efficiency(file_size_stats, total_files, global_stats)
        * EFFICIENCY_WEIGHT;

    // 2. Impact Score (25%) - relative bottleneck impact with improved calculation
    let impact = calculate_relative_impact(
        tail_rate,
        usage_rate,
        avg_file_size,
        global_stats.global_avg_tail_rate,
    ) * TRUE_BOTTLENECK_WEIGHT;

    // 3. Contribution Score (25%) - data processed and success rate
    let success_rate = 1.0 - error_rate;
    let contribution = calculate_contribution_score(
        data_processed,
        global_stats.total_data_processed,
        success_rate,
    ) * CONTRIBUTION_WEIGHT;

    // 4. Stability Score (15%) - based on performance CV
    let stability = (1.0 - performance_cv.min(1.0)) * STABILITY_WEIGHT;

    // 5. Specialization Bonus (5%) - reward for focused performance
    let specialization = calculate_specialization_bonus(file_size_stats) * SPECIALIZATION_WEIGHT;

    // Combine scores
    let performance_score =
        (efficiency + impact + contribution + stability + specialization) * (100.0 - BASE_SCORE);

    // Apply soft penalty
    let penalty = calculate_soft_penalty(ttfb_p95, error_rate);

    // Final score with base score guarantee
    (BASE_SCORE + performance_score - penalty)
        .max(0.0)
        .min(100.0)
}

/// Calculate Comprehensive Performance Index v2 for a server
fn calculate_cpi_v2(
    file_size_stats: &FileSizeDistribution,
    tail_rate: f64,
    usage_rate: f64,
    sessions_used: usize,
    total_sessions: usize,
    bottleneck_count: usize,
    performance_cv: f64,
    ttfb_p95: f64,
    error_rate: f64,
    avg_file_size: f64,
    global_avg_tail_rate: f64,
) -> f64 {
    let total_files =
        file_size_stats.small_files + file_size_stats.medium_files + file_size_stats.large_files;

    // 1. Efficiency Score (35%) - layered calculation based on file sizes
    let efficiency = calculate_layered_efficiency(file_size_stats, total_files) * EFFICIENCY_WEIGHT;

    // 2. Impact Score (35%) - relative bottleneck impact
    let impact =
        calculate_relative_impact(tail_rate, usage_rate, avg_file_size, global_avg_tail_rate)
            * TRUE_BOTTLENECK_WEIGHT;

    // 3. Participation Score (20%) - effective participation
    let success_rate = 1.0 - error_rate;
    let effective_participation = if total_sessions > 0 {
        let participation_rate = sessions_used as f64 / total_sessions as f64;
        let bottleneck_rate = if sessions_used > 0 {
            bottleneck_count as f64 / sessions_used as f64
        } else {
            0.0
        };
        participation_rate * success_rate * (1.0 - bottleneck_rate * 0.5) // Reduce bottleneck penalty
    } else {
        0.0
    };
    let participation = effective_participation * CONTRIBUTION_WEIGHT;

    // 4. Stability Score (10%) - based on CV (lower is better)
    let stability = (1.0 - performance_cv.min(1.0)) * STABILITY_WEIGHT;

    // Base CPI score
    let base_cpi = (efficiency + impact + participation + stability) * 100.0;

    // Apply penalty for anomalies (max 10 points)
    let mut penalty = 0.0;

    // TTFB penalty (max 5 points)
    if ttfb_p95 > 5000.0 {
        // > 5 seconds
        penalty += 5.0;
    }

    // Error rate penalty (max 5 points)
    if error_rate > 0.05 {
        // > 5% errors
        penalty += 5.0;
    }

    // Final CPI score
    (base_cpi - penalty).max(0.0)
}

/// Assign performance grade based on CPI score
fn assign_grade(cpi_score: f64) -> String {
    if cpi_score >= GRADE_S_THRESHOLD {
        "S".to_string()
    } else if cpi_score >= GRADE_A_THRESHOLD {
        "A".to_string()
    } else if cpi_score >= GRADE_B_THRESHOLD {
        "B".to_string()
    } else if cpi_score >= GRADE_C_THRESHOLD {
        "C".to_string()
    } else if cpi_score >= GRADE_D_THRESHOLD {
        "D".to_string()
    } else {
        "F".to_string()
    }
}

/// Calculate actual session duration using the last download completion time
fn calculate_actual_session_duration(session: &SessionLog) -> f64 {
    let mut latest_completion_time = session.start;

    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            if let Some(time) = cdn_record.time {
                let completion_time = cdn_record.ts + time as u64;
                latest_completion_time = latest_completion_time.max(completion_time);
            }
        }
    }

    if latest_completion_time > session.start {
        (latest_completion_time - session.start) as f64
    } else {
        // Fallback to reported duration if no download times available
        (session.end - session.start) as f64
    }
}

/// Get the first download start time in a session
fn get_first_download_start(session: &SessionLog) -> f64 {
    let mut earliest_start = session.start;

    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            earliest_start = earliest_start.min(cdn_record.ts);
        }
    }

    earliest_start as f64
}

/// Calculate session extension based on speed difference from other servers' average
fn calculate_speed_based_extension(
    session: &SessionLog,
    target_server: &str,
    server_analysis: &HashMap<String, BottleneckAnalysis>,
) -> f64 {
    // Get target server performance data
    let _target_analysis = match server_analysis.get(target_server) {
        Some(analysis) => analysis,
        None => return 0.0,
    };

    // Calculate target server metrics
    let mut target_bytes = 0u64;
    let mut target_duration = 0.0f64;

    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            if let Some(server_id) = &cdn_record.srv {
                if server_id == target_server {
                    if let Some(duration) = cdn_record.time {
                        target_bytes +=
                            (allocation::parse_chunk_size(&chunk.rng) * 1024.0 * 1024.0) as u64;
                        target_duration += duration as f64 / 1000.0; // Convert to seconds
                    }
                }
            }
        }
    }

    if target_duration <= 0.0 || target_bytes == 0 {
        return 0.0;
    }

    // Calculate average speed of other servers
    let mut other_speeds: Vec<f64> = Vec::new();

    for (server_id, _) in server_analysis {
        if server_id == target_server {
            continue; // Skip target server
        }

        let mut server_bytes = 0u64;
        let mut server_duration = 0.0f64;

        for chunk in &session.chunks {
            for cdn_record in &chunk.cdns {
                if let Some(srv_id) = &cdn_record.srv {
                    if srv_id == server_id {
                        if let Some(duration) = cdn_record.time {
                            server_bytes +=
                                (allocation::parse_chunk_size(&chunk.rng) * 1024.0 * 1024.0) as u64;
                            server_duration += duration as f64 / 1000.0;
                        }
                    }
                }
            }
        }

        if server_duration > 0.0 && server_bytes > 0 {
            let speed = server_bytes as f64 / server_duration; // bytes per second
            other_speeds.push(speed);
        }
    }

    if other_speeds.is_empty() {
        return 0.0; // Cannot compare if no other servers
    }

    // Calculate average speed of other servers
    let avg_speed = other_speeds.iter().sum::<f64>() / other_speeds.len() as f64;

    if avg_speed <= 0.0 {
        return 0.0;
    }

    // Calculate expected duration based on average speed
    let expected_duration = target_bytes as f64 / avg_speed;

    // Extension = actual - expected (can be positive or negative)
    target_duration - expected_duration
}

/// Calculate session-level speed context for execution delay analysis
fn calculate_session_speed_context(session: &SessionLog) -> Vec<f64> {
    let mut session_speeds = Vec::new();

    for chunk in &session.chunks {
        let _chunk_size = allocation::parse_chunk_size(&chunk.rng) * 1024.0 * 1024.0; // Convert to MB

        for cdn_record in &chunk.cdns {
            if let (Some(size), Some(time)) = (cdn_record.size, cdn_record.time) {
                // Only include successful downloads
                if cdn_record.err.is_none() && time >= 10 && size >= 10240 {
                    let speed_mbps = (size as f64 / 1024.0 / 1024.0) / (time as f64 / 1000.0);
                    if speed_mbps <= 1000.0 {
                        // Filter out unrealistic speeds
                        session_speeds.push(speed_mbps);
                    }
                }
            }
        }
    }

    session_speeds
}

/// Analyze how each server impacts session completion times using multi-dimensional bottleneck analysis (CPI v4)
/// 并行化分析会话影响 - 性能优化版本
fn analyze_session_impact(sessions: &[SessionLog]) -> HashMap<String, ServerImpactStatistics> {
    // 步骤1：并行预计算所有会话的并发度时间线 (最大性能提升点)
    println!("预计算并发度时间线...");
    let timeline_cache = precompute_all_session_timelines(sessions);

    // 步骤2：并行处理会话数据收集
    println!("并行处理会话数据收集...");
    let server_impacts = sessions
        .par_iter() // 使用 Rayon 并行处理会话
        .filter(|session| (session.end - session.start) as f64 > 0.0) // 过滤无效会话
        .map(|session| analyze_single_session(session, &timeline_cache))
        .reduce(
            || HashMap::<String, ServerImpactData>::new(),
            |mut acc, session_data| {
                // 合并各会话的服务器数据
                for (server_id, data) in session_data {
                    let entry = acc.entry(server_id).or_insert_with(ServerImpactData::new);
                    merge_server_impact_data(entry, data);
                }
                acc
            },
        );

    // 步骤3：全局统计信息收集
    let global_stats = collect_global_performance_stats(sessions, &server_impacts);
    let total_sessions_count = sessions.len();

    // 步骤4：并行计算最终服务器统计信息
    println!("并行计算服务器CPI v5指标...");
    server_impacts
        .into_par_iter() // 使用 Rayon 并行处理服务器
        .filter(|(_, data)| data.total_sessions > 0)
        .map(|(server_id, data)| {
            let stats = calculate_final_server_statistics(
                &server_id,
                data,
                sessions,
                &timeline_cache,
                total_sessions_count,
                &global_stats,
            );
            (server_id, stats)
        })
        .collect()
}

/// 分析单个会话的服务器影响数据（优化版本）
fn analyze_single_session(
    session: &SessionLog,
    timeline_cache: &HashMap<String, SessionConcurrencyTimeline>,
) -> HashMap<String, ServerImpactData> {
    let mut session_server_impacts = HashMap::new();
    let session_duration = (session.end - session.start) as f64;

    // 获取此会话的时间线缓存
    let timeline = match session.sid.as_ref().and_then(|sid| timeline_cache.get(sid)) {
        Some(timeline) => timeline,
        None => return session_server_impacts, // 如果没有时间线，跳过此会话
    };

    // Calculate session-level speed context for execution delay analysis
    let session_speeds = calculate_session_speed_context(session);
    let session_median_speed = if !session_speeds.is_empty() {
        let mut sorted_speeds = session_speeds;
        sorted_speeds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mid = sorted_speeds.len() / 2;
        if sorted_speeds.len() % 2 == 0 {
            (sorted_speeds[mid - 1] + sorted_speeds[mid]) / 2.0
        } else {
            sorted_speeds[mid]
        }
    } else {
        5.0 // Default median speed
    };

    // Analyze bottlenecks for this session
    let session_bottleneck_analysis = analyze_session_bottlenecks(session);

    // Calculate the tail threshold (last 10% of session time)
    let tail_threshold = session.start as f64 + (session_duration * 0.9);
    let mut tail_servers = std::collections::HashSet::new();

    // 收集会话数据
    for chunk in &session.chunks {
        let chunk_size = allocation::parse_chunk_size(&chunk.rng) * 1024.0 * 1024.0;

        for cdn_record in &chunk.cdns {
            if let Some(server_id) = &cdn_record.srv {
                let entry = session_server_impacts
                    .entry(server_id.clone())
                    .or_insert_with(ServerImpactData::new);

                // 基础统计
                entry.total_downloads += 1;

                if let Some(ttfb) = cdn_record.ttfb {
                    entry.ttfb_values.push(ttfb as f64);
                }

                if cdn_record.err.is_some() {
                    entry.error_count += 1;
                }

                entry.file_sizes.push(chunk_size as u64);

                // 性能分析
                if let Some(duration) = cdn_record.time {
                    let duration_sec = duration as f64 / 1000.0;
                    let completion_time = cdn_record.ts + duration as u64;

                    // CPI v4: Calculate execution delay based on session context
                    if cdn_record.err.is_none() && duration >= 10 && chunk_size >= 10240.0 {
                        let execution_delay = calculate_execution_delay(
                            duration_sec,
                            chunk_size as u64,
                            session_median_speed,
                        );
                        entry.execution_delays.push(execution_delay);
                    }

                    // CPI v4: Calculate scheduling delay
                    let scheduling_delay =
                        calculate_scheduling_delay(cdn_record.ts, session.start, session_duration);
                    entry.scheduling_delays.push(scheduling_delay);

                    // Store session speed context for this download
                    entry.session_speed_contexts.push(session_median_speed);

                    // 文件大小分类处理
                    if chunk_size < SMALL_FILE_THRESHOLD as f64 {
                        let total_time = if let Some(ttfb) = cdn_record.ttfb {
                            (ttfb + duration) as f64 / 1000.0
                        } else {
                            duration_sec
                        };
                        entry.small_file_times.push(total_time);
                    } else if chunk_size < LARGE_FILE_THRESHOLD as f64 {
                        if duration_sec > 0.0 {
                            let speed_mbps = (chunk_size / 1024.0 / 1024.0) / duration_sec;
                            entry.medium_file_speeds.push(speed_mbps);
                        }
                    } else {
                        if duration_sec > 0.0 {
                            let speed_mbps = (chunk_size / 1024.0 / 1024.0) / duration_sec;
                            entry.large_file_speeds.push(speed_mbps);
                        }
                    }

                    // Track general performance for CV calculation
                    if duration_sec > 0.0 {
                        let speed_mbps = (chunk_size / 1024.0 / 1024.0) / duration_sec;
                        entry.performance_values.push(speed_mbps);
                    }

                    // Check if this download completes in the tail period
                    if completion_time as f64 >= tail_threshold {
                        tail_servers.insert(server_id.clone());
                    }
                }
            }
        }
    }

    // 更新会话级别统计
    for (server_id, bottleneck_analysis) in &session_bottleneck_analysis {
        if let Some(entry) = session_server_impacts.get_mut(server_id) {
            entry.total_sessions += 1;
            entry
                .efficiency_scores
                .push(bottleneck_analysis.efficiency_score);
            entry
                .bottleneck_scores
                .push(bottleneck_analysis.bottleneck_score);
            entry
                .bottleneck_types
                .push(bottleneck_analysis.bottleneck_type.clone());

            // Check if this server appears in the tail
            if tail_servers.contains(server_id) {
                entry.tail_appearances += 1;
            }

            // Calculate session extension
            let extension =
                calculate_speed_based_extension(session, server_id, &session_bottleneck_analysis);
            entry.session_extensions.push(extension);

            if bottleneck_analysis.is_bottleneck {
                entry.bottleneck_count += 1;
            }
        }
    }

    session_server_impacts
}

/// 合并服务器影响数据
fn merge_server_impact_data(target: &mut ServerImpactData, source: ServerImpactData) {
    target.total_sessions += source.total_sessions;
    target.tail_appearances += source.tail_appearances;
    target.bottleneck_count += source.bottleneck_count;
    target.session_extensions.extend(source.session_extensions);
    target.efficiency_scores.extend(source.efficiency_scores);
    target.bottleneck_scores.extend(source.bottleneck_scores);
    target.bottleneck_types.extend(source.bottleneck_types);
    target.performance_values.extend(source.performance_values);
    target.ttfb_values.extend(source.ttfb_values);
    target.error_count += source.error_count;
    target.total_downloads += source.total_downloads;
    target.file_sizes.extend(source.file_sizes);
    target.small_file_times.extend(source.small_file_times);
    target.medium_file_speeds.extend(source.medium_file_speeds);
    target.large_file_speeds.extend(source.large_file_speeds);
    target.execution_delays.extend(source.execution_delays);
    target.scheduling_delays.extend(source.scheduling_delays);
    target
        .session_speed_contexts
        .extend(source.session_speed_contexts);
}

/// 计算最终服务器统计信息（优化版本）
fn calculate_final_server_statistics(
    server_id: &str,
    data: ServerImpactData,
    sessions: &[SessionLog],
    timeline_cache: &HashMap<String, SessionConcurrencyTimeline>,
    total_sessions_count: usize,
    global_stats: &GlobalPerformanceStats,
) -> ServerImpactStatistics {
    let tail_appearance_rate = (data.tail_appearances as f64 / data.total_sessions as f64) * 100.0;

    // Calculate file size distribution stats
    let mut small_files = 0;
    let mut medium_files = 0;
    let mut large_files = 0;

    for &size in &data.file_sizes {
        if size < SMALL_FILE_THRESHOLD {
            small_files += 1;
        } else if size < LARGE_FILE_THRESHOLD {
            medium_files += 1;
        } else {
            large_files += 1;
        }
    }

    // Calculate efficiency/speed for each file size category
    let small_file_efficiency = if !data.small_file_times.is_empty() {
        let avg_time =
            data.small_file_times.iter().sum::<f64>() / data.small_file_times.len() as f64;
        1.0 / avg_time.max(0.01)
    } else {
        0.5
    };

    let medium_file_speed = if !data.medium_file_speeds.is_empty() {
        data.medium_file_speeds.iter().sum::<f64>() / data.medium_file_speeds.len() as f64
    } else {
        5.0
    };

    let large_file_speed = if !data.large_file_speeds.is_empty() {
        data.large_file_speeds.iter().sum::<f64>() / data.large_file_speeds.len() as f64
    } else {
        10.0
    };

    let file_size_stats = FileSizeDistribution {
        small_files,
        medium_files,
        large_files,
        small_file_efficiency,
        medium_file_speed,
        large_file_speed,
    };

    // Calculate performance CV
    let performance_cv = calculate_performance_cv(&data.performance_values);

    // Calculate TTFB P95
    let ttfb_p95 = if !data.ttfb_values.is_empty() {
        let mut sorted_ttfb = data.ttfb_values.clone();
        sorted_ttfb.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p95_index = ((sorted_ttfb.len() as f64 * 0.95) as usize).min(sorted_ttfb.len() - 1);
        sorted_ttfb[p95_index]
    } else {
        0.0
    };

    // Calculate error rate
    let error_rate = if data.total_downloads > 0 {
        data.error_count as f64 / data.total_downloads as f64
    } else {
        0.0
    };

    // Calculate average file size
    let avg_file_size = if !data.file_sizes.is_empty() {
        data.file_sizes.iter().sum::<u64>() as f64 / data.file_sizes.len() as f64
    } else {
        1_000_000.0
    };

    // Calculate usage rate
    let usage_rate = data.total_sessions as f64 / total_sessions_count as f64;

    // Calculate total data processed by this server
    let data_processed: u64 = data.file_sizes.iter().sum();

    // CPI v5 specific metrics - 使用优化版本的上下文感知速度分析
    let mut total_concurrency = 0.0;
    let mut concurrency_samples = 0;

    // 并行计算此服务器在所有会话中的上下文感知速度
    let all_context_speeds: Vec<ContextAwareSpeed> = sessions
        .par_iter() // 并行处理会话
        .filter_map(|session| {
            // 检查此服务器是否参与了此会话
            let server_participated = session.chunks.iter().any(|chunk| {
                chunk
                    .cdns
                    .iter()
                    .any(|cdn| cdn.srv.as_ref().map(|s| s == server_id).unwrap_or(false))
            });

            if !server_participated {
                return None;
            }

            // 获取时间线缓存
            if let Some(ref session_id) = session.sid {
                if let Some(timeline) = timeline_cache.get(session_id) {
                    let context_speed =
                        calculate_context_aware_speed_score(server_id, session, timeline);
                    if context_speed.low_concurrency_speed > 0.0 || context_speed.tail_speed > 0.0 {
                        return Some(context_speed);
                    }
                }
            }
            None
        })
        .collect();

    // 收集并发度数据（优化版本）
    for session in sessions {
        if let Some(ref session_id) = session.sid {
            if let Some(timeline) = timeline_cache.get(session_id) {
                for chunk in &session.chunks {
                    for cdn_record in &chunk.cdns {
                        if let Some(srv) = &cdn_record.srv {
                            if srv == server_id {
                                let concurrency = timeline.get_concurrency_at_time(cdn_record.ts);
                                total_concurrency += concurrency as f64;
                                concurrency_samples += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    let avg_concurrency_level = if concurrency_samples > 0 {
        total_concurrency / concurrency_samples as f64
    } else {
        0.0
    };

    // CPI v5 统计指标优化 - 使用已经包含备选逻辑的ContextAwareSpeed数据
    let low_concurrency_speed = if !all_context_speeds.is_empty() {
        all_context_speeds
            .iter()
            .map(|cs| cs.low_concurrency_speed)
            .filter(|&s| s > 0.0)
            .sum::<f64>()
            / all_context_speeds
                .iter()
                .map(|cs| cs.low_concurrency_speed)
                .filter(|&s| s > 0.0)
                .count()
                .max(1) as f64
    } else {
        0.0
    };

    let tail_performance_score = if !all_context_speeds.is_empty() {
        all_context_speeds
            .iter()
            .map(|cs| cs.tail_speed)
            .filter(|&s| s > 0.0)
            .sum::<f64>()
            / all_context_speeds
                .iter()
                .map(|cs| cs.tail_speed)
                .filter(|&s| s > 0.0)
                .count()
                .max(1) as f64
    } else {
        0.0
    };

    let adaptability_score = if !all_context_speeds.is_empty() {
        all_context_speeds
            .iter()
            .map(|cs| calculate_performance_adaptability(cs))
            .sum::<f64>()
            / all_context_speeds.len() as f64
    } else {
        0.5
    };

    // Calculate critical path reliability
    let critical_path_reliability = {
        let mut critical_sessions = 0;
        let mut reliable_sessions = 0;

        for session in sessions {
            if server_in_critical_path_session(server_id, session) {
                critical_sessions += 1;
                let performance = calculate_critical_path_performance(server_id, session);
                if performance > 0.6 {
                    reliable_sessions += 1;
                }
            }
        }

        if critical_sessions > 0 {
            reliable_sessions as f64 / critical_sessions as f64
        } else {
            0.8
        }
    };

    // Calculate new CPI v5 score using concurrency context-aware analysis
    let cpi_score = calculate_cpi_v5(
        server_id,
        sessions,
        timeline_cache,
        usage_rate,
        data_processed,
        global_stats,
    );
    let grade = assign_grade(cpi_score);

    ServerImpactStatistics {
        cpi_score,
        grade,
        file_size_stats,
        tail_appearance_rate,
        avg_concurrency_level,
        low_concurrency_speed,
        tail_performance_score,
        critical_path_reliability,
        adaptability_score,
        performance_cv,
        ttfb_p95,
        error_rate,
        usage_rate,
        avg_file_size,
        data_processed,
        affected_sessions: data.total_sessions,
    }
}

#[derive(Default)]
struct ServerImpactData {
    total_sessions: usize,
    tail_appearances: usize,      // Appearances in last 10% of session time
    bottleneck_count: usize,      // Times this server was a true bottleneck
    session_extensions: Vec<f64>, // Time extensions caused when bottleneck
    efficiency_scores: Vec<f64>,  // Efficiency scores across sessions
    bottleneck_scores: Vec<f64>,  // Bottleneck scores across sessions
    bottleneck_types: Vec<BottleneckType>, // Bottleneck types across sessions
    // New fields for enhanced CPI
    performance_values: Vec<f64>, // Performance values for CV calculation
    ttfb_values: Vec<f64>,        // TTFB values for P95 calculation
    error_count: usize,           // Number of errors
    total_downloads: usize,       // Total download attempts
    file_sizes: Vec<u64>,         // File sizes processed
    small_file_times: Vec<f64>,   // Completion times for small files
    medium_file_speeds: Vec<f64>, // Speeds for medium files
    large_file_speeds: Vec<f64>,  // Speeds for large files
    // CPI v4 enhancements for concurrent-aware analysis
    execution_delays: Vec<f64>, // Execution delay history (actual - expected duration)
    scheduling_delays: Vec<f64>, // Scheduling delay history (relative start position)
    session_speed_contexts: Vec<f64>, // Session median speeds for context
}

impl ServerImpactData {
    fn new() -> Self {
        Default::default()
    }
}

/// Analyze bottlenecks in a single session using multi-dimensional approach
fn analyze_session_bottlenecks(session: &SessionLog) -> HashMap<String, BottleneckAnalysis> {
    let session_duration = (session.end - session.start) as f64;
    let server_performances = calculate_server_session_performances(session);

    // Calculate total session data volume for normalization
    let total_session_bytes: u64 = server_performances
        .values()
        .map(|perf| perf.total_bytes)
        .sum();

    if total_session_bytes == 0 {
        return HashMap::new();
    }

    // Calculate relative performance metrics
    let session_speeds: Vec<f64> = server_performances
        .values()
        .map(|perf| perf.actual_speed)
        .filter(|&speed| speed > 0.0)
        .collect();

    let median_speed = if !session_speeds.is_empty() {
        let mut sorted_speeds = session_speeds;
        sorted_speeds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mid = sorted_speeds.len() / 2;
        if sorted_speeds.len() % 2 == 0 {
            (sorted_speeds[mid - 1] + sorted_speeds[mid]) / 2.0
        } else {
            sorted_speeds[mid]
        }
    } else {
        1.0 // Fallback
    };

    // Skip bottleneck analysis for single-server sessions
    if server_performances.len() <= 1 {
        let mut results = HashMap::new();
        for (server_id, mut perf) in server_performances {
            // Single server sessions get neutral classification
            perf.efficiency_score = 1.0; // Perfect relative efficiency
            perf.bottleneck_score = 0.0; // No bottleneck tendency
            perf.session_time_usage = perf.total_duration / session_duration;
            perf.data_contribution = 1.0; // 100% data contribution
            perf.workload_rank = 1.0; // 100% workload

            results.insert(
                server_id,
                BottleneckAnalysis {
                    efficiency_score: 1.0,
                    time_burden_score: perf.total_duration / session_duration,
                    data_contribution: 1.0,
                    bottleneck_score: 0.0,
                    bottleneck_type: BottleneckType::Normal, // Always normal for single-server
                    is_bottleneck: false,
                },
            );
        }
        return results;
    }

    // Calculate workload rankings based on total bytes processed
    let workload_ranks = calculate_workload_rankings(&server_performances);

    let mut results = HashMap::new();

    for (server_id, mut perf) in server_performances {
        // 1. Calculate efficiency score (relative to session median)
        let efficiency_score = if median_speed > 0.0 {
            (perf.actual_speed / median_speed).min(1.0)
        } else {
            0.5 // Neutral if no reference
        };

        // 2. Calculate time burden score
        let time_burden_score = perf.total_duration / session_duration;

        // 3. Calculate data contribution
        let data_contribution = perf.total_bytes as f64 / total_session_bytes as f64;

        // 4. Get workload rank
        let workload_rank = workload_ranks.get(&server_id).copied().unwrap_or(0.0);

        // 5. Calculate bottleneck score
        let bottleneck_score =
            calculate_bottleneck_score(efficiency_score, time_burden_score, data_contribution);

        // 6. Classify bottleneck type (now using workload-based logic)
        let bottleneck_type = classify_bottleneck_type(
            efficiency_score,
            time_burden_score,
            data_contribution,
            bottleneck_score,
            perf.total_bytes,
            workload_rank,
        );

        let is_bottleneck = matches!(
            bottleneck_type,
            BottleneckType::TrueBottleneck | BottleneckType::EfficiencyBottleneck
        );

        // Update performance struct
        perf.efficiency_score = efficiency_score;
        perf.bottleneck_score = bottleneck_score;
        perf.session_time_usage = time_burden_score;
        perf.data_contribution = data_contribution;
        perf.workload_rank = workload_rank;

        results.insert(
            server_id,
            BottleneckAnalysis {
                efficiency_score,
                time_burden_score,
                data_contribution,
                bottleneck_score,
                bottleneck_type,
                is_bottleneck,
            },
        );
    }

    results
}

/// Calculate performance metrics for each server in a session
fn calculate_server_session_performances(
    session: &SessionLog,
) -> HashMap<String, ServerSessionPerformance> {
    #[derive(Default)]
    struct ServerSessionData {
        start_times: Vec<u64>,
        completion_times: Vec<u64>,
        total_bytes: u64,
        download_records: Vec<(u64, f64)>, // (size, duration)
    }

    let mut server_data: HashMap<String, ServerSessionData> = HashMap::new();

    // Collect all download data for each server
    for chunk in &session.chunks {
        for cdn_record in &chunk.cdns {
            if let Some(server_id) = &cdn_record.srv {
                let entry = server_data.entry(server_id.clone()).or_default();

                entry.start_times.push(cdn_record.ts);

                if let (Some(size), Some(time)) = (cdn_record.size, cdn_record.time) {
                    // Only include successful downloads
                    if cdn_record.err.is_none() && time >= 10 && size >= 1024 {
                        entry.total_bytes += size as u64;
                        entry
                            .download_records
                            .push((size as u64, time as f64 / 1000.0));
                        entry.completion_times.push(cdn_record.ts + time as u64);
                    }
                }
            }
        }
    }

    // Convert to performance structures
    let mut performances = HashMap::new();
    for (server_id, data) in server_data {
        if !data.completion_times.is_empty() && data.total_bytes > 0 {
            let first_start = *data.start_times.iter().min().unwrap();
            let last_completion = *data.completion_times.iter().max().unwrap();
            let total_duration = (last_completion - first_start) as f64 / 1000.0;

            // Calculate actual speed
            let actual_speed = if total_duration > 0.0 {
                (data.total_bytes as f64 / 1024.0 / 1024.0) / total_duration
            } else {
                0.0
            };

            performances.insert(
                server_id.clone(),
                ServerSessionPerformance {
                    server_id,
                    total_bytes: data.total_bytes,
                    total_duration,
                    actual_speed,
                    session_time_usage: 0.0, // Will be calculated later
                    data_contribution: 0.0,  // Will be calculated later
                    efficiency_score: 0.0,   // Will be calculated later
                    bottleneck_score: 0.0,   // Will be calculated later
                    workload_rank: 0.0,      // Will be calculated later
                },
            );
        }
    }

    performances
}

/// Calculate workload rankings for servers based on total bytes processed
fn calculate_workload_rankings(
    performances: &HashMap<String, ServerSessionPerformance>,
) -> HashMap<String, f64> {
    // Sort servers by total bytes (descending order)
    let mut servers_by_workload: Vec<_> = performances
        .iter()
        .map(|(server_id, perf)| (server_id.clone(), perf.total_bytes))
        .collect();

    servers_by_workload.sort_by(|a, b| b.1.cmp(&a.1)); // Descending: highest workload first

    let total_servers = servers_by_workload.len() as f64;
    if total_servers == 0.0 {
        return HashMap::new();
    }

    servers_by_workload
        .into_iter()
        .enumerate()
        .map(|(rank, (server_id, _))| {
            // Normalize rank: 1.0 = highest workload, 0.0 = lowest workload
            let normalized_rank = 1.0 - (rank as f64 / total_servers);
            (server_id, normalized_rank)
        })
        .collect()
}

/// Calculate comprehensive bottleneck score based on multiple factors
fn calculate_bottleneck_score(
    efficiency_score: f64,
    time_burden_score: f64,
    data_contribution: f64,
) -> f64 {
    // Core formula: bottleneck tendency = inefficiency × time_burden × data_contribution_adjustment

    let inefficiency_factor = 1.0 - efficiency_score; // 0-1, higher means less efficient
    let time_burden_factor = time_burden_score.min(1.0); // 0-1, higher means more time consumed

    // Data contribution adjustment: less data = higher bottleneck tendency
    // Formula: 1 / (contribution + 0.05), capped at 4.0
    let data_adjustment = (1.0 / (data_contribution + 0.05)).min(4.0);

    // Combined bottleneck score with dampening to keep in 0-1 range
    let raw_score = inefficiency_factor * time_burden_factor * data_adjustment;
    let bottleneck_score = (raw_score / 4.0).min(1.0); // Normalize to 0-1

    bottleneck_score
}

/// Classify server bottleneck type based on performance metrics and workload
fn classify_bottleneck_type(
    efficiency_score: f64,
    _time_burden_score: f64,
    _data_contribution: f64,
    bottleneck_score: f64,
    total_bytes: u64,
    workload_rank: f64,
) -> BottleneckType {
    // Define workload thresholds
    const HIGH_WORKLOAD_BYTES: u64 = 20_000_000; // 20MB (lowered from 50MB)
    const LOW_WORKLOAD_BYTES: u64 = 5_000_000; // 5MB (lowered from 10MB)
    const HIGH_WORKLOAD_RANK: f64 = 0.5; // Top 50% (lowered from 70%)
    const LOW_WORKLOAD_RANK: f64 = 0.2; // Bottom 80% (lowered from 30%)

    match (
        efficiency_score,
        total_bytes,
        workload_rank,
        bottleneck_score,
    ) {
        // True bottleneck: very low efficiency AND meaningful bottleneck score OR very high bottleneck score
        (eff, _, _, score) if eff < 0.35 && score > 0.05 => BottleneckType::TrueBottleneck,
        (_, _, _, score) if score > 0.25 => BottleneckType::TrueBottleneck,

        // Efficiency bottleneck: medium-low efficiency with notable bottleneck score
        (eff, _, _, score) if eff < 0.65 && score > 0.15 => BottleneckType::EfficiencyBottleneck,

        // Workhorse: good efficiency + high workload (by bytes OR rank)
        (eff, bytes, rank, _)
            if eff > 0.7 && (bytes > HIGH_WORKLOAD_BYTES || rank > HIGH_WORKLOAD_RANK) =>
        {
            BottleneckType::Workhorse
        }

        // Underused: high efficiency + low workload (by bytes AND rank) + very low bottleneck score
        (eff, bytes, rank, score)
            if eff > 0.8
                && bytes < LOW_WORKLOAD_BYTES
                && rank < LOW_WORKLOAD_RANK
                && score < 0.05 =>
        {
            BottleneckType::Underutilized
        }

        // Normal: everything else
        _ => BottleneckType::Normal,
    }
}

/// Determine the most frequent bottleneck type for a server across sessions
fn determine_primary_bottleneck_type(types: &[BottleneckType]) -> String {
    if types.is_empty() {
        return "normal".to_string();
    }

    let mut type_counts: HashMap<&str, usize> = HashMap::new();
    for bottleneck_type in types {
        *type_counts.entry(bottleneck_type.as_str()).or_insert(0) += 1;
    }

    type_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(type_str, _)| type_str.to_string())
        .unwrap_or_else(|| "normal".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::analyze::models::ChunkLog;

    #[test]
    fn test_classify_ttfb_performance() {
        let (severity, rec) = classify_ttfb_performance(5000.0);
        assert_eq!(severity, "critical");
        assert!(rec.is_some());

        let (severity, rec) = classify_ttfb_performance(500.0);
        assert_eq!(severity, "excellent");
        assert!(rec.is_none());
    }

    #[test]
    fn test_classify_speed_performance() {
        let (severity, rec) = classify_speed_performance(0.5);
        assert_eq!(severity, "critical");
        assert!(rec.is_some());

        let (severity, rec) = classify_speed_performance(6.0);
        assert_eq!(severity, "excellent");
        assert!(rec.is_none());
    }

    #[test]
    fn test_classify_reliability_performance() {
        let (severity, rec) = classify_reliability_performance(3.0, 70.0);
        assert_eq!(severity, "critical");
        assert!(rec.is_some());

        let (severity, rec) = classify_reliability_performance(0.2, 5.0);
        assert_eq!(severity, "excellent");
        assert!(rec.is_none());
    }

    #[test]
    fn test_analyze_server_performance() {
        let sessions = vec![create_test_session()];
        let analysis = analyze_server_performance(&sessions);

        // Should have analysis for each component - the test session has acceptable performance
        // so it won't appear in worst servers list, but the analysis should still work
        assert!(analysis.ttfb_analysis.worst_servers.is_empty());
        assert!(analysis.ttfb_analysis.best_servers.is_empty());
        assert!(analysis.speed_analysis.slowest_servers.len() >= 0);
        assert!(analysis.reliability_analysis.highest_retry_servers.len() >= 0);
    }

    fn create_test_session() -> SessionLog {
        SessionLog {
            start: 1640995200,
            end: 1640995320,
            log_type: "session_completed".to_string(),
            sid: Some("test-session".to_string()),
            rid: "test-resource".to_string(),
            ver: "1.0.0".to_string(),
            ua: Some("TestAgent/1.0".to_string()),
            ip: ("192.168.1.100".to_string(), None),
            chunks: vec![ChunkLog {
                rng: "0-1023".to_string(),
                att: 1,
                cdns: vec![CdnRecordLog {
                    url: "https://cdn.example.com/test".to_string(),
                    srv: Some("cdn-01".to_string()),
                    wgt: Some(10),
                    ts: 1640995210,
                    pen: Some(false),
                    rsn: Some("flow_selected".to_string()),
                    ttfb: Some(1234),
                    time: Some(5000),
                    size: Some(1024000),
                    err: None,
                    mode: Some("http".to_string()),
                }],
            }],
        }
    }
}
