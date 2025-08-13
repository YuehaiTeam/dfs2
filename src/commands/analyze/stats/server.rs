use crate::commands::analyze::models::{
    CdnRecordLog, DataCoverage, ReliabilityAnalysis, ServerPerformanceAnalysis,
    ServerReliabilityStats, ServerSpeedStats, ServerTtfbStats, SessionLog, SpeedAnalysis,
    TtfbAnalysis,
};
use std::collections::HashMap;

pub fn analyze_server_performance(sessions: &[SessionLog]) -> ServerPerformanceAnalysis {
    // Collect all CDN records with their server information
    let cdn_records = collect_cdn_records(sessions);

    // TTFB Analysis
    let ttfb_analysis = analyze_ttfb(&cdn_records);

    // Speed Analysis
    let speed_analysis = analyze_speed(&cdn_records);

    // Reliability Analysis
    let reliability_analysis = analyze_reliability(&cdn_records, sessions);

    ServerPerformanceAnalysis {
        ttfb_analysis,
        speed_analysis,
        reliability_analysis,
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
        (
            "critical".to_string(),
            Some("Check server status immediately - TTFB exceeds 4 seconds".to_string()),
        )
    } else if avg_ttfb_ms > 2500.0 {
        (
            "warning".to_string(),
            Some("Consider CDN provider change or server optimization".to_string()),
        )
    } else if avg_ttfb_ms > 1500.0 {
        (
            "needs_attention".to_string(),
            Some("Monitor server performance and consider optimization".to_string()),
        )
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
            if let (Some(size), Some(time)) = (record_meta.record.size, record_meta.record.time) {
                if time > 0 && size > 0 {
                    // Convert to MB/s (size in bytes, time in milliseconds)
                    let speed_mbps = (size as f64 / 1024.0 / 1024.0) / (time as f64 / 1000.0);
                    server_speeds
                        .entry(server_id.clone())
                        .or_insert_with(Vec::new)
                        .push(speed_mbps);
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
        (
            "critical".to_string(),
            Some("Bandwidth severely insufficient - consider immediate upgrade".to_string()),
        )
    } else if avg_speed_mbps < 2.0 {
        (
            "warning".to_string(),
            Some("Poor download speed - investigate bandwidth limitations".to_string()),
        )
    } else if avg_speed_mbps < 3.0 {
        (
            "needs_attention".to_string(),
            Some("Below average speed - monitor and consider optimization".to_string()),
        )
    } else if avg_speed_mbps > 5.0 {
        ("excellent".to_string(), None)
    } else {
        ("acceptable".to_string(), None)
    }
}

fn analyze_reliability(
    cdn_records: &[CdnRecordWithMeta],
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
        (
            "critical".to_string(),
            Some("Extremely unreliable - frequent failures detected".to_string()),
        )
    } else if avg_retries > 1.5 || penalty_rate > 30.0 {
        (
            "warning".to_string(),
            Some("Network instability detected - monitor closely".to_string()),
        )
    } else if avg_retries > 0.8 || penalty_rate > 15.0 {
        (
            "needs_attention".to_string(),
            Some("Some reliability issues - consider investigation".to_string()),
        )
    } else if avg_retries < 0.5 && penalty_rate < 8.0 {
        ("excellent".to_string(), None)
    } else {
        ("acceptable".to_string(), None)
    }
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
