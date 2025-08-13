use crate::commands::analyze::models::{
    CriticalServer, DataQuality, ExcellentPerformer, ExperienceIssues, IssuesSummary,
    RetryAnalysis, ServerPerformanceAnalysis, SessionDurationAnalysis, SessionLog,
};
use std::collections::HashMap;

pub fn analyze_data_quality(sessions: &[SessionLog]) -> DataQuality {
    if sessions.is_empty() {
        return DataQuality {
            session_duration_coverage: 0.0,
            retry_statistics_coverage: 0.0,
            server_id_coverage: 0.0,
            ttfb_data_coverage: 0.0,
            speed_data_coverage: 0.0,
            recommendation: "No session data available for analysis".to_string(),
        };
    }

    let total_sessions = sessions.len();
    let mut session_duration_valid = 0;
    let mut retry_stats_valid = 0;
    let mut server_id_count = 0;
    let mut ttfb_count = 0;
    let mut speed_count = 0;
    let mut total_cdn_records = 0;

    for session in sessions {
        // Session duration is always available (start/end fields required)
        if session.start > 0 && session.end > session.start {
            session_duration_valid += 1;
        }

        // Retry statistics are always available (att field always present)
        retry_stats_valid += 1;

        for chunk in &session.chunks {
            for cdn_record in &chunk.cdns {
                total_cdn_records += 1;

                // Server ID coverage
                if cdn_record.srv.is_some() {
                    server_id_count += 1;
                }

                // TTFB data coverage (client reported)
                if cdn_record.ttfb.is_some() {
                    ttfb_count += 1;
                }

                // Speed data coverage (requires both size and time)
                if cdn_record.size.is_some() && cdn_record.time.is_some() {
                    if let (Some(size), Some(time)) = (cdn_record.size, cdn_record.time) {
                        if size > 0 && time > 0 {
                            speed_count += 1;
                        }
                    }
                }
            }
        }
    }

    let session_duration_coverage = if total_sessions > 0 {
        (session_duration_valid as f64 / total_sessions as f64) * 100.0
    } else {
        0.0
    };

    let retry_statistics_coverage = if total_sessions > 0 {
        (retry_stats_valid as f64 / total_sessions as f64) * 100.0
    } else {
        0.0
    };

    let server_id_coverage = if total_cdn_records > 0 {
        (server_id_count as f64 / total_cdn_records as f64) * 100.0
    } else {
        0.0
    };

    let ttfb_data_coverage = if total_cdn_records > 0 {
        (ttfb_count as f64 / total_cdn_records as f64) * 100.0
    } else {
        0.0
    };

    let speed_data_coverage = if total_cdn_records > 0 {
        (speed_count as f64 / total_cdn_records as f64) * 100.0
    } else {
        0.0
    };

    let recommendation = generate_quality_recommendation(
        server_id_coverage,
        ttfb_data_coverage,
        speed_data_coverage,
    );

    DataQuality {
        session_duration_coverage,
        retry_statistics_coverage,
        server_id_coverage,
        ttfb_data_coverage,
        speed_data_coverage,
        recommendation,
    }
}

fn generate_quality_recommendation(
    server_id_coverage: f64,
    ttfb_coverage: f64,
    speed_coverage: f64,
) -> String {
    let mut recommendations = Vec::new();

    if server_id_coverage < 80.0 {
        recommendations.push(format!(
            "Server ID coverage is only {:.1}% - improve server identification in logs",
            server_id_coverage
        ));
    }

    if ttfb_coverage < 30.0 {
        recommendations.push(format!(
            "TTFB data coverage is only {:.1}% - improve client telemetry reporting",
            ttfb_coverage
        ));
    }

    if speed_coverage < 25.0 {
        recommendations.push(format!(
            "Speed data coverage is only {:.1}% - ensure clients report both size and time",
            speed_coverage
        ));
    }

    if recommendations.is_empty() {
        "Data quality is acceptable for analysis".to_string()
    } else {
        format!("Recommendations: {}", recommendations.join("; "))
    }
}

pub fn generate_issues_summary(
    server_performance: &ServerPerformanceAnalysis,
    retry_analysis: &RetryAnalysis,
    duration_analysis: &SessionDurationAnalysis,
) -> IssuesSummary {
    let critical_servers = identify_critical_servers(server_performance);
    let experience_issues = analyze_experience_issues(duration_analysis, retry_analysis);
    let excellent_performers = identify_excellent_performers(server_performance);

    IssuesSummary {
        critical_servers,
        experience_issues,
        excellent_performers,
    }
}

fn identify_critical_servers(
    server_performance: &ServerPerformanceAnalysis,
) -> Vec<CriticalServer> {
    let mut critical_servers = Vec::new();

    // Critical TTFB servers
    for server in &server_performance.ttfb_analysis.worst_servers {
        if server.severity == "critical" {
            critical_servers.push(CriticalServer {
                server_id: server.server_id.clone(),
                issue_type: "ttfb".to_string(),
                value: format!("{:.0}ms", server.avg_ttfb_ms),
                severity: "critical".to_string(),
                recommendation: server
                    .recommendation
                    .clone()
                    .unwrap_or_else(|| "Check server status immediately".to_string()),
            });
        }
    }

    // Critical speed servers
    for server in &server_performance.speed_analysis.slowest_servers {
        if server.severity == "critical" {
            critical_servers.push(CriticalServer {
                server_id: server.server_id.clone(),
                issue_type: "speed".to_string(),
                value: format!("{:.1}MB/s", server.avg_speed_mbps),
                severity: "critical".to_string(),
                recommendation: server
                    .recommendation
                    .clone()
                    .unwrap_or_else(|| "Bandwidth severely insufficient".to_string()),
            });
        }
    }

    // Critical reliability servers
    for server in &server_performance
        .reliability_analysis
        .highest_retry_servers
    {
        if server.severity == "critical" {
            critical_servers.push(CriticalServer {
                server_id: server.server_id.clone(),
                issue_type: "retry_rate".to_string(),
                value: format!("{:.1}x retries", server.avg_retries),
                severity: "critical".to_string(),
                recommendation: server
                    .recommendation
                    .clone()
                    .unwrap_or_else(|| "Extremely unreliable server".to_string()),
            });
        }
    }

    // Sort by severity and server impact
    critical_servers.sort_by(|a, b| {
        // Critical > warning > other
        match (a.severity.as_str(), b.severity.as_str()) {
            ("critical", "critical") => a.server_id.cmp(&b.server_id),
            ("critical", _) => std::cmp::Ordering::Less,
            (_, "critical") => std::cmp::Ordering::Greater,
            _ => a.server_id.cmp(&b.server_id),
        }
    });

    critical_servers
}

fn analyze_experience_issues(
    duration_analysis: &SessionDurationAnalysis,
    retry_analysis: &RetryAnalysis,
) -> ExperienceIssues {
    let users_over_5min_percentage = duration_analysis.distribution.slow_5_10min.percentage
        + duration_analysis.distribution.very_slow_10_20min.percentage
        + duration_analysis
            .distribution
            .extremely_slow_gt_20min
            .percentage;

    let users_over_10min_percentage = duration_analysis.distribution.very_slow_10_20min.percentage
        + duration_analysis
            .distribution
            .extremely_slow_gt_20min
            .percentage;

    let users_over_20min_percentage = duration_analysis
        .distribution
        .extremely_slow_gt_20min
        .percentage;

    let requests_requiring_retry_percentage =
        retry_analysis.retry_distribution.one_retry.percentage
            + retry_analysis.retry_distribution.two_retries.percentage
            + retry_analysis.retry_distribution.three_retries.percentage
            + retry_analysis
                .retry_distribution
                .four_plus_retries
                .percentage;

    ExperienceIssues {
        users_over_5min_percentage,
        users_over_10min_percentage,
        users_over_20min_percentage,
        requests_requiring_retry_percentage,
    }
}

fn identify_excellent_performers(
    server_performance: &ServerPerformanceAnalysis,
) -> Vec<ExcellentPerformer> {
    let mut excellent_performers = Vec::new();
    let mut server_metrics: HashMap<String, HashMap<String, String>> = HashMap::new();

    // Collect excellent TTFB performers
    for server in &server_performance.ttfb_analysis.best_servers {
        if server.severity == "excellent" {
            server_metrics
                .entry(server.server_id.clone())
                .or_insert_with(HashMap::new)
                .insert("ttfb".to_string(), format!("{:.0}ms", server.avg_ttfb_ms));
        }
    }

    // Collect excellent speed performers
    for server in &server_performance.speed_analysis.fastest_servers {
        if server.severity == "excellent" {
            server_metrics
                .entry(server.server_id.clone())
                .or_insert_with(HashMap::new)
                .insert(
                    "speed".to_string(),
                    format!("{:.1}MB/s", server.avg_speed_mbps),
                );
        }
    }

    // Collect excellent reliability performers
    for server in &server_performance
        .reliability_analysis
        .most_reliable_servers
    {
        if server.severity == "excellent" {
            server_metrics
                .entry(server.server_id.clone())
                .or_insert_with(HashMap::new)
                .insert(
                    "reliability".to_string(),
                    format!("{:.1}% penalty rate", server.penalty_rate_percentage),
                );
        }
    }

    // Generate descriptions based on metrics
    for (server_id, metrics) in server_metrics {
        let description = if metrics.len() >= 3 {
            "Excellent overall performance across all metrics".to_string()
        } else if metrics.len() == 2 {
            "Strong performance in multiple areas".to_string()
        } else {
            format!("Best {} performance", metrics.keys().next().unwrap())
        };

        excellent_performers.push(ExcellentPerformer {
            server_id,
            description,
            metrics,
        });
    }

    // Sort by number of excellent metrics (most comprehensive first)
    excellent_performers.sort_by(|a, b| b.metrics.len().cmp(&a.metrics.len()));

    excellent_performers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::analyze::models::{
        CdnRecordLog, ChunkLog, CountAndPercentage, DurationDistribution, DurationStatistics,
    };

    #[test]
    fn test_data_quality_analysis() {
        let sessions = vec![
            create_test_session_with_data(true, true, true), // Full data
            create_test_session_with_data(true, false, false), // No client data
            create_test_session_with_data(false, false, false), // No server ID
        ];

        let quality = analyze_data_quality(&sessions);

        assert_eq!(quality.session_duration_coverage, 100.0); // Always available
        assert_eq!(quality.retry_statistics_coverage, 100.0); // Always available
        assert!((quality.server_id_coverage - 66.66666666666667).abs() < 0.0001); // 2 out of 3
        assert!((quality.ttfb_data_coverage - 33.33333333333333).abs() < 0.0001); // 1 out of 3
        assert!((quality.speed_data_coverage - 33.33333333333333).abs() < 0.0001); // 1 out of 3
    }

    #[test]
    fn test_experience_issues() {
        let duration_analysis = SessionDurationAnalysis {
            statistics: DurationStatistics {
                average_seconds: 180.0,
                median_seconds: 120.0,
                p95_seconds: 600.0,
                p99_seconds: 1200.0,
                max_seconds: 1800.0,
                min_seconds: 30.0,
            },
            distribution: DurationDistribution {
                fast_lt_2min: CountAndPercentage {
                    count: 20,
                    percentage: 20.0,
                },
                normal_2_5min: CountAndPercentage {
                    count: 60,
                    percentage: 60.0,
                },
                slow_5_10min: CountAndPercentage {
                    count: 15,
                    percentage: 15.0,
                },
                very_slow_10_20min: CountAndPercentage {
                    count: 4,
                    percentage: 4.0,
                },
                extremely_slow_gt_20min: CountAndPercentage {
                    count: 1,
                    percentage: 1.0,
                },
            },
            by_type: HashMap::new(),
            by_resource: HashMap::new(),
        };

        let retry_analysis = RetryAnalysis {
            global_statistics: crate::commands::analyze::models::GlobalRetryStats {
                total_sessions: 100,
                sessions_with_retries: 40,
                retry_rate_percentage: 40.0,
                avg_retries: 0.8,
            },
            retry_distribution: crate::commands::analyze::models::RetryDistribution {
                zero_retries: CountAndPercentage {
                    count: 60,
                    percentage: 60.0,
                },
                one_retry: CountAndPercentage {
                    count: 30,
                    percentage: 30.0,
                },
                two_retries: CountAndPercentage {
                    count: 8,
                    percentage: 8.0,
                },
                three_retries: CountAndPercentage {
                    count: 2,
                    percentage: 2.0,
                },
                four_plus_retries: CountAndPercentage {
                    count: 0,
                    percentage: 0.0,
                },
            },
            time_impact: crate::commands::analyze::models::TimeImpact {
                zero_retries_avg_seconds: 120.0,
                one_retry_avg_seconds: 180.0,
                two_retries_avg_seconds: 240.0,
                three_plus_retries_avg_seconds: 360.0,
            },
            by_server: HashMap::new(),
        };

        let issues = analyze_experience_issues(&duration_analysis, &retry_analysis);

        assert_eq!(issues.users_over_5min_percentage, 20.0); // 15 + 4 + 1
        assert_eq!(issues.users_over_10min_percentage, 5.0); // 4 + 1
        assert_eq!(issues.users_over_20min_percentage, 1.0); // 1
        assert_eq!(issues.requests_requiring_retry_percentage, 40.0); // 30 + 8 + 2
    }

    fn create_test_session_with_data(
        has_server_id: bool,
        has_ttfb: bool,
        has_speed: bool,
    ) -> SessionLog {
        SessionLog {
            start: 1000,
            end: 1060,
            log_type: "session_completed".to_string(),
            sid: Some("test-session".to_string()),
            rid: "test-resource".to_string(),
            ver: "1.0.0".to_string(),
            ua: Some("TestAgent/1.0".to_string()),
            ip: ("192.168.1.100".to_string(), None),
            chunks: vec![ChunkLog {
                rng: "0-1023".to_string(),
                att: 0,
                cdns: vec![CdnRecordLog {
                    url: "https://cdn.example.com/test".to_string(),
                    srv: if has_server_id {
                        Some("cdn-01".to_string())
                    } else {
                        None
                    },
                    wgt: Some(10),
                    ts: 1010,
                    pen: Some(false),
                    rsn: Some("flow_selected".to_string()),
                    ttfb: if has_ttfb { Some(1000) } else { None },
                    time: if has_speed { Some(5000) } else { None },
                    size: if has_speed { Some(1024000) } else { None },
                    err: None,
                    mode: Some("http".to_string()),
                }],
            }],
        }
    }
}
