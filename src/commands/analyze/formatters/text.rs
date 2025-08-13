use crate::commands::analyze::models::{
    AnalysisResult, ServerReliabilityStats, ServerSpeedStats, ServerTtfbStats,
};
use crate::commands::analyze::stats::duration::format_duration;

/// Format analysis result as human-readable text
pub fn format_text(analysis_result: &AnalysisResult) -> String {
    let mut output = String::new();

    // Header
    output.push_str("=== DFS2 Session Log Analysis Report ===\n");
    output.push_str(&format!(
        "Analysis Period: {} - {}\n",
        analysis_result
            .analysis_info
            .analysis_period
            .start
            .format("%Y-%m-%d %H:%M:%S"),
        analysis_result
            .analysis_info
            .analysis_period
            .end
            .format("%Y-%m-%d %H:%M:%S")
    ));
    output.push_str(&format!(
        "Log File: {}\n",
        analysis_result.analysis_info.log_file
    ));
    output.push_str(&format!(
        "Total Records: {}\n\n",
        analysis_result.analysis_info.total_records
    ));

    // Session Duration Analysis
    format_session_duration(&mut output, analysis_result);

    // Server Performance Analysis
    format_server_performance(&mut output, analysis_result);

    // Retry Analysis
    format_retry_analysis(&mut output, analysis_result);

    // Issues Summary
    format_issues_summary(&mut output, analysis_result);

    // Data Quality Report
    format_data_quality(&mut output, analysis_result);

    output
}

fn format_session_duration(output: &mut String, analysis: &AnalysisResult) {
    let duration = &analysis.session_duration;

    output.push_str("📊 SESSION DURATION ANALYSIS (User Experience)\n");
    output.push_str(&format!(
        "├─ Average Duration: {}\n",
        format_duration(duration.statistics.average_seconds)
    ));
    output.push_str(&format!(
        "├─ Median Duration: {}\n",
        format_duration(duration.statistics.median_seconds)
    ));
    output.push_str(&format!(
        "├─ P95 Duration: {} (95% users complete within this time)\n",
        format_duration(duration.statistics.p95_seconds)
    ));
    output.push_str(&format!(
        "├─ P99 Duration: {}\n",
        format_duration(duration.statistics.p99_seconds)
    ));
    output.push_str(&format!(
        "└─ Longest Session: {}\n\n",
        format_duration(duration.statistics.max_seconds)
    ));

    output.push_str("📈 Duration Distribution:\n");
    output.push_str(&format!(
        "├─ 🟢 Fast (<2min): {} sessions ({:.1}%) - Excellent Experience\n",
        duration.distribution.fast_lt_2min.count, duration.distribution.fast_lt_2min.percentage
    ));
    output.push_str(&format!(
        "├─ 🟢 Normal (2-5min): {} sessions ({:.1}%) - Good Experience\n",
        duration.distribution.normal_2_5min.count, duration.distribution.normal_2_5min.percentage
    ));
    output.push_str(&format!(
        "├─ 🟡 Slow (5-10min): {} sessions ({:.1}%) - Needs Attention\n",
        duration.distribution.slow_5_10min.count, duration.distribution.slow_5_10min.percentage
    ));
    output.push_str(&format!(
        "├─ 🔴 Very Slow (10-20min): {} sessions ({:.1}%) - Poor Experience\n",
        duration.distribution.very_slow_10_20min.count,
        duration.distribution.very_slow_10_20min.percentage
    ));
    output.push_str(&format!(
        "└─ 🔴 Extremely Slow (>20min): {} sessions ({:.1}%) - Critical Issue\n\n",
        duration.distribution.extremely_slow_gt_20min.count,
        duration.distribution.extremely_slow_gt_20min.percentage
    ));
}

fn format_server_performance(output: &mut String, analysis: &AnalysisResult) {
    let server_perf = &analysis.server_performance;

    output.push_str("🖥️ SERVER PERFORMANCE ANALYSIS\n\n");

    // TTFB Analysis
    if !server_perf.ttfb_analysis.worst_servers.is_empty() {
        output.push_str("🔴 WORST TTFB SERVERS:\n");
        for (i, server) in server_perf
            .ttfb_analysis
            .worst_servers
            .iter()
            .take(5)
            .enumerate()
        {
            format_ttfb_server(
                output,
                server,
                i == server_perf.ttfb_analysis.worst_servers.len() - 1,
            );
        }
        output.push('\n');
    }

    // Speed Analysis
    if !server_perf.speed_analysis.slowest_servers.is_empty() {
        output.push_str("🔴 SLOWEST DOWNLOAD SERVERS:\n");
        for (i, server) in server_perf
            .speed_analysis
            .slowest_servers
            .iter()
            .take(5)
            .enumerate()
        {
            format_speed_server(
                output,
                server,
                i == server_perf.speed_analysis.slowest_servers.len() - 1,
            );
        }
        output.push('\n');
    }

    // Reliability Analysis
    if !server_perf
        .reliability_analysis
        .highest_retry_servers
        .is_empty()
    {
        output.push_str("🔴 HIGHEST RETRY/PENALTY SERVERS:\n");
        for (i, server) in server_perf
            .reliability_analysis
            .highest_retry_servers
            .iter()
            .take(5)
            .enumerate()
        {
            format_reliability_server(
                output,
                server,
                i == server_perf.reliability_analysis.highest_retry_servers.len() - 1,
            );
        }
        output.push('\n');
    }

    // Best Performing Servers
    if !server_perf.ttfb_analysis.best_servers.is_empty()
        || !server_perf.speed_analysis.fastest_servers.is_empty()
        || !server_perf
            .reliability_analysis
            .most_reliable_servers
            .is_empty()
    {
        output.push_str("🟢 BEST PERFORMING SERVERS:\n");

        // Show TTFB champions
        for server in server_perf.ttfb_analysis.best_servers.iter().take(2) {
            output.push_str(&format!(
                "├─ ⭐ {}: {:.0}ms TTFB ({:.1}% coverage)\n",
                server.server_id, server.avg_ttfb_ms, server.data_coverage.coverage_percentage
            ));
        }

        // Show speed champions
        for server in server_perf.speed_analysis.fastest_servers.iter().take(2) {
            output.push_str(&format!(
                "├─ ⭐ {}: {:.1}MB/s speed ({:.1}% coverage)\n",
                server.server_id, server.avg_speed_mbps, server.data_coverage.coverage_percentage
            ));
        }

        // Show reliability champions
        for (i, server) in server_perf
            .reliability_analysis
            .most_reliable_servers
            .iter()
            .take(2)
            .enumerate()
        {
            let prefix = if i == server_perf.reliability_analysis.most_reliable_servers.len() - 1
                || i == 1
            {
                "└─"
            } else {
                "├─"
            };
            output.push_str(&format!(
                "{} ⭐ {}: {:.1} avg retries, {:.1}% penalty\n",
                prefix, server.server_id, server.avg_retries, server.penalty_rate_percentage
            ));
        }
        output.push('\n');
    }
}

fn format_ttfb_server(output: &mut String, server: &ServerTtfbStats, is_last: bool) {
    let prefix = if is_last { "└─" } else { "├─" };
    let severity_icon = match server.severity.as_str() {
        "critical" => "🚨",
        "warning" => "⚠️",
        _ => "🔴",
    };

    output.push_str(&format!(
        "{} {} {}: {:.0}ms avg ({}/{} records, {:.1}% coverage)\n",
        prefix,
        severity_icon,
        server.server_id,
        server.avg_ttfb_ms,
        server.data_coverage.valid_records,
        server.data_coverage.total_requests,
        server.data_coverage.coverage_percentage
    ));

    if let Some(recommendation) = &server.recommendation {
        output.push_str(&format!(
            "│   └─ {} {}\n",
            if server.severity == "critical" {
                "🚨"
            } else {
                "⚠️"
            },
            recommendation
        ));
    }
}

fn format_speed_server(output: &mut String, server: &ServerSpeedStats, is_last: bool) {
    let prefix = if is_last { "└─" } else { "├─" };
    let severity_icon = match server.severity.as_str() {
        "critical" => "🚨",
        "warning" => "⚠️",
        _ => "🔴",
    };

    output.push_str(&format!(
        "{} {} {}: {:.1}MB/s avg ({}/{} records, {:.1}% coverage)\n",
        prefix,
        severity_icon,
        server.server_id,
        server.avg_speed_mbps,
        server.data_coverage.valid_records,
        server.data_coverage.total_requests,
        server.data_coverage.coverage_percentage
    ));

    if let Some(recommendation) = &server.recommendation {
        output.push_str(&format!(
            "│   └─ {} {}\n",
            if server.severity == "critical" {
                "🚨"
            } else {
                "⚠️"
            },
            recommendation
        ));
    }
}

fn format_reliability_server(output: &mut String, server: &ServerReliabilityStats, is_last: bool) {
    let prefix = if is_last { "└─" } else { "├─" };
    let severity_icon = match server.severity.as_str() {
        "critical" => "🚨",
        "warning" => "⚠️",
        _ => "🔴",
    };

    output.push_str(&format!(
        "{} {} {}: {:.1} avg retries, {:.1}% penalty rate ({} requests)\n",
        prefix,
        severity_icon,
        server.server_id,
        server.avg_retries,
        server.penalty_rate_percentage,
        server.total_requests
    ));

    if let Some(recommendation) = &server.recommendation {
        output.push_str(&format!(
            "│   └─ {} {}\n",
            if server.severity == "critical" {
                "🚨"
            } else {
                "⚠️"
            },
            recommendation
        ));
    }
}

fn format_retry_analysis(output: &mut String, analysis: &AnalysisResult) {
    let retry = &analysis.retry_analysis;

    output.push_str("🔄 RETRY ANALYSIS\n");
    output.push_str(&format!(
        "├─ Global Retry Rate: {:.1}% ({} of {} sessions)\n",
        retry.global_statistics.retry_rate_percentage,
        retry.global_statistics.sessions_with_retries,
        retry.global_statistics.total_sessions
    ));

    output.push_str("├─ Retry Distribution:\n");
    output.push_str(&format!(
        "│   ├─ 0 retries: {} ({:.1}%) - Success on first try\n",
        retry.retry_distribution.zero_retries.count,
        retry.retry_distribution.zero_retries.percentage
    ));
    output.push_str(&format!(
        "│   ├─ 1 retry: {} ({:.1}%) - Recovered successfully\n",
        retry.retry_distribution.one_retry.count, retry.retry_distribution.one_retry.percentage
    ));
    output.push_str(&format!(
        "│   ├─ 2 retries: {} ({:.1}%) - Multiple attempts needed\n",
        retry.retry_distribution.two_retries.count, retry.retry_distribution.two_retries.percentage
    ));
    output.push_str(&format!(
        "│   ├─ 3 retries: {} ({:.1}%) - Significant issues\n",
        retry.retry_distribution.three_retries.count,
        retry.retry_distribution.three_retries.percentage
    ));
    output.push_str(&format!(
        "│   └─ 4+ retries: {} ({:.1}%) - 🚨 Critical problems\n",
        retry.retry_distribution.four_plus_retries.count,
        retry.retry_distribution.four_plus_retries.percentage
    ));

    output.push_str(&format!(
        "└─ Average Retries per Session: {:.2}\n\n",
        retry.global_statistics.avg_retries
    ));

    output.push_str("⏱️ RETRY TIME IMPACT:\n");
    output.push_str(&format!(
        "├─ 0 retries: {} avg duration\n",
        format_duration(retry.time_impact.zero_retries_avg_seconds)
    ));

    if retry.time_impact.one_retry_avg_seconds > 0.0 {
        let increase = ((retry.time_impact.one_retry_avg_seconds
            - retry.time_impact.zero_retries_avg_seconds)
            / retry.time_impact.zero_retries_avg_seconds)
            * 100.0;
        output.push_str(&format!(
            "├─ 1 retry: {} avg duration (+{:.0}% increase)\n",
            format_duration(retry.time_impact.one_retry_avg_seconds),
            increase
        ));
    }

    if retry.time_impact.two_retries_avg_seconds > 0.0 {
        let increase = ((retry.time_impact.two_retries_avg_seconds
            - retry.time_impact.zero_retries_avg_seconds)
            / retry.time_impact.zero_retries_avg_seconds)
            * 100.0;
        output.push_str(&format!(
            "├─ 2 retries: {} avg duration (+{:.0}% increase)\n",
            format_duration(retry.time_impact.two_retries_avg_seconds),
            increase
        ));
    }

    if retry.time_impact.three_plus_retries_avg_seconds > 0.0 {
        let increase = ((retry.time_impact.three_plus_retries_avg_seconds
            - retry.time_impact.zero_retries_avg_seconds)
            / retry.time_impact.zero_retries_avg_seconds)
            * 100.0;
        output.push_str(&format!(
            "└─ 3+ retries: {} avg duration (+{:.0}% increase)\n",
            format_duration(retry.time_impact.three_plus_retries_avg_seconds),
            increase
        ));
    }

    output.push('\n');
}

fn format_issues_summary(output: &mut String, analysis: &AnalysisResult) {
    let issues = &analysis.issues_summary;

    output.push_str("🎯 KEY ISSUES SUMMARY\n");

    if !issues.critical_servers.is_empty() {
        output.push_str("├─ 🚨 Critical Servers (Immediate Action Required):\n");
        for (i, server) in issues.critical_servers.iter().take(5).enumerate() {
            let prefix = if i == issues.critical_servers.len().min(5) - 1 {
                "│   └─"
            } else {
                "│   ├─"
            };
            output.push_str(&format!(
                "{} {}: {} ({})\n",
                prefix,
                server.server_id,
                server.issue_type.replace('_', " "),
                server.value
            ));
        }
    }

    output.push_str("├─ ⚠️ Experience Issues:\n");
    output.push_str(&format!(
        "│   ├─ {:.1}% users take >5 minutes to install\n",
        issues.experience_issues.users_over_5min_percentage
    ));
    output.push_str(&format!(
        "│   ├─ {:.1}% users take >10 minutes to install\n",
        issues.experience_issues.users_over_10min_percentage
    ));
    output.push_str(&format!(
        "│   └─ {:.1}% requests require retry\n",
        issues.experience_issues.requests_requiring_retry_percentage
    ));

    if !issues.excellent_performers.is_empty() {
        output.push_str("└─ ✅ Excellent Performance:\n");
        for (i, performer) in issues.excellent_performers.iter().take(3).enumerate() {
            let prefix = if i == issues.excellent_performers.len().min(3) - 1 {
                "    └─"
            } else {
                "    ├─"
            };
            output.push_str(&format!(
                "{} {}: {}\n",
                prefix, performer.server_id, performer.description
            ));
        }
    } else {
        output.push_str("└─ ✅ No servers meeting excellence criteria\n");
    }

    output.push('\n');
}

fn format_data_quality(output: &mut String, analysis: &AnalysisResult) {
    let quality = &analysis.data_quality;

    output.push_str("📋 DATA QUALITY REPORT\n");
    output.push_str(&format!(
        "├─ Session Duration: {:.1}% coverage (timestamp based)\n",
        quality.session_duration_coverage
    ));
    output.push_str(&format!(
        "├─ Retry Statistics: {:.1}% coverage (attempt field based)\n",
        quality.retry_statistics_coverage
    ));
    output.push_str(&format!(
        "├─ Server Distribution: {:.1}% have server ID ({:.1}% unknown)\n",
        quality.server_id_coverage,
        100.0 - quality.server_id_coverage
    ));
    output.push_str(&format!(
        "├─ TTFB Data: {:.1}% coverage (client reported)\n",
        quality.ttfb_data_coverage
    ));
    output.push_str(&format!(
        "├─ Speed Data: {:.1}% coverage (requires size & time fields)\n",
        quality.speed_data_coverage
    ));
    output.push_str(&format!(
        "└─ 💡 Recommendation: {}\n",
        quality.recommendation
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::analyze::analyzer;
    use crate::commands::analyze::models::{CdnRecordLog, ChunkLog, SessionLog};

    #[test]
    fn test_format_text() {
        let sessions = vec![create_test_session()];
        let analysis_result = analyzer::analyze_sessions(sessions).unwrap();

        let text_output = format_text(&analysis_result);

        // Check that all major sections are present
        assert!(text_output.contains("SESSION DURATION ANALYSIS"));
        assert!(text_output.contains("SERVER PERFORMANCE ANALYSIS"));
        assert!(text_output.contains("RETRY ANALYSIS"));
        assert!(text_output.contains("KEY ISSUES SUMMARY"));
        assert!(text_output.contains("DATA QUALITY REPORT"));

        // Check emojis are present for readability
        assert!(text_output.contains("📊"));
        assert!(text_output.contains("🖥️"));
        assert!(text_output.contains("🔄"));
        assert!(text_output.contains("🎯"));
        assert!(text_output.contains("📋"));

        // Check that we have some data
        assert!(text_output.contains("Total Records: 1"));
    }

    #[test]
    fn test_format_duration_display() {
        // Duration formatting is tested in the duration module
        // This just verifies integration
        let duration_str = format_duration(125.0);
        assert_eq!(duration_str, "2m 5s");
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
