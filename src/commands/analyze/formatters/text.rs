use crate::commands::analyze::models::{
    AnalysisResult, ChunkAllocationAnalysis, FileSizePerformance, FileSizeStats,
    ServerDetailedStats, ServerErrorStats, ServerReliabilityStats, ServerRetryStats,
    ServerSpeedStats, ServerTtfbStats,
};
use crate::commands::analyze::stats::duration::format_duration;
use std::collections::HashMap;
use tabled::{Table, Tabled, settings::Style};

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
        "├─ 🟢 Fast (<2min): {} sessions ({:.1}%)\n",
        duration.distribution.fast_lt_2min.count, duration.distribution.fast_lt_2min.percentage
    ));
    output.push_str(&format!(
        "├─ 🟢 Normal (2-5min): {} sessions ({:.1}%)\n",
        duration.distribution.normal_2_5min.count, duration.distribution.normal_2_5min.percentage
    ));
    output.push_str(&format!(
        "├─ 🟡 Slow (5-10min): {} sessions ({:.1}%)\n",
        duration.distribution.slow_5_10min.count, duration.distribution.slow_5_10min.percentage
    ));
    output.push_str(&format!(
        "├─ 🔴 Very Slow (10-20min): {} sessions ({:.1}%)\n",
        duration.distribution.very_slow_10_20min.count,
        duration.distribution.very_slow_10_20min.percentage
    ));
    output.push_str(&format!(
        "└─ 🔴 Extremely Slow (>20min): {} sessions ({:.1}%)\n\n",
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

    // Error Rate Analysis
    if !server_perf.error_analysis.highest_error_servers.is_empty() {
        output.push_str("🔴 SERVER ERROR RATE ANALYSIS:\n");
        for (i, server) in server_perf
            .error_analysis
            .highest_error_servers
            .iter()
            .enumerate()
        {
            format_error_server_detailed(
                output,
                server,
                i == server_perf.error_analysis.highest_error_servers.len() - 1,
            );
        }
        output.push('\n');
    }

    // Detailed Server Statistics Tables
    format_server_statistics_tables(output, &analysis.server_performance.detailed_server_stats);

    // Chunk Allocation Analysis
    format_chunk_allocation_analysis(
        output,
        &analysis.server_performance.chunk_allocation_analysis,
    );

    // Best Performing Servers
    if !server_perf.ttfb_analysis.best_servers.is_empty()
        || !server_perf.speed_analysis.fastest_servers.is_empty()
        || !server_perf
            .reliability_analysis
            .most_reliable_servers
            .is_empty()
        || !server_perf.error_analysis.most_reliable_servers.is_empty()
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

        // Show error-free champions
        for (i, server) in server_perf
            .error_analysis
            .most_reliable_servers
            .iter()
            .take(2)
            .enumerate()
        {
            let is_last = i == server_perf.error_analysis.most_reliable_servers.len() - 1 || i == 1;
            let prefix = if is_last { "└─" } else { "├─" };
            output.push_str(&format!(
                "{} ⭐ {}: {:.1}% error rate ({} requests)\n",
                prefix, server.server_id, server.error_rate_percentage, server.total_requests
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
}

fn format_error_server_detailed(output: &mut String, server: &ServerErrorStats, is_last: bool) {
    let prefix = if is_last { "└─" } else { "├─" };
    let severity_icon = match server.severity.as_str() {
        "critical" => "🚨",
        "warning" => "⚠️",
        _ => "🔴",
    };

    // Server header
    output.push_str(&format!(
        "{} {} {}: {:.1}% error rate ({}/{} requests)\n",
        prefix,
        severity_icon,
        server.server_id,
        server.error_rate_percentage,
        server.error_count,
        server.total_requests
    ));

    // Sort error types by count (highest first)
    let mut error_types: Vec<_> = server.error_types.iter().collect();
    error_types.sort_by(|a, b| b.1.cmp(a.1));

    // Display each error type with its percentage
    for (i, (error_type, count)) in error_types.iter().enumerate() {
        let error_percentage = (**count as f64 / server.error_count as f64) * 100.0;
        let error_total_percentage = (**count as f64 / server.total_requests as f64) * 100.0;

        let error_prefix = if is_last {
            if i == error_types.len() - 1 {
                "    └─"
            } else {
                "    ├─"
            }
        } else {
            if i == error_types.len() - 1 {
                "│   └─"
            } else {
                "│   ├─"
            }
        };

        output.push_str(&format!(
            "{} {}: {} occurrences ({:.1}% of errors, {:.1}% of total requests)\n",
            error_prefix, error_type, count, error_percentage, error_total_percentage
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
        "│   ├─ 0 retries: {} ({:.1}%)\n",
        retry.retry_distribution.zero_retries.count,
        retry.retry_distribution.zero_retries.percentage
    ));
    output.push_str(&format!(
        "│   ├─ 1 retry: {} ({:.1}%)\n",
        retry.retry_distribution.one_retry.count, retry.retry_distribution.one_retry.percentage
    ));
    output.push_str(&format!(
        "│   ├─ 2 retries: {} ({:.1}%)\n",
        retry.retry_distribution.two_retries.count, retry.retry_distribution.two_retries.percentage
    ));
    output.push_str(&format!(
        "│   ├─ 3 retries: {} ({:.1}%)\n",
        retry.retry_distribution.three_retries.count,
        retry.retry_distribution.three_retries.percentage
    ));
    output.push_str(&format!(
        "│   └─ 4+ retries: {} ({:.1}%)\n",
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

    // Server retry statistics
    format_server_retry_statistics(output, &retry.by_server);
}

fn format_server_retry_statistics(
    output: &mut String,
    by_server: &HashMap<String, ServerRetryStats>,
) {
    if by_server.is_empty() {
        return;
    }

    output.push_str("📊 SERVER RETRY STATISTICS:\n");

    // Convert to vector and sort by avg_retries (highest first)
    let mut server_stats: Vec<_> = by_server.values().collect();
    server_stats.sort_by(|a, b| {
        b.avg_retries
            .partial_cmp(&a.avg_retries)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Show high retry servers (avg_retries > 0.5)
    let high_retry_servers: Vec<_> = server_stats
        .iter()
        .filter(|stats| stats.avg_retries > 0.5)
        .take(5)
        .collect();

    if !high_retry_servers.is_empty() {
        output.push_str("├─ 🔴 High Retry Servers:\n");
        for (i, stats) in high_retry_servers.iter().enumerate() {
            let prefix = if i == high_retry_servers.len() - 1 {
                "│   └─"
            } else {
                "│   ├─"
            };

            // Show main retry reason for this server
            let top_reason = stats
                .retry_reasons
                .iter()
                .max_by_key(|(_, count)| *count)
                .map(|(reason, _)| reason.as_str())
                .unwrap_or("unknown");

            output.push_str(&format!(
                "{} {}: {:.1} avg retries, {:.1}% penalty rate ({})\n",
                prefix, stats.server_id, stats.avg_retries, stats.penalty_rate, top_reason
            ));
        }
    }

    // Show reliable servers (avg_retries <= 0.5)
    let reliable_servers: Vec<_> = server_stats
        .iter()
        .filter(|stats| stats.avg_retries <= 0.5)
        .take(3)
        .collect();

    if !reliable_servers.is_empty() {
        let connector = if high_retry_servers.is_empty() {
            "├─"
        } else {
            "└─"
        };
        output.push_str(&format!("{} 🟢 Reliable Servers:\n", connector));
        for (i, stats) in reliable_servers.iter().enumerate() {
            let prefix = if i == reliable_servers.len() - 1 {
                "    └─"
            } else {
                "    ├─"
            };

            // Show main retry reason for this server if it has any retries
            if !stats.retry_reasons.is_empty() {
                let top_reason = stats
                    .retry_reasons
                    .iter()
                    .max_by_key(|(_, count)| *count)
                    .map(|(reason, _)| format!(" ({})", reason))
                    .unwrap_or_default();

                output.push_str(&format!(
                    "{} {}: {:.1} avg retries, {:.1}% penalty rate{}\n",
                    prefix, stats.server_id, stats.avg_retries, stats.penalty_rate, top_reason
                ));
            } else {
                output.push_str(&format!(
                    "{} {}: {:.1} avg retries, {:.1}% penalty rate\n",
                    prefix, stats.server_id, stats.avg_retries, stats.penalty_rate
                ));
            }
        }
    }

    output.push('\n');
}

fn format_chunk_allocation_analysis(output: &mut String, analysis: &ChunkAllocationAnalysis) {
    if analysis.total_impact.total_misallocated_chunks == 0 {
        return;
    }

    output.push_str("🎯 CHUNK ALLOCATION ANALYSIS:\n");

    // Overall impact summary
    output.push_str(&format!(
        "├─ Misallocated Large Files: {} chunks (total penalty: {})\n",
        analysis.total_impact.total_misallocated_chunks,
        format_duration(analysis.total_impact.total_time_penalty_seconds)
    ));

    // Server-wise misallocation summary
    if !analysis.misallocated_chunks.is_empty() {
        output.push_str("├─ 🔴 Misallocation by Server:\n");

        // Group chunks by server and calculate statistics
        let mut server_misallocations: HashMap<
            String,
            Vec<&crate::commands::analyze::models::MisallocatedChunk>,
        > = HashMap::new();
        for chunk in &analysis.misallocated_chunks {
            server_misallocations
                .entry(chunk.server_id.clone())
                .or_default()
                .push(chunk);
        }

        // Sort servers by total time penalty (worst first)
        let mut server_stats: Vec<_> = server_misallocations
            .iter()
            .map(|(server_id, chunks)| {
                let total_chunks = chunks.len();
                let total_penalty = chunks.iter().map(|c| c.time_penalty_seconds).sum::<f64>();
                let avg_chunk_size =
                    chunks.iter().map(|c| c.chunk_size_mb).sum::<f64>() / chunks.len() as f64;
                let avg_speed =
                    chunks.iter().map(|c| c.download_speed_mbps).sum::<f64>() / chunks.len() as f64;
                let worst_case = chunks
                    .iter()
                    .max_by(|a, b| {
                        a.time_penalty_seconds
                            .partial_cmp(&b.time_penalty_seconds)
                            .unwrap()
                    })
                    .unwrap();

                (
                    server_id,
                    total_chunks,
                    total_penalty,
                    avg_chunk_size,
                    avg_speed,
                    worst_case,
                )
            })
            .collect();

        server_stats.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

        // Display server statistics
        for (i, (server_id, chunk_count, total_penalty, avg_chunk_size, avg_speed, worst_case)) in
            server_stats.iter().enumerate()
        {
            let prefix = if i == server_stats.len() - 1 {
                "│   └─"
            } else {
                "│   ├─"
            };

            output.push_str(&format!(
                "{} {}: {} chunks, {} total penalty, avg {:.1}MB at {:.3}MB/s (worst: +{})\n",
                prefix,
                server_id,
                chunk_count,
                format_duration(*total_penalty),
                avg_chunk_size,
                avg_speed,
                format_duration(worst_case.time_penalty_seconds)
            ));
        }
    }

    // Server distribution analysis
    let fast_servers_large_chunks: usize = analysis
        .server_chunk_distribution
        .values()
        .filter(|stats| stats.avg_speed_mbps >= 2.0)
        .map(|stats| stats.large_chunks)
        .sum();

    let slow_servers_large_chunks: usize = analysis
        .server_chunk_distribution
        .values()
        .filter(|stats| stats.avg_speed_mbps < 2.0)
        .map(|stats| stats.large_chunks)
        .sum();

    let total_large_chunks = fast_servers_large_chunks + slow_servers_large_chunks;

    if total_large_chunks > 0 {
        let fast_percentage =
            (fast_servers_large_chunks as f64 / total_large_chunks as f64) * 100.0;
        let slow_percentage =
            (slow_servers_large_chunks as f64 / total_large_chunks as f64) * 100.0;

        output.push_str("├─ 📊 Server Chunk Distribution:\n");
        output.push_str(&format!(
            "│   ├─ Fast servers handle {:.0}% of large chunks\n",
            fast_percentage
        ));
        output.push_str(&format!(
            "│   └─ Slow servers handle {:.0}% of large chunks\n",
            slow_percentage
        ));
    }

    // Optimization potential
    let total_sessions = analysis.total_impact.affected_sessions;
    if total_sessions > 0 {
        output.push_str(&format!(
            "└─ 💡 Optimization Potential: {} penalty across {} sessions\n",
            format_duration(analysis.total_impact.total_time_penalty_seconds),
            total_sessions
        ));
    }

    output.push('\n');
}

fn format_issues_summary(output: &mut String, analysis: &AnalysisResult) {
    let issues = &analysis.issues_summary;

    output.push_str("🎯 KEY ISSUES SUMMARY\n");

    if !issues.critical_servers.is_empty() {
        output.push_str("├─ 🚨 Critical Servers:\n");
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
    output.push_str(&format!("└─ {}\n", quality.recommendation));
}

/// Table row for TTFB statistics display
#[derive(Tabled)]
struct TtfbTableRow {
    #[tabled(rename = "Server ID")]
    server_id: String,
    #[tabled(rename = "Mean")]
    mean: String,
    #[tabled(rename = "Median")]
    median: String,
    #[tabled(rename = "Min")]
    min: String,
    #[tabled(rename = "Max")]
    max: String,
    #[tabled(rename = "Std Dev")]
    std_dev: String,
    #[tabled(rename = "P95")]
    p95: String,
    #[tabled(rename = "P99")]
    p99: String,
    #[tabled(rename = "Samples")]
    samples: String,
}

/// Table row for Speed statistics display
#[derive(Tabled)]
struct SpeedTableRow {
    #[tabled(rename = "Server ID")]
    server_id: String,
    #[tabled(rename = "P95")]
    p95: String,
    #[tabled(rename = "P99")]
    p99: String,
    #[tabled(rename = "Mean")]
    mean: String,
    #[tabled(rename = "Median")]
    median: String,
    #[tabled(rename = "Min")]
    min: String,
    #[tabled(rename = "Max")]
    max: String,
    #[tabled(rename = "Std Dev")]
    std_dev: String,
    #[tabled(rename = "Samples")]
    samples: String,
}

fn format_server_statistics_tables(output: &mut String, server_stats: &[ServerDetailedStats]) {
    if server_stats.is_empty() {
        return;
    }

    // TTFB Table (sorted by mean TTFB, fastest first - lowest values first)
    let mut ttfb_stats_sorted: Vec<&ServerDetailedStats> = server_stats
        .iter()
        .filter(|stats| stats.ttfb_stats.is_some())
        .collect();

    ttfb_stats_sorted.sort_by(|a, b| {
        let a_mean = a.ttfb_stats.as_ref().unwrap().mean;
        let b_mean = b.ttfb_stats.as_ref().unwrap().mean;
        a_mean
            .partial_cmp(&b_mean)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let ttfb_rows: Vec<TtfbTableRow> = ttfb_stats_sorted
        .iter()
        .map(|stats| {
            let ttfb = stats.ttfb_stats.as_ref().unwrap();
            TtfbTableRow {
                server_id: stats.server_id.clone(),
                mean: format!("{:.0}", ttfb.mean),
                median: format!("{:.0}", ttfb.median),
                min: format!("{:.0}", ttfb.min),
                max: format!("{:.0}", ttfb.max),
                std_dev: format!("{:.0}", ttfb.std_dev),
                p95: format!("{:.0}", ttfb.p95),
                p99: format!("{:.0}", ttfb.p99),
                samples: format_number(ttfb.sample_count),
            }
        })
        .collect();

    if !ttfb_rows.is_empty() {
        output.push_str("📊 DETAILED TTFB STATISTICS (milliseconds):\n");
        let table = Table::new(&ttfb_rows).with(Style::rounded()).to_string();
        output.push_str(&table);
        output.push_str("\n\n");
    }

    // Speed Table (sorted by mean speed, fastest first - highest values first)
    let mut speed_stats_sorted: Vec<&ServerDetailedStats> = server_stats
        .iter()
        .filter(|stats| stats.speed_stats.is_some())
        .collect();

    speed_stats_sorted.sort_by(|a, b| {
        let a_mean = a.speed_stats.as_ref().unwrap().mean;
        let b_mean = b.speed_stats.as_ref().unwrap().mean;
        b_mean
            .partial_cmp(&a_mean)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let speed_rows: Vec<SpeedTableRow> = speed_stats_sorted
        .iter()
        .map(|stats| {
            let speed = stats.speed_stats.as_ref().unwrap();
            SpeedTableRow {
                server_id: stats.server_id.clone(),
                p95: format!("{:.3}", speed.p95),
                p99: format!("{:.3}", speed.p99),
                mean: format!("{:.3}", speed.mean),
                median: format!("{:.3}", speed.median),
                min: format!("{:.3}", speed.min),
                max: format!("{:.3}", speed.max),
                std_dev: format!("{:.3}", speed.std_dev),
                samples: format_number(speed.sample_count),
            }
        })
        .collect();

    if !speed_rows.is_empty() {
        output.push_str("📊 DETAILED SPEED STATISTICS (MB/s):\n");
        let table = Table::new(&speed_rows).with(Style::rounded()).to_string();
        output.push_str(&table);
        output.push_str("\n\n");
    }

    // File Size Performance Analysis Tables
    format_file_size_performance_tables(output, server_stats);

    // Session Impact Analysis Table
    format_session_impact_table(output, server_stats);
}

fn format_number(num: usize) -> String {
    if num >= 1000 {
        format!("{:.1}k", num as f64 / 1000.0)
    } else {
        num.to_string()
    }
}

/// Format file size performance analysis tables
fn format_file_size_performance_tables(output: &mut String, server_stats: &[ServerDetailedStats]) {
    // Filter servers with file size analysis data
    let servers_with_file_stats: Vec<_> = server_stats
        .iter()
        .filter(|stats| stats.file_size_stats.is_some())
        .collect();

    if servers_with_file_stats.is_empty() {
        return;
    }

    output.push_str("📊 FILE SIZE PERFORMANCE ANALYSIS:\n\n");

    // Tiny Files (<1MB) - TTFB Performance
    format_tiny_files_table(output, &servers_with_file_stats);

    // Small Files (1-4MB) - Mixed Performance
    format_small_files_table(output, &servers_with_file_stats);

    // Medium Files (4-20MB) - Speed Performance
    format_medium_files_table(output, &servers_with_file_stats);

    // Large Files (>20MB) - Speed Performance
    format_large_files_table(output, &servers_with_file_stats);
}

#[derive(Tabled)]
struct TinyFileTableRow {
    #[tabled(rename = "Server")]
    server_id: String,
    #[tabled(rename = "Count")]
    count: String,
    #[tabled(rename = "P50 ms")]
    p50_ttfb: String,
    #[tabled(rename = "P95 ms")]
    p95_ttfb: String,
    #[tabled(rename = "P99 ms")]
    p99_ttfb: String,
    #[tabled(rename = "Max ms")]
    max_ttfb: String,
}

#[derive(Tabled)]
struct SmallFileTableRow {
    #[tabled(rename = "Server")]
    server_id: String,
    #[tabled(rename = "Count")]
    count: String,
    #[tabled(rename = "TTFB P50")]
    ttfb_p50: String,
    #[tabled(rename = "Speed P50")]
    speed_p50: String,
    #[tabled(rename = "Dur P95")]
    duration_p95: String,
}

#[derive(Tabled)]
struct LargeFileTableRow {
    #[tabled(rename = "Server")]
    server_id: String,
    #[tabled(rename = "Count")]
    count: String,
    #[tabled(rename = "P50")]
    p50_speed: String,
    #[tabled(rename = "P95")]
    p95_speed: String,
    #[tabled(rename = "Min")]
    min_speed: String,
    #[tabled(rename = "Avg Dur")]
    avg_duration: String,
}

fn format_tiny_files_table(output: &mut String, servers: &[&ServerDetailedStats]) {
    let mut rows: Vec<TinyFileTableRow> = Vec::new();

    for stats in servers {
        if let Some(ref file_stats) = stats.file_size_stats
            && file_stats.tiny_files.count > 0
        {
            let ttfb_stats = &file_stats.tiny_files.ttfb_stats;
            rows.push(TinyFileTableRow {
                server_id: stats.server_id.clone(),
                count: file_stats.tiny_files.count.to_string(),
                p50_ttfb: ttfb_stats
                    .as_ref()
                    .map(|s| format!("{:.0}", s.median))
                    .unwrap_or("-".to_string()),
                p95_ttfb: ttfb_stats
                    .as_ref()
                    .map(|s| format!("{:.0}", s.p95))
                    .unwrap_or("-".to_string()),
                p99_ttfb: ttfb_stats
                    .as_ref()
                    .map(|s| format!("{:.0}", s.p99))
                    .unwrap_or("-".to_string()),
                max_ttfb: ttfb_stats
                    .as_ref()
                    .map(|s| format!("{:.0}", s.max))
                    .unwrap_or("-".to_string()),
            });
        }
    }

    if !rows.is_empty() {
        // Sort by P95 TTFB (ascending - faster first)
        rows.sort_by(|a, b| {
            let a_p95 = a.p95_ttfb.parse::<f64>().unwrap_or(f64::MAX);
            let b_p95 = b.p95_ttfb.parse::<f64>().unwrap_or(f64::MAX);
            a_p95
                .partial_cmp(&b_p95)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        output.push_str("Small Files (<1MB) - TTFB Performance:\n");
        let table = Table::new(&rows).with(Style::rounded()).to_string();
        output.push_str(&table);
        output.push_str("\n\n");
    }
}

fn format_small_files_table(output: &mut String, servers: &[&ServerDetailedStats]) {
    let mut rows: Vec<SmallFileTableRow> = Vec::new();

    for stats in servers {
        if let Some(ref file_stats) = stats.file_size_stats
            && file_stats.small_files.count > 0
        {
            rows.push(SmallFileTableRow {
                server_id: stats.server_id.clone(),
                count: file_stats.small_files.count.to_string(),
                ttfb_p50: file_stats
                    .small_files
                    .ttfb_stats
                    .as_ref()
                    .map(|s| format!("{:.0}ms", s.median))
                    .unwrap_or("-".to_string()),
                speed_p50: file_stats
                    .small_files
                    .speed_stats
                    .as_ref()
                    .map(|s| format!("{:.2}MB/s", s.median))
                    .unwrap_or("-".to_string()),
                duration_p95: format!("{:.1}s", file_stats.small_files.duration_stats.p95),
            });
        }
    }

    if !rows.is_empty() {
        output.push_str("Medium Files (1-4MB) - Mixed Performance:\n");
        let table = Table::new(&rows).with(Style::rounded()).to_string();
        output.push_str(&table);
        output.push_str("\n\n");
    }
}

fn format_medium_files_table(output: &mut String, servers: &[&ServerDetailedStats]) {
    format_large_files_table_with_title(output, servers, "Medium Files (4-20MB)", |stats| {
        &stats.medium_files
    });
}

fn format_large_files_table(output: &mut String, servers: &[&ServerDetailedStats]) {
    format_large_files_table_with_title(output, servers, "Large Files (>20MB)", |stats| {
        &stats.large_files
    });
}

fn format_large_files_table_with_title<F>(
    output: &mut String,
    servers: &[&ServerDetailedStats],
    title: &str,
    selector: F,
) where
    F: Fn(&FileSizePerformance) -> &FileSizeStats,
{
    let mut rows: Vec<LargeFileTableRow> = Vec::new();

    for stats in servers {
        if let Some(ref file_stats) = stats.file_size_stats {
            let file_size_stats = selector(file_stats);
            if file_size_stats.count > 0 {
                rows.push(LargeFileTableRow {
                    server_id: stats.server_id.clone(),
                    count: file_size_stats.count.to_string(),
                    p50_speed: file_size_stats
                        .speed_stats
                        .as_ref()
                        .map(|s| format!("{:.3}", s.median))
                        .unwrap_or("-".to_string()),
                    p95_speed: file_size_stats
                        .speed_stats
                        .as_ref()
                        .map(|s| format!("{:.3}", s.p95))
                        .unwrap_or("-".to_string()),
                    min_speed: file_size_stats
                        .speed_stats
                        .as_ref()
                        .map(|s| format!("{:.3}", s.min))
                        .unwrap_or("-".to_string()),
                    avg_duration: format!("{:.1}s", file_size_stats.duration_stats.mean),
                });
            }
        }
    }

    if !rows.is_empty() {
        output.push_str(&format!("{} - Speed Performance:\n", title));
        let table = Table::new(&rows).with(Style::rounded()).to_string();
        output.push_str(&table);
        output.push_str("\n\n");
    }
}

/// Format session impact analysis table
fn format_session_impact_table(output: &mut String, server_stats: &[ServerDetailedStats]) {
    let servers_with_impact: Vec<_> = server_stats
        .iter()
        .filter(|stats| stats.impact_stats.is_some())
        .collect();

    if servers_with_impact.is_empty() {
        return;
    }

    #[derive(Tabled)]
    struct SessionImpactRow {
        #[tabled(rename = "Server")]
        server_id: String,
        #[tabled(rename = "Grade")]
        grade: String,
        #[tabled(rename = "CPI v5")]
        cpi_score: String,
        #[tabled(rename = "Tail %")]
        tail_rate: String,
        #[tabled(rename = "LowConcur")]
        low_concurrency_speed: String,
        #[tabled(rename = "TailPerf")]
        tail_performance: String,
        #[tabled(rename = "CritPath")]
        critical_path_reliability: String,
        #[tabled(rename = "Adapt")]
        adaptability: String,
        #[tabled(rename = "AvgConc")]
        avg_concurrency: String,
        #[tabled(rename = "Sessions")]
        affected_sessions: String,
    }

    let mut impact_rows: Vec<SessionImpactRow> = Vec::new();

    for stats in &servers_with_impact {
        if let Some(ref impact) = stats.impact_stats {
            impact_rows.push(SessionImpactRow {
                server_id: stats.server_id.clone(),
                grade: impact.grade.clone(),
                cpi_score: format!("{:.1}", impact.cpi_score),
                tail_rate: format!("{:.1}%", impact.tail_appearance_rate),
                low_concurrency_speed: if impact.low_concurrency_speed > 0.0 {
                    format!("{:.1}MB/s", impact.low_concurrency_speed)
                } else {
                    "N/A".to_string()
                },
                tail_performance: if impact.tail_performance_score > 0.0 {
                    format!("{:.1}MB/s", impact.tail_performance_score)
                } else {
                    "N/A".to_string()
                },
                critical_path_reliability: format!("{:.2}", impact.critical_path_reliability),
                adaptability: format!("{:.2}", impact.adaptability_score),
                avg_concurrency: format!("{:.1}", impact.avg_concurrency_level),
                affected_sessions: format!("{}", impact.affected_sessions),
            });
        }
    }

    if !impact_rows.is_empty() {
        // Sort by CPI score (highest first - best performers first)
        impact_rows.sort_by(|a, b| {
            let a_cpi = a.cpi_score.parse::<f64>().unwrap_or(0.0);
            let b_cpi = b.cpi_score.parse::<f64>().unwrap_or(0.0);
            b_cpi
                .partial_cmp(&a_cpi)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        output.push_str("📊 SESSION IMPACT ANALYSIS:\n");
        let table = Table::new(&impact_rows).with(Style::rounded()).to_string();
        output.push_str(&table);
        output.push_str("\n\nLegend:\n");
        output.push_str("- Grade: Performance grade (S/A/B/C/D/F, S is best)\n");
        output.push_str("- CPI: Comprehensive Performance Index (0-100, higher is better)\n");
        output.push_str("- Type: Bottleneck classification (Bottleneck/EffBottleneck/Workhorse/Normal/Underused)\n");
        output.push_str(
            "- Eff: Efficiency score (0-1, higher is better, relative to session median speed)\n",
        );
        output.push_str("- Btl: Bottleneck score (0-1, higher means more bottleneck-like)\n");
        output.push_str("- Tail %: Rate of downloads completing in last 10% of session time\n");
        output.push_str("- Ext: Session time difference vs average speed (+slow, -fast)\n");
        output.push_str("- Cnt: Bottleneck occurrences / Total session participations\n\n");
    }
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
