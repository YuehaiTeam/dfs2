use crate::commands::analyze::models::{
    CountAndPercentage, GlobalRetryStats, RetryAnalysis, RetryDistribution, ServerRetryStats,
    SessionLog, TimeImpact,
};
use std::collections::HashMap;

pub fn analyze_retry_patterns(sessions: &[SessionLog]) -> RetryAnalysis {
    if sessions.is_empty() {
        return create_empty_retry_analysis();
    }

    // Global retry statistics
    let global_statistics = calculate_global_retry_stats(sessions);

    // Retry distribution
    let retry_distribution = calculate_retry_distribution(sessions);

    // Time impact analysis
    let time_impact = calculate_time_impact(sessions);

    // By server analysis
    let by_server = analyze_retry_by_server(sessions);

    RetryAnalysis {
        global_statistics,
        retry_distribution,
        time_impact,
        by_server,
    }
}

fn calculate_global_retry_stats(sessions: &[SessionLog]) -> GlobalRetryStats {
    let total_sessions = sessions.len();
    let mut total_retries = 0u32;
    let mut sessions_with_retries = 0;

    for session in sessions {
        let mut session_has_retries = false;

        for chunk in &session.chunks {
            total_retries += chunk.att;
            if chunk.att > 0 {
                session_has_retries = true;
            }
        }

        if session_has_retries {
            sessions_with_retries += 1;
        }
    }

    let retry_rate_percentage = if total_sessions > 0 {
        (sessions_with_retries as f64 / total_sessions as f64) * 100.0
    } else {
        0.0
    };

    let avg_retries = if total_sessions > 0 {
        total_retries as f64 / total_sessions as f64
    } else {
        0.0
    };

    GlobalRetryStats {
        total_sessions,
        sessions_with_retries,
        retry_rate_percentage,
        avg_retries,
    }
}

fn calculate_retry_distribution(sessions: &[SessionLog]) -> RetryDistribution {
    let mut retry_counts = HashMap::new();

    for session in sessions {
        let mut max_retries = 0u32;

        // Find the maximum retry count for this session
        for chunk in &session.chunks {
            max_retries = max_retries.max(chunk.att);
        }

        *retry_counts.entry(max_retries).or_insert(0) += 1;
    }

    let total_sessions = sessions.len();

    let zero_retries = *retry_counts.get(&0).unwrap_or(&0);
    let one_retry = *retry_counts.get(&1).unwrap_or(&0);
    let two_retries = *retry_counts.get(&2).unwrap_or(&0);
    let three_retries = *retry_counts.get(&3).unwrap_or(&0);

    // Count sessions with 4+ retries
    let four_plus_retries = retry_counts
        .iter()
        .filter(|(retries, _)| **retries >= 4)
        .map(|(_, count)| *count)
        .sum::<usize>();

    RetryDistribution {
        zero_retries: CountAndPercentage {
            count: zero_retries,
            percentage: percentage(zero_retries, total_sessions),
        },
        one_retry: CountAndPercentage {
            count: one_retry,
            percentage: percentage(one_retry, total_sessions),
        },
        two_retries: CountAndPercentage {
            count: two_retries,
            percentage: percentage(two_retries, total_sessions),
        },
        three_retries: CountAndPercentage {
            count: three_retries,
            percentage: percentage(three_retries, total_sessions),
        },
        four_plus_retries: CountAndPercentage {
            count: four_plus_retries,
            percentage: percentage(four_plus_retries, total_sessions),
        },
    }
}

fn calculate_time_impact(sessions: &[SessionLog]) -> TimeImpact {
    let mut durations_by_retries: HashMap<u32, Vec<f64>> = HashMap::new();

    for session in sessions {
        let duration = (session.end - session.start) as f64;
        let mut max_retries = 0u32;

        // Find the maximum retry count for this session
        for chunk in &session.chunks {
            max_retries = max_retries.max(chunk.att);
        }

        durations_by_retries
            .entry(max_retries)
            .or_insert_with(Vec::new)
            .push(duration);
    }

    let zero_retries_avg = calculate_average_duration(&durations_by_retries, 0);
    let one_retry_avg = calculate_average_duration(&durations_by_retries, 1);
    let two_retries_avg = calculate_average_duration(&durations_by_retries, 2);

    // Calculate average for 3+ retries combined
    let mut three_plus_durations = Vec::new();
    for (&retry_count, durations) in &durations_by_retries {
        if retry_count >= 3 {
            three_plus_durations.extend(durations);
        }
    }
    let three_plus_avg = if three_plus_durations.is_empty() {
        0.0
    } else {
        three_plus_durations.iter().sum::<f64>() / three_plus_durations.len() as f64
    };

    TimeImpact {
        zero_retries_avg_seconds: zero_retries_avg,
        one_retry_avg_seconds: one_retry_avg,
        two_retries_avg_seconds: two_retries_avg,
        three_plus_retries_avg_seconds: three_plus_avg,
    }
}

fn calculate_average_duration(durations_map: &HashMap<u32, Vec<f64>>, retry_count: u32) -> f64 {
    if let Some(durations) = durations_map.get(&retry_count) {
        if !durations.is_empty() {
            return durations.iter().sum::<f64>() / durations.len() as f64;
        }
    }
    0.0
}

fn analyze_retry_by_server(sessions: &[SessionLog]) -> HashMap<String, ServerRetryStats> {
    let mut server_data: HashMap<String, ServerRetryData> = HashMap::new();

    for session in sessions {
        for chunk in &session.chunks {
            for cdn_record in &chunk.cdns {
                if let Some(server_id) = &cdn_record.srv {
                    let data = server_data
                        .entry(server_id.clone())
                        .or_insert_with(ServerRetryData::new);

                    data.total_requests += 1;
                    data.total_retries += chunk.att;

                    // Track retry reasons
                    if let Some(reason) = &cdn_record.rsn {
                        *data.retry_reasons.entry(reason.clone()).or_insert(0) += 1;
                    }

                    // Track penalty rate
                    if cdn_record.pen == Some(true) {
                        data.penalty_count += 1;
                    }
                }
            }
        }
    }

    let mut result = HashMap::new();

    for (server_id, data) in server_data {
        if data.total_requests == 0 {
            continue;
        }

        let avg_retries = data.total_retries as f64 / data.total_requests as f64;
        let penalty_rate = (data.penalty_count as f64 / data.total_requests as f64) * 100.0;

        result.insert(
            server_id.clone(),
            ServerRetryStats {
                server_id,
                total_requests: data.total_requests,
                avg_retries,
                penalty_rate,
                retry_reasons: data.retry_reasons,
            },
        );
    }

    result
}

struct ServerRetryData {
    total_requests: usize,
    total_retries: u32,
    penalty_count: usize,
    retry_reasons: HashMap<String, usize>,
}

impl ServerRetryData {
    fn new() -> Self {
        Self {
            total_requests: 0,
            total_retries: 0,
            penalty_count: 0,
            retry_reasons: HashMap::new(),
        }
    }
}

fn percentage(count: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (count as f64 / total as f64) * 100.0
    }
}

fn create_empty_retry_analysis() -> RetryAnalysis {
    RetryAnalysis {
        global_statistics: GlobalRetryStats {
            total_sessions: 0,
            sessions_with_retries: 0,
            retry_rate_percentage: 0.0,
            avg_retries: 0.0,
        },
        retry_distribution: RetryDistribution {
            zero_retries: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
            one_retry: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
            two_retries: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
            three_retries: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
            four_plus_retries: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
        },
        time_impact: TimeImpact {
            zero_retries_avg_seconds: 0.0,
            one_retry_avg_seconds: 0.0,
            two_retries_avg_seconds: 0.0,
            three_plus_retries_avg_seconds: 0.0,
        },
        by_server: HashMap::new(),
    }
}

pub fn calculate_retry_time_increase(base_duration: f64, current_duration: f64) -> f64 {
    if base_duration == 0.0 {
        0.0
    } else {
        ((current_duration - base_duration) / base_duration) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::analyze::models::{CdnRecordLog, ChunkLog};

    #[test]
    fn test_retry_distribution() {
        let sessions = vec![
            create_test_session(0), // 0 retries
            create_test_session(1), // 1 retry
            create_test_session(1), // 1 retry
            create_test_session(2), // 2 retries
            create_test_session(4), // 4 retries
        ];

        let distribution = calculate_retry_distribution(&sessions);

        assert_eq!(distribution.zero_retries.count, 1);
        assert_eq!(distribution.zero_retries.percentage, 20.0);

        assert_eq!(distribution.one_retry.count, 2);
        assert_eq!(distribution.one_retry.percentage, 40.0);

        assert_eq!(distribution.two_retries.count, 1);
        assert_eq!(distribution.two_retries.percentage, 20.0);

        assert_eq!(distribution.four_plus_retries.count, 1);
        assert_eq!(distribution.four_plus_retries.percentage, 20.0);
    }

    #[test]
    fn test_time_impact() {
        let sessions = vec![
            create_test_session_with_duration(0, 100, 160), // 0 retries, 60s
            create_test_session_with_duration(1, 200, 320), // 1 retry, 120s
            create_test_session_with_duration(2, 300, 540), // 2 retries, 240s
        ];

        let time_impact = calculate_time_impact(&sessions);

        assert_eq!(time_impact.zero_retries_avg_seconds, 60.0);
        assert_eq!(time_impact.one_retry_avg_seconds, 120.0);
        assert_eq!(time_impact.two_retries_avg_seconds, 240.0);
    }

    #[test]
    fn test_global_retry_stats() {
        let sessions = vec![
            create_test_session(0), // No retry
            create_test_session(1), // 1 retry
            create_test_session(2), // 2 retries
        ];

        let stats = calculate_global_retry_stats(&sessions);

        assert_eq!(stats.total_sessions, 3);
        assert_eq!(stats.sessions_with_retries, 2); // Sessions with retries > 0
        assert!((stats.retry_rate_percentage - 66.66666666666667).abs() < 0.0001);
        assert_eq!(stats.avg_retries, 1.0); // (0 + 1 + 2) / 3
    }

    #[test]
    fn test_calculate_retry_time_increase() {
        let increase = calculate_retry_time_increase(60.0, 120.0);
        assert_eq!(increase, 100.0); // 100% increase

        let increase = calculate_retry_time_increase(100.0, 150.0);
        assert_eq!(increase, 50.0); // 50% increase
    }

    fn create_test_session(retries: u32) -> SessionLog {
        create_test_session_with_duration(retries, 1000, 1060)
    }

    fn create_test_session_with_duration(retries: u32, start: u64, end: u64) -> SessionLog {
        SessionLog {
            start,
            end,
            log_type: "session_completed".to_string(),
            sid: Some("test-session".to_string()),
            rid: "test-resource".to_string(),
            ver: "1.0.0".to_string(),
            ua: Some("TestAgent/1.0".to_string()),
            ip: ("192.168.1.100".to_string(), None),
            chunks: vec![ChunkLog {
                rng: "0-1023".to_string(),
                att: retries,
                cdns: vec![CdnRecordLog {
                    url: "https://cdn.example.com/test".to_string(),
                    srv: Some("cdn-01".to_string()),
                    wgt: Some(10),
                    ts: start + 10,
                    pen: Some(retries > 1),
                    rsn: if retries > 0 {
                        Some("retry_fallback".to_string())
                    } else {
                        Some("flow_selected".to_string())
                    },
                    ttfb: Some(1000),
                    time: Some(5000),
                    size: Some(1024000),
                    err: None,
                    mode: Some("http".to_string()),
                }],
            }],
        }
    }
}
