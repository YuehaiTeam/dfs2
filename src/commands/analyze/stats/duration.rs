use crate::commands::analyze::models::{
    CountAndPercentage, DurationDistribution, DurationStatistics, SessionDurationAnalysis,
    SessionLog,
};
use std::collections::HashMap;

pub fn analyze_session_duration(sessions: &[SessionLog]) -> SessionDurationAnalysis {
    if sessions.is_empty() {
        return create_empty_duration_analysis();
    }

    // Calculate all durations
    let mut durations: Vec<f64> = sessions.iter().map(|s| (s.end - s.start) as f64).collect();
    durations.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // Overall statistics
    let statistics = calculate_duration_statistics(&durations);

    // Duration distribution
    let distribution = calculate_duration_distribution(&durations, sessions.len());

    // By session type
    let by_type = analyze_duration_by_type(sessions);

    // By resource
    let by_resource = analyze_duration_by_resource(sessions);

    SessionDurationAnalysis {
        statistics,
        distribution,
        by_type,
        by_resource,
    }
}

fn calculate_duration_statistics(durations: &[f64]) -> DurationStatistics {
    if durations.is_empty() {
        return DurationStatistics {
            average_seconds: 0.0,
            median_seconds: 0.0,
            p95_seconds: 0.0,
            p99_seconds: 0.0,
            max_seconds: 0.0,
            min_seconds: 0.0,
        };
    }

    let len = durations.len();
    let sum: f64 = durations.iter().sum();
    let average = sum / len as f64;

    let median = if len % 2 == 0 {
        (durations[len / 2 - 1] + durations[len / 2]) / 2.0
    } else {
        durations[len / 2]
    };

    let p95_index = ((len as f64 * 0.95) as usize).min(len - 1);
    let p99_index = ((len as f64 * 0.99) as usize).min(len - 1);

    DurationStatistics {
        average_seconds: average,
        median_seconds: median,
        p95_seconds: durations[p95_index],
        p99_seconds: durations[p99_index],
        max_seconds: durations[len - 1],
        min_seconds: durations[0],
    }
}

fn calculate_duration_distribution(durations: &[f64], total_count: usize) -> DurationDistribution {
    let mut fast = 0; // < 2 minutes (120 seconds)
    let mut normal = 0; // 2-5 minutes (120-300 seconds)
    let mut slow = 0; // 5-10 minutes (300-600 seconds)
    let mut very_slow = 0; // 10-20 minutes (600-1200 seconds)
    let mut extremely_slow = 0; // > 20 minutes (1200+ seconds)

    for &duration in durations {
        if duration < 120.0 {
            fast += 1;
        } else if duration < 300.0 {
            normal += 1;
        } else if duration < 600.0 {
            slow += 1;
        } else if duration < 1200.0 {
            very_slow += 1;
        } else {
            extremely_slow += 1;
        }
    }

    DurationDistribution {
        fast_lt_2min: CountAndPercentage {
            count: fast,
            percentage: (fast as f64 / total_count as f64) * 100.0,
        },
        normal_2_5min: CountAndPercentage {
            count: normal,
            percentage: (normal as f64 / total_count as f64) * 100.0,
        },
        slow_5_10min: CountAndPercentage {
            count: slow,
            percentage: (slow as f64 / total_count as f64) * 100.0,
        },
        very_slow_10_20min: CountAndPercentage {
            count: very_slow,
            percentage: (very_slow as f64 / total_count as f64) * 100.0,
        },
        extremely_slow_gt_20min: CountAndPercentage {
            count: extremely_slow,
            percentage: (extremely_slow as f64 / total_count as f64) * 100.0,
        },
    }
}

fn analyze_duration_by_type(sessions: &[SessionLog]) -> HashMap<String, DurationStatistics> {
    let mut by_type: HashMap<String, Vec<f64>> = HashMap::new();

    for session in sessions {
        let duration = (session.end - session.start) as f64;
        by_type
            .entry(session.log_type.clone())
            .or_insert_with(Vec::new)
            .push(duration);
    }

    let mut result = HashMap::new();
    for (log_type, mut durations) in by_type {
        durations.sort_by(|a, b| a.partial_cmp(b).unwrap());
        result.insert(log_type, calculate_duration_statistics(&durations));
    }

    result
}

fn analyze_duration_by_resource(sessions: &[SessionLog]) -> HashMap<String, DurationStatistics> {
    let mut by_resource: HashMap<String, Vec<f64>> = HashMap::new();

    for session in sessions {
        let duration = (session.end - session.start) as f64;
        by_resource
            .entry(session.rid.clone())
            .or_insert_with(Vec::new)
            .push(duration);
    }

    let mut result = HashMap::new();
    for (resource_id, mut durations) in by_resource {
        durations.sort_by(|a, b| a.partial_cmp(b).unwrap());
        result.insert(resource_id, calculate_duration_statistics(&durations));
    }

    result
}

fn create_empty_duration_analysis() -> SessionDurationAnalysis {
    SessionDurationAnalysis {
        statistics: DurationStatistics {
            average_seconds: 0.0,
            median_seconds: 0.0,
            p95_seconds: 0.0,
            p99_seconds: 0.0,
            max_seconds: 0.0,
            min_seconds: 0.0,
        },
        distribution: DurationDistribution {
            fast_lt_2min: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
            normal_2_5min: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
            slow_5_10min: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
            very_slow_10_20min: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
            extremely_slow_gt_20min: CountAndPercentage {
                count: 0,
                percentage: 0.0,
            },
        },
        by_type: HashMap::new(),
        by_resource: HashMap::new(),
    }
}

pub fn format_duration(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{}s", seconds as u32)
    } else if seconds < 3600.0 {
        let minutes = (seconds / 60.0) as u32;
        let remaining_seconds = (seconds % 60.0) as u32;
        format!("{}m {}s", minutes, remaining_seconds)
    } else {
        let hours = (seconds / 3600.0) as u32;
        let minutes = ((seconds % 3600.0) / 60.0) as u32;
        let remaining_seconds = (seconds % 60.0) as u32;
        format!("{}h {}m {}s", hours, minutes, remaining_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duration_statistics() {
        let durations = vec![30.0, 60.0, 90.0, 120.0, 180.0, 300.0, 600.0, 1200.0];
        let stats = calculate_duration_statistics(&durations);

        assert_eq!(stats.min_seconds, 30.0);
        assert_eq!(stats.max_seconds, 1200.0);
        assert_eq!(stats.median_seconds, 150.0); // average of 120 and 180

        // P95 should be close to the 8th element (index 7)
        assert_eq!(stats.p95_seconds, 1200.0);
    }

    #[test]
    fn test_duration_distribution() {
        let durations = vec![
            30.0, 60.0, 90.0, // 3 fast (< 2min)
            150.0, 200.0, 250.0, // 3 normal (2-5min)
            350.0, 450.0,  // 2 slow (5-10min)
            800.0,  // 1 very slow (10-20min)
            1500.0, // 1 extremely slow (>20min)
        ]; // Total: 10

        let distribution = calculate_duration_distribution(&durations, 10);

        assert_eq!(distribution.fast_lt_2min.count, 3);
        assert_eq!(distribution.fast_lt_2min.percentage, 30.0);

        assert_eq!(distribution.normal_2_5min.count, 3);
        assert_eq!(distribution.normal_2_5min.percentage, 30.0);

        assert_eq!(distribution.slow_5_10min.count, 2);
        assert_eq!(distribution.slow_5_10min.percentage, 20.0);

        assert_eq!(distribution.very_slow_10_20min.count, 1);
        assert_eq!(distribution.very_slow_10_20min.percentage, 10.0);

        assert_eq!(distribution.extremely_slow_gt_20min.count, 1);
        assert_eq!(distribution.extremely_slow_gt_20min.percentage, 10.0);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30.0), "30s");
        assert_eq!(format_duration(90.0), "1m 30s");
        assert_eq!(format_duration(3661.0), "1h 1m 1s");
    }

    #[test]
    fn test_analyze_session_duration() {
        let sessions = vec![
            create_test_session("session_completed", 100, 160), // 60 seconds
            create_test_session("session_completed", 200, 320), // 120 seconds
            create_test_session("direct_download", 300, 330),   // 30 seconds
            create_test_session("session_timeout", 400, 1000),  // 600 seconds
        ];

        let analysis = analyze_session_duration(&sessions);

        assert_eq!(analysis.statistics.min_seconds, 30.0);
        assert_eq!(analysis.statistics.max_seconds, 600.0);

        // Should have entries for each session type
        assert!(analysis.by_type.contains_key("session_completed"));
        assert!(analysis.by_type.contains_key("direct_download"));
        assert!(analysis.by_type.contains_key("session_timeout"));

        // Fast: 30s, 60s (2)
        // Normal: 120s (1)
        // Very Slow: 600s (1)
        assert_eq!(analysis.distribution.fast_lt_2min.count, 2);
        assert_eq!(analysis.distribution.normal_2_5min.count, 1);
        assert_eq!(analysis.distribution.slow_5_10min.count, 0);
        assert_eq!(analysis.distribution.very_slow_10_20min.count, 1);
        assert_eq!(analysis.distribution.extremely_slow_gt_20min.count, 0);
    }

    fn create_test_session(log_type: &str, start: u64, end: u64) -> SessionLog {
        SessionLog {
            start,
            end,
            log_type: log_type.to_string(),
            sid: Some("test-session".to_string()),
            rid: "test-resource".to_string(),
            ver: "1.0.0".to_string(),
            ua: Some("TestAgent/1.0".to_string()),
            ip: ("192.168.1.100".to_string(), None),
            chunks: vec![],
        }
    }
}
