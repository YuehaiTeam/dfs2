use crate::commands::analyze::models::{AnalysisInfo, AnalysisPeriod, AnalysisResult, SessionLog};
use crate::commands::analyze::stats::{duration, quality, retry, server};
use chrono::{DateTime, Utc};
use std::path::Path;

/// Main analysis engine that orchestrates all analysis components
pub fn analyze_sessions(
    sessions: Vec<SessionLog>,
) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    if sessions.is_empty() {
        return Err("No session data to analyze".into());
    }

    eprintln!("Running session duration analysis...");
    let session_duration = duration::analyze_session_duration(&sessions);

    eprintln!("Running server performance analysis...");
    let server_performance = server::analyze_server_performance(&sessions);

    eprintln!("Running retry pattern analysis...");
    let retry_analysis = retry::analyze_retry_patterns(&sessions);

    eprintln!("Running data quality analysis...");
    let data_quality = quality::analyze_data_quality(&sessions);

    eprintln!("Generating issues summary...");
    let issues_summary =
        quality::generate_issues_summary(&server_performance, &retry_analysis, &session_duration);

    // Calculate analysis period from session timestamps
    let (start_time, end_time) = calculate_analysis_period(&sessions);

    let analysis_info = AnalysisInfo {
        analysis_period: AnalysisPeriod {
            start: start_time,
            end: end_time,
        },
        log_file: "session_log".to_string(), // Will be updated by caller
        total_records: sessions.len(),
        generated_at: Utc::now(),
    };

    Ok(AnalysisResult {
        analysis_info,
        session_duration,
        server_performance,
        retry_analysis,
        issues_summary,
        data_quality,
    })
}

fn calculate_analysis_period(sessions: &[SessionLog]) -> (DateTime<Utc>, DateTime<Utc>) {
    if sessions.is_empty() {
        let now = Utc::now();
        return (now, now);
    }

    let mut min_timestamp = u64::MAX;
    let mut max_timestamp = 0u64;

    for session in sessions {
        min_timestamp = min_timestamp.min(session.start);
        max_timestamp = max_timestamp.max(session.end);
    }

    let start_time = DateTime::from_timestamp(min_timestamp as i64, 0).unwrap_or_else(Utc::now);
    let end_time = DateTime::from_timestamp(max_timestamp as i64, 0).unwrap_or_else(Utc::now);

    (start_time, end_time)
}

/// Update analysis info with actual log file path
pub fn update_log_file_info(analysis_result: &mut AnalysisResult, log_file_path: &str) {
    analysis_result.analysis_info.log_file = Path::new(log_file_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(log_file_path)
        .to_string();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::analyze::models::{CdnRecordLog, ChunkLog};

    #[test]
    fn test_analyze_sessions() {
        let sessions = vec![
            create_test_session("session_completed", 1640995200, 1640995320),
            create_test_session("direct_download", 1640995400, 1640995460),
        ];

        let result = analyze_sessions(sessions).unwrap();

        assert_eq!(result.analysis_info.total_records, 2);
        assert!(result.session_duration.statistics.average_seconds > 0.0);
        assert!(
            !result.issues_summary.critical_servers.is_empty()
                || !result.issues_summary.excellent_performers.is_empty()
                || result
                    .issues_summary
                    .experience_issues
                    .users_over_5min_percentage
                    >= 0.0
        );
    }

    #[test]
    fn test_calculate_analysis_period() {
        let sessions = vec![
            create_test_session("session_completed", 1640995200, 1640995320), // 2022-01-01 00:00:00
            create_test_session("session_completed", 1640995400, 1640995500), // 2022-01-01 00:03:20
        ];

        let (start, end) = calculate_analysis_period(&sessions);

        assert_eq!(start.timestamp(), 1640995200);
        assert_eq!(end.timestamp(), 1640995500);
    }

    #[test]
    fn test_empty_sessions() {
        let sessions = vec![];
        let result = analyze_sessions(sessions);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "No session data to analyze"
        );
    }

    #[test]
    fn test_update_log_file_info() {
        let sessions = vec![create_test_session("session_completed", 1000, 1100)];
        let mut result = analyze_sessions(sessions).unwrap();

        update_log_file_info(&mut result, "/path/to/sessions.2024-01-15.log");
        assert_eq!(result.analysis_info.log_file, "sessions.2024-01-15.log");

        update_log_file_info(&mut result, "simple.log");
        assert_eq!(result.analysis_info.log_file, "simple.log");
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
            chunks: vec![ChunkLog {
                rng: "0-1023".to_string(),
                att: 1,
                cdns: vec![CdnRecordLog {
                    url: "https://cdn.example.com/test".to_string(),
                    srv: Some("cdn-01".to_string()),
                    wgt: Some(10),
                    ts: start + 10,
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
