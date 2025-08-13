use crate::commands::analyze::models::AnalysisResult;

/// Format analysis result as JSON
pub fn format_json(analysis_result: &AnalysisResult) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(analysis_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::analyze::analyzer;
    use crate::commands::analyze::models::{CdnRecordLog, ChunkLog, SessionLog};

    #[test]
    fn test_format_json() {
        let sessions = vec![create_test_session()];
        let analysis_result = analyzer::analyze_sessions(sessions).unwrap();

        let json_output = format_json(&analysis_result).unwrap();

        // Verify it's valid JSON
        assert!(serde_json::from_str::<serde_json::Value>(&json_output).is_ok());

        // Check that key fields are present
        assert!(json_output.contains("analysis_info"));
        assert!(json_output.contains("session_duration"));
        assert!(json_output.contains("server_performance"));
        assert!(json_output.contains("retry_analysis"));
        assert!(json_output.contains("issues_summary"));
        assert!(json_output.contains("data_quality"));
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
