use crate::commands::analyze::models::SessionLog;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tokio::task;

/// Parse a log file containing JSONL session records
pub async fn parse_log_file(file_path: &str) -> Result<Vec<SessionLog>, String> {
    let file_path = file_path.to_string();

    // Use blocking task for file I/O to avoid blocking the async runtime
    let sessions = task::spawn_blocking(move || parse_log_file_sync(&file_path))
        .await
        .map_err(|e| format!("Task join error: {}", e))??;

    Ok(sessions)
}

/// Synchronous log file parser
fn parse_log_file_sync(file_path: &str) -> Result<Vec<SessionLog>, String> {
    let file = File::open(file_path).map_err(|e| format!("Failed to open file: {}", e))?;
    let reader = BufReader::new(file);

    let mut sessions = Vec::new();
    let mut total_lines = 0;
    let mut parse_errors = 0;

    for (line_num, line) in reader.lines().enumerate() {
        total_lines += 1;

        let line = line.map_err(|e| format!("Failed to read line {}: {}", line_num + 1, e))?;

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse JSON line
        match serde_json::from_str::<SessionLog>(&line) {
            Ok(session) => {
                // Validate session data
                if is_valid_session(&session) {
                    sessions.push(session);
                } else {
                    parse_errors += 1;
                    eprintln!("Warning: Invalid session data at line {}", line_num + 1);
                }
            }
            Err(e) => {
                parse_errors += 1;
                eprintln!("Warning: Failed to parse line {}: {}", line_num + 1, e);
            }
        }

        // Progress reporting for large files
        if total_lines % 10000 == 0 {
            eprintln!(
                "Processed {} lines, parsed {} sessions",
                total_lines,
                sessions.len()
            );
        }
    }

    if parse_errors > 0 {
        eprintln!(
            "Warning: {} parsing errors out of {} total lines",
            parse_errors, total_lines
        );
    }

    eprintln!(
        "Successfully parsed {} sessions from {} lines",
        sessions.len(),
        total_lines
    );

    Ok(sessions)
}

/// Validate session data quality
fn is_valid_session(session: &SessionLog) -> bool {
    // Basic validation checks
    if session.start == 0 || session.end == 0 {
        return false;
    }

    if session.end < session.start {
        return false;
    }

    if session.rid.is_empty() {
        return false;
    }

    // Duration should be reasonable (not more than 24 hours)
    let duration = session.end - session.start;
    if duration > 86400 {
        return false;
    }

    // Should have at least some chunk data for most session types
    if session.log_type != "cached_download" && session.chunks.is_empty() {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::analyze::models::{CdnRecordLog, ChunkLog};
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_valid_session() {
        let session_json = r#"{
            "start": 1640995200,
            "end": 1640995320,
            "type": "session_completed",
            "sid": "test-session-123",
            "rid": "test-resource",
            "ver": "1.0.0",
            "ua": "TestAgent/1.0",
            "ip": ["192.168.1.100", "Beijing, China"],
            "chunks": [{
                "rng": "0-1023",
                "att": 1,
                "cdns": [{
                    "url": "https://cdn.example.com/test",
                    "srv": "cdn-server-01",
                    "wgt": 10,
                    "ts": 1640995210,
                    "pen": false,
                    "rsn": "flow_selected",
                    "ttfb": 1234,
                    "time": 5678,
                    "size": 1024,
                    "err": null,
                    "mode": "http"
                }]
            }]
        }"#;

        let session: SessionLog = serde_json::from_str(session_json).unwrap();
        assert_eq!(session.rid, "test-resource");
        assert_eq!(session.chunks.len(), 1);
        assert!(is_valid_session(&session));
    }

    #[test]
    fn test_parse_invalid_session() {
        // Test session with end < start
        let mut session = create_test_session();
        session.end = session.start - 100;
        assert!(!is_valid_session(&session));

        // Test session with empty resource id
        let mut session = create_test_session();
        session.rid = String::new();
        assert!(!is_valid_session(&session));
    }

    #[tokio::test]
    async fn test_parse_log_file() {
        // Create temporary log file
        let mut temp_file = NamedTempFile::new().unwrap();

        let log_content = r#"{"start":1640995200,"end":1640995320,"type":"session_completed","sid":"test-1","rid":"resource-1","ver":"1.0.0","ua":"TestAgent/1.0","ip":["192.168.1.100",null],"chunks":[{"rng":"0-1023","att":1,"cdns":[{"url":"https://cdn.example.com/test","srv":"cdn-01","wgt":10,"ts":1640995210,"pen":false,"rsn":"flow_selected","ttfb":1234,"time":5678,"size":1024,"err":null,"mode":"http"}]}]}
{"start":1640995400,"end":1640995500,"type":"direct_download","sid":null,"rid":"resource-2","ver":"1.1.0","ua":"TestAgent/1.0","ip":["10.0.0.1","Shanghai, China"],"chunks":[{"rng":"full_file","att":0,"cdns":[{"url":"https://cdn2.example.com/test","srv":"cdn-02","wgt":8,"ts":1640995410,"pen":null,"rsn":"flow_selected","ttfb":null,"time":null,"size":null,"err":null,"mode":null}]}]}"#;

        fs::write(temp_file.path(), log_content).unwrap();

        let sessions = parse_log_file(temp_file.path().to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].rid, "resource-1");
        assert_eq!(sessions[1].rid, "resource-2");
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
            ip: (
                "192.168.1.100".to_string(),
                Some("Test Location".to_string()),
            ),
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
                    time: Some(5678),
                    size: Some(1024),
                    err: None,
                    mode: Some("http".to_string()),
                }],
            }],
        }
    }
}
