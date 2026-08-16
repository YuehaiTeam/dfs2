use crate::commands::analyze::models::{
    ChunkAllocationAnalysis, ChunkAllocationImpact, MisallocatedChunk, ServerChunkStats, SessionLog,
};
use std::collections::{HashMap, HashSet};

/// Threshold for considering a chunk as "large" (in MB) - lowered from 10MB to 4MB for better detection
const LARGE_CHUNK_THRESHOLD_MB: f64 = 4.0;

/// Threshold for considering a server as "slow" (in MB/s) - lowered from 2.0 to 1.0 for stricter detection
const SLOW_SERVER_THRESHOLD_MBPS: f64 = 1.0;

/// Minimum time penalty to consider a misallocation (in seconds)
const MIN_TIME_PENALTY_SECONDS: f64 = 5.0;

/// Threshold for considering any download as problematically long (in seconds)
const LONG_DOWNLOAD_THRESHOLD_SECONDS: f64 = 30.0;

/// Threshold for considering small file downloads as problematically slow (in seconds)
const SMALL_FILE_SLOW_THRESHOLD_SECONDS: f64 = 10.0;

pub fn analyze_chunk_allocation(sessions: &[SessionLog]) -> ChunkAllocationAnalysis {
    if sessions.is_empty() {
        return create_empty_allocation_analysis();
    }

    // Collect all chunk data with server performance
    let chunk_data = collect_chunk_data(sessions);

    // Calculate server performance metrics
    let server_speeds = calculate_server_speeds(&chunk_data);

    // Build server chunk distribution
    let server_chunk_distribution = build_server_chunk_distribution(&chunk_data);

    // Detect misallocated chunks
    let misallocated_chunks = detect_misallocated_chunks(&chunk_data, &server_speeds);

    // Calculate total impact
    let total_impact = calculate_total_impact(&misallocated_chunks, sessions);

    ChunkAllocationAnalysis {
        misallocated_chunks,
        server_chunk_distribution,
        total_impact,
    }
}

#[derive(Clone)]
struct ChunkData {
    server_id: String,
    chunk_size_mb: f64,
    download_speed_mbps: f64,
    download_time_seconds: f64,
    session_id: Option<String>,
}

fn collect_chunk_data(sessions: &[SessionLog]) -> Vec<ChunkData> {
    let mut chunk_data = Vec::new();

    for session in sessions {
        for chunk in &session.chunks {
            let chunk_size_mb = parse_chunk_size(&chunk.rng);

            for cdn_record in &chunk.cdns {
                if let (Some(server_id), Some(size), Some(time)) =
                    (&cdn_record.srv, cdn_record.size, cdn_record.time)
                {
                    // Apply multiple filters for accurate speed measurement
                    // Only include successful downloads (no error)
                    if cdn_record.err.is_none() 
                        && time >= 10  // Minimum 50ms to avoid unrealistic high speeds (reduced from 100ms)
                        && size >= 10240
                    // Minimum 10KB for accurate measurement
                    {
                        let download_speed_mbps =
                            (size as f64 / 1024.0 / 1024.0) / (time as f64 / 1000.0);
                        let download_time_seconds = time as f64 / 1000.0;

                        // Apply maximum speed filter (1000MB/s to avoid filtering high-speed downloads, increased from 500MB/s)
                        if download_speed_mbps <= 1000.0 {
                            chunk_data.push(ChunkData {
                                server_id: server_id.clone(),
                                chunk_size_mb,
                                download_speed_mbps,
                                download_time_seconds,
                                session_id: session.sid.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    chunk_data
}

pub fn parse_chunk_size(range: &str) -> f64 {
    // Parse range format like "117607337-152236120" to get size in MB
    if let Some((start_str, end_str)) = range.split_once('-') {
        if let (Ok(start), Ok(end)) = (start_str.parse::<u64>(), end_str.parse::<u64>()) {
            return (end - start + 1) as f64 / 1024.0 / 1024.0; // Convert to MB
        }
    }
    0.0 // Return 0 if parsing fails
}

fn calculate_server_speeds(chunk_data: &[ChunkData]) -> HashMap<String, f64> {
    let mut server_speeds: HashMap<String, Vec<f64>> = HashMap::new();

    for chunk in chunk_data {
        server_speeds
            .entry(chunk.server_id.clone())
            .or_insert_with(Vec::new)
            .push(chunk.download_speed_mbps);
    }

    server_speeds
        .into_iter()
        .map(|(server_id, speeds)| {
            let avg_speed = speeds.iter().sum::<f64>() / speeds.len() as f64;
            (server_id, avg_speed)
        })
        .collect()
}

fn build_server_chunk_distribution(chunk_data: &[ChunkData]) -> HashMap<String, ServerChunkStats> {
    let mut distribution: HashMap<String, Vec<&ChunkData>> = HashMap::new();

    for chunk in chunk_data {
        distribution
            .entry(chunk.server_id.clone())
            .or_insert_with(Vec::new)
            .push(chunk);
    }

    distribution
        .into_iter()
        .map(|(server_id, chunks)| {
            let total_chunks = chunks.len();
            let large_chunks = chunks
                .iter()
                .filter(|chunk| chunk.chunk_size_mb >= LARGE_CHUNK_THRESHOLD_MB)
                .count();

            let avg_chunk_size_mb =
                chunks.iter().map(|c| c.chunk_size_mb).sum::<f64>() / chunks.len() as f64;
            let avg_speed_mbps =
                chunks.iter().map(|c| c.download_speed_mbps).sum::<f64>() / chunks.len() as f64;

            let stats = ServerChunkStats {
                server_id: server_id.clone(),
                total_chunks,
                large_chunks,
                avg_chunk_size_mb,
                avg_speed_mbps,
            };

            (server_id, stats)
        })
        .collect()
}

fn detect_misallocated_chunks(
    chunk_data: &[ChunkData],
    server_speeds: &HashMap<String, f64>,
) -> Vec<MisallocatedChunk> {
    let mut misallocated = Vec::new();

    // Find the fastest server for calculating optimal time
    let max_speed = server_speeds
        .values()
        .fold(0.0f64, |max, &speed| max.max(speed));

    for chunk in chunk_data {
        let mut should_flag = false;
        let optimal_time_seconds = chunk.chunk_size_mb / max_speed;
        let time_penalty = chunk.download_time_seconds - optimal_time_seconds;

        // Check multiple misallocation conditions:

        // 1. Large chunks assigned to slow servers (existing logic with updated thresholds)
        if chunk.chunk_size_mb >= LARGE_CHUNK_THRESHOLD_MB {
            if let Some(&server_speed) = server_speeds.get(&chunk.server_id) {
                if server_speed < SLOW_SERVER_THRESHOLD_MBPS
                    && time_penalty >= MIN_TIME_PENALTY_SECONDS
                {
                    should_flag = true;
                }
            }
        }

        // 2. Any download taking longer than 30 seconds (regardless of file size)
        if chunk.download_time_seconds >= LONG_DOWNLOAD_THRESHOLD_SECONDS {
            should_flag = true;
        }

        // 3. Small files (<4MB) taking longer than 10 seconds
        if chunk.chunk_size_mb < LARGE_CHUNK_THRESHOLD_MB
            && chunk.download_time_seconds >= SMALL_FILE_SLOW_THRESHOLD_SECONDS
        {
            should_flag = true;
        }

        if should_flag {
            misallocated.push(MisallocatedChunk {
                server_id: chunk.server_id.clone(),
                chunk_size_mb: chunk.chunk_size_mb,
                download_speed_mbps: chunk.download_speed_mbps,
                actual_time_seconds: chunk.download_time_seconds,
                optimal_time_seconds,
                time_penalty_seconds: time_penalty,
                session_id: chunk.session_id.clone(),
            });
        }
    }

    // Sort by time penalty (worst first), then by server_id for consistent ordering
    misallocated.sort_by(|a, b| {
        match b.time_penalty_seconds.partial_cmp(&a.time_penalty_seconds) {
            Some(std::cmp::Ordering::Equal) => a.server_id.cmp(&b.server_id),
            Some(ordering) => ordering,
            None => std::cmp::Ordering::Equal,
        }
    });

    misallocated
}

fn calculate_total_impact(
    misallocated_chunks: &[MisallocatedChunk],
    _sessions: &[SessionLog],
) -> ChunkAllocationImpact {
    let total_misallocated_chunks = misallocated_chunks.len();
    let total_time_penalty_seconds = misallocated_chunks
        .iter()
        .map(|chunk| chunk.time_penalty_seconds)
        .sum();

    // Count affected sessions
    let affected_sessions: HashSet<_> = misallocated_chunks
        .iter()
        .filter_map(|chunk| chunk.session_id.as_ref())
        .collect();
    let affected_sessions_count = affected_sessions.len();

    let worst_misallocation = misallocated_chunks.first().cloned();

    ChunkAllocationImpact {
        total_misallocated_chunks,
        total_time_penalty_seconds,
        affected_sessions: affected_sessions_count,
        worst_misallocation,
    }
}

fn create_empty_allocation_analysis() -> ChunkAllocationAnalysis {
    ChunkAllocationAnalysis {
        misallocated_chunks: Vec::new(),
        server_chunk_distribution: HashMap::new(),
        total_impact: ChunkAllocationImpact {
            total_misallocated_chunks: 0,
            total_time_penalty_seconds: 0.0,
            affected_sessions: 0,
            worst_misallocation: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::analyze::models::{CdnRecordLog, ChunkLog};

    #[test]
    fn test_parse_chunk_size() {
        let size_mb = parse_chunk_size("117607337-152236120");
        assert!((size_mb - 33.01).abs() < 0.1); // Should be around 33MB
    }

    #[test]
    fn test_chunk_allocation_analysis() {
        let sessions = vec![create_test_session()];
        let analysis = analyze_chunk_allocation(&sessions);

        // Should have some server chunk distribution
        assert!(!analysis.server_chunk_distribution.is_empty());
    }

    fn create_test_session() -> SessionLog {
        SessionLog {
            start: 1000,
            end: 1100,
            log_type: "session_completed".to_string(),
            sid: Some("test-session".to_string()),
            rid: "test-resource".to_string(),
            ver: "1.0.0".to_string(),
            ua: Some("TestAgent/1.0".to_string()),
            ip: ("192.168.1.100".to_string(), None),
            chunks: vec![ChunkLog {
                rng: "0-20971519".to_string(), // 20MB chunk
                att: 1,
                cdns: vec![CdnRecordLog {
                    url: "https://slow-server.example.com/test".to_string(),
                    srv: Some("slow-server".to_string()),
                    wgt: Some(10),
                    ts: 1010,
                    pen: Some(false),
                    rsn: Some("flow_selected".to_string()),
                    ttfb: Some(1000),
                    time: Some(20000), // 20 seconds = 1MB/s
                    size: Some(20971520),
                    err: None,
                    mode: Some("http".to_string()),
                }],
            }],
        }
    }
}
