use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use xxhash_rust::xxh3::xxh3_64;

pub const VERSION_FILE_MAX_BYTES: u64 = 256 * 1024;

/// Per-server observation collected during a version-file census.
#[derive(Debug, Clone)]
pub struct VersionFileObservation {
    pub server_id: String,
    pub hash: Option<String>,
    pub content: Option<Vec<u8>>,
    pub file_size: Option<u64>,
    pub observed_cert_hash: Option<String>,
}

/// Cluster view for one (resource, version-file path).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionFileView {
    pub majority_hash: Option<String>,
    #[serde(default)]
    pub groups: HashMap<String, u32>,
    #[serde(default)]
    pub server_hashes: HashMap<String, String>,
    pub responder_count: u32,
    pub split_since: Option<u64>,
    pub failed: bool,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionFileDecision {
    Unknown,
    Match,
    Mismatch,
    SplitFailed,
}

pub fn hash_content(bytes: &[u8]) -> String {
    format!("{:016x}", xxh3_64(bytes))
}

pub fn view_storage_key(resource_id: &str, path: &str) -> String {
    let path_hash = xxh3_64(path.as_bytes());
    format!("version_file_view:{resource_id}:{path_hash:x}")
}

/// Strict majority among responders: count * 2 > responder_count.
pub fn apply_observations(
    previous: Option<&VersionFileView>,
    observations: &[VersionFileObservation],
    now: u64,
    split_ttl: u32,
    strict_split_fail: bool,
) -> VersionFileView {
    let mut groups: HashMap<String, u32> = HashMap::new();
    let mut server_hashes: HashMap<String, String> = HashMap::new();

    for obs in observations {
        if let Some(hash) = &obs.hash {
            *groups.entry(hash.clone()).or_insert(0) += 1;
            server_hashes.insert(obs.server_id.clone(), hash.clone());
        }
    }

    let responder_count = server_hashes.len() as u32;

    if responder_count == 0 {
        return VersionFileView {
            majority_hash: previous.and_then(|p| p.majority_hash.clone()),
            groups: previous.map(|p| p.groups.clone()).unwrap_or_default(),
            server_hashes: HashMap::new(),
            responder_count: 0,
            split_since: previous.and_then(|p| p.split_since),
            failed: previous.map(|p| p.failed).unwrap_or(false),
            updated_at: now,
        };
    }

    let majority_hash = groups
        .iter()
        .filter(|(_, count)| **count * 2 > responder_count)
        .max_by_key(|(_, count)| *count)
        .map(|(hash, _)| hash.clone());

    if let Some(majority_hash) = majority_hash {
        return VersionFileView {
            majority_hash: Some(majority_hash),
            groups,
            server_hashes,
            responder_count,
            split_since: None,
            failed: false,
            updated_at: now,
        };
    }

    let previous_majority = previous.and_then(|p| p.majority_hash.clone());
    let split_since = previous.and_then(|p| p.split_since).unwrap_or(now);
    let failed = strict_split_fail
        || previous_majority.is_none()
        || now.saturating_sub(split_since) >= split_ttl as u64;

    VersionFileView {
        majority_hash: previous_majority,
        groups,
        server_hashes,
        responder_count,
        split_since: Some(split_since),
        failed,
        updated_at: now,
    }
}

pub fn evaluate_server(view: &VersionFileView, server_id: &str) -> VersionFileDecision {
    if view.failed {
        return VersionFileDecision::SplitFailed;
    }

    match (&view.majority_hash, view.server_hashes.get(server_id)) {
        (Some(majority), Some(hash)) if hash == majority => VersionFileDecision::Match,
        (Some(_), Some(_)) => VersionFileDecision::Mismatch,
        (None, Some(_)) => VersionFileDecision::Mismatch,
        (_, None) => VersionFileDecision::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(server: &str, hash: Option<&str>) -> VersionFileObservation {
        VersionFileObservation {
            server_id: server.to_string(),
            hash: hash.map(|h| h.to_string()),
            content: None,
            file_size: None,
            observed_cert_hash: None,
        }
    }

    fn observations(pairs: &[(&str, Option<&str>)]) -> Vec<VersionFileObservation> {
        pairs.iter().map(|(s, h)| obs(s, *h)).collect()
    }

    #[test]
    fn strict_majority_wins() {
        let view = apply_observations(
            None,
            &observations(&[
                ("a", Some("new")),
                ("b", Some("new")),
                ("c", Some("new")),
                ("d", Some("old")),
                ("e", None),
            ]),
            100,
            300,
            false,
        );
        assert_eq!(view.majority_hash.as_deref(), Some("new"));
        assert!(!view.failed);
        assert_eq!(view.responder_count, 4);
        assert_eq!(evaluate_server(&view, "a"), VersionFileDecision::Match);
        assert_eq!(evaluate_server(&view, "d"), VersionFileDecision::Mismatch);
        assert_eq!(evaluate_server(&view, "e"), VersionFileDecision::Unknown);
    }

    #[test]
    fn offline_nodes_are_not_content_votes() {
        let view = apply_observations(
            None,
            &observations(&[
                ("a", Some("x")),
                ("b", Some("x")),
                ("c", Some("x")),
                ("d", Some("x")),
                ("e", Some("x")),
                ("f", None),
                ("g", None),
                ("h", None),
            ]),
            1,
            300,
            false,
        );
        assert_eq!(view.majority_hash.as_deref(), Some("x"));
        assert!(!view.failed);
        assert_eq!(view.responder_count, 5);
    }

    #[test]
    fn even_split_has_no_majority() {
        let view = apply_observations(
            None,
            &observations(&[
                ("a", Some("old")),
                ("b", Some("old")),
                ("c", Some("new")),
                ("d", Some("new")),
            ]),
            10,
            300,
            false,
        );
        assert!(view.failed);
        assert_eq!(view.majority_hash, None);
        assert_eq!(view.split_since, Some(10));
        assert_eq!(evaluate_server(&view, "a"), VersionFileDecision::SplitFailed);
    }

    #[test]
    fn previous_majority_gets_ttl_grace() {
        let previous = VersionFileView {
            majority_hash: Some("old".to_string()),
            groups: HashMap::new(),
            server_hashes: HashMap::new(),
            responder_count: 4,
            split_since: None,
            failed: false,
            updated_at: 0,
        };
        let view = apply_observations(
            Some(&previous),
            &observations(&[
                ("a", Some("old")),
                ("b", Some("old")),
                ("c", Some("new")),
                ("d", Some("new")),
            ]),
            50,
            300,
            false,
        );
        assert!(!view.failed);
        assert_eq!(view.majority_hash.as_deref(), Some("old"));
        assert_eq!(view.split_since, Some(50));
        assert_eq!(evaluate_server(&view, "a"), VersionFileDecision::Match);
        assert_eq!(evaluate_server(&view, "c"), VersionFileDecision::Mismatch);
    }

    #[test]
    fn split_beyond_ttl_fails() {
        let previous = VersionFileView {
            majority_hash: Some("old".to_string()),
            groups: HashMap::new(),
            server_hashes: HashMap::new(),
            responder_count: 4,
            split_since: Some(10),
            failed: false,
            updated_at: 10,
        };
        let view = apply_observations(
            Some(&previous),
            &observations(&[
                ("a", Some("old")),
                ("b", Some("old")),
                ("c", Some("new")),
                ("d", Some("new")),
            ]),
            320,
            300,
            false,
        );
        assert!(view.failed);
        assert_eq!(view.majority_hash.as_deref(), Some("old"));
        assert_eq!(evaluate_server(&view, "a"), VersionFileDecision::SplitFailed);
    }

    #[test]
    fn check_command_fails_split_immediately() {
        let previous = VersionFileView {
            majority_hash: Some("old".to_string()),
            groups: HashMap::new(),
            server_hashes: HashMap::new(),
            responder_count: 4,
            split_since: None,
            failed: false,
            updated_at: 0,
        };
        let view = apply_observations(
            Some(&previous),
            &observations(&[
                ("a", Some("old")),
                ("b", Some("old")),
                ("c", Some("new")),
                ("d", Some("new")),
            ]),
            1,
            300,
            true,
        );
        assert!(view.failed);
    }

    #[test]
    fn majority_recovery_clears_split() {
        let previous = VersionFileView {
            majority_hash: Some("old".to_string()),
            groups: HashMap::new(),
            server_hashes: HashMap::new(),
            responder_count: 4,
            split_since: Some(10),
            failed: true,
            updated_at: 10,
        };
        let view = apply_observations(
            Some(&previous),
            &observations(&[
                ("a", Some("new")),
                ("b", Some("new")),
                ("c", Some("new")),
                ("d", Some("old")),
            ]),
            20,
            300,
            false,
        );
        assert!(!view.failed);
        assert_eq!(view.split_since, None);
        assert_eq!(view.majority_hash.as_deref(), Some("new"));
    }

    #[test]
    fn three_way_split_has_no_majority() {
        let view = apply_observations(
            None,
            &observations(&[
                ("a", Some("a")),
                ("b", Some("b")),
                ("c", Some("c")),
            ]),
            1,
            300,
            false,
        );
        assert!(view.failed);
        assert_eq!(view.majority_hash, None);
    }

    #[test]
    fn zero_ttl_fails_as_soon_as_split_starts() {
        let previous = VersionFileView {
            majority_hash: Some("old".to_string()),
            groups: HashMap::new(),
            server_hashes: HashMap::new(),
            responder_count: 2,
            split_since: None,
            failed: false,
            updated_at: 0,
        };
        let view = apply_observations(
            Some(&previous),
            &observations(&[("a", Some("old")), ("b", Some("new"))]),
            5,
            0,
            false,
        );
        assert!(view.failed);
    }

    #[test]
    fn no_responders_keep_previous_view() {
        let previous = VersionFileView {
            majority_hash: Some("old".to_string()),
            groups: HashMap::from([("old".to_string(), 3)]),
            server_hashes: HashMap::new(),
            responder_count: 3,
            split_since: None,
            failed: false,
            updated_at: 1,
        };
        let view = apply_observations(
            Some(&previous),
            &observations(&[("a", None), ("b", None)]),
            9,
            300,
            false,
        );
        assert_eq!(view.majority_hash.as_deref(), Some("old"));
        assert!(!view.failed);
        assert_eq!(view.responder_count, 0);
    }
}
