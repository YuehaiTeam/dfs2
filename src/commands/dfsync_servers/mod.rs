use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

use crate::config::{AppConfig, ServerConfig};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DfsyncServerEntry {
    #[serde(rename = "type")]
    pub server_type: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check_path: Option<String>,
}

pub fn generate_dfsync_servers(config: &AppConfig, profile_filter: Option<&str>) -> Result<String> {
    let mut out: BTreeMap<String, DfsyncServerEntry> = BTreeMap::new();

    let mut server_ids: Vec<&String> = config.servers.keys().collect();
    server_ids.sort();

    for server_id in server_ids {
        let server = config
            .servers
            .get(server_id)
            .ok_or_else(|| anyhow::anyhow!("Server '{}' not found while iterating", server_id))?;

        if server
            .generation_skip
            .iter()
            .any(|v| v.eq_ignore_ascii_case("dfsync"))
        {
            continue;
        }

        if let Some(filter) = profile_filter {
            if server.profile.as_deref() != Some(filter) {
                continue;
            }
        }

        match server.r#type.as_str() {
            "s3" => {
                validate_http_url(server_id, &server.url)?;
                out.insert(
                    server_id.clone(),
                    DfsyncServerEntry {
                        server_type: "s3".to_string(),
                        url: server.url.clone(),
                        profile: server.profile.clone(),
                        health_check_path: server.health_check_path.clone(),
                    },
                );
            }
            "dfs_node" => {
                let selected_url = select_dfs_node_sync_url(server);
                let Some(selected_url) = selected_url else {
                    continue;
                };

                let normalized = normalize_dfsnode_sync_url(server_id, selected_url)?;
                out.insert(
                    server_id.clone(),
                    DfsyncServerEntry {
                        server_type: "webdav_tus".to_string(),
                        url: normalized,
                        profile: server.profile.clone(),
                        health_check_path: server.health_check_path.clone(),
                    },
                );
            }
            _ => {}
        }
    }

    serde_yaml::to_string(&out).context("Failed to serialize dfsync servers YAML")
}

fn select_dfs_node_sync_url(server: &ServerConfig) -> Option<&str> {
    let sync_url = server
        .sync_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());

    if server.ssh_only || server.h3_only {
        return sync_url;
    }

    sync_url.or_else(|| {
        let raw = server.url.trim();
        if raw.is_empty() { None } else { Some(raw) }
    })
}

fn validate_http_url(server_id: &str, raw_url: &str) -> Result<()> {
    let parsed = Url::parse(raw_url).with_context(|| {
        format!(
            "Server '{}' has invalid URL: {}",
            server_id,
            redact_url_userinfo(raw_url)
        )
    })?;
    validate_url_scheme(server_id, &parsed, raw_url)?;
    Ok(())
}

fn normalize_dfsnode_sync_url(server_id: &str, raw_url: &str) -> Result<String> {
    let mut parsed = Url::parse(raw_url).with_context(|| {
        format!(
            "Server '{}' has invalid dfs_node sync URL: {}",
            server_id,
            redact_url_userinfo(raw_url)
        )
    })?;

    validate_url_scheme(server_id, &parsed, raw_url)?;

    let query_pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| k != "expire_seconds")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    parsed.set_query(None);
    if !query_pairs.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in query_pairs {
            serializer.append_pair(&k, &v);
        }
        let query = serializer.finish();
        parsed.set_query(Some(&query));
    }

    if parsed.path().is_empty() {
        parsed.set_path("/");
    }

    Ok(parsed.to_string())
}

fn validate_url_scheme(server_id: &str, parsed: &Url, raw_url: &str) -> Result<()> {
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        _ => anyhow::bail!(
            "Server '{}' has unsupported URL scheme in {}",
            server_id,
            redact_url_userinfo(raw_url)
        ),
    }
}

fn redact_url_userinfo(raw_url: &str) -> String {
    let Ok(mut parsed) = Url::parse(raw_url) else {
        return raw_url.to_string();
    };

    if parsed.username().is_empty() && parsed.password().is_none() {
        return raw_url.to_string();
    }

    if parsed.set_username("***").is_err() {
        return raw_url.to_string();
    }
    let _ = parsed.set_password(None);
    parsed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse_app_config(yaml: &str) -> AppConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    fn parse_generated(yaml: &str) -> HashMap<String, DfsyncServerEntry> {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn test_generate_s3_passthrough() {
        let config = parse_app_config(
            r#"
servers:
  minio1:
    id: minio1
    type: s3
    url: "http://ak:sk@127.0.0.1:9000/prefix?bucket=test&region=us-east-1"
resources: {}
plugins: {}
"#,
        );

        let generated = generate_dfsync_servers(&config, None).unwrap();
        let map = parse_generated(&generated);

        assert_eq!(map.len(), 1);
        assert_eq!(map["minio1"].server_type, "s3");
        assert_eq!(
            map["minio1"].url,
            "http://ak:sk@127.0.0.1:9000/prefix?bucket=test&region=us-east-1"
        );
    }

    #[test]
    fn test_generate_dfs_node_from_url() {
        let config = parse_app_config(
            r#"
servers:
  node1:
    id: node1
    type: dfs_node
    url: "http://u:p@127.0.0.1:8080/dav?expire_seconds=3600"
resources: {}
plugins: {}
"#,
        );

        let generated = generate_dfsync_servers(&config, None).unwrap();
        let map = parse_generated(&generated);

        assert_eq!(map["node1"].server_type, "webdav_tus");
        assert_eq!(map["node1"].url, "http://u:p@127.0.0.1:8080/dav");
    }

    #[test]
    fn test_generate_dfs_node_prefers_sync_url() {
        let config = parse_app_config(
            r#"
servers:
  node1:
    id: node1
    type: dfs_node
    url: "http://u:p@127.0.0.1:8080/original"
    sync_url: "http://su:sp@127.0.0.1:8080/dav"
resources: {}
plugins: {}
"#,
        );

        let generated = generate_dfsync_servers(&config, None).unwrap();
        let map = parse_generated(&generated);
        assert_eq!(map["node1"].url, "http://su:sp@127.0.0.1:8080/dav");
    }

    #[test]
    fn test_skip_dfs_node_ssh_only_without_sync_url() {
        let config = parse_app_config(
            r#"
servers:
  node1:
    id: node1
    type: dfs_node
    url: "http://u:p@127.0.0.1:8080/"
    ssh_only: true
resources: {}
plugins: {}
"#,
        );

        let generated = generate_dfsync_servers(&config, None).unwrap();
        let map = parse_generated(&generated);
        assert!(!map.contains_key("node1"));
    }

    #[test]
    fn test_generation_skip_and_profile_filter() {
        let config = parse_app_config(
            r#"
servers:
  node_a:
    id: node_a
    type: dfs_node
    profile: alpha
    url: "http://u:p@127.0.0.1:8080/"
    generation_skip: ["dfsync"]
  node_b:
    id: node_b
    type: dfs_node
    profile: beta
    url: "http://u:p@127.0.0.1:8081/"
resources: {}
plugins: {}
"#,
        );

        let generated = generate_dfsync_servers(&config, Some("beta")).unwrap();
        let map = parse_generated(&generated);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("node_b"));
    }

    #[test]
    fn test_redacted_error_for_invalid_scheme() {
        let config = parse_app_config(
            r#"
servers:
  bad:
    id: bad
    type: s3
    url: "ftp://ak:sk@example.com/b"
resources: {}
plugins: {}
"#,
        );

        let err = generate_dfsync_servers(&config, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ftp://***@example.com/b"));
        assert!(!err.contains("ak:sk@"));
    }
}
