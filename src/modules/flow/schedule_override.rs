//! 强制调度 override：读管理员写的票，认领后按主体写绑定，调度按 key 查找。

use crate::config::AppConfig;
use crate::error::{DfsError, DfsResult};
use crate::modules::storage::data_store::DataStore;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// 管理员写入的票：节点，以及可选的资源范围。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideTicket {
    pub target_node: String,
    pub resource_id: Option<String>,
}

/// 认领后写入的绑定。匹配维度在 key 上，不在这份 JSON 里。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideBinding {
    pub target_node: String,
    pub ticket: String,
}

/// 一次认领写下的主体与票上的节点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedOverride {
    pub target_node: String,
    pub ttl_seconds: u32,
    pub bound_ip: Option<IpAddr>,
    pub bound_sid: Option<String>,
    pub resource_id: Option<String>,
}

/// 解析票 CSV：`node` 或 `node,resid`。字段 trim；多于两段或空节点则失败。
pub fn parse_ticket_csv(raw: &str) -> DfsResult<OverrideTicket> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(DfsError::invalid_input("req", "override ticket is empty"));
    }
    let mut parts = raw.split(',');
    let target_node = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DfsError::invalid_input("req", "override ticket has no node"))?
        .to_string();
    let resource_id = match parts.next() {
        None => None,
        Some(resid) => {
            let resid = resid.trim();
            if resid.is_empty() {
                None
            } else {
                Some(resid.to_string())
            }
        }
    };
    if parts.next().is_some() {
        return Err(DfsError::invalid_input(
            "req",
            "override ticket has more than two fields",
        ));
    }
    Ok(OverrideTicket {
        target_node,
        resource_id,
    })
}

pub(crate) fn bind_suffix(kind: &str, subject: &str, resource_id: Option<&str>) -> String {
    match resource_id {
        Some(resid) if !resid.is_empty() => format!("{kind}:{subject}:{resid}"),
        _ => format!("{kind}:{subject}"),
    }
}

fn normalize_ticket_id(ticket_id: &str) -> DfsResult<&str> {
    let ticket_id = ticket_id.trim();
    if ticket_id.is_empty() {
        return Err(DfsError::invalid_input("req", "req is required"));
    }
    if ticket_id.starts_with("bind:") {
        return Err(DfsError::invalid_input(
            "req",
            "req must not start with bind:",
        ));
    }
    Ok(ticket_id)
}

fn normalize_sid(sid: Option<&str>) -> Option<&str> {
    sid.map(str::trim).filter(|s| !s.is_empty())
}

/// 读票、校验节点在配置中、按票的 resid 决定绑定 key 后缀，把剩余 TTL 抄到绑定上。
pub async fn claim_override(
    store: &DataStore,
    config: &AppConfig,
    ticket_id: &str,
    client_ip: Option<IpAddr>,
    sid: Option<&str>,
) -> DfsResult<ClaimedOverride> {
    let ticket_id = normalize_ticket_id(ticket_id)?;
    let sid = normalize_sid(sid);

    if client_ip.is_none() && sid.is_none() {
        return Err(DfsError::invalid_input(
            "req",
            "override claim needs a client IP or sid",
        ));
    }

    let (csv, remaining_ttl) = match store.get_override_ticket(ticket_id).await? {
        None => {
            return Err(DfsError::invalid_input(
                "req",
                "override ticket not found or expired",
            ));
        }
        Some((_, None)) => {
            return Err(DfsError::invalid_input("req", "override ticket has no TTL"));
        }
        Some((_, Some(0))) => {
            return Err(DfsError::invalid_input(
                "req",
                "override ticket not found or expired",
            ));
        }
        Some((csv, Some(ttl))) => (csv, ttl),
    };

    let ticket = parse_ticket_csv(&csv)?;
    if !config.servers.contains_key(&ticket.target_node) {
        return Err(DfsError::invalid_input(
            "req",
            format!(
                "override target_node '{}' is not configured",
                ticket.target_node
            ),
        ));
    }

    let binding = OverrideBinding {
        target_node: ticket.target_node.clone(),
        ticket: ticket_id.to_string(),
    };
    let json = serde_json::to_string(&binding)?;
    let resid = ticket.resource_id.as_deref();

    if let Some(ip) = client_ip {
        store
            .set_override_binding(
                &bind_suffix("ip", &ip.to_string(), resid),
                &json,
                remaining_ttl,
            )
            .await?;
    }
    if let Some(sid) = sid {
        store
            .set_override_binding(&bind_suffix("sid", sid, resid), &json, remaining_ttl)
            .await?;
    }

    Ok(ClaimedOverride {
        target_node: ticket.target_node,
        ttl_seconds: remaining_ttl,
        bound_ip: client_ip,
        bound_sid: sid.map(str::to_string),
        resource_id: ticket.resource_id,
    })
}

/// 按 sid+resid → sid → ip+resid → ip 查找绑定。key 不在即未命中。
pub async fn lookup_override(
    store: &DataStore,
    session_id: Option<&str>,
    client_ip: Option<IpAddr>,
    resource_id: &str,
) -> DfsResult<Option<OverrideBinding>> {
    let resid = if resource_id.is_empty() {
        None
    } else {
        Some(resource_id)
    };

    let mut suffixes = Vec::new();
    if let Some(sid) = normalize_sid(session_id) {
        if let Some(resid) = resid {
            suffixes.push(bind_suffix("sid", sid, Some(resid)));
        }
        suffixes.push(bind_suffix("sid", sid, None));
    }
    if let Some(ip) = client_ip {
        let ip = ip.to_string();
        if let Some(resid) = resid {
            suffixes.push(bind_suffix("ip", &ip, Some(resid)));
        }
        suffixes.push(bind_suffix("ip", &ip, None));
    }

    for suffix in suffixes {
        if let Some(json) = store.get_override_binding(&suffix).await? {
            let binding: OverrideBinding = serde_json::from_str(&json)
                .map_err(|e| DfsError::internal_error(format!("invalid override binding: {e}")))?;
            return Ok(Some(binding));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::common::TestEnvironment;
    use std::net::IpAddr;

    fn test_ip() -> IpAddr {
        "203.0.113.10".parse().unwrap()
    }

    fn other_ip() -> IpAddr {
        "203.0.113.20".parse().unwrap()
    }

    #[test]
    fn parse_ticket_csv_accepts_node_and_optional_resid() {
        assert_eq!(
            parse_ticket_csv("node_a").unwrap(),
            OverrideTicket {
                target_node: "node_a".to_string(),
                resource_id: None,
            }
        );
        assert_eq!(
            parse_ticket_csv(" node_a , resid_1 ").unwrap(),
            OverrideTicket {
                target_node: "node_a".to_string(),
                resource_id: Some("resid_1".to_string()),
            }
        );
        assert_eq!(
            parse_ticket_csv("node_a,").unwrap(),
            OverrideTicket {
                target_node: "node_a".to_string(),
                resource_id: None,
            }
        );
        assert!(parse_ticket_csv("").is_err());
        assert!(parse_ticket_csv("a,b,c").is_err());
    }

    #[tokio::test]
    async fn claim_writes_ip_and_optional_sid_bindings() {
        let env = TestEnvironment::new().await;
        env.mock_data_store
            .seed_override_ticket("ticket-1", "test_server_2", Some(300))
            .await
            .unwrap();

        let claimed = claim_override(
            &env.data_store,
            &env.shared_config.load(),
            "ticket-1",
            Some(test_ip()),
            Some("sid-a"),
        )
        .await
        .unwrap();
        assert_eq!(claimed.target_node, "test_server_2");
        assert_eq!(claimed.bound_sid.as_deref(), Some("sid-a"));
        assert_eq!(claimed.ttl_seconds, 300);

        let by_sid = lookup_override(&env.data_store, Some("sid-a"), None, "test_resource")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_sid.target_node, "test_server_2");
        assert_eq!(by_sid.ticket, "ticket-1");

        let by_ip = lookup_override(&env.data_store, None, Some(test_ip()), "test_resource")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_ip.target_node, "test_server_2");
    }

    #[tokio::test]
    async fn resid_scoped_ticket_writes_suffixed_keys_only() {
        let env = TestEnvironment::new().await;
        env.mock_data_store
            .seed_override_ticket("ticket-res", "test_server_2,test_resource", Some(120))
            .await
            .unwrap();

        claim_override(
            &env.data_store,
            &env.shared_config.load(),
            "ticket-res",
            Some(test_ip()),
            Some("sid-res"),
        )
        .await
        .unwrap();

        assert!(
            lookup_override(&env.data_store, Some("sid-res"), None, "test_resource")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            lookup_override(&env.data_store, Some("sid-res"), None, "other_app")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn second_subject_claim_does_not_drop_the_first() {
        let env = TestEnvironment::new().await;
        env.mock_data_store
            .seed_override_ticket("ticket-shared", "test_server_1", Some(300))
            .await
            .unwrap();

        claim_override(
            &env.data_store,
            &env.shared_config.load(),
            "ticket-shared",
            Some(test_ip()),
            Some("sid-a"),
        )
        .await
        .unwrap();
        claim_override(
            &env.data_store,
            &env.shared_config.load(),
            "ticket-shared",
            Some(other_ip()),
            Some("sid-b"),
        )
        .await
        .unwrap();

        assert_eq!(
            lookup_override(&env.data_store, Some("sid-a"), None, "test_resource")
                .await
                .unwrap()
                .unwrap()
                .target_node,
            "test_server_1"
        );
        assert_eq!(
            lookup_override(&env.data_store, Some("sid-b"), None, "test_resource")
                .await
                .unwrap()
                .unwrap()
                .target_node,
            "test_server_1"
        );
        assert_eq!(
            lookup_override(&env.data_store, None, Some(test_ip()), "test_resource")
                .await
                .unwrap()
                .unwrap()
                .target_node,
            "test_server_1"
        );
        assert_eq!(
            lookup_override(&env.data_store, None, Some(other_ip()), "test_resource")
                .await
                .unwrap()
                .unwrap()
                .target_node,
            "test_server_1"
        );
    }

    #[tokio::test]
    async fn sid_lookup_wins_over_conflicting_ip() {
        let env = TestEnvironment::new().await;
        env.mock_data_store
            .seed_override_ticket("t-ip", "test_server_1", Some(300))
            .await
            .unwrap();
        env.mock_data_store
            .seed_override_ticket("t-sid", "test_server_2", Some(300))
            .await
            .unwrap();

        claim_override(
            &env.data_store,
            &env.shared_config.load(),
            "t-ip",
            Some(test_ip()),
            None,
        )
        .await
        .unwrap();
        claim_override(
            &env.data_store,
            &env.shared_config.load(),
            "t-sid",
            Some(test_ip()),
            Some("sid-win"),
        )
        .await
        .unwrap();

        let hit = lookup_override(
            &env.data_store,
            Some("sid-win"),
            Some(test_ip()),
            "test_resource",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(hit.target_node, "test_server_2");
    }

    #[tokio::test]
    async fn distinct_sids_keep_distinct_nodes() {
        let env = TestEnvironment::new().await;
        env.mock_data_store
            .seed_override_ticket("t-a", "test_server_1", Some(300))
            .await
            .unwrap();
        env.mock_data_store
            .seed_override_ticket("t-b", "test_server_2", Some(300))
            .await
            .unwrap();

        claim_override(
            &env.data_store,
            &env.shared_config.load(),
            "t-a",
            Some(test_ip()),
            Some("sid-a"),
        )
        .await
        .unwrap();
        claim_override(
            &env.data_store,
            &env.shared_config.load(),
            "t-b",
            Some(other_ip()),
            Some("sid-b"),
        )
        .await
        .unwrap();

        assert_eq!(
            lookup_override(&env.data_store, Some("sid-a"), None, "test_resource")
                .await
                .unwrap()
                .unwrap()
                .target_node,
            "test_server_1"
        );
        assert_eq!(
            lookup_override(&env.data_store, Some("sid-b"), None, "test_resource")
                .await
                .unwrap()
                .unwrap()
                .target_node,
            "test_server_2"
        );
    }

    #[tokio::test]
    async fn claim_rejects_missing_expired_untimed_and_unknown_node() {
        let env = TestEnvironment::new().await;
        let config = env.shared_config.load();

        let missing = claim_override(&env.data_store, &config, "no-such", Some(test_ip()), None)
            .await
            .unwrap_err();
        assert!(format!("{missing}").contains("not found"));

        env.mock_data_store
            .seed_expired_override_ticket("old", "test_server_1")
            .await;
        let expired = claim_override(&env.data_store, &config, "old", Some(test_ip()), None)
            .await
            .unwrap_err();
        assert!(format!("{expired}").contains("not found"));

        env.mock_data_store
            .seed_override_ticket("forever", "test_server_1", None)
            .await
            .unwrap();
        let no_ttl = claim_override(&env.data_store, &config, "forever", Some(test_ip()), None)
            .await
            .unwrap_err();
        assert!(format!("{no_ttl}").contains("no TTL"));

        env.mock_data_store
            .seed_override_ticket("ghost", "not_a_server", Some(60))
            .await
            .unwrap();
        let unknown = claim_override(&env.data_store, &config, "ghost", Some(test_ip()), None)
            .await
            .unwrap_err();
        assert!(format!("{unknown}").contains("not configured"));
    }
}
