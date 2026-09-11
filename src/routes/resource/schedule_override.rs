use axum::{
    extract::{Extension, Query},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::json;

use crate::container::AppContext;
use crate::error::DfsResult;
use crate::modules::external::geolocation;
use crate::modules::flow::schedule_override;
use crate::modules::network::RealConnectInfo;
use crate::responses::{ApiResponse, ResponseData};

#[derive(Debug, Deserialize)]
pub struct OverrideQuery {
    pub req: String,
    #[serde(default)]
    pub sid: Option<String>,
}

#[utoipa::path(
    get,
    path = "/override",
    tag = "Resource",
    summary = "Claim a schedule override ticket",
    params(
        ("req" = String, Query, description = "Override ticket uuid"),
        ("sid" = Option<String>, Query, description = "Optional session id to bind")
    ),
    responses(
        (status = 200, description = "Override claimed"),
        (status = 400, description = "Ticket missing, expired, or invalid")
    )
)]
pub async fn claim(
    Extension(ctx): Extension<AppContext>,
    Extension(real_connect_info): Extension<RealConnectInfo>,
    headers: HeaderMap,
    Query(query): Query<OverrideQuery>,
) -> DfsResult<ApiResponse> {
    let client_ip = geolocation::extract_client_ip(&headers)
        .or_else(|| Some(real_connect_info.remote_addr.ip()));
    let sid = query.sid.filter(|s| !s.trim().is_empty());
    let config = ctx.get_config();

    let claimed = schedule_override::claim_override(
        &ctx.data_store,
        &config,
        &query.req,
        client_ip,
        sid.as_deref(),
    )
    .await?;

    Ok(ApiResponse::success(ResponseData::Json(json!({
        "target_node": claimed.target_node,
        "ttl_seconds": claimed.ttl_seconds,
        "bound_ip": claimed.bound_ip.map(|ip| ip.to_string()),
        "bound_sid": claimed.bound_sid,
        "resource_id": claimed.resource_id,
    }))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::network::RealConnectInfo;
    use crate::tests::common::TestEnvironment;
    use axum::extract::{Extension, Query};
    use axum::http::{HeaderMap, HeaderValue};

    fn connect_info() -> RealConnectInfo {
        RealConnectInfo {
            remote_addr: "198.51.100.7:443".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn claim_route_binds_request_ip() {
        let env = TestEnvironment::new().await;
        env.mock_data_store
            .seed_override_ticket("route-ticket", "test_server_2", Some(90))
            .await
            .unwrap();

        let response = claim(
            Extension(env.app_context.clone()),
            Extension(connect_info()),
            HeaderMap::new(),
            Query(OverrideQuery {
                req: "route-ticket".to_string(),
                sid: Some("route-sid".to_string()),
            }),
        )
        .await
        .unwrap();

        let ApiResponse::Success(ResponseData::Json(body)) = response else {
            panic!("expected json success, got {response:?}");
        };
        assert_eq!(body["target_node"], "test_server_2");
        assert_eq!(body["bound_sid"], "route-sid");
        assert_eq!(body["bound_ip"], "198.51.100.7");

        let hit = schedule_override::lookup_override(
            &env.data_store,
            Some("route-sid"),
            None,
            "test_resource",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(hit.target_node, "test_server_2");
    }

    #[tokio::test]
    async fn claim_route_prefers_forwarded_ip_header() {
        let env = TestEnvironment::new().await;
        env.mock_data_store
            .seed_override_ticket("hdr-ticket", "test_server_1", Some(60))
            .await
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.88"));

        let response = claim(
            Extension(env.app_context.clone()),
            Extension(connect_info()),
            headers,
            Query(OverrideQuery {
                req: "hdr-ticket".to_string(),
                sid: None,
            }),
        )
        .await
        .unwrap();

        let ApiResponse::Success(ResponseData::Json(body)) = response else {
            panic!("expected json success, got {response:?}");
        };
        assert_eq!(body["bound_ip"], "203.0.113.88");
    }
}
