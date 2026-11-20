use super::oauth::{self, OAuthState};
use super::settings::{EnabledToolGroups, GrafanaSettings, McpSettings, ToolGroup};
use crate::config::CertHashPolicy;
use crate::container::AppContext;
use crate::models::CdnRecord;
use crate::modules::analytics::session_log_rotate::{
    archive_object_keys_union, archive_probe_hours, bucket_stem, rotate_hours_from_env,
};
use crate::modules::external::geolocation;
use crate::modules::flow::schedule_override::{bind_suffix, parse_ticket_csv};
use crate::modules::network::capabilities::{ClientCapabilities, rewrite_url};
use crate::modules::storage::data_store::BANDWIDTH_MINUTE_RING_SIZE;
use crate::modules::version_file::{VersionFileDecision, VersionFileView, evaluate_server};
use crate::services::resource_service::{
    version_base_path_for_resource, version_file_path_for_resource, version_path_for_resource,
};
use crate::services::session_service::sid_created_at;
use axum::{
    Router,
    extract::State,
    http::Request,
    middleware::{self, Next},
    response::Response,
};
use chrono::Local;
use futures::StreamExt;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, ListResourcesResult, ReadResourceRequestParams,
        ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, ServerCapabilities,
        ServerInfo,
    },
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const METRICS_CATALOG: &str = include_str!("metrics_catalog.md");
const DEFAULT_PLAYBOOK: &str = include_str!("playbook.md");
const MAX_GRAFANA_POINTS: i64 = 5000;
const EXISTENCE_PROBE_CONCURRENCY: usize = 16;
/// `sign_url` 默认 Range 大小。单段 Range 的 end 是 u32，所以一次最多签 4GiB。
const SIGN_URL_DEFAULT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct McpState {
    pub settings: Arc<McpSettings>,
    pub ctx: AppContext,
}

#[derive(Clone)]
pub struct DfsMcp {
    state: Arc<McpState>,
    /// `#[tool_handler]` reads this field; rustc does not see the macro use.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct LogObjectsArgs {
    from: i64,
    to: i64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SidArgs {
    sid: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ServerHealthArgs {
    server_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CacheEntryArgs {
    resid: String,
    version: String,
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BandwidthArgs {
    kind: Option<String>,
    id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BandwidthRecentArgs {
    server_id: Option<String>,
    minutes: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GeoIpArgs {
    ip: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ResolvePathsArgs {
    resid: String,
    version: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct VersionCensusArgs {
    resid: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SignUrlArgs {
    server_id: String,
    resid: String,
    version: Option<String>,
    sub_path: Option<String>,
    max_bytes: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ResidArgs {
    resid: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct OptionalResidArgs {
    resid: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TicketArgs {
    uuid: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct OverrideArgs {
    kind: String,
    id: String,
    resource_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GrafanaArgs {
    promql: String,
    from: i64,
    to: i64,
    step: Option<i64>,
}

fn tool_group(name: &str) -> Option<ToolGroup> {
    match name {
        "log_objects" | "log_objects_for_sid" => Some(ToolGroup::Log),
        "config" | "config_mirror" => Some(ToolGroup::Config),
        "grafana_query" => Some(ToolGroup::Metrics),
        "server_health" | "session" | "cache_entry" | "bandwidth_today" | "override_binding"
        | "geoip" | "resolve_paths" | "metrics_snapshot" | "runtime_info" | "version_census"
        | "bandwidth_recent" | "cache_entries" | "resource_versions" | "override_ticket" => {
            Some(ToolGroup::Runtime)
        }
        "sign_url" => Some(ToolGroup::Sign),
        _ => None,
    }
}

/// `metrics_snapshot` 只有本进程的 registry；配了指标系统时不注册，免得被当成全池数据读。
fn tool_enabled(settings: &McpSettings, name: &str) -> bool {
    if name == "grafana_query" && settings.grafana.is_none() {
        return false;
    }
    if name == "metrics_snapshot" && settings.grafana.is_some() {
        return false;
    }
    match tool_group(name) {
        Some(group) => settings.tool_groups.allows(group),
        None => matches!(settings.tool_groups, EnabledToolGroups::All),
    }
}

impl DfsMcp {
    fn new(state: Arc<McpState>) -> Self {
        let mut tool_router = Self::tool_router();
        let names: Vec<String> = tool_router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        for name in names {
            if !tool_enabled(&state.settings, &name) {
                tool_router.disable_route(name);
            }
        }
        Self { state, tool_router }
    }

    #[cfg(test)]
    fn listed_tool_names(&self) -> Vec<String> {
        self.tool_router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    fn json_ok(value: impl serde::Serialize) -> Result<CallToolResult, McpError> {
        let text = serde_json::to_string(&value)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    fn tool_err(message: impl Into<String>) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::error(vec![ContentBlock::text(
            message.into(),
        )]))
    }
}

#[tool_router]
impl DfsMcp {
    #[tool(
        description = "Compute session-log object keys in [from,to] (unix seconds) for daily and hourly stems, probe which objects exist, and return GET presigned URLs only for those that do. The current bucket may be truncated and lag one sync interval."
    )]
    async fn log_objects(
        &self,
        Parameters(args): Parameters<LogObjectsArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.presign_window(args.from, args.to).await
    }

    #[tool(
        description = "Resolve a server-generated sid to its session-log search window (creation time through session timeout plus cleanup interval, both in runtime_info) and return presigned GET URLs for the archive objects that exist. Errors if the sid carries no creation time; use log_objects with an explicit window then."
    )]
    async fn log_objects_for_sid(
        &self,
        Parameters(args): Parameters<SidArgs>,
    ) -> Result<CallToolResult, McpError> {
        let Some(created) = sid_created_at(&args.sid) else {
            return Self::tool_err(
                "this sid carries no creation time; use log_objects with an explicit window",
            );
        };
        let timeout_h: u64 = std::env::var("SESSION_TIMEOUT_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);
        let cleanup_min: u64 = std::env::var("SESSION_CLEANUP_INTERVAL_MIN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let to =
            created.saturating_add(timeout_h.saturating_mul(3600) + cleanup_min.saturating_mul(60));
        self.presign_window(created as i64, to as i64).await
    }

    #[tool(
        description = "Return the loaded config.yaml after credential redaction. Comments and key order match the file. After the file, a `---` separator is followed by loaded_at and any flow server refs removed at load."
    )]
    async fn config(&self) -> Result<CallToolResult, McpError> {
        let guard = self.state.ctx.shared_config.load();
        if guard.config_yaml.is_empty() {
            return Self::tool_err("no loaded config.yaml");
        }
        let yaml = match crate::redact::redact_yaml(&guard.config_yaml) {
            Ok(text) => text,
            Err(e) => return Self::tool_err(e.to_string()),
        };
        let loaded_at = self
            .state
            .ctx
            .shared_config
            .loaded_at()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut note = format!("loaded_at: {loaded_at}");
        if !guard.pruned_flow_server_refs.is_empty() {
            note.push_str("\npruned_flow_server_refs:");
            for (resource_id, server_id) in &guard.pruned_flow_server_refs {
                note.push_str(&format!("\n- {resource_id} {server_id}"));
            }
        }
        let mut text = yaml;
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("---\n");
        text.push_str(&note);
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(
        description = "Return the config-mirror clone URL (may include a deploy token) as stored in MCP_CONFIG_MIRROR_URL."
    )]
    async fn config_mirror(&self) -> Result<CallToolResult, McpError> {
        match &self.state.settings.config_mirror_url {
            Some(url) => Self::json_ok(json!({ "url": url })),
            None => Self::tool_err("MCP_CONFIG_MIRROR_URL is not set"),
        }
    }

    #[tool(
        description = "Point-read cached connectivity from the periodic ping of each server's health_check_path. This is node reachability, not whether a given resource file can be served. Omit server_id to list every server that has a health_check_path. Servers without a path appear in unchecked, not as healthy. Each checked entry includes age_seconds; a missing entry means the census ping has not published (or the TTL expired), not that the node is healthy."
    )]
    async fn server_health(
        &self,
        Parameters(args): Parameters<ServerHealthArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard = self.state.ctx.shared_config.load();
        let mut checked = Vec::new();
        let mut unchecked: Vec<String> = guard
            .servers
            .iter()
            .filter(|(_, s)| s.health_check_path.is_none())
            .map(|(id, _)| id.clone())
            .collect();
        unchecked.sort();
        let targets: Vec<(String, &crate::config::ServerConfig)> = match args.server_id {
            Some(id) => guard
                .servers
                .get(&id)
                .map(|s| vec![(id, s)])
                .unwrap_or_default(),
            None => guard
                .servers
                .iter()
                .map(|(id, s)| (id.clone(), s))
                .collect(),
        };
        for (server_id, server) in targets {
            let Some(path) = server.health_check_path.as_deref() else {
                continue;
            };
            match self
                .state
                .ctx
                .data_store
                .get_health_info(&server_id, path)
                .await
            {
                Ok(info) => {
                    let now = chrono::Utc::now().timestamp() as u64;
                    let age_seconds = info.as_ref().map(|h| now.saturating_sub(h.last_check));
                    checked.push(json!({
                        "server_id": server_id,
                        "path": path,
                        "health": info,
                        "age_seconds": age_seconds,
                    }));
                }
                Err(e) => checked.push(json!({
                    "server_id": server_id,
                    "path": path,
                    "error": e,
                })),
            }
        }
        Self::json_ok(json!({ "checked": checked, "unchecked": unchecked }))
    }

    #[tool(
        description = "Return the session still in storage plus banned/demoted schedule penalties. Missing means expired or never created; recover from log_objects_for_sid. Signed query strings are stripped from recorded URLs."
    )]
    async fn session(
        &self,
        Parameters(args): Parameters<SidArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut session = match self.state.ctx.data_store.get_session(&args.sid).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                return Self::tool_err(
                    "session not in storage (expired or never created); use log_objects_for_sid",
                );
            }
            Err(e) => return Self::tool_err(e),
        };
        session.cdn_records = strip_cdn_record_queries(session.cdn_records);
        let penalties = self
            .state
            .ctx
            .session_service
            .get_schedule_penalties(&args.sid, None)
            .await
            .unwrap_or_default();
        let stats = self
            .state
            .ctx
            .session_service
            .get_session_stats(&args.sid)
            .await
            .ok()
            .flatten();
        let (download_counts, cdn_records) = match stats {
            Some(s) => (s.download_counts, strip_cdn_record_queries(s.cdn_records)),
            None => (Default::default(), Default::default()),
        };
        Self::json_ok(json!({
            "session": session,
            "banned": penalties.banned,
            "demoted": penalties.demoted,
            "download_counts": download_counts,
            "cdn_records": cdn_records,
        }))
    }

    #[tool(
        description = "Return cache metadata for resid/version/path, including provenance src. Does not return object bytes."
    )]
    async fn cache_entry(
        &self,
        Parameters(args): Parameters<CacheEntryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let keys =
            self.state
                .ctx
                .data_store
                .generate_cache_keys(&args.resid, &args.version, &args.path);
        match self
            .state
            .ctx
            .data_store
            .get_cache_metadata(&keys.metadata_key)
            .await
        {
            Ok(Some(meta)) => Self::json_ok(meta),
            Ok(None) => Self::tool_err("cache entry not found"),
            Err(e) => Self::tool_err(e),
        }
    }

    #[tool(
        description = "Today's bandwidth counters, incremented when a URL is issued using the requested size — not delivered bytes. Cached downloads are counted under id cache. With kind=resource|server and id, point-read that counter. Omit both to fan out all resources, all servers, and the global total."
    )]
    async fn bandwidth_today(
        &self,
        Parameters(args): Parameters<BandwidthArgs>,
    ) -> Result<CallToolResult, McpError> {
        match (args.kind.as_deref(), args.id.as_deref()) {
            (None, None) => self.bandwidth_today_all().await,
            (Some(kind), Some(id)) => self.bandwidth_today_one(kind, id).await,
            _ => Self::tool_err("kind and id must both be set or both omitted"),
        }
    }

    #[tool(
        description = "Read the schedule-override binding for kind=ip|sid and id. Optional resource_id uses the scoped key first."
    )]
    async fn override_binding(
        &self,
        Parameters(args): Parameters<OverrideArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.kind != "ip" && args.kind != "sid" {
            return Self::tool_err("kind must be ip or sid");
        }
        let resid = args.resource_id.as_deref();
        let suffixes = [
            bind_suffix(&args.kind, &args.id, resid),
            bind_suffix(&args.kind, &args.id, None),
        ];
        for suffix in suffixes {
            match self
                .state
                .ctx
                .data_store
                .get_override_binding(&suffix)
                .await
            {
                Ok(Some(raw)) => {
                    return Self::json_ok(json!({ "suffix": suffix, "binding": raw }));
                }
                Ok(None) => {}
                Err(e) => return Self::tool_err(e),
            }
        }
        Self::tool_err("override binding not found")
    }

    #[tool(
        description = "Look up an IP the same way flow geoip/cnip conditions do: location string, IP version, public vs private. Also returns the same fields for internal.egress_ip, or configured=false when that is unset."
    )]
    async fn geoip(
        &self,
        Parameters(args): Parameters<GeoIpArgs>,
    ) -> Result<CallToolResult, McpError> {
        let Ok(ip) = args.ip.parse::<IpAddr>() else {
            return Self::tool_err(format!("invalid IP address: {}", args.ip));
        };
        let guard = self.state.ctx.shared_config.load();
        let egress = match guard.internal.egress_ip() {
            Some(egress_ip) => json!({
                "configured": true,
                "ip": egress_ip.to_string(),
                "lookup": classify_ip(egress_ip),
            }),
            None => json!({ "configured": false }),
        };
        Self::json_ok(json!({
            "ip": args.ip,
            "lookup": classify_ip(ip),
            "egress": egress,
        }))
    }

    #[tool(
        description = "Expand a resource's versions/default templates to the fetch path on each server, plus each version_files path. Omit version to use the resource's effective version."
    )]
    async fn resolve_paths(
        &self,
        Parameters(args): Parameters<ResolvePathsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard = self.state.ctx.shared_config.load();
        let Some(resource) = guard.resources.get(&args.resid) else {
            return Self::tool_err(format!("resource '{}' not found", args.resid));
        };
        let version = match args.version {
            Some(v) => v,
            None => match self
                .state
                .ctx
                .resource_service
                .get_effective_version(&args.resid)
                .await
            {
                Ok(v) => v,
                Err(e) => return Self::tool_err(e.to_string()),
            },
        };
        let mut servers = serde_json::Map::new();
        let mut server_ids: Vec<String> = guard.servers.keys().cloned().collect();
        server_ids.sort();
        for server_id in server_ids {
            let path = version_path_for_resource(resource, &version, Some(&server_id), None)
                .or_else(|| version_base_path_for_resource(resource, &version, Some(&server_id)));
            servers.insert(server_id, json!(path));
        }
        let version_files: Vec<String> = resource
            .version_files
            .iter()
            .filter_map(|vf| version_file_path_for_resource(resource, &version, None, vf))
            .collect();
        Self::json_ok(json!({
            "resid": args.resid,
            "version": version,
            "servers": servers,
            "version_files": version_files,
        }))
    }

    #[tool(
        description = "This process's Prometheus registry as text. Only this instance; not registered when grafana_query is configured."
    )]
    async fn metrics_snapshot(&self) -> Result<CallToolResult, McpError> {
        let encoder = prometheus::TextEncoder::new();
        let families = self.state.ctx.metrics.registry.gather();
        let text = encoder
            .encode_to_string(&families)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(
        description = "Non-secret runtime settings: package version, process start, config load time, data-store kind, rotate hours, session timeout, cleanup interval."
    )]
    async fn runtime_info(&self) -> Result<CallToolResult, McpError> {
        Self::json_ok(runtime_info_value(
            &self.state.ctx.shared_config.loaded_at(),
        ))
    }

    #[tool(
        description = "Read stored version-file census views for resources that have version_files. Omit resid for all such resources. Background census writes the views; this tool does not ping or refresh."
    )]
    async fn version_census(
        &self,
        Parameters(args): Parameters<VersionCensusArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.version_census_read(args.resid.as_deref()).await
    }

    #[tool(
        description = "Read the last N minutes of server bandwidth from the minute ring. Counted when a URL is issued, not delivered bytes. Omit server_id to fan out every configured server. minutes is clamped to the ring length."
    )]
    async fn bandwidth_recent(
        &self,
        Parameters(args): Parameters<BandwidthRecentArgs>,
    ) -> Result<CallToolResult, McpError> {
        let minutes = args.minutes.min(BANDWIDTH_MINUTE_RING_SIZE);
        let guard = self.state.ctx.shared_config.load();
        let mut server_ids: Vec<String> = match args.server_id {
            Some(id) => vec![id],
            None => guard.servers.keys().cloned().collect(),
        };
        drop(guard);
        server_ids.sort();
        let read_at = unix_secs(SystemTime::now());
        let mut servers = Vec::new();
        for server_id in server_ids {
            match self
                .state
                .ctx
                .bandwidth_cache_service
                .get_server_minutes_bandwidth(&server_id, minutes)
                .await
            {
                Ok(bytes) => servers.push(json!({
                    "server_id": server_id,
                    "bytes": bytes,
                })),
                Err(e) => servers.push(json!({
                    "server_id": server_id,
                    "error": e,
                })),
            }
        }
        Self::json_ok(json!({
            "minutes": minutes,
            "minutes_requested": args.minutes,
            "ring_size": BANDWIDTH_MINUTE_RING_SIZE,
            "read_at": read_at,
            "servers": servers,
        }))
    }

    #[tool(
        description = "List cache metadata for a resource's enumerable version_files paths. Empty when cache is disabled or version_files is empty. Does not return object bytes or cache_subpaths wildcard entries."
    )]
    async fn cache_entries(
        &self,
        Parameters(args): Parameters<ResidArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard = self.state.ctx.shared_config.load();
        let Some(resource) = guard.resources.get(&args.resid) else {
            return Self::tool_err(format!("resource '{}' not found", args.resid));
        };
        if !resource.cache_enabled || resource.version_files.is_empty() {
            return Self::json_ok(json!({ "resid": args.resid, "entries": [] }));
        }
        drop(guard);
        let version = match self
            .state
            .ctx
            .resource_service
            .get_effective_version(&args.resid)
            .await
        {
            Ok(v) => v,
            Err(e) => return Self::tool_err(e.to_string()),
        };
        let paths = self
            .state
            .ctx
            .version_file_service
            .resolved_version_file_paths(&args.resid, &version)
            .await;
        let mut entries = Vec::new();
        for path in paths {
            let keys = self
                .state
                .ctx
                .data_store
                .generate_cache_keys(&args.resid, &version, &path);
            match self
                .state
                .ctx
                .data_store
                .get_cache_metadata(&keys.metadata_key)
                .await
            {
                Ok(Some(meta)) => entries.push(json!({
                    "path": path,
                    "cached_at": meta.cached_at,
                    "max_age": meta.max_age,
                    "content_length": meta.content_length,
                    "etag": meta.etag,
                    "src": meta.src,
                })),
                Ok(None) => {}
                Err(e) => return Self::tool_err(e),
            }
        }
        Self::json_ok(json!({
            "resid": args.resid,
            "version": version,
            "entries": entries,
        }))
    }

    #[tool(
        description = "Per-resource latest, effective version, cached version info, and version_provider plugin name plus cache_ttl. Omit resid to fan out every resource."
    )]
    async fn resource_versions(
        &self,
        Parameters(args): Parameters<OptionalResidArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard = self.state.ctx.shared_config.load();
        let mut ids: Vec<String> = match args.resid {
            Some(id) => {
                if !guard.resources.contains_key(&id) {
                    return Self::tool_err(format!("resource '{id}' not found"));
                }
                vec![id]
            }
            None => guard.resources.keys().cloned().collect(),
        };
        drop(guard);
        ids.sort();
        let mut out = Vec::new();
        for resid in ids {
            out.push(self.resource_version_one(&resid).await?);
        }
        Self::json_ok(out)
    }

    #[tool(
        description = "Read a schedule-override ticket by uuid: target node, optional resid, remaining TTL. Missing or expired is not found."
    )]
    async fn override_ticket(
        &self,
        Parameters(args): Parameters<TicketArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self
            .state
            .ctx
            .data_store
            .get_override_ticket(&args.uuid)
            .await
        {
            Ok(None) => Self::json_ok(json!({ "found": false })),
            Ok(Some((_, None))) | Ok(Some((_, Some(0)))) => {
                Self::json_ok(json!({ "found": false }))
            }
            Ok(Some((csv, Some(ttl)))) => match parse_ticket_csv(&csv) {
                Ok(ticket) => Self::json_ok(json!({
                    "found": true,
                    "target_node": ticket.target_node,
                    "resource_id": ticket.resource_id,
                    "ttl_seconds": ttl,
                })),
                Err(e) => Self::tool_err(e.to_string()),
            },
            Err(e) => Self::tool_err(e),
        }
    }

    #[tool(
        description = "Sign a short-lived GET for one configured resource path on one server. Path comes from the same templates as resolve_paths; arbitrary paths are rejected. Prefix resources require sub_path. max_bytes defaults to 32MiB; known file_size shrinks the Range. s3 / dfs_node / dfs_webtransport / dfs_sftp encode that Range in the signature, direct and git_lfs cannot. Probe from the caller to the node, not from users. Does not write a session or today's bandwidth counters. Bytes transferred count against the node's quota."
    )]
    async fn sign_url(
        &self,
        Parameters(args): Parameters<SignUrlArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.sign_url_inner(args).await
    }

    #[tool(
        description = "Forward PromQL to the configured metrics datasource. Response is Grafana /api/ds/query frames, not the Prometheus HTTP API. In object-store traffic series, received is downlink (user download) and the node id is the server label; a missing series means that node is not reporting, not zero traffic. Span and step are clamped to a per-series point cap."
    )]
    async fn grafana_query(
        &self,
        Parameters(args): Parameters<GrafanaArgs>,
    ) -> Result<CallToolResult, McpError> {
        let Some(grafana) = &self.state.settings.grafana else {
            return Self::tool_err("grafana_query is not configured");
        };
        query_grafana(grafana, args).await
    }
}

impl DfsMcp {
    async fn bandwidth_today_one(&self, kind: &str, id: &str) -> Result<CallToolResult, McpError> {
        let bytes = match kind {
            "resource" => {
                self.state
                    .ctx
                    .data_store
                    .get_resource_daily_bandwidth(id)
                    .await
            }
            "server" => {
                self.state
                    .ctx
                    .data_store
                    .get_server_daily_bandwidth(id)
                    .await
            }
            _ => return Self::tool_err("kind must be resource or server"),
        };
        match bytes {
            Ok(n) => Self::json_ok(json!({ "kind": kind, "id": id, "bytes": n })),
            Err(e) => Self::tool_err(e),
        }
    }

    async fn bandwidth_today_all(&self) -> Result<CallToolResult, McpError> {
        let guard = self.state.ctx.shared_config.load();
        let mut resource_ids: Vec<String> = guard.resources.keys().cloned().collect();
        let mut server_ids: Vec<String> = guard.servers.keys().cloned().collect();
        drop(guard);
        resource_ids.sort();
        server_ids.sort();
        let mut resources = Vec::new();
        for id in resource_ids {
            match self
                .state
                .ctx
                .data_store
                .get_resource_daily_bandwidth(&id)
                .await
            {
                Ok(bytes) => resources.push(json!({ "id": id, "bytes": bytes })),
                Err(e) => resources.push(json!({ "id": id, "error": e })),
            }
        }
        let mut servers = Vec::new();
        for id in server_ids {
            match self
                .state
                .ctx
                .data_store
                .get_server_daily_bandwidth(&id)
                .await
            {
                Ok(bytes) => servers.push(json!({ "id": id, "bytes": bytes })),
                Err(e) => servers.push(json!({ "id": id, "error": e })),
            }
        }
        let global = match self.state.ctx.data_store.get_global_daily_bandwidth().await {
            Ok(n) => n,
            Err(e) => return Self::tool_err(e),
        };
        Self::json_ok(json!({
            "resources": resources,
            "servers": servers,
            "global": { "bytes": global },
        }))
    }

    async fn version_census_read(&self, resid: Option<&str>) -> Result<CallToolResult, McpError> {
        let guard = self.state.ctx.shared_config.load();
        let mut resource_ids: Vec<String> = match resid {
            Some(id) => {
                if !guard.resources.contains_key(id) {
                    return Self::tool_err(format!("resource '{id}' not found"));
                }
                vec![id.to_string()]
            }
            None => guard
                .resources
                .iter()
                .filter(|(_, r)| !r.version_files.is_empty())
                .map(|(id, _)| id.clone())
                .collect(),
        };
        resource_ids.sort();
        let mut views = Vec::new();
        for resource_id in resource_ids {
            let Some(resource) = guard.resources.get(&resource_id) else {
                continue;
            };
            if resource.version_files.is_empty() {
                continue;
            }
            let version = self
                .state
                .ctx
                .resource_service
                .get_effective_version(&resource_id)
                .await
                .unwrap_or_else(|_| resource.latest.clone());
            let paths = self
                .state
                .ctx
                .version_file_service
                .resolved_version_file_paths(&resource_id, &version)
                .await;
            let mut server_ids: Vec<String> = guard.servers.keys().cloned().collect();
            server_ids.sort();
            for path in paths {
                let view = self
                    .state
                    .ctx
                    .version_file_service
                    .get_view(&resource_id, &path)
                    .await;
                views.push(census_view_json(
                    &resource_id,
                    &path,
                    view.as_ref(),
                    &server_ids,
                ));
            }
        }
        Self::json_ok(json!({ "views": views }))
    }

    async fn sign_url_inner(&self, args: SignUrlArgs) -> Result<CallToolResult, McpError> {
        let requested = args.max_bytes.unwrap_or(SIGN_URL_DEFAULT_BYTES);
        if requested == 0 {
            return Self::tool_err("max_bytes must be positive");
        }
        let max_bytes = requested;
        let ttl = self.state.settings.presign_ttl_seconds;
        let guard = self.state.ctx.shared_config.load();
        let Some(server) = guard.servers.get(&args.server_id).cloned() else {
            return Self::tool_err(format!("server '{}' not found", args.server_id));
        };
        let Some(server_impl) = guard.get_server(&args.server_id).cloned() else {
            return Self::tool_err(format!("server '{}' has no implementation", args.server_id));
        };
        let Some(resource) = guard.resources.get(&args.resid).cloned() else {
            return Self::tool_err(format!("resource '{}' not found", args.resid));
        };
        drop(guard);
        if resource.resource_type == "prefix" && args.sub_path.is_none() {
            return Self::tool_err("prefix resource requires sub_path");
        }
        let version = match args.version {
            Some(v) => v,
            None => match self
                .state
                .ctx
                .resource_service
                .get_effective_version(&args.resid)
                .await
            {
                Ok(v) => v,
                Err(e) => return Self::tool_err(e.to_string()),
            },
        };
        let Some(raw_path) = version_path_for_resource(
            &resource,
            &version,
            Some(&args.server_id),
            args.sub_path.as_deref(),
        )
        .or_else(|| version_base_path_for_resource(&resource, &version, Some(&args.server_id))) else {
            return Self::tool_err("no path for this resource on that server");
        };
        let path = match crate::modules::extent_map::parse_map_path(&raw_path) {
            Some(Ok(spec)) => spec.manifest_path,
            Some(Err(e)) => return Self::tool_err(format!("invalid map path: {e}")),
            None => raw_path,
        };
        let health_path = server.health_check_path.clone();
        let file_size = match health_path.as_deref() {
            Some(hp) => self
                .state
                .ctx
                .data_store
                .get_health_info(&args.server_id, hp)
                .await
                .ok()
                .flatten()
                .and_then(|h| h.file_size),
            None => None,
        };
        let cap = match file_size {
            Some(0) => return Self::tool_err("object size is 0"),
            Some(n) => n.min(max_bytes),
            None => max_bytes,
        };
        if cap > u64::from(u32::MAX) + 1 {
            return Self::tool_err("max_bytes exceeds a single Range (end must fit in 32 bits)");
        }
        let end = (cap - 1) as u32;
        let range = format!("0-{end}");
        let capped = range_is_signed(&server.r#type);
        let mut url = match server_impl
            .url_expiring(
                &path,
                Some(vec![(0, end)]),
                None,
                Some(&self.state.ctx.data_store),
                ttl,
            )
            .await
        {
            Ok(u) => u,
            Err(e) => return Self::tool_err(e.to_string()),
        };
        if server.ssh_only {
            let caps = ClientCapabilities {
                h3: true,
                wrtc: true,
                wt: true,
                ssh: true,
                sftp: true,
            };
            match rewrite_url(&url, &server, None, &caps) {
                Ok(rewritten) => url = rewritten,
                Err(e) => return Self::tool_err(e.to_string()),
            }
        }
        let expires_at = unix_secs(SystemTime::now()).saturating_add(u64::from(ttl));
        let mut headers = serde_json::Map::new();
        headers.insert("Range".into(), json!(format!("bytes={range}")));
        Self::json_ok(json!({
            "url": url,
            "headers": headers,
            "range": range,
            "capped": capped,
            "expires_at": expires_at,
            "expires_in": ttl,
            "path": path,
            "server_id": args.server_id,
            "resid": args.resid,
            "version": version,
            "file_size": file_size,
            "max_bytes": max_bytes,
            "transport": transport_json(&server),
            "notes": [
                "Measures from the caller to the node, not from users.",
                "Does not write a session or today's bandwidth counters.",
                "Bytes transferred count against the node's quota.",
            ],
        }))
    }

    async fn resource_version_one(&self, resid: &str) -> Result<serde_json::Value, McpError> {
        let guard = self.state.ctx.shared_config.load();
        let Some(resource) = guard.resources.get(resid) else {
            return Err(McpError::invalid_params(
                format!("resource '{resid}' not found"),
                None,
            ));
        };
        let latest = resource.latest.clone();
        let provider = resource.version_provider.as_ref().map(|p| {
            json!({
                "plugin_name": p.plugin_name,
                "cache_ttl": p.cache_ttl,
            })
        });
        drop(guard);
        let effective = self
            .state
            .ctx
            .resource_service
            .get_effective_version(resid)
            .await
            .ok();
        let cached = self
            .state
            .ctx
            .resource_service
            .version_cache
            .get_cached_version_info(resid)
            .await;
        let (cached_version, cached_at) = match cached {
            Some(info) => (Some(info.version), Some(unix_secs(info.cached_at))),
            None => (None, None),
        };
        Ok(json!({
            "resid": resid,
            "latest": latest,
            "effective_version": effective,
            "cached_version": cached_version,
            "cached_at": cached_at,
            "version_provider": provider,
        }))
    }

    async fn presign_window(&self, from: i64, to: i64) -> Result<CallToolResult, McpError> {
        let Some(signer) = &self.state.settings.log_signer else {
            return Self::tool_err("no archive S3 URL configured");
        };
        let rotate_hours = rotate_hours_from_env();
        let probed_hours = archive_probe_hours();
        let keys =
            archive_object_keys_union(from, to, &probed_hours, &self.state.settings.log_prefixes);
        let now_stems: Vec<String> = probed_hours
            .iter()
            .map(|h| bucket_stem(Local::now(), *h))
            .collect();
        let ttl = self.state.settings.presign_ttl_seconds;
        let probed = keys.len();
        let outcomes: Vec<Result<(String, bool), String>> = futures::stream::iter(keys)
            .map(|key| {
                let signer = signer.clone();
                async move {
                    match signer.object_exists(&key).await {
                        Ok(exists) => Ok((key, exists)),
                        Err(e) => Err(e.to_string()),
                    }
                }
            })
            .buffer_unordered(EXISTENCE_PROBE_CONCURRENCY)
            .collect()
            .await;
        let mut existing = Vec::new();
        let mut missing = 0usize;
        for outcome in outcomes {
            match outcome {
                Ok((key, true)) => existing.push(key),
                Ok((_, false)) => {
                    missing += 1;
                }
                Err(e) => return Self::tool_err(e),
            }
        }
        existing.sort();
        let mut objects = Vec::with_capacity(existing.len());
        for key in existing {
            let url = match signer.generate_presigned_get_url_for_expires(&key, ttl) {
                Ok(u) => u,
                Err(e) => return Self::tool_err(e.to_string()),
            };
            let current = now_stems.iter().any(|stem| key.contains(stem));
            objects.push(json!({
                "key": key,
                "url": url,
                "current": current,
            }));
        }
        Self::json_ok(json!({
            "objects": objects,
            "tz_offset_seconds": Local::now().offset().local_minus_utc(),
            "rotate_hours": rotate_hours,
            "rotate_hours_probed": probed_hours,
            "probed": probed,
            "missing": missing,
            "current_may_be_partial": true,
        }))
    }
}

fn process_started_at() -> SystemTime {
    static START: OnceLock<SystemTime> = OnceLock::new();
    *START.get_or_init(SystemTime::now)
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn runtime_info_value(loaded_at: &SystemTime) -> serde_json::Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "started_at": unix_secs(process_started_at()),
        "config_loaded_at": unix_secs(*loaded_at),
        "data_store": std::env::var("DATA_STORE_TYPE").unwrap_or_else(|_| "file".into()),
        "rotate_hours": rotate_hours_from_env(),
        "session_timeout_hours": env_u64("SESSION_TIMEOUT_HOURS", 2),
        "session_cleanup_interval_min": env_u64("SESSION_CLEANUP_INTERVAL_MIN", 5),
    })
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_broadcast()
                && !v.is_unspecified()
                && !v.is_documentation()
        }
        IpAddr::V6(v) => !v.is_loopback() && !v.is_unspecified() && !v.is_multicast(),
    }
}

fn range_is_signed(server_type: &str) -> bool {
    matches!(
        server_type,
        "s3" | "dfs_node" | "dfs_webtransport" | "dfs_sftp"
    )
}

fn transport_json(server: &crate::config::ServerConfig) -> serde_json::Value {
    let cert = if server.h3_only || server.r#type == "dfs_webtransport" {
        match server.cert_hash_policy() {
            Ok(CertHashPolicy::ValidCert) => json!("valid"),
            Ok(CertHashPolicy::Trust) => json!("trust"),
            Ok(CertHashPolicy::PinnedHex(_)) => json!(server.cert_hash),
            Err(_) => json!("valid"),
        }
    } else {
        json!(null)
    };
    json!({
        "type": server.r#type,
        "h3_only": server.h3_only,
        "ssh_only": server.ssh_only,
        "cert": cert,
    })
}

fn strip_query_and_fragment(url: &str) -> String {
    match url.find(['?', '#']) {
        Some(i) => url[..i].to_string(),
        None => url.to_string(),
    }
}

fn strip_cdn_record_queries(
    records: HashMap<String, Vec<CdnRecord>>,
) -> HashMap<String, Vec<CdnRecord>> {
    records
        .into_iter()
        .map(|(chunk, items)| {
            (
                chunk,
                items
                    .into_iter()
                    .map(|mut rec| {
                        rec.url = strip_query_and_fragment(&rec.url);
                        rec
                    })
                    .collect(),
            )
        })
        .collect()
}

fn classify_ip(ip: IpAddr) -> serde_json::Value {
    json!({
        "geo": geolocation::get_ip_location_data(ip),
        "ip_version": if ip.is_ipv6() { 6 } else { 4 },
        "is_public": is_public_ip(ip),
        "is_cn": !geolocation::is_global_ip(ip),
    })
}

fn decision_label(decision: VersionFileDecision) -> &'static str {
    match decision {
        VersionFileDecision::Match => "Match",
        VersionFileDecision::Mismatch => "Mismatch",
        VersionFileDecision::Unknown => "Unknown",
        VersionFileDecision::SplitFailed => "SplitFailed",
    }
}

fn census_view_json(
    resource_id: &str,
    path: &str,
    view: Option<&VersionFileView>,
    server_ids: &[String],
) -> serde_json::Value {
    let decisions: serde_json::Map<String, serde_json::Value> = server_ids
        .iter()
        .map(|id| {
            let label = match view {
                Some(v) => decision_label(evaluate_server(v, id)),
                None => "Unknown",
            };
            (id.clone(), json!(label))
        })
        .collect();
    match view {
        Some(v) => json!({
            "resid": resource_id,
            "path": path,
            "majority_hash": v.majority_hash,
            "groups": v.groups,
            "server_hashes": v.server_hashes,
            "responder_count": v.responder_count,
            "split_since": v.split_since,
            "failed": v.failed,
            "updated_at": v.updated_at,
            "decisions": decisions,
        }),
        None => json!({
            "resid": resource_id,
            "path": path,
            "majority_hash": null,
            "groups": {},
            "server_hashes": {},
            "responder_count": 0,
            "split_since": null,
            "failed": false,
            "updated_at": null,
            "decisions": decisions,
        }),
    }
}

async fn query_grafana(
    grafana: &GrafanaSettings,
    args: GrafanaArgs,
) -> Result<CallToolResult, McpError> {
    let span = (args.to - args.from).abs().max(1);
    let min_step = (span / MAX_GRAFANA_POINTS).max(1);
    let step = args.step.unwrap_or(min_step).max(min_step);
    let endpoint = format!("{}/api/ds/query", grafana.url.trim_end_matches('/'));
    let body = json!({
        "from": format!("{}", args.from.saturating_mul(1000)),
        "to": format!("{}", args.to.saturating_mul(1000)),
        "queries": [{
            "refId": "A",
            "datasource": { "uid": grafana.datasource_uid },
            "expr": args.promql,
            "intervalMs": step.saturating_mul(1000),
            "maxDataPoints": MAX_GRAFANA_POINTS,
        }]
    });
    let response = grafana
        .client
        .post(endpoint)
        .bearer_auth(&grafana.token)
        .json(&body)
        .send()
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    if !status.is_success() {
        return DfsMcp::tool_err(format!("grafana {status}: {text}"));
    }
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

#[tool_handler]
impl ServerHandler for DfsMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_instructions(
            "Read-only DFS2 troubleshooting: session-log presigns, redacted config, runtime point lookups, optional metrics query, signed probe URLs.",
        )
    }

    fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, McpError>> + Send {
        std::future::ready(Ok(ListResourcesResult {
            resources: vec![
                Resource::new("dfs2://metrics-catalog", "metrics-catalog")
                    .with_mime_type("text/markdown")
                    .with_description(
                        "Which metric direction is downlink, where node id lives, and which series are partial.",
                    ),
                Resource::new("dfs2://playbook", "playbook")
                    .with_mime_type("text/markdown")
                    .with_description("Troubleshooting playbook."),
            ],
            ..Default::default()
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, McpError>> + Send {
        let playbook = read_playbook(self.state.settings.playbook_path.as_deref());
        let uri = request.uri;
        std::future::ready(match uri.as_str() {
            "dfs2://metrics-catalog" => Ok(ReadResourceResult::new(vec![
                ResourceContents::text(METRICS_CATALOG, uri).with_mime_type("text/markdown"),
            ])
            .into()),
            "dfs2://playbook" => Ok(ReadResourceResult::new(vec![
                ResourceContents::text(playbook, uri).with_mime_type("text/markdown"),
            ])
            .into()),
            _ => Err(McpError::resource_not_found(
                "resource_not_found",
                Some(json!({ "uri": uri })),
            )),
        })
    }
}

fn read_playbook(path: Option<&str>) -> String {
    match path {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|_| DEFAULT_PLAYBOOK.to_string()),
        None => DEFAULT_PLAYBOOK.to_string(),
    }
}

pub fn router(settings: Arc<McpSettings>, ctx: AppContext) -> Router {
    let oauth_state = OAuthState::new(settings.clone(), ctx.data_store.clone());
    let state = Arc::new(McpState {
        settings: settings.clone(),
        ctx,
    });
    let service = rmcp::transport::StreamableHttpService::new(
        {
            let state = state.clone();
            move || Ok(DfsMcp::new(state.clone()))
        },
        Arc::new(
            rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default(),
        ),
        rmcp::transport::StreamableHttpServerConfig::default()
            .disable_allowed_hosts()
            .with_legacy_session_mode(false)
            .with_json_response(true),
    );
    let router = Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(state, auth_middleware));
    match oauth_state {
        Some(oauth_state) => router.merge(oauth::prefixed_router(oauth_state)),
        None => router,
    }
}

/// 静态 `MCP_TOKEN` 先比对；不中且设了 `MCP_PUBLIC_URL` 时，Bearer 值再按 OAuth access token 查存储。
async fn auth_middleware(
    State(state): State<Arc<McpState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let settings = &state.settings;
    let token = extract_token(request.headers(), request.uri());
    if token.is_some_and(|t| settings.token_matches(&t)) {
        return next.run(request).await;
    }
    if settings.public_url.is_some()
        && let Some(bearer) = bearer_token(request.headers())
        && oauth::access_token_valid(settings, &state.ctx.data_store, &bearer).await
    {
        return next.run(request).await;
    }
    tracing::debug!("mcp auth rejected");
    oauth::unauthorized(settings)
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    oauth::authorization_param(headers, "Bearer").map(str::to_string)
}

fn extract_token(headers: &axum::http::HeaderMap, uri: &axum::http::Uri) -> Option<String> {
    if let Some(bearer) = bearer_token(headers) {
        return Some(bearer);
    }
    if let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(key.trim().to_string());
    }
    let query = uri.query()?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if parts.next() == Some("token") {
            let value = parts.next().unwrap_or("");
            return Some(
                urlencoding::decode(value)
                    .unwrap_or(std::borrow::Cow::Borrowed(value))
                    .into_owned(),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Session, SessionKind};
    use crate::modules::analytics::session_log_rotate::archive_object_keys;
    use crate::modules::mcp::settings::tests::{ENV_LOCK, clear_mcp_env};
    use crate::modules::server::s3::S3Signer;
    use crate::modules::storage::data_store::CacheMetadata;
    use crate::tests::common::{TestEnvironment, create_default_test_config};
    use axum::body::Body;
    use axum::http::header::AUTHORIZATION;
    use axum::http::{Request, StatusCode};
    use chrono::TimeZone;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    fn test_settings(
        tokens: Vec<String>,
        grafana: Option<GrafanaSettings>,
        log_signer: Option<S3Signer>,
        log_prefixes: Vec<String>,
    ) -> Arc<McpSettings> {
        Arc::new(McpSettings {
            tokens,
            prefix: "mcpqa".into(),
            log_signer,
            log_prefixes,
            presign_ttl_seconds: 900,
            grafana,
            config_mirror_url: None,
            playbook_path: None,
            tool_groups: EnabledToolGroups::All,
            public_url: None,
        })
    }

    async fn mcp_with(
        tokens: Vec<String>,
        grafana: Option<GrafanaSettings>,
        log_signer: Option<S3Signer>,
        log_prefixes: Vec<String>,
    ) -> (DfsMcp, TestEnvironment) {
        let mut config = create_default_test_config();
        if let Some(server) = config.servers.get_mut("test_server_1") {
            server.id = "test_server_1".into();
            server.health_check_path = Some("/test/file.bin".into());
        }
        let env = TestEnvironment::with_config(config).await;
        let mcp = DfsMcp::new(Arc::new(McpState {
            settings: test_settings(tokens, grafana, log_signer, log_prefixes),
            ctx: env.app_context.clone(),
        }));
        (mcp, env)
    }

    #[test]
    fn extract_token_three_entries() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer abc".parse().unwrap());
        let uri: axum::http::Uri = "/x".parse().unwrap();
        assert_eq!(extract_token(&headers, &uri).as_deref(), Some("abc"));
        for scheme in ["bearer", "BEARER", "bEaReR"] {
            headers.insert(AUTHORIZATION, format!("{scheme} abc").parse().unwrap());
            assert_eq!(extract_token(&headers, &uri).as_deref(), Some("abc"));
        }

        headers.clear();
        headers.insert("x-api-key", "def".parse().unwrap());
        assert_eq!(extract_token(&headers, &uri).as_deref(), Some("def"));

        headers.clear();
        let uri: axum::http::Uri = "/x?token=ghi%2Fj".parse().unwrap();
        assert_eq!(extract_token(&headers, &uri).as_deref(), Some("ghi/j"));
    }

    #[test]
    fn presign_uses_configured_ttl() {
        let signer =
            S3Signer::from_url("s3://AKID:secret@s3.example.com/bucket?region=us-east-1").unwrap();
        let url = signer
            .generate_presigned_get_url_for_expires("sessions.2026-09-11.log.zst", 900)
            .unwrap();
        assert!(url.contains("X-Amz-Expires=900"), "{url}");
        assert!(url.contains("X-Amz-Signature="), "{url}");
    }

    #[test]
    fn mcp_sources_are_not_in_openapi() {
        for src in [
            include_str!("handler.rs"),
            include_str!("settings.rs"),
            include_str!("mod.rs"),
            include_str!("oauth.rs"),
        ] {
            let openapi_attr = format!("{}{}", "utoipa", "::");
            let swagger_crate = format!("{}{}", "utoipa", "_swagger");
            assert!(
                !src.contains(&openapi_attr) && !src.contains(&swagger_crate),
                "MCP routes must stay out of generated API docs"
            );
        }
    }

    #[tokio::test]
    async fn auth_three_entries_dual_tokens_and_401() {
        let env = TestEnvironment::new().await;
        let settings = test_settings(vec!["alpha".into(), "beta".into()], None, None, vec![]);
        let app = router(settings, env.app_context);
        let send = |req: Request<Body>| {
            let app = app.clone();
            async move { app.oneshot(req).await.unwrap() }
        };

        let unauthorized = send(Request::builder().uri("/mcp").body(Body::empty()).unwrap()).await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let wrong = send(
            Request::builder()
                .uri("/mcp")
                .header(AUTHORIZATION, "Bearer nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        for req in [
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(AUTHORIZATION, "Bearer alpha")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("x-api-key", "beta")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            Request::builder()
                .method("POST")
                .uri("/mcp?token=alpha")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        ] {
            let response = send(req).await;
            assert_ne!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "accepted token should pass the auth gate"
            );
        }
    }

    #[tokio::test]
    async fn query_token_is_absent_from_tracing() {
        let env = TestEnvironment::new().await;
        let settings = test_settings(vec!["supersecrettoken".into()], None, None, vec![]);
        let app = router(settings, env.app_context);
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        #[derive(Clone)]
        struct Writer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Writer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer({
                let buf = buf.clone();
                move || Writer(buf.clone())
            })
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp?token=supersecrettoken")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let logged = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            !logged.contains("supersecrettoken"),
            "query token leaked into tracing: {logged}"
        );
    }

    #[tokio::test]
    async fn grafana_tool_absent_when_unset() {
        let (mcp, _) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let names = mcp.listed_tool_names();
        assert!(!names.iter().any(|n| n == "grafana_query"), "{names:?}");
        assert!(names.iter().any(|n| n == "metrics_snapshot"), "{names:?}");
        assert!(names.iter().any(|n| n == "config"), "{names:?}");
        assert!(names.iter().any(|n| n == "sign_url"), "{names:?}");
    }

    #[tokio::test]
    async fn grafana_tool_present_when_configured() {
        let grafana = GrafanaSettings {
            url: "http://metrics.example".into(),
            token: "viewer".into(),
            datasource_uid: "prom".into(),
            client: reqwest::Client::new(),
        };
        let (mcp, _) = mcp_with(vec!["t".into()], Some(grafana), None, vec![]).await;
        let names = mcp.listed_tool_names();
        assert!(names.iter().any(|n| n == "grafana_query"), "{names:?}");
        assert!(!names.iter().any(|n| n == "metrics_snapshot"), "{names:?}");
        assert!(names.iter().any(|n| n == "sign_url"), "{names:?}");
    }

    fn test_grafana() -> GrafanaSettings {
        GrafanaSettings {
            url: "http://metrics.example".into(),
            token: "viewer".into(),
            datasource_uid: "prom".into(),
            client: reqwest::Client::new(),
        }
    }

    async fn mcp_with_groups(
        tool_groups: EnabledToolGroups,
        grafana: Option<GrafanaSettings>,
    ) -> DfsMcp {
        let mut settings = (*test_settings(vec!["t".into()], grafana, None, vec![])).clone();
        settings.tool_groups = tool_groups;
        let env = TestEnvironment::with_config(create_default_test_config()).await;
        DfsMcp::new(Arc::new(McpState {
            settings: Arc::new(settings),
            ctx: env.app_context.clone(),
        }))
    }

    #[tokio::test]
    async fn every_listed_tool_has_a_group() {
        let mcp = mcp_with_groups(EnabledToolGroups::All, Some(test_grafana())).await;
        let names = mcp.listed_tool_names();
        assert!(names.iter().any(|n| n == "grafana_query"), "{names:?}");
        for name in &names {
            assert!(
                tool_group(name).is_some(),
                "tool {name} has no group; listed={names:?}"
            );
        }
    }

    #[tokio::test]
    async fn tool_groups_allowlist_lists_only_those_groups() {
        let mcp = mcp_with_groups(
            EnabledToolGroups::Only(HashSet::from([ToolGroup::Runtime])),
            Some(test_grafana()),
        )
        .await;
        let names = mcp.listed_tool_names();
        assert!(names.iter().any(|n| n == "session"), "{names:?}");
        assert!(!names.iter().any(|n| n == "metrics_snapshot"), "{names:?}");
        assert!(!names.iter().any(|n| n == "config"), "{names:?}");
        assert!(!names.iter().any(|n| n == "log_objects"), "{names:?}");
        assert!(!names.iter().any(|n| n == "grafana_query"), "{names:?}");
        assert!(!names.iter().any(|n| n == "sign_url"), "{names:?}");
        assert!(
            names
                .iter()
                .all(|n| tool_group(n) == Some(ToolGroup::Runtime)),
            "{names:?}"
        );
    }

    #[tokio::test]
    async fn tool_groups_metrics_still_requires_grafana() {
        let mcp = mcp_with_groups(
            EnabledToolGroups::Only(HashSet::from([ToolGroup::Metrics])),
            None,
        )
        .await;
        let names = mcp.listed_tool_names();
        assert!(!names.iter().any(|n| n == "grafana_query"), "{names:?}");
        assert!(names.is_empty(), "{names:?}");
    }

    #[tokio::test]
    async fn runtime_tools_do_not_scan() {
        let (mcp, env) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let session = Session {
            resource_id: "test_resource".into(),
            version: "1.0.0".into(),
            chunks: vec![],
            sub_path: None,
            cdn_records: Default::default(),
            extras: serde_json::json!({}),
            created_at: 1,
            kind: SessionKind::Chunk,
            expires_at: None,
        };
        env.data_store
            .store_session("sid-runtime", &session)
            .await
            .unwrap();
        let keys = env
            .data_store
            .generate_cache_keys("test_resource", "1.0.0", "/test/file.bin");
        env.data_store
            .set_cache_entry(
                &keys.metadata_key,
                &keys.content_key,
                &CacheMetadata {
                    cached_at: chrono::Utc::now().timestamp() as u64,
                    max_age: 300,
                    content_length: 1,
                    content_type: Some("application/octet-stream".into()),
                    etag: "etag".into(),
                    src: Some("test_server_1".into()),
                },
                b"x",
            )
            .await
            .unwrap();
        env.data_store
            .set_override_binding(
                "ip:1.2.3.4",
                r#"{"target_node":"test_server_1","ticket":"u"}"#,
                60,
            )
            .await
            .unwrap();

        let _ = mcp
            .session(Parameters(SidArgs {
                sid: "sid-runtime".into(),
            }))
            .await
            .unwrap();
        let _ = mcp
            .cache_entry(Parameters(CacheEntryArgs {
                resid: "test_resource".into(),
                version: "1.0.0".into(),
                path: "/test/file.bin".into(),
            }))
            .await
            .unwrap();
        let _ = mcp
            .bandwidth_today(Parameters(BandwidthArgs {
                kind: Some("resource".into()),
                id: Some("test_resource".into()),
            }))
            .await
            .unwrap();
        let _ = mcp
            .override_binding(Parameters(OverrideArgs {
                kind: "ip".into(),
                id: "1.2.3.4".into(),
                resource_id: None,
            }))
            .await
            .unwrap();
        let _ = mcp
            .server_health(Parameters(ServerHealthArgs {
                server_id: Some("test_server_1".into()),
            }))
            .await
            .unwrap();
        let _ = mcp
            .geoip(Parameters(GeoIpArgs {
                ip: "8.8.8.8".into(),
            }))
            .await
            .unwrap();
        let _ = mcp
            .resolve_paths(Parameters(ResolvePathsArgs {
                resid: "test_resource".into(),
                version: None,
            }))
            .await
            .unwrap();
        let _ = mcp.metrics_snapshot().await.unwrap();
        let _ = mcp.runtime_info().await.unwrap();
        let _ = mcp
            .version_census(Parameters(VersionCensusArgs { resid: None }))
            .await
            .unwrap();
        let _ = mcp
            .bandwidth_recent(Parameters(BandwidthRecentArgs {
                server_id: None,
                minutes: 5,
            }))
            .await
            .unwrap();
        let _ = mcp
            .bandwidth_today(Parameters(BandwidthArgs {
                kind: None,
                id: None,
            }))
            .await
            .unwrap();
        let _ = mcp
            .cache_entries(Parameters(ResidArgs {
                resid: "test_resource".into(),
            }))
            .await
            .unwrap();
        let _ = mcp
            .resource_versions(Parameters(OptionalResidArgs { resid: None }))
            .await
            .unwrap();
        let _ = mcp
            .override_ticket(Parameters(TicketArgs {
                uuid: "missing".into(),
            }))
            .await
            .unwrap();
        let _ = mcp
            .sign_url(Parameters(SignUrlArgs {
                server_id: "test_server_1".into(),
                resid: "test_resource".into(),
                version: None,
                sub_path: None,
                max_bytes: Some(1024),
            }))
            .await
            .unwrap();

        assert_eq!(env.mock_data_store.scan_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn log_object_candidates_cover_daily_and_hourly() {
        let from = Local
            .with_ymd_and_hms(2026, 9, 11, 23, 0, 0)
            .single()
            .unwrap()
            .timestamp();
        let to = Local
            .with_ymd_and_hms(2026, 9, 12, 1, 0, 0)
            .single()
            .unwrap()
            .timestamp();
        let keys = archive_object_keys_union(from, to, &[1, 24], &[String::new()]);
        for expected in archive_object_keys(from, to, 1, &[String::new()]) {
            assert!(keys.contains(&expected), "missing hourly {expected}");
        }
        for expected in archive_object_keys(from, to, 24, &[String::new()]) {
            assert!(keys.contains(&expected), "missing daily {expected}");
        }
    }

    #[tokio::test]
    async fn maybe_router_disabled_when_unset() {
        let env = TestEnvironment::new().await;
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        assert!(
            crate::modules::mcp::maybe_router(env.app_context)
                .unwrap()
                .is_none()
        );
        clear_mcp_env();
    }

    fn first_text(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|block| block.as_text().map(|t| t.text.clone()))
            .next()
            .expect("tool result text")
    }

    fn all_text(result: &CallToolResult) -> Vec<String> {
        result
            .content
            .iter()
            .filter_map(|block| block.as_text().map(|t| t.text.clone()))
            .collect()
    }

    fn tool_json(result: &CallToolResult) -> serde_json::Value {
        serde_json::from_str(&first_text(result)).expect("tool JSON")
    }

    #[tokio::test]
    async fn config_returns_redacted_yaml() {
        let mut config = create_default_test_config();
        config.config_yaml = r#"
servers:
  s3n:
    id: s3n
    url: "s3://AKIASECRET:wJalrXUtnFEMI/K7MDENG@s3.example.com/bucket?region=us-east-1"
    type: s3
  cdn:  # 免费EO
    id: cdn
    type: direct
    url: "https://cdn.example.com/"
plugins: {}
resources:
  app:
    latest: "1.0.0"
    versions:
      default:
        default: "path/${version}"
    tries: []
    server: []
    flow: []
    version_provider:
      type: plugin
      plugin_name: version_provider_github
      webhook_token: "webhook-secret-literal"
"#
        .into();
        let env = TestEnvironment::with_config(config).await;
        let mcp = DfsMcp::new(Arc::new(McpState {
            settings: test_settings(vec!["t".into()], None, None, vec![]),
            ctx: env.app_context.clone(),
        }));
        let result = mcp.config().await.unwrap();
        let texts = all_text(&result);
        assert_eq!(texts.len(), 1, "{texts:?}");
        let (yaml, note) = texts[0].rsplit_once("\n---\n").unwrap();
        for secret in [
            "AKIASECRET",
            "wJalrXUtnFEMI/K7MDENG",
            "webhook-secret-literal",
        ] {
            assert!(!yaml.contains(secret), "leaked {secret} in {yaml}");
        }
        assert!(yaml.contains("s3://*:*@s3.example.com/bucket?region=us-east-1"));
        assert!(yaml.contains("免费EO"));
        assert!(yaml.contains("webhook_token: '*'"));
        assert!(note.starts_with("loaded_at:"), "{note}");
    }

    fn prometheus_text_parses(text: &str) -> bool {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let rest = if let Some(end) = line.find('}') {
                line.get(end + 1..).unwrap_or("")
            } else {
                line.split_once(char::is_whitespace)
                    .map(|(_, r)| r)
                    .unwrap_or("")
            };
            let value = rest.split_whitespace().next().unwrap_or("");
            if value != "+Inf" && value != "-Inf" && value != "NaN" && value.parse::<f64>().is_err()
            {
                return false;
            }
        }
        true
    }

    #[tokio::test]
    async fn geoip_matches_flow_geo_string_and_egress_unset_is_explicit() {
        let (mcp, _) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let result = mcp
            .geoip(Parameters(GeoIpArgs { ip: ip.to_string() }))
            .await
            .unwrap();
        let body = tool_json(&result);
        assert_eq!(
            body["lookup"]["geo"],
            json!(geolocation::get_ip_location_data(ip))
        );
        assert_eq!(body["lookup"]["ip_version"], 4);
        assert_eq!(body["lookup"]["is_public"], true);
        assert_eq!(body["egress"]["configured"], false);
    }

    #[tokio::test]
    async fn resolve_paths_matches_resource_helpers() {
        let mut config = create_default_test_config();
        let resource = config.resources.get_mut("test_resource").unwrap();
        resource.latest = "1.5.0".into();
        resource.versions.clear();
        resource.versions.insert(
            "1.5.0".into(),
            HashMap::from([
                ("test_server_1".into(), "/s1/app.bin".into()),
                ("default".into(), "/default/app.bin".into()),
            ]),
        );
        resource.versions.insert(
            "default".into(),
            HashMap::from([("default".into(), "/tmpl/${version}/app.bin".into())]),
        );
        resource.version_files = vec!["hash.txt".into()];
        let expected_s1 = version_path_for_resource(resource, "1.5.0", Some("test_server_1"), None);
        let expected_s2 = version_path_for_resource(resource, "1.5.0", Some("test_server_2"), None);
        let expected_files: Vec<String> = resource
            .version_files
            .iter()
            .filter_map(|vf| version_file_path_for_resource(resource, "1.5.0", None, vf))
            .collect();
        let env = TestEnvironment::with_config(config).await;
        let mcp = DfsMcp::new(Arc::new(McpState {
            settings: test_settings(vec!["t".into()], None, None, vec![]),
            ctx: env.app_context.clone(),
        }));
        let body = tool_json(
            &mcp.resolve_paths(Parameters(ResolvePathsArgs {
                resid: "test_resource".into(),
                version: Some("1.5.0".into()),
            }))
            .await
            .unwrap(),
        );
        assert_eq!(body["servers"]["test_server_1"], json!(expected_s1));
        assert_eq!(body["servers"]["test_server_2"], json!(expected_s2));
        assert_eq!(body["version_files"], json!(expected_files));
        let via_service = env
            .app_context
            .version_file_service
            .resolved_version_file_paths("test_resource", "1.5.0")
            .await;
        assert_eq!(body["version_files"], json!(via_service));
    }

    #[tokio::test]
    async fn metrics_snapshot_is_prometheus_text_with_active_sessions() {
        let (mcp, _) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let text = first_text(&mcp.metrics_snapshot().await.unwrap());
        assert!(prometheus_text_parses(&text), "{text}");
        assert!(text.contains("dfs_active_sessions"), "{text}");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn runtime_info_omits_secret_env_literals() {
        let (mcp, _) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("REDIS_URL", "redis://secret-user:s3cret@redis.example/0");
            std::env::set_var(
                "SESSION_LOG_ARCHIVE_S3",
                "s3://AKIASECRET:wJalr@s3.example.com/bucket",
            );
            std::env::set_var("MCP_TOKEN", "literal-token-value");
        }
        let text = first_text(&mcp.runtime_info().await.unwrap());
        unsafe {
            std::env::remove_var("REDIS_URL");
            std::env::remove_var("SESSION_LOG_ARCHIVE_S3");
            std::env::remove_var("MCP_TOKEN");
        }
        assert!(!text.contains("REDIS_URL"), "{text}");
        assert!(
            !text.contains("redis://secret-user:s3cret@redis.example/0"),
            "{text}"
        );
        assert!(
            !text.contains("s3://AKIASECRET:wJalr@s3.example.com/bucket"),
            "{text}"
        );
        assert!(!text.contains("literal-token-value"), "{text}");
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(body.get("version").is_some());
        assert!(body.get("data_store").is_some());
    }

    async fn census_mcp() -> (DfsMcp, TestEnvironment) {
        let mut config = create_default_test_config();
        if let Some(s) = config.servers.get_mut("test_server_1") {
            s.health_check_path = Some("/health".into());
        }
        if let Some(s) = config.servers.get_mut("test_server_2") {
            s.health_check_path = Some("/health".into());
        }
        config.server_impl.clear();
        let mut a = config.resources.get("test_resource").unwrap().clone();
        a.version_files = vec!["a.json".into(), "b.json".into(), "c.json".into()];
        a.cache_enabled = true;
        a.flow[0].r#use = vec![crate::modules::flow::config::FlowUse::Server {
            id: "test_server_1".into(),
            weight: 10,
        }];
        let mut b = a.clone();
        b.version_files = vec!["x.json".into(), "y.json".into(), "z.json".into()];
        b.flow[0].r#use = vec![crate::modules::flow::config::FlowUse::Server {
            id: "test_server_2".into(),
            weight: 10,
        }];
        config.resources.insert("census_a".into(), a);
        config.resources.insert("census_b".into(), b);
        let env = TestEnvironment::with_config(config).await;
        for (resid, files) in [
            ("census_a", ["a.json", "b.json", "c.json"]),
            ("census_b", ["x.json", "y.json", "z.json"]),
        ] {
            for file in files {
                let path = format!("/test/{file}");
                let view = VersionFileView {
                    majority_hash: Some("aaaaaaaaaaaaaaaa".into()),
                    groups: HashMap::from([("aaaaaaaaaaaaaaaa".into(), 1)]),
                    server_hashes: HashMap::from([(
                        if resid == "census_a" {
                            "test_server_1"
                        } else {
                            "test_server_2"
                        }
                        .into(),
                        "aaaaaaaaaaaaaaaa".into(),
                    )]),
                    responder_count: 1,
                    split_since: None,
                    failed: false,
                    updated_at: 1,
                };
                env.data_store
                    .set_string(
                        &crate::modules::version_file::view_storage_key(resid, &path),
                        &serde_json::to_string(&view).unwrap(),
                        None,
                    )
                    .await
                    .unwrap();
            }
        }
        let mcp = DfsMcp::new(Arc::new(McpState {
            settings: test_settings(vec!["t".into()], None, None, vec![]),
            ctx: env.app_context.clone(),
        }));
        (mcp, env)
    }

    #[tokio::test]
    async fn version_census_reads_six_views() {
        let (mcp, _) = census_mcp().await;
        let body = tool_json(
            &mcp.version_census(Parameters(VersionCensusArgs { resid: None }))
                .await
                .unwrap(),
        );
        let views = body["views"].as_array().expect("views");
        assert_eq!(views.len(), 6, "{body}");
        for view in views {
            assert!(view["decisions"]["test_server_1"].is_string(), "{view}");
            assert!(view["decisions"]["test_server_2"].is_string(), "{view}");
        }
        let one = tool_json(
            &mcp.version_census(Parameters(VersionCensusArgs {
                resid: Some("census_a".into()),
            }))
            .await
            .unwrap(),
        );
        assert_eq!(one["views"].as_array().unwrap().len(), 3, "{one}");
        assert!(one.get("pinged").is_none());
    }

    #[tokio::test]
    async fn server_health_after_census_ping_has_age_and_unchecked() {
        let mut config = create_default_test_config();
        for (id, server) in config.servers.iter_mut() {
            server.url = "http://127.0.0.1:1".into();
            server.health_check_path = if id == "test_server_1" || id == "test_server_2" {
                Some("/health".into())
            } else {
                None
            };
        }
        config.servers.insert(
            "test_server_3".into(),
            crate::config::ServerConfig {
                id: "test_server_3".into(),
                url: "http://127.0.0.1:1".into(),
                r#type: "direct".into(),
                health_check_path: None,
                ..Default::default()
            },
        );
        config.server_impl.clear();
        for (id, server_config) in config.servers.iter() {
            if let Ok(server) = crate::modules::server::ServerImpl::new(server_config) {
                config.server_impl.insert(id.clone(), server);
            }
        }
        let env = TestEnvironment::with_config(config).await;
        env.app_context
            .version_file_service
            .ping_and_census_all(false)
            .await
            .unwrap();
        let mcp = DfsMcp::new(Arc::new(McpState {
            settings: test_settings(vec!["t".into()], None, None, vec![]),
            ctx: env.app_context.clone(),
        }));
        let body = tool_json(
            &mcp.server_health(Parameters(ServerHealthArgs { server_id: None }))
                .await
                .unwrap(),
        );
        let mut checked_ids: Vec<String> = body["checked"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["server_id"].as_str().unwrap().to_string())
            .collect();
        checked_ids.sort();
        assert_eq!(
            checked_ids,
            vec!["test_server_1".to_string(), "test_server_2".to_string()]
        );
        for row in body["checked"].as_array().unwrap() {
            assert!(row["age_seconds"].as_u64().is_some(), "{row}");
            assert!(row["health"].is_object(), "{row}");
        }
        assert_eq!(body["unchecked"], json!(["test_server_3"]));
    }

    #[tokio::test]
    async fn server_health_lists_unchecked_without_path() {
        let (mcp, env) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let expected: Vec<String> = {
            let guard = env.app_context.shared_config.load();
            let mut ids: Vec<String> = guard
                .servers
                .iter()
                .filter(|(_, s)| s.health_check_path.is_none())
                .map(|(id, _)| id.clone())
                .collect();
            ids.sort();
            ids
        };
        let body = tool_json(
            &mcp.server_health(Parameters(ServerHealthArgs { server_id: None }))
                .await
                .unwrap(),
        );
        assert_eq!(body["unchecked"], json!(expected));
        assert!(!expected.is_empty());
    }

    #[tokio::test]
    async fn bandwidth_recent_fans_out_and_clamps_minutes() {
        let (mcp, env) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let server_count = env.app_context.shared_config.load().servers.len();
        let body = tool_json(
            &mcp.bandwidth_recent(Parameters(BandwidthRecentArgs {
                server_id: None,
                minutes: BANDWIDTH_MINUTE_RING_SIZE + 50,
            }))
            .await
            .unwrap(),
        );
        assert_eq!(body["minutes"], BANDWIDTH_MINUTE_RING_SIZE);
        assert_eq!(body["servers"].as_array().unwrap().len(), server_count);
    }

    #[tokio::test]
    async fn bandwidth_today_all_has_three_groups() {
        let (mcp, _) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let body = tool_json(
            &mcp.bandwidth_today(Parameters(BandwidthArgs {
                kind: None,
                id: None,
            }))
            .await
            .unwrap(),
        );
        assert!(body.get("resources").is_some(), "{body}");
        assert!(body.get("servers").is_some(), "{body}");
        assert!(body.get("global").is_some(), "{body}");
    }

    #[tokio::test]
    async fn cache_entries_empty_without_cache_or_version_files_and_includes_src() {
        let (mcp, env) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let disabled = tool_json(
            &mcp.cache_entries(Parameters(ResidArgs {
                resid: "test_resource".into(),
            }))
            .await
            .unwrap(),
        );
        assert_eq!(disabled["entries"], json!([]));
        let no_vf = tool_json(
            &mcp.cache_entries(Parameters(ResidArgs {
                resid: "game_assets".into(),
            }))
            .await
            .unwrap(),
        );
        assert_eq!(no_vf["entries"], json!([]));

        let mut config = create_default_test_config();
        let resource = config.resources.get_mut("test_resource").unwrap();
        resource.cache_enabled = true;
        resource.version_files = vec!["a.json".into()];
        let env2 = TestEnvironment::with_config(config).await;
        let path = env2
            .app_context
            .version_file_service
            .resolved_version_file_paths("test_resource", "1.0.0")
            .await
            .into_iter()
            .next()
            .unwrap();
        let keys = env2
            .data_store
            .generate_cache_keys("test_resource", "1.0.0", &path);
        env2.data_store
            .set_cache_entry(
                &keys.metadata_key,
                &keys.content_key,
                &CacheMetadata {
                    cached_at: 10,
                    max_age: 300,
                    content_length: 4,
                    content_type: None,
                    etag: "\"1\"".into(),
                    src: Some("test_server_1".into()),
                },
                b"data",
            )
            .await
            .unwrap();
        let mcp2 = DfsMcp::new(Arc::new(McpState {
            settings: test_settings(vec!["t".into()], None, None, vec![]),
            ctx: env2.app_context.clone(),
        }));
        let listed = tool_json(
            &mcp2
                .cache_entries(Parameters(ResidArgs {
                    resid: "test_resource".into(),
                }))
                .await
                .unwrap(),
        );
        assert_eq!(listed["entries"][0]["src"], json!("test_server_1"));
        let _ = env;
    }

    #[tokio::test]
    async fn resource_versions_without_provider_has_empty_cache_fields() {
        let (mcp, _) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let body = tool_json(
            &mcp.resource_versions(Parameters(OptionalResidArgs {
                resid: Some("game_assets".into()),
            }))
            .await
            .unwrap(),
        );
        let row = &body[0];
        assert!(row["cached_version"].is_null(), "{row}");
        assert!(row["cached_at"].is_null(), "{row}");
        assert!(row["version_provider"].is_null(), "{row}");
        assert!(row.get("error").is_none());
    }

    #[tokio::test]
    async fn override_ticket_found_expired_and_missing() {
        let (mcp, env) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        env.mock_data_store
            .seed_override_ticket("live", "test_server_1,test_resource", Some(90))
            .await
            .unwrap();
        env.mock_data_store
            .seed_expired_override_ticket("old", "test_server_1")
            .await;
        let live = tool_json(
            &mcp.override_ticket(Parameters(TicketArgs {
                uuid: "live".into(),
            }))
            .await
            .unwrap(),
        );
        assert_eq!(live["found"], true);
        assert_eq!(live["target_node"], "test_server_1");
        assert!(live["ttl_seconds"].as_u64().unwrap() > 0);
        assert_eq!(
            tool_json(
                &mcp.override_ticket(Parameters(TicketArgs { uuid: "old".into() }))
                    .await
                    .unwrap()
            )["found"],
            false
        );
        assert_eq!(
            tool_json(
                &mcp.override_ticket(Parameters(TicketArgs {
                    uuid: "nope".into(),
                }))
                .await
                .unwrap()
            )["found"],
            false
        );
    }

    #[tokio::test]
    async fn session_includes_download_counts_and_strips_signed_query() {
        let (mcp, env) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let session = Session {
            resource_id: "test_resource".into(),
            version: "1.0.0".into(),
            chunks: vec!["0-1".into()],
            sub_path: None,
            cdn_records: Default::default(),
            extras: serde_json::json!({}),
            created_at: 1,
            kind: SessionKind::Chunk,
            expires_at: None,
        };
        env.data_store
            .store_session("sid-stats", &session)
            .await
            .unwrap();
        env.data_store
            .increment_download_count("sid-stats", "0-1")
            .await
            .unwrap();
        env.data_store
            .update_cdn_record_v2(
                "sid-stats",
                "0-1",
                crate::models::CdnRecord {
                    url: "https://cdn.example/file?$=secret-sig".into(),
                    server_id: Some("test_server_1".into()),
                    skip_penalty: false,
                    timestamp: 2,
                    weight: 10,
                    size: Some(8),
                },
            )
            .await
            .unwrap();
        let result = mcp
            .session(Parameters(SidArgs {
                sid: "sid-stats".into(),
            }))
            .await
            .unwrap();
        let text = first_text(&result);
        assert!(!text.contains("secret-sig"), "{text}");
        let body = tool_json(&result);
        assert!(body.get("session").is_some());
        assert!(body.get("banned").is_some());
        assert!(body.get("demoted").is_some());
        assert_eq!(body["download_counts"]["0-1"], 1);
        assert_eq!(
            body["cdn_records"]["0-1"][0]["url"],
            "https://cdn.example/file"
        );
    }

    #[tokio::test]
    async fn sign_url_direct_uses_file_size_or_requested_range() {
        let (mcp, _) = mcp_with(vec!["t".into()], None, None, vec![]).await;
        let body = tool_json(
            &mcp.sign_url(Parameters(SignUrlArgs {
                server_id: "test_server_1".into(),
                resid: "test_resource".into(),
                version: Some("1.0.0".into()),
                sub_path: None,
                max_bytes: Some(100 * 1024 * 1024),
            }))
            .await
            .unwrap(),
        );
        assert_eq!(body["capped"], false);
        assert_eq!(body["max_bytes"], 100 * 1024 * 1024);
        assert_eq!(body["url"], "https://test1.example.com/test/file.bin");
        assert_eq!(body["file_size"], 1024);
        assert_eq!(body["headers"]["Range"], "bytes=0-1023");
        assert_eq!(body["transport"]["type"], "direct");
        assert_eq!(body["notes"].as_array().unwrap().len(), 3);

        let requested = 100 * 1024 * 1024;
        let no_size = tool_json(
            &mcp.sign_url(Parameters(SignUrlArgs {
                server_id: "test_server_2".into(),
                resid: "test_resource".into(),
                version: Some("1.0.0".into()),
                sub_path: None,
                max_bytes: Some(requested),
            }))
            .await
            .unwrap(),
        );
        assert!(no_size["file_size"].is_null(), "{no_size}");
        assert_eq!(no_size["max_bytes"], requested);
        assert_eq!(
            no_size["headers"]["Range"],
            format!("bytes=0-{}", requested - 1)
        );

        let too_big = mcp
            .sign_url(Parameters(SignUrlArgs {
                server_id: "test_server_2".into(),
                resid: "test_resource".into(),
                version: Some("1.0.0".into()),
                sub_path: None,
                max_bytes: Some(u64::from(u32::MAX) + 2),
            }))
            .await
            .unwrap();
        assert_eq!(too_big.is_error, Some(true));
        assert!(first_text(&too_big).contains("Range"));

        let prefix_err = mcp
            .sign_url(Parameters(SignUrlArgs {
                server_id: "test_server_1".into(),
                resid: "game_assets".into(),
                version: None,
                sub_path: None,
                max_bytes: None,
            }))
            .await
            .unwrap();
        assert_eq!(prefix_err.is_error, Some(true));
        assert!(first_text(&prefix_err).contains("sub_path"));
    }

    #[tokio::test]
    async fn sign_url_s3_signs_range_header() {
        let mut config = create_default_test_config();
        config.servers.insert(
            "s3n".into(),
            crate::config::ServerConfig {
                id: "s3n".into(),
                r#type: "s3".into(),
                url: "s3://AKID:secret@s3.example.com/bucket?region=us-east-1".into(),
                ..Default::default()
            },
        );
        if let Ok(server) =
            crate::modules::server::ServerImpl::new(config.servers.get("s3n").unwrap())
        {
            config.server_impl.insert("s3n".into(), server);
        }
        let env = TestEnvironment::with_config(config).await;
        let mcp = DfsMcp::new(Arc::new(McpState {
            settings: test_settings(vec!["t".into()], None, None, vec![]),
            ctx: env.app_context.clone(),
        }));
        let body = tool_json(
            &mcp.sign_url(Parameters(SignUrlArgs {
                server_id: "s3n".into(),
                resid: "test_resource".into(),
                version: Some("1.0.0".into()),
                sub_path: None,
                max_bytes: Some(1024),
            }))
            .await
            .unwrap(),
        );
        assert_eq!(body["capped"], true);
        let url = body["url"].as_str().unwrap();
        assert!(url.contains("X-Amz-Expires=900"), "{url}");
        assert!(url.contains("X-Amz-SignedHeaders="), "{url}");
        assert!(url.to_ascii_lowercase().contains("range"), "{url}");
        assert_eq!(body["headers"]["Range"], "bytes=0-1023");
    }

    #[tokio::test]
    async fn tool_groups_sign_lists_only_sign_url() {
        let mcp = mcp_with_groups(
            EnabledToolGroups::Only(HashSet::from([ToolGroup::Sign])),
            None,
        )
        .await;
        let names = mcp.listed_tool_names();
        assert_eq!(names, vec!["sign_url".to_string()]);
    }
}
