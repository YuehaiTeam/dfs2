//! `/{MCP_PREFIX}` 下的最小 OAuth 2.1 授权服务器：发现元数据、动态注册、授权码 + PKCE、令牌签发。
//! 授权页唯一的门是 `MCP_TOKEN`；签发的 access token 只经 `Authorization: Bearer` 生效。

use super::settings::McpSettings;
use crate::modules::storage::data_store::DataStore;
use axum::{
    Form, Json, Router,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const KEY_NS: &str = "mcp_oauth";
const CODE_TTL: u32 = 300;
const ACCESS_TTL: u32 = 3600;
const REFRESH_TTL: u32 = 30 * 24 * 3600;
/// 每次签发令牌时顺延，与 refresh token 同寿。
const CLIENT_TTL: u32 = REFRESH_TTL;
/// 授权页错误计数的固定窗口：从该窗口第一次错误起算，到点清零。
const FAIL_WINDOW: u32 = 900;
/// 单个 client 在一个窗口内允许的错误次数。
const MAX_FAILS: u64 = 10;
/// 所有 client 合计在一个窗口内允许的错误次数，兜住反复注册新 client 的情况。
const MAX_GLOBAL_FAILS: u64 = 100;
const REG_WINDOW: u32 = 3600;
const MAX_REGS: u64 = 20;
const MAX_REDIRECT_URIS: usize = 16;
const CLIENT_AUTH_METHODS: [&str; 3] = ["none", "client_secret_basic", "client_secret_post"];
const MAX_CLIENT_NAME: usize = 100;

#[derive(Clone)]
pub struct OAuthState {
    settings: Arc<McpSettings>,
    store: DataStore,
    /// 取自 `MCP_PUBLIC_URL`。
    origin: String,
}

impl OAuthState {
    /// 设了 `MCP_PUBLIC_URL` 才返回 `Some`；调用方只在拿到 `Some` 时挂 OAuth 路由。
    pub fn new(settings: Arc<McpSettings>, store: DataStore) -> Option<Self> {
        let origin = settings.public_url.clone()?;
        Some(Self {
            settings,
            store,
            origin,
        })
    }

    fn issuer(&self) -> String {
        issuer(&self.settings, &self.origin)
    }
}

#[derive(Serialize, Deserialize)]
struct Client {
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    secret_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Grant {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    token_fp: String,
}

/// `token_fp` 是授权时所用 `MCP_TOKEN` 的指纹；该值从 `MCP_TOKEN` 移除后，派生出的令牌随之失效。
/// `grant_id` 标识一次授权码兑换出的整条令牌链，refresh 沿用；撤销 refresh token 时据此作废同链的 access token。
/// 早于该字段签发的记录读出来为空串，在下一次 refresh 时补上。
#[derive(Serialize, Deserialize)]
struct TokenRecord {
    client_id: String,
    token_fp: String,
    #[serde(default)]
    grant_id: String,
}

/// 根路径下按 RFC 8414 / RFC 9728 路径插入的发现端点，路径里带完整前缀。
pub fn well_known_router(state: OAuthState) -> Router {
    let prefix = state.settings.prefix.clone();
    Router::new()
        .route(
            &format!("/.well-known/oauth-protected-resource/{prefix}/mcp"),
            get(protected_resource_metadata),
        )
        .route(
            &format!("/.well-known/oauth-authorization-server/{prefix}"),
            get(authorization_server_metadata),
        )
        .route(
            &format!("/.well-known/openid-configuration/{prefix}"),
            get(authorization_server_metadata),
        )
        .with_state(state)
}

/// 挂在 `/{prefix}` 下、不经 `MCP_TOKEN` 门的授权端点。
pub fn prefixed_router(state: OAuthState) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(authorization_server_metadata),
        )
        .route("/oauth/authorize", get(authorize_get).post(authorize_post))
        .route("/oauth/token", post(token))
        .route("/oauth/register", post(register))
        .route("/oauth/revoke", post(revoke))
        .with_state(state)
}

fn issuer(settings: &McpSettings, origin: &str) -> String {
    format!("{origin}/{}", settings.prefix)
}

pub fn resource_metadata_url(settings: &McpSettings, origin: &str) -> String {
    format!(
        "{origin}/.well-known/oauth-protected-resource/{}/mcp",
        settings.prefix
    )
}

/// `/{prefix}/mcp` 鉴权失败的响应：401；设了 `MCP_PUBLIC_URL` 时带指向受保护资源元数据的 `WWW-Authenticate`。
pub fn unauthorized(settings: &McpSettings) -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    if let Some(origin) = settings.public_url.as_deref()
        && let Ok(value) = HeaderValue::from_str(&format!(
            "Bearer resource_metadata=\"{}\"",
            resource_metadata_url(settings, origin)
        ))
    {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// `Authorization` 头里 `scheme` 之后的凭据；scheme 按 RFC 7235 不区分大小写。
pub fn authorization_param<'a>(headers: &'a HeaderMap, scheme: &str) -> Option<&'a str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (name, rest) = raw.split_once(' ')?;
    name.eq_ignore_ascii_case(scheme).then(|| rest.trim())
}

pub async fn access_token_valid(settings: &McpSettings, store: &DataStore, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let Some(record) =
        get_json::<TokenRecord>(store, &store_key("access", &sha256_hex(token))).await
    else {
        return false;
    };
    fingerprint_current(settings, &record.token_fp) && !grant_revoked(store, &record.grant_id).await
}

async fn protected_resource_metadata(State(state): State<OAuthState>) -> Response {
    let issuer = state.issuer();
    Json(json!({
        "resource": format!("{issuer}/mcp"),
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
        "resource_name": "DFS2 MCP",
    }))
    .into_response()
}

async fn authorization_server_metadata(State(state): State<OAuthState>) -> Response {
    let issuer = state.issuer();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": CLIENT_AUTH_METHODS,
        "revocation_endpoint_auth_methods_supported": CLIENT_AUTH_METHODS,
        "authorization_response_iss_parameter_supported": true,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    token: Option<String>,
}

struct Validated {
    client_id: String,
    client_name: Option<String>,
    redirect_uri: String,
    code_challenge: String,
}

/// client_id 与 redirect_uri 不可信时只出错误页；其余错误按 RFC 6749 §4.1.2.1 回跳。
async fn validate_authorize(
    state: &OAuthState,
    p: &AuthorizeParams,
) -> Result<Validated, Box<Response>> {
    let Some(client_id) = p.client_id.as_deref().filter(|s| !s.is_empty()) else {
        return Err(Box::new(page(StatusCode::BAD_REQUEST, "缺少 client_id")));
    };
    let Some(client) = get_json::<Client>(&state.store, &store_key("client", client_id)).await
    else {
        return Err(Box::new(page(
            StatusCode::BAD_REQUEST,
            "client_id 未注册或已过期",
        )));
    };
    let redirect_uri = match p.redirect_uri.as_deref() {
        Some(uri) if client.redirect_uris.iter().any(|r| r == uri) => uri.to_string(),
        None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
        _ => {
            return Err(Box::new(page(
                StatusCode::BAD_REQUEST,
                "redirect_uri 与注册值不一致",
            )));
        }
    };
    let fail = |error: &str, description: &str| {
        error_redirect(
            &redirect_uri,
            error,
            description,
            p.state.as_deref(),
            &state.issuer(),
        )
    };
    if p.response_type.as_deref() != Some("code") {
        return Err(Box::new(fail(
            "unsupported_response_type",
            "response_type must be code",
        )));
    }
    let challenge = p.code_challenge.as_deref().unwrap_or("");
    if p.code_challenge_method.as_deref() != Some("S256")
        || challenge.len() != 43
        || !challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Box::new(fail(
            "invalid_request",
            "PKCE S256 code_challenge required",
        )));
    }
    Ok(Validated {
        client_id: client_id.to_string(),
        client_name: client.client_name,
        redirect_uri,
        code_challenge: challenge.to_string(),
    })
}

async fn authorize_get(
    State(state): State<OAuthState>,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    match validate_authorize(&state, &p).await {
        Ok(v) => consent_page(StatusCode::OK, &p, &v, None),
        Err(response) => *response,
    }
}

/// 错误计数分两层固定窗口：按 client 计 `MAX_FAILS`，全体合计 `MAX_GLOBAL_FAILS`；任一层到顶即 429，直到该层窗口过期。
async fn authorize_post(
    State(state): State<OAuthState>,
    Form(p): Form<AuthorizeParams>,
) -> Response {
    let v = match validate_authorize(&state, &p).await {
        Ok(v) => v,
        Err(response) => return *response,
    };
    let client_fail_key = store_key("fail:client", &v.client_id);
    let global_fail_key = store_key("fail", "all");
    if read_count(&state.store, &client_fail_key).await >= MAX_FAILS
        || read_count(&state.store, &global_fail_key).await >= MAX_GLOBAL_FAILS
    {
        return page(StatusCode::TOO_MANY_REQUESTS, "失败次数过多，请稍后再试");
    }
    let provided = p.token.as_deref().unwrap_or("").trim();
    let Some(matched) = state
        .settings
        .tokens
        .iter()
        .find(|t| t.as_str() == provided)
    else {
        count_in_window(&state.store, &client_fail_key, FAIL_WINDOW).await;
        count_in_window(&state.store, &global_fail_key, FAIL_WINDOW).await;
        tracing::warn!("mcp oauth authorize rejected");
        return consent_page(StatusCode::UNAUTHORIZED, &p, &v, Some("MCP_TOKEN 不正确"));
    };
    let code = random_token();
    let grant = Grant {
        client_id: v.client_id,
        redirect_uri: v.redirect_uri.clone(),
        code_challenge: v.code_challenge,
        token_fp: fingerprint(matched),
    };
    if let Err(e) = put_json(
        &state.store,
        &store_key("code", &sha256_hex(&code)),
        &grant,
        CODE_TTL,
    )
    .await
    {
        tracing::error!(error = %e, "mcp oauth code store failed");
        return page(StatusCode::INTERNAL_SERVER_ERROR, "存储失败");
    }
    let mut pairs = vec![("code", code.as_str())];
    if let Some(s) = p.state.as_deref() {
        pairs.push(("state", s));
    }
    let iss = state.issuer();
    pairs.push(("iss", iss.as_str()));
    no_store(Redirect::to(&append_query(&v.redirect_uri, &pairs)).into_response())
}

#[derive(Deserialize)]
struct TokenParams {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

/// 令牌端点与撤销端点共用的客户端认证：公共客户端只认 `client_id`，机密客户端须经 Basic 或表单出示 secret。
async fn authenticate_client(
    state: &OAuthState,
    headers: &HeaderMap,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> Result<(String, Client), Box<Response>> {
    let basic = basic_credentials(headers);
    let client_id = basic
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| client_id.map(str::to_string))
        .unwrap_or_default();
    let secret = basic
        .map(|(_, s)| s)
        .or_else(|| client_secret.map(str::to_string));
    let Some(client) = get_json::<Client>(&state.store, &store_key("client", &client_id)).await
    else {
        return Err(Box::new(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "unknown client",
        )));
    };
    if let Some(hash) = &client.secret_hash
        && secret.as_deref().map(sha256_hex).as_deref() != Some(hash.as_str())
    {
        return Err(Box::new(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        )));
    }
    Ok((client_id, client))
}

async fn token(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Form(p): Form<TokenParams>,
) -> Response {
    let (client_id, client) = match authenticate_client(
        &state,
        &headers,
        p.client_id.as_deref(),
        p.client_secret.as_deref(),
    )
    .await
    {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let (token_fp, grant_id, kept_refresh) = match p.grant_type.as_deref() {
        Some("authorization_code") => {
            let key = store_key("code", &sha256_hex(p.code.as_deref().unwrap_or("")));
            let Some(grant) = take_json::<Grant>(&state.store, &key).await else {
                return invalid_grant("code invalid, expired or used");
            };
            if grant.client_id != client_id {
                return invalid_grant("code issued to another client");
            }
            if p.redirect_uri
                .as_deref()
                .is_some_and(|r| r != grant.redirect_uri)
            {
                return invalid_grant("redirect_uri mismatch");
            }
            let verifier = p.code_verifier.as_deref().unwrap_or("");
            if !pkce_matches(verifier, &grant.code_challenge) {
                return invalid_grant("PKCE verification failed");
            }
            (grant.token_fp, random_token(), None)
        }
        Some("refresh_token") => {
            let presented = p.refresh_token.clone().unwrap_or_default();
            let key = store_key("refresh", &sha256_hex(&presented));
            let Some(record) = get_json::<TokenRecord>(&state.store, &key).await else {
                return invalid_grant("refresh_token invalid or expired");
            };
            if record.client_id != client_id {
                return invalid_grant("refresh_token issued to another client");
            }
            if grant_revoked(&state.store, &record.grant_id).await {
                return invalid_grant("refresh_token revoked");
            }
            let grant_id = if record.grant_id.is_empty() {
                random_token()
            } else {
                record.grant_id
            };
            (record.token_fp, grant_id, Some(presented))
        }
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "grant_type must be authorization_code or refresh_token",
            );
        }
    };
    if !fingerprint_current(&state.settings, &token_fp) {
        return invalid_grant("grant revoked by MCP_TOKEN rotation");
    }
    let access = random_token();
    let refresh = kept_refresh.unwrap_or_else(random_token);
    let record = TokenRecord {
        client_id: client_id.clone(),
        token_fp,
        grant_id,
    };
    let stored = async {
        put_json(
            &state.store,
            &store_key("access", &sha256_hex(&access)),
            &record,
            ACCESS_TTL,
        )
        .await?;
        put_json(
            &state.store,
            &store_key("refresh", &sha256_hex(&refresh)),
            &record,
            REFRESH_TTL,
        )
        .await?;
        put_json(
            &state.store,
            &store_key("client", &client_id),
            &client,
            CLIENT_TTL,
        )
        .await
    };
    if let Err(e) = stored.await {
        tracing::error!(error = %e, "mcp oauth token store failed");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "storage failed",
        );
    }
    no_store(
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL,
            "refresh_token": refresh,
        }))
        .into_response(),
    )
}

#[derive(Deserialize)]
struct RevokeParams {
    token: Option<String>,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// RFC 7009。只撤销记录里 `client_id` 与认证结果一致的令牌；未知、过期或属于别的 client 的令牌同样回 200。
/// 撤销 refresh token 时写下该授权链的作废标记，同链已签发的 access token 随之失效。
async fn revoke(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Form(p): Form<RevokeParams>,
) -> Response {
    let client_id = match authenticate_client(
        &state,
        &headers,
        p.client_id.as_deref(),
        p.client_secret.as_deref(),
    )
    .await
    {
        Ok((client_id, _)) => client_id,
        Err(response) => return *response,
    };
    let Some(token) = p.token.as_deref().filter(|t| !t.is_empty()) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "token required");
    };
    let hashed = sha256_hex(token);
    let kinds = if p.token_type_hint.as_deref() == Some("refresh_token") {
        ["refresh", "access"]
    } else {
        ["access", "refresh"]
    };
    for kind in kinds {
        let key = store_key(kind, &hashed);
        let Some(record) = get_json::<TokenRecord>(&state.store, &key).await else {
            continue;
        };
        if record.client_id != client_id {
            tracing::warn!("mcp oauth revoke ignored: token belongs to another client");
            break;
        }
        let revoked = async {
            if kind == "refresh" && !record.grant_id.is_empty() {
                state
                    .store
                    .set_string(
                        &store_key("revoked", &record.grant_id),
                        "1",
                        Some(ACCESS_TTL),
                    )
                    .await?;
            }
            state.store.delete(&key).await
        };
        if let Err(e) = revoked.await {
            tracing::error!(error = %e, "mcp oauth revoke store failed");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "storage failed",
            );
        }
        break;
    }
    no_store(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
struct RegisterRequest {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
}

async fn register(State(state): State<OAuthState>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<RegisterRequest>(&body) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "body must be JSON client metadata",
        );
    };
    if req.redirect_uris.is_empty()
        || req.redirect_uris.len() > MAX_REDIRECT_URIS
        || !req.redirect_uris.iter().all(|u| redirect_uri_allowed(u))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uris must be 1-16 https or http loopback URLs",
        );
    }
    let with_secret = match req.token_endpoint_auth_method.as_deref() {
        None | Some("none") => false,
        Some("client_secret_basic" | "client_secret_post") => true,
        Some(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "unsupported token_endpoint_auth_method",
            );
        }
    };
    if req.grant_types.as_ref().is_some_and(|g| {
        g.iter()
            .any(|g| g != "authorization_code" && g != "refresh_token")
    }) || req
        .response_types
        .as_ref()
        .is_some_and(|r| r.iter().any(|r| r != "code"))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "only authorization_code with response_type code",
        );
    }
    if count_in_window(&state.store, &store_key("reg", "count"), REG_WINDOW).await > MAX_REGS {
        return oauth_error(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "registration limit reached",
        );
    }
    let client_name = req
        .client_name
        .map(|n| n.chars().take(MAX_CLIENT_NAME).collect::<String>());
    let client_id = random_token();
    let secret = with_secret.then(random_token);
    let client = Client {
        redirect_uris: req.redirect_uris.clone(),
        client_name: client_name.clone(),
        secret_hash: secret.as_deref().map(sha256_hex),
    };
    if let Err(e) = put_json(
        &state.store,
        &store_key("client", &client_id),
        &client,
        CLIENT_TTL,
    )
    .await
    {
        tracing::error!(error = %e, "mcp oauth client store failed");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "storage failed",
        );
    }
    let mut body = json!({
        "client_id": client_id,
        "client_id_issued_at": chrono::Utc::now().timestamp(),
        "redirect_uris": req.redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": req.token_endpoint_auth_method.as_deref().unwrap_or("none"),
    });
    if let Some(name) = client_name {
        body["client_name"] = json!(name);
    }
    if let Some(secret) = secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    no_store((StatusCode::CREATED, Json(body)).into_response())
}

fn redirect_uri_allowed(raw: &str) -> bool {
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => match url.host() {
            Some(url::Host::Domain(d)) => d == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        && URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge
}

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let encoded = authorization_param(headers, "Basic")?;
    let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let id = urlencoding::decode(id).ok()?.into_owned();
    let secret = urlencoding::decode(secret).ok()?.into_owned();
    Some((id, secret))
}

fn fingerprint(token: &str) -> String {
    sha256_hex(&format!("mcp-oauth-fp:{token}"))
}

fn fingerprint_current(settings: &McpSettings, fp: &str) -> bool {
    settings.tokens.iter().any(|t| fingerprint(t) == fp)
}

fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn store_key(kind: &str, id: &str) -> String {
    format!("{KEY_NS}:{kind}:{id}")
}

async fn get_json<T: DeserializeOwned>(store: &DataStore, key: &str) -> Option<T> {
    match store.get_string(key).await {
        Ok(Some(raw)) => serde_json::from_str(&raw).ok(),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "mcp oauth store read failed");
            None
        }
    }
}

async fn take_json<T: DeserializeOwned>(store: &DataStore, key: &str) -> Option<T> {
    match store.take_string(key).await {
        Ok(Some(raw)) => serde_json::from_str(&raw).ok(),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "mcp oauth store take failed");
            None
        }
    }
}

async fn put_json<T: Serialize>(
    store: &DataStore,
    key: &str,
    value: &T,
    ttl: u32,
) -> Result<(), String> {
    let raw = serde_json::to_string(value).map_err(|e| e.to_string())?;
    store.set_string(key, &raw, Some(ttl)).await
}

async fn read_count(store: &DataStore, key: &str) -> u64 {
    match store.get_string(key).await {
        Ok(Some(raw)) => raw.parse().unwrap_or(0),
        _ => 0,
    }
}

/// 固定窗口计数：原子自增，过期只在窗口内第一次计数时设定。存储出错时返回 0。
async fn count_in_window(store: &DataStore, key: &str, window: u32) -> u64 {
    match store.incr_fixed_window(key, window).await {
        Ok(count) => count,
        Err(e) => {
            tracing::warn!(error = %e, "mcp oauth counter write failed");
            0
        }
    }
}

/// 读不到存储时按已作废处理。
async fn grant_revoked(store: &DataStore, grant_id: &str) -> bool {
    !grant_id.is_empty()
        && !matches!(
            store.get_string(&store_key("revoked", grant_id)).await,
            Ok(None)
        )
}

fn append_query(base: &str, pairs: &[(&str, &str)]) -> String {
    match url::Url::parse(base) {
        Ok(mut url) => {
            url.query_pairs_mut().extend_pairs(pairs.iter().copied());
            url.to_string()
        }
        Err(_) => base.to_string(),
    }
}

fn error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
    iss: &str,
) -> Response {
    let mut pairs = vec![("error", error), ("error_description", description)];
    if let Some(s) = state {
        pairs.push(("state", s));
    }
    pairs.push(("iss", iss));
    no_store(Redirect::to(&append_query(redirect_uri, &pairs)).into_response())
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    no_store(
        (
            status,
            Json(json!({ "error": error, "error_description": description })),
        )
            .into_response(),
    )
}

fn invalid_grant(description: &str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

fn no_store(mut response: Response) -> Response {
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn html_response(status: StatusCode, body: String) -> Response {
    let mut response = no_store((status, Html(body)).into_response());
    let h = response.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        ),
    );
    response
}

fn page(status: StatusCode, message: &str) -> Response {
    html_response(
        status,
        format!(
            "<!doctype html><meta charset=\"utf-8\"><title>DFS2 MCP</title><p>{}</p>",
            escape(message)
        ),
    )
}

fn consent_page(
    status: StatusCode,
    p: &AuthorizeParams,
    v: &Validated,
    error: Option<&str>,
) -> Response {
    let hidden = [
        ("response_type", p.response_type.as_deref()),
        ("client_id", Some(v.client_id.as_str())),
        ("redirect_uri", Some(v.redirect_uri.as_str())),
        ("code_challenge", Some(v.code_challenge.as_str())),
        ("code_challenge_method", p.code_challenge_method.as_deref()),
        ("state", p.state.as_deref()),
        ("scope", p.scope.as_deref()),
        ("resource", p.resource.as_deref()),
    ]
    .iter()
    .filter_map(|(k, val)| {
        val.map(|val| {
            format!(
                "<input type=\"hidden\" name=\"{k}\" value=\"{}\">",
                escape(val)
            )
        })
    })
    .collect::<String>();
    let target = url::Url::parse(&v.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let client = v.client_name.as_deref().unwrap_or("未命名客户端");
    let error = error
        .map(|e| format!("<p style=\"color:#b00\">{}</p>", escape(e)))
        .unwrap_or_default();
    html_response(
        status,
        format!(
            "<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
<title>DFS2 MCP 授权</title><body style=\"font-family:sans-serif;max-width:28em;margin:3em auto\">\
<h3>DFS2 MCP 授权</h3><p>{} 请求只读访问，授权后跳转到 {}。</p>{error}\
<form method=\"post\" action=\"authorize\">{hidden}\
<input type=\"password\" name=\"token\" placeholder=\"MCP_TOKEN\" autocomplete=\"off\" required autofocus style=\"width:100%\">\
<p><button type=\"submit\">授权</button></p></form></body>",
            escape(client),
            escape(&target)
        ),
    )
}

fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::mcp::settings::EnabledToolGroups;
    use crate::tests::common::TestEnvironment;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    const ORIGIN: &str = "https://dfs.example.com";
    const REDIRECT: &str = "https://client.example.com/cb";

    fn settings(tokens: &[&str], public_url: Option<&str>) -> Arc<McpSettings> {
        Arc::new(McpSettings {
            tokens: tokens.iter().map(|t| t.to_string()).collect(),
            prefix: "mcpqa".into(),
            log_signer: None,
            log_prefixes: vec![],
            presign_ttl_seconds: 900,
            grafana: None,
            config_mirror_url: None,
            playbook_path: None,
            tool_groups: EnabledToolGroups::All,
            public_url: public_url.map(str::to_string),
        })
    }

    async fn app() -> (Router, TestEnvironment) {
        let env = TestEnvironment::new().await;
        let app = super::super::mount(
            settings(&["alpha", "beta"], Some(ORIGIN)),
            env.app_context.clone(),
        );
        (app, env)
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: String,
    }

    impl Reply {
        fn json(&self) -> serde_json::Value {
            serde_json::from_str(&self.body).unwrap()
        }

        fn location(&self) -> url::Url {
            url::Url::parse(self.headers[header::LOCATION].to_str().unwrap()).unwrap()
        }
    }

    async fn send(app: &Router, req: Request<Body>) -> Reply {
        let response = app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        Reply {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    fn form(uri: &str, pairs: &[(&str, &str)]) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(serde_urlencoded::to_string(pairs).unwrap()))
            .unwrap()
    }

    fn mcp_post(auth: Option<(&str, &str)>, uri: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some((name, value)) = auth {
            builder = builder.header(name, value);
        }
        builder.body(Body::from("{}")).unwrap()
    }

    async fn register_client(app: &Router, body: serde_json::Value) -> Reply {
        send(
            app,
            Request::builder()
                .method("POST")
                .uri("/mcpqa/oauth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn public_client(app: &Router) -> String {
        let reply = register_client(
            app,
            json!({ "redirect_uris": [REDIRECT], "client_name": "Gemini" }),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        reply.json()["client_id"].as_str().unwrap().to_string()
    }

    fn pkce() -> (String, String) {
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        (verifier, challenge)
    }

    fn authorize_fields<'a>(client_id: &'a str, challenge: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", "st-1"),
        ]
    }

    async fn obtain_code(app: &Router, client_id: &str, challenge: &str) -> String {
        let mut fields = authorize_fields(client_id, challenge);
        fields.push(("token", "alpha"));
        let reply = send(app, form("/mcpqa/oauth/authorize", &fields)).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        let location = reply.location();
        let query: HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(query["state"], "st-1");
        assert_eq!(query["iss"], format!("{ORIGIN}/mcpqa"));
        query["code"].clone()
    }

    async fn exchange(app: &Router, client_id: &str, code: &str, verifier: &str) -> Reply {
        send(
            app,
            form(
                "/mcpqa/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", REDIRECT),
                    ("client_id", client_id),
                    ("code_verifier", verifier),
                ],
            ),
        )
        .await
    }

    use std::collections::HashMap;

    #[tokio::test]
    async fn well_known_without_exact_prefix_is_plain_404() {
        let (app, _env) = app().await;
        let unknown = send(&app, get("/definitely-not-a-route")).await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND);
        for uri in [
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server/other",
            "/.well-known/oauth-protected-resource/other/mcp",
            "/.well-known/oauth-authorization-server/mcpqa/extra",
            "/authorize",
            "/token",
            "/register",
            "/oauth/authorize",
        ] {
            for req in [get(uri), form(uri, &[])] {
                let reply = send(&app, req).await;
                assert_eq!(reply.status, unknown.status, "{uri}");
                assert_eq!(reply.body, unknown.body, "{uri}");
                assert_eq!(reply.headers, unknown.headers, "{uri}");
            }
        }
    }

    #[tokio::test]
    async fn discovery_under_prefix_uses_public_url() {
        let (app, _env) = app().await;
        let prm = send(&app, get("/.well-known/oauth-protected-resource/mcpqa/mcp")).await;
        assert_eq!(prm.status, StatusCode::OK);
        assert_eq!(prm.json()["resource"], format!("{ORIGIN}/mcpqa/mcp"));
        assert_eq!(
            prm.json()["authorization_servers"][0],
            format!("{ORIGIN}/mcpqa")
        );
        for uri in [
            "/.well-known/oauth-authorization-server/mcpqa",
            "/.well-known/openid-configuration/mcpqa",
            "/mcpqa/.well-known/oauth-authorization-server",
            "/mcpqa/.well-known/openid-configuration",
        ] {
            let asm = send(&app, get(uri)).await;
            assert_eq!(asm.status, StatusCode::OK, "{uri}");
            let meta = asm.json();
            assert_eq!(meta["issuer"], format!("{ORIGIN}/mcpqa"));
            assert_eq!(
                meta["authorization_endpoint"],
                format!("{ORIGIN}/mcpqa/oauth/authorize")
            );
            assert_eq!(
                meta["token_endpoint"],
                format!("{ORIGIN}/mcpqa/oauth/token")
            );
            assert_eq!(
                meta["registration_endpoint"],
                format!("{ORIGIN}/mcpqa/oauth/register")
            );
            assert_eq!(
                meta["revocation_endpoint"],
                format!("{ORIGIN}/mcpqa/oauth/revoke")
            );
            assert_eq!(
                meta["revocation_endpoint_auth_methods_supported"],
                json!(["none", "client_secret_basic", "client_secret_post"])
            );
            assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
        }
    }

    #[tokio::test]
    async fn without_public_url_oauth_is_absent_and_static_tokens_work() {
        let env = TestEnvironment::new().await;
        let app = super::super::mount(settings(&["alpha", "beta"], None), env.app_context.clone());
        let unknown = send(&app, get("/definitely-not-a-route")).await;
        for uri in [
            "/.well-known/oauth-protected-resource/mcpqa/mcp",
            "/.well-known/oauth-authorization-server/mcpqa",
            "/.well-known/openid-configuration/mcpqa",
            "/mcpqa/.well-known/oauth-authorization-server",
            "/mcpqa/.well-known/openid-configuration",
            "/mcpqa/oauth/authorize",
            "/mcpqa/oauth/token",
            "/mcpqa/oauth/register",
            "/mcpqa/oauth/revoke",
        ] {
            for req in [get(uri), form(uri, &[])] {
                let reply = send(&app, req).await;
                assert_eq!(reply.status, StatusCode::NOT_FOUND, "{uri}");
                assert_eq!(reply.body, unknown.body, "{uri}");
                assert_eq!(reply.headers, unknown.headers, "{uri}");
            }
        }
        let missing = send(&app, get("/mcpqa/mcp")).await;
        assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
        assert_eq!(missing.body, "");
        assert!(!missing.headers.contains_key(header::WWW_AUTHENTICATE));
        for req in [
            mcp_post(Some(("authorization", "Bearer alpha")), "/mcpqa/mcp"),
            mcp_post(Some(("authorization", "bearer alpha")), "/mcpqa/mcp"),
            mcp_post(Some(("x-api-key", "beta")), "/mcpqa/mcp"),
            mcp_post(None, "/mcpqa/mcp?token=alpha"),
        ] {
            assert_ne!(send(&app, req).await.status, StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn store_counter_window_is_fixed_and_take_is_single_use() {
        let env = TestEnvironment::new().await;
        let store = &env.data_store;
        assert_eq!(store.incr_fixed_window("qa:counter", 1).await.unwrap(), 1);
        assert_eq!(
            store.incr_fixed_window("qa:counter", 3600).await.unwrap(),
            2
        );
        assert_eq!(
            store.get_string("qa:counter").await.unwrap().as_deref(),
            Some("2")
        );
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
        assert_eq!(
            store.incr_fixed_window("qa:counter", 3600).await.unwrap(),
            1
        );

        store.set_string("qa:once", "v", Some(60)).await.unwrap();
        assert_eq!(
            store.take_string("qa:once").await.unwrap().as_deref(),
            Some("v")
        );
        assert_eq!(store.take_string("qa:once").await.unwrap(), None);
        assert_eq!(store.get_string("qa:once").await.unwrap(), None);
    }

    #[tokio::test]
    async fn static_tokens_unchanged_and_401_carries_resource_metadata() {
        let (app, _env) = app().await;
        let missing = send(&app, get("/mcpqa/mcp")).await;
        assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
        assert_eq!(missing.body, "");
        assert_eq!(
            missing.headers[header::WWW_AUTHENTICATE],
            format!(
                "Bearer resource_metadata=\"{ORIGIN}/.well-known/oauth-protected-resource/mcpqa/mcp\""
            )
        );
        let wrong = send(
            &app,
            mcp_post(Some(("authorization", "Bearer nope")), "/mcpqa/mcp"),
        )
        .await;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
        for req in [
            mcp_post(Some(("authorization", "Bearer alpha")), "/mcpqa/mcp"),
            mcp_post(Some(("authorization", "bearer alpha")), "/mcpqa/mcp"),
            mcp_post(Some(("x-api-key", "beta")), "/mcpqa/mcp"),
            mcp_post(None, "/mcpqa/mcp?token=alpha"),
        ] {
            assert_ne!(send(&app, req).await.status, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(
            send(&app, get("/mcpqa/other")).await.status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn dcr_authorize_token_flow_and_access_token_at_mcp() {
        let (app, _env) = app().await;
        let client_id = public_client(&app).await;
        let (verifier, challenge) = pkce();

        let query = serde_urlencoded::to_string(authorize_fields(&client_id, &challenge)).unwrap();
        let page = send(&app, get(&format!("/mcpqa/oauth/authorize?{query}"))).await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.body.contains("name=\"token\""), "{}", page.body);
        assert!(page.body.contains("Gemini"));
        assert_eq!(page.headers[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(page.headers[header::X_FRAME_OPTIONS], "DENY");

        let mut wrong = authorize_fields(&client_id, &challenge);
        wrong.push(("token", "nope"));
        let reply = send(&app, form("/mcpqa/oauth/authorize", &wrong)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert!(!reply.headers.contains_key(header::LOCATION));

        let code = obtain_code(&app, &client_id, &challenge).await;
        let tokens = exchange(&app, &client_id, &code, &verifier).await;
        assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
        assert_eq!(tokens.headers[header::CACHE_CONTROL], "no-store");
        let body = tokens.json();
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], ACCESS_TTL);
        let access = body["access_token"].as_str().unwrap().to_string();
        let refresh = body["refresh_token"].as_str().unwrap().to_string();

        let bearer = format!("Bearer {access}");
        let ok = send(
            &app,
            mcp_post(Some(("authorization", &bearer)), "/mcpqa/mcp"),
        )
        .await;
        assert_ne!(ok.status, StatusCode::UNAUTHORIZED);
        let lower = send(
            &app,
            mcp_post(
                Some(("authorization", &format!("bearer {access}"))),
                "/mcpqa/mcp",
            ),
        )
        .await;
        assert_ne!(lower.status, StatusCode::UNAUTHORIZED);
        let via_key = send(&app, mcp_post(Some(("x-api-key", &access)), "/mcpqa/mcp")).await;
        assert_eq!(via_key.status, StatusCode::UNAUTHORIZED);
        let via_query = send(&app, mcp_post(None, &format!("/mcpqa/mcp?token={access}"))).await;
        assert_eq!(via_query.status, StatusCode::UNAUTHORIZED);

        let reused = exchange(&app, &client_id, &code, &verifier).await;
        assert_eq!(reused.status, StatusCode::BAD_REQUEST);
        assert_eq!(reused.json()["error"], "invalid_grant");

        let refresh_form = |rt: String| {
            form(
                "/mcpqa/oauth/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &rt),
                    ("client_id", &client_id),
                ],
            )
        };
        let renewed = send(&app, refresh_form(refresh.clone())).await;
        assert_eq!(renewed.status, StatusCode::OK, "{}", renewed.body);
        let new_access = renewed.json()["access_token"].as_str().unwrap().to_string();
        let ok = send(
            &app,
            mcp_post(
                Some(("authorization", &format!("Bearer {new_access}"))),
                "/mcpqa/mcp",
            ),
        )
        .await;
        assert_ne!(ok.status, StatusCode::UNAUTHORIZED);
        assert_eq!(renewed.json()["refresh_token"], refresh.as_str());
        let again = send(&app, refresh_form(refresh.clone())).await;
        assert_eq!(again.status, StatusCode::OK, "{}", again.body);
        assert_eq!(again.json()["refresh_token"], refresh.as_str());
        assert_ne!(again.json()["access_token"], new_access.as_str());
    }

    #[tokio::test]
    async fn wrong_pkce_and_wrong_client_rejected_and_code_consumed() {
        let (app, _env) = app().await;
        let client_id = public_client(&app).await;
        let other_client = public_client(&app).await;
        let (verifier, challenge) = pkce();

        let code = obtain_code(&app, &client_id, &challenge).await;
        let (other_verifier, _) = pkce();
        let bad = exchange(&app, &client_id, &code, &other_verifier).await;
        assert_eq!(bad.json()["error"], "invalid_grant");
        let after = exchange(&app, &client_id, &code, &verifier).await;
        assert_eq!(
            after.json()["error"],
            "invalid_grant",
            "code must be single-use"
        );

        let code = obtain_code(&app, &client_id, &challenge).await;
        let stolen = exchange(&app, &other_client, &code, &verifier).await;
        assert_eq!(stolen.json()["error"], "invalid_grant");

        let unknown = exchange(&app, "no-such-client", "x", &verifier).await;
        assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
        assert_eq!(unknown.json()["error"], "invalid_client");
    }

    #[tokio::test]
    async fn authorize_validates_client_redirect_and_pkce() {
        let (app, _env) = app().await;
        let client_id = public_client(&app).await;
        let (_, challenge) = pkce();
        let authorize = |fields: Vec<(&str, &str)>| {
            get(&format!(
                "/mcpqa/oauth/authorize?{}",
                serde_urlencoded::to_string(fields).unwrap()
            ))
        };

        let mut fields = authorize_fields("nope", &challenge);
        let reply = send(&app, authorize(fields.clone())).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(!reply.headers.contains_key(header::LOCATION));

        fields = authorize_fields(&client_id, &challenge);
        fields[2] = ("redirect_uri", "https://evil.example.com/cb");
        let reply = send(&app, authorize(fields)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(!reply.headers.contains_key(header::LOCATION));

        for (index, replacement) in [
            (4, ("code_challenge_method", "plain")),
            (3, ("code_challenge", "short")),
            (0, ("response_type", "token")),
        ] {
            let mut fields = authorize_fields(&client_id, &challenge);
            fields[index] = replacement;
            let reply = send(&app, authorize(fields)).await;
            assert_eq!(reply.status, StatusCode::SEE_OTHER);
            let location = reply.location();
            assert!(location.as_str().starts_with(REDIRECT));
            let query: HashMap<_, _> = location.query_pairs().into_owned().collect();
            assert!(query.contains_key("error"), "{location}");
            assert!(!query.contains_key("code"));
            assert_eq!(query["state"], "st-1");
        }
    }

    async fn authorize_with(app: &Router, client_id: &str, token: &str) -> StatusCode {
        let (_, challenge) = pkce();
        let mut fields = authorize_fields(client_id, &challenge);
        fields.push(("token", token));
        send(app, form("/mcpqa/oauth/authorize", &fields))
            .await
            .status
    }

    #[tokio::test]
    async fn failed_attempts_lock_only_that_client() {
        let (app, _env) = app().await;
        let locked = public_client(&app).await;
        let other = public_client(&app).await;
        for _ in 0..MAX_FAILS {
            assert_eq!(
                authorize_with(&app, &locked, "nope").await,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            authorize_with(&app, &locked, "alpha").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            authorize_with(&app, &other, "alpha").await,
            StatusCode::SEE_OTHER
        );
        assert_eq!(
            authorize_with(&app, &other, "nope").await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn global_failure_cap_locks_every_client() {
        let (app, _env) = app().await;
        let per_client = MAX_GLOBAL_FAILS / MAX_FAILS;
        for _ in 0..per_client {
            let client_id = public_client(&app).await;
            for _ in 0..MAX_FAILS {
                assert_eq!(
                    authorize_with(&app, &client_id, "nope").await,
                    StatusCode::UNAUTHORIZED
                );
            }
        }
        let fresh = public_client(&app).await;
        assert_eq!(
            authorize_with(&app, &fresh, "alpha").await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn failure_window_is_not_extended_by_later_failures() {
        let (app, env) = app().await;
        let client_id = public_client(&app).await;
        assert_eq!(
            authorize_with(&app, &client_id, "nope").await,
            StatusCode::UNAUTHORIZED
        );
        let key = store_key("fail:client", &client_id);
        // 把窗口缩到 1 秒，之后的错误若顺延过期，计数会一直留着。
        env.data_store.set_string(&key, "1", Some(1)).await.unwrap();
        for _ in 1..MAX_FAILS {
            assert_eq!(
                authorize_with(&app, &client_id, "nope").await,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            authorize_with(&app, &client_id, "alpha").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
        assert_eq!(
            authorize_with(&app, &client_id, "alpha").await,
            StatusCode::SEE_OTHER
        );
    }

    fn revoke_form(client_id: &str, token: &str, hint: Option<&str>) -> Request<Body> {
        let mut pairs = vec![("client_id", client_id), ("token", token)];
        if let Some(hint) = hint {
            pairs.push(("token_type_hint", hint));
        }
        form("/mcpqa/oauth/revoke", &pairs)
    }

    #[tokio::test]
    async fn revocation_deletes_tokens_of_the_authenticated_client_only() {
        let (app, _env) = app().await;
        let client_id = public_client(&app).await;
        let other = public_client(&app).await;
        let (verifier, challenge) = pkce();
        let code = obtain_code(&app, &client_id, &challenge).await;
        let tokens = exchange(&app, &client_id, &code, &verifier).await.json();
        let access = tokens["access_token"].as_str().unwrap().to_string();
        let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
        let at_mcp = |token: String| {
            mcp_post(
                Some(("authorization", &format!("Bearer {token}"))),
                "/mcpqa/mcp",
            )
        };
        let refresh_req = || {
            form(
                "/mcpqa/oauth/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh),
                    ("client_id", &client_id),
                ],
            )
        };

        for (token, hint) in [(&access, None), (&refresh, Some("refresh_token"))] {
            let reply = send(&app, revoke_form(&other, token, hint)).await;
            assert_eq!(reply.status, StatusCode::OK);
        }
        assert_ne!(
            send(&app, at_mcp(access.clone())).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(send(&app, refresh_req()).await.status, StatusCode::OK);

        let unknown = send(&app, revoke_form(&client_id, "no-such-token", None)).await;
        assert_eq!(unknown.status, StatusCode::OK);
        assert_eq!(unknown.headers[header::CACHE_CONTROL], "no-store");
        let anonymous = send(&app, revoke_form("no-such-client", &access, None)).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        assert_eq!(anonymous.json()["error"], "invalid_client");
        let empty = send(&app, revoke_form(&client_id, "", None)).await;
        assert_eq!(empty.json()["error"], "invalid_request");

        let revoked = send(&app, revoke_form(&client_id, &access, Some("access_token"))).await;
        assert_eq!(revoked.status, StatusCode::OK);
        assert_eq!(
            send(&app, at_mcp(access.clone())).await.status,
            StatusCode::UNAUTHORIZED
        );

        let renewed = send(&app, refresh_req()).await;
        assert_eq!(renewed.status, StatusCode::OK, "{}", renewed.body);
        let second_access = renewed.json()["access_token"].as_str().unwrap().to_string();
        assert_ne!(
            send(&app, at_mcp(second_access.clone())).await.status,
            StatusCode::UNAUTHORIZED
        );
        let revoked = send(&app, revoke_form(&client_id, &refresh, None)).await;
        assert_eq!(revoked.status, StatusCode::OK);
        let refused = send(&app, refresh_req()).await;
        assert_eq!(refused.json()["error"], "invalid_grant");
        assert_eq!(
            send(&app, at_mcp(second_access)).await.status,
            StatusCode::UNAUTHORIZED
        );
        let again = send(&app, revoke_form(&client_id, &refresh, None)).await;
        assert_eq!(again.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn register_validates_metadata_and_caps_count() {
        let (app, _env) = app().await;
        for uris in [
            json!([]),
            json!(["http://client.example.com/cb"]),
            json!(["javascript:alert(1)"]),
            json!(["https://client.example.com/cb#frag"]),
        ] {
            let reply = register_client(&app, json!({ "redirect_uris": uris })).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{uris}");
            assert_eq!(reply.json()["error"], "invalid_redirect_uri");
        }
        let bad_grant = register_client(
            &app,
            json!({ "redirect_uris": [REDIRECT], "grant_types": ["client_credentials"] }),
        )
        .await;
        assert_eq!(bad_grant.json()["error"], "invalid_client_metadata");

        let google: Vec<String> = ["", "-sandbox", "-test"]
            .iter()
            .flat_map(|env| {
                ["r", "a"].map(|kind| {
                    format!("https://oauth-redirect{env}.googleusercontent.com/{kind}/user_bound_custom-mcp-1")
                })
            })
            .collect();
        let google = register_client(&app, json!({ "redirect_uris": google })).await;
        assert_eq!(google.status, StatusCode::CREATED);
        let too_many: Vec<String> = (0..17)
            .map(|i| format!("https://c.example.com/{i}"))
            .collect();
        let too_many = register_client(&app, json!({ "redirect_uris": too_many })).await;
        assert_eq!(too_many.json()["error"], "invalid_redirect_uri");

        let loopback = register_client(
            &app,
            json!({ "redirect_uris": ["http://localhost:3000/cb", "http://127.0.0.1:8080/cb"] }),
        )
        .await;
        assert_eq!(loopback.status, StatusCode::CREATED);
        assert_eq!(loopback.json()["token_endpoint_auth_method"], "none");
        assert!(loopback.json().get("client_secret").is_none());

        for _ in 2..MAX_REGS {
            assert_eq!(public_client(&app).await.len(), 43);
        }
        let capped = register_client(&app, json!({ "redirect_uris": [REDIRECT] })).await;
        assert_eq!(capped.status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn confidential_client_must_present_secret() {
        let (app, _env) = app().await;
        let reply = register_client(
            &app,
            json!({ "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "client_secret_basic" }),
        )
        .await;
        let client_id = reply.json()["client_id"].as_str().unwrap().to_string();
        let secret = reply.json()["client_secret"].as_str().unwrap().to_string();
        let (verifier, challenge) = pkce();

        let code = obtain_code(&app, &client_id, &challenge).await;
        let no_secret = exchange(&app, &client_id, &code, &verifier).await;
        assert_eq!(no_secret.json()["error"], "invalid_client");

        let code = obtain_code(&app, &client_id, &challenge).await;
        let basic = STANDARD.encode(format!("{client_id}:{secret}"));
        let mut req = form(
            "/mcpqa/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", &verifier),
            ],
        );
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Basic {basic}").parse().unwrap(),
        );
        let ok = send(&app, req).await;
        assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
        let refresh = ok.json()["refresh_token"].as_str().unwrap().to_string();

        let unauthenticated = send(&app, revoke_form(&client_id, &refresh, None)).await;
        assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
        let mut req = revoke_form(&client_id, &refresh, None);
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("basic {basic}").parse().unwrap(),
        );
        assert_eq!(send(&app, req).await.status, StatusCode::OK);
        let refused = send(
            &app,
            form(
                "/mcpqa/oauth/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh),
                    ("client_id", &client_id),
                    ("client_secret", &secret),
                ],
            ),
        )
        .await;
        assert_eq!(refused.json()["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn removing_mcp_token_revokes_derived_tokens() {
        let (app, env) = app().await;
        let client_id = public_client(&app).await;
        let (verifier, challenge) = pkce();
        let code = obtain_code(&app, &client_id, &challenge).await;
        let tokens = exchange(&app, &client_id, &code, &verifier).await.json();
        let bearer = format!("Bearer {}", tokens["access_token"].as_str().unwrap());

        let rotated =
            super::super::mount(settings(&["beta"], Some(ORIGIN)), env.app_context.clone());
        let reply = send(
            &rotated,
            mcp_post(Some(("authorization", &bearer)), "/mcpqa/mcp"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let refreshed = send(
            &rotated,
            form(
                "/mcpqa/oauth/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
                    ("client_id", &client_id),
                ],
            ),
        )
        .await;
        assert_eq!(refreshed.json()["error"], "invalid_grant");
    }
}
