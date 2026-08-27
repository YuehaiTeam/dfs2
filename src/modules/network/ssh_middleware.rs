//! Reqwest middleware that tunnels HTTP requests through SSH port-forwarding.
//!
//! URL format (all SSH credentials live in the **fragment** because reqwest
//! strips URL userinfo):
//!
//! ```text
//! ssh+http://ssh_host:ssh_port/http_path?http_query
//!     #user=<ssh_user>&pass=<ssh_pass>&fingerprint=<hex SHA-256>
//!      &internal_host=<tunnel target host, default "tunnel">
//!      &internal_port=<tunnel target port, default 80>
//! ```
//!
//! Non-`ssh+http` requests are passed through to the next middleware unchanged.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use reqwest_middleware::{Middleware, Next};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::AbortHandle;
use tracing::{debug, warn};

// ====================================================================
// SSH Handler — host key fingerprint verification
// ====================================================================

pub(crate) struct SshHandler {
    expected_fingerprint: String, // hex-encoded SHA-256, always required
}

#[async_trait]
impl russh::client::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(russh::keys::HashAlg::Sha256);
        let actual_hex: String = fp.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let expected_norm = normalize_hex(&self.expected_fingerprint);

        let ok = actual_hex == expected_norm;
        if !ok {
            warn!(
                expected = %self.expected_fingerprint,
                actual_hex = %actual_hex,
                "SSH host key fingerprint mismatch"
            );
        }
        Ok(ok)
    }
}

/// Strip non-hex characters (colons, spaces, …) and lowercase.
pub(crate) fn normalize_hex(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

// ====================================================================
// URL parsing
// ====================================================================

pub(crate) struct SshUrlParts {
    pub(crate) ssh_user: String,
    pub(crate) ssh_pass: String,
    pub(crate) ssh_host: String,
    pub(crate) ssh_port: u16,
    pub(crate) fingerprint: String, // required
    pub(crate) internal_host: String,
    pub(crate) internal_port: u16,
    /// e.g. "/api/v1?foo=bar"
    pub(crate) http_path_and_query: String,
}

impl SshUrlParts {
    /// Build the canonical pool key (host lowercased, fingerprint normalised).
    fn pool_key(&self) -> PoolKey {
        PoolKey::new(
            &self.ssh_host,
            self.ssh_port,
            &self.ssh_user,
            &self.ssh_pass,
            &self.fingerprint,
        )
    }

    /// HTTP `Host` header value.
    fn http_host_header(&self) -> String {
        let host_part = if self.internal_host.contains(':') {
            format!("[{}]", self.internal_host)
        } else {
            self.internal_host.clone()
        };
        if self.internal_port == 80 {
            host_part
        } else {
            format!("{}:{}", host_part, self.internal_port)
        }
    }

    /// Human-readable target for error messages.
    fn ssh_target(&self) -> String {
        format!("{}@{}:{}", self.ssh_user, self.ssh_host, self.ssh_port)
    }
}

fn parse_ssh_url(url: &reqwest::Url) -> anyhow::Result<SshUrlParts> {
    anyhow::ensure!(
        url.scheme() == "ssh+http",
        "expected scheme 'ssh+http', got '{}'",
        url.scheme()
    );

    let raw_host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing SSH host in URL"))?;
    // Strip IPv6 brackets: url crate returns "[::1]" for non-special schemes
    let ssh_host = raw_host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw_host)
        .to_string();
    let ssh_port = url.port().unwrap_or(22);
    anyhow::ensure!(ssh_port > 0, "invalid ssh_port 0 in URL");

    let http_path_and_query = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };

    // Fragment: user=xxx&pass=xxx&fingerprint=xxx&internal_host=xxx&internal_port=xxx
    let frag_str = url.fragment().unwrap_or("");
    let mut frag: HashMap<&str, String> = HashMap::new();
    for pair in frag_str.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            frag.insert(k, percent_decode(v)?);
        }
    }

    // user is REQUIRED (in fragment, not URL userinfo — reqwest strips userinfo)
    let ssh_user = frag
        .get("user")
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing required 'user' in URL fragment"))?;

    let ssh_pass = frag.get("pass").cloned().unwrap_or_default();

    // fingerprint is REQUIRED
    let fingerprint = frag
        .get("fingerprint")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing required 'fingerprint' in URL fragment for {}:{}",
                ssh_host,
                ssh_port
            )
        })?;
    let fp_norm = normalize_hex(fingerprint);
    anyhow::ensure!(
        fp_norm.len() == 64,
        "fingerprint must be 64 hex chars (SHA-256), got {} chars from '{}'",
        fp_norm.len(),
        fingerprint
    );

    let internal_host = frag
        .get("internal_host")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| "tunnel".to_string());

    let internal_port: u16 = match frag.get("internal_port") {
        Some(s) => s
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid internal_port '{s}' in URL fragment"))?,
        None => 80,
    };
    anyhow::ensure!(internal_port > 0, "invalid internal_port 0 in URL fragment");

    Ok(SshUrlParts {
        ssh_user,
        ssh_pass,
        ssh_host,
        ssh_port,
        fingerprint: fp_norm,
        internal_host,
        internal_port,
        http_path_and_query,
    })
}

/// Minimal percent-decoding for URL fragment components.
pub(crate) fn percent_decode(input: &str) -> anyhow::Result<String> {
    let mut bytes = Vec::with_capacity(input.len());
    let src = input.as_bytes();
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'%'
            && i + 2 < src.len()
            && let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&src[i + 1..i + 3]).unwrap_or(""), 16)
        {
            bytes.push(byte);
            i += 3;
            continue;
        }
        bytes.push(src[i]);
        i += 1;
    }
    String::from_utf8(bytes)
        .map_err(|e| anyhow::anyhow!("URL percent-decoded value is not valid UTF-8: {e}"))
}

// ====================================================================
// Connection pool types
// ====================================================================

pub(crate) const MAX_POOL_SIZE: usize = 32;
pub(crate) const MAX_CONNECTIONS_PER_TARGET: usize = 4;
pub(crate) const MAX_STREAMS_PER_SESSION: usize = 4;

const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_AUTH_TIMEOUT: Duration = Duration::from_secs(15);
const SSH_CHANNEL_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP_SEND_TIMEOUT: Duration = Duration::from_secs(30);
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(60);
const REAPER_INTERVAL: Duration = Duration::from_secs(15);

/// Hop-by-hop headers that MUST NOT be forwarded through the tunnel.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct PoolKey {
    host: String,
    port: u16,
    user: String,
    fingerprint: String,
    credential_hash: [u8; 32],
}

impl PoolKey {
    pub(crate) fn new(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        fingerprint: &str,
    ) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            port,
            user: user.to_string(),
            fingerprint: normalize_hex(fingerprint),
            credential_hash: Sha256::digest(password.as_bytes()).into(),
        }
    }
}

pub(crate) struct SshConnection {
    id: u64,
    handle: Arc<russh::client::Handle<SshHandler>>,
    active_streams: AtomicUsize,
    last_used: StdMutex<Instant>,
    _permit: OwnedSemaphorePermit,
}

impl SshConnection {
    fn touch(&self) {
        if let Ok(mut last_used) = self.last_used.lock() {
            *last_used = Instant::now();
        }
    }

    fn idle_for(&self, now: Instant) -> Duration {
        self.last_used
            .lock()
            .map(|last_used| now.saturating_duration_since(*last_used))
            .unwrap_or_default()
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }
}

pub(crate) struct SshLease {
    connection: Arc<SshConnection>,
    notify: Arc<Notify>,
}

impl SshLease {
    pub(crate) fn handle(&self) -> Arc<russh::client::Handle<SshHandler>> {
        Arc::clone(&self.connection.handle)
    }

    pub(crate) fn connection_id(&self) -> u64 {
        self.connection.id
    }

    pub(crate) fn downgrade_connection(&self) -> Weak<SshConnection> {
        Arc::downgrade(&self.connection)
    }
}

impl Drop for SshLease {
    fn drop(&mut self) {
        self.connection
            .active_streams
            .fetch_sub(1, Ordering::AcqRel);
        self.connection.touch();
        self.notify.notify_waiters();
    }
}

/// RAII guard — aborts a spawned task on drop.
struct AbortOnDrop(AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Default)]
struct SshPoolState {
    connections: HashMap<PoolKey, Vec<Arc<SshConnection>>>,
    creating: HashMap<PoolKey, usize>,
}

pub(crate) struct SshPoolInner {
    state: Mutex<SshPoolState>,
    permits: Arc<Semaphore>,
    notify: Arc<Notify>,
    next_connection_id: AtomicU64,
    pub(crate) idle_timeout: Duration,
}

impl SshPoolInner {
    pub(crate) fn new(idle_timeout: Duration) -> Arc<Self> {
        let pool = Arc::new(Self {
            state: Mutex::new(SshPoolState::default()),
            permits: Arc::new(Semaphore::new(MAX_POOL_SIZE)),
            notify: Arc::new(Notify::new()),
            next_connection_id: AtomicU64::new(1),
            idle_timeout,
        });
        Self::spawn_reaper(&pool);
        pool
    }

    fn spawn_reaper(pool: &Arc<Self>) {
        let weak = Arc::downgrade(pool);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let mut interval = tokio::time::interval(REAPER_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let Some(pool) = weak.upgrade() else {
                        break;
                    };
                    pool.reap().await;
                }
            });
        }
    }

    fn prune_locked(&self, state: &mut SshPoolState, now: Instant) {
        state.connections.retain(|_, connections| {
            connections.retain(|connection| {
                if connection.is_closed() {
                    return false;
                }
                let active = connection.active_streams.load(Ordering::Acquire);
                active > 0 || connection.idle_for(now) < self.idle_timeout
            });
            !connections.is_empty()
        });
    }

    async fn reap(&self) {
        let mut state = self.state.lock().await;
        self.prune_locked(&mut state, Instant::now());
        drop(state);
        self.notify.notify_waiters();
    }

    async fn finish_creation(&self, key: &PoolKey) {
        let mut state = self.state.lock().await;
        if let Some(creating) = state.creating.get_mut(key) {
            *creating = creating.saturating_sub(1);
            if *creating == 0 {
                state.creating.remove(key);
            }
        }
        drop(state);
        self.notify.notify_waiters();
    }

    pub(crate) async fn evict_connection(&self, key: &PoolKey, connection_id: u64) {
        let mut state = self.state.lock().await;
        if let Some(connections) = state.connections.get_mut(key) {
            connections.retain(|connection| connection.id != connection_id);
            if connections.is_empty() {
                state.connections.remove(key);
            }
        }
        drop(state);
        self.notify.notify_waiters();
    }

    pub(crate) async fn evict_target(&self, key: &PoolKey) {
        let mut state = self.state.lock().await;
        state.connections.remove(key);
        drop(state);
        self.notify.notify_waiters();
    }
}

// ====================================================================
// SSH connect helper
// ====================================================================

pub(crate) async fn ssh_connect(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    fingerprint: &str,
) -> anyhow::Result<russh::client::Handle<SshHandler>> {
    let config = Arc::new(russh::client::Config::default());
    let handler = SshHandler {
        expected_fingerprint: fingerprint.to_string(),
    };

    debug!(host, port, user, "SSH connecting");
    let mut session = tokio::time::timeout(
        SSH_CONNECT_TIMEOUT,
        russh::client::connect(config, (host, port), handler),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SSH connect timeout to {user}@{host}:{port}"))??;

    let auth_fut = async {
        if pass.is_empty() {
            anyhow::ensure!(
                session.authenticate_none(user).await?,
                "SSH none-auth failed for {user}@{host}:{port}"
            );
        } else {
            anyhow::ensure!(
                session.authenticate_password(user, pass).await?,
                "SSH password-auth failed for {user}@{host}:{port}"
            );
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(SSH_AUTH_TIMEOUT, auth_fut)
        .await
        .map_err(|_| anyhow::anyhow!("SSH auth timeout for {user}@{host}:{port}"))??;

    debug!(host, port, user, "SSH authenticated");
    Ok(session)
}

/// Conservative check: only known "session is dead" errors trigger
/// reconnection.  Everything else (policy rejection, auth failure, …)
/// is treated as permanent.
pub(crate) fn is_recoverable_ssh_error(err: &russh::Error) -> bool {
    matches!(
        err,
        russh::Error::Disconnect | russh::Error::SendError | russh::Error::IO(_)
    )
}

// ====================================================================
// SshMiddleware
// ====================================================================

pub struct SshMiddleware {
    inner: Arc<SshPoolInner>,
}

impl SshMiddleware {
    #[allow(dead_code)]
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            inner: SshPoolInner::new(idle_timeout),
        }
    }

    /// Create a middleware sharing an existing SSH connection pool.
    pub(crate) fn with_pool(pool: Arc<SshPoolInner>) -> Self {
        Self { inner: pool }
    }

    /// Get a pooled session or create a new one.
    ///
    /// When a connection's active streams reach [`MAX_STREAMS_PER_SESSION`],
    /// a new SSH connection is opened to spread load across connections.
    pub(crate) async fn get_session(
        &self,
        parts: &SshUrlParts,
    ) -> Result<SshLease, reqwest_middleware::Error> {
        let key = parts.pool_key();
        loop {
            let notified = self.inner.notify.notified();
            let should_create = {
                let mut state = self.inner.state.lock().await;
                self.inner.prune_locked(&mut state, Instant::now());

                if let Some(connection) = state
                    .connections
                    .get(&key)
                    .and_then(|connections| {
                        connections.iter().find(|connection| {
                            !connection.is_closed()
                                && connection.active_streams.load(Ordering::Acquire)
                                    < MAX_STREAMS_PER_SESSION
                        })
                    })
                    .cloned()
                {
                    connection.active_streams.fetch_add(1, Ordering::AcqRel);
                    connection.touch();
                    return Ok(SshLease {
                        connection,
                        notify: Arc::clone(&self.inner.notify),
                    });
                }

                let existing = state.connections.get(&key).map_or(0, Vec::len);
                let creating = state.creating.get(&key).copied().unwrap_or(0);
                if existing + creating < MAX_CONNECTIONS_PER_TARGET {
                    *state.creating.entry(key.clone()).or_default() += 1;
                    true
                } else {
                    false
                }
            };

            if !should_create {
                notified.await;
                continue;
            }

            let permit = match Arc::clone(&self.inner.permits).acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    self.inner.finish_creation(&key).await;
                    return Err(mw_err("SSH connection pool is closed".to_string()));
                }
            };

            let handle = match ssh_connect(
                &parts.ssh_host,
                parts.ssh_port,
                &parts.ssh_user,
                &parts.ssh_pass,
                &parts.fingerprint,
            )
            .await
            {
                Ok(handle) => Arc::new(handle),
                Err(error) => {
                    drop(permit);
                    self.inner.finish_creation(&key).await;
                    return Err(mw_err(format!(
                        "SSH connect to {} failed: {error}",
                        parts.ssh_target()
                    )));
                }
            };

            let connection = Arc::new(SshConnection {
                id: self
                    .inner
                    .next_connection_id
                    .fetch_add(1, Ordering::Relaxed),
                handle,
                active_streams: AtomicUsize::new(1),
                last_used: StdMutex::new(Instant::now()),
                _permit: permit,
            });

            {
                let mut state = self.inner.state.lock().await;
                if let Some(creating) = state.creating.get_mut(&key) {
                    *creating = creating.saturating_sub(1);
                    if *creating == 0 {
                        state.creating.remove(&key);
                    }
                }
                state
                    .connections
                    .entry(key.clone())
                    .or_default()
                    .push(Arc::clone(&connection));
            }
            self.inner.notify.notify_waiters();

            return Ok(SshLease {
                connection,
                notify: Arc::clone(&self.inner.notify),
            });
        }
    }

    /// Open a direct-tcpip channel, reconnecting **once** if the session
    /// appears dead.
    async fn open_channel(
        &self,
        parts: &SshUrlParts,
    ) -> Result<(russh::Channel<russh::client::Msg>, SshLease), reqwest_middleware::Error> {
        let lease = self.get_session(parts).await?;
        let handle = lease.handle();

        let ch_result = tokio::time::timeout(
            SSH_CHANNEL_TIMEOUT,
            handle.channel_open_direct_tcpip(
                parts.internal_host.as_str(),
                parts.internal_port as u32,
                "127.0.0.1",
                0u32,
            ),
        )
        .await;

        match ch_result {
            Ok(Ok(ch)) => return Ok((ch, lease)),
            Ok(Err(ref err)) if !is_recoverable_ssh_error(err) => {
                return Err(reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                    "SSH channel to {}:{} via {} rejected: {err}",
                    parts.internal_host,
                    parts.internal_port,
                    parts.ssh_target()
                )));
            }
            Ok(Err(err)) => {
                debug!(err = %err, target = %parts.ssh_target(),
                       "SSH channel failed (recoverable), reconnecting");
            }
            Err(_) => {
                debug!(target = %parts.ssh_target(), "SSH channel open timed out, reconnecting");
            }
        }

        // ── reconnect once ──
        let failed_connection_id = lease.connection_id();
        drop(lease);
        self.inner
            .evict_connection(&parts.pool_key(), failed_connection_id)
            .await;

        let lease = self.get_session(parts).await?;
        let handle = lease.handle();
        let ch_result = tokio::time::timeout(
            SSH_CHANNEL_TIMEOUT,
            handle.channel_open_direct_tcpip(
                parts.internal_host.as_str(),
                parts.internal_port as u32,
                "127.0.0.1",
                0u32,
            ),
        )
        .await;

        let ch = match ch_result {
            Ok(Ok(channel)) => channel,
            Ok(Err(error)) => {
                let connection_id = lease.connection_id();
                drop(lease);
                self.inner
                    .evict_connection(&parts.pool_key(), connection_id)
                    .await;
                return Err(mw_err(format!(
                    "SSH channel to {}:{} via {} failed after reconnect: {error}",
                    parts.internal_host,
                    parts.internal_port,
                    parts.ssh_target()
                )));
            }
            Err(_) => {
                let connection_id = lease.connection_id();
                drop(lease);
                self.inner
                    .evict_connection(&parts.pool_key(), connection_id)
                    .await;
                return Err(mw_err(format!(
                    "SSH channel to {}:{} via {} timed out after reconnect",
                    parts.internal_host,
                    parts.internal_port,
                    parts.ssh_target()
                )));
            }
        };

        Ok((ch, lease))
    }

    // ---- HTTP-over-SSH -----------------------------------------------

    async fn ssh_request(
        &self,
        req: reqwest::Request,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        let parts = parse_ssh_url(req.url()).map_err(reqwest_middleware::Error::Middleware)?;
        let method = req.method().clone();
        let req_headers = req.headers().clone();

        let body_bytes: Bytes = match req.body() {
            None => Bytes::new(),
            Some(b) => match b.as_bytes() {
                Some(slice) => Bytes::copy_from_slice(slice),
                None => {
                    return Err(reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                        "SSH tunnel to {} does not support streaming request bodies",
                        parts.ssh_target()
                    )));
                }
            },
        };

        let key = parts.pool_key();

        // 1. Open SSH channel
        let (channel, lease) = self.open_channel(&parts).await?;
        let connection_id = lease.connection_id();
        let io = TokioIo::new(channel.into_stream());

        // 2. HTTP/1.1 handshake
        let handshake_result = tokio::time::timeout(
            HTTP_HANDSHAKE_TIMEOUT,
            hyper::client::conn::http1::handshake(io),
        )
        .await;
        let (mut sender, conn) = match handshake_result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                drop(lease);
                self.inner.evict_connection(&key, connection_id).await;
                return Err(mw_err(format!(
                    "HTTP/1.1 handshake over SSH to {} failed: {error}",
                    parts.ssh_target()
                )));
            }
            Err(_) => {
                drop(lease);
                self.inner.evict_connection(&key, connection_id).await;
                return Err(mw_err(format!(
                    "HTTP/1.1 handshake timeout over SSH to {}",
                    parts.ssh_target()
                )));
            }
        };

        let conn_task = tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(err = %e, "SSH HTTP connection driver finished");
            }
        });
        let abort_guard = AbortOnDrop(conn_task.abort_handle());

        // 3. Build the HTTP request
        let host_hdr = parts.http_host_header();
        let mut builder = http::Request::builder()
            .method(method.as_str())
            .uri(&parts.http_path_and_query)
            .header("host", &host_hdr);

        for (name, value) in req_headers.iter() {
            let lc = name.as_str();
            if lc == "host" || HOP_BY_HOP_HEADERS.contains(&lc) {
                continue;
            }
            builder = builder.header(name, value);
        }

        let hyper_req = builder
            .body(http_body_util::Full::new(body_bytes))
            .map_err(|e| mw_err(format!("failed to build HTTP request: {e}")))?;

        // 4. Send request
        let send_result =
            tokio::time::timeout(HTTP_SEND_TIMEOUT, sender.send_request(hyper_req)).await;
        let hyper_resp = match send_result {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                drop(lease);
                self.inner.evict_connection(&key, connection_id).await;
                return Err(mw_err(format!(
                    "HTTP send over SSH to {}{} failed: {error}",
                    parts.ssh_target(),
                    parts.http_path_and_query
                )));
            }
            Err(_) => {
                drop(lease);
                self.inner.evict_connection(&key, connection_id).await;
                return Err(mw_err(format!(
                    "HTTP send timeout over SSH to {}{}",
                    parts.ssh_target(),
                    parts.http_path_and_query
                )));
            }
        };

        let (resp_parts, body) = hyper_resp.into_parts();

        // 5. Stream response body — captures keep the SSH session, pool
        //    guard, and conn driver alive until the body is fully consumed
        //    or dropped.
        let pool = Arc::clone(&self.inner);
        let stream_key = key.clone();
        let byte_stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>> =
            Box::pin(async_stream::try_stream! {
                let _lease = lease;
                let _abort = abort_guard;

                let mut body = body;
                loop {
                    match tokio::time::timeout(BODY_READ_TIMEOUT, body.frame()).await {
                        Ok(Some(Ok(frame))) => {
                            if let Ok(data) = frame.into_data()
                                && !data.is_empty() {
                                    yield data;
                                }
                        }
                        Ok(Some(Err(error))) => {
                            pool.evict_connection(&stream_key, connection_id).await;
                            Err::<(), std::io::Error>(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                error.to_string(),
                            ))?;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            pool.evict_connection(&stream_key, connection_id).await;
                            Err::<(), std::io::Error>(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "SSH response body read timed out",
                            ))?;
                        }
                    }
                }
            });

        // 6. Convert to reqwest::Response
        let mut resp_builder = http::Response::builder().status(resp_parts.status);
        for (name, value) in &resp_parts.headers {
            resp_builder = resp_builder.header(name, value);
        }
        let http_resp = resp_builder
            .body(reqwest::Body::wrap_stream(byte_stream))
            .map_err(|e| mw_err(format!("failed to build response: {e}")))?;

        Ok(http_resp.into())
    }
}

pub(crate) fn mw_err(msg: String) -> reqwest_middleware::Error {
    reqwest_middleware::Error::Middleware(anyhow::anyhow!(msg))
}

#[async_trait]
impl Middleware for SshMiddleware {
    async fn handle(
        &self,
        req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        if req.url().scheme() == "ssh+http" {
            self.ssh_request(req).await
        } else {
            next.run(req, extensions).await
        }
    }
}
