//! Reqwest middleware backed by Quinn for `http3://` requests.

use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use futures::Stream;
use reqwest_middleware::{Middleware, Next};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tracing::debug;

use super::ssh_middleware::mw_err;

const MAX_POOL_CONNECTIONS: usize = 32;
const MAX_CONNECTIONS_PER_TARGET: usize = 2;
const MAX_STREAMS_PER_CONNECTION: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(60);
const REAPER_INTERVAL: Duration = Duration::from_secs(15);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CertVerifyPolicy {
    ValidCert,
    Trust,
    PinnedHex([u8; 32]),
}

#[derive(Debug, Default, Clone)]
struct CapturedCert(Arc<StdMutex<Option<Vec<u8>>>>);

impl CapturedCert {
    fn set(&self, cert: &CertificateDer<'_>) {
        if let Ok(mut captured) = self.0.lock() {
            *captured = Some(cert.as_ref().to_vec());
        }
    }

    fn take(&self) -> Option<Vec<u8>> {
        self.0.lock().ok().and_then(|captured| captured.clone())
    }
}

fn supported_signature_schemes() -> Vec<rustls::SignatureScheme> {
    vec![
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        rustls::SignatureScheme::RSA_PSS_SHA256,
        rustls::SignatureScheme::RSA_PSS_SHA384,
        rustls::SignatureScheme::RSA_PSS_SHA512,
        rustls::SignatureScheme::RSA_PKCS1_SHA256,
        rustls::SignatureScheme::RSA_PKCS1_SHA384,
        rustls::SignatureScheme::RSA_PKCS1_SHA512,
        rustls::SignatureScheme::ED25519,
    ]
}

#[derive(Debug)]
struct TrustingVerifier {
    captured: CapturedCert,
}

impl ServerCertVerifier for TrustingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.captured.set(end_entity);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        supported_signature_schemes()
    }
}

#[derive(Debug)]
struct PinnedVerifier {
    captured: CapturedCert,
    pinned: [u8; 32],
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.captured.set(end_entity);
        if Sha256::digest(end_entity.as_ref()).as_slice() == self.pinned {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        supported_signature_schemes()
    }
}

fn cert_hash_hex_from_der(cert_der: &[u8]) -> String {
    hex::encode(Sha256::digest(cert_der))
}

fn extract_leaf_cert_der_from_peer_identity(conn: &quinn::Connection) -> Option<Vec<u8>> {
    let identity = conn.peer_identity()?;
    if let Some(certs) = identity.downcast_ref::<Vec<CertificateDer<'static>>>() {
        return certs.first().map(|cert| cert.as_ref().to_vec());
    }
    identity
        .downcast_ref::<Vec<Vec<u8>>>()
        .and_then(|certs| certs.first().cloned())
}

async fn resolve_first_addr(
    host: &str,
    port: u16,
) -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| format!("DNS lookup returned no addresses for {host}:{port}").into())
}

fn build_quinn_client_config(
    policy: &CertVerifyPolicy,
    captured: &CapturedCert,
) -> Result<quinn::ClientConfig, Box<dyn Error + Send + Sync>> {
    let mut tls = match policy {
        CertVerifyPolicy::ValidCert => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        CertVerifyPolicy::Trust => rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustingVerifier {
                captured: captured.clone(),
            }))
            .with_no_client_auth(),
        CertVerifyPolicy::PinnedHex(pinned) => rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                captured: captured.clone(),
                pinned: *pinned,
            }))
            .with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_tls)))
}

#[derive(Debug, Clone)]
pub struct H3TransportInfo {
    pub observed_cert_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct H3PoolKey {
    host: String,
    port: u16,
    policy: CertVerifyPolicy,
}

struct H3Connection {
    id: u64,
    sender: H3Sender,
    quinn: quinn::Connection,
    observed_cert_hash: Option<String>,
    active_streams: AtomicUsize,
    last_used: StdMutex<Instant>,
    _permit: OwnedSemaphorePermit,
}

impl H3Connection {
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

    fn is_closed(&self) -> bool {
        self.quinn.close_reason().is_some()
    }

    fn close(&self) {
        self.quinn.close(0u32.into(), b"evicted from H3 pool");
    }
}

struct H3Lease {
    connection: Arc<H3Connection>,
    notify: Arc<Notify>,
}

impl H3Lease {
    fn sender(&self) -> H3Sender {
        self.connection.sender.clone()
    }

    fn connection_id(&self) -> u64 {
        self.connection.id
    }

    fn transport_info(&self) -> H3TransportInfo {
        H3TransportInfo {
            observed_cert_hash: self.connection.observed_cert_hash.clone(),
        }
    }
}

impl Drop for H3Lease {
    fn drop(&mut self) {
        self.connection
            .active_streams
            .fetch_sub(1, Ordering::AcqRel);
        self.connection.touch();
        self.notify.notify_waiters();
    }
}

#[derive(Default)]
struct H3PoolState {
    connections: HashMap<H3PoolKey, Vec<Arc<H3Connection>>>,
    creating: HashMap<H3PoolKey, usize>,
}

struct H3PoolInner {
    state: Mutex<H3PoolState>,
    permits: Arc<Semaphore>,
    notify: Arc<Notify>,
    next_connection_id: AtomicU64,
    idle_timeout: Duration,
    ipv4_endpoint: StdMutex<Option<quinn::Endpoint>>,
    ipv6_endpoint: StdMutex<Option<quinn::Endpoint>>,
}

impl H3PoolInner {
    fn new(idle_timeout: Duration) -> Arc<Self> {
        let pool = Arc::new(Self {
            state: Mutex::new(H3PoolState::default()),
            permits: Arc::new(Semaphore::new(MAX_POOL_CONNECTIONS)),
            notify: Arc::new(Notify::new()),
            next_connection_id: AtomicU64::new(1),
            idle_timeout,
            ipv4_endpoint: StdMutex::new(None),
            ipv6_endpoint: StdMutex::new(None),
        });

        let weak = Arc::downgrade(&pool);
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

        pool
    }

    fn prune_locked(&self, state: &mut H3PoolState, now: Instant) {
        state.connections.retain(|_, connections| {
            connections.retain(|connection| {
                let active = connection.active_streams.load(Ordering::Acquire);
                let retain = !connection.is_closed()
                    && (active > 0 || connection.idle_for(now) < self.idle_timeout);
                if !retain {
                    connection.close();
                }
                retain
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

    async fn finish_creation(&self, key: &H3PoolKey) {
        let mut state = self.state.lock().await;
        if let Some(creating) = state.creating.get_mut(key) {
            *creating = creating.saturating_sub(1);
            if *creating == 0 {
                state.creating.remove(key);
            }
        }
    }

    async fn evict_connection(&self, key: &H3PoolKey, connection_id: u64) {
        let mut state = self.state.lock().await;
        if let Some(connections) = state.connections.get_mut(key) {
            connections.retain(|connection| {
                let retain = connection.id != connection_id;
                if !retain {
                    connection.close();
                }
                retain
            });
            if connections.is_empty() {
                state.connections.remove(key);
            }
        }
        drop(state);
        self.notify.notify_waiters();
    }

    async fn get_connection(
        self: &Arc<Self>,
        key: &H3PoolKey,
    ) -> Result<H3Lease, reqwest_middleware::Error> {
        loop {
            let notified = self.notify.notified();
            let should_create = {
                let mut state = self.state.lock().await;
                self.prune_locked(&mut state, Instant::now());

                if let Some(connection) = state.connections.get(key).and_then(|connections| {
                    connections
                        .iter()
                        .filter(|connection| {
                            !connection.is_closed()
                                && connection.active_streams.load(Ordering::Acquire)
                                    < MAX_STREAMS_PER_CONNECTION
                        })
                        .min_by_key(|connection| connection.active_streams.load(Ordering::Acquire))
                        .cloned()
                }) {
                    connection.active_streams.fetch_add(1, Ordering::AcqRel);
                    connection.touch();
                    return Ok(H3Lease {
                        connection,
                        notify: Arc::clone(&self.notify),
                    });
                }

                let existing = state.connections.get(key).map_or(0, Vec::len);
                let creating = state.creating.get(key).copied().unwrap_or(0);
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

            let permit = match Arc::clone(&self.permits).acquire_owned().await {
                Ok(permit) => permit,
                Err(error) => {
                    self.finish_creation(key).await;
                    return Err(mw_err(format!("H3 connection pool closed: {error}")));
                }
            };

            let created = create_connection(
                self.next_connection_id.fetch_add(1, Ordering::Relaxed),
                key,
                permit,
                self.idle_timeout,
                self,
            )
            .await;
            self.finish_creation(key).await;

            match created {
                Ok(connection) => {
                    connection.active_streams.store(1, Ordering::Release);
                    let mut state = self.state.lock().await;
                    state
                        .connections
                        .entry(key.clone())
                        .or_default()
                        .push(Arc::clone(&connection));
                    drop(state);
                    self.notify.notify_waiters();
                    return Ok(H3Lease {
                        connection,
                        notify: Arc::clone(&self.notify),
                    });
                }
                Err(error) => {
                    self.notify.notify_waiters();
                    return Err(error);
                }
            }
        }
    }

    fn endpoint_for(&self, addr: SocketAddr) -> Result<quinn::Endpoint, reqwest_middleware::Error> {
        let endpoints = if addr.is_ipv6() {
            &self.ipv6_endpoint
        } else {
            &self.ipv4_endpoint
        };
        let mut endpoint = endpoints
            .lock()
            .map_err(|_| mw_err("H3 endpoint lock is poisoned".to_string()))?;
        if endpoint.is_none() {
            let bind_addr: SocketAddr = if addr.is_ipv6() {
                "[::]:0".parse().expect("valid IPv6 wildcard address")
            } else {
                "0.0.0.0:0".parse().expect("valid IPv4 wildcard address")
            };
            *endpoint = Some(
                quinn::Endpoint::client(bind_addr)
                    .map_err(|error| mw_err(format!("failed to create H3 endpoint: {error}")))?,
            );
        }
        endpoint
            .as_ref()
            .cloned()
            .ok_or_else(|| mw_err("H3 endpoint was not initialized".to_string()))
    }
}

async fn create_connection(
    id: u64,
    key: &H3PoolKey,
    permit: OwnedSemaphorePermit,
    idle_timeout: Duration,
    pool: &H3PoolInner,
) -> Result<Arc<H3Connection>, reqwest_middleware::Error> {
    let addr = tokio::time::timeout(CONNECT_TIMEOUT, resolve_first_addr(&key.host, key.port))
        .await
        .map_err(|_| {
            mw_err(format!(
                "H3 DNS lookup timed out for {}:{}",
                key.host, key.port
            ))
        })?
        .map_err(|error| {
            mw_err(format!(
                "H3 DNS lookup failed for {}:{}: {error}",
                key.host, key.port
            ))
        })?;

    let captured = CapturedCert::default();
    let mut client_config = build_quinn_client_config(&key.policy, &captured)
        .map_err(|error| mw_err(format!("failed to configure H3 TLS: {error}")))?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        idle_timeout
            .try_into()
            .map_err(|error| mw_err(format!("invalid H3 idle timeout: {error}")))?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(30)));
    client_config.transport_config(Arc::new(transport));

    let endpoint = pool.endpoint_for(addr)?;

    let server_name = key.host.trim_start_matches('[').trim_end_matches(']');
    let connecting = endpoint
        .connect_with(client_config, addr, server_name)
        .map_err(|error| mw_err(format!("failed to start H3 connection: {error}")))?;
    let quinn = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| {
            mw_err(format!(
                "H3 connection timed out for {}:{}",
                key.host, key.port
            ))
        })?
        .map_err(|error| {
            mw_err(format!(
                "H3 connection failed for {}:{}: {error}",
                key.host, key.port
            ))
        })?;

    let observed_cert =
        extract_leaf_cert_der_from_peer_identity(&quinn).or_else(|| captured.take());
    let observed_cert_hash = observed_cert.as_deref().map(cert_hash_hex_from_der);
    let h3_connection = h3_quinn::Connection::new(quinn.clone());
    let (mut driver, sender) = h3::client::new(h3_connection)
        .await
        .map_err(|error| mw_err(format!("failed to initialize H3 connection: {error}")))?;
    tokio::spawn(async move {
        let error = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        debug!(?error, "H3 connection driver closed");
    });

    Ok(Arc::new(H3Connection {
        id,
        sender,
        quinn,
        observed_cert_hash,
        active_streams: AtomicUsize::new(0),
        last_used: StdMutex::new(Instant::now()),
        _permit: permit,
    }))
}

fn parse_pool_key(
    url: &reqwest::Url,
    extensions: &http::Extensions,
) -> Result<H3PoolKey, reqwest_middleware::Error> {
    let host = url
        .host_str()
        .ok_or_else(|| mw_err("http3 URL is missing a host".to_string()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let port = url.port().unwrap_or(443);
    let policy = if let Some(policy) = extensions.get::<CertVerifyPolicy>() {
        policy.clone()
    } else if let Some(cert) = url.fragment().and_then(|fragment| {
        fragment
            .split('&')
            .find_map(|part| part.strip_prefix("cert="))
    }) {
        let normalized: String = cert
            .chars()
            .filter(|character| character.is_ascii_hexdigit())
            .collect();
        let bytes = hex::decode(&normalized)
            .map_err(|error| mw_err(format!("invalid H3 certificate hash: {error}")))?;
        let pinned: [u8; 32] = bytes.try_into().map_err(|_| {
            mw_err(format!(
                "H3 certificate hash must contain 32 bytes, got {}",
                normalized.len() / 2
            ))
        })?;
        CertVerifyPolicy::PinnedHex(pinned)
    } else {
        CertVerifyPolicy::ValidCert
    };

    Ok(H3PoolKey { host, port, policy })
}

fn h3_uri(url: &reqwest::Url) -> Result<http::Uri, reqwest_middleware::Error> {
    let host = url
        .host_str()
        .ok_or_else(|| mw_err("http3 URL is missing a host".to_string()))?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let host_for_uri = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let authority = if url.port().unwrap_or(443) == 443 {
        host_for_uri
    } else {
        format!("{host_for_uri}:{}", url.port().unwrap_or(443))
    };
    let mut path_and_query = url.path().to_string();
    if path_and_query.is_empty() {
        path_and_query.push('/');
    }
    if let Some(query) = url.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }

    http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .map_err(|error| mw_err(format!("failed to build H3 URI: {error}")))
}

pub struct H3Middleware {
    pool: Arc<H3PoolInner>,
}

impl H3Middleware {
    pub fn new() -> Self {
        Self {
            pool: H3PoolInner::new(DEFAULT_IDLE_TIMEOUT),
        }
    }

    async fn request(
        &self,
        req: reqwest::Request,
        extensions: &http::Extensions,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        let key = parse_pool_key(req.url(), extensions)?;
        let uri = h3_uri(req.url())?;
        let method = req.method().clone();
        let headers = req.headers().clone();
        let body = match req.body() {
            None => Bytes::new(),
            Some(body) => body.as_bytes().map(Bytes::copy_from_slice).ok_or_else(|| {
                mw_err("H3 middleware does not support streaming request bodies".to_string())
            })?,
        };

        let lease = self.pool.get_connection(&key).await?;
        let connection_id = lease.connection_id();
        let transport_info = lease.transport_info();
        let mut sender = lease.sender();
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in &headers {
            let name_lower = name.as_str().to_ascii_lowercase();
            if name_lower == "host"
                || matches!(
                    name_lower.as_str(),
                    "connection"
                        | "keep-alive"
                        | "proxy-authenticate"
                        | "proxy-authorization"
                        | "te"
                        | "trailer"
                        | "transfer-encoding"
                        | "upgrade"
                )
            {
                continue;
            }
            builder = builder.header(name, value);
        }
        let request = builder
            .body(())
            .map_err(|error| mw_err(format!("failed to build H3 request: {error}")))?;

        let mut stream =
            match tokio::time::timeout(REQUEST_TIMEOUT, sender.send_request(request)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    drop(lease);
                    self.pool.evict_connection(&key, connection_id).await;
                    return Err(mw_err(format!("failed to send H3 request: {error}")));
                }
                Err(_) => {
                    drop(lease);
                    self.pool.evict_connection(&key, connection_id).await;
                    return Err(mw_err("H3 request send timed out".to_string()));
                }
            };

        if !body.is_empty() {
            match tokio::time::timeout(REQUEST_TIMEOUT, stream.send_data(body)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    drop(lease);
                    self.pool.evict_connection(&key, connection_id).await;
                    return Err(mw_err(format!("failed to send H3 request body: {error}")));
                }
                Err(_) => {
                    drop(lease);
                    self.pool.evict_connection(&key, connection_id).await;
                    return Err(mw_err("H3 request body send timed out".to_string()));
                }
            }
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, stream.finish()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                drop(lease);
                self.pool.evict_connection(&key, connection_id).await;
                return Err(mw_err(format!("failed to finish H3 request: {error}")));
            }
            Err(_) => {
                drop(lease);
                self.pool.evict_connection(&key, connection_id).await;
                return Err(mw_err("H3 request finish timed out".to_string()));
            }
        }

        let response = match tokio::time::timeout(REQUEST_TIMEOUT, stream.recv_response()).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                drop(lease);
                self.pool.evict_connection(&key, connection_id).await;
                return Err(mw_err(format!("failed to receive H3 response: {error}")));
            }
            Err(_) => {
                drop(lease);
                self.pool.evict_connection(&key, connection_id).await;
                return Err(mw_err("H3 response headers timed out".to_string()));
            }
        };
        let (response_parts, ()) = response.into_parts();

        let pool = Arc::clone(&self.pool);
        let stream_key = key.clone();
        let byte_stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>> =
            Box::pin(async_stream::try_stream! {
                let _lease = lease;
                let mut stream = stream;
                loop {
                    match tokio::time::timeout(BODY_READ_TIMEOUT, stream.recv_data()).await {
                        Ok(Ok(Some(mut data))) => {
                            let bytes = data.copy_to_bytes(data.remaining());
                            if !bytes.is_empty() {
                                yield bytes;
                            }
                        }
                        Ok(Ok(None)) => break,
                        Ok(Err(error)) => {
                            pool.evict_connection(&stream_key, connection_id).await;
                            Err::<(), std::io::Error>(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                error.to_string(),
                            ))?;
                        }
                        Err(_) => {
                            pool.evict_connection(&stream_key, connection_id).await;
                            Err::<(), std::io::Error>(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "H3 response body read timed out",
                            ))?;
                        }
                    }
                }
            });

        let mut response_builder = http::Response::builder()
            .status(response_parts.status)
            .version(http::Version::HTTP_3);
        for (name, value) in &response_parts.headers {
            response_builder = response_builder.header(name, value);
        }
        let mut response = response_builder
            .body(reqwest::Body::wrap_stream(byte_stream))
            .map_err(|error| mw_err(format!("failed to build H3 response: {error}")))?;
        response.extensions_mut().insert(transport_info);
        Ok(response.into())
    }
}

impl Default for H3Middleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Middleware for H3Middleware {
    async fn handle(
        &self,
        req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        if req.url().scheme() == "http3" {
            self.request(req, extensions).await
        } else {
            next.run(req, extensions).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_uri_preserves_authority_path_and_query() {
        let url = reqwest::Url::parse("http3://example.com:8443/files/a.bin?part=1#cert=ignored")
            .expect("valid test URL");
        assert_eq!(
            h3_uri(&url).expect("valid H3 URI").to_string(),
            "https://example.com:8443/files/a.bin?part=1"
        );
    }

    #[test]
    fn certificate_fragment_becomes_pinned_policy() {
        let hash = "11".repeat(32);
        let url = reqwest::Url::parse(&format!("http3://example.com/file#cert={hash}"))
            .expect("valid test URL");
        let key = parse_pool_key(&url, &http::Extensions::new()).expect("valid pool key");
        assert_eq!(key.policy, CertVerifyPolicy::PinnedHex([0x11; 32]));
    }

    #[test]
    fn request_extension_overrides_certificate_fragment() {
        let hash = "22".repeat(32);
        let url = reqwest::Url::parse(&format!("http3://example.com/file#cert={hash}"))
            .expect("valid test URL");
        let mut extensions = http::Extensions::new();
        extensions.insert(CertVerifyPolicy::Trust);
        let key = parse_pool_key(&url, &extensions).expect("valid pool key");
        assert_eq!(key.policy, CertVerifyPolicy::Trust);
    }

    #[test]
    fn invalid_certificate_fragment_is_rejected() {
        let url =
            reqwest::Url::parse("http3://example.com/file#cert=abcd").expect("valid test URL");
        assert!(parse_pool_key(&url, &http::Extensions::new()).is_err());
    }
}
