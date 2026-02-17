//! HTTP/3 probe over QUIC for h3_only upstreams.
//!
//! The probe performs a lightweight HTTP/3 GET with a small Range request and:
//! - returns liveness (`is_alive`)
//! - extracts file size from Content-Range/Content-Length
//! - learns the upstream leaf certificate hash (SHA-256 over DER)

use axum::http;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

/// HTTP/3 probe result
#[derive(Debug, Clone)]
pub struct H3ProbeResult {
    pub is_alive: bool,
    pub file_size: Option<u64>,
    /// SHA-256 hex of leaf cert DER
    pub observed_cert_hash: Option<String>,
}

/// Certificate verification policy
#[derive(Debug, Clone)]
pub enum CertVerifyPolicy {
    /// Require a valid certificate using a root store.
    ValidCert,
    /// Skip verification, capture hash.
    Trust,
    /// Verify against pinned hash.
    PinnedHex([u8; 32]),
}

#[derive(Debug, Default, Clone)]
struct CapturedCert(Arc<Mutex<Option<Vec<u8>>>>);

impl CapturedCert {
    fn set(&self, cert: &CertificateDer<'_>) {
        let mut lock = self.0.lock().expect("poisoned cert capture mutex");
        *lock = Some(cert.as_ref().to_vec());
    }

    fn take(&self) -> Option<Vec<u8>> {
        self.0.lock().ok().and_then(|g| g.clone())
    }
}

fn default_supported_schemes() -> Vec<rustls::SignatureScheme> {
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

impl TrustingVerifier {
    fn new(captured: CapturedCert) -> Self {
        Self { captured }
    }
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
        default_supported_schemes()
    }
}

#[derive(Debug)]
struct PinnedVerifier {
    captured: CapturedCert,
    pinned: [u8; 32],
}

impl PinnedVerifier {
    fn new(captured: CapturedCert, pinned: [u8; 32]) -> Self {
        Self { captured, pinned }
    }
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
        let observed = Sha256::digest(end_entity.as_ref());
        if observed.as_slice() == self.pinned {
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
        default_supported_schemes()
    }
}

fn parse_total_size_from_content_range(range_value: &str) -> Option<u64> {
    // Expected: "bytes 0-255/1048576" or "bytes 0-255/*"
    let total = range_value.split('/').nth(1)?.trim();
    if total == "*" {
        return None;
    }
    total.parse().ok()
}

fn extract_file_size_from_headers(headers: &http::HeaderMap) -> Option<u64> {
    if let Some(v) = headers.get(http::header::CONTENT_RANGE)
        && let Ok(s) = v.to_str()
        && let Some(total) = parse_total_size_from_content_range(s)
    {
        return Some(total);
    }
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

fn cert_hash_hex_from_der(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    hex::encode(digest)
}

fn extract_leaf_cert_der_from_peer_identity(conn: &quinn::Connection) -> Option<Vec<u8>> {
    let identity = conn.peer_identity()?;

    // Quinn's rustls backend typically exposes a Vec<CertificateDer<'static>>.
    if let Some(certs) = identity.downcast_ref::<Vec<CertificateDer<'static>>>() {
        return certs.first().map(|c| c.as_ref().to_vec());
    }

    // Fallback for potential older/alternate types.
    if let Some(certs) = identity.downcast_ref::<Vec<Vec<u8>>>() {
        return certs.first().cloned();
    }

    None
}

async fn resolve_first_addr(host: &str, port: u16) -> Result<SocketAddr, Box<dyn Error>> {
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .next()
        .ok_or_else(|| format!("DNS lookup returned no addresses for {host}:{port}").into())
}

fn build_quinn_client_config(
    policy: &CertVerifyPolicy,
    captured: &CapturedCert,
) -> Result<quinn::ClientConfig, Box<dyn Error>> {
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
            .with_custom_certificate_verifier(Arc::new(TrustingVerifier::new(captured.clone())))
            .with_no_client_auth(),
        CertVerifyPolicy::PinnedHex(pinned) => rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(
                captured.clone(),
                *pinned,
            )))
            .with_no_client_auth(),
    };

    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(2).try_into()?));
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

/// Probe an HTTPS URL over HTTP/3
pub async fn probe_h3(
    url: &str,
    policy: CertVerifyPolicy,
    timeout_secs: u64,
) -> Result<H3ProbeResult, Box<dyn Error>> {
    let url = Url::parse(url)?;
    if url.scheme() != "https" {
        return Err(format!("probe_h3 requires https URL, got: {}", url).into());
    }

    let host = url
        .host_str()
        .ok_or_else(|| "URL missing host".to_string())?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    let path = {
        let mut p = url.path().to_string();
        if p.is_empty() {
            p.push('/');
        }
        if let Some(q) = url.query() {
            p.push('?');
            p.push_str(q);
        }
        p
    };

    let deadline = Duration::from_secs(timeout_secs.max(1));
    let captured = CapturedCert::default();

    let fut = async {
        let addr = resolve_first_addr(&host, port).await?;

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(build_quinn_client_config(&policy, &captured)?);

        let connecting = endpoint.connect(addr, &host)?;
        let conn = connecting.await?;

        // Extract observed cert hash as early as possible.
        let observed_cert_der =
            extract_leaf_cert_der_from_peer_identity(&conn).or_else(|| captured.take());
        let observed_cert_hash = observed_cert_der.as_deref().map(cert_hash_hex_from_der);

        let h3_conn = h3_quinn::Connection::new(conn);

        let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;
        tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method("GET")
            .uri(&path)
            .header(http::header::HOST, host.clone())
            .header(http::header::RANGE, "bytes=0-255")
            .body(())?;

        let mut stream = send_request.send_request(req).await?;
        let resp = stream.recv_response().await?;
        let is_alive = resp.status().is_success();
        let file_size = if is_alive {
            extract_file_size_from_headers(resp.headers())
        } else {
            None
        };

        // Drain a small amount of data to complete the exchange quickly.
        // We don't need the payload, only the headers/status.
        let _ = stream.recv_data().await;

        Ok::<_, Box<dyn Error>>(H3ProbeResult {
            is_alive,
            file_size,
            observed_cert_hash,
        })
    };

    match tokio::time::timeout(deadline, fut).await {
        Ok(r) => r,
        Err(_) => Ok(H3ProbeResult {
            is_alive: false,
            file_size: None,
            observed_cert_hash: captured.take().as_deref().map(cert_hash_hex_from_der),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== parse_total_size_from_content_range tests =====

    #[test]
    fn test_parse_content_range_standard() {
        assert_eq!(
            parse_total_size_from_content_range("bytes 0-255/1048576"),
            Some(1048576)
        );
    }

    #[test]
    fn test_parse_content_range_unknown_total() {
        assert_eq!(parse_total_size_from_content_range("bytes 0-255/*"), None);
    }

    #[test]
    fn test_parse_content_range_large_file() {
        assert_eq!(
            parse_total_size_from_content_range("bytes 0-255/10737418240"),
            Some(10_737_418_240) // 10 GB
        );
    }

    #[test]
    fn test_parse_content_range_zero_size() {
        assert_eq!(parse_total_size_from_content_range("bytes 0-0/0"), Some(0));
    }

    #[test]
    fn test_parse_content_range_no_slash() {
        assert_eq!(parse_total_size_from_content_range("bytes 0-255"), None);
    }

    #[test]
    fn test_parse_content_range_invalid_total() {
        assert_eq!(
            parse_total_size_from_content_range("bytes 0-255/notanumber"),
            None
        );
    }

    // ===== extract_file_size_from_headers tests =====

    #[test]
    fn test_extract_size_from_content_range_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_RANGE,
            "bytes 0-255/1048576".parse().unwrap(),
        );
        assert_eq!(extract_file_size_from_headers(&headers), Some(1048576));
    }

    #[test]
    fn test_extract_size_from_content_length_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "2048".parse().unwrap());
        assert_eq!(extract_file_size_from_headers(&headers), Some(2048));
    }

    #[test]
    fn test_extract_size_content_range_takes_priority() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_RANGE,
            "bytes 0-255/1048576".parse().unwrap(),
        );
        headers.insert(http::header::CONTENT_LENGTH, "256".parse().unwrap());
        // Content-Range total should take priority over Content-Length
        assert_eq!(extract_file_size_from_headers(&headers), Some(1048576));
    }

    #[test]
    fn test_extract_size_no_headers() {
        let headers = http::HeaderMap::new();
        assert_eq!(extract_file_size_from_headers(&headers), None);
    }

    #[test]
    fn test_extract_size_unknown_content_range_falls_back_to_content_length() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_RANGE,
            "bytes 0-255/*".parse().unwrap(),
        );
        headers.insert(http::header::CONTENT_LENGTH, "256".parse().unwrap());
        // Content-Range has *, so falls through to Content-Length
        assert_eq!(extract_file_size_from_headers(&headers), Some(256));
    }

    // ===== cert_hash_hex_from_der tests =====

    #[test]
    fn test_cert_hash_hex_from_der_known_value() {
        // SHA-256 of empty bytes is a known constant
        let empty_hash = cert_hash_hex_from_der(&[]);
        assert_eq!(
            empty_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 of empty input should match known constant"
        );
    }

    #[test]
    fn test_cert_hash_hex_from_der_deterministic() {
        let data = b"test certificate DER data";
        let hash1 = cert_hash_hex_from_der(data);
        let hash2 = cert_hash_hex_from_der(data);
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_eq!(hash1.len(), 64, "SHA-256 hex should be 64 characters");
    }

    #[test]
    fn test_cert_hash_hex_is_lowercase() {
        let data = b"some cert data";
        let hash = cert_hash_hex_from_der(data);
        assert_eq!(
            hash,
            hash.to_ascii_lowercase(),
            "Hash should be lowercase hex"
        );
    }

    // ===== CertVerifyPolicy enum tests =====

    #[test]
    fn test_cert_verify_policy_debug() {
        // Verify the enum variants are constructable
        let _valid = CertVerifyPolicy::ValidCert;
        let _trust = CertVerifyPolicy::Trust;
        let _pinned = CertVerifyPolicy::PinnedHex([0u8; 32]);
    }

    // ===== H3ProbeResult tests =====

    #[test]
    fn test_h3_probe_result_clone() {
        let result = H3ProbeResult {
            is_alive: true,
            file_size: Some(1024),
            observed_cert_hash: Some("abcdef".to_string()),
        };
        let cloned = result.clone();
        assert_eq!(cloned.is_alive, true);
        assert_eq!(cloned.file_size, Some(1024));
        assert_eq!(cloned.observed_cert_hash, Some("abcdef".to_string()));
    }

    #[test]
    fn test_h3_probe_result_no_cert_hash() {
        let result = H3ProbeResult {
            is_alive: false,
            file_size: None,
            observed_cert_hash: None,
        };
        assert!(!result.is_alive);
        assert!(result.file_size.is_none());
        assert!(result.observed_cert_hash.is_none());
    }
}
