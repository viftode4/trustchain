//! TLS certificate generation from Ed25519 identity.
//!
//! Generates self-signed certificates where the certificate embeds the node's
//! Ed25519 public key as a custom X.509 extension. This enables TLS pubkey
//! pinning: when connecting to a peer whose Ed25519 pubkey is known, the
//! verifier confirms the peer's certificate carries a matching embedded pubkey,
//! preventing impersonation even with self-signed certificates.
//!
//! # Extension format
//!
//! OID: `1.3.6.1.4.1.99999.1` (TrustChain node identity)
//! Value: ASN.1 OCTET STRING wrapping the 32 raw bytes of the Ed25519 pubkey.
//! Encoding: `04 20 <32 bytes>` — total 34 bytes inside the extension's
//! extnValue OCTET STRING.

use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::{Arc, Once};

static INIT_CRYPTO: Once = Once::new();
/// Guard that emits the AcceptAnyCert startup warning exactly once.
static WARN_ACCEPT_ANY_CERT: Once = Once::new();

/// OID for the custom TrustChain identity extension.
/// Arc: 1.3.6.1.4.1.99999.1  (private enterprise, TrustChain node identity)
const TRUSTCHAIN_PUBKEY_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// Ensure the rustls CryptoProvider is installed (once).
fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Encode a 32-byte pubkey as an ASN.1 OCTET STRING: `04 20 <bytes>`.
///
/// This is the value stored inside the extension's extnValue field.
fn encode_pubkey_as_octet_string(pubkey_bytes: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(34);
    buf.push(0x04); // OCTET STRING tag
    buf.push(0x20); // length: 32 bytes
    buf.extend_from_slice(pubkey_bytes);
    buf
}

/// Generate a self-signed TLS certificate and private key.
///
/// The certificate embeds the TrustChain Ed25519 public key as a custom
/// X.509 extension (OID `1.3.6.1.4.1.99999.1`). The TLS key itself is an
/// ECDSA P-256 keypair (required by rustls); the Ed25519 identity is carried
/// out-of-band in the extension so that peers can perform pubkey pinning.
pub fn generate_self_signed_cert(
    trustchain_pubkey_hex: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let pubkey_bytes_vec = hex::decode(trustchain_pubkey_hex)?;
    if pubkey_bytes_vec.len() != 32 {
        return Err(format!(
            "expected 32-byte Ed25519 pubkey, got {} bytes",
            pubkey_bytes_vec.len()
        )
        .into());
    }
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&pubkey_bytes_vec);

    let mut params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("TrustChain Node {}", &trustchain_pubkey_hex[..16]),
    );

    // Embed the Ed25519 pubkey as a custom extension so the verifier can pin it.
    let ext_value = encode_pubkey_as_octet_string(&pubkey_bytes);
    let mut identity_ext = CustomExtension::from_oid_content(TRUSTCHAIN_PUBKEY_OID, ext_value);
    identity_ext.set_criticality(false); // non-critical — unknown peers can ignore it
    params.custom_extensions.push(identity_ext);

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((vec![cert_der], key_der))
}

/// Build a rustls ServerConfig with a self-signed cert that embeds the Ed25519 pubkey.
pub fn build_server_config(
    trustchain_pubkey_hex: &str,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let (certs, key) = generate_self_signed_cert(trustchain_pubkey_hex)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig.
///
/// When `expected_pubkey_hex` is `Some(hex)`, the returned config will verify
/// that the server's TLS certificate carries the matching TrustChain Ed25519
/// pubkey in its custom extension (OID `1.3.6.1.4.1.99999.1`). A mismatch
/// causes the TLS handshake to fail, preventing impersonation.
///
/// When `expected_pubkey_hex` is `None`, the config falls back to
/// `AcceptAnyCert` behaviour (for bootstrap connections where the peer's
/// pubkey is not yet known).
pub fn build_client_config(
    expected_pubkey_hex: Option<&str>,
) -> Result<Arc<rustls::ClientConfig>, Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    if let Some(pubkey_hex) = expected_pubkey_hex {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PubkeyVerifier::new(pubkey_hex)?))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    // Bootstrap / unknown peer — accept any cert but warn operators.
    WARN_ACCEPT_ANY_CERT.call_once(|| {
        tracing::warn!(
            "QUIC TLS: certificate verification in AcceptAnyCert mode for \
             bootstrap connections — peer identity not pinned; \
             use expected_pubkey to enable pinning for known peers"
        );
    });

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// PubkeyVerifier — pins the TrustChain Ed25519 pubkey embedded in the cert
// ---------------------------------------------------------------------------

/// Certificate verifier that pins the peer's Ed25519 pubkey.
///
/// It extracts the 32-byte Ed25519 pubkey from the custom X.509 extension
/// (OID `1.3.6.1.4.1.99999.1`) in the peer's DER certificate and compares it
/// to the expected pubkey supplied at construction time.
#[derive(Debug)]
pub struct PubkeyVerifier {
    /// Expected 32-byte Ed25519 pubkey.
    expected_pubkey: [u8; 32],
}

impl PubkeyVerifier {
    /// Construct a verifier that pins `expected_pubkey_hex` (64 hex chars).
    pub fn new(expected_pubkey_hex: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = hex::decode(expected_pubkey_hex)?;
        if bytes.len() != 32 {
            return Err(
                format!("expected 32-byte Ed25519 pubkey, got {} bytes", bytes.len()).into(),
            );
        }
        let mut expected_pubkey = [0u8; 32];
        expected_pubkey.copy_from_slice(&bytes);
        Ok(Self { expected_pubkey })
    }
}

impl rustls::client::danger::ServerCertVerifier for PubkeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Extract the Ed25519 pubkey from the custom extension in the DER cert.
        let found = extract_trustchain_pubkey(end_entity.as_ref()).map_err(|e| {
            rustls::Error::General(format!("TrustChain pubkey extraction failed: {e}"))
        })?;

        if found != self.expected_pubkey {
            return Err(rustls::Error::General(format!(
                "TrustChain pubkey mismatch: expected {}, got {}",
                hex::encode(self.expected_pubkey),
                hex::encode(found),
            )));
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Delegate actual signature verification to rustls default provider.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// AcceptAnyCert — fallback for bootstrap connections
// ---------------------------------------------------------------------------

/// Certificate verifier that accepts any certificate (bootstrap / unknown peers).
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ---------------------------------------------------------------------------
// ASN.1 / DER parsing helpers — no external crate required
// ---------------------------------------------------------------------------

/// Parse a DER-encoded X.509 certificate and return the 32-byte Ed25519 pubkey
/// stored in the TrustChain identity extension (OID `1.3.6.1.4.1.99999.1`).
///
/// # DER structure overview
///
/// ```text
/// Certificate  ::= SEQUENCE {
///   tbsCertificate  TBSCertificate,
///   ...
/// }
/// TBSCertificate ::= SEQUENCE {
///   ... (version, serialNumber, signature, issuer, validity, subject, spki) ...
///   extensions  [3] EXPLICIT SEQUENCE OF Extension OPTIONAL
/// }
/// Extension ::= SEQUENCE {
///   extnID    OID,
///   critical  BOOLEAN DEFAULT FALSE,
///   extnValue OCTET STRING  -- contains the DER-encoded extension value
/// }
/// ```
///
/// Our extension value is: `OCTET STRING { <32 bytes of Ed25519 pubkey> }`.
fn extract_trustchain_pubkey(der: &[u8]) -> Result<[u8; 32], String> {
    // Encode the OID we are looking for as DER bytes so we can do a byte scan.
    // OID DER: tag 0x06, length, then base-128 encoded arcs.
    let oid_der = encode_oid_der(TRUSTCHAIN_PUBKEY_OID)?;

    // Walk through the DER looking for our OID. After the OID we expect the
    // extension value: optionally a BOOLEAN (critical flag), then an OCTET STRING
    // wrapping the actual extension content (another OCTET STRING with 32 bytes).
    let pos = find_subsequence(der, &oid_der)
        .ok_or_else(|| "TrustChain pubkey extension not found in certificate".to_string())?;

    // `pos` points to the start of the OID tag inside the DER stream.
    // Skip past the OID bytes to reach the next element.
    let after_oid = pos + oid_der.len();

    // The next element is either:
    //   - BOOLEAN (if critical=true): 01 01 FF  — skip it
    //   - OCTET STRING (extnValue): 04 <len> <content>
    let rest = der
        .get(after_oid..)
        .ok_or_else(|| "unexpected end of cert after OID".to_string())?;

    let rest = skip_boolean_if_present(rest);

    // Now we should be at the extnValue OCTET STRING.
    let ext_content = parse_octet_string(rest)
        .ok_or_else(|| "failed to parse extnValue OCTET STRING".to_string())?;

    // Inside extnValue is the extension value itself — another OCTET STRING: 04 20 <32 bytes>.
    let pubkey_bytes = parse_octet_string(ext_content)
        .ok_or_else(|| "failed to parse inner pubkey OCTET STRING".to_string())?;

    if pubkey_bytes.len() != 32 {
        return Err(format!(
            "expected 32-byte Ed25519 pubkey in extension, got {} bytes",
            pubkey_bytes.len()
        ));
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(pubkey_bytes);
    Ok(result)
}

/// Encode an OID as DER bytes (tag `0x06`, length, base-128 arcs).
fn encode_oid_der(arcs: &[u64]) -> Result<Vec<u8>, String> {
    if arcs.len() < 2 {
        return Err("OID must have at least 2 arcs".to_string());
    }
    // First two arcs are combined: first * 40 + second.
    let first_octet = arcs[0] * 40 + arcs[1];
    let mut content: Vec<u8> = Vec::new();
    encode_base128(&mut content, first_octet);
    for &arc in &arcs[2..] {
        encode_base128(&mut content, arc);
    }
    let mut out = vec![0x06]; // OID tag
    encode_der_length(&mut out, content.len());
    out.extend_from_slice(&content);
    Ok(out)
}

/// Encode a single OID arc in base-128 (big-endian, MSBs set on all but last byte).
fn encode_base128(buf: &mut Vec<u8>, mut value: u64) {
    if value == 0 {
        buf.push(0x00);
        return;
    }
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0x7f) as u8);
        value >>= 7;
    }
    bytes.reverse();
    for (i, b) in bytes.iter().enumerate() {
        if i < bytes.len() - 1 {
            buf.push(b | 0x80);
        } else {
            buf.push(*b);
        }
    }
}

/// Encode a DER length field (short or long form).
fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xFF {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// Find the first occurrence of `needle` within `haystack`, returning the start index.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// If the byte slice starts with a DER BOOLEAN (`01 01 xx`), return the slice
/// after the BOOLEAN. Otherwise return the slice unchanged.
fn skip_boolean_if_present(data: &[u8]) -> &[u8] {
    if data.len() >= 3 && data[0] == 0x01 && data[1] == 0x01 {
        &data[3..]
    } else {
        data
    }
}

/// Parse a DER OCTET STRING at the start of `data`.
/// Returns the contents (inner bytes) on success, or `None` on malformed input.
fn parse_octet_string(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() || data[0] != 0x04 {
        return None;
    }
    let (len, header_len) = parse_der_length(&data[1..])?;
    let start = 1 + header_len;
    let end = start + len;
    if end > data.len() {
        return None;
    }
    Some(&data[start..end])
}

/// Parse a DER length field at the start of `data`.
/// Returns `(length_value, bytes_consumed)` or `None` on malformed input.
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        // Short form: single byte.
        Some((data[0] as usize, 1))
    } else {
        // Long form: first byte tells us how many subsequent bytes hold the length.
        let num_bytes = (data[0] & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[1..=num_bytes] {
            len = (len << 8) | (b as usize);
        }
        Some((len, 1 + num_bytes))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier as _;

    // --- Unit tests for ASN.1 helpers ---

    #[test]
    fn test_encode_oid_der_round_trip() {
        // The encoded OID must start with tag 0x06.
        let oid = encode_oid_der(TRUSTCHAIN_PUBKEY_OID).unwrap();
        assert_eq!(oid[0], 0x06, "OID tag must be 0x06");
        assert!(oid.len() > 2, "OID encoding must have content");
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let payload = b"hello trustchain extension";
        let mut encoded = vec![0x04, payload.len() as u8];
        encoded.extend_from_slice(payload);
        let decoded = parse_octet_string(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_parse_der_length_short_form() {
        let (len, consumed) = parse_der_length(&[0x20]).unwrap();
        assert_eq!(len, 32);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_parse_der_length_long_form_one_byte() {
        let (len, consumed) = parse_der_length(&[0x81, 0xC8]).unwrap();
        assert_eq!(len, 200);
        assert_eq!(consumed, 2);
    }

    // --- Certificate generation ---

    #[test]
    fn test_generate_cert_embeds_pubkey() {
        let id = trustchain_core::identity::Identity::generate();
        let pubkey_hex = id.pubkey_hex();

        let (certs, _key) = generate_self_signed_cert(&pubkey_hex).unwrap();
        assert_eq!(certs.len(), 1);

        // The embedded pubkey must round-trip through the extension.
        let found = extract_trustchain_pubkey(certs[0].as_ref()).unwrap();
        assert_eq!(found, id.pubkey_bytes());
    }

    #[test]
    fn test_generate_cert_rejects_wrong_length_pubkey() {
        let result = generate_self_signed_cert("aabb");
        assert!(
            result.is_err(),
            "should reject a pubkey that is not 32 bytes"
        );
    }

    // --- PubkeyVerifier construction ---

    #[test]
    fn test_pubkey_verifier_rejects_bad_hex() {
        assert!(PubkeyVerifier::new("not-hex!!").is_err());
    }

    #[test]
    fn test_pubkey_verifier_rejects_wrong_length() {
        assert!(PubkeyVerifier::new("aabb").is_err());
    }

    // --- build_server_config / build_client_config ---

    #[test]
    fn test_server_config() {
        let pubkey = hex::encode([0xaa; 32]);
        let config = build_server_config(&pubkey).unwrap();
        let _ = config; // must not panic
    }

    #[test]
    fn test_client_config_bootstrap_mode() {
        // None => AcceptAnyCert path, must succeed.
        let config = build_client_config(None).unwrap();
        let _ = config;
    }

    #[test]
    fn test_client_config_pinned_mode() {
        let pubkey = hex::encode([0xbb; 32]);
        let config = build_client_config(Some(&pubkey)).unwrap();
        let _ = config;
    }

    // --- End-to-end pinning: PubkeyVerifier against a real cert ---

    #[test]
    fn test_pinning_succeeds_when_pubkeys_match() {
        let id = trustchain_core::identity::Identity::generate();
        let pubkey_hex = id.pubkey_hex();

        let (certs, _key) = generate_self_signed_cert(&pubkey_hex).unwrap();

        let verifier = PubkeyVerifier::new(&pubkey_hex).unwrap();

        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let now = rustls::pki_types::UnixTime::now();

        let result = verifier.verify_server_cert(&certs[0], &[], &server_name, &[], now);
        assert!(
            result.is_ok(),
            "pinning must succeed when pubkeys match: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_pinning_fails_when_pubkeys_differ() {
        // Server generates a cert with its own identity.
        let server_id = trustchain_core::identity::Identity::generate();
        let server_pubkey_hex = server_id.pubkey_hex();
        let (certs, _key) = generate_self_signed_cert(&server_pubkey_hex).unwrap();

        // Client expects a completely different pubkey.
        let other_id = trustchain_core::identity::Identity::generate();
        let expected_hex = other_id.pubkey_hex();

        let verifier = PubkeyVerifier::new(&expected_hex).unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let now = rustls::pki_types::UnixTime::now();

        let result = verifier.verify_server_cert(&certs[0], &[], &server_name, &[], now);
        assert!(result.is_err(), "pinning must fail when pubkeys differ");
        // The error message must mention mismatch for clear diagnostics.
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("mismatch"),
            "error must mention 'mismatch': {err_str}"
        );
    }

    #[test]
    fn test_accept_any_cert_bootstrap_mode() {
        // AcceptAnyCert must always succeed regardless of the cert content.
        let id = trustchain_core::identity::Identity::generate();
        let (certs, _key) = generate_self_signed_cert(&id.pubkey_hex()).unwrap();

        let verifier = AcceptAnyCert;
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let now = rustls::pki_types::UnixTime::now();

        let result = verifier.verify_server_cert(&certs[0], &[], &server_name, &[], now);
        assert!(result.is_ok(), "AcceptAnyCert must always pass");
    }
}
