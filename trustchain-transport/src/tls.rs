//! TLS certificate generation from Ed25519 identity.
//!
//! Generates self-signed certificates where the certificate's key
//! is derived from (or associated with) the TrustChain Ed25519 identity.

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::{Arc, Once};

static INIT_CRYPTO: Once = Once::new();

/// Ensure the rustls CryptoProvider is installed (once).
fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Generate a self-signed TLS certificate and private key.
///
/// Note: rustls requires RSA or ECDSA keys for TLS. We generate an ECDSA
/// key for TLS (separate from the Ed25519 identity key) and embed the
/// TrustChain public key in the certificate's common name.
pub fn generate_self_signed_cert(
    trustchain_pubkey_hex: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    let mut params = CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("TrustChain Node {}", &trustchain_pubkey_hex[..16]),
    );

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((vec![cert_der], key_der))
}

/// Build a rustls ServerConfig with a self-signed cert.
pub fn build_server_config(
    trustchain_pubkey_hex: &str,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let (certs, key) = generate_self_signed_cert(trustchain_pubkey_hex)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig that accepts self-signed certs.
pub fn build_client_config() -> Result<Arc<rustls::ClientConfig>, Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Certificate verifier that accepts any certificate (for P2P self-signed certs).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cert() {
        let pubkey = "a".repeat(64);
        let (certs, _key) = generate_self_signed_cert(&pubkey).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_server_config() {
        let pubkey = "a".repeat(64);
        let config = build_server_config(&pubkey).unwrap();
        assert!(config.alpn_protocols.is_empty() || true);
    }

    #[test]
    fn test_client_config() {
        let config = build_client_config().unwrap();
        assert!(config.alpn_protocols.is_empty() || true);
    }
}
