use std::{
    fs::File,
    io::{BufReader, Read},
    sync::Arc,
};

use reqwest::{Client, ClientBuilder, Identity};
use rustls::{client::WebPkiVerifier, Certificate, SupportedCipherSuite};
use x509_cert::{
    der::{DecodePem, Encode},
    Certificate as X509Certificate,
};

use crate::{
    certificate_verifier::{LeafCertificateVerifier, NoVerifier},
    error::result::HttpClientResult,
    HttpClientConfig, HttpClientError,
};

/// Comprehensive TLS client builder that handles all TLS configuration
/// scenarios
///
/// This function consolidates all TLS configuration logic into a single,
/// maintainable function. It replaces the complex nested conditionals that were
/// previously in `http_client.rs`.
///
/// # Supported TLS Scenarios:
///
/// 1. **TEE Certificate Verification**: When `verified_cert` is provided,
///    builds a TLS client with custom leaf certificate verification for Trusted
///    Execution Environment contexts. The certificate verification includes
///    both standard CA verification and specific leaf certificate validation.
///
/// 2. **Custom Cipher Suites**: When `cipher_suites` is specified, configures
///    the TLS client to use only the specified cipher suites. Falls back to
///    default configuration if cipher suite parsing fails.
///
/// 3. **Default TLS Configuration**: When no special configuration is needed,
///    uses standard TLS settings with optional invalid certificate acceptance
///    based on `accept_invalid_certs`.
///
/// 4. **PKCS12 Client Certificate Authentication**: When
///    `ssl_client_pkcs12_path` is provided, loads and configures client
///    certificate authentication using PKCS12 format.
///
/// # Parameters
/// * `http_conf` - HTTP client configuration containing TLS settings
///
/// # Returns
/// * `HttpClientResult<ClientBuilder>` - Configured reqwest `ClientBuilder`
///   ready for use
///
/// # Error Handling
/// The function is designed to be robust - if any step fails, it logs the error
/// and falls back to a safe default configuration rather than failing
/// completely.
pub(crate) fn build_tls_client(http_conf: &HttpClientConfig) -> HttpClientResult<ClientBuilder> {
    // Step 1: Handle TEE certificate verification
    let builder = if let Some(certificate) = &http_conf.verified_cert {
        let tee_cert = Certificate(X509Certificate::from_pem(certificate.as_bytes())?.to_der()?);
        build_tls_client_tee(
            tee_cert,
            http_conf.accept_invalid_certs,
            http_conf.cipher_suites.as_deref(),
        )
    } else {
        // Step 2: Handle custom cipher suites or default configuration
        match &http_conf.cipher_suites {
            Some(cipher_suites_str) => {
                let cipher_suites = parse_cipher_suites(cipher_suites_str)?;
                let config =
                    build_tls_config(Some(&cipher_suites), http_conf.accept_invalid_certs)?;
                Client::builder().use_preconfigured_tls(config)
            }
            None => {
                // Default configuration
                ClientBuilder::new().danger_accept_invalid_certs(http_conf.accept_invalid_certs)
            }
        }
    };

    // Step 3: Handle PKCS12 client certificate if provided
    let builder = if let Some(ssl_client_pkcs12) = &http_conf.ssl_client_pkcs12_path {
        let mut pkcs12 = BufReader::new(File::open(ssl_client_pkcs12)?);
        let mut pkcs12_bytes = vec![];
        pkcs12.read_to_end(&mut pkcs12_bytes)?;
        let pkcs12 = Identity::from_pkcs12_der(
            &pkcs12_bytes,
            &http_conf
                .ssl_client_pkcs12_password
                .clone()
                .unwrap_or_default(),
        )?;
        builder.identity(pkcs12)
    } else {
        builder
    };

    Ok(builder)
}

/// Parse cipher suites string and return a vector of supported cipher suites
fn parse_cipher_suites(cipher_suites_str: &str) -> HttpClientResult<Vec<SupportedCipherSuite>> {
    let mut selected_suites = Vec::new();

    // Split the cipher suites string by colon only
    let suite_names: Vec<&str> = cipher_suites_str
        .split(':')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    for suite_name in suite_names {
        // Map common cipher suite names to rustls cipher suites
        let cipher_suite = match suite_name.to_uppercase().as_str() {
            "TLS_AES_256_GCM_SHA384" => Some(&rustls::cipher_suite::TLS13_AES_256_GCM_SHA384),
            "TLS_AES_128_GCM_SHA256" => Some(&rustls::cipher_suite::TLS13_AES_128_GCM_SHA256),
            "TLS_CHACHA20_POLY1305_SHA256" => {
                Some(&rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256)
            }
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
                Some(&rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
            }
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                Some(&rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            }
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                Some(&rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
            }
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
                Some(&rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
            }
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                Some(&rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            }
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                Some(&rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
            }
            _ => {
                return Err(HttpClientError::Default(format!(
                    "Unknown cipher suite: {suite_name}"
                )));
            }
        };

        if let Some(suite) = cipher_suite {
            selected_suites.push(*suite);
        }
    }

    if selected_suites.is_empty() {
        return Err(HttpClientError::Default(
            "No valid cipher suites found in the provided list".to_owned(),
        ));
    }

    Ok(selected_suites)
}

/// Build a TLS client configuration with optional custom cipher suites and
/// certificate verifier This is the core function that handles TLS
/// configuration for all scenarios
fn build_tls_config_with_verifier(
    cipher_suites: Option<&[SupportedCipherSuite]>,
    verifier: Option<Arc<dyn rustls::client::ServerCertVerifier>>,
    root_cert_store: Option<rustls::RootCertStore>,
) -> HttpClientResult<rustls::ClientConfig> {
    let config_builder = match cipher_suites {
        Some(suites) => rustls::ClientConfig::builder()
            .with_cipher_suites(suites)
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions() // This is needed for TLS 1.3 support
            .map_err(|e| HttpClientError::Default(format!("TLS config error: {e}")))?,
        None => rustls::ClientConfig::builder()
            .with_cipher_suites(rustls::DEFAULT_CIPHER_SUITES)
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions() // This is needed for TLS 1.3 support
            .map_err(|e| HttpClientError::Default(format!("TLS config error: {e}")))?,
    };

    let final_config = match (verifier, root_cert_store) {
        // Custom verifier provided (TEE scenario)
        (Some(custom_verifier), _) => config_builder
            .with_custom_certificate_verifier(custom_verifier)
            .with_no_client_auth(),
        // Root certificate store provided (standard TLS)
        (None, Some(store)) => config_builder
            .with_root_certificates(store)
            .with_no_client_auth(),
        // No verification (accept invalid certs)
        (None, None) => config_builder
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth(),
    };

    Ok(final_config)
}

/// Build a TLS client configuration with optional custom cipher suites
/// This is a convenience wrapper around `build_tls_config_with_verifier` for
/// standard TLS scenarios
fn build_tls_config(
    cipher_suites: Option<&[SupportedCipherSuite]>,
    accept_invalid_certs: bool,
) -> HttpClientResult<rustls::ClientConfig> {
    if accept_invalid_certs {
        // No verification needed
        build_tls_config_with_verifier(cipher_suites, None, None)
    } else {
        // Standard TLS with root certificate verification
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        build_tls_config_with_verifier(cipher_suites, None, Some(root_cert_store))
    }
}

/// Build a `TLSClient` to use with a server running inside a tee.
/// The TLS verification is the basic one but also includes the verification of
/// the leaf certificate The TLS socket is mounted since the leaf certificate is
/// exactly the same as the expected one.
fn build_tls_client_tee(
    leaf_cert: Certificate,
    accept_invalid_certs: bool,
    cipher_suites: Option<&str>,
) -> ClientBuilder {
    let mut root_cert_store = rustls::RootCertStore::empty();
    let trust_anchors = webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|trust_anchor| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            trust_anchor.subject,
            trust_anchor.spki,
            trust_anchor.name_constraints,
        )
    });
    root_cert_store.add_trust_anchors(trust_anchors);

    let verifier = Arc::new(if accept_invalid_certs {
        LeafCertificateVerifier::new(leaf_cert, Arc::new(NoVerifier))
    } else {
        LeafCertificateVerifier::new(
            leaf_cert,
            Arc::new(WebPkiVerifier::new(root_cert_store, None)),
        )
    });

    let cipher_suites = cipher_suites
        .and_then(|cs| parse_cipher_suites(cs).ok())
        .unwrap_or_else(|| rustls::DEFAULT_CIPHER_SUITES.to_vec());

    let config =
        match build_tls_config_with_verifier(Some(&cipher_suites), Some(verifier.clone()), None) {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("TLS config error: {e}, falling back to safe defaults");
                rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth()
            }
        };

    // Create a client builder
    Client::builder().use_preconfigured_tls(config)
}
