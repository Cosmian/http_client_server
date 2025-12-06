use std::{
    fs::File,
    io::{BufReader, Read},
    sync::Arc,
};

use reqwest::{Client, ClientBuilder, Identity};
use rustls::{
    client::danger::ServerCertVerifier, pki_types::CertificateDer, RootCertStore,
    SupportedCipherSuite,
};
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
        let tee_cert =
            CertificateDer::from(X509Certificate::from_pem(certificate.as_bytes())?.to_der()?);
        build_tls_client_tee(
            tee_cert,
            http_conf.accept_invalid_certs,
            http_conf.cipher_suites.as_deref(),
        )
    } else if let Some(cipher_suites_str) = &http_conf.cipher_suites {
        // Step 2: Handle custom cipher suites
        match parse_cipher_suites(cipher_suites_str) {
            Ok(cipher_suites) => {
                match build_tls_config(Some(&cipher_suites), http_conf.accept_invalid_certs) {
                    Ok(config) => Client::builder().use_preconfigured_tls(config),
                    Err(e) => {
                        tracing::error!("TLS config error: {e}, falling back to safe defaults");
                        ClientBuilder::new()
                            .danger_accept_invalid_certs(http_conf.accept_invalid_certs)
                    }
                }
            }
            Err(e) => {
                tracing::error!("Cipher suite parsing error: {e}, falling back to safe defaults");
                ClientBuilder::new().danger_accept_invalid_certs(http_conf.accept_invalid_certs)
            }
        }
    } else {
        // Default configuration
        ClientBuilder::new().danger_accept_invalid_certs(http_conf.accept_invalid_certs)
    };

    // Step 3: Handle client certificate authentication
    // Prefer PEM (cert + key) if provided; otherwise fall back to PKCS#12
    let builder = if let (Some(cert_path), Some(key_path)) = (
        http_conf.ssl_client_pem_cert_path.as_deref(),
        http_conf.ssl_client_pem_key_path.as_deref(),
    ) {
        let mut cert_reader = BufReader::new(File::open(cert_path)?);
        let mut cert_bytes = vec![];
        cert_reader.read_to_end(&mut cert_bytes)?;

        let mut key_reader = BufReader::new(File::open(key_path)?);
        let mut key_bytes = vec![];
        key_reader.read_to_end(&mut key_bytes)?;

        // Combine cert and key into a single PEM as expected by reqwest Identity
        let mut pem = Vec::with_capacity(cert_bytes.len() + 1 + key_bytes.len());
        pem.extend_from_slice(&cert_bytes);
        if !pem.ends_with(b"\n") {
            pem.push(b'\n');
        }
        pem.extend_from_slice(&key_bytes);

        let identity = Identity::from_pem(&pem)?;
        builder.identity(identity)
    } else if let Some(ssl_client_pkcs12) = &http_conf.ssl_client_pkcs12_path {
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
            "TLS_AES_256_GCM_SHA384" => {
                Some(rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384)
            }
            "TLS_AES_128_GCM_SHA256" => {
                Some(rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256)
            }
            "TLS_CHACHA20_POLY1305_SHA256" => {
                Some(rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256)
            }
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
                Some(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
            }
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                Some(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            }
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => Some(
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ),
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
                Some(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
            }
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                Some(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            }
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                Some(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
            }
            _ => {
                return Err(HttpClientError::Default(format!(
                    "Unknown cipher suite: {suite_name}"
                )));
            }
        };

        if let Some(suite) = cipher_suite {
            selected_suites.push(suite);
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
    verifier: Option<Arc<dyn ServerCertVerifier>>,
    root_cert_store: Option<RootCertStore>,
) -> HttpClientResult<rustls::ClientConfig> {
    let config_builder = match cipher_suites {
        Some(suites) => rustls::ClientConfig::builder_with_provider(
            rustls::crypto::CryptoProvider {
                cipher_suites: suites.to_vec(),
                ..rustls::crypto::aws_lc_rs::default_provider()
            }
            .into(),
        )
        .with_safe_default_protocol_versions()
        .map_err(|e| HttpClientError::Default(format!("TLS config error: {e}")))?,
        None => rustls::ClientConfig::builder(),
    };
    let final_config = match (verifier, root_cert_store, cipher_suites) {
        // Custom verifier provided (TEE scenario)
        (Some(custom_verifier), _, Some(_)) => {
            // With custom cipher suites
            config_builder
                .dangerous()
                .with_custom_certificate_verifier(custom_verifier)
                .with_no_client_auth()
        }
        (Some(custom_verifier), _, None) => {
            // No custom cipher suites
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(custom_verifier)
                .with_no_client_auth()
        }
        // Root certificate store provided (standard TLS)
        (None, Some(store), Some(_)) => {
            // With custom cipher suites - need to use dangerous() first, then set roots
            // manually Install default crypto provider if not already set
            drop(rustls::crypto::aws_lc_rs::default_provider().install_default());
            let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(store))
                .build()
                .map_err(|e| {
                    HttpClientError::Default(format!("Failed to build WebPkiServerVerifier: {e}"))
                })?;
            config_builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        (None, Some(store), None) => {
            // No custom cipher suites
            rustls::ClientConfig::builder()
                .with_root_certificates(store)
                .with_no_client_auth()
        }
        // No verification (accept invalid certs)
        (None, None, _) => {
            let no_verifier = Arc::new(NoVerifier::new());
            if cipher_suites.is_some() {
                config_builder
                    .dangerous()
                    .with_custom_certificate_verifier(no_verifier)
                    .with_no_client_auth()
            } else {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(no_verifier)
                    .with_no_client_auth()
            }
        }
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
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        build_tls_config_with_verifier(cipher_suites, None, Some(root_cert_store))
    }
}

/// Build a `TLSClient` to use with a server running inside a tee.
/// The TLS verification is the basic one but also includes the verification of
/// the leaf certificate The TLS socket is mounted since the leaf certificate is
/// exactly the same as the expected one.
fn build_tls_client_tee(
    leaf_cert: CertificateDer<'static>,
    accept_invalid_certs: bool,
    cipher_suites: Option<&str>,
) -> ClientBuilder {
    // Install default crypto provider if not already set
    drop(rustls::crypto::aws_lc_rs::default_provider().install_default());

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let default_verifier: Arc<dyn ServerCertVerifier> = if accept_invalid_certs {
        Arc::new(NoVerifier::new())
    } else {
        match rustls::client::WebPkiServerVerifier::builder(Arc::new(root_cert_store.clone()))
            .build()
        {
            Ok(verifier) => verifier,
            Err(e) => {
                tracing::error!("Failed to build WebPkiServerVerifier: {e}, using NoVerifier");
                Arc::new(NoVerifier::new())
            }
        }
    };

    let verifier = Arc::new(LeafCertificateVerifier::new(leaf_cert, default_verifier));

    let cipher_suites_vec = cipher_suites.and_then(|cs| parse_cipher_suites(cs).ok());

    let config = match build_tls_config_with_verifier(
        cipher_suites_vec.as_deref(),
        Some(verifier.clone()),
        None,
    ) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("TLS config error: {e}, falling back to safe defaults");
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
    };

    // Create a client builder
    Client::builder().use_preconfigured_tls(config)
}
