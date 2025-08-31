use std::{
    fs::File,
    io::{BufReader, Read},
    sync::Arc,
};

use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, ClientBuilder, Identity,
};
use rustls::{client::WebPkiVerifier, Certificate, SupportedCipherSuite};
use serde::{Deserialize, Serialize};
use tracing::info;
use x509_cert::{
    der::{DecodePem, Encode},
    Certificate as X509Certificate,
};

use crate::{
    certificate_verifier::{LeafCertificateVerifier, NoVerifier},
    error::{result::HttpClientResultHelper, HttpClientError},
    http_client_error, Oauth2LoginConfig, ProxyParams,
};

/// Configuration for the HTTP client
///
/// # Examples
///
/// ## Basic HTTP client
/// ```rust
/// use cosmian_http_client::HttpClientConfig;
///
/// let config = HttpClientConfig::default();
/// ```
///
/// ## HTTP client with custom cipher suites
/// ```rust
/// use cosmian_http_client::HttpClientConfig;
///
/// let mut config = HttpClientConfig::default();
/// config.cipher_suites = Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_string());
/// ```
///
/// ## Supported cipher suites
/// - TLS 1.3: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`,
///   `TLS_CHACHA20_POLY1305_SHA256`
/// - TLS 1.2 ECDHE-ECDSA: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`,
///   `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`,
///   `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
/// - TLS 1.2 ECDHE-RSA: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`,
///   `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
///   `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct HttpClientConfig {
    // accept_invalid_certs is useful if the cli needs to connect to an HTTPS server
    // running an invalid or unsecure SSL certificate
    #[serde(default)]
    #[serde(skip_serializing_if = "not")]
    pub accept_invalid_certs: bool,
    pub server_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_client_pkcs12_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_client_pkcs12_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth2_conf: Option<Oauth2LoginConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_params: Option<ProxyParams>,
    /// Colon-separated list of cipher suites to use for TLS connections.
    /// If not specified, rustls safe defaults will be used.
    ///
    /// Example: "`TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suites: Option<String>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            accept_invalid_certs: false,
            server_url: "http://0.0.0.0:9998".to_owned(),
            verified_cert: None,
            access_token: None,
            database_secret: None,
            ssl_client_pkcs12_path: None,
            ssl_client_pkcs12_password: None,
            oauth2_conf: None,
            proxy_params: None,
            cipher_suites: None,
        }
    }
}
/// used for serialization
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn not(b: &bool) -> bool {
    !*b
}

/// A struct implementing some of the 50+ operations a KMIP client should
/// implement: <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip>
#[derive(Clone)]
pub struct HttpClient {
    pub server_url: String,
    pub client: Client,
}

impl HttpClient {
    /// Instantiate a new HTTP(S) Client
    /// # Errors
    /// Will return an error if the client cannot be instantiated
    pub fn instantiate(http_conf: &HttpClientConfig) -> Result<Self, HttpClientError> {
        // Ensure the server URL does not end with a slash
        let server_url = http_conf.server_url.strip_suffix('/').map_or_else(
            || http_conf.server_url.clone(),
            std::string::ToString::to_string,
        );
        info!("Using server URL: {}", server_url);

        let mut headers = HeaderMap::new();
        if let Some(bearer_token) = http_conf.access_token.clone() {
            headers.insert(
                "Authorization",
                HeaderValue::from_str(format!("Bearer {bearer_token}").as_str())?,
            );
        }
        if let Some(database_secret) = http_conf.database_secret.clone() {
            headers.insert("DatabaseSecret", HeaderValue::from_str(&database_secret)?);
        }

        // We deal with 4 scenarios:
        // 1. HTTP: no TLS
        // 2. HTTPS:
        //
        //      a) self-signed: we want to remove the verifications
        //
        //      b) signed in a tee context: we want to verify the /quote and then only
        // accept the allowed          certificate -> For efficiency purpose,
        // this verification is made outside          this call (async with the
        // queries) Only the verified certificate is used here
        //
        //      c) signed in a non-tee context: we want classic TLS verification based
        // on the root ca
        let allowed_tee_tls_cert = if let Some(certificate) = &http_conf.verified_cert {
            Some(Certificate(
                X509Certificate::from_pem(certificate.as_bytes())?.to_der()?,
            ))
        } else {
            None
        };

        let builder = allowed_tee_tls_cert.map_or_else(
            || {
                http_conf.cipher_suites.as_ref().map_or_else(
                    || {
                        ClientBuilder::new()
                            .danger_accept_invalid_certs(http_conf.accept_invalid_certs)
                    },
                    |cipher_suites| {
                        build_tls_client_with_cipher_suites(
                            cipher_suites,
                            http_conf.accept_invalid_certs,
                        )
                    },
                )
            },
            |certificate| {
                build_tls_client_tee(
                    certificate,
                    http_conf.accept_invalid_certs,
                    http_conf.cipher_suites.as_deref(),
                )
            },
        );

        // If a PKCS12 file is provided, use it to build the client
        let builder = match http_conf.ssl_client_pkcs12_path.clone() {
            Some(ssl_client_pkcs12) => {
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
            }
            None => builder,
        };

        // Note: TLS 1.3 support is enabled through custom rustls configuration
        // The rustls backend in reqwest doesn't support TLS 1.3 through builder methods
        // Instead, we'll use custom rustls config for all cases to ensure TLS 1.3
        // support

        // Determine which TLS configuration to use and build the client
        let mut client_builder = if let Some(cipher_suites_str) = &http_conf.cipher_suites {
            // Use custom cipher suites configuration, but preserve PKCS12 identity if
            // present
            if http_conf.ssl_client_pkcs12_path.is_some() {
                // PKCS12 identity is already set on the builder above, just apply cipher suites
                // We need to use the builder with identity, not create a new one
                builder
            } else {
                build_tls_client_with_cipher_suites(
                    cipher_suites_str,
                    http_conf.accept_invalid_certs,
                )
            }
        } else if http_conf.verified_cert.is_some() {
            // Use TEE certificate configuration (already handled above)
            builder
        } else if http_conf.ssl_client_pkcs12_path.is_some() {
            // Use PKCS12 certificate configuration (already handled above)
            builder
        } else {
            // Use default TLS configuration with TLS 1.3 support
            build_default_tls_client(http_conf.accept_invalid_certs)?
        };

        // Apply proxy settings if configured
        if let Some(proxy_params) = &http_conf.proxy_params {
            let mut proxy = reqwest::Proxy::all(proxy_params.url.clone()).map_err(|e| {
                http_client_error!("Failed to configure the HTTPS proxy for HTTP client: {e}")
            })?;

            if let Some(ref username) = proxy_params.basic_auth_username {
                if let Some(ref password) = proxy_params.basic_auth_password {
                    proxy = proxy.basic_auth(username, password);
                }
            } else if let Some(custom_auth_header) = &proxy_params.custom_auth_header {
                proxy = proxy.custom_http_auth(HeaderValue::from_str(custom_auth_header).map_err(
                    |e| {
                        http_client_error!(
                            "Failed to set custom HTTP auth header for HTTP client: {e}"
                        )
                    },
                )?);
            }
            if !proxy_params.exclusion_list.is_empty() {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(
                    &proxy_params.exclusion_list.join(","),
                ));
            }

            info!("Overriding reqwest builder with proxy: {:?}", proxy);
            client_builder = client_builder.proxy(proxy);
        }

        // Build the client
        Ok(Self {
            server_url,
            client: client_builder
                .default_headers(headers)
                .build()
                .context("Reqwest client builder")?,
        })
    }
}

/// Build a `TLSClient` to use with a server running inside a tee.
/// The TLS verification is the basic one but also includes the verification of
/// the leaf certificate The TLS socket is mounted since the leaf certificate is
/// exactly the same as the expected one.
pub(crate) fn build_tls_client_tee(
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

    let verifier = if accept_invalid_certs {
        LeafCertificateVerifier::new(leaf_cert, Arc::new(NoVerifier))
    } else {
        LeafCertificateVerifier::new(
            leaf_cert,
            Arc::new(WebPkiVerifier::new(root_cert_store, None)),
        )
    };

    let config = if let Some(cipher_suites_str) = cipher_suites {
        // Use custom cipher suites if provided
        if let Ok(cipher_suites) = parse_cipher_suites(cipher_suites_str) {
            match rustls::ClientConfig::builder()
                .with_cipher_suites(&cipher_suites)
                .with_safe_default_kx_groups()
                .with_safe_default_protocol_versions()
            {
                Ok(builder) => builder
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth(),
                Err(e) => {
                    tracing::error!("TLS config error: {e}, falling back to safe defaults");
                    rustls::ClientConfig::builder()
                        .with_safe_defaults()
                        .with_custom_certificate_verifier(Arc::new(verifier))
                        .with_no_client_auth()
                }
            }
        } else {
            // Fallback to safe defaults if cipher suite parsing fails
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        }
    } else {
        // Use safe defaults
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    };

    // Create a client builder
    Client::builder().use_preconfigured_tls(config)
}

/// Parse cipher suites string and return a vector of supported cipher suites
fn parse_cipher_suites(
    cipher_suites_str: &str,
) -> Result<Vec<SupportedCipherSuite>, HttpClientError> {
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
                tracing::warn!("Unknown cipher suite: {}", suite_name);
                None
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

/// Build a default TLS client configuration with TLS 1.3 support
/// This provides a baseline configuration when no special cipher suites or
/// certificates are needed
fn build_default_tls_client(accept_invalid_certs: bool) -> Result<ClientBuilder, HttpClientError> {
    // Build standard rustls config with TLS 1.3 support
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(rustls::DEFAULT_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions() // This includes TLS 1.3 by default
        .map_err(|e| HttpClientError::Default(format!("TLS config error: {e}")))?;

    let final_config = if accept_invalid_certs {
        config
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        config
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    };

    Ok(Client::builder().use_preconfigured_tls(final_config))
}

/// Build a TLS client with custom cipher suites
/// Falls back to PKCS12 certificate handling if cipher suites are not specified
fn build_tls_client_with_cipher_suites(
    cipher_suites_str: &str,
    accept_invalid_certs: bool,
) -> ClientBuilder {
    let cipher_suites = match parse_cipher_suites(cipher_suites_str) {
        Ok(suites) => suites,
        Err(e) => {
            tracing::error!("Failed to parse cipher suites: {}, using default", e);
            return ClientBuilder::new().danger_accept_invalid_certs(accept_invalid_certs);
        }
    };

    let mut root_cert_store = rustls::RootCertStore::empty();
    let trust_anchors = webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|trust_anchor| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            trust_anchor.subject,
            trust_anchor.spki,
            trust_anchor.name_constraints,
        )
    });
    root_cert_store.add_trust_anchors(trust_anchors);

    let config = match rustls::ClientConfig::builder()
        .with_cipher_suites(&cipher_suites)
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
    {
        Ok(builder) => builder,
        Err(e) => {
            tracing::error!("Failed to parse cipher suites: {}, using default", e);
            return ClientBuilder::new().danger_accept_invalid_certs(accept_invalid_certs);
        }
    };

    let final_config = if accept_invalid_certs {
        config
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        config
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    };

    Client::builder().use_preconfigured_tls(final_config)
}
