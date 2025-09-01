use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    error::{
        result::{HttpClientResult, HttpClientResultHelper},
        HttpClientError,
    },
    http_client_error,
    tls::build_tls_client,
    Oauth2LoginConfig, ProxyParams,
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

        // Build a TLS client builder with rustls backend compatible with TLS 1.3 and
        // 1.2
        let mut builder = build_tls_client(http_conf)?;

        // Apply proxy settings if configured
        if let Some(proxy_params) = &http_conf.proxy_params {
            builder = configure_proxy(builder, proxy_params)?;
        }

        // Build the client
        Ok(Self {
            server_url,
            client: builder
                .default_headers(headers)
                .build()
                .context("Reqwest client builder")?,
        })
    }
}

fn configure_proxy(
    mut client_builder: reqwest::ClientBuilder,
    proxy_params: &ProxyParams,
) -> HttpClientResult<reqwest::ClientBuilder> {
    // Apply proxy settings if configured
    let mut proxy = reqwest::Proxy::all(proxy_params.url.clone()).map_err(|e| {
        http_client_error!("Failed to configure the HTTPS proxy for HTTP client: {e}")
    })?;

    if let Some(ref username) = proxy_params.basic_auth_username {
        if let Some(ref password) = proxy_params.basic_auth_password {
            proxy = proxy.basic_auth(username, password);
        }
    } else if let Some(custom_auth_header) = &proxy_params.custom_auth_header {
        proxy = proxy.custom_http_auth(HeaderValue::from_str(custom_auth_header).map_err(|e| {
            http_client_error!("Failed to set custom HTTP auth header for HTTP client: {e}")
        })?);
    }
    if !proxy_params.exclusion_list.is_empty() {
        proxy = proxy.no_proxy(reqwest::NoProxy::from_string(
            &proxy_params.exclusion_list.join(","),
        ));
    }

    info!("Overriding reqwest builder with proxy: {:?}", proxy);
    client_builder = client_builder.proxy(proxy);
    Ok(client_builder)
}
