use std::{
    fs::File,
    io::{BufReader, Read},
    sync::Arc,
    time::Duration,
};

use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, ClientBuilder, Identity,
};
use rustls::{client::WebPkiVerifier, Certificate};
use serde::{Deserialize, Serialize};
use x509_cert::{
    der::{DecodePem, Encode},
    Certificate as X509Certificate,
};

use crate::{
    certificate_verifier::{LeafCertificateVerifier, NoVerifier},
    error::{result::HttpClientResultHelper, HttpClientError},
    Oauth2LoginConfig,
};

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
        let server_url = http_conf.server_url.strip_suffix('/').map_or_else(
            || http_conf.server_url.clone(),
            std::string::ToString::to_string,
        );

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
            || ClientBuilder::new().danger_accept_invalid_certs(http_conf.accept_invalid_certs),
            |certificate| build_tls_client_tee(certificate, http_conf.accept_invalid_certs),
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

        // Build the client
        Ok(Self {
            client: builder
                .default_headers(headers)
                .tcp_keepalive(Duration::from_secs(60))
                .build()
                .context("Reqwest client builder")?,
            server_url,
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

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    // Create a client builder
    Client::builder().use_preconfigured_tls(config)
}
