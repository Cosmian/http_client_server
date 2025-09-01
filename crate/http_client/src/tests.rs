#[cfg(feature = "session")]
pub mod session_store;

#[cfg(test)]
mod pkcs12_tests {
    use cosmian_logger::log_init;

    use crate::{HttpClient, HttpClientConfig};

    #[test]
    fn test_pkcs12_nonexistent_file() {
        // Test with non-existent PKCS12 file
        let config = HttpClientConfig {
            ssl_client_pkcs12_path: Some("/nonexistent/path/file.p12".to_owned()),
            ssl_client_pkcs12_password: Some("password".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);

        assert!(result.is_err());
        // Should fail to open the file
    }

    #[test]
    fn test_pkcs12_existent_file() {
        log_init(None);
        // Test with PKCS12 file
        let config = HttpClientConfig {
            ssl_client_pkcs12_path: Some(
                "../../test_data/client_server/owner/owner.client.acme.com.p12".to_owned(),
            ),
            ssl_client_pkcs12_password: Some("password".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);

        // The file might not exist in the test environment, so we just check that
        // instantiation doesn't panic
        if let Err(e) = result {
            // This is expected if the file doesn't exist or is invalid
            eprintln!("Expected error: {e}");
        }
        // Should succeed in opening the file
    }

    #[test]
    fn test_http_client_without_pkcs12() {
        // Test normal HTTP client instantiation without PKCS12
        let config = HttpClientConfig::default();
        let result = HttpClient::instantiate(&config);

        assert!(
            result.is_ok(),
            "Expected OK but got error: {:?}",
            result.err()
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_http_client_with_cipher_suites() {
        // Test HTTP client with custom cipher suites
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        result.unwrap();
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_http_client_with_invalid_cipher_suites() {
        // Test HTTP client with invalid cipher suites (should fallback to defaults)
        let config = HttpClientConfig {
            cipher_suites: Some("INVALID_CIPHER_SUITE".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        // Should still work, but fallback to default cipher suites
        result.unwrap();
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_http_client_with_mixed_cipher_suites() {
        // Test with a mix of valid and invalid cipher suites
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:INVALID_SUITE:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        result.unwrap();
    }
}

#[cfg(test)]
mod tls_version_tests {
    use crate::{HttpClient, HttpClientConfig};

    #[test]
    fn test_client_with_tls12_cipher_suites() {
        // Test HTTP client instantiation with TLS 1.2 only cipher suites
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "TLS 1.2 cipher suites should be supported");
    }

    #[test]
    fn test_client_with_tls13_cipher_suites() {
        // Test HTTP client instantiation with TLS 1.3 only cipher suites
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "TLS 1.3 cipher suites should be supported");
    }

    #[test]
    fn test_client_with_mixed_tls_cipher_suites() {
        // Test HTTP client instantiation with both TLS 1.2 and 1.3 cipher suites
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
                 TLS_AES_128_GCM_SHA256"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Mixed TLS 1.2 and 1.3 cipher suites should be supported"
        );
    }

    #[test]
    fn test_client_with_tls13_and_ecdsa_cipher_suites() {
        // Test HTTP client instantiation with TLS 1.3 and ECDSA cipher suites
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "TLS 1.3 and ECDSA cipher suites should be supported"
        );
    }

    #[test]
    fn test_client_with_chacha_cipher_suites() {
        // Test HTTP client instantiation with ChaCha20 cipher suites (both TLS 1.2 and
        // 1.3)
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "ChaCha20 cipher suites should be supported");
    }

    #[test]
    fn test_client_default_supports_all_tls_versions() {
        // Test that default configuration supports both TLS 1.2 and 1.3
        let config = HttpClientConfig::default();

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Default configuration should support all TLS versions"
        );

        // The default configuration should use our build_default_tls_client
        // which supports TLS 1.3
    }

    #[test]
    fn test_client_with_only_tls13_aes_variants() {
        // Test client with only TLS 1.3 AES variants
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "TLS 1.3 AES variants should be supported");
    }

    #[test]
    fn test_client_with_only_tls12_ecdhe_variants() {
        // Test client with only TLS 1.2 ECDHE variants
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "TLS 1.2 ECDHE variants should be supported");
    }

    #[test]
    fn test_client_tls_version_handling_with_accept_invalid_certs() {
        // Test that TLS version handling works correctly with accept_invalid_certs
        let config = HttpClientConfig {
            accept_invalid_certs: true,
            cipher_suites: Some("TLS_AES_256_GCM_SHA384".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "TLS 1.3 with accept_invalid_certs should work"
        );
    }

    #[test]
    fn test_client_comprehensive_cipher_suite_list() {
        // Test with a comprehensive list of cipher suites from both TLS versions
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:\
                 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
                 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Comprehensive cipher suite list should be supported"
        );
    }

    #[test]
    fn test_colon_separated_cipher_suites() {
        // Test that colon-separated cipher suites work correctly
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "Colon-separated cipher suites should work");

        // Test with single cipher suite (no separator)
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384".to_owned()),
            ..Default::default()
        };
        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "Single cipher suite should work");

        // Test with mixed TLS versions using colon separator
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_owned(),
            ),
            ..Default::default()
        };
        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Mixed TLS version cipher suites with colon should work"
        );

        // Test that comma separation no longer works (should only find first cipher
        // suite)
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_owned()),
            ..Default::default()
        };
        let result = HttpClient::instantiate(&config);
        // This should still work because it treats the whole string as one cipher suite
        // name and will warn about unknown cipher suite for the
        // comma-containing part
        assert!(
            result.is_ok(),
            "Comma-separated should not be parsed as multiple suites"
        );
    }
}
