#![cfg(test)]

use crate::{log_init, tracing_init, TelemetryConfig, TelemetryGuards, TracingConfig};

/// tracing_init is idempotent: the second call must not panic or reinitialise.
#[test]
fn init_twice_is_safe() {
    let _g1 = tracing_init(&TracingConfig {
        service_name: "test".into(),
        rust_log: Some("info".into()),
        with_ansi_colors: false,
        ..Default::default()
    });
    // second call must return empty guards without panicking
    let _g2 = tracing_init(&TracingConfig::default());
}

/// log_init convenience wrapper must not panic when called after tracing_init.
#[test]
fn log_init_is_safe_after_init() {
    // May already be initialised by another test — must not panic.
    log_init(Some("warn"));
}

/// TracingConfig defaults: all flags off, no otlp, no file, no syslog.
#[test]
fn tracing_config_default() {
    let c = TracingConfig::default();
    assert!(c.service_name.is_empty());
    assert!(c.otlp.is_none());
    assert!(!c.no_log_to_stdout);
    assert!(c.log_to_file.is_none());
    assert!(c.rust_log.is_none());
    assert!(!c.with_ansi_colors);
    #[cfg(not(target_os = "windows"))]
    assert!(!c.log_to_syslog);
}

/// TelemetryConfig defaults.
#[test]
fn telemetry_config_default() {
    let c = TelemetryConfig::default();
    assert!(c.version.is_none());
    assert!(c.environment.is_none());
    assert!(c.otlp_url.is_empty());
    assert!(!c.enable_metering);
}

/// TelemetryGuards::shutdown on an empty guard must not panic.
#[test]
fn telemetry_guards_shutdown_empty() {
    TelemetryGuards::default().shutdown();
}

/// TelemetryGuards::meter returns a valid (no-op) meter when OTLP is absent.
#[test]
fn telemetry_guards_meter_noop() {
    let g = TelemetryGuards::default();
    // Should not panic, even with no provider installed.
    let _m = g.meter("test-scope");
}

mod macros {
    /// __fn_name! must return a non-empty string containing the function name.
    #[test]
    fn fn_name_not_empty() {
        let name = crate::__fn_name!();
        assert!(!name.is_empty(), "function name must not be empty");
        assert!(
            name.contains("fn_name_not_empty"),
            "expected 'fn_name_not_empty', got '{name}'"
        );
    }

    /// __fn_name! must resolve to the enclosing async fn name, not
    /// `{{closure}}`.
    #[tokio::test]
    async fn fn_name_inside_async_fn() {
        let name = crate::__fn_name!();
        assert!(
            !name.contains("{{"),
            "fn_name must not contain '{{{{' (got '{name}') — async closure stripping failed"
        );
        assert!(
            name.contains("fn_name_inside_async_fn"),
            "expected 'fn_name_inside_async_fn', got '{name}'"
        );
    }

    /// Verify that our info!/debug!/warn!/error!/trace! macros expand without
    /// panicking (they rely on a subscriber being present; if none is installed
    /// the tracing no-op path is taken instead).
    #[test]
    fn macros_do_not_panic() {
        crate::info!("info message {}", 1);
        crate::debug!("debug message {}", 2);
        crate::warn!("warn message {}", 3);
        crate::error!("error message {}", 4);
        crate::trace!("trace message {}", 5);
    }
}
