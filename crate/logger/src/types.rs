use std::path::PathBuf;

#[cfg(not(target_arch = "wasm32"))]
use opentelemetry_sdk::{
    logs::SdkLoggerProvider, metrics::SdkMeterProvider, trace::SdkTracerProvider,
};

// ── config ───────────────────────────────────────────────────────────────────

/// OTLP exporter configuration (used with [`TracingConfig`]).
#[derive(Debug, Default, Clone)]
pub struct TelemetryConfig {
    pub version: Option<String>,
    pub environment: Option<String>,
    pub otlp_url: String,
    pub enable_metering: bool,
}

/// Configuration for the tracing / logging stack (used with [`tracing_init`]).
#[derive(Debug, Default, Clone)]
pub struct TracingConfig {
    /// Logical service name (appears in spans and OTLP resource).
    pub service_name: String,

    /// OpenTelemetry OTLP configuration.
    pub otlp: Option<TelemetryConfig>,

    /// Suppress stdout logging.
    pub no_log_to_stdout: bool,

    /// Forward logs to syslog (Unix only, non-wasm).
    #[cfg(not(any(target_os = "windows", target_arch = "wasm32")))]
    pub log_to_syslog: bool,

    /// Rolling daily log file: `(directory, filename_prefix)`.
    pub log_to_file: Option<(PathBuf, String)>,

    /// Override for `RUST_LOG`. Applied before subscriber init.
    pub rust_log: Option<String>,

    /// Enable ANSI colour codes in stdout output.
    pub with_ansi_colors: bool,
}

// ── guards ───────────────────────────────────────────────────────────────────

/// Guards that keep OTLP exporters alive for the lifetime of the process.
///
/// Only available on non-wasm targets.  Call [`TelemetryGuards::shutdown`]
/// before process exit to flush pending telemetry and release resources cleanly.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
pub struct TelemetryGuards {
    pub(crate) tracer_provider: Option<SdkTracerProvider>,
    pub(crate) logger_provider: Option<SdkLoggerProvider>,
    pub(crate) meter_provider: Option<SdkMeterProvider>,
}

#[cfg(not(target_arch = "wasm32"))]
impl TelemetryGuards {
    /// Flush and shut down all active OTLP exporters.
    pub fn shutdown(self) {
        if let Some(tp) = self.tracer_provider {
            let _ = tp.shutdown();
        }
        if let Some(lp) = self.logger_provider {
            let _ = lp.shutdown();
        }
        if let Some(mp) = self.meter_provider {
            let _ = mp.shutdown();
        }
    }

    /// Returns a [`Meter`] from the global `MeterProvider` installed during
    /// [`init_tracing`].  Use a `'static` scope name, typically
    /// `env!("CARGO_PKG_NAME")`.
    ///
    /// Returns a no-op meter when OTLP is not configured.
    pub fn meter(&self, scope: &'static str) -> opentelemetry::metrics::Meter {
        opentelemetry::global::meter(scope)
    }
}

/// Guards that keep background exporters alive (for [`tracing_init`]).
///
/// The tracing pipeline shuts down cleanly when this value is dropped.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
pub struct LoggingGuards {
    pub(crate) _tracer_provider: Option<SdkTracerProvider>,
    pub(crate) _meter_provider: Option<SdkMeterProvider>,
    pub(crate) _rolling_appender_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for LoggingGuards {
    fn drop(&mut self) {
        if let Some(tp) = self._tracer_provider.take() {
            let _ = tp.shutdown();
        }
        if let Some(mp) = self._meter_provider.take() {
            let _ = mp.shutdown();
        }
    }
}

/// On wasm32, `LoggingGuards` is an empty no-op (no OTLP, no file appender).
#[cfg(target_arch = "wasm32")]
#[derive(Default)]
pub struct LoggingGuards;
