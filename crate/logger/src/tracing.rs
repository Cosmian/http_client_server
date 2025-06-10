use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::{metrics::SdkMeterProvider, trace::SdkTracerProvider};
use std::path::PathBuf;
use std::{
    env::set_var,
    sync::atomic::{AtomicBool, Ordering},
};
use tracing::{debug, info, span, warn};
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_subscriber::{layer::SubscriberExt, reload, util::SubscriberInitExt, EnvFilter, Layer};

use crate::{otlp, LoggerError};

static TRACING_SET: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Default, Clone)]
pub struct TracingConfig {
    /// The Name of the service using this config
    /// Only used by the OTLP collector and syslog
    pub service_name: String,

    /// Use the OpenTelemetry provider
    pub otlp: Option<TelemetryConfig>,

    /// Do not log to stdout
    pub no_log_to_stdout: bool,

    #[cfg(not(target_os = "windows"))]
    /// log to syslog
    pub log_to_syslog: bool,

    /// If set, logs will be written to the specified directory (first argument)
    /// using the specified file name (second argument): <name>.YYYY-MM-DD.
    /// It is a rolling file appender that creates a new log file every day.
    pub log_to_file: Option<(PathBuf, String)>,

    /// Default `RUST_LOG` configuration.
    /// If it is not set, the value of the environment variable `RUST_LOG` will
    /// be used.
    pub rust_log: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct TelemetryConfig {
    /// The version of the service using this config
    pub version: Option<String>,

    /// The name of the environment
    /// (for instance, "production", "staging", "development")
    pub environment: Option<String>,

    /// The OTLP collector URL
    /// (for instance, <http://localhost:4317>)
    pub otlp_url: String,

    /// Tracing is enabled by default.
    /// This controls whether metering should also be enabled.
    pub enable_metering: bool,
}

#[derive(Default)]
pub struct LoggingGuards {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
    rolling_appender_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

impl Drop for LoggingGuards {
    fn drop(&mut self) {
        if let Some(tracer_provider) = &mut self.tracer_provider {
            debug!("dropping OTLP tracer");
            if let Err(err) = tracer_provider.shutdown() {
                eprintln!("Trace provider shutdown error: {err:?}");
            }
        }
        if let Some(meter_provider) = &mut self.meter_provider {
            debug!("dropping OTLP meter");
            if let Err(_err) = meter_provider.shutdown() {
                // ignore the error
            }
        }
    }
}

/// Initialize the telemetry system
///
/// # Usage
///
/// ```rust-ignore
/// use cosmian_logger::{telemetry_init, TelemetryConfig};
/// use tracing::span;
/// use tracing_core::Level;
///
/// #[tokio::main]
/// async fn main() {
///
///    let tracing = TracingConfig {
///        service_name: "test".to_string(),
///        otlp: Some(TelemetryConfig {
///            version: Some(
///                option_env!("CARGO_PKG_VERSION")
///                    .unwrap_or("1.0.0")
///                    .to_string(),
///            ),
///            environment: Some("test".to_string()),
///            otlp_url: "http://localhost:4317".to_string(),
///            enable_metering: true,
///        }),
///        no_log_to_stdout: false,
///        #[cfg(not(target_os = "windows"))]
///        log_to_syslog: true,
///        rust_log: Some("trace".to_string()),
///    };
///    let _otel_guard = tracing_init(&tracing);
///
///    let span = span!(Level::TRACE, "application");
///    let _span_guard = span.enter();
///
///     tracing::info!(
///         monotonic_counter.foo = 1_u64,
///         key_1 = "bar",
///         key_2 = 10,
///         "handle foo",
///     );
///
///     tracing::info!(histogram.baz = 10, "histogram example",);
///
/// }
/// ```
///
/// # Note
/// The OTLP gRPC provider fails when the telemetry is initialized from a test
/// started with `#[tokio::test]`. The reason is currently unknown. Use
/// `log_init()` instead.
///
/// # Arguments
/// * `telemetry` - The `TelemetryConfig` object containing the telemetry
///   configuration
///
/// # Errors
/// Returns an error if there is an issue initializing the telemetry system.
pub fn tracing_init(tracing_config: &TracingConfig) -> LoggingGuards {
    // Set the RUST_LOG environment variable if a config value is provided
    if let Some(rust_log) = &tracing_config.rust_log {
        set_var("RUST_LOG", rust_log);
    }

    // Enable backtraces for all errors
    set_var("RUST_BACKTRACE", "full");

    if TRACING_SET.swap(true, Ordering::Acquire) {
        let span = span!(tracing::Level::INFO, "tracing_init");
        let _guard = span.enter();
        warn!("Tracing already initialized or crashed");
        return LoggingGuards::default();
    }

    match tracing_init_(tracing_config) {
        Ok(otel_guard) => {
            let span = span!(tracing::Level::INFO, "tracing_init");
            let _guard = span.enter();
            info!("Tracing initialized with config {tracing_config:#?}",);
            otel_guard
        }
        Err(err) => {
            TRACING_SET.store(false, Ordering::Release);
            // If we cannot initialize the tracing system, we should not panic
            eprintln!("Failed to initialize tracing: {err:?}");
            LoggingGuards::default()
        }
    }
}

fn tracing_init_(config: &TracingConfig) -> Result<LoggingGuards, LoggerError> {
    let mut otel_guard = LoggingGuards::default();
    let mut layers = vec![];

    let filter = if config.otlp.is_some() {
        // To prevent a telemetry-induced-telemetry loop, OpenTelemetry's own internal
        // logging is properly suppressed. However, logs emitted by external components
        // (such as reqwest, tonic, etc.) are not suppressed as they do not propagate
        // OpenTelemetry context. Until this issue is addressed
        // (https://github.com/open-telemetry/opentelemetry-rust/issues/2877),
        // filtering like this is the best way to suppress such logs.
        //
        // The filter levels are set as follows:
        // - Allow `info` level and above by default.
        // - Completely restrict logs from `hyper`, `tonic`, `h2`, and `reqwest`.
        //
        // Note: This filtering will also drop logs from these components even when
        // they are used outside of the OTLP Exporter.
        let (filter, _reload_handle) = reload::Layer::new(
            EnvFilter::from_default_env()
                .add_directive("hyper=error".parse()?)
                .add_directive("tonic=error".parse()?)
                .add_directive("tower::buffer=off".parse()?)
                .add_directive("opentelemetry-otlp=off".parse()?)
                .add_directive("opentelemetry_sdk=error".parse()?)
                // .add_directive("reqwest=off".parse()?)
                .add_directive("h2=off".parse()?),
        );
        filter
    } else {
        // If no OTLP URL is provided, we can use the default filter
        let (filter, _reload_handle) = reload::Layer::new(EnvFilter::from_default_env());
        filter
    };

    // Logging to stdout
    if !config.no_log_to_stdout {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_level(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_file(true)
            .compact();
        layers.push(fmt_layer.boxed());
    }

    // Logging the rolling file appender
    if let Some((dir, name)) = &config.log_to_file {
        // create the logs directory if it does not exist
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(|err| {
                LoggerError::IOError(format!("Failed to create logs directory: {dir:?}: {err:?}"))
            })?;
        }

        // Configure a daily rolling file appender
        // Log files will be created in the "logs" directory
        // with names like "app.log.YYYY-MM-DD"
        let file_appender = tracing_appender::rolling::daily(dir, name);
        let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);
        otel_guard.rolling_appender_guard = Some(guard);

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking_writer)
            .with_level(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_file(true)
            .with_ansi(false) // Disable ANSI colors in file logs
            .compact();
        layers.push(fmt_layer.boxed());
    }

    // Logging to syslog
    #[cfg(not(target_os = "windows"))]
    if config.log_to_syslog {
        let identity =
            std::borrow::Cow::Owned(std::ffi::CString::new(config.service_name.clone())?);
        let (options, facility) = Default::default();
        if let Some(syslog) = syslog_tracing::Syslog::new(identity, options, facility) {
            let syslog_layer = tracing_subscriber::fmt::layer().with_writer(syslog);
            layers.push(syslog_layer.boxed());
        }
    }

    // Logging to the OpenTelemetry collector
    if let Some(otlp_config) = &config.otlp {
        // The OpenTelemetry tracing provider
        let otlp_provider = otlp::init_tracer_provider(
            &config.service_name,
            &otlp_config.otlp_url,
            otlp_config.version.clone(),
            otlp_config.environment.clone(),
        )?;
        layers.push(
            OpenTelemetryLayer::new(otlp_provider.tracer(config.service_name.clone())).boxed(),
        );

        let meter_provider = otlp_config
            .enable_metering
            .then(|| {
                otlp::init_meter_provider(
                    &config.service_name,
                    &otlp_config.otlp_url,
                    otlp_config.version.clone(),
                    otlp_config.environment.clone(),
                )
                .map(|meter_provider| {
                    layers.push(MetricsLayer::new(meter_provider.clone()).boxed());
                    meter_provider
                })
            })
            .transpose()?;

        otel_guard.tracer_provider = Some(otlp_provider);
        otel_guard.meter_provider = meter_provider;
    };

    // Initialize the global tracing subscriber
    tracing_subscriber::registry()
        .with(filter)
        .with(layers)
        .try_init()?;

    Ok(otel_guard)
}
