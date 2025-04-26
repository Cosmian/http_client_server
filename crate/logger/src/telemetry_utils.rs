use crate::{otlp, LoggerError};
use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::env::set_var;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, span, warn};
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};
use tracing_subscriber::{reload, Layer};

static TELEMETRY_SET: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Default, Clone)]
pub struct TelemetryConfig {
    /// The Name of the service using this config
    /// Only used by the OTLP collector
    pub service_name: String,

    /// The version of the service using this config
    /// Only used by the OTLP collector
    pub version: Option<String>,

    /// The name of the environment
    /// (for instance, "production", "staging", "development")
    /// Only used by the OTLP collector
    pub environment: Option<String>,

    /// The OTLP collector URL
    /// (for instance, <http://localhost:4317>)
    ///
    /// The OpenTelemetry provider will not be initialized if this is not set
    pub otlp_url: Option<String>,

    /// Do not log to stdout
    pub no_stdout: bool,

    /// Default RUST_LOG configuration.
    /// If it is not set, the value of the environment variable `RUST_LOG` will be used.
    pub rust_log: Option<String>,
}

#[derive(Default)]
pub struct OtelGuard {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl OtelGuard {
    pub fn flush(&self) {
        if let Some(tracer_provider) = &self.tracer_provider {
            tracer_provider.force_flush().unwrap()
        }
    }
}

impl Drop for OtelGuard {
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
///     let telemetry = TelemetryConfig {
///         service_name: "my-app".to_string(),
///         otlp_url: Some("http://localhost:4317".to_string()),
///         no_stdout: false,
///         rust_log: Some("trace".to_string()),
///     };
///     let _otel_guard = telemetry_init(&telemetry);
///
///     let span = span!(Level::TRACE, "application");
///     let _span_guard = span.enter();
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
/// The OTLP gRPC provider fails when the telemetry is initialized from a test started
/// with `#[tokio::test]`. The reason is unknown at this stage. Use `log_init()` instead.
///
/// # Arguments
/// * `telemetry` - The `TelemetryConfig` object containing the telemetry configuration
///
/// # Errors
/// Returns an error if there is an issue initializing the telemetry system.
pub fn telemetry_init(telemetry_config: &TelemetryConfig) -> OtelGuard {
    // Set the RUST_LOG environment variable if a config value is provided
    if let Some(rust_log) = &telemetry_config.rust_log {
        set_var("RUST_LOG", rust_log);
    }

    // Enable backtraces for all errors
    set_var("RUST_BACKTRACE", "full");

    if TELEMETRY_SET.swap(true, Ordering::Acquire) {
        let span = span!(tracing::Level::INFO, "telemetry_init");
        let _guard = span.enter();
        warn!("Telemetry already initialized or crashed");
        return OtelGuard::default();
    }

    match telemetry_init_(telemetry_config) {
        Ok(otel_guard) => {
            let span = span!(tracing::Level::INFO, "telemetry_init");
            let _guard = span.enter();
            info!("Telemetry initialized with config {telemetry_config:#?}",);
            otel_guard
        }
        Err(err) => {
            TELEMETRY_SET.store(false, Ordering::Release);
            // If we cannot initialize the telemetry system, we should not panic
            eprintln!("Failed to initialize telemetry: {err:?}");
            OtelGuard::default()
        }
    }
}

fn telemetry_init_(config: &TelemetryConfig) -> Result<OtelGuard, LoggerError> {
    let mut otel_guard = OtelGuard::default();
    let mut layers = vec![];

    let filter_layer = if config.otlp_url.is_some() {
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
        Layer::boxed(filter)
    } else {
        // If no OTLP URL is provided, we can use the default filter
        let (filter, _reload_handle) = reload::Layer::new(EnvFilter::from_default_env());
        Layer::boxed(filter)
    };
    layers.push(filter_layer);

    if !config.no_stdout {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_level(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_file(true)
            .compact();
        layers.push(fmt_layer.boxed());
    }

    if let Some(url) = &config.otlp_url {
        // The OpenTelemetry tracing provider
        let otlp_provider = otlp::init_tracer_provider(
            &config.service_name,
            url,
            config.version.clone(),
            config.environment.clone(),
        )?;
        layers.push(
            OpenTelemetryLayer::new(otlp_provider.tracer(config.service_name.clone())).boxed(),
        );

        // The OpenTelemetry metrics provider
        let meter_provider = otlp::init_meter_provider(
            &config.service_name,
            url,
            config.version.clone(),
            config.environment.clone(),
        );
        layers.push(MetricsLayer::new(meter_provider.clone()).boxed());

        otel_guard = OtelGuard {
            tracer_provider: Some(otlp_provider),
            meter_provider: Some(meter_provider),
        };
    }

    // Initialize the global tracing subscriber
    tracing_subscriber::registry().with(layers).try_init()?;

    Ok(otel_guard)
}
