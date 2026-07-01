pub mod error;
mod macros;
mod tests;
pub mod types;

use std::sync::atomic::{AtomicBool, Ordering};

pub use error::{LoggingError, LoggingResult, ResultExt};
#[cfg(not(target_arch = "wasm32"))]
use opentelemetry::trace::TracerProvider;
#[cfg(not(target_arch = "wasm32"))]
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
#[cfg(not(target_arch = "wasm32"))]
use opentelemetry_otlp::WithExportConfig;
#[cfg(not(target_arch = "wasm32"))]
use opentelemetry_sdk::{
    logs::SdkLoggerProvider,
    metrics::{PeriodicReader, SdkMeterProvider},
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
    Resource,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
pub use types::{LoggingGuards, TelemetryConfig, TelemetryGuards, TracingConfig};

/// Re-exports for downstream crates (used by the logging macros).
pub mod reexport {
    pub use tracing;
    pub use tracing_subscriber;
}

// ── private helpers ──────────────────────────────────────────────────────────

static INITIALIZED: AtomicBool = AtomicBool::new(false);

#[cfg(not(target_arch = "wasm32"))]
fn build_resource_simple(service_name: &str) -> Resource {
    Resource::builder_empty()
        .with_attributes([opentelemetry::KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_NAME,
            service_name.to_owned(),
        )])
        .build()
}

#[cfg(not(target_arch = "wasm32"))]
fn build_resource_with_config(service_name: &str, config: &TelemetryConfig) -> Resource {
    use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
    let mut kvs = vec![opentelemetry::KeyValue::new(
        SERVICE_NAME,
        service_name.to_owned(),
    )];
    if let Some(v) = &config.version {
        kvs.push(opentelemetry::KeyValue::new(SERVICE_VERSION, v.clone()));
    }
    if let Some(env) = &config.environment {
        kvs.push(opentelemetry::KeyValue::new(
            "deployment.environment.name",
            env.clone(),
        ));
    }
    Resource::builder_empty().with_attributes(kvs).build()
}

#[cfg(not(target_arch = "wasm32"))]
fn new_tracer_provider(endpoint: &str, resource: Resource) -> LoggingResult<SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(LoggingError::SpanExporter)?;

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build())
}

#[cfg(not(target_arch = "wasm32"))]
fn new_logger_provider(endpoint: &str, resource: Resource) -> LoggingResult<SdkLoggerProvider> {
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(LoggingError::LogExporter)?;

    Ok(SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build())
}

#[cfg(not(target_arch = "wasm32"))]
fn new_meter_provider(endpoint: &str, resource: Resource) -> LoggingResult<SdkMeterProvider> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(LoggingError::MetricExporter)?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(std::time::Duration::from_secs(30))
        .build();

    Ok(SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build())
}

// ── public API ───────────────────────────────────────────────────────────────

/// Initialise the global tracing subscriber from a [`TracingConfig`].
///
/// Safe to call more than once — subsequent calls are no-ops and return empty
/// guards.
pub fn tracing_init(config: &TracingConfig) -> LoggingGuards {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return LoggingGuards::default();
    }

    // NOTE: Avoid mutating process-wide environment variables here
    // (std::env::set_var is `unsafe`). If `rust_log` is provided, apply it
    // directly when building the `EnvFilter` below.

    // `mut` is required on non-wasm targets where guards fields are populated
    // inside the #[cfg(not(target_arch = "wasm32"))] block below.
    #[allow(unused_mut)]
    let mut guards = LoggingGuards::default();

    // --- stdout layer ---
    let stdout_layer = if config.no_log_to_stdout {
        None
    } else {
        Some(
            tracing_subscriber::fmt::layer()
                .with_level(true)
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true)
                .with_file(true)
                .with_ansi(config.with_ansi_colors)
                .compact(),
        )
    };

    let filter = config
        .rust_log
        .as_deref()
        .map(EnvFilter::new)
        .unwrap_or_else(EnvFilter::from_default_env);

    // ── non-wasm subscriber: file + syslog + OTLP layers ────────────────────
    #[cfg(not(target_arch = "wasm32"))]
    {
        // --- rolling file layer ---
        // tracing-appender uses platform-specific file rotation support and does
        // not compile on wasm32.
        let file_layer = config.log_to_file.as_ref().map(|(dir, name)| {
            if !dir.exists() {
                if let Err(e) = std::fs::create_dir_all(dir) {
                    eprintln!("Failed to create log directory {}: {e}", dir.display());
                }
            }
            let appender = tracing_appender::rolling::daily(dir, name);
            let (non_blocking, guard) = tracing_appender::non_blocking(appender);
            guards._rolling_appender_guard = Some(guard);
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .compact()
        });

        // --- syslog layer (Unix only) ---
        #[cfg(not(target_os = "windows"))]
        let syslog_layer = if config.log_to_syslog {
            std::ffi::CString::new(config.service_name.as_str())
                .ok()
                .and_then(|id| {
                    syslog_tracing::Syslog::new(
                        id,
                        Default::default(),
                        syslog_tracing::Facility::User,
                    )
                })
                .map(|syslog| {
                    tracing_subscriber::fmt::layer()
                        .with_writer(syslog)
                        .with_ansi(false)
                        .compact()
                })
        } else {
            None
        };

        // --- OTLP layer ---
        let otel_layer = config.otlp.as_ref().and_then(|telemetry| {
            let resource = build_resource_with_config(&config.service_name, telemetry);

            let tracer_provider = match new_tracer_provider(&telemetry.otlp_url, resource.clone()) {
                Ok(tp) => tp,
                Err(e) => {
                    eprintln!("Failed to initialise OTLP span exporter: {e}");
                    return None;
                }
            };

            let tracer = tracer_provider.tracer(config.service_name.clone());
            opentelemetry::global::set_tracer_provider(tracer_provider.clone());
            guards._tracer_provider = Some(tracer_provider);

            if telemetry.enable_metering {
                match new_meter_provider(&telemetry.otlp_url, resource) {
                    Ok(mp) => {
                        opentelemetry::global::set_meter_provider(mp.clone());
                        guards._meter_provider = Some(mp);
                    }
                    Err(e) => eprintln!("Failed to initialise OTLP metric exporter: {e}"),
                }
            }

            Some(tracing_opentelemetry::layer().with_tracer(tracer))
        });

        let ts = tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(file_layer)
            .with(otel_layer);

        #[cfg(not(target_os = "windows"))]
        let ts = ts.with(syslog_layer);

        if let Err(e) = ts.try_init() {
            // Best-effort cleanup: avoid leaving background exporters running when
            // subscriber init fails.
            if let Some(tp) = guards._tracer_provider.take() {
                let _ = tp.shutdown();
            }
            if let Some(mp) = guards._meter_provider.take() {
                let _ = mp.shutdown();
            }
            INITIALIZED.store(false, Ordering::SeqCst);
            eprintln!("Failed to initialise tracing: {e}");
        }
    }

    // ── wasm32 subscriber: stdout only ───────────────────────────────────────
    #[cfg(target_arch = "wasm32")]
    {
        let ts = tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer);

        if let Err(e) = ts.try_init() {
            INITIALIZED.store(false, Ordering::SeqCst);
            eprintln!("Failed to initialise tracing: {e}");
        }
    }

    guards
}

/// Convenience initialiser for tests and simple CLIs (stdout only).
pub fn log_init(rust_log: Option<&str>) {
    let _guards = tracing_init(&TracingConfig {
        rust_log: rust_log.map(String::from),
        with_ansi_colors: true,
        ..Default::default()
    });
}

/// Initialise structured logging, OTLP tracing, OTLP logs, and OTLP metrics.
///
/// Reads two environment variables at start-up:
///
/// | Variable | Effect |
/// |---|---|
/// | `OTEL_EXPORTER_OTLP_ENDPOINT` | Enables all three OTLP signals (gRPC). Falls back to console-only when absent. |
/// | `OTEL_SERVICE_NAME` | Overrides `default_service_name`. |
///
/// Returns [`TelemetryGuards`] that must be kept alive for the entire process
/// lifetime.  Call [`TelemetryGuards::shutdown`] before exit to flush buffers.
#[cfg(not(target_arch = "wasm32"))]
pub fn init_tracing(default_service_name: &str) -> LoggingResult<TelemetryGuards> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_target(true)
        .compact();

    if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        let service_name =
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| default_service_name.to_string());
        let resource = build_resource_simple(&service_name);

        // ── traces ──────────────────────────────────────────────────────────
        let tracer_provider = new_tracer_provider(&endpoint, resource.clone())?;
        opentelemetry::global::set_tracer_provider(tracer_provider.clone());
        let tracer = tracer_provider.tracer(service_name.clone());

        // ── logs ─────────────────────────────────────────────────────────────
        let logger_provider = new_logger_provider(&endpoint, resource.clone())?;
        let otel_log_layer = OpenTelemetryTracingBridge::new(&logger_provider);

        // ── metrics ──────────────────────────────────────────────────────────
        let meter_provider = new_meter_provider(&endpoint, resource)?;
        opentelemetry::global::set_meter_provider(meter_provider.clone());

        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .with(otel_log_layer)
            .try_init()
            .map_err(LoggingError::SubscriberInit)
            .context("failed to initialize tracing subscriber with OTLP")?;

        tracing::info!(
            endpoint = %endpoint,
            service_name = %service_name,
            "OTLP telemetry enabled (traces + logs + metrics)"
        );

        Ok(TelemetryGuards {
            tracer_provider: Some(tracer_provider),
            logger_provider: Some(logger_provider),
            meter_provider: Some(meter_provider),
        })
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .try_init()
            .map_err(LoggingError::SubscriberInit)
            .context("failed to initialize tracing subscriber")?;

        tracing::info!("OTLP telemetry disabled; using console logs only");
        Ok(TelemetryGuards::default())
    }
}
