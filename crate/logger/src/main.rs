use cosmian_logger::{tracing_init, TelemetryConfig, TracingConfig};
use std::path::PathBuf;
use tracing::span;
use tracing_core::Level;

/// Example of how to use the tracing system
///
/// Make sure to first start Jaeger with the following command:
///
/// ```bash
/// docker run  -p16686:16686 -p4317:4317 -p 4318:4318 \
/// -e COLLECTOR_OTLP_ENABLED=true -e LOG_LEVEL=debug \
/// jaegertracing/jaeger:2.5.0
/// ```
#[tokio::main]
async fn main() {
    println!(
        r"
Make sure that Jaeger is started and running on localhost:4317:

    docker run  -p16686:16686 -p4317:4317 -p 4318:4318 \
    -e COLLECTOR_OTLP_ENABLED=true -e LOG_LEVEL=debug \
    jaegertracing/jaeger:2.5.0

    "
    );

    let tracing = TracingConfig {
        service_name: "test".to_owned(),
        otlp: Some(TelemetryConfig {
            version: Some(
                option_env!("CARGO_PKG_VERSION")
                    .unwrap_or("1.0.0")
                    .to_owned(),
            ),
            environment: Some("test".to_owned()),
            otlp_url: "http://localhost:4317".to_owned(),
            enable_metering: true,
        }),
        no_log_to_stdout: false,
        log_to_file: Some((PathBuf::from("test_logs"), "test.log".to_owned())),
        #[cfg(not(target_os = "windows"))]
        log_to_syslog: true,
        rust_log: Some("trace".to_owned()),
        with_ansi_colors: false,
    };
    let _otel_guard = tracing_init(&tracing);

    let span = span!(Level::TRACE, "application");
    let _span_guard = span.enter();

    foo().await;

    // Reloading of OTLP will be ignored
    let _otel_guard_2 = tracing_init(&tracing);

    tracing::debug!("Tracing after second initialization attempt");
}

async fn foo() {
    tracing::info!(
        monotonic_counter.foo = 1_u64,
        key_1 = "bar",
        key_2 = 10,
        "handle foo",
    );

    tracing::info!(histogram.baz = 10, "histogram example",);

    tracing::debug!(
        monotonic_counter.foo = 2_u64,
        key_1 = "bar",
        key_2 = 20,
        "handle foo",
    );
}
