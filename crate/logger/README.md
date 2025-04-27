# Cosmian Logger

A versatile logging and tracing utility for Rust applications that provides:

- Structured logging to stdout
- Syslog integration
- OpenTelemetry support for distributed tracing
- Runtime configuration options

## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
cosmian_logger = { path = "../path/to/crate/logger" }
```

## Basic Usage

For simple applications, use the `log_init` function to set up logging:

```rust
use cosmian_logger::log_init;
use tracing::{debug, info};

fn main() {
    // Initialize with custom log level
    log_init(Some("debug"));

    info!("This is an info message");
    debug!("This is a debug message");
}
```

The `log_init` function accepts an optional log level string parameter:

- When `None` is provided, it falls back to the `RUST_LOG` environment variable
- Log levels follow Rust's standard: trace, debug, info, warn, error

## Advanced Configuration with OpenTelemetry

For more advanced use cases with OpenTelemetry integration:

```rust
use cosmian_logger::{tracing_init, TelemetryConfig, TracingConfig};
use tracing::span;
use tracing_core::Level;

#[tokio::main]
async fn main() {
    let config = TracingConfig {
        service_name: "my_service".to_string(),
        otlp: Some(TelemetryConfig {
            version: Some("1.0.0".to_string()),
            environment: Some("development".to_string()),
            otlp_url: "http://localhost:4317".to_string(),
            enable_metering: true,
        }),
        no_log_to_stdout: false,
        #[cfg(not(target_os = "windows"))]
        log_to_syslog: true,
        rust_log: Some("debug".to_string()),
    };

    let _otel_guard = tracing_init(&config);

    // Create and enter a span for better tracing context
    let span = span!(Level::TRACE, "application");
    let _span_guard = span.enter();

    // Your application code here
    tracing::info!("Application started");
}
```

## OpenTelemetry Setup

To use OpenTelemetry, start a collector like Jaeger:

```bash
docker run -p16686:16686 -p4317:4317 -p4318:4318 \
-e COLLECTOR_OTLP_ENABLED=true -e LOG_LEVEL=debug \
jaegertracing/jaeger:2.5.0
```

Then access the Jaeger UI at `http://localhost:16686`

## Configuration Options

The `TracingConfig` struct supports:

- `service_name`: Name of your service for tracing
- `otlp`: OpenTelemetry configuration (optional)
- `no_log_to_stdout`: Disable logging to stdout
- `log_to_syslog`: Enable logging to system log
- `rust_log`: Log level configuration

## In Tests

The `log_init` function is safe to use in tests:

```rust
#[test]
fn test_something() {
    cosmian_logger::log_init(Some("debug"));
    // Your test code
}
```

## Re-exports

The logger crate re-exports common tracing utilities:

```rust
use cosmian_logger::reexport::{tracing, tracing_subscriber};
```