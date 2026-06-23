# shared_logging

## Why

Velo platform services export three observability signals — **logs**, **traces**, and **metrics** — to
Grafana Alloy over OTLP/gRPC.  Without a shared, consistent initialisation path, each service would
re-implement the same boilerplate and risk diverging from the platform's
Alloy → Loki / Tempo / Prometheus pipeline.

## What

`shared_logging` provides two initialisation paths and a set of logging macros:

| API | Use case |
|-----|----------|
| [`tracing_init`] | Full-featured init driven by a `TracingConfig` struct: stdout, syslog, rolling files, and OTLP. Used by long-running services with rich operator configuration. |
| [`init_tracing`] | Lightweight init driven by two environment variables (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`). Used by minimal daemons and jobs. |
| `info!` / `debug!` / `warn!` / `error!` / `trace!` | Drop-in replacements for the `tracing` macros that automatically prefix each message with the calling function name. |

### Signal pipeline

| Signal | SDK pipeline | Destination |
|--------|-------------|-------------|
| **Logs** | `opentelemetry-appender-tracing` bridges `tracing` events → `SdkLoggerProvider` → OTLP/gRPC `LogExporter` | Alloy → Loki |
| **Traces** | `tracing-opentelemetry` bridges `tracing` spans → `SdkTracerProvider` → OTLP/gRPC `SpanExporter` | Alloy → Tempo |
| **Metrics** | `SdkMeterProvider` with a 30-second `PeriodicReader` → OTLP/gRPC `MetricExporter` | Alloy → Prometheus |

When `OTEL_EXPORTER_OTLP_ENDPOINT` is **not** set all three pipelines are skipped and
output falls back to structured console logging with no network traffic.

## How

### `tracing_init` layer composition

```text
TracingConfig
│
├─ stdout_layer    (unless no_log_to_stdout)
├─ file_layer      (when log_to_file is set — daily rolling)
├─ syslog_layer    (when log_to_syslog, Unix only)
└─ otel_layer      (when otlp is set)
    ├─ SdkTracerProvider  → SpanExporter   ──► Tempo
    └─ SdkMeterProvider   → MetricExporter ──► Prometheus (when enable_metering)
```

### `init_tracing` layer composition

```text
OTEL_EXPORTER_OTLP_ENDPOINT set?
│
├─ YES ──► stdout layer
│          tracing-opentelemetry layer  → SdkTracerProvider  → SpanExporter   ──► Tempo
│          OpenTelemetryTracingBridge   → SdkLoggerProvider  → LogExporter    ──► Loki
│          SdkMeterProvider (global)   → MetricExporter (30 s)                ──► Prometheus
│
└─ NO  ──► stdout layer only
```

All OTLP exporters share the same gRPC endpoint and `service.name` resource attribute so
every signal from a service is correlated in Grafana.

## Using

```toml
[dependencies]
shared_logging = { workspace = true }
```

### Full-featured init (`tracing_init`)

```rust
use shared_logging::{TelemetryConfig, TracingConfig, info, tracing_init};

fn main() {
    let _guards = tracing_init(&TracingConfig {
        service_name: "my-service".into(),
        otlp: Some(TelemetryConfig {
            otlp_url: "http://alloy.observability.svc:4317".into(),
            version: option_env!("CARGO_PKG_VERSION").map(String::from),
            environment: Some("production".into()),
            enable_metering: true,
        }),
        rust_log: Some("info,my_crate=debug".into()),
        with_ansi_colors: true,
        ..Default::default()
    });

    info!("service started");   // prefixed with function name in message
}
```

`LoggingGuards` is dropped at the end of `main` — no explicit shutdown needed.

### ANSI colours

Coloured output is controlled by `with_ansi_colors` in `TracingConfig`. It applies only to the
**stdout layer** — the file and syslog layers always disable ANSI codes.

```rust
tracing_init(&TracingConfig {
    service_name: "my-service".into(),
    with_ansi_colors: true,     // enable colours in stdout (default: false)
    ..Default::default()
});
```

Tip: set `with_ansi_colors: true` in development and `false` in production / when stdout is
piped to a log collector that does not interpret ANSI sequences.

### Syslog (Unix only)

Setting `log_to_syslog: true` adds a syslog layer alongside any other layers that are active.
Logs are forwarded to the system syslog daemon using `Facility::User` and the
`service_name` as the syslog identity. The layer is compiled out on Windows.

```rust
tracing_init(&TracingConfig {
    service_name: "my-service".into(),
    #[cfg(not(target_os = "windows"))]
    log_to_syslog: true,        // writes to syslog(3) via syslog-tracing
    no_log_to_stdout: false,    // stdout and syslog are independent; both can be on
    ..Default::default()
});
```

You can verify syslog output on Linux with:

```sh
journalctl -t my-service -f
# or
tail -f /var/log/syslog | grep my-service
```

On macOS:

```sh
log stream --predicate 'senderImagePath contains "my-service"'
```

### Lightweight env-var init (`init_tracing`)

```rust
use shared_logging::init_tracing;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let telemetry = init_tracing("my-service")?;

    info!(version = "1.0", "service started");
    warn!(code = 42, "something noteworthy");

    telemetry.shutdown();   // flush all OTLP exporters before exit
    Ok(())
}
```

### Logging macros

`shared_logging` exports `info!`, `debug!`, `warn!`, `error!`, and `trace!` macros that
wrap the standard `tracing` macros and automatically prepend `[function_name]` to every
message, making it easy to locate the call site in log aggregators:

```rust
use shared_logging::info;

fn process_request(id: u64) {
    info!("processing request {id}");
    // emits: INFO [process_request] processing request 42
}
```

### Recording metrics

```rust
use opentelemetry::metrics::Counter;
use shared_logging::init_tracing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let telemetry = init_tracing("my-service")?;
    let meter = telemetry.meter(env!("CARGO_PKG_NAME"));

    let requests: Counter<u64> = meter
        .u64_counter("requests_total")
        .with_description("Total number of requests processed")
        .build();

    requests.add(1, &[]);
    telemetry.shutdown();
    Ok(())
}
```

### Distributed tracing with `#[instrument]`

```rust
use tracing::instrument;

#[instrument(fields(user_id = %user_id))]
async fn handle_request(user_id: u64) -> anyhow::Result<()> {
    tracing::info!("handling request");
    Ok(())
}
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(absent — console only)* | gRPC endpoint for all three OTLP signals, e.g. `http://obs-stack-alloy.observability.svc.cluster.local:4317` |
| `OTEL_SERVICE_NAME` | value passed to `init_tracing` | `service.name` resource attribute stamped on every signal |
| `RUST_LOG` | `info` | `tracing_subscriber` log filter, e.g. `debug,hyper=warn` |

### Kubernetes manifest

```yaml
env:
  - name: OTEL_EXPORTER_OTLP_ENDPOINT
    value: "http://obs-stack-alloy.observability.svc.cluster.local:4317"
  - name: OTEL_SERVICE_NAME
    value: "my-service"
  - name: RUST_LOG
    value: "info"
```

## Building

```sh
# From workspace root
cargo build -p shared_logging
cargo build -p shared_logging --release
```

## Testing

```sh
# Unit tests (no network required)
cargo test -p shared_logging

# Smoke test against a live collector
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
OTEL_SERVICE_NAME=test-service \
RUST_LOG=debug \
  cargo test -p shared_logging -- --nocapture
```

To port-forward the Velo platform's Alloy instance:

```sh
kubectl port-forward -n observability svc/obs-stack-alloy 4317:4317
```
