mod error;
mod log_utils;
mod otlp;
mod tracing;

pub use error::LoggerError;
pub use log_utils::log_init;
pub use tracing::{tracing_init, OtelGuard, TelemetryConfig, TracingConfig};
pub mod reexport {
    pub use tracing;
    pub use tracing_subscriber;
}
