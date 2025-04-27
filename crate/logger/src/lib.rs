mod error;
mod log_utils;
mod otlp;
mod tracing;

pub use error::LoggerError;
pub use log_utils::log_init;
pub use tracing::{OtelGuard, TelemetryConfig, TracingConfig, tracing_init};
pub mod reexport {
    pub use tracing;
    pub use tracing_subscriber;
}
