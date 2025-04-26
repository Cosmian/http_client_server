mod error;
mod log_utils;
mod otlp;
mod telemetry_utils;

pub use error::LoggerError;
pub use log_utils::log_init;
pub use telemetry_utils::{telemetry_init, OtelGuard, TelemetryConfig};
pub mod reexport {
    pub use tracing;
    pub use tracing_subscriber;
}
