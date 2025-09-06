mod error;
mod log_utils;
mod macros;
mod otlp;
mod tracing;

pub use error::LoggerError;
pub use log_utils::log_init;
pub use tracing::{tracing_init, LoggingGuards, TelemetryConfig, TracingConfig};

/// Re-exported dependencies for use with the logging macros
///
/// The logging macros (info!, debug!, warn!, error!, trace!) use these
/// re-exported tracing modules internally, so external crates don't need to add
/// tracing as a direct dependency.
pub mod reexport {
    pub use tracing;
    pub use tracing_subscriber;
}
