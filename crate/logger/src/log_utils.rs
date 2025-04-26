use crate::{telemetry_init, TelemetryConfig};

/// Initializing the stdout logger only
/// (no open telemetry)
///
/// # Arguments
/// * `rust_log` - The log string to set for RUST_LOG
///
/// # Notes
/// - calling `log_init(None`) is equivalent to calling `log_init(option_env!("RUST_LOG"))`
/// - this function can be called from a `[tokio::test]` function, in contrast to `telemetry_init`
pub fn log_init(rust_log: Option<&str>) {
    let config = TelemetryConfig {
        service_name: "".to_string(),
        version: None,
        environment: None,
        otlp_url: None,
        no_stdout: false,
        rust_log: rust_log.or(option_env!("RUST_LOG")).map(|s| s.to_string()),
    };
    telemetry_init(&config);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{debug, info, trace};
    use tracing_core::field::debug;

    #[test]
    fn test_log_init() {
        log_init(Some("info"));
        info!("This is an INFO test log message");
        debug!("This is a DEBUG test log message");
        debug!("RUST_LOG: {:?}", std::env::var("RUST_LOG"));
        trace!("This is a TRACE test log message");
    }
}
