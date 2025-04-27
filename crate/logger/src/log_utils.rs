use crate::{tracing_init, TracingConfig};

/// Initializing the stdout logger only
/// (no open tracing)
///
/// # Arguments
/// * `rust_log` - The log string to set for RUST_LOG
///
/// # Notes
/// - calling `log_init(None`) is equivalent to calling `log_init(option_env!("RUST_LOG"))`
/// - this function can be called from a `[tokio::test]` function, in contrast to `tracing_init`
pub fn log_init(rust_log: Option<&str>) {
    let config = TracingConfig {
        otlp: None,
        service_name: "".to_string(),
        no_log_to_stdout: false,
        log_to_syslog: false,
        rust_log: rust_log.or(option_env!("RUST_LOG")).map(|s| s.to_string()),
    };
    tracing_init(&config);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{debug, info, trace};

    #[test]
    fn test_log_init() {
        log_init(Some("debug"));
        info!("This is an INFO test log message");
        debug!("This is a DEBUG test log message");
        debug!("RUST_LOG: {:?}", std::env::var("RUST_LOG"));
        // The next message is a TRACING level and should be ignored
        trace!("This is a TRACE test log message");
    }
}
