/// Errors that can occur while initialising or configuring the logging stack.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("failed to build OTLP span exporter: {0}")]
    SpanExporter(#[source] opentelemetry_otlp::ExporterBuildError),

    #[error("failed to build OTLP log exporter: {0}")]
    LogExporter(#[source] opentelemetry_otlp::ExporterBuildError),

    #[error("failed to build OTLP metric exporter: {0}")]
    MetricExporter(#[source] opentelemetry_otlp::ExporterBuildError),

    #[error("failed to initialise tracing subscriber: {0}")]
    SubscriberInit(#[source] tracing_subscriber::util::TryInitError),

    #[error("{context}: {source}")]
    WithContext {
        context: &'static str,
        #[source]
        source: Box<LoggingError>,
    },
}

/// Result type for the logging stack initialisation.
pub type LoggingResult<T> = Result<T, LoggingError>;

/// Extension trait that adds `.context(msg)` to [`LoggingResult`], mirroring
/// the ergonomics of `anyhow::Context`.
pub trait ResultExt<T> {
    fn context(self, ctx: &'static str) -> LoggingResult<T>;
}

impl<T> ResultExt<T> for LoggingResult<T> {
    fn context(self, ctx: &'static str) -> LoggingResult<T> {
        self.map_err(|source| LoggingError::WithContext {
            context: ctx,
            source: Box::new(source),
        })
    }
}
