use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoggerError {
    #[error("OTLP error: {0}")]
    Otlp(String),

    #[error("Parsing error: {0}")]
    Parsing(String),

    #[error("Tracing subscriber error: {0}")]
    TracingSubscriber(String),
}

impl From<opentelemetry_otlp::ExporterBuildError> for LoggerError {
    fn from(e: opentelemetry_otlp::ExporterBuildError) -> Self {
        LoggerError::Otlp(e.to_string())
    }
}

impl From<tracing_subscriber::filter::ParseError> for LoggerError {
    fn from(e: tracing_subscriber::filter::ParseError) -> Self {
        LoggerError::Parsing(e.to_string())
    }
}

impl From<tracing_subscriber::util::TryInitError> for LoggerError {
    fn from(value: tracing_subscriber::util::TryInitError) -> Self {
        LoggerError::TracingSubscriber(value.to_string())
    }
}
