use std::io;

use thiserror::Error;

pub(crate) mod result;

#[derive(Error, Debug)]
pub enum ConfigUtilsError {
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Invalid conversion: {0}")]
    Conversion(String),

    #[error("{0}")]
    Default(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unexpected Error: {0}")]
    UnexpectedError(String),

    #[error(transparent)]
    UrlError(#[from] url::ParseError),
}

impl From<io::Error> for ConfigUtilsError {
    fn from(e: io::Error) -> Self {
        Self::Default(e.to_string())
    }
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! config_error {
    ($msg:literal) => {
        $crate::ConfigUtilsError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::ConfigUtilsError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::ConfigUtilsError::Default(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! config_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::config_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::config_error!($fmt, $($arg)*))
    };
}
