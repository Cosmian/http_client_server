use std::fmt::Display;

use super::ConfigUtilsError;

pub(crate) type ConfigUtilsResult<R> = Result<R, ConfigUtilsError>;

#[allow(dead_code)]
pub(crate) trait ConfigUtilsResultHelper<T> {
    fn context(self, context: &str) -> ConfigUtilsResult<T>;
    fn with_context<D, O>(self, op: O) -> ConfigUtilsResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> ConfigUtilsResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> ConfigUtilsResult<T> {
        self.map_err(|e| ConfigUtilsError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> ConfigUtilsResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| ConfigUtilsError::Default(format!("{}: {e}", op())))
    }
}

impl<T> ConfigUtilsResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> ConfigUtilsResult<T> {
        self.ok_or_else(|| ConfigUtilsError::Default(context.to_owned()))
    }

    fn with_context<D, O>(self, op: O) -> ConfigUtilsResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| ConfigUtilsError::Default(format!("{}", op())))
    }
}
