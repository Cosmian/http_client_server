//! Logging macros that prefix each message with the calling function name.

/// Helper: extract the current function name at compile time.
#[doc(hidden)]
#[macro_export]
macro_rules! __fn_name {
    () => {{
        // `type_name_of_val` on a nested closure yields a path ending in
        // `::{{closure}}`. We strip that suffix and extract the last segment.
        fn _f() {}
        fn _strip(name: &str) -> &str {
            // Remove `::_f` suffix
            let trimmed = match name.rfind("::") {
                Some(pos) => &name[..pos],
                None => name,
            };
            // Take last segment
            match trimmed.rfind("::") {
                Some(pos) => &trimmed[pos + 2..],
                None => trimmed,
            }
        }
        _strip(std::any::type_name_of_val(&_f))
    }};
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::reexport::tracing::info!("[{}] {}", $crate::__fn_name!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::reexport::tracing::debug!("[{}] {}", $crate::__fn_name!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::reexport::tracing::warn!("[{}] {}", $crate::__fn_name!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::reexport::tracing::error!("[{}] {}", $crate::__fn_name!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::reexport::tracing::trace!("[{}] {}", $crate::__fn_name!(), format_args!($($arg)*))
    };
}
