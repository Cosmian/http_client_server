//! Logging macros that annotate each event with a `fn_name` structured field.
//!
//! The full tracing field syntax is preserved: `target:`, `?field`, `%field`,
//! named fields (`key = value`), and positional format strings all work
//! exactly as they do with the bare `tracing::` macros.
//! A `fn_name` structured field is automatically injected so that every log
//! event carries the name of the emitting function, which is visible in
//! structured back-ends (OTLP, JSON) and standard `tracing-subscriber` output.

/// Helper: extract the current function name at compile time.
///
/// Returns `&'static str` — the last path segment of the calling function.
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
        _strip(::std::any::type_name_of_val(&_f))
    }};
}

/// Emit a `tracing::info!` event, automatically adding a `fn_name` field.
///
/// All standard tracing field syntax is supported:
/// ```rust,ignore
/// info!("plain message");
/// info!("format {}", value);
/// info!(target: "my_target", "message");
/// info!(key = %value, "message");
/// info!(?err, "import failed");
/// ```
#[macro_export]
macro_rules! info {
    // `target:` must remain the first token — inject fn_name right after it.
    // The fn_name is bound to a local to avoid passing a block-expression
    // directly as a macro argument (which confuses token-tree parsers such as
    // `tokio::select!`).
    (target: $target:expr, $($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::info!(target: $target, fn_name = __kms_fn_name, $($rest)*)
    }};
    // All other syntax (plain message, structured fields, ?field, %field …).
    ($($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::info!(fn_name = __kms_fn_name, $($rest)*)
    }};
}

/// Emit a `tracing::debug!` event, automatically adding a `fn_name` field.
#[macro_export]
macro_rules! debug {
    (target: $target:expr, $($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::debug!(target: $target, fn_name = __kms_fn_name, $($rest)*)
    }};
    ($($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::debug!(fn_name = __kms_fn_name, $($rest)*)
    }};
}

/// Emit a `tracing::warn!` event, automatically adding a `fn_name` field.
#[macro_export]
macro_rules! warn {
    (target: $target:expr, $($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::warn!(target: $target, fn_name = __kms_fn_name, $($rest)*)
    }};
    ($($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::warn!(fn_name = __kms_fn_name, $($rest)*)
    }};
}

/// Emit a `tracing::error!` event, automatically adding a `fn_name` field.
#[macro_export]
macro_rules! error {
    (target: $target:expr, $($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::error!(target: $target, fn_name = __kms_fn_name, $($rest)*)
    }};
    ($($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::error!(fn_name = __kms_fn_name, $($rest)*)
    }};
}

/// Emit a `tracing::trace!` event, automatically adding a `fn_name` field.
#[macro_export]
macro_rules! trace {
    (target: $target:expr, $($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::trace!(target: $target, fn_name = __kms_fn_name, $($rest)*)
    }};
    ($($rest:tt)*) => {{
        let __kms_fn_name = $crate::__fn_name!();
        $crate::reexport::tracing::trace!(fn_name = __kms_fn_name, $($rest)*)
    }};
}
