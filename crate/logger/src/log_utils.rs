use std::{
    env::{set_var, var},
    sync::Once,
};

use tracing_subscriber::{
    EnvFilter, layer::SubscriberExt, registry, reload, util::SubscriberInitExt,
};

static LOG_INIT: Once = Once::new();

/// # Panics
///
/// Will panic if we cannot set global tracing subscriber
pub fn log_init(default_value: Option<&str>) {
    if default_value.is_some() || var("RUST_LOG").is_ok() {
        LOG_INIT.call_once(|| unsafe {
            if let Ok(current_value) = var("RUST_LOG") {
                set_var("RUST_LOG", current_value);
                set_var("RUST_BACKTRACE", "full");
                tracing_setup();
            } else if let Some(input_value) = default_value {
                set_var("RUST_LOG", input_value);
                set_var("RUST_BACKTRACE", "full");
                tracing_setup();
            }
        });
    }
}

/// # Panics
///
/// Will panic if:
/// - we cannot set global subscriber
/// - we cannot init the log tracer
fn tracing_setup() {
    let format = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_file(true)
        .with_ansi(true)
        .compact();

    let (filter, _reload_handle) = reload::Layer::new(EnvFilter::from_default_env());

    registry().with(filter).with(format).init();
}
