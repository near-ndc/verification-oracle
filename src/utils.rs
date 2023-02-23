use backtrace::Backtrace;
use hex::FromHex;
use std::{panic, thread};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter, Registry};

pub fn set_heavy_panic() {
    panic::set_hook(Box::new(|panic_info| {
        let backtrace = Backtrace::new();

        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            log::error!("Panic occurred: {:?}", s);
        }

        // Get code location
        let location = panic_info.location().unwrap();

        // Extract msg
        let msg = match panic_info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Box<Any>",
            },
        };

        let handle = thread::current();
        let thread_name = handle.name().unwrap_or("<unnamed>");

        log::error!(
            "thread '{}' panicked at '{}', {}",
            thread_name,
            location,
            msg
        );

        log::error!("{:?}", backtrace);

        std::process::exit(1)
    }));
}

/// Enables console logging and optionally file logging
pub fn enable_logging() {
    // Setup subscriber to print out logs from tracing
    let subscriber = Registry::default().with(
        fmt::Layer::default()
            // Enable colored output
            .with_ansi(true)
            // Write to console
            .with_writer(std::io::stdout)
            // Filter messages based on RUST_LOG env variable
            .with_filter(EnvFilter::from_default_env()),
    );

    tracing::subscriber::set_global_default(subscriber).unwrap();
}

pub fn parse_hex_signature<T>(hex_text: &str) -> Result<T, hex::FromHexError>
where
    T: FromHex<Error = hex::FromHexError>,
{
    let hex_text = hex_text.strip_prefix("0x").unwrap_or(hex_text);

    <T>::from_hex(hex_text)
}
