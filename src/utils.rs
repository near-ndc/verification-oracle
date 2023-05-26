use crate::ExternalAccountId;
use backtrace::Backtrace;
use near_sdk::{
    serde::{de, Deserialize},
    serde_json::Value,
};
use std::str::FromStr;
use std::{panic, thread};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter, Registry};
use uuid::Uuid;

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
            // disable colored output
            .with_ansi(false)
            // Write to console
            .with_writer(std::io::stdout)
            // Filter messages based on RUST_LOG env variable
            .with_filter(EnvFilter::from_default_env()),
    );

    tracing::subscriber::set_global_default(subscriber).unwrap();
}

pub fn de_strings_joined_by_plus<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let levels = String::deserialize(deserializer)?
        .split('+')
        .filter_map(|level| T::deserialize(Value::from(level)).ok())
        .collect();

    Ok(levels)
}

pub fn de_external_account_id_from_uuid<'de, D>(
    deserializer: D,
) -> Result<ExternalAccountId, D::Error>
where
    D: de::Deserializer<'de>,
{
    let uuid = Uuid::from_str(&String::deserialize(deserializer)?).map_err(|e| {
        de::Error::custom(format!(
            "Unable to deserialize external account id from uuid. Error: {e:?}"
        ))
    })?;

    Ok(uuid.into())
}
