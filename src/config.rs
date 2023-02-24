use crate::signer::SignerConfig;
use crate::verification_provider::VerificationProviderConfig;
use config::{self, ConfigError};
use near_sdk::serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct AppConfig {
    pub port: u16,
    pub verification_provider: VerificationProviderConfig,
    pub signer: SignerConfig,
}

pub fn load_config() -> Result<AppConfig, ConfigError> {
    config::Config::builder()
        // Load default set of configuration
        .add_source(config::File::with_name("config/default"))
        // Overlay configuration with local configuration
        .add_source(config::File::with_name("config/local").required(false))
        .build()
        .and_then(|config| config.try_deserialize())
}
