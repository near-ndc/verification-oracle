use near_crypto::SecretKey;
use near_sdk::serde::de::{self, Error};
use near_sdk::serde::Deserialize;
use std::{env::VarError, str::FromStr};

#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct SignerConfig {
    pub credentials: SignerCredentials,
}

#[derive(Debug, Clone)]
pub struct SignerCredentials {
    pub signing_key: SecretKey,
}

impl<'de> Deserialize<'de> for SignerCredentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let properties: std::collections::HashMap<String, String> =
            Deserialize::deserialize(deserializer).unwrap_or_default();

        let raw_signing_key = match std::env::var("SIGNING_KEY") {
          Err(VarError::NotPresent) => properties.get("signingKey").cloned(),
          Err(VarError::NotUnicode(invalid_data)) => {
              return Err(de::Error::custom(format!("Invalid SIGNING_KEY {:?}", invalid_data)))
          },
          Ok(value) => Some(value),
        }.ok_or_else(|| {
            D::Error::custom("Signing key should be provided either with SIGNING_KEY env variable or within configuration file")
        })?;

        let signing_key = SecretKey::from_str(&raw_signing_key).map_err(|e| {
            de::Error::custom(format!("Signing key deserialization failure. Error {e}"))
        })?;

        if !verify_signing_key(&signing_key) {
            return Err(de::Error::custom("Signing key is incorrect"));
        }

        Ok(Self { signing_key })
    }
}

fn verify_signing_key(signing_key: &SecretKey) -> bool {
    let verification_data = "verify".as_bytes();
    let sig = signing_key.sign(verification_data);
    sig.verify(verification_data, &signing_key.public_key())
}
