use near_crypto::{PublicKey, SecretKey};
use near_sdk::serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct SignerConfig {
    pub credentials: SignerCredentials,
    pub expiration_timeout: i64,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct SignerCredentials {
    pub seckey: SecretKey,
    pub pubkey: PublicKey,
}

#[cfg(test)]
pub fn generate_keys() -> (SecretKey, PublicKey) {
    let seckey = SecretKey::from_random(near_crypto::KeyType::ED25519);
    let pubkey = seckey.public_key();

    (seckey, pubkey)
}
