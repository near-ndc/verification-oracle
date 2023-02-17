use secp256k1::{ecdsa, All, Error, Message, PublicKey, Secp256k1, SecretKey};
use serde::Deserialize;
use std::str::FromStr;
use web3::signing::keccak256;

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignerConfig {
    pub credentials: SignerCredentials,
    pub expiration_timeout: i64,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct SignerCredentials {
    pub seckey: String,
    pub pubkey: String,
}

pub struct Signer {
    pub secp: Secp256k1<All>,
}

impl Signer {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }
}

impl Signer {
    pub fn sign(&self, seckey: &str, message: &[u8]) -> Result<ecdsa::Signature, Error> {
        let message = Message::from_slice(keccak256(message).as_ref())?;
        let seckey = SecretKey::from_str(seckey)?;

        Ok(self.secp.sign_ecdsa(&message, &seckey))
    }

    pub fn verify(&self, message: &[u8], signature: [u8; 64], pubkey: &str) -> Result<(), Error> {
        let message = Message::from_slice(keccak256(message).as_ref())?;
        let signature = ecdsa::Signature::from_compact(&signature)?;
        let pubkey = PublicKey::from_str(pubkey)?;

        self.secp.verify_ecdsa(&message, &signature, &pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::ToHex;
    use serde_json::json;

    #[test]
    fn test_signer() {
        let msg = serde_json::to_string(&json!({
            "test": "test abcd"
        }))
        .unwrap();

        let (seckey, pubkey) = generate_keys();
        let signer = Signer::new();

        let seckey_text = seckey.as_ref().encode_hex::<String>();
        let pubkey_text = pubkey.to_string();

        let signature = signer
            .sign(
                &seckey_text,
                serde_json::to_string(&msg).unwrap().as_bytes(),
            )
            .unwrap();

        signer
            .verify(
                serde_json::to_string(&msg).unwrap().as_bytes(),
                signature.serialize_compact(),
                &pubkey_text,
            )
            .unwrap();
    }

    pub fn generate_keys() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        secp.generate_keypair(&mut rng)
    }
}
