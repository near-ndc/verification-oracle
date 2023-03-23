mod config;
mod error;
mod signer;
mod utils;
mod verification_provider;

use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use error::AppError;
use hex::ToHex;
use near_crypto::Signature;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::AccountId;
use std::str::FromStr;
use tower_http::cors::CorsLayer;
use web3::signing::{hash_message, recover};
use web3::types::Address;

use crate::config::AppConfig;
use utils::{enable_logging, parse_hex_signature, set_heavy_panic};
use verification_provider::FuseClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Exit on any panic in any async task
    set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    enable_logging();

    let config = config::load_config()?;

    // initialize tracing
    // Log a base64 encoded ed25519 public key to be used in smart contract for signature verification
    tracing::info!(
        "ED25519 public key (base64 encoded): {}",
        general_purpose::STANDARD.encode(
            config
                .signer
                .credentials
                .signing_key
                .public_key()
                .unwrap_as_ed25519()
                .as_ref()
        )
    );

    let addr = config
        .listen_address
        .parse()
        .expect("Can't parse socket address");

    let state = AppState::new(
        config.clone(),
        config.verification_provider.identity_contract_address,
    )?;

    let app = Router::new()
        .route("/verify", post(verify))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::debug!("Server listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub client: FuseClient,
}

impl AppState {
    pub fn new(
        config: AppConfig,
        contract_addr: Address,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let web3 = web3::Web3::new(web3::transports::Http::new(
            &config.verification_provider.url,
        )?);

        Ok(Self {
            config,
            client: FuseClient::create(&web3, contract_addr.to_owned())?,
        })
    }
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct VerificationReq {
    #[serde(rename = "m")]
    pub message: String,
    #[serde(rename = "c")]
    pub claimer: AccountId,
    #[serde(rename = "sig")]
    pub signature: String,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct User {
    #[serde(rename = "a")]
    pub account: Account,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Account {
    pub value: String,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct VerifiedAccountToken {
    pub claimer: AccountId,
    pub ext_account: String,
    pub timestamp: u64,
}

#[derive(Serialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct SignedResponse {
    #[serde(rename = "m")]
    pub message: String,
    #[serde(rename = "sig")]
    pub signature_ed25519: String,
}

pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerificationReq>,
) -> Result<Json<SignedResponse>, AppError> {
    tracing::debug!("Req: {:?}", req);

    let raw_signature =
        parse_hex_signature::<[u8; 65]>(&req.signature).map_err(|_| AppError::SignatureInvalid)?;
    let raw_message = req.message.as_bytes();

    // TODO: verify nonce

    let user = near_sdk::serde_json::from_str::<User>(&req.message)
        .map_err(|_| AppError::SignatureInvalid)?;

    let account_addr =
        Address::from_str(&user.account.value).map_err(|_| AppError::UserAddressInvalid)?;

    let recovered_ext_account = recover(
        hash_message(raw_message).as_bytes(),
        &raw_signature[..64],
        raw_signature[64] as i32 - 27,
    )
    .map(|account| ["0x", &account.as_bytes().encode_hex::<String>()].concat())
    .map_err(|_| AppError::SignatureInvalid)?;

    tracing::debug!(
        "User account address to verify: {:?}",
        recovered_ext_account
    );

    if recovered_ext_account != user.account.value.to_lowercase() {
        return Err(AppError::SignatureInvalid);
    }

    match state.client.is_whitelisted(account_addr).await {
        // Account is verified
        Ok(true) => {
            create_verified_account_response(&state.config, req.claimer, recovered_ext_account)
        }
        // Account is not verified
        Ok(false) => Err(AppError::UserNotVerified),
        // Any contract failure
        Err(_) => Err(AppError::TransportProtocolError),
    }
}

/// Creates signed json response with verified account
fn create_verified_account_response(
    config: &AppConfig,
    claimer: AccountId,
    ext_account: String,
) -> Result<Json<SignedResponse>, AppError> {
    let credentials = &config.signer.credentials;
    let raw_message = VerifiedAccountToken {
        claimer,
        ext_account,
        timestamp: Utc::now().timestamp() as u64,
    }
    .try_to_vec()
    .map_err(|_| AppError::SigningError)?;
    let signature = credentials.signing_key.sign(&raw_message);

    if !signature.verify(&raw_message, &credentials.signing_key.public_key()) {
        return Err(AppError::SigningError);
    }

    let raw_signature_ed25519 = match signature {
        Signature::ED25519(signature) => signature.to_bytes(),
        _ => return Err(AppError::SigningError),
    };

    let message = general_purpose::STANDARD.encode(&raw_message);
    let signature_ed25519 = general_purpose::STANDARD.encode(raw_signature_ed25519);

    Ok(Json(SignedResponse {
        message,
        signature_ed25519,
    }))
}

#[cfg(test)]
mod tests {
    use crate::signer::{SignerConfig, SignerCredentials};
    use crate::{
        create_verified_account_response, AppConfig, User, VerificationReq, VerifiedAccountToken,
    };
    use assert_matches::assert_matches;
    use base64::{engine::general_purpose, Engine};
    use near_crypto::{KeyType, Signature};
    use near_sdk::borsh::BorshDeserialize;
    use near_sdk::AccountId;

    #[test]
    fn test_verification_req_parser() {
        let req = near_sdk::serde_json::from_str::<VerificationReq>(r#"{"m":"{\"I\":{\"value\":\"Ukraine\",\"attestation\":\"\"},\"n\":{\"value\":\"Oleksandr Molotsylo\",\"attestation\":\"\"},\"e\":{\"value\":\"motzart66@gmail.com\",\"attestation\":\"\"},\"m\":{\"value\":\"\",\"attestation\":\"\"},\"a\":{\"value\":\"0xd6Bd36ce6f5e53da4eb7f83522441008F3A8644c\",\"attestation\":\"\"},\"v\":{\"value\":false,\"attestation\":\"\"},\"nonce\":{\"value\":1676466734313,\"attestation\":\"\"}}","c":"test.near","sig":"0x6cc861240b8f90f06ea519a536ceda0df7507518e87d3de13cfdeabc600dea531562a6fb8c8beba80d8b87384898679176df0a514be116d7c6c3c47a628e7d161b"}"#).unwrap();

        let _ = near_sdk::serde_json::from_str::<User>(&req.message).unwrap();
    }

    #[test]
    fn test_create_verified_account_response() {
        let signing_key = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
        let config = AppConfig {
            signer: SignerConfig {
                credentials: SignerCredentials { signing_key },
            },
            listen_address: "0.0.0.0:8080".to_owned(),
            verification_provider: Default::default(),
        };

        let claimer = AccountId::new_unchecked("test.near".to_owned());
        let ext_account = "test".to_owned();
        let res = create_verified_account_response(&config, claimer.clone(), ext_account.clone())
            .unwrap();

        let credentials = &config.signer.credentials;

        let decoded_bytes = general_purpose::STANDARD.decode(&res.message).unwrap();

        assert!(Signature::from_parts(
            KeyType::ED25519,
            &general_purpose::STANDARD
                .decode(&res.signature_ed25519)
                .unwrap()
        )
        .unwrap()
        .verify(&decoded_bytes, &credentials.signing_key.public_key()));

        let decoded_msg = VerifiedAccountToken::try_from_slice(&decoded_bytes).unwrap();

        assert_matches!(decoded_msg, VerifiedAccountToken {
            claimer: claimer_res,
            ext_account: ext_account_res,
            timestamp: _
        } if claimer_res == claimer && ext_account_res == ext_account);
    }
}
