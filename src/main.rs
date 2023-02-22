mod config;
mod error;
mod signer;
mod utils;
mod verification_provider;

use axum::{extract::State, routing::post, Json, Router};
use chrono::{Duration, Utc};
use error::AppError;
use hex::ToHex;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use tower_http::cors::{AllowOrigin, CorsLayer};
use web3::signing::{hash_message, recover};
use web3::types::Address;

use crate::config::AppConfig;
use utils::{enable_logging, parse_hex_signature, set_heavy_panic};
use verification_provider::{FuseClient, IDENTITY_CONTRACT_ADDRESS};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Exit on any panic in any async task
    set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    enable_logging();

    let contract_addr = *IDENTITY_CONTRACT_ADDRESS;

    // initialize tracing
    let config = config::load_config().unwrap();

    let state = AppState::new(config.clone(), contract_addr)?;

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(AllowOrigin::predicate(
            |origin: &http::HeaderValue, request_parts: &http::request::Parts| {
                println!("Origin: {:?} Parts: {:?}", origin, request_parts);
                true
            },
        )); //.allow_origin(Any);

    let app = Router::new()
        .route("/verify", post(verify))
        .with_state(state)
        .layer(cors);

    let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
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
pub struct VerificationReq {
    #[serde(rename = "m")]
    pub message: String,
    #[serde(rename = "sig")]
    pub signature: String,
}

#[derive(Deserialize, Debug)]
pub struct User {
    #[serde(rename = "a")]
    pub account: Account,
}

#[derive(Deserialize, Debug)]
pub struct Account {
    pub value: String,
}

#[derive(Serialize, Debug)]
pub struct VerifiedAccountToken {
    #[serde(rename = "a")]
    pub account: String,
    #[serde(rename = "e")]
    pub expire_at: u64,
}

#[derive(Serialize, Debug)]
pub struct SignedResponse {
    #[serde(rename = "m")]
    pub message: String,
    #[serde(rename = "sig")]
    pub signature: String,
}

pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerificationReq>,
) -> Result<Json<SignedResponse>, AppError> {
    tracing::debug!("Req: {:?}", req);

    let raw_signature =
        parse_hex_signature(req.signature).map_err(|_| AppError::SignatureInvalid)?;
    let raw_message = req.message.as_bytes();

    // TODO: verify nonce

    let user =
        serde_json::from_str::<User>(&req.message).map_err(|_| AppError::SignatureInvalid)?;

    let account_addr =
        Address::from_str(&user.account.value).map_err(|_| AppError::UserAddressInvalid)?;

    let recovered_account = recover(
        hash_message(raw_message).as_bytes(),
        &raw_signature[..64],
        raw_signature[64] as i32 - 27,
    )
    .map(|account| ["0x", &account.as_bytes().encode_hex::<String>()].concat())
    .map_err(|_| AppError::SignatureInvalid)?;

    tracing::debug!("User account address to verify: {:?}", recovered_account);

    if recovered_account != user.account.value.to_lowercase() {
        return Err(AppError::SignatureInvalid);
    }

    // TODO: remove this
    // let verified = state.client.is_whitelisted(Address::from_str("2909DE691E22eE927D6AC1Abb5d1B9b6CA7976f0").unwrap()).await;

    match state.client.is_whitelisted(account_addr).await {
        // Account is verified
        Ok(true) => create_verified_account_response(&state.config, recovered_account),
        // Account is not verified
        Ok(false) => Err(AppError::UserNotVerified),
        // Any contract failure
        Err(_) => Err(AppError::TransportProtocolError),
    }
}

/// Creates signed json response with verified account
fn create_verified_account_response(
    config: &AppConfig,
    account: String,
) -> Result<Json<SignedResponse>, AppError> {
    let expire_at = Utc::now() + Duration::milliseconds(config.signer.expiration_timeout);
    let credentials = &config.signer.credentials;
    let signer = signer::Signer::new();
    let message = serde_json::to_string(&VerifiedAccountToken {
        account,
        expire_at: expire_at.timestamp_millis() as u64,
    })
    .map_err(|_| AppError::SigningError)?;

    let signature = signer
        .sign(&credentials.seckey, message.as_bytes())
        .map_err(|_| AppError::SigningError)?
        .serialize_compact();

    // TODO: should we verify signed message before response?
    signer
        .verify(message.as_bytes(), signature, &credentials.pubkey)
        .map_err(|_| AppError::SigningError)?;

    Ok(Json(SignedResponse {
        message,
        signature: signature.encode_hex::<String>(),
    }))
}

#[cfg(test)]
mod tests {
    use crate::{User, VerificationReq};

    #[test]
    fn test_verification_req_parser() {
        let req = serde_json::from_str::<VerificationReq>(r#"{"m":"{\"I\":{\"value\":\"Ukraine\",\"attestation\":\"\"},\"n\":{\"value\":\"Oleksandr Molotsylo\",\"attestation\":\"\"},\"e\":{\"value\":\"motzart66@gmail.com\",\"attestation\":\"\"},\"m\":{\"value\":\"\",\"attestation\":\"\"},\"a\":{\"value\":\"0xd6Bd36ce6f5e53da4eb7f83522441008F3A8644c\",\"attestation\":\"\"},\"v\":{\"value\":false,\"attestation\":\"\"},\"nonce\":{\"value\":1676466734313,\"attestation\":\"\"}}","sig":"0x6cc861240b8f90f06ea519a536ceda0df7507518e87d3de13cfdeabc600dea531562a6fb8c8beba80d8b87384898679176df0a514be116d7c6c3c47a628e7d161b"}"#).unwrap();

        let _ = serde_json::from_str::<User>(&req.message).unwrap();
    }
}
