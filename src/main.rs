mod config;
mod error;
mod signer;
mod utils;
mod verification_provider;

use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use error::AppError;
use near_crypto::Signature;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::AccountId;
use tower_http::cors::CorsLayer;

use crate::config::AppConfig;
use utils::{enable_logging, set_heavy_panic};
use verification_provider::FractalClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Exit on any panic in any async task
    set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    enable_logging();
    let config = config::load_config()?;

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

    let state = AppState::new(config.clone())?;

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
    pub client: FractalClient,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, AppError> {
        Ok(Self {
            client: FractalClient::create(config.verification_provider.clone())?,
            config,
        })
    }
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct VerificationReq {
    pub code: String,
    pub claimer: AccountId,
    pub redirect_uri: String,
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

    let user = match state.client.fetch_user(req.code, req.redirect_uri).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Unable to fetch user. Error: {:?}", e);
            return Err(e);
        }
    };

    if state.client.verify(&user) {
        // Account is verified
        create_verified_account_response(&state.config, req.claimer, user.uid)
    } else {
        Err(AppError::UserNotVerified)
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
    use crate::{create_verified_account_response, AppConfig, VerifiedAccountToken};
    use assert_matches::assert_matches;
    use base64::{engine::general_purpose, Engine};
    use near_crypto::{KeyType, Signature};
    use near_sdk::borsh::BorshDeserialize;
    use near_sdk::AccountId;

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
