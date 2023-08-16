mod captcha;
mod config;
mod error;
mod signer;
mod utils;
mod verification_provider;

use axum::{extract::State, routing::post, Json, Router};
use captcha::CaptchaClient;
use chrono::Utc;
use error::AppError;
use near_crypto::Signature;
use near_sdk::base64::encode;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::AccountId;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use crate::config::AppConfig;
use utils::{enable_logging, is_allowed_named_sub_account, set_heavy_panic};
use verification_provider::{
    FractalClient, FractalTokenKind, FractalUser, OAuthToken, VerificationStatus,
};

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
        encode(
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
    pub captcha: CaptchaClient,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, AppError> {
        Ok(Self {
            captcha: CaptchaClient::new(config.captcha.clone())?,
            client: FractalClient::create(config.verification_provider.clone())?,
            config,
        })
    }
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct VerificationReq {
    pub claimer: AccountId,
    #[serde(flatten)]
    pub fractal_token: FractalTokenKind,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct VerifiedAccountToken {
    pub claimer: AccountId,
    pub ext_account: ExternalAccountId,
    pub timestamp: u64,
    pub verified_kyc: bool,
}

/// External account id represented as hexadecimal string
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct ExternalAccountId(String);

impl std::fmt::Display for ExternalAccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<String> for ExternalAccountId {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl From<Uuid> for ExternalAccountId {
    fn from(value: Uuid) -> Self {
        let mut buf = [0u8; uuid::fmt::Simple::LENGTH];
        Self(value.as_simple().encode_lower(&mut buf).to_owned())
    }
}

#[derive(Serialize, Debug)]
#[serde(crate = "near_sdk::serde", untagged)]
pub enum VerificationResponse {
    Approved(ApprovedResponse),
    Pending(PendingResponse),
}

/// Signed response for a fractal user with approved face verification
#[derive(Serialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct ApprovedResponse {
    #[serde(rename = "m")]
    pub message: String,
    #[serde(rename = "sig")]
    pub signature_ed25519: String,
    #[serde(rename = "kyc")]
    pub kyc_status: VerificationStatus,
}

/// Response for a fractal user whos face verification is pending for final decision
#[derive(Serialize, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub struct PendingResponse {
    pub token: OAuthToken,
}

pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerificationReq>,
) -> Result<Json<VerificationResponse>, AppError> {
    tracing::debug!("Request: {req:?}");

    if !state.config.allow_named_sub_accounts && !is_allowed_named_sub_account(&req.claimer) {
        return Err(AppError::NotAllowedNamedSubAccount(req.claimer));
    }

    if let Some(captcha_token) = req.fractal_token.captcha() {
        match state.captcha.verify(captcha_token).await {
            Ok(true) => (),
            Ok(false) => return Err(AppError::SuspiciousUser),
            Err(e) => {
                tracing::error!(
                    "Captcha verification failure for an account `{:?}`. Error: {e:?}",
                    req.claimer
                );
                return Err(AppError::from(e));
            }
        };
    }

    let user = state.client.fetch_user(req.fractal_token).await?;

    let res = match user.fv_status {
        VerificationStatus::Approved => create_approved_response(&state.config, req.claimer, user),
        VerificationStatus::Pending => Ok(VerificationResponse::Pending(PendingResponse {
            token: user.token,
        })),
        VerificationStatus::Rejected => Err(AppError::FaceVerificationRejected),
        VerificationStatus::Unavailable => Err(AppError::FaceVerificationMissed),
    };

    tracing::debug!("Response: {res:?}");

    res.map(Json)
}

/// Creates signed json response for fractal user with approved face verification
fn create_approved_response(
    config: &AppConfig,
    claimer: AccountId,
    user: FractalUser,
) -> Result<VerificationResponse, AppError> {
    let credentials = &config.signer.credentials;
    let raw_message = VerifiedAccountToken {
        claimer,
        ext_account: user.user_id,
        timestamp: Utc::now().timestamp() as u64,
        verified_kyc: user.kyc_status == VerificationStatus::Approved,
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

    let message = encode(&raw_message);
    let signature_ed25519 = encode(raw_signature_ed25519);

    Ok(VerificationResponse::Approved(ApprovedResponse {
        message,
        signature_ed25519,
        kyc_status: user.kyc_status,
    }))
}

#[cfg(test)]
mod tests {
    use crate::signer::{SignerConfig, SignerCredentials};
    use crate::*;
    use assert_matches::assert_matches;
    use chrono::Utc;
    use near_crypto::{KeyType, Signature};
    use near_sdk::base64::decode;
    use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
    use near_sdk::AccountId;
    use std::str::FromStr;
    use uuid::Uuid;

    #[test]
    fn test_approved_account_response_no_kyc() {
        let config = gen_app_config(false);

        let claimer = AccountId::new_unchecked("test.near".to_owned());
        let verified_user = FractalUser {
            user_id: Uuid::default().into(),
            token: OAuthToken {
                access_token: "some_auth_token".to_owned(),
                refresh_token: "some_refresh_token".to_owned(),
                expires_at: Utc::now(),
            },
            fv_status: VerificationStatus::Approved,
            kyc_status: VerificationStatus::Unavailable,
        };
        let approved_res =
            match create_approved_response(&config, claimer.clone(), verified_user.clone()) {
                Ok(VerificationResponse::Approved(res)) => res,
                _ => panic!("Not an approved verification"),
            };

        let credentials = &config.signer.credentials;

        let decoded_bytes = decode(&approved_res.message).unwrap();

        assert!(Signature::from_parts(
            KeyType::ED25519,
            &decode(&approved_res.signature_ed25519).unwrap()
        )
        .unwrap()
        .verify(&decoded_bytes, &credentials.signing_key.public_key()));

        let decoded_msg = VerifiedAccountToken::try_from_slice(&decoded_bytes).unwrap();

        assert_matches!(decoded_msg, VerifiedAccountToken {
            claimer: claimer_res,
            ext_account: ext_account_res,
            timestamp: _,
            verified_kyc: false,
        } if claimer_res == claimer && ext_account_res == verified_user.user_id);
    }

    #[test]
    fn test_approved_account_response_with_kyc() {
        let config = gen_app_config(false);

        let claimer = AccountId::new_unchecked("test.near".to_owned());
        let verified_user = FractalUser {
            user_id: Uuid::default().into(),
            token: OAuthToken {
                access_token: "some_auth_token".to_owned(),
                refresh_token: "some_refresh_token".to_owned(),
                expires_at: Utc::now(),
            },
            fv_status: VerificationStatus::Approved,
            kyc_status: VerificationStatus::Approved,
        };

        let approved_res =
            match create_approved_response(&config, claimer.clone(), verified_user.clone()) {
                Ok(VerificationResponse::Approved(res)) => res,
                _ => panic!("Not an approved verification"),
            };

        let credentials = &config.signer.credentials;

        let decoded_bytes = decode(&approved_res.message).unwrap();

        assert!(Signature::from_parts(
            KeyType::ED25519,
            &decode(&approved_res.signature_ed25519).unwrap()
        )
        .unwrap()
        .verify(&decoded_bytes, &credentials.signing_key.public_key()));

        let decoded_msg = VerifiedAccountToken::try_from_slice(&decoded_bytes).unwrap();

        assert_matches!(decoded_msg, VerifiedAccountToken {
            claimer: claimer_res,
            ext_account: ext_account_res,
            timestamp: _,
            verified_kyc: true,
        } if claimer_res == claimer && ext_account_res == verified_user.user_id);
    }

    #[test]
    fn test_account_id_uuid_borsh_serde() {
        let serialized = VerifiedAccountToken {
            claimer: AccountId::new_unchecked("test.near".to_owned()),
            ext_account: Uuid::from_str("f20181ba-fc0c-11ed-be56-0242ac120002")
                .unwrap()
                .into(),
            timestamp: Utc::now().timestamp() as u64,
            verified_kyc: true,
        }
        .try_to_vec()
        .unwrap();

        assert_eq!(
            VerifiedAccountToken::try_from_slice(serialized.as_slice())
                .unwrap()
                .ext_account
                .0,
            "f20181bafc0c11edbe560242ac120002"
        );
    }

    fn gen_app_config(allow_named_sub_accounts: bool) -> AppConfig {
        let signing_key = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);

        AppConfig {
            signer: SignerConfig {
                credentials: SignerCredentials { signing_key },
            },
            listen_address: "0.0.0.0:8080".to_owned(),
            verification_provider: Default::default(),
            captcha: Default::default(),
            allow_named_sub_accounts,
        }
    }
}
