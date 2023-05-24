use crate::{utils, AppError, VerificationReq};
use chrono::{DateTime, Utc};
use near_sdk::{
    serde::{Deserialize, Serialize},
    serde_json,
};
use reqwest::Client;

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct VerificationProviderConfig {
    pub path: String,
    pub request_token_url: String,
    pub request_user_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct UserToken {
    pub access_token: String,
    pub token_type: String,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct User {
    pub uid: String,
    pub emails: Vec<Email>,
    pub phones: Vec<Phone>,
    pub wallets: Vec<Wallet>,
    pub verification_cases: Vec<VerificationCase>,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Email {
    pub address: String,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Phone {
    pub number: String,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Wallet {
    pub id: String,
    pub address: String,
    pub currency: String,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct VerificationCase {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(deserialize_with = "utils::de_strings_joined_by_plus")]
    pub level: Vec<VerificationLevel>,
    pub status: VerificationStatus,
    pub credential: CredentialStatus,
    pub details: VerificationDetails,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde", rename_all = "lowercase")]
pub enum VerificationLevel {
    Uniqueness,
    Basic,
    Plus,
    Liveness,
    Selfie,
    Sow,
    Telegram,
    Twitter,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde", rename_all = "lowercase")]
pub enum VerificationStatus {
    Pending,
    Contacted,
    Done,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde", rename_all = "lowercase")]
pub enum CredentialStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct VerificationDetails {
    pub liveness: bool,
}

#[derive(Clone, Debug)]
pub struct FractalClient {
    inner_client: Client,
    config: VerificationProviderConfig,
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[serde(crate = "near_sdk::serde", rename_all = "lowercase")]
pub enum KycStatus {
    Unavailable,
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone)]
pub struct VerifiedUser {
    pub user_id: String,
    pub kyc_status: KycStatus,
}

impl FractalClient {
    pub fn create(config: VerificationProviderConfig) -> Result<Self, AppError> {
        let inner_client = Client::builder().pool_max_idle_per_host(0).build()?;

        Ok(Self {
            inner_client,
            config,
        })
    }

    pub async fn verify(&self, req: &VerificationReq) -> Result<VerifiedUser, AppError> {
        match self.fetch_user(&req.code, &req.redirect_uri).await {
            Ok(mut user) if user.is_verified_uniqueness() => Ok(VerifiedUser {
                kyc_status: user.get_kyc_status(),
                user_id: user.uid,
            }),
            Ok(_) => Err(AppError::UserUniquenessNotVerified),
            Err(e) => {
                tracing::error!("Unable to fetch user. Error: {:?}", e);
                Err(e)
            }
        }
    }

    async fn fetch_user(&self, auth_code: &str, redirect_uri: &str) -> Result<User, AppError> {
        let params: [(&str, &str); 5] = [
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("code", auth_code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
        ];

        let data = self
            .inner_client
            .post(&self.config.request_token_url)
            .form(&params)
            .send()
            .await?
            .text()
            .await?;

        match serde_json::from_str(&data) {
            Ok(UserToken {
                access_token,
                token_type,
            }) if token_type.as_str() == "Bearer" => self
                .inner_client
                .get(&self.config.request_user_url)
                .bearer_auth(access_token)
                .send()
                .await?
                .json::<User>()
                .await
                .map_err(AppError::from),
            Ok(token) => Err(format!("Unsupported token type {:?}", token).into()),
            Err(_) => Err(format!("Failed to parse token response {:?}", data).into()),
        }
    }
}

impl User {
    fn is_verified_uniqueness(&self) -> bool {
        self.verification_cases.iter().any(|case| {
            matches!(case,
                VerificationCase {
                    level,
                    status: VerificationStatus::Done,
                    credential: CredentialStatus::Approved,
                    ..
                } if level
                    .iter()
                    .any(|level| level == &VerificationLevel::Uniqueness)
            )
        })
    }

    fn get_kyc_status(&mut self) -> KycStatus {
        // Sort by updated_at timestamp, most recent first
        self.verification_cases
            .sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

        let cases_status = self
            .verification_cases
            .iter()
            .filter_map(|case| {
                // Ignore other than `basic+liveness` verification cases
                if !(case
                    .level
                    .iter()
                    .any(|level| level == &VerificationLevel::Basic)
                    && case
                        .level
                        .iter()
                        .any(|level| level == &VerificationLevel::Liveness))
                {
                    return None;
                }

                match case {
                    VerificationCase {
                        credential: CredentialStatus::Approved,
                        details: VerificationDetails { liveness: true },
                        ..
                    } => Some(KycStatus::Approved),
                    VerificationCase {
                        credential: CredentialStatus::Pending,
                        details: VerificationDetails { liveness: true },
                        ..
                    } => Some(KycStatus::Pending),
                    VerificationCase {
                        credential: CredentialStatus::Rejected,
                        details: VerificationDetails { liveness: true },
                        ..
                    } => Some(KycStatus::Rejected),
                    // Ignore verification cases without `liveness: true`
                    _ => None,
                }
            })
            .collect::<Vec<_>>();

        // If user has any approved case
        if cases_status
            .iter()
            .any(|status| status == &KycStatus::Approved)
        {
            return KycStatus::Approved;
        }

        // Otherwise, check the most recent result
        *cases_status.first().unwrap_or(&KycStatus::Unavailable)
    }
}
