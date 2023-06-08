use crate::{utils, AppError, ExternalAccountId};
use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, Duration, TimeZone, Utc};
use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    serde::{
        de::{self, Deserializer},
        ser::{self, Serializer},
        Deserialize, Serialize,
    },
    serde_json,
};
use reqwest::Client;

/// Minimum time required before oauth2 token expires in minutes
static OAUTH_TOKEN_MINIMUM_LIFETIME: i64 = 5;

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct VerificationProviderConfig {
    pub request_token_url: String,
    pub request_user_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde", untagged)]
pub enum FractalTokenKind {
    AuthorizationCode {
        code: String,
        captcha: String,
        redirect_uri: String,
    },
    OAuth {
        token: OAuthToken,
        redirect_uri: String,
    },
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
#[serde(crate = "near_sdk::serde", remote = "Self")]
pub struct OAuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct RawFractalToken {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    #[serde(flatten)]
    pub lifetime: TokenLifetime,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct TokenLifetime {
    pub expires_in: u64,
    pub created_at: u64,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct RawFractalUser {
    #[serde(deserialize_with = "utils::de_external_account_id_from_uuid")]
    pub uid: ExternalAccountId,
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
    pub status: CaseStatus,
    pub credential: CredentialStatus,
    pub details: VerificationDetails,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde", rename_all = "lowercase")]
pub enum VerificationLevel {
    /// Face Verification
    Uniqueness,
    /// KYC (always comes with Liveness)
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
pub enum CaseStatus {
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
pub enum VerificationStatus {
    Unavailable,
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone)]
pub struct FractalUser {
    pub user_id: ExternalAccountId,
    pub token: OAuthToken,
    pub fv_status: VerificationStatus,
    pub kyc_status: VerificationStatus,
}

impl FractalClient {
    pub fn create(config: VerificationProviderConfig) -> Result<Self, AppError> {
        let inner_client = Client::builder().pool_max_idle_per_host(0).build()?;

        Ok(Self {
            inner_client,
            config,
        })
    }

    pub async fn fetch_user(
        &self,
        fractal_token: FractalTokenKind,
    ) -> Result<FractalUser, AppError> {
        let mut oauth_token = match fractal_token {
            FractalTokenKind::AuthorizationCode {
                code, redirect_uri, ..
            } => self.acquire_oauth_token(&code, &redirect_uri).await?,
            FractalTokenKind::OAuth { token, .. } => token,
        };

        if oauth_token.requires_refresh() {
            oauth_token = self.refresh_oauth_token(oauth_token).await?;
        }

        tracing::trace!("Acquired user token: {oauth_token:?}");

        let fetched_res = self
            .inner_client
            .get(&self.config.request_user_url)
            .bearer_auth(&oauth_token.access_token)
            .send()
            .await?
            .json::<RawFractalUser>()
            .await
            .map_err(AppError::from);

        match fetched_res {
            Ok(mut user) => {
                tracing::debug!("Fetched raw user: {user:?}");

                Ok(FractalUser {
                    fv_status: user.get_status(&[VerificationLevel::Uniqueness]),
                    kyc_status: user
                        .get_status(&[VerificationLevel::Basic, VerificationLevel::Liveness]),
                    user_id: user.uid,
                    token: oauth_token,
                })
            }
            Err(e) => {
                tracing::error!("Unable to fetch user. Error: {:?}", e);
                Err(e)
            }
        }
    }

    async fn acquire_oauth_token(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<OAuthToken, AppError> {
        let params: [(&str, &str); 5] = [
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("code", code),
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

        tracing::trace!("Acquired raw fractal token response: {data}");

        match serde_json::from_str::<RawFractalToken>(&data) {
            Ok(token) if token.token_type.as_str() == "Bearer" => Ok(OAuthToken::from(token)),
            Ok(token) => Err(format!("Unsupported token type {:?}", token).into()),
            Err(_) => Err(format!("Failed to parse token response {:?}", data).into()),
        }
    }

    async fn refresh_oauth_token(&self, oauth_token: OAuthToken) -> Result<OAuthToken, AppError> {
        tracing::trace!("Refresh for OAuthToken: {oauth_token:?}");

        let params: [(&str, &str); 4] = [
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("refresh_token", &oauth_token.refresh_token),
            ("grant_type", "refresh_token"),
        ];

        let data = self
            .inner_client
            .post(&self.config.request_token_url)
            .form(&params)
            .send()
            .await?
            .text()
            .await?;

        match serde_json::from_str::<RawFractalToken>(&data) {
            Ok(token) if token.token_type.as_str() == "Bearer" => Ok(OAuthToken::from(token)),
            Ok(token) => Err(format!("Unsupported token type {:?}", token).into()),
            Err(_) => Err(format!("Failed to parse token response {:?}", data).into()),
        }
    }
}

impl RawFractalUser {
    fn get_status(&mut self, levels: &[VerificationLevel]) -> VerificationStatus {
        // Sort by updated_at timestamp, most recent first
        self.verification_cases
            .sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

        let cases_status = self
            .verification_cases
            .iter()
            .filter_map(|case| {
                // Ignore cases other than related to requested levels
                for level in levels {
                    if !case.level.iter().any(|l| l == level) {
                        return None;
                    }
                }

                match case {
                    VerificationCase {
                        credential: CredentialStatus::Approved,
                        details: VerificationDetails { liveness: true },
                        ..
                    } => Some(VerificationStatus::Approved),
                    VerificationCase {
                        credential: CredentialStatus::Pending,
                        details: VerificationDetails { liveness: true },
                        ..
                    } => Some(VerificationStatus::Pending),
                    VerificationCase {
                        credential: CredentialStatus::Rejected,
                        details: VerificationDetails { liveness: true },
                        ..
                    } => Some(VerificationStatus::Rejected),
                    // Ignore verification cases without `liveness: true`
                    _ => None,
                }
            })
            .collect::<Vec<_>>();

        // If user has any approved case
        if cases_status
            .iter()
            .any(|status| status == &VerificationStatus::Approved)
        {
            return VerificationStatus::Approved;
        }

        // Otherwise, check the most recent result
        *cases_status
            .first()
            .unwrap_or(&VerificationStatus::Unavailable)
    }
}

impl<'de> Deserialize<'de> for OAuthToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: String = Deserialize::deserialize(deserializer)?;

        let raw = general_purpose::STANDARD.decode(encoded).map_err(|e| {
            de::Error::custom(format!(
                "Failed to deserialize base64 encoded oauth token {e:?}"
            ))
        })?;

        OAuthToken::try_from_slice(&raw).map_err(|e| {
            de::Error::custom(format!(
                "Failed to deserialize borsh serialized oauth token {e:?}"
            ))
        })
    }
}

impl<'a> FractalTokenKind {
    pub fn captcha(&'a self) -> Option<&'a str> {
        match self {
            Self::AuthorizationCode { captcha, .. } => Some(captcha),
            Self::OAuth { .. } => None,
        }
    }
}

impl TokenLifetime {
    pub fn expires_at(&self) -> DateTime<Utc> {
        Utc.timestamp_nanos((self.created_at + self.expires_in) as i64 * 1_000_000_000)
    }
}

impl OAuthToken {
    pub fn requires_refresh(&self) -> bool {
        Utc::now() + Duration::minutes(OAUTH_TOKEN_MINIMUM_LIFETIME) >= self.expires_at
    }
}

impl From<RawFractalToken> for OAuthToken {
    fn from(token: RawFractalToken) -> Self {
        Self {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_at: token.lifetime.expires_at(),
        }
    }
}

impl Serialize for OAuthToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let raw = self
            .try_to_vec()
            .map_err(|e| ser::Error::custom(format!("Failed to serialize oauth token {e:?}")))?;
        let encoded = general_purpose::STANDARD.encode(raw);

        serializer.serialize_str(&encoded)
    }
}

impl BorshDeserialize for OAuthToken {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let access_token = BorshDeserialize::deserialize(buf)?;
        let refresh_token = BorshDeserialize::deserialize(buf)?;
        let ts = BorshDeserialize::deserialize(buf)?;

        Ok(OAuthToken {
            access_token,
            refresh_token,
            expires_at: Utc.timestamp_nanos(ts),
        })
    }
}

impl BorshSerialize for OAuthToken {
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> borsh::maybestd::io::Result<()> {
        let ts = self.expires_at.timestamp_nanos();
        BorshSerialize::serialize(&self.access_token, writer)?;
        BorshSerialize::serialize(&self.refresh_token, writer)?;
        BorshSerialize::serialize(&ts, writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use near_sdk::serde_json;

    #[test]
    fn test_oauth_token() {
        let expires_in = 7200;
        let now_secs = Utc::now().timestamp();
        let created_at = now_secs - expires_in; // let it expire now
        let json = format!(
            r#"{{
            "access_token": "7rgojfemuk-aq8RcA7xWxJQKv6Ux0VWJ1DQtU6178B8",
            "token_type": "bearer",
            "expires_in": {expires_in},
            "refresh_token": "thPSSHGnk3NGU5vV4V_g-Qrs47RibO9KEEhfKYEgJOw",
            "scope": "uid:read email:read",
            "created_at": {created_at}
        }}"#
        );

        let raw_token = serde_json::from_str::<RawFractalToken>(&json).unwrap();
        let mut oauth_token = OAuthToken::from(raw_token);

        assert_eq!(
            oauth_token,
            OAuthToken {
                access_token: "7rgojfemuk-aq8RcA7xWxJQKv6Ux0VWJ1DQtU6178B8".to_owned(),
                refresh_token: "thPSSHGnk3NGU5vV4V_g-Qrs47RibO9KEEhfKYEgJOw".to_owned(),
                expires_at: Utc.timestamp_opt(now_secs, 0).unwrap(),
            }
        );

        assert!(oauth_token.requires_refresh());
        oauth_token.expires_at = Utc::now() + Duration::days(1);
        assert!(!oauth_token.requires_refresh());
    }

    #[test]
    fn test_oauth_token_serde() {
        let token = FractalTokenKind::OAuth {
            redirect_uri: "https://some_url".to_owned(),
            token: OAuthToken {
                access_token: "some_auth_token".to_owned(),
                refresh_token: "some_refresh_token".to_owned(),
                expires_at: Utc::now(),
            },
        };
        let json = serde_json::to_string(&token).unwrap();
        let deserialized = serde_json::from_str::<FractalTokenKind>(&json).unwrap();
        assert_eq!(deserialized, token);
    }

    #[test]
    fn test_user_verify_uniqueness() {
        struct TestCase {
            name: &'static str,
            input: RawFractalUser,
            expected: VerificationStatus,
        }

        let test_cases = [
            TestCase {
                name: "Verify uniqueness success (single case)",
                input: gen_user(vec![
                    // finished & approved case
                    gen_verification_case(
                        Utc::now(),
                        Utc::now(),
                        VerificationLevelState::Uniqueness(
                            CaseStatus::Done,
                            CredentialStatus::Approved,
                        ),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Approved,
            },
            TestCase {
                name: "Verify uniqueness success (multiple cases)",
                input: gen_user(vec![
                    // not finished case
                    gen_verification_case(
                        Utc::now() - Duration::days(2),
                        Utc::now() - Duration::days(1),
                        VerificationLevelState::Uniqueness(
                            CaseStatus::Contacted,
                            CredentialStatus::Pending,
                        ),
                        true,
                    ),
                    // finished & approved case
                    gen_verification_case(
                        Utc::now() - Duration::days(3),
                        Utc::now(),
                        VerificationLevelState::Uniqueness(
                            CaseStatus::Done,
                            CredentialStatus::Approved,
                        ),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Approved,
            },
            TestCase {
                name: "Verify uniqueness failure (single case)",
                input: gen_user(vec![
                    // rejected case
                    gen_verification_case(
                        Utc::now(),
                        Utc::now(),
                        VerificationLevelState::Uniqueness(
                            CaseStatus::Done,
                            CredentialStatus::Rejected,
                        ),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Rejected,
            },
            TestCase {
                name: "Verify uniqueness failure (multiple cases)",
                input: gen_user(vec![
                    // finished & rejected case
                    gen_verification_case(
                        Utc::now() - Duration::days(2),
                        Utc::now() - Duration::days(1),
                        VerificationLevelState::Uniqueness(
                            CaseStatus::Done,
                            CredentialStatus::Rejected,
                        ),
                        true,
                    ),
                    // not finished case
                    gen_verification_case(
                        Utc::now() - Duration::days(3),
                        Utc::now(),
                        VerificationLevelState::Uniqueness(
                            CaseStatus::Pending,
                            CredentialStatus::Pending,
                        ),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Pending,
            },
            TestCase {
                name: "Verify uniqueness failure (w/o liveness)",
                input: gen_user(vec![
                    // finished without liveness
                    gen_verification_case(
                        Utc::now(),
                        Utc::now(),
                        VerificationLevelState::Uniqueness(
                            CaseStatus::Done,
                            CredentialStatus::Approved,
                        ),
                        false,
                    ),
                ]),
                expected: VerificationStatus::Unavailable,
            },
            TestCase {
                name: "Verify uniqueness failure (no cases)",
                input: gen_user(vec![]),
                expected: VerificationStatus::Unavailable,
            },
        ];

        for TestCase {
            name,
            mut input,
            expected,
        } in test_cases
        {
            let result = input.get_status(&[VerificationLevel::Uniqueness]);
            assert_eq!(
                result, expected,
                "Test case `{name}` failed with result {result:?}. Expected {expected:?}"
            );
        }
    }

    #[test]
    fn test_user_get_kyc_status() {
        struct TestCase {
            name: &'static str,
            input: RawFractalUser,
            expected: VerificationStatus,
        }

        let test_cases = [
            TestCase {
                name: "Verify KYC approved (single case)",
                input: gen_user(vec![
                    // approved case
                    gen_verification_case(
                        Utc::now(),
                        Utc::now(),
                        VerificationLevelState::Kyc(CaseStatus::Done, CredentialStatus::Approved),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Approved,
            },
            TestCase {
                name: "Verify KYC approved (multiple cases, recently approved)",
                input: gen_user(vec![
                    // rejected case
                    gen_verification_case(
                        Utc::now() - Duration::days(2),
                        Utc::now() - Duration::days(1),
                        VerificationLevelState::Kyc(CaseStatus::Done, CredentialStatus::Rejected),
                        true,
                    ),
                    // approved case
                    gen_verification_case(
                        Utc::now() - Duration::days(3),
                        Utc::now(),
                        VerificationLevelState::Kyc(CaseStatus::Done, CredentialStatus::Approved),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Approved,
            },
            TestCase {
                name: "Verify KYC pending (single case)",
                input: gen_user(vec![
                    // pending case
                    gen_verification_case(
                        Utc::now(),
                        Utc::now(),
                        VerificationLevelState::Kyc(CaseStatus::Pending, CredentialStatus::Pending),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Pending,
            },
            TestCase {
                name: "Verify KYC pending (multiple cases, previously rejected)",
                input: gen_user(vec![
                    // rejected case
                    gen_verification_case(
                        Utc::now() - Duration::days(2),
                        Utc::now() - Duration::days(1),
                        VerificationLevelState::Kyc(CaseStatus::Done, CredentialStatus::Rejected),
                        true,
                    ),
                    // pending case
                    gen_verification_case(
                        Utc::now() - Duration::days(3),
                        Utc::now(),
                        VerificationLevelState::Kyc(
                            CaseStatus::Contacted,
                            CredentialStatus::Pending,
                        ),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Pending,
            },
            TestCase {
                name: "Verify KYC unavailable (no cases)",
                input: gen_user(vec![]),
                expected: VerificationStatus::Unavailable,
            },
            TestCase {
                name: "Verify KYC unavailable (w/o liveness)",
                input: gen_user(vec![
                    // approved case without liveness
                    gen_verification_case(
                        Utc::now(),
                        Utc::now(),
                        VerificationLevelState::Kyc(CaseStatus::Done, CredentialStatus::Approved),
                        false,
                    ),
                ]),
                expected: VerificationStatus::Unavailable,
            },
            TestCase {
                name: "Verify KYC rejected (single case)",
                input: gen_user(vec![
                    // rejected case
                    gen_verification_case(
                        Utc::now(),
                        Utc::now(),
                        VerificationLevelState::Kyc(CaseStatus::Done, CredentialStatus::Rejected),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Rejected,
            },
            TestCase {
                name: "Verify KYC rejected (multiple cases)",
                input: gen_user(vec![
                    // rejected case
                    gen_verification_case(
                        Utc::now() - Duration::days(2),
                        Utc::now() - Duration::days(1),
                        VerificationLevelState::Kyc(CaseStatus::Done, CredentialStatus::Rejected),
                        true,
                    ),
                    // pending case
                    gen_verification_case(
                        Utc::now() - Duration::days(3),
                        Utc::now(),
                        VerificationLevelState::Kyc(CaseStatus::Done, CredentialStatus::Rejected),
                        true,
                    ),
                ]),
                expected: VerificationStatus::Rejected,
            },
        ];

        for TestCase {
            name,
            mut input,
            expected,
        } in test_cases
        {
            let result = input.get_status(&[VerificationLevel::Basic, VerificationLevel::Liveness]);
            assert_eq!(
                result, expected,
                "Test case `{name}` failed with result {result:?}. Expected {expected:?}"
            );
        }
    }

    #[test]
    fn test_parse_user() {
        let user_json = r#"{
            "emails": [
              {
                "address": "test@abc.net"
              }
            ],
            "institution": null,
            "person": {
              "identification_document_front_file": "https://some_url",
              "liveness": true,
              "liveness_audit_best_file": "https://some_url",
              "liveness_audit_least_similar_file": "https://some_url",
              "liveness_audit_open_eyes_file": "https://some_url",
              "liveness_audit_quality1_file": "https://some_url",
              "liveness_audit_quality2_file": "https://some_url",
              "liveness_audit_quality3_file": "https://some_url"
            },
            "phones": [],
            "uid": "de223722-fe21-11ed-be56-0242ac120002",
            "verification_cases": [
              {
                "created_at": "2023-05-19 21:57:42 UTC",
                "credential": "approved",
                "details": {
                  "liveness": true,
                  "liveness_audit_best_file": "https://some_url",
                  "liveness_audit_least_similar_file": "https://some_url",
                  "liveness_audit_open_eyes_file": "https://some_url",
                  "liveness_audit_quality1_file": "https://some_url",
                  "liveness_audit_quality2_file": "https://some_url",
                  "liveness_audit_quality3_file": "https://some_url",
                  "identification_document_front_file": "https://some_url"
                },
                "id": "07f10ea2-fe22-11ed-be56-0242ac120002",
                "journey_completed": true,
                "level": "basic+liveness",
                "status": "done",
                "updated_at": "2023-05-24 19:59:19 UTC"
              },
              {
                "created_at": "2023-05-19 22:08:09 UTC",
                "credential": "approved",
                "details": {
                  "identification_document_front_file": null,
                  "liveness_audit_quality2_file": "https://some_url",
                  "liveness_audit_quality3_file": "https://some_url",
                  "liveness": true,
                  "liveness_audit_best_file": "https://some_url",
                  "liveness_audit_least_similar_file": "https://some_url",
                  "liveness_audit_open_eyes_file": "https://some_url",
                  "liveness_audit_quality1_file": "https://some_url"
                },
                "id": "37c01d4e-fe22-11ed-be56-0242ac120002",
                "journey_completed": true,
                "level": "uniqueness",
                "status": "done",
                "updated_at": "2023-05-19 22:09:23 UTC"
              }
            ],
            "wallets": []
        }"#;

        let parsed = serde_json::from_str::<RawFractalUser>(user_json);

        assert_matches!(parsed.as_ref(), Ok(RawFractalUser {
            uid,
            ..
        }) if uid.as_ref() == "de223722fe2111edbe560242ac120002");

        assert_matches!(parsed.unwrap().verification_cases.as_slice(), [
            VerificationCase {
                id: id0,
                credential: CredentialStatus::Approved,
                status: CaseStatus::Done,
                level: levels0,
                created_at: created_at0,
                updated_at: updated_at0,
                ..
            },
            VerificationCase {
                id: id1,
                credential: CredentialStatus::Approved,
                status: CaseStatus::Done,
                level: levels1,
                ..
            },
        ] if id0.as_str() == "07f10ea2-fe22-11ed-be56-0242ac120002" && levels0.as_slice() == [VerificationLevel::Basic, VerificationLevel::Liveness] && 
             created_at0.to_string().as_str() == "2023-05-19 21:57:42 UTC" && updated_at0.to_string().as_str() == "2023-05-24 19:59:19 UTC" &&
             id1.as_str() == "37c01d4e-fe22-11ed-be56-0242ac120002" && levels1.as_slice() == [VerificationLevel::Uniqueness]);
    }

    enum VerificationLevelState {
        Uniqueness(CaseStatus, CredentialStatus),
        Kyc(CaseStatus, CredentialStatus),
    }

    fn gen_verification_case(
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        state: VerificationLevelState,
        liveness: bool,
    ) -> VerificationCase {
        let (level, status, credential) = match state {
            VerificationLevelState::Uniqueness(status, credential) => {
                (vec![VerificationLevel::Uniqueness], status, credential)
            }
            VerificationLevelState::Kyc(status, credential) => (
                vec![VerificationLevel::Basic, VerificationLevel::Liveness],
                status,
                credential,
            ),
        };

        VerificationCase {
            id: uuid::Uuid::new_v4().to_string(),
            created_at,
            updated_at,
            level,
            status,
            credential,
            details: VerificationDetails { liveness },
        }
    }

    fn gen_user(verification_cases: Vec<VerificationCase>) -> RawFractalUser {
        RawFractalUser {
            uid: ExternalAccountId::from(uuid::Uuid::new_v4()),
            emails: vec![],
            phones: vec![],
            wallets: vec![],
            verification_cases,
        }
    }
}
