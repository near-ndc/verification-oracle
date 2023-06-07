use crate::error::AppError;
use chrono::{DateTime, Utc};
use near_sdk::{serde::Deserialize, serde_json};
use reqwest::Client;

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct CaptchaConfig {
    action: String,
    threshold: f64,
    secret: String,
}

#[derive(Clone)]
pub struct CaptchaClient {
    inner_client: Client,
    config: CaptchaConfig,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(crate = "near_sdk::serde", rename_all = "kebab-case")]
pub enum CaptchaErrorCode {
    MissingInputSecret,
    InvalidInputSecret,
    MissingInputResponse,
    InvalidInputResponse,
    BadRequest,
    TimeoutOrDuplicate,
    #[serde(other)]
    Unknown,
}

impl Default for CaptchaErrorCode {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CaptchaError {
    #[error("Response error code: {0:?}")]
    ResponseError(CaptchaErrorCode),
    #[error("Invalid action")]
    InvalidAction,
    #[error("Request failure {0}")]
    RequestFailure(reqwest::Error),
    #[error("Request parse failure {0}")]
    ParseFailure(serde_json::Error),
}

#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde", untagged)]
pub enum CaptchaResult {
    Success(CaptchaResponse),
    Failure(CaptchaErrorResponse),
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub struct CaptchaResponse {
    success: bool,
    score: f64,
    action: String,
    #[serde(rename = "challenge_ts")]
    _challenge_ts: DateTime<Utc>,
    #[serde(rename = "hostname")]
    _hostname: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct CaptchaErrorResponse {
    #[serde(rename = "error-codes")]
    error_codes: Vec<CaptchaErrorCode>,
}

impl CaptchaClient {
    pub fn new(config: CaptchaConfig) -> Result<Self, AppError> {
        let inner_client = Client::builder().pool_max_idle_per_host(0).build()?;

        Ok(Self {
            inner_client,
            config,
        })
    }

    async fn fetch_captcha(&self, token: &str) -> Result<String, CaptchaError> {
        let params: [(&str, &str); 2] = [("secret", &self.config.secret), ("response", token)];

        self.inner_client
            .post("https://www.google.com/recaptcha/api/siteverify")
            .form(&params)
            .send()
            .await
            .map_err(CaptchaError::RequestFailure)?
            .text()
            .await
            .map_err(CaptchaError::RequestFailure)
    }

    fn parse_captcha_response(&self, result: String) -> Result<CaptchaResponse, CaptchaError> {
        let captcha_res = serde_json::from_str::<CaptchaResult>(&result);
        tracing::trace!("Parsed captcha result: {captcha_res:?}");

        match captcha_res {
            Ok(CaptchaResult::Success(CaptchaResponse { success, .. })) if !success => {
                Err(CaptchaError::ResponseError(CaptchaErrorCode::BadRequest))
            }
            Ok(CaptchaResult::Success(CaptchaResponse { action, .. }))
                if action != self.config.action =>
            {
                Err(CaptchaError::InvalidAction)
            }
            Ok(CaptchaResult::Success(response)) => Ok(response),
            Ok(CaptchaResult::Failure(CaptchaErrorResponse { error_codes, .. })) => Err(
                CaptchaError::ResponseError(error_codes.first().copied().unwrap_or_default()),
            ),
            Err(e) => Err(CaptchaError::ParseFailure(e)),
        }
    }

    pub async fn verify(&self, token: &str) -> Result<bool, CaptchaError> {
        tracing::trace!("Verify captcha token `{token}`");

        let fetched = self.fetch_captcha(token).await?;

        let CaptchaResponse { score, .. } = self.parse_captcha_response(fetched)?;

        Ok(score >= self.config.threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::{CaptchaClient, CaptchaConfig, CaptchaError, CaptchaErrorCode, CaptchaResponse};
    use assert_matches::assert_matches;
    use chrono::Utc;

    #[test]
    fn test_captcha_parsed() {
        let client = CaptchaClient::default();
        let now = Utc::now();

        assert_matches!(client.parse_captcha_response(format!(
                r#"{{
                    "success": true,
                    "score": 0.9,
                    "action": "homepage",
                    "challenge_ts": "{}",
                    "hostname": "http://some_url"
                }}"#,
                now.to_string()
            )),
            Ok(CaptchaResponse { score, .. }) if score == 0.9
        );
    }

    #[test]
    fn test_captcha_bad_request() {
        let client = CaptchaClient::default();
        let now = Utc::now();

        assert_matches!(
            client.parse_captcha_response(format!(
                r#"{{
                    "success": false,
                    "score": 0.0,
                    "action": "homepage",
                    "challenge_ts": "{}",
                    "hostname": "http://some_url"
                }}"#,
                now.to_string()
            )),
            Err(CaptchaError::ResponseError(CaptchaErrorCode::BadRequest))
        );
    }

    #[test]
    fn test_captcha_invalid_action() {
        let client = CaptchaClient::default();
        let now = Utc::now();

        assert_matches!(
            client.parse_captcha_response(format!(
                r#"{{
                    "success": true,
                    "score": 0.0,
                    "action": "test",
                    "challenge_ts": "{}",
                    "hostname": "http://some_url"
                }}"#,
                now.to_string()
            )),
            Err(CaptchaError::InvalidAction)
        );
    }

    #[test]
    fn test_captcha_error_codes() {
        struct TestCase {
            name: &'static str,
            input: &'static str,
            expected: CaptchaErrorCode,
        }
        let client = CaptchaClient::default();

        let test_cases = [
            TestCase {
                name: "Test error code missing-input-secret",
                input: r#"{
                    "success": false,
                    "error-codes": ["missing-input-secret"]
                }"#,
                expected: CaptchaErrorCode::MissingInputSecret,
            },
            TestCase {
                name: "Test error code invalid-input-secret",
                input: r#"{
                    "success": false,
                    "error-codes": ["invalid-input-secret"]
                }"#,
                expected: CaptchaErrorCode::InvalidInputSecret,
            },
            TestCase {
                name: "Test error code missing-input-response",
                input: r#"{
                    "success": false,
                    "error-codes": ["missing-input-response"]
                }"#,
                expected: CaptchaErrorCode::MissingInputResponse,
            },
            TestCase {
                name: "Test error code invalid-input-response",
                input: r#"{
                    "success": false,
                    "error-codes": ["invalid-input-response"]
                }"#,
                expected: CaptchaErrorCode::InvalidInputResponse,
            },
            TestCase {
                name: "Test error code bad-request",
                input: r#"{
                    "success": false,
                    "error-codes": ["bad-request"]
                }"#,
                expected: CaptchaErrorCode::BadRequest,
            },
            TestCase {
                name: "Test error code timeout-or-duplicate",
                input: r#"{
                    "success": false,
                    "error-codes": ["timeout-or-duplicate"]
                }"#,
                expected: CaptchaErrorCode::TimeoutOrDuplicate,
            },
            TestCase {
                name: "Test error code unknown",
                input: r#"{
                    "success": false,
                    "error-codes": ["any_unknown_error"]
                }"#,
                expected: CaptchaErrorCode::Unknown,
            },
        ];

        for TestCase {
            name,
            input,
            expected,
        } in test_cases
        {
            let result = client.parse_captcha_response(input.to_owned());
            assert_matches!(result, Err(CaptchaError::ResponseError(err_code)) if err_code == expected, "Test case `{name}` failed with result {result:?}. Expected {expected:?}");
        }
    }

    impl Default for CaptchaClient {
        fn default() -> Self {
            Self::new(CaptchaConfig {
                threshold: 0.5,
                action: "homepage".to_owned(),
                secret: String::default(),
            })
            .unwrap()
        }
    }
}
