use axum::{http::StatusCode, response::IntoResponse, Json};
use near_sdk::serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Signing error")]
    SigningError,
    #[error("User uniqueness is not verified error")]
    UserUniquenessNotVerified,
    #[error("Http request timed out: {0}")]
    TimeoutError(String),
    #[error("Http request failed: {0}")]
    ReqwestError(reqwest::Error),
    #[error("JSON parse failure: {0}")]
    ParseError(#[from] near_sdk::serde_json::Error),
    #[error("Generic error: {0}")]
    Generic(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match self {
            Self::SigningError | Self::ParseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            Self::UserUniquenessNotVerified => {
                (StatusCode::UNAUTHORIZED, "User didn't pass verification")
            }
            Self::ReqwestError(_) | Self::Generic(_) | Self::TimeoutError(_) => {
                (StatusCode::UNAUTHORIZED, "User verification failure")
            }
        };
        (status, Json(json!({ "error": err_msg }))).into_response()
    }
}

impl From<String> for AppError {
    fn from(error_str: String) -> Self {
        Self::Generic(error_str)
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            Self::TimeoutError(e.to_string())
        } else {
            Self::ReqwestError(e)
        }
    }
}
