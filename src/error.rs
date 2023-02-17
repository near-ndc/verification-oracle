use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    TransportProtocolError,
    SigningError,
    SignatureInvalid,
    UserAddressInvalid,
    UserNotVerified,
    UserAlreadyRegistered,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match self {
            Self::TransportProtocolError | Self::SigningError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            Self::UserAddressInvalid => (StatusCode::BAD_REQUEST, "Invalid user address"),
            Self::SignatureInvalid => (StatusCode::BAD_REQUEST, "Invalid signature"),
            Self::UserNotVerified => (StatusCode::UNAUTHORIZED, "User didn't pass verification"),
            Self::UserAlreadyRegistered => (StatusCode::BAD_REQUEST, "User already registered"),
        };
        (status, Json(json!({ "error": err_msg }))).into_response()
    }
}
