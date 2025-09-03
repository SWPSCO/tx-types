// Minimal error types for noun-serde
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrownError {
    #[error("Generic error: {0}")]
    Generic(String),
}

#[derive(Debug, Error)]
pub enum NockAppError {
    #[error("Generic error: {0}")]
    Generic(String),
    #[error("Noun decode error: {0}")]
    NounDecodeError(Box<dyn std::error::Error + Send + Sync>),
}