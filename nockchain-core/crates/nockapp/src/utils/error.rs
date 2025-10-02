use thiserror::Error;

#[derive(Debug, Error)]
pub enum NockAppError {
    #[error("io error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("interpreter error: {0:?}")]
    InterpreterError(nockvm::interpreter::Error),
    #[error("noun error: {0:?}")]
    NounError(nockvm::noun::Error),
    #[error("noun decode error: {0}")]
    NounDecodeError(Box<dyn std::error::Error>),
    #[error("{0}")]
    Utf8FromError(#[from] std::string::FromUtf8Error),
    #[error("{0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("conversion error: {0}")]
    ConversionError(String),
}

impl From<nockvm::interpreter::Error> for NockAppError {
    fn from(e: nockvm::interpreter::Error) -> Self {
        NockAppError::InterpreterError(e)
    }
}

impl From<nockvm::noun::Error> for NockAppError {
    fn from(e: nockvm::noun::Error) -> Self {
        NockAppError::NounError(e)
    }
}

// Compatibility aliases
pub type CrownError = NockAppError;
pub type Result<T> = std::result::Result<T, NockAppError>;