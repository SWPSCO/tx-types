/// Validation module for transaction processing
///
/// This module contains transaction validation logic including:
/// - Signature verification
/// - Input/output balance validation
/// - Timelock constraint validation
/// - Fee validation

pub mod validator;
pub mod signature_verification;

// Re-export validation types
pub use validator::{TransactionValidator, TransactionValidationError};
pub use signature_verification::schnorr_verify_digest;