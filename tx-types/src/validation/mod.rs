pub mod signature_verification;
/// Validation module for transaction processing
///
/// This module contains transaction validation logic including:
/// - Signature verification
/// - Input/output balance validation
/// - Timelock constraint validation
/// - Fee validation
pub mod validator;

// Re-export validation types
pub use signature_verification::schnorr_verify_digest;
pub use validator::{TransactionValidationError, TransactionValidator};
