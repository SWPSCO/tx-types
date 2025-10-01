/// Cryptographic primitives for Nockchain transaction signing
///
/// This module provides the cryptographic foundations for signing transactions:
/// - Cheetah elliptic curve over F^6 extension field
/// - Schnorr signatures with TIP5 challenge generation
pub mod cheetah;
pub mod utils;

// Re-export main types for convenience
pub use crate::signer::schnorr_sign_digest;
pub use cheetah::{CheetahPoint, F6Element};
