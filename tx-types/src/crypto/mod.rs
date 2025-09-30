/// Cryptographic primitives for Nockchain transaction signing
///
/// This module provides the cryptographic foundations for signing transactions:
/// - Cheetah elliptic curve over F^6 extension field
/// - Schnorr signatures with TIP5 challenge generation
/// - SLIP-10 hierarchical deterministic key derivation

pub mod cheetah;
pub mod slip10;
pub mod utils;

// Re-export main types for convenience
pub use cheetah::{CheetahPoint, F6Element};
pub use slip10::{ExtendedKey, master_from_seed, master_from_mnemonic};
pub use crate::signer::schnorr_sign_digest;

/// Cryptographic errors
#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidSeed,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    DerivationFailed,
    Bip39Error(String),
    Pbkdf2Error,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CryptoError::InvalidSeed => write!(f, "Invalid seed"),
            CryptoError::InvalidPrivateKey => write!(f, "Invalid private key"),
            CryptoError::InvalidPublicKey => write!(f, "Invalid public key"),
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::DerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::Bip39Error(s) => write!(f, "BIP39 error: {}", s),
            CryptoError::Pbkdf2Error => write!(f, "PBKDF2 error"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;