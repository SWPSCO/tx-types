/// Cryptographic primitives for Nockchain transaction signing.
///
/// This module consolidates the low-level crypto that must run in both hosted and
/// firmware environments:
/// - Goldilocks field arithmetic and TIP5 permutation
/// - Cheetah elliptic curve operations and Schnorr signing helpers
/// - SLIP-10 hierarchical deterministic key derivation
/// - Utility routines for scalar arithmetic

// For no_std builds, use the self-contained cheetah_nostd and goldilocks modules
#[cfg(not(feature = "std"))]
pub mod goldilocks;
#[cfg(not(feature = "std"))]
pub mod utils_nostd;
#[cfg(not(feature = "std"))]
pub mod cheetah_nostd;

// For std builds, use the new modular structure
#[cfg(feature = "std")]
pub mod cheetah;
#[cfg(feature = "std")]
pub mod slip10;
#[cfg(feature = "std")]
pub mod utils;

// Re-exports for no_std builds
#[cfg(not(feature = "std"))]
pub use cheetah_nostd::{
    cheetah_pub_from_sk, hmac_split_512, master_from_seed, schnorr_sign_digest, schnorr_sign_tx,
    ser_a_pt, ser_a_pt_rep104, xprv_derive_child, xpub_derive_child, CheetahPoint, F6lt, Hash,
    XKey, T8,
};

#[cfg(not(feature = "std"))]
pub use goldilocks::{Belt, GOLDILOCKS_P, tip5_permute};

// Re-exports for std builds
#[cfg(feature = "std")]
pub use cheetah::{CheetahPoint, F6Element};
#[cfg(feature = "std")]
pub use slip10::{master_from_mnemonic, master_from_seed, ExtendedKey};
#[cfg(feature = "std")]
pub use cheetah::point::cheetah_pub_from_sk;

// schnorr_sign_digest is in signer.rs for std builds
#[cfg(feature = "std")]
pub use crate::signer::schnorr_sign_digest;

/// Cryptographic errors (std only)
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidSeed,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    DerivationFailed,
    Bip39Error(String),
    Pbkdf2Error,
    InvalidExtendedKeyString,
    Base58DecodeError(String),
    Other(String),
}

#[cfg(feature = "std")]
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
            CryptoError::InvalidExtendedKeyString => write!(f, "Invalid extended key string"),
            CryptoError::Base58DecodeError(s) => write!(f, "Base58 decode error: {}", s),
            CryptoError::Other(s) => write!(f, "{s}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, CryptoError>;
