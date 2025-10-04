//! SLIP-10 hierarchical key derivation wrappers.
//!
//! This module bridges the firmware-friendly cheetah primitives with the
//! existing host-side API that expects fallible operations returning
//! `ExtendedKey` handles.

use alloc::string::String;

pub mod derive;
pub mod master;

pub use derive::{DerivationError, ExtendedKey};
#[cfg(not(feature = "std"))]
pub use master::master_from_seed;
#[cfg(feature = "std")]
pub use master::{bip39_to_seed, master_from_mnemonic, master_from_seed};

#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidSeed,
    DerivationFailed,
    Bip39Error(String),
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidSeed => write!(f, "invalid seed"),
            CryptoError::DerivationFailed => write!(f, "key derivation failed"),
            CryptoError::Bip39Error(e) => write!(f, "BIP39 error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

pub type Result<T> = core::result::Result<T, CryptoError>;
