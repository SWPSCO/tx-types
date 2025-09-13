/// Cryptographic primitives for Nockchain transaction signing
/// 
/// This module provides the cryptographic foundations for signing transactions:
/// - Cheetah elliptic curve over F^6 extension field
/// - Schnorr signatures with TIP5 challenge generation
/// - SLIP-10 hierarchical deterministic key derivation
/// - RFC6979 deterministic nonce generation

pub mod cheetah;
pub mod schnorr;
pub mod slip10;
pub mod utils;

// Re-export main types for convenience
pub use cheetah::{CheetahPoint, F6Element};
pub use schnorr::{schnorr_sign_txid, verify_signature};
pub use slip10::{ExtendedKey, master_from_seed, master_from_mnemonic};
pub use utils::{UBigExt, T8Conversion};

use crate::transaction_types::{Hash, T8, SchnorrPubkey};
use ibig::UBig;
use zeroize::Zeroize;

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

/// Transaction signer for Nockchain
#[derive(Clone)]
pub struct TransactionSigner {
    extended_key: ExtendedKey,
}

impl TransactionSigner {
    /// Create signer from BIP39 mnemonic
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self> {
        let extended_key = master_from_mnemonic(mnemonic, passphrase)?;
        Ok(Self { extended_key })
    }
    
    /// Create signer from raw seed bytes
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let extended_key = master_from_seed(seed)?;
        Ok(Self { extended_key })
    }
    
    /// Create signer from raw private key
    pub fn from_private_key(key: [u8; 32]) -> Self {
        let extended_key = ExtendedKey::from_private_key(key);
        Self { extended_key }
    }
    
    /// Get the public key for this signer
    pub fn get_public_key(&self) -> SchnorrPubkey {
        self.extended_key.to_schnorr_pubkey()
    }
    
    /// Derive a child signer
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        let child_key = self.extended_key.derive_child(index)?;
        Ok(Self { extended_key: child_key })
    }
    
    /// Get the private key (if available)
    pub fn private_key(&self) -> Option<[u8; 32]> {
        self.extended_key.private_key
    }
}

impl Zeroize for TransactionSigner {
    fn zeroize(&mut self) {
        self.extended_key.zeroize();
    }
}

impl Drop for TransactionSigner {
    fn drop(&mut self) {
        self.zeroize();
    }
}