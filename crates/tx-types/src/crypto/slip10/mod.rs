/// SLIP-10 hierarchical deterministic key derivation for Nockchain
/// 
/// This module implements SLIP-10 compatible key derivation with Nockchain-specific
/// modifications:
/// - Uses "Nockchain seed" as HMAC key instead of "ed25519 seed"
/// - Implements retry logic for invalid private keys
/// - Compatible with BIP39 mnemonic seed generation

pub mod master;
pub mod derive;

pub use master::{master_from_seed, master_from_mnemonic, bip39_to_seed};
pub use derive::{ExtendedKey, DerivationError};

use crate::crypto::{CryptoError, Result};