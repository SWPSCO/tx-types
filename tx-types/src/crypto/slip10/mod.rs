pub mod derive;
/// SLIP-10 hierarchical deterministic key derivation for Nockchain
///
/// This module implements SLIP-10 compatible key derivation with Nockchain-specific
/// modifications:
/// - Uses "Nockchain seed" as HMAC key instead of "ed25519 seed"
/// - Implements retry logic for invalid private keys
/// - Compatible with BIP39 mnemonic seed generation
pub mod master;

pub use derive::{DerivationError, ExtendedKey};
pub use master::{bip39_to_seed, master_from_mnemonic, master_from_seed};

use crate::crypto::{CryptoError, Result};
