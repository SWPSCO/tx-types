#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub mod block_types;
#[cfg(feature = "std")]
pub mod signer;
/// Transaction processing module
///
/// This module contains all transaction-related functionality organized into:
/// - Core transaction types (transaction_types.rs)
/// - Noun encoding/decoding (to_noun.rs)
/// - Hashing algorithms and transaction ID computation (hashing/)
/// - Data structures like Z-maps (collections/)
/// - Transaction validation logic (validation/)

// Core modules in root
#[cfg(feature = "std")]
pub mod transaction_types;
#[cfg(feature = "std")]
pub mod tx_to_noun;

// Submodules
#[cfg(feature = "std")]
pub mod collections;
pub mod crypto;
#[cfg(feature = "std")]
pub mod hashing;
#[cfg(feature = "std")]
pub mod validation;

// Re-export commonly used types from submodules
#[cfg(feature = "std")]
pub use hashing::{
    hashable::Hashable,
    hasher::{hash_hashable, hash_noun_varlen, hash_ten_cell},
    tip5::{Tip5Error, Tip5Hasher},
    tx_id::{compute_tx_id, compute_tx_id_base58},
};

#[cfg(feature = "std")]
pub use collections::{
    zmap::ZMap,
    zset::{DorTip, ZSet},
};

#[cfg(feature = "std")]
pub use validation::validator::{TransactionValidationError, TransactionValidator};

#[cfg(feature = "std")]
pub use signer::{schnorr_sign_digest, sign_spend, sign_tx};

// Re-export main transaction types
#[cfg(feature = "std")]
pub use transaction_types::*;

// Re-export block types for RPC usage
#[cfg(feature = "std")]
pub use block_types::{
    BlockPage, CoinbaseRecipient, SimpleTransaction, SimpleTransactionInput,
    SimpleTransactionOutput,
};

// Test modules
#[cfg(all(test, feature = "std"))]
mod tests;
