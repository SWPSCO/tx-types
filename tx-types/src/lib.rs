/// Transaction processing module
///
/// This module contains all transaction-related functionality organized into:
/// - Core transaction types (transaction_types.rs)
/// - Noun encoding/decoding (to_noun.rs)
/// - Hashing algorithms and transaction ID computation (hashing/)
/// - Data structures like Z-maps (collections/)
/// - Transaction validation logic (validation/)

// Core modules in root
pub mod transaction_types;
pub mod tx_to_noun;
pub mod block_types;
pub mod signer;

// Submodules
pub mod hashing;
pub mod collections;
pub mod validation;
pub mod crypto;


// Re-export commonly used types from submodules
pub use hashing::{
    hashable::Hashable,
    hasher::{hash_hashable, hash_noun_varlen, hash_ten_cell},
    tip5::{Tip5Hasher, Tip5Error},
    tx_id::{compute_tx_id, compute_tx_id_base58},
};

pub use collections::{zmap::ZMap, zset::{ZSet, DorTip}};

pub use validation::{
    TransactionValidator,
    TransactionValidationError,
    schnorr_verify_digest,
};

pub use crypto::CryptoError;

pub use signer::{schnorr_sign_digest, sign_spend, sign_tx};

// Re-export main transaction types
pub use transaction_types::*;

// Re-export tx-engine types
pub use transaction_types::{Tx, Outputs, Output};

// Re-export block types for RPC usage
pub use block_types::{BlockPage, SimpleTransaction, SimpleTransactionInput, SimpleTransactionOutput, CoinbaseRecipient};

// Test modules
#[cfg(test)]
mod tests;