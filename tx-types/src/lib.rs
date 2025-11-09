pub mod block_types;
/// Transaction processing module
///
/// This module contains all transaction-related functionality organized into:
/// - Core transaction types (transaction_types.rs)
/// - Noun encoding/decoding (to_noun.rs)
/// - Hashing algorithms and transaction ID computation (hashing/)
/// - Data structures like Z-maps (collections/)
/// - Transaction validation logic (validation/)
// Core modules in root
pub mod fee_calculator;
pub mod generic_noun;
pub mod inner_peeks;
pub mod inspect;
pub mod signer;
pub mod transaction_types;
pub mod transaction_types_v0;
pub mod transaction_types_v1;
pub mod tx_builder_batch;
pub mod tx_builder_v1;
pub mod tx_to_noun;

// Submodules
pub mod collections;
pub mod crypto;
pub mod hashing;
pub mod validation;

// Re-export commonly used types from submodules
pub use hashing::{
    hashable::Hashable,
    hasher::{hash_hashable, hash_noun_varlen, hash_ten_cell},
    tip5::{Tip5Error, Tip5Hasher},
    tx_id::{compute_tx_id, compute_tx_id_base58},
};

pub use collections::{
    zmap::ZMap,
    zset::{DorTip, ZSet},
};

pub use validation::{schnorr_verify_digest, TransactionValidationError, TransactionValidator};

pub use crypto::CryptoError;

pub use signer::{schnorr_sign_digest, sign_spend, sign_tx};

pub use tx_builder_v1::{
    build_spends, create_spends_0, create_spends_1, lock_data_to_untyped_noun, sign_spend_v0_to_v1,
    sign_spend_v1, LockData, Order,
};

pub use tx_builder_batch::{build_batch_spends, BatchOrder};

pub use fee_calculator::{calculate_min_fee, BASE_FEE, MIN_FEE};

// Re-export main transaction types
pub use transaction_types::*;
pub use transaction_types_v0::*;
pub use transaction_types_v1::*;

pub use inspect::{spends_dump, transaction_json, transaction_stats, TransactionStats};

// Re-export tx-engine types
pub use transaction_types::{Output, Outputs, Tx};

// Re-export block types
pub use block_types::*;

// Re-export generic noun
pub use generic_noun::*;

// Test modules
#[cfg(test)]
mod tests;
