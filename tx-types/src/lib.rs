#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pokenoun;

// Crypto module is always available (no_std compatible)
pub mod crypto;

// All other modules require std
#[cfg(feature = "std")]
pub mod block_types;
#[cfg(feature = "std")]
pub mod collections;
#[cfg(feature = "std")]
pub mod fee_calculator;
#[cfg(feature = "std")]
pub mod generic_noun;
#[cfg(feature = "std")]
pub mod hashing;
#[cfg(feature = "std")]
pub mod inner_peeks;
#[cfg(feature = "std")]
pub mod inspect;
#[cfg(feature = "std")]
pub mod signer;
#[cfg(feature = "std")]
pub mod transaction_types;
#[cfg(feature = "std")]
pub mod transaction_types_v0;
#[cfg(feature = "std")]
pub mod transaction_types_v1;
#[cfg(feature = "std")]
pub mod tx_builder_batch;
#[cfg(feature = "std")]
pub mod tx_builder_v1;
#[cfg(feature = "std")]
pub mod tx_to_noun;
#[cfg(feature = "std")]
pub mod validation;

// Re-exports for std builds
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
pub use validation::{schnorr_verify_digest, TransactionValidationError, TransactionValidator};

#[cfg(feature = "std")]
pub use signer::{schnorr_sign_digest, sign_spend, sign_tx};

#[cfg(feature = "std")]
pub use tx_builder_v1::{
    build_spends, create_spends_0, create_spends_1, lock_data_to_untyped_noun, sign_spend_v0_to_v1,
    sign_spend_v1, LockData, Order,
};

#[cfg(feature = "std")]
pub use tx_builder_batch::{build_batch_spends, BatchOrder};

#[cfg(feature = "std")]
pub use fee_calculator::{
    calculate_min_fee, calculate_min_fee_for_page, BASE_FEE, BYTHOS_PHASE, INPUT_FEE_DIVISOR,
    MIN_FEE,
};

#[cfg(feature = "std")]
pub use transaction_types::*;
#[cfg(feature = "std")]
pub use transaction_types_v0::*;
#[cfg(feature = "std")]
pub use transaction_types_v1::*;

#[cfg(feature = "std")]
pub use inspect::{spends_dump, transaction_json, transaction_stats, TransactionStats};

#[cfg(feature = "std")]
pub use block_types::*;

#[cfg(feature = "std")]
pub use generic_noun::*;

// Test modules
#[cfg(all(test, feature = "std"))]
mod tests;
