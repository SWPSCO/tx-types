#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

#[cfg(all(feature = "embedded", feature = "native"))]
compile_error!("features `embedded` and `native` are mutually exclusive");

#[cfg(all(feature = "std", not(feature = "embedded"), not(feature = "native")))]
compile_error!("feature `std` requires either `embedded` or `native`");

// The same source is compiled against either the vendored minimal runtime or
// the upstream nockchain crates. Aliasing the dependencies onto their canonical
// names keeps every `::nockvm` / `::noun_serde` path (including derive output)
// resolving identically for both.
// ibig is needed by the crypto-only no_std path as well, where no Nockchain
// backend is selected.
#[cfg(not(feature = "native"))]
extern crate ibig_minimal as ibig;
#[cfg(feature = "embedded")]
extern crate nockapp_minimal as nockapp;
#[cfg(feature = "embedded")]
extern crate nockchain_libp2p_io_minimal as nockchain_libp2p_io;
#[cfg(feature = "embedded")]
extern crate nockchain_math_minimal as nockchain_math;
#[cfg(feature = "embedded")]
extern crate nockvm_minimal as nockvm;
#[cfg(feature = "embedded")]
extern crate nockvm_macros_minimal as nockvm_macros;
#[cfg(feature = "embedded")]
extern crate noun_serde_minimal as noun_serde;
#[cfg(feature = "embedded")]
extern crate zkvm_jetpack_minimal as zkvm_jetpack;

#[cfg(feature = "native")]
extern crate ibig_upstream as ibig;
#[cfg(feature = "native")]
extern crate nockapp_upstream as nockapp;
#[cfg(feature = "native")]
extern crate nockchain_libp2p_io_upstream as nockchain_libp2p_io;
#[cfg(feature = "native")]
extern crate nockchain_math_upstream as nockchain_math;
#[cfg(feature = "native")]
extern crate nockvm_upstream as nockvm;
#[cfg(feature = "native")]
extern crate nockvm_macros_upstream as nockvm_macros;
#[cfg(feature = "native")]
extern crate noun_serde_upstream as noun_serde;
#[cfg(feature = "native")]
extern crate zkvm_jetpack_upstream as zkvm_jetpack;

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
