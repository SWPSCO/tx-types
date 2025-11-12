/// Hashing module for transaction processing
///
/// This module contains all hashing-related functionality including:
/// - The Hashable trait and enum for creating hashable structures
/// - TIP5 hashing algorithm implementation
/// - Transaction ID computation
/// - General hashing utilities
pub mod hashable;
pub mod hasher;
pub mod raw;
pub mod tip5;
pub mod tx_id;
pub mod u320;

// Re-export commonly used items
pub use hashable::Hashable;
pub use hasher::{hash_hashable, hash_noun_varlen, hash_ten_cell};
pub use raw::{
    compute_tx_id_v1_from_raw_noun, hashable_note_data_from_raw, hashable_pkh_signature_direct,
    hashable_pkh_signature_from_raw, hashable_seeds_from_raw, hashable_spend_from_raw,
    hashable_spends_from_raw, hashable_witness_from_raw,
};
pub use tip5::{Tip5Error, Tip5Hasher};
pub use tx_id::{compute_tx_id, compute_tx_id_base58};
