pub mod cheetah;
/// Cryptographic primitives for Nockchain transaction signing.
///
/// This module consolidates the low-level crypto that must run in both hosted and
/// firmware environments:
/// - Goldilocks field arithmetic and TIP5 permutation
/// - Cheetah elliptic curve operations and Schnorr signing helpers
/// - SLIP-10 hierarchical deterministic key derivation
/// - Utility routines for scalar arithmetic
pub mod goldilocks;
pub mod slip10;
pub mod utils;

#[cfg(feature = "std")]
pub use crate::signer::schnorr_sign_digest;
#[cfg(not(feature = "std"))]
pub use cheetah::schnorr_sign_digest;

pub use cheetah::{
    cheetah_pub_from_sk, hmac_split_512, master_from_seed, schnorr_sign_tx, ser_a_pt,
    ser_a_pt_rep104, xprv_derive_child, xpub_derive_child, CheetahPoint, Hash, XKey, T8,
};
#[cfg(feature = "std")]
pub use slip10::{
    bip39_to_seed, master_from_mnemonic, master_from_seed as slip10_master_from_seed,
    CryptoError as Slip10Error, ExtendedKey,
};
#[cfg(not(feature = "std"))]
pub use slip10::{
    master_from_seed as slip10_master_from_seed, CryptoError as Slip10Error, ExtendedKey,
};
