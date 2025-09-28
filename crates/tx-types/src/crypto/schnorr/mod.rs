/// Schnorr signature scheme for Nockchain
/// 
/// This module implements Schnorr signatures with Nockchain-specific modifications:
/// - Uses TIP5 hash function for challenge generation
/// - RFC6979 deterministic nonce generation with SHA-256

pub mod rfc6979;

pub use rfc6979::generate_nonce;