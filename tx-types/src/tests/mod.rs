// Test modules for tx-types

#[cfg(test)]
pub mod test_base58_conversion;
#[cfg(all(test, feature = "legacy-tests"))]
pub mod test_coinbase;
#[cfg(all(test, feature = "legacy-tests"))]
pub mod test_complex_input;
#[cfg(test)]
pub mod test_empty_hashes;
#[cfg(test)]
pub mod test_schnorr_pubkey_hash;
#[cfg(test)]
pub mod test_schnorr_signature_hash;
#[cfg(test)]
pub mod test_signature_hash;
#[cfg(test)]
pub mod test_signature_hashable;
#[cfg(all(test, feature = "legacy-tests"))]
pub mod test_tx_builder_sighash;
#[cfg(test)]
pub mod test_zmap_structure;
#[cfg(test)]
pub mod test_zset_simple;
#[cfg(test)]
pub mod test_zset_structure;
#[cfg(all(test, feature = "legacy-tests"))]
pub mod timelock_tests;
