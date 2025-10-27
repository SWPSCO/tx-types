//! Tests for transaction builder signature hash computation
//!
//! These tests focus on the critical signature hash functions that were implemented
//! to match the Hoon tx-engine specifications.

#[cfg(test)]
mod test_tx_builder_sighash {
    use crate::collections::ZSet;
    use crate::hashing::hashable::Hashable;
    use crate::hashing::hasher::hash_hashable;
    use crate::transaction_types::*;
    use crate::transaction_types_v0::*;
    use crate::transaction_types_v1::*;
    use crate::tx_builder_v1::*;

    #[test]
    fn test_signature_hash_v0_non_zero() {
        println!("\n=== Testing V0 Signature Hash Computation ===\n");

        // Create empty seeds for simplicity
        let seeds = SeedsV0 { set: ZSet::new() };
        let fee = Coins { value: 100 };

        let sig_hash = compute_spend_v0_sig_hash(&seeds, &fee);

        println!("✓ Computed V0 signature hash");

        // Hash should not be all zeros (empty seeds + fee should produce deterministic hash)
        let is_zero = sig_hash.values.values.iter().all(|&v| v == 0);
        assert!(!is_zero, "Signature hash should not be all zeros");
    }

    #[test]
    fn test_signature_hash_v1_non_zero() {
        println!("\n=== Testing V1 Signature Hash Computation ===\n");

        // Create empty seeds for simplicity
        let seeds = SeedsV1 { set: ZSet::new() };
        let fee = Coins { value: 100 };

        let sig_hash = compute_spend_v1_sig_hash(&seeds, &fee);

        println!("✓ Computed V1 signature hash");

        // Hash should not be all zeros
        let is_zero = sig_hash.values.values.iter().all(|&v| v == 0);
        assert!(!is_zero, "Signature hash should not be all zeros");
    }

    #[test]
    fn test_signature_hash_v0_deterministic() {
        println!("\n=== Testing V0 Signature Hash is Deterministic ===\n");

        let seeds = SeedsV0 { set: ZSet::new() };
        let fee = Coins { value: 100 };

        let hash1 = compute_spend_v0_sig_hash(&seeds, &fee);
        let hash2 = compute_spend_v0_sig_hash(&seeds, &fee);

        println!("✓ Hash computed twice with same inputs");

        assert_eq!(hash1, hash2, "Same inputs should produce same hash");
    }

    #[test]
    fn test_signature_hash_v1_deterministic() {
        println!("\n=== Testing V1 Signature Hash is Deterministic ===\n");

        let seeds = SeedsV1 { set: ZSet::new() };
        let fee = Coins { value: 100 };

        let hash1 = compute_spend_v1_sig_hash(&seeds, &fee);
        let hash2 = compute_spend_v1_sig_hash(&seeds, &fee);

        println!("✓ Hash computed twice with same inputs");

        assert_eq!(hash1, hash2, "Same inputs should produce same hash");
    }

    #[test]
    fn test_signature_hash_v0_different_fees() {
        println!("\n=== Testing V0 Signature Hash with Different Fees ===\n");

        let seeds = SeedsV0 { set: ZSet::new() };

        let fee1 = Coins { value: 100 };
        let fee2 = Coins { value: 200 };

        let hash1 = compute_spend_v0_sig_hash(&seeds, &fee1);
        let hash2 = compute_spend_v0_sig_hash(&seeds, &fee2);

        println!("✓ Hashes computed with different fees");

        assert_ne!(
            hash1, hash2,
            "Different fees should produce different hashes"
        );
    }

    #[test]
    fn test_signature_hash_v1_different_fees() {
        println!("\n=== Testing V1 Signature Hash with Different Fees ===\n");

        let seeds = SeedsV1 { set: ZSet::new() };

        let fee1 = Coins { value: 100 };
        let fee2 = Coins { value: 200 };

        let hash1 = compute_spend_v1_sig_hash(&seeds, &fee1);
        let hash2 = compute_spend_v1_sig_hash(&seeds, &fee2);

        println!("✓ Hashes computed with different fees");

        assert_ne!(
            hash1, hash2,
            "Different fees should produce different hashes"
        );
    }

    #[test]
    fn test_lock_data_to_noun_v0() {
        println!("\n=== Testing LockData V0 Serialization ===\n");

        // Create a simple spend condition
        let spend_condition: SpendCondition = vec![];
        let lock_data = LockData::V0(spend_condition);

        let result = lock_data_to_untyped_noun(&lock_data);
        assert!(
            result.is_ok(),
            "Failed to serialize V0 LockData: {:?}",
            result.err()
        );

        let untyped_noun = result.unwrap();
        println!("✓ Serialized V0 LockData to UntypedNoun");
        println!("  Jammed bytes length: {}", untyped_noun.jammed_bytes.len());

        // Should have non-empty jammed bytes
        assert!(
            !untyped_noun.jammed_bytes.is_empty(),
            "Jammed bytes should not be empty"
        );
    }

    #[test]
    fn test_spend_condition_to_noun_empty() {
        println!("\n=== Testing Empty SpendCondition Serialization ===\n");

        let spend_condition: SpendCondition = vec![];

        let result = spend_condition_to_noun(&spend_condition);
        assert!(result.is_ok(), "Failed to serialize empty SpendCondition");

        println!("✓ Successfully serialized empty SpendCondition");
    }

    #[test]
    fn test_hashable_structure() {
        println!("\n=== Testing Hashable Structure for Signature Hash ===\n");

        // Test that we can build the hashable structure matching the Hoon formula:
        // hash([sig-hashable(seeds), leaf(fee)])
        let seeds_hashable = Hashable::Hash(Hash {
            values: T8 { values: [0; 8] },
        });
        let fee_hashable = Hashable::leaf_from_atom(&100u64.to_le_bytes());

        let combined = Hashable::cell(seeds_hashable, fee_hashable);
        let hash = hash_hashable(&combined);

        println!("✓ Built hashable structure and computed hash");

        // Verify hash is not all zeros
        let is_zero = hash.values.values.iter().all(|&v| v == 0);
        assert!(!is_zero, "Hash should not be all zeros");
    }
}
