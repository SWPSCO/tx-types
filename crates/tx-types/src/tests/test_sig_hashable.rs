#[cfg(test)]
mod tests {
    use crate::transaction_types::{Seed, Seeds, Source, Lock, TimelockIntent, Coins, Hash, Spend};
    use crate::collections::zset::ZSet;
    use crate::hashing::hasher::hash_hashable;

    #[test]
    fn test_seed_sig_hashable_differs_from_hashable() {
        // Create a seed with an output source to verify the difference
        let seed = Seed {
            output_source: Some(Source {
                p: Hash { values: [1, 2, 3, 4, 5] },
                is_coinbase: false,
            }),
            recipient: Lock {
                m: 1,
                pubkeys: ZSet::new(),
            },
            timelock_intent: TimelockIntent::None,
            gift: Coins { value: 100 },
            parent_hash: Hash { values: [10, 11, 12, 13, 14] },
        };
        
        // Get both hashables
        let regular_hashable = seed.to_hashable();
        let sig_hashable = seed.to_sig_hashable();
        
        // Hash them to compare
        let regular_hash = hash_hashable(&regular_hashable);
        let sig_hash = hash_hashable(&sig_hashable);
        
        // They should be different because sig_hashable includes output_source
        assert_ne!(regular_hash, sig_hash, "sig_hashable should differ from regular hashable when output_source is present");
        
        println!("Regular hash: {:x?}", regular_hash.values);
        println!("Sig hash: {:x?}", sig_hash.values);
    }
    
    #[test]
    fn test_seed_sig_hashable_with_no_output_source() {
        // Create a seed without an output source
        let seed = Seed {
            output_source: None,
            recipient: Lock {
                m: 1,
                pubkeys: ZSet::new(),
            },
            timelock_intent: TimelockIntent::None,
            gift: Coins { value: 100 },
            parent_hash: Hash { values: [10, 11, 12, 13, 14] },
        };
        
        // Get both hashables
        let regular_hashable = seed.to_hashable();
        let sig_hashable = seed.to_sig_hashable();
        
        // Hash them to compare
        let regular_hash = hash_hashable(&regular_hashable);
        let sig_hash = hash_hashable(&sig_hashable);
        
        // They should still be different because sig_hashable includes a null for output_source
        assert_ne!(regular_hash, sig_hash, "sig_hashable should differ from regular hashable even when output_source is None");
        
        println!("Regular hash (no source): {:x?}", regular_hash.values);
        println!("Sig hash (no source): {:x?}", sig_hash.values);
    }
    
    #[test]
    fn test_spend_sig_hash() {
        // Create a simple spend structure
        let seed = Seed {
            output_source: None,
            recipient: Lock {
                m: 1,
                pubkeys: ZSet::new(),
            },
            timelock_intent: TimelockIntent::None,
            gift: Coins { value: 100 },
            parent_hash: Hash { values: [10, 11, 12, 13, 14] },
        };
        
        let mut seeds_set = ZSet::new();
        seeds_set.put(seed);
        
        let spend = Spend {
            signature: None,
            seeds: Seeds { set: seeds_set },
            fee: Coins { value: 10 },
        };
        
        // Get the sig_hash for signing
        let sig_hash = spend.sig_hash();
        
        // Get the regular hash for comparison
        let regular_hash = spend.to_hash();
        
        // They should be different because sig_hash uses sig_hashable for seeds
        assert_ne!(sig_hash, regular_hash, "sig_hash should differ from regular hash");
        
        println!("Spend regular hash: {:x?}", regular_hash.values);
        println!("Spend sig hash: {:x?}", sig_hash.values);
    }
    
    #[test]
    fn test_seeds_sig_hashable() {
        // Create multiple seeds with different properties
        let seed1 = Seed {
            output_source: Some(Source {
                p: Hash { values: [1, 2, 3, 4, 5] },
                is_coinbase: false,
            }),
            recipient: Lock {
                m: 1,
                pubkeys: ZSet::new(),
            },
            timelock_intent: TimelockIntent::None,
            gift: Coins { value: 100 },
            parent_hash: Hash { values: [10, 11, 12, 13, 14] },
        };
        
        let seed2 = Seed {
            output_source: None,
            recipient: Lock {
                m: 2,
                pubkeys: ZSet::new(),
            },
            timelock_intent: TimelockIntent::None,
            gift: Coins { value: 200 },
            parent_hash: Hash { values: [20, 21, 22, 23, 24] },
        };
        
        let mut seeds_set = ZSet::new();
        seeds_set.put(seed1);
        seeds_set.put(seed2);
        
        let seeds = Seeds { set: seeds_set };
        
        // Get both hashables
        let regular_hashable = seeds.to_hashable();
        let sig_hashable = seeds.to_sig_hashable();
        
        // Hash them to compare
        let regular_hash = hash_hashable(&regular_hashable);
        let sig_hash = hash_hashable(&sig_hashable);
        
        // They should be different because sig_hashable uses sig_hashable for each seed
        assert_ne!(regular_hash, sig_hash, "Seeds sig_hashable should differ from regular hashable");
        
        println!("Seeds regular hash: {:x?}", regular_hash.values);
        println!("Seeds sig hash: {:x?}", sig_hash.values);
    }
}