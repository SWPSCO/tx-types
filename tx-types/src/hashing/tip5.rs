use nockapp::noun::slab::NounSlab;
use nockapp::Noun;
// Re-export for use by other modules in this crate
use nockapp::noun::NounAllocatorExt;
pub use nockchain_libp2p_io::tip5_util::tip5_hash_to_base58;
use nockchain_math::shape::do_leaf_sequence;
use nockchain_math::tip5::hash::{hash_belts_slice, hash_noun_varlen_digest, hash_ten_cell};
use nockvm::jets::util::test::init_context;
use nockvm::jets::JetErr;
use nockvm::noun::{NounAllocator, NounSpace};
use zkvm_jetpack::jets::tip5_jets::hash_hashable as hash_hashable_noun;

use crate::transaction_types::Hash;

/// Errors that can occur during TIP5 hashing
#[derive(Debug, Clone)]
pub enum Tip5Error {
    /// Failed to serialize the noun for hashing
    SerializationError(String),
    /// TIP5 hashing operation failed
    HashingError(String),
    /// Invalid noun structure
    InvalidNoun(String),
}

impl std::fmt::Display for Tip5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tip5Error::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Tip5Error::HashingError(msg) => write!(f, "Hashing error: {}", msg),
            Tip5Error::InvalidNoun(msg) => write!(f, "Invalid noun: {}", msg),
        }
    }
}

impl std::error::Error for Tip5Error {}

impl From<JetErr> for Tip5Error {
    fn from(err: JetErr) -> Self {
        Tip5Error::HashingError(format!("Jet error: {:?}", err))
    }
}

/// TIP5 hasher for Nock nouns
pub struct Tip5Hasher;

impl Tip5Hasher {
    /// Parse a hash noun which can be either:
    /// - A 5-tuple: [a [b [c [d e]]]] (from digest_to_noundigest)
    /// - A Hoon list with terminator: [a [b [c [d [e 0]]]]] (from vec_to_hoon_list)
    fn digest_from_noun(hash_noun: Noun, space: &NounSpace) -> Result<Hash, Tip5Error> {
        let mut values = [0u64; 5];
        let mut current = hash_noun;

        // Parse first 4 elements (always in cells)
        for i in 0..4 {
            let cell = current
                .in_space(space)
                .as_cell()
                .map_err(|_| Tip5Error::HashingError(format!("Expected cell at position {}", i)))?;

            let atom = cell
                .head()
                .as_atom()
                .map_err(|_| Tip5Error::HashingError(format!("Expected atom at position {}", i)))?;

            values[i] = atom.as_u64().map_err(|_| {
                Tip5Error::HashingError(format!("Atom too large at position {}", i))
            })?;

            current = cell.tail().noun();
        }

        // The 5th element: could be either:
        // - An atom (5-tuple format: [a [b [c [d e]]]])
        // - A cell [e 0] (Hoon list format: [a [b [c [d [e 0]]]]])
        let current_handle = current.in_space(space);
        if let Ok(atom) = current_handle.as_atom() {
            // 5-tuple format - current is already the 5th element
            values[4] = atom
                .as_u64()
                .map_err(|_| Tip5Error::HashingError("Atom too large at position 4".to_string()))?;
        } else if let Ok(cell) = current_handle.as_cell() {
            // Hoon list format - extract head of [e 0]
            let atom = cell
                .head()
                .as_atom()
                .map_err(|_| Tip5Error::HashingError("Expected atom at position 4".to_string()))?;
            values[4] = atom
                .as_u64()
                .map_err(|_| Tip5Error::HashingError("Atom too large at position 4".to_string()))?;
        } else {
            return Err(Tip5Error::HashingError(
                "Invalid hash noun structure at position 4".to_string(),
            ));
        }

        Ok(Hash { values })
    }

    /// Hash a noun using the TIP5 algorithm and return as a Hash struct
    ///
    /// This corresponds to the Hoon hash-noun-varlen function. It takes any noun
    /// and returns its TIP5 hash as a Hash struct containing the 5-element belt.
    ///
    /// # Arguments
    /// * `noun` - The noun to hash
    /// * `space` - The [`NounSpace`] `noun` was allocated in
    ///
    /// # Returns
    /// * `Result<Hash, Tip5Error>` - The hash as a Hash struct or an error
    pub fn hash_noun_varlen(noun: Noun, space: &NounSpace) -> Result<Hash, Tip5Error> {
        // The digest walk reads the noun directly in its own space and does not
        // allocate, so no scratch stack copy is needed.
        let context = &mut init_context();
        let values = hash_noun_varlen_digest(&mut context.stack, noun, space)
            .map_err(|e| Tip5Error::HashingError(format!("TIP5 hashing failed: {:?}", e)))?;
        Ok(Hash { values })
    }

    /// Hash a 10-tuple using the TIP5 hash_10 algorithm
    ///
    /// This is specifically for hashing 10-element tuples, as used in hash_ten_cell.
    /// It wraps the hash_10_jet function which implements the Hoon hash-10 function.
    ///
    /// # Arguments
    /// * `ten_list` - A noun that should be a 10-element list
    /// * `space` - The [`NounSpace`] `ten_list` was allocated in
    ///
    /// # Returns
    /// * `Result<Hash, Tip5Error>` - The hash as a Hash struct or an error
    pub fn hash_10(ten_list: Noun, space: &NounSpace) -> Result<Hash, Tip5Error> {
        let mut leaf = Vec::<u64>::new();
        do_leaf_sequence(ten_list, &mut leaf, space)
            .map_err(|e| Tip5Error::HashingError(format!("TIP5 hash_10 failed: {:?}", e)))?;
        let leaf: [u64; nockchain_math::tip5::RATE] = leaf.try_into().map_err(|_| {
            Tip5Error::HashingError("hash_10 expects exactly 10 leaves".to_string())
        })?;
        Ok(Hash {
            values: hash_ten_cell(leaf),
        })
    }

    /// Hash 10 u64 values using the TIP5 hash_10 algorithm
    ///
    /// This builds the list directly in the NockStack to avoid memory issues.
    ///
    /// # Arguments
    /// * `values` - Array of 10 u64 values to hash
    ///
    /// # Returns
    /// * `Result<Hash, Tip5Error>` - The hash as a Hash struct or an error
    pub fn hash_10_from_values(values: &[u64; 10]) -> Result<Hash, Tip5Error> {
        Ok(Hash {
            values: hash_ten_cell(*values),
        })
    }

    /// Hash a Hashable structure using the TIP5 jet.
    pub fn hash_hashable(hashable: &crate::hashing::hashable::Hashable) -> Result<Hash, Tip5Error> {
        hashable.validate_leaves()?;
        let mut slab: NounSlab = NounSlab::new();
        let noun = hashable.to_noun(&mut slab);
        slab.set_root(noun);
        let slab_space = slab.noun_space();

        let context = &mut init_context();
        let copied = context.stack.copy_into(noun, &slab_space);
        let stack_space = context.stack.noun_space();
        let hash_noun = hash_hashable_noun(&mut context.stack, copied, &stack_space)
            .map_err(|e| Tip5Error::HashingError(format!("TIP5 hash_hashable failed: {:?}", e)))?;

        let result_space = context.stack.noun_space();
        Self::digest_from_noun(hash_noun, &result_space)
    }

    /// Hash a noun and convert to base58 string
    ///
    /// Convenience function that hashes and converts to base58.
    ///
    /// # Arguments
    /// * `noun` - The noun to hash
    /// * `space` - The [`NounSpace`] `noun` was allocated in
    ///
    /// # Returns
    /// * `Result<String, Tip5Error>` - The base58-encoded hash or an error
    pub fn hash_noun_varlen_to_base58(noun: Noun, space: &NounSpace) -> Result<String, Tip5Error> {
        let hash = Self::hash_noun_varlen(noun, space)?;
        Ok(hash.to_b58())
    }

    /// Hash a list of field elements using the TIP5 algorithm
    ///
    /// This corresponds to the Hoon hash-varlen function which takes a list of field
    /// elements (belts) and hashes them directly without noun conversion.
    ///
    /// # Arguments
    /// * `belts_list` - A noun that should be a list of field elements (u64 values)
    ///
    /// # Returns
    /// * `Result<Hash, Tip5Error>` - The hash as a Hash struct or an error
    pub fn hash_varlen(belts_list: Noun, space: &NounSpace) -> Result<Hash, Tip5Error> {
        let mut values = Vec::new();
        let mut current = belts_list;

        loop {
            let handle = current.in_space(space);
            if let Ok(cell) = handle.as_cell() {
                let atom = cell
                    .head()
                    .as_atom()
                    .map_err(|_| Tip5Error::HashingError("Expected atom in list".to_string()))?;
                values.push(
                    atom.as_u64().map_err(|_| {
                        Tip5Error::HashingError("Atom too large in list".to_string())
                    })?,
                );
                current = cell.tail().noun();
                continue;
            }

            let atom = handle
                .as_atom()
                .map_err(|_| Tip5Error::HashingError("Expected atom or cell".to_string()))?;
            if atom.as_u64().unwrap_or(1) == 0 {
                break;
            }
            return Err(Tip5Error::HashingError(
                "Expected list to end with 0".to_string(),
            ));
        }

        Ok(Hash {
            values: hash_belts_slice(&values),
        })
    }
}

// Tests for the TIP5Hasher struct

#[cfg(test)]
mod tests {
    use super::*;
    use nockvm::noun::{D, T};

    #[test]
    fn test_hash_simple_atom() {
        let noun = D(42);
        let space = NounSpace::empty();
        let hash = Tip5Hasher::hash_noun_varlen(noun, &space).expect("Should hash successfully");

        // Hash should have 5 u64 values
        assert_eq!(hash.values.len(), 5);

        // All values should be non-zero (very likely for a hash)
        assert!(
            hash.values.iter().any(|&v| v != 0),
            "Hash should have non-zero values"
        );

        // Test the base58 conversion function
        let hash_str =
            Tip5Hasher::hash_noun_varlen_to_base58(noun, &space).expect("Should convert to base58");
        assert!(!hash_str.is_empty());
        assert!(hash_str
            .chars()
            .all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)));
    }

    #[test]
    fn test_hash_consistency() {
        let noun = D(123);
        let space = NounSpace::empty();
        let hash1 = Tip5Hasher::hash_noun_varlen(noun, &space).expect("Should hash successfully");
        let hash2 = Tip5Hasher::hash_noun_varlen(noun, &space).expect("Should hash successfully");

        // Same input should produce same hash
        assert_eq!(hash1.values, hash2.values);
    }

    #[test]
    fn test_hash_different_values() {
        let space = NounSpace::empty();
        let hash1 = Tip5Hasher::hash_noun_varlen(D(42), &space).expect("Should hash successfully");
        let hash2 = Tip5Hasher::hash_noun_varlen(D(43), &space).expect("Should hash successfully");

        // Different inputs should produce different hashes
        assert_ne!(hash1.values, hash2.values);
    }

    #[test]
    fn test_hash_varlen() {
        // Create a test context to build a list of field elements
        let context = &mut init_context();

        // Create a list [1, 2, 3] as field elements (belts)
        // In Hoon list format: [1 [2 [3 0]]]
        let list_noun = T(&mut context.stack, &[D(1), D(2), D(3), D(0)]);

        let stack_space = context.stack.noun_space();
        let hash =
            Tip5Hasher::hash_varlen(list_noun, &stack_space).expect("Should hash successfully");

        // Hash should have 5 u64 values
        assert_eq!(hash.values.len(), 5);

        // All values should be non-zero (very likely for a hash)
        assert!(
            hash.values.iter().any(|&v| v != 0),
            "Hash should have non-zero values"
        );

        // Test consistency - same input should produce same hash
        let hash2 =
            Tip5Hasher::hash_varlen(list_noun, &stack_space).expect("Should hash successfully");
        assert_eq!(hash.values, hash2.values, "Hash should be deterministic");

        println!("hash_varlen([1, 2, 3]) = {:x?}", hash.values);
    }
}
