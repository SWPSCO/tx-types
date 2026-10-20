//! TIP5 hashing over the shared noun arena.
use super::{hashable::Hashable, tip5::Tip5Error};
use crate::transaction_types::Hash;
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use pokenoun::codec::Encode;

pub const GOLDILOCKS_PRIME: u64 = pokenoun::GOLDILOCKS_P;

pub fn hash_noun_varlen(data: &[u8]) -> Result<Hash, Tip5Error> {
    let mut arena = pokenoun::Arena::new();
    let noun = pokenoun::cue(data, &mut arena)
        .map_err(|error| Tip5Error::SerializationError(format!("invalid jam: {error:?}")))?;
    hash_arena_noun(noun, &arena)
}

pub fn hash_arena_noun(noun: pokenoun::Noun, arena: &pokenoun::Arena) -> Result<Hash, Tip5Error> {
    pokenoun::hash_noun_varlen(noun, arena)
        .map(|values| Hash { values })
        .map_err(Into::into)
}

pub fn hash_ten_cell(left: Hash, right: Hash) -> Hash {
    Hash {
        values: pokenoun::hash_ten_cell(left.values, right.values).expect("digest limbs are based"),
    }
}

pub fn hash_hashable(h: &Hashable) -> Result<Hash, Tip5Error> {
    match h {
        Hashable::Leaf(jam) => hash_noun_varlen(jam),
        Hashable::Hash(hash) => Ok(hash.clone()),
        Hashable::Cell(left, right) => {
            Ok(hash_ten_cell(hash_hashable(left)?, hash_hashable(right)?))
        }
        Hashable::List(items) => {
            let hashes = items
                .iter()
                .map(hash_hashable)
                .collect::<Result<Vec<_>, _>>()?;
            hash_noun_varlen(
                &hashes
                    .to_jam()
                    .map_err(|error| Tip5Error::SerializationError(error.to_string()))?,
            )
        }
    }
}

#[cfg(feature = "std")]
pub fn digest_to_base58(digest: &Hash) -> String {
    digest.to_b58()
}

pub fn hash_transcript_list(element_arrays: &[&[u64]]) -> Result<Hash, Tip5Error> {
    let words: Vec<_> = element_arrays
        .iter()
        .flat_map(|array| array.iter().copied())
        .collect();
    pokenoun::hash_varlen_words(&words)
        .map(|values| Hash { values })
        .map_err(Into::into)
}

#[cfg(all(test, feature = "std"))]

mod tests {
    use super::*;

    #[test]
    fn test_hash_hashable_leaf() {
        let h = Hashable::leaf_from_tas("test");
        let digest = hash_hashable(&h).expect("leaf must hash");
        // Just check it doesn't panic and produces a digest
        assert_eq!(digest.values.len(), 5);
    }

    #[test]
    fn test_hash_hashable_cell() {
        let h = Hashable::cell(
            Hashable::leaf_from_tas("left"),
            Hashable::leaf_from_tas("right"),
        );
        let digest = hash_hashable(&h).expect("cell must hash");
        assert_eq!(digest.values.len(), 5);
    }

    #[test]
    fn test_hash_hashable_preserves_hash() {
        let digest = Hash {
            values: [1, 2, 3, 4, 5],
        };
        let h = Hashable::Hash(digest.clone());
        let result = hash_hashable(&h).expect("precomputed hash must pass through");
        assert_eq!(result, digest);
    }

    #[test]
    fn test_hash_ten_cell() {
        // Test that hash_ten_cell creates a proper list and hashes it correctly
        let left = Hash {
            values: [1, 2, 3, 4, 5],
        };
        let right = Hash {
            values: [6, 7, 8, 9, 10],
        };

        let result = hash_ten_cell(left, right);

        // Should produce a hash
        assert_eq!(result.values.len(), 5);

        // The result should be deterministic
        let result2 = hash_ten_cell(
            Hash {
                values: [1, 2, 3, 4, 5],
            },
            Hash {
                values: [6, 7, 8, 9, 10],
            },
        );
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hash_ten_cell_different_inputs() {
        // Different inputs should produce different hashes
        let hash1 = hash_ten_cell(
            Hash {
                values: [1, 2, 3, 4, 5],
            },
            Hash {
                values: [6, 7, 8, 9, 10],
            },
        );

        let hash2 = hash_ten_cell(
            Hash {
                values: [11, 12, 13, 14, 15],
            },
            Hash {
                values: [16, 17, 18, 19, 20],
            },
        );

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_transcript_list_deterministic() {
        // Test that hashing is deterministic
        let numbers = [1u64, 2u64, 3u64, 4u64, 5u64];
        let element_arrays: &[&[u64]] = &[&numbers];

        let result1 =
            hash_transcript_list(element_arrays).expect("hash_transcript_list should succeed");
        let result2 =
            hash_transcript_list(element_arrays).expect("hash_transcript_list should succeed");

        assert_eq!(
            result1.values, result2.values,
            "Hash should be deterministic"
        );
    }

    #[test]
    fn test_hash_transcript_list_multiple_arrays() {
        // Test hashing with multiple input arrays
        let arr1 = [1u64, 2u64, 3u64];
        let arr2 = [4u64, 5u64];
        let arr3 = [6u64, 7u64, 8u64, 9u64];

        let element_arrays: &[&[u64]] = &[&arr1, &arr2, &arr3];

        let result =
            hash_transcript_list(element_arrays).expect("hash_transcript_list should succeed");

        // Verify it produces a valid hash (5 u64 values)
        assert_eq!(result.values.len(), 5);

        // Compare with hashing all elements in one array
        let all_elements = [1u64, 2u64, 3u64, 4u64, 5u64, 6u64, 7u64, 8u64, 9u64];
        let result_flat =
            hash_transcript_list(&[&all_elements]).expect("hash_transcript_list should succeed");

        assert_eq!(
            result.values, result_flat.values,
            "Multiple arrays should hash same as flattened array"
        );
    }
}
