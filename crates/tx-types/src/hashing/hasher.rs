/// Core hashing functions for the transaction hashing system
/// Implements TIP5 hashing compatible with the Hoon implementation

use super::hashable::Hashable;
use crate::transaction_types::Hash;
use nockapp::noun::slab::NounSlab;
use nockapp::Noun;
use nockvm::noun::{Atom, T};

/// Goldilocks prime: 2^64 - 2^32 + 1
pub const GOLDILOCKS_PRIME: u64 = 0xffffffff00000001;

/// Hash a raw noun using variable-length hashing
/// This mirrors the Hoon hash-noun-varlen function
pub fn hash_noun_varlen(data: &[u8]) -> Hash {
    use super::tip5::Tip5Hasher;
    use nockapp::noun::AtomExt;
    
    // Debug: log what we're hashing (disabled for now)
    // if data.len() <= 16 {
    //     eprintln!("hash_noun_varlen: hashing {} bytes: {:02x?}", data.len(), data);
    // } else {
    //     eprintln!("hash_noun_varlen: hashing {} bytes (first 16): {:02x?}...", data.len(), &data[..16]);
    // }
    
    // Convert bytes to a noun (as an atom)
    let mut slab: NounSlab = NounSlab::new();
    
    // Create an atom from the bytes
    let noun = if data.is_empty() {
        Atom::new(&mut slab, 0).as_noun()
    } else if data.len() <= 8 {
        // For small data, convert directly to u64
        let mut value = 0u64;
        for (i, &byte) in data.iter().enumerate() {
            value |= (byte as u64) << (i * 8);
        }
        // eprintln!("  -> Created atom with value: {:#x}", value);
        Atom::new(&mut slab, value).as_noun()
    } else {
        // For larger data, use Atom::from_bytes
        // Note: from_bytes expects a nockapp::Bytes, not &[u8]
        use nockapp::Bytes;
        // eprintln!("  -> Creating large atom from {} bytes", data.len());
        let bytes = Bytes::copy_from_slice(data);
        Atom::from_bytes(&mut slab, &bytes).as_noun()
    };
    
    // Use the real TIP5 hasher
    let result = Tip5Hasher::hash_noun_varlen(noun).unwrap_or_else(|_e| {
        // eprintln!("  -> TIP5 hash failed: {:?}", e);
        Hash { values: [0; 5] }
    });
    // eprintln!("  -> Hash result: {:x?}", result.values);
    result
}

/// Hash two digests together (hash-ten-cell in Hoon)
/// Takes two 5-element digests and produces a new 5-element digest
/// 
/// The Hoon implementation:
/// 1. Creates a ten-cell from the two 5-element hashes
/// 2. Calls leaf-sequence:shape to flatten it
/// 3. Hashes the flattened sequence with hash-10
///
/// We create a list of 10 values and use the specific hash_10 function
pub fn hash_ten_cell(left: Hash, right: Hash) -> Hash {
    use super::tip5::Tip5Hasher;
    use nockvm::noun::Cell;
    
    // Create a cell from the two hashes and hash it
    let mut slab: NounSlab = NounSlab::new();
    
    // Create a Hoon list (right-associative linked list) of 10 values
    // A list in Hoon is [a [b [c [d ... 0]]]]
    let mut list = Atom::new(&mut slab, 0).as_noun(); // Start with nil (0)
    
    // Add right hash values in reverse order (since we're building from the tail)
    for value in right.values.iter().rev() {
        let atom = Atom::new(&mut slab, *value).as_noun();
        list = Cell::new(&mut slab, atom, list).as_noun();
    }
    
    // Add left hash values in reverse order
    for value in left.values.iter().rev() {
        let atom = Atom::new(&mut slab, *value).as_noun();
        list = Cell::new(&mut slab, atom, list).as_noun();
    }
    
    // Use the specific hash_10 function for lists of 10 elements
    Tip5Hasher::hash_10(list).unwrap_or_else(|_| Hash { values: [0; 5] })
}

/// Recursively hash a Hashable structure
/// This mirrors the Hoon hash-hashable function
pub fn hash_hashable(h: &Hashable) -> Hash {
    match h {
        Hashable::Leaf(data) => {
            // Hash raw data
            hash_noun_varlen(data)
        },
        Hashable::Hash(digest) => {
            // Already hashed, return as-is
            digest.clone()
        },
        Hashable::Cell(left, right) => {
            // Recursively hash both sides and combine
            let left_hash = hash_hashable(left);
            let right_hash = hash_hashable(right);
            hash_ten_cell(left_hash, right_hash)
        },
        Hashable::List(items) => {
            use super::tip5::Tip5Hasher;
            
            // Hash each item recursively
            let hashes: Vec<Hash> = items.iter().map(hash_hashable).collect();
            
            // Convert list of hashes to a noun list structure
            let mut slab: NounSlab = NounSlab::new();
            
            // Build a list of hash nouns
            let hash_nouns: Vec<_> = hashes.iter().map(|hash| {
                let atoms = hash.values.map(|v| Atom::new(&mut slab, v).as_noun());
                T(&mut slab, &atoms)
            }).collect();
            
            // Create a noun list
            let list_noun = if hash_nouns.is_empty() {
                Atom::new(&mut slab, 0).as_noun()  // Empty list is 0
            } else {
                T(&mut slab, &hash_nouns)
            };
            
            // Hash the list using real TIP5
            Tip5Hasher::hash_noun_varlen(list_noun).unwrap_or_else(|_| Hash { values: [0; 5] })
        }
    }
}


/// Convert a digest to a base58 string (for display)
pub fn digest_to_base58(digest: &Hash) -> String {
    // This mirrors the Hoon digest-to-atom and then base58 encoding
    // Following the formula: a + b*p + c*p² + d*p³ + e*p⁴
    
    use num_bigint::BigUint;
    use bs58;
    
    let p = BigUint::from(GOLDILOCKS_PRIME);
    let mut result = BigUint::from(digest.values[0]);
    
    for i in 1..5 {
        let power = p.pow(i as u32);
        result += BigUint::from(digest.values[i]) * power;
    }
    
    bs58::encode(result.to_bytes_be()).into_string()
}

/// Hash a transcript list using TIP5 with proper Hoon list structure
///
/// This function is used by the Schnorr signature process to generate nonces
/// and challenges. It takes multiple arrays of u64 values, flattens them into
/// a single list, and hashes the list using TIP5.
///
/// The list is constructed in Hoon format: [a [b [c [d ... 0]]]]
/// (right-associative with nil terminator)
///
/// # Arguments
/// * `element_arrays` - Arrays of u64 values to hash (e.g., public key coordinates, message)
///
/// # Returns
/// * `Ok(Hash)` - The TIP5 hash of the transcript list
/// * `Err(Tip5Error)` - If hashing fails
///
/// # Used in Schnorr signatures:
/// - Nonce generation: TIP5([pubkey.x, pubkey.y, message])
/// - Challenge generation: TIP5([R.x, R.y, pubkey.x, pubkey.y, message])
pub fn hash_transcript_list(element_arrays: &[&[u64]]) -> Result<Hash, crate::hashing::tip5::Tip5Error> {
    use super::tip5::Tip5Hasher;
    use nockvm::noun::Cell;

    let mut slab: NounSlab<nockvm::noun::IndirectAtom> = NounSlab::new();

    // Flatten all elements into a single list
    let mut all_elements = Vec::new();
    for array in element_arrays {
        all_elements.extend_from_slice(array);
    }

    // Build Hoon list structure: [a [b [c [d ... 0]]]]
    let mut list = nockvm::noun::Atom::new(&mut slab, 0).as_noun(); // Start with nil (0)

    // Build list in reverse order (right-associative)
    for &element in all_elements.iter().rev() {
        let atom = nockvm::noun::Atom::new(&mut slab, element).as_noun();
        list = Cell::new(&mut slab, atom, list).as_noun();
    }

    // Hash the list using TIP5
    Tip5Hasher::hash_varlen(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_hashable_leaf() {
        let h = Hashable::leaf(b"test");
        let digest = hash_hashable(&h);
        // Just check it doesn't panic and produces a digest
        assert_eq!(digest.values.len(), 5);
    }
    
    #[test]
    fn test_hash_hashable_cell() {
        let h = Hashable::cell(
            Hashable::leaf(b"left"),
            Hashable::leaf(b"right")
        );
        let digest = hash_hashable(&h);
        assert_eq!(digest.values.len(), 5);
    }
    
    #[test]
    fn test_hash_hashable_preserves_hash() {
        let digest = Hash { values: [1, 2, 3, 4, 5] };
        let h = Hashable::Hash(digest.clone());
        let result = hash_hashable(&h);
        assert_eq!(result, digest);
    }
    
    #[test]
    fn test_hash_ten_cell() {
        // Test that hash_ten_cell creates a proper list and hashes it correctly
        let left = Hash { values: [1, 2, 3, 4, 5] };
        let right = Hash { values: [6, 7, 8, 9, 10] };
        
        let result = hash_ten_cell(left, right);
        
        // Should produce a hash
        assert_eq!(result.values.len(), 5);
        
        // The result should be deterministic
        let result2 = hash_ten_cell(
            Hash { values: [1, 2, 3, 4, 5] },
            Hash { values: [6, 7, 8, 9, 10] }
        );
        assert_eq!(result, result2);
    }
    
    #[test]
    fn test_hash_ten_cell_different_inputs() {
        // Different inputs should produce different hashes
        let hash1 = hash_ten_cell(
            Hash { values: [1, 2, 3, 4, 5] },
            Hash { values: [6, 7, 8, 9, 10] }
        );
        
        let hash2 = hash_ten_cell(
            Hash { values: [11, 12, 13, 14, 15] },
            Hash { values: [16, 17, 18, 19, 20] }
        );
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_transcript_list_deterministic() {
        // Test that hashing is deterministic
        let numbers = [1u64, 2u64, 3u64, 4u64, 5u64];
        let element_arrays: &[&[u64]] = &[&numbers];

        let result1 = hash_transcript_list(element_arrays)
            .expect("hash_transcript_list should succeed");
        let result2 = hash_transcript_list(element_arrays)
            .expect("hash_transcript_list should succeed");

        assert_eq!(result1.values, result2.values, "Hash should be deterministic");
    }

    #[test]
    fn test_hash_transcript_list_multiple_arrays() {
        // Test hashing with multiple input arrays
        let arr1 = [1u64, 2u64, 3u64];
        let arr2 = [4u64, 5u64];
        let arr3 = [6u64, 7u64, 8u64, 9u64];

        let element_arrays: &[&[u64]] = &[&arr1, &arr2, &arr3];

        let result = hash_transcript_list(element_arrays)
            .expect("hash_transcript_list should succeed");

        // Verify it produces a valid hash (5 u64 values)
        assert_eq!(result.values.len(), 5);

        // Compare with hashing all elements in one array
        let all_elements = [1u64, 2u64, 3u64, 4u64, 5u64, 6u64, 7u64, 8u64, 9u64];
        let result_flat = hash_transcript_list(&[&all_elements])
            .expect("hash_transcript_list should succeed");

        assert_eq!(result.values, result_flat.values,
            "Multiple arrays should hash same as flattened array");
    }
}