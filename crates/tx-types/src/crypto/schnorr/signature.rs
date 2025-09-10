/// Schnorr signature implementation with TIP5 challenge
use core::cmp::min;
use ibig::UBig;
use num_traits::Zero;
use zkvm_jetpack::form::math::badd;
use zkvm_jetpack::form::math::tip5::permute as tip5_permute;
use crate::crypto::cheetah::{CheetahPoint, constants::group_order};
use crate::crypto::utils::UBigExt;
use crate::transaction_types::{Hash, T8};
use super::rfc6979::generate_nonce;

/// Signature-related errors
#[derive(Debug, Clone)]
pub enum SignatureError {
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidMessage,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SignatureError::InvalidPrivateKey => write!(f, "Invalid private key"),
            SignatureError::InvalidPublicKey => write!(f, "Invalid public key"),
            SignatureError::InvalidSignature => write!(f, "Invalid signature"),
            SignatureError::InvalidMessage => write!(f, "Invalid message"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// TIP5 hash constants
const DIGEST_LENGTH: usize = 5;
const STATE_SIZE: usize = 16;
const RATE: usize = 10;

/// Compute TIP5 hash of word array
fn tip5_hash_words(words: &[u64]) -> [u64; DIGEST_LENGTH] {
    let mut state = [0u64; STATE_SIZE];
    
    // Absorb phase
    let mut i = 0;
    while i < words.len() {
        let take = min(RATE, words.len() - i);
        for j in 0..take {
            state[j] = badd(state[j], words[i + j]);
        }
        i += take;
        tip5_permute(&mut state);
    }
    
    // Domain separation
    state[words.len() % RATE] = badd(state[words.len() % RATE], 1);
    state[STATE_SIZE - 1] = badd(state[STATE_SIZE - 1], 1 << 63);
    tip5_permute(&mut state);
    
    // Extract digest
    let mut output = [0u64; DIGEST_LENGTH];
    output.copy_from_slice(&state[..DIGEST_LENGTH]);
    output
}

/// Pack point coordinates into word array for hashing
fn pack_point_words(point: &CheetahPoint) -> [u64; 12] {
    let coords = point.to_coordinates();
    let mut words = [0u64; 12];
    words[..6].copy_from_slice(&coords[0]);
    words[6..].copy_from_slice(&coords[1]);
    words
}

/// Sign a hash using Schnorr signatures with TIP5 challenge
/// 
/// Algorithm:
/// 1. Generate RFC6979 nonce k from private key and hash
/// 2. Compute R = k*G 
/// 3. Compute challenge e = TIP5(R || P || hash)
/// 4. Compute signature s = k + e*private_key mod n
/// 5. Return (e, s) as T8 arrays
pub fn sign_hash(
    private_key: &[u8; 32],
    public_key: &CheetahPoint,
    hash: &Hash,
) -> Result<(T8, T8), SignatureError> {
    let n = group_order();
    
    // Validate private key
    let sk_int = UBig::from_be_bytes(private_key);
    if sk_int.is_zero() || sk_int >= n {
        return Err(SignatureError::InvalidPrivateKey);
    }
    
    // Convert hash to message bytes for RFC6979
    let mut message = Vec::with_capacity(5 * 8);
    for word in hash.values {
        message.extend_from_slice(&word.to_be_bytes());
    }
    
    // Generate deterministic nonce
    let k = generate_nonce(private_key, &message, &n);
    
    // Compute R = k*G
    let r_point = CheetahPoint::generator().scalar_mul(&k);
    
    // Compute challenge: e = TIP5(R || P || hash)
    let mut challenge_words = Vec::with_capacity(12 + 12 + 5);
    challenge_words.extend_from_slice(&pack_point_words(&r_point));
    challenge_words.extend_from_slice(&pack_point_words(public_key));
    challenge_words.extend_from_slice(&hash.values);
    
    let e_words = tip5_hash_words(&challenge_words);
    
    // Convert challenge to UBig
    let mut e_bytes = [0u8; 40]; // 5 * 8 bytes
    for (i, word) in e_words.iter().enumerate() {
        e_bytes[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    let e = UBig::from_be_bytes(&e_bytes) % &n;
    
    // Compute signature: s = k + e*private_key mod n
    let s = (k + e.clone() * sk_int) % &n;
    
    // Convert to T8 format
    let e_t8 = e.to_t8();
    let s_t8 = s.to_t8();
    
    Ok((e_t8, s_t8))
}

/// Verify a Schnorr signature
/// 
/// Algorithm:
/// 1. Compute R' = s*G - e*P
/// 2. Compute e' = TIP5(R' || P || hash)  
/// 3. Check if e' == e
pub fn verify_signature(
    public_key: &CheetahPoint,
    hash: &Hash,
    signature: &(T8, T8),
) -> bool {
    let n = group_order();
    let (e_t8, s_t8) = signature;
    
    // Convert T8 to UBig
    let e = match UBig::from_t8(e_t8) {
        Ok(val) => val,
        Err(_) => return false,
    };
    let s = match UBig::from_t8(s_t8) {
        Ok(val) => val,
        Err(_) => return false,
    };
    
    // Validate signature components
    if e.is_zero() || e >= n || s.is_zero() || s >= n {
        return false;
    }
    
    // Compute R' = s*G - e*P
    let sg = CheetahPoint::generator().scalar_mul(&s);
    let ep = public_key.scalar_mul(&e);
    let r_prime = sg.add(&ep.scalar_mul(&(n.clone() - UBig::from(1u32)))); // Subtract by adding -eP
    
    // Compute challenge: e' = TIP5(R' || P || hash)
    let mut challenge_words = Vec::with_capacity(12 + 12 + 5);
    challenge_words.extend_from_slice(&pack_point_words(&r_prime));
    challenge_words.extend_from_slice(&pack_point_words(public_key));
    challenge_words.extend_from_slice(&hash.values);
    
    let e_prime_words = tip5_hash_words(&challenge_words);
    
    // Convert to UBig and compare
    let mut e_prime_bytes = [0u8; 40];
    for (i, word) in e_prime_words.iter().enumerate() {
        e_prime_bytes[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    let e_prime = UBig::from_be_bytes(&e_prime_bytes) % &n;
    
    e == e_prime
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cheetah::CheetahPoint;
    
    #[test]
    fn test_sign_and_verify() {
        let private_key = [1u8; 32];
        let public_key = CheetahPoint::from_private_key(&private_key);
        let hash = Hash { values: [1, 2, 3, 4, 5] };
        
        let signature = sign_hash(&private_key, &public_key, &hash).unwrap();
        assert!(verify_signature(&public_key, &hash, &signature));
    }
    
    #[test]
    fn test_different_hash_fails_verification() {
        let private_key = [1u8; 32];
        let public_key = CheetahPoint::from_private_key(&private_key);
        let hash1 = Hash { values: [1, 2, 3, 4, 5] };
        let hash2 = Hash { values: [5, 4, 3, 2, 1] };
        
        let signature = sign_hash(&private_key, &public_key, &hash1).unwrap();
        assert!(!verify_signature(&public_key, &hash2, &signature));
    }
    
    #[test]
    fn test_wrong_public_key_fails_verification() {
        let private_key1 = [1u8; 32];
        let private_key2 = [2u8; 32];
        let public_key1 = CheetahPoint::from_private_key(&private_key1);
        let public_key2 = CheetahPoint::from_private_key(&private_key2);
        let hash = Hash { values: [1, 2, 3, 4, 5] };
        
        let signature = sign_hash(&private_key1, &public_key1, &hash).unwrap();
        assert!(!verify_signature(&public_key2, &hash, &signature));
    }
}