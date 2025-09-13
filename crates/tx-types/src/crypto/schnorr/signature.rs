/// Schnorr signature implementation with TIP5 challenge (copied from working siger-esp implementation)
use core::cmp::min;
use ibig::UBig;
use num_traits::Zero;
use zkvm_jetpack::form::math::badd;
use zkvm_jetpack::form::math::tip5::permute as tip5_permute;
use crate::crypto::cheetah::point::{cheetah_order, cheetah_pub_from_sk, scalar_mul_g, CheetahPoint};
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
    pack_point_words_from_coords(&coords)
}

/// Pack point coordinates from coordinate array
fn pack_point_words_from_coords(pt: &[[u64; 6]; 2]) -> [u64; 12] {
    let mut out = [0u64; 12];
    out[..6].copy_from_slice(&pt[0]);
    out[6..].copy_from_slice(&pt[1]);
    out
}

/// Sign a transaction ID using the exact algorithm from working siger-esp implementation
pub fn schnorr_sign_txid(sk_be32: [u8; 32], pk: [[u64; 6]; 2], txid: Hash) -> (T8, T8) {
    let n = cheetah_order();
    
    // RFC6979 nonce over txid bytes (40 bytes)
    let mut msg = Vec::with_capacity(5 * 8);
    for w in txid.values { 
        msg.extend_from_slice(&w.to_be_bytes()); 
    }
    let k = generate_nonce(&sk_be32, &msg, &n);
    
    // R = k*G
    let mut kb = k.to_be_bytes();
    if kb.len() < 32 {
        let mut pad = vec![0u8; 32 - kb.len()];
        pad.extend_from_slice(&kb);
        kb = pad;
    }
    let mut k32 = [0u8; 32];
    k32.copy_from_slice(&kb[kb.len() - 32..]);
    let r_pt = cheetah_pub_from_sk(k32);
    
    // e = TIP5( R || P || txid )
    let mut words = Vec::<u64>::with_capacity(12 + 12 + 5);
    words.extend_from_slice(&pack_point_words_from_coords(&r_pt));
    words.extend_from_slice(&pack_point_words_from_coords(&pk));
    words.extend_from_slice(&txid.values);
    let e_words = tip5_hash_words(&words);
    
    let mut e_be = [0u8; 40];
    for (i, w) in e_words.iter().enumerate() {
        e_be[i * 8..(i + 1) * 8].copy_from_slice(&w.to_be_bytes());
    }
    let e = UBig::from_be_bytes(&e_be) % &n;
    
    // s = k + e*x mod n
    let x = UBig::from_be_bytes(&sk_be32);
    let s = (k + e.clone() * x) % &n;
    
    (ubig_to_t8(&e), ubig_to_t8(&s))
}

/// Convert UBig to T8 using working implementation
fn ubig_to_t8(v: &UBig) -> T8 {
    // 8 limbs, limb[0] = least-significant 64 bits (LE by limb)
    let mut be = v.to_be_bytes();
    if be.len() < 64 {
        let mut pad = vec![0u8; 64 - be.len()];
        pad.extend_from_slice(&be);
        be = pad;
    } else if be.len() > 64 {
        be = be[be.len() - 64..].to_vec();
    }
    let mut limbs = [0u64; 8];
    for i in 0..8 {
        let start = 64 - (i + 1) * 8;
        limbs[i] = u64::from_be_bytes(be[start..start + 8].try_into().unwrap());
    }
    T8 { values: limbs }
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
    let n = cheetah_order();
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
    use crate::crypto::cheetah::point::{CheetahPoint, cheetah_pub_from_sk};
    
    #[test]
    fn test_schnorr_sign_txid() {
        let private_key = [1u8; 32];
        let public_key_coords = cheetah_pub_from_sk(private_key);
        let hash = Hash { values: [1, 2, 3, 4, 5] };
        
        let signature = schnorr_sign_txid(private_key, public_key_coords, hash);
        // Just verify it returns valid T8 values without panicking
        assert!(signature.0.values.len() == 8);
        assert!(signature.1.values.len() == 8);
    }
    
    #[test]
    fn test_deterministic_signatures() {
        let private_key = [1u8; 32];
        let public_key_coords = cheetah_pub_from_sk(private_key);
        let hash = Hash { values: [1, 2, 3, 4, 5] };
        
        let signature1 = schnorr_sign_txid(private_key, public_key_coords, hash.clone());
        let signature2 = schnorr_sign_txid(private_key, public_key_coords, hash);
        
        // Signatures should be deterministic
        assert_eq!(signature1.0.values, signature2.0.values);
        assert_eq!(signature1.1.values, signature2.1.values);
    }
    
    #[test]
    fn test_different_keys_different_signatures() {
        let private_key1 = [1u8; 32];
        let private_key2 = [2u8; 32];
        let public_key_coords1 = cheetah_pub_from_sk(private_key1);
        let public_key_coords2 = cheetah_pub_from_sk(private_key2);
        let hash = Hash { values: [1, 2, 3, 4, 5] };
        
        let signature1 = schnorr_sign_txid(private_key1, public_key_coords1, hash.clone());
        let signature2 = schnorr_sign_txid(private_key2, public_key_coords2, hash);
        
        // Different keys should produce different signatures
        assert_ne!(signature1.0.values, signature2.0.values);
        assert_ne!(signature1.1.values, signature2.1.values);
    }
}