/// RFC6979 deterministic nonce generation for Schnorr signatures
use hmac::{Hmac, Mac};
use sha2::Sha256;
use ibig::UBig;
use num_traits::Zero;

type HmacSha256 = Hmac<Sha256>;

/// Generate deterministic nonce using RFC6979 with HMAC-SHA256
/// 
/// This implements Section 3.2 of RFC6979 for deterministic ECDSA/Schnorr nonces.
/// We use SHA-256 instead of SHA-512 to match the siger-esp implementation.
pub fn generate_nonce(private_key: &[u8; 32], message: &[u8], curve_order: &UBig) -> UBig {
    // Initialize V and K according to RFC6979
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];
    
    // K = HMAC(K, V || 0x00 || private_key || message)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key length is valid");
    mac.update(&v);
    mac.update(&[0x00]);
    mac.update(private_key);
    mac.update(message);
    k.copy_from_slice(&mac.finalize().into_bytes());
    
    // V = HMAC(K, V)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key length is valid");
    mac.update(&v);
    v.copy_from_slice(&mac.finalize().into_bytes());
    
    // K = HMAC(K, V || 0x01 || private_key || message)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key length is valid");
    mac.update(&v);
    mac.update(&[0x01]);
    mac.update(private_key);
    mac.update(message);
    k.copy_from_slice(&mac.finalize().into_bytes());
    
    // V = HMAC(K, V)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key length is valid");
    mac.update(&v);
    v.copy_from_slice(&mac.finalize().into_bytes());
    
    // Generate candidate nonces until we find a valid one
    loop {
        // T = HMAC(K, V)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key length is valid");
        mac.update(&v);
        let t = mac.finalize().into_bytes();
        
        // Convert to integer and check if valid
        let candidate = UBig::from_be_bytes(&t) % curve_order;
        if !candidate.is_zero() {
            return candidate;
        }
        
        // Update K and V for next iteration
        // K = HMAC(K, V || 0x00)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key length is valid");
        mac.update(&v);
        mac.update(&[0x00]);
        k.copy_from_slice(&mac.finalize().into_bytes());
        
        // V = HMAC(K, V)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key length is valid");
        mac.update(&v);
        v.copy_from_slice(&mac.finalize().into_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cheetah::constants::group_order;
    
    #[test]
    fn test_nonce_generation() {
        let private_key = [1u8; 32];
        let message = b"test message";
        let n = group_order();
        
        let nonce1 = generate_nonce(&private_key, message, &n);
        let nonce2 = generate_nonce(&private_key, message, &n);
        
        // Should be deterministic
        assert_eq!(nonce1, nonce2);
        
        // Should be non-zero and less than order
        assert!(!nonce1.is_zero());
        assert!(nonce1 < n);
    }
    
    #[test]
    fn test_different_messages_different_nonces() {
        let private_key = [1u8; 32];
        let n = group_order();
        
        let nonce1 = generate_nonce(&private_key, b"message1", &n);
        let nonce2 = generate_nonce(&private_key, b"message2", &n);
        
        // Different messages should produce different nonces
        assert_ne!(nonce1, nonce2);
    }
}