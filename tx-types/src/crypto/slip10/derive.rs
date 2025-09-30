/// Extended key structure and child key derivation
use hmac::{Hmac, Mac};
use sha2::Sha512;
use ibig::UBig;
use num_traits::Zero;
use zeroize::Zeroize;
use crate::crypto::cheetah::point::{CheetahPoint, cheetah_order};
use crate::crypto::{CryptoError, Result};
use crate::transaction_types::SchnorrPubkey;

type HmacSha512 = Hmac<Sha512>;

/// Errors that can occur during key derivation
#[derive(Debug, Clone)]
pub enum DerivationError {
    InvalidIndex,
    InvalidKey,
    HmacError,
}

impl std::fmt::Display for DerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DerivationError::InvalidIndex => write!(f, "Invalid derivation index"),
            DerivationError::InvalidKey => write!(f, "Invalid key during derivation"),
            DerivationError::HmacError => write!(f, "HMAC error during derivation"),
        }
    }
}

impl std::error::Error for DerivationError {}

/// Extended key for hierarchical deterministic key derivation
#[derive(Clone)]
pub struct ExtendedKey {
    pub private_key: Option<[u8; 32]>,
    pub public_key: CheetahPoint,
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub index: u32,
    pub parent_fingerprint: [u8; 4],
}

impl ExtendedKey {
    /// Create a new master key
    pub fn new_master(private_key: [u8; 32], chain_code: [u8; 32]) -> Self {
        let public_key = CheetahPoint::from_private_key(&private_key);
        
        ExtendedKey {
            private_key: Some(private_key),
            public_key,
            chain_code,
            depth: 0,
            index: 0,
            parent_fingerprint: [0u8; 4],
        }
    }
    
    /// Create extended key from just a private key
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let public_key = CheetahPoint::from_private_key(&private_key);
        
        ExtendedKey {
            private_key: Some(private_key),
            public_key,
            chain_code: [0u8; 32], // No chain code for raw keys
            depth: 0,
            index: 0,
            parent_fingerprint: [0u8; 4],
        }
    }
    
    /// Check if this is a hardened derivation index
    fn is_hardened(index: u32) -> bool {
        index >= (1 << 31)
    }
    
    /// Serialize a 32-bit integer as big-endian bytes
    fn serialize_u32(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }
    
    /// Derive a child key at the given index
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        let n = cheetah_order();
        
        if self.private_key.is_none() && Self::is_hardened(index) {
            return Err(CryptoError::DerivationFailed);
        }
        
        // Prepare HMAC input
        let mut hmac_input = Vec::with_capacity(37);
        
        if Self::is_hardened(index) {
            // Hardened derivation: HMAC(chain_code, 0x00 || private_key || index)
            hmac_input.push(0x00);
            hmac_input.extend_from_slice(&self.private_key.unwrap());
        } else {
            // Non-hardened derivation: HMAC(chain_code, public_key || index)
            let pubkey_coords = self.public_key.to_coordinates();
            // Serialize public key (simplified - would need proper compression in real implementation)
            for coord in &pubkey_coords {
                for &limb in coord {
                    hmac_input.extend_from_slice(&limb.to_be_bytes());
                }
            }
        }
        hmac_input.extend_from_slice(&Self::serialize_u32(index));
        
        // Compute HMAC-SHA512
        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
            .map_err(|_| CryptoError::DerivationFailed)?;
        mac.update(&hmac_input);
        let i = mac.finalize().into_bytes();
        
        // Split result
        let mut il = [0u8; 32];
        let mut ir = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        ir.copy_from_slice(&i[32..]);
        
        // Check if il is valid
        let il_int = UBig::from_be_bytes(&il);
        if il_int.is_zero() || il_int >= n {
            return Err(CryptoError::DerivationFailed);
        }
        
        // Derive child private key if parent has private key
        let child_private_key = if let Some(parent_private) = self.private_key {
            let parent_sk = UBig::from_be_bytes(&parent_private);
            let child_sk = (il_int.clone() + parent_sk) % &n;
            
            if child_sk.is_zero() {
                return Err(CryptoError::DerivationFailed);
            }
            
            let mut child_sk_bytes = [0u8; 32];
            let sk_bytes = child_sk.to_be_bytes();
            if sk_bytes.len() <= 32 {
                child_sk_bytes[32 - sk_bytes.len()..].copy_from_slice(&sk_bytes);
            } else {
                child_sk_bytes.copy_from_slice(&sk_bytes[sk_bytes.len() - 32..]);
            }
            
            Some(child_sk_bytes)
        } else {
            None
        };
        
        // Derive child public key
        let child_public_key = if let Some(child_sk) = child_private_key {
            CheetahPoint::from_private_key(&child_sk)
        } else {
            // Public key derivation: parent_pubkey + il*G
            let il_point = CheetahPoint::generator().scalar_mul(&il_int);
            self.public_key.add(&il_point)
        };
        
        // Compute parent fingerprint (simplified)
        let parent_fingerprint = [0u8; 4]; // TODO: Implement proper fingerprinting
        
        Ok(ExtendedKey {
            private_key: child_private_key,
            public_key: child_public_key,
            chain_code: ir,
            depth: self.depth.saturating_add(1),
            index,
            parent_fingerprint,
        })
    }
    
    /// Derive a key at the given derivation path
    pub fn derive_path(&self, path: &[u32]) -> Result<Self> {
        let mut current = self.clone();
        for &index in path {
            current = current.derive_child(index)?;
        }
        Ok(current)
    }
    
    /// Convert to SchnorrPubkey format
    pub fn to_schnorr_pubkey(&self) -> SchnorrPubkey {
        self.public_key.to_schnorr_pubkey()
    }
    
    /// Get the private key if available
    pub fn private_key_bytes(&self) -> Option<[u8; 32]> {
        self.private_key
    }
}

impl Zeroize for ExtendedKey {
    fn zeroize(&mut self) {
        if let Some(ref mut sk) = self.private_key {
            sk.zeroize();
        }
        self.chain_code.zeroize();
    }
}

impl Drop for ExtendedKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hardened_derivation() {
        let master_sk = [1u8; 32];
        let chain_code = [2u8; 32];
        let master = ExtendedKey::new_master(master_sk, chain_code);
        
        // Test hardened derivation
        let child = master.derive_child(0x80000000).unwrap();
        assert_eq!(child.depth, 1);
        assert_eq!(child.index, 0x80000000);
        assert!(child.private_key.is_some());
    }
    
    #[test]
    fn test_normal_derivation() {
        let master_sk = [1u8; 32];
        let chain_code = [2u8; 32];
        let master = ExtendedKey::new_master(master_sk, chain_code);
        
        // Test normal derivation
        let child = master.derive_child(0).unwrap();
        assert_eq!(child.depth, 1);
        assert_eq!(child.index, 0);
        assert!(child.private_key.is_some());
    }
    
    #[test]
    fn test_derivation_path() {
        let master_sk = [1u8; 32];
        let chain_code = [2u8; 32];
        let master = ExtendedKey::new_master(master_sk, chain_code);
        
        // Test path derivation: m/44'/0'/0'/0/0
        let path = [0x8000002C, 0x80000000, 0x80000000, 0, 0];
        let derived = master.derive_path(&path).unwrap();
        assert_eq!(derived.depth, 5);
    }
}