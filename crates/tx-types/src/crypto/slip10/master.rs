/// Master key derivation from seed using SLIP-10 with Nockchain modifications
use hmac::{Hmac, Mac};
use sha2::Sha512;
use ibig::UBig;
use num_traits::Zero;
use bip39::{Mnemonic, Language};
use pbkdf2::pbkdf2;
use crate::crypto::cheetah::constants::group_order;
use crate::crypto::{CryptoError, Result};
use super::derive::ExtendedKey;

type HmacSha512 = Hmac<Sha512>;

/// Nockchain-specific HMAC key for SLIP-10 derivation
pub const NOCKCHAIN_SLIP10_KEY: &[u8] = b"Nockchain seed";

/// Convert BIP39 mnemonic to 512-bit seed using PBKDF2
pub fn bip39_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    // Parse and validate mnemonic
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|e| CryptoError::Bip39Error(e.to_string()))?;
    
    // Generate seed using BIP39 standard
    let seed = mnemonic.to_seed(passphrase);
    
    // Convert to fixed-size array
    let mut result = [0u8; 64];
    result.copy_from_slice(&seed[..64]);
    Ok(result)
}

/// Generate master key from seed using Nockchain SLIP-10 variant
/// 
/// This follows the SLIP-10 standard but with Nockchain-specific modifications:
/// 1. Uses "Nockchain seed" as HMAC key
/// 2. Implements retry logic for invalid private keys
/// 3. Returns (private_key, chain_code)
pub fn master_from_seed(seed: &[u8]) -> Result<ExtendedKey> {
    let n = group_order();
    
    // First derivation attempt
    let mut mac = HmacSha512::new_from_slice(NOCKCHAIN_SLIP10_KEY)
        .map_err(|_| CryptoError::InvalidSeed)?;
    mac.update(seed);
    let mut i = mac.finalize().into_bytes().to_vec();
    
    loop {
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        left.copy_from_slice(&i[..32]);
        right.copy_from_slice(&i[32..]);
        
        let sk = UBig::from_be_bytes(&left);
        if !sk.is_zero() && sk < n {
            // Valid private key found
            return Ok(ExtendedKey::new_master(left, right));
        }
        
        // Retry by rehashing the full 64-byte digest
        let mut mac = HmacSha512::new_from_slice(NOCKCHAIN_SLIP10_KEY)
            .map_err(|_| CryptoError::InvalidSeed)?;
        mac.update(&i);
        i = mac.finalize().into_bytes().to_vec();
    }
}

/// Generate master key from BIP39 mnemonic
pub fn master_from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<ExtendedKey> {
    let seed = bip39_to_seed(mnemonic, passphrase)?;
    master_from_seed(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_master_from_seed() {
        let seed = [1u8; 32];
        let master = master_from_seed(&seed).unwrap();
        assert!(master.private_key.is_some());
        assert_eq!(master.depth, 0);
        assert_eq!(master.index, 0);
    }
    
    #[test]
    fn test_bip39_seed_generation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = bip39_to_seed(mnemonic, "").unwrap();
        assert_eq!(seed.len(), 64);
    }
    
    #[test]
    fn test_master_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let master = master_from_mnemonic(mnemonic, "").unwrap();
        assert!(master.private_key.is_some());
    }
}