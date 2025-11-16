use super::derive::ExtendedKey;
use crate::crypto::{CryptoError, Result};
use bip39::{Language, Mnemonic};

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

pub fn master_from_seed(seed: &[u8]) -> Result<ExtendedKey> {
    ExtendedKey::from_seed(seed, 0)
}

/// Generate master key from BIP39 mnemonic
pub fn master_from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<ExtendedKey> {
    let seed = bip39_to_seed(mnemonic, passphrase)?;
    ExtendedKey::from_seed(&seed, 0)
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
