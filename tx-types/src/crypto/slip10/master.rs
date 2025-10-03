use crate::crypto::cheetah::{master_from_seed as cheetah_master_from_seed, XKey};
use crate::crypto::slip10::{CryptoError, ExtendedKey, Result};

#[cfg(feature = "std")]
use bip39::{Language, Mnemonic};

/// Convert a BIP39 mnemonic to a 512-bit seed.
#[cfg(feature = "std")]
pub fn bip39_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|e| CryptoError::Bip39Error(e.to_string()))?;
    let seed = mnemonic.to_seed(passphrase);
    let mut out = [0u8; 64];
    out.copy_from_slice(&seed[..64]);
    Ok(out)
}

/// Derive the SLIP-10 master key from a BIP39 mnemonic.
#[cfg(feature = "std")]
pub fn master_from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<ExtendedKey> {
    let seed = bip39_to_seed(mnemonic, passphrase)?;
    master_from_seed(&seed)
}

/// Derive the SLIP-10 master key from a raw seed.
pub fn master_from_seed(seed: &[u8]) -> Result<ExtendedKey> {
    let (sk, chain_code) = cheetah_master_from_seed(seed);
    let xkey = XKey::from_master(sk, chain_code);
    Ok(ExtendedKey::from_xkey(xkey))
}
