use crate::crypto::cheetah::point::{cheetah_order, CheetahPoint};
use crate::crypto::{CryptoError, Result};
use crate::transaction_types::SchnorrPubkey;
/// Extended key structure and child key derivation
use hmac::{Hmac, Mac};
use ibig::UBig;
use num_traits::Zero;
use sha2::Sha512;
use zeroize::Zeroize;
use bs58;
use std::convert::TryInto;

type HmacSha512 = Hmac<Sha512>;

/// Prefix constants used to match the Hoon `serialize-extended` arm.
const ZPRV_TYPE: u32 = 0x0110_6331;
const ZPUB_TYPE: u32 = 0x0c0e_bb09;
const PRIVATE_KEY_TAG: u8 = 0x00;
const PUBLIC_KEY_TAG: u8 = 0x01;

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
    pub version: u8,
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
            version: 0,
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
            version: 0,
        }
    }

    pub fn from_extended_key_string(key: &str) -> Result<Self> {
        let (key_size, is_private) = {
            let prefix: String = key.chars().take(4).collect();
            match prefix.as_str() {
                "zprv" => (33, true),
                "zpub" => (97, false),
                _ => return Err(CryptoError::InvalidExtendedKeyString),
            }
        };

        let payload = bs58::decode(key)
            .with_check(None)
            .into_vec()
            .map_err(|e| CryptoError::Base58DecodeError(e.to_string()))?;

        let version = if payload.len() >= (key_size + 46) {
            cut(&payload, key_size + 41, 1)?[0]
        } else {
            0
        };

        //  metadata layout: [key-data][chain-code][index][parent-fp][depth][ver][typ]

        // (cut 3 [(add key-size 40) 1] payload)
        let depth = cut(&payload, key_size + 40, 1)?[0];

        // (cut 3 [(add key-size 36) 4] payload)
        let parent_fingerprint = slice_to_array::<4>(cut(&payload, key_size + 36, 4)?)?;

        // (cut 3 [(add key-size 32) 4] payload)
        let index = u32::from_be_bytes(slice_to_array::<4>(cut(&payload, key_size + 32, 4)?)?);

        // (cut 3 [key-size 32] payload)
        let chain_code = slice_to_array::<32>(cut(&payload, key_size, 32)?)?;

        // (cut 3 [0 key-size] payload)
        let key_data = cut(&payload, 0, key_size)?.to_vec();

        let private_key = if is_private {
            Some(slice_to_array::<32>(cut(&key_data, 0, 32)?)?)
        } else {
            None
        };

        let public_key = if let Some(ref sk) = private_key {
            CheetahPoint::from_private_key(sk)
        } else {
            CheetahPoint::from_public_key_bytes(&key_data)?
        };

        Ok(ExtendedKey {
            private_key,
            public_key,
            chain_code,
            depth,
            index,
            parent_fingerprint,
            version,
        })
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

        // Prepare base HMAC input
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

        // SLIP-10 retry logic: if IL is invalid (zero or >= curve_order), retry with hash of previous output
        const MAX_RETRIES: u32 = 100;
        let mut current_input = hmac_input.clone();
        let (il, ir, il_int) = loop {
            // Compute HMAC-SHA512
            let mut mac = HmacSha512::new_from_slice(&self.chain_code)
                .map_err(|_| CryptoError::DerivationFailed)?;
            mac.update(&current_input);
            let i = mac.finalize().into_bytes();

            // Split result
            let mut il_temp = [0u8; 32];
            let mut ir_temp = [0u8; 32];
            il_temp.copy_from_slice(&i[..32]);
            ir_temp.copy_from_slice(&i[32..]);

            // Check if il is valid
            let il_int_temp = UBig::from_be_bytes(&il_temp);
            if !il_int_temp.is_zero() && il_int_temp < n {
                // Valid IL found
                break (il_temp, ir_temp, il_int_temp);
            }

            // Invalid IL, retry per SLIP-10: use I (the entire 64-byte HMAC output) as new input
            if current_input.len() >= MAX_RETRIES as usize * 64 {
                // Safety limit to prevent infinite loops
                return Err(CryptoError::DerivationFailed);
            }
            current_input = i.to_vec();
        };

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
            version: 0,
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

    /// convert into zpub bs58 string
    pub fn to_zpub_string(&self) -> Result<String> {
        let mut payload = Vec::with_capacity(4 + 1 + 1 + 4 + 4 + 32 + 97);
        payload.extend_from_slice(&ZPUB_TYPE.to_be_bytes());
        payload.push(self.version);
        payload.push(self.depth);
        payload.extend_from_slice(&self.parent_fingerprint);
        payload.extend_from_slice(&self.index.to_be_bytes());
        payload.extend_from_slice(&self.chain_code);

        let coords = self.public_key.to_coordinates();
        let x_coords = coords[0];
        let y_coords = coords[1];

        payload.push(PUBLIC_KEY_TAG);
        for limb in y_coords.into_iter().rev() {
            payload.extend_from_slice(&limb.to_be_bytes());
        }
        for limb in x_coords.into_iter().rev() {
            payload.extend_from_slice(&limb.to_be_bytes());
        }

        Ok(bs58::encode(payload).with_check().into_string())
    }

    pub fn to_zprv_string(&self) -> Result<String> {
        let private_key = self
            .private_key
            .ok_or(CryptoError::InvalidPrivateKey)?;

        let mut payload = Vec::with_capacity(4 + 1 + 1 + 4 + 4 + 32 + 33);
        payload.extend_from_slice(&ZPRV_TYPE.to_be_bytes());
        payload.push(self.version);
        payload.push(self.depth);
        payload.extend_from_slice(&self.parent_fingerprint);
        payload.extend_from_slice(&self.index.to_be_bytes());
        payload.extend_from_slice(&self.chain_code);
        payload.push(PRIVATE_KEY_TAG);
        payload.extend_from_slice(&private_key);

        Ok(bs58::encode(payload).with_check().into_string())
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

fn slice_to_array<const N: usize>(slice: &[u8]) -> Result<[u8; N]> {
    slice
        .try_into()
        .map_err(|_| CryptoError::InvalidExtendedKeyString)
}

// Cut helper
fn cut<'a>(payload: &'a [u8], offset_from_end: usize, len: usize) -> Result<&'a [u8]> {
  let total = payload.len();
  let start = total
      .checked_sub(offset_from_end + len)
      .ok_or(CryptoError::Other("failed to cut payload".to_string()))?;
  let end = start + len;
  Ok(&payload[start..end])
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

    #[test]
    fn test_zkey_serialization_roundtrip() {
        // Known-good vectors from nockchain_zorp/scripts/fakenet-wallet-0.txt
        let zprv = concat!(
            "zprvLxxkCBq3s5HYzjsmivdvYRD8KtW3cbuwDtAPmpZvFQyicQzWqKCL9sQpna2x",
            "4vgmNBF3cw1urezrhA7MNMbVVRt5GeXrBdg4qQ8QpKBt92Re"
        );
        let zpub = concat!(
            "zpub2kRJ7D6VCvzVfDgydtAWpzxgDR7dQyJnmfEuwVM9LS7oJFb1vb7gTSBrfMvZ",
            "X8dTs73sYq2UMGTYJg5kEgVZh23xiU7CWhW4Gkqztq8G856akEgyafdddnu6aKEqt",
            "i2t9jufYWDR1Mj9RCo62bMNAyegCxNGShqexbhnMwGudSqwSNgDpgxzRU7gvUxioS",
            "JyGtMW"
        );

        let private_key = ExtendedKey::from_extended_key_string(zprv).unwrap();
        assert_eq!(private_key.to_zprv_string().unwrap(), zprv);
        assert_eq!(private_key.to_zpub_string().unwrap(), zpub);

        let public_key = ExtendedKey::from_extended_key_string(zpub).unwrap();
        assert!(public_key.private_key.is_none());
        assert_eq!(public_key.to_zpub_string().unwrap(), zpub);
    }
}
