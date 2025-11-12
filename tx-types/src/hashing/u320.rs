use anyhow::{anyhow, Result};
use bs58;
use num_bigint::BigUint;

/// A 320-bit unsigned integer type for handling TIP5 hash operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U320 {
    inner: BigUint,
}

impl U320 {
    const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

    /// Create U320 from base58 string
    pub fn from_base58(b58_str: &str) -> Result<Self> {
        let bytes = bs58::decode(b58_str)
            .into_vec()
            .map_err(|e| anyhow!("Invalid base58: {}", e))?;

        let inner = BigUint::from_bytes_be(&bytes);
        Ok(U320 { inner })
    }

    /// Divide by the Goldilocks prime, returning (quotient, remainder)
    pub fn divrem_p(&self) -> (U320, u64) {
        let p = BigUint::from(Self::GOLDILOCKS_PRIME);
        let quotient = &self.inner / &p;
        let remainder = &self.inner % &p;

        // Convert remainder to u64 - it must fit since it's mod p
        let remainder_u64: u64 = remainder
            .try_into()
            .expect("Remainder mod Goldilocks prime should fit in u64");

        (U320 { inner: quotient }, remainder_u64)
    }

    /// Convert to a single u64 if possible
    pub fn as_single_u64(&self) -> Result<u64> {
        (&self.inner)
            .try_into()
            .map_err(|_| anyhow!("Value too large to fit in u64"))
    }
}

#[cfg(test)]
mod tests {
    use super::U320;
    use crate::transaction_types::Hash;

    #[test]
    fn test_u320_from_b58_basic() {
        // Test with a known base58 string
        let b58 = "HvGNkunXfn3KZ8HLVsEmBrweZf7c6c51g6Vsc73N1hs4";
        let hash = Hash::from_b58(b58).unwrap();

        // Should successfully decode
        assert_eq!(hash.values.len(), 5);

        // Round-trip test
        let b58_back = hash.to_b58();
        assert_eq!(b58, b58_back);
    }

    #[test]
    fn test_u320_handles_large_values() {
        // Create a hash with maximum valid values
        let hash = Hash {
            values: [
                0xFFFF_FFFF_0000_0000, // Just under Goldilocks prime
                0xFFFF_FFFF_0000_0000,
                0xFFFF_FFFF_0000_0000,
                0xFFFF_FFFF_0000_0000,
                1000, // Small e value
            ],
        };

        let b58 = hash.to_b58();
        let hash_back = Hash::from_b58(&b58).unwrap();
        assert_eq!(hash.values, hash_back.values);
    }

    #[test]
    fn test_u320_rejects_too_large() {
        // Create a very large base58 string that would overflow
        // This should be rejected by the new implementation
        let huge_bytes = vec![0xFF; 100]; // 100 bytes of 0xFF
        let huge_b58 = bs58::encode(huge_bytes).into_string();

        let result = Hash::from_b58(&huge_b58);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }
}
