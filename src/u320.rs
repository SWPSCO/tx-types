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
        let remainder_u64: u64 = remainder.try_into()
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