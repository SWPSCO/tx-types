/// Conversion utilities between different numeric representations
use ibig::UBig;
use crate::transaction_types::T8;

/// Error types for conversions
#[derive(Debug, Clone)]
pub enum ConversionError {
    InvalidSize,
    InvalidFormat,
}

impl std::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConversionError::InvalidSize => write!(f, "Invalid size for conversion"),
            ConversionError::InvalidFormat => write!(f, "Invalid format for conversion"),
        }
    }
}

impl std::error::Error for ConversionError {}

/// Trait for UBig extensions
pub trait UBigExt {
    fn to_t8(&self) -> T8;
    fn from_t8(t8: &T8) -> Result<UBig, ConversionError>;
}

impl UBigExt for UBig {
    /// Convert UBig to T8 format (8 limbs, little-endian by limb)
    fn to_t8(&self) -> T8 {
        let mut be_bytes = self.to_be_bytes();
        
        // Pad or truncate to 64 bytes (8 * 8)
        if be_bytes.len() < 64 {
            let mut padded = vec![0u8; 64 - be_bytes.len()];
            padded.extend_from_slice(&be_bytes);
            be_bytes = padded;
        } else if be_bytes.len() > 64 {
            be_bytes = be_bytes[be_bytes.len() - 64..].to_vec();
        }
        
        // Convert to 8 limbs (little-endian by limb)
        let mut limbs = [0u64; 8];
        for i in 0..8 {
            let start = 64 - (i + 1) * 8;
            let end = start + 8;
            limbs[i] = u64::from_be_bytes(
                be_bytes[start..end].try_into().expect("Slice is exactly 8 bytes")
            );
        }
        
        T8 { values: limbs }
    }
    
    /// Convert T8 to UBig
    fn from_t8(t8: &T8) -> Result<UBig, ConversionError> {
        let mut bytes = Vec::with_capacity(64);
        
        // Convert limbs to big-endian bytes (reverse limb order)
        for i in (0..8).rev() {
            bytes.extend_from_slice(&t8.values[i].to_be_bytes());
        }
        
        Ok(UBig::from_be_bytes(&bytes))
    }
}

/// Trait for T8 conversions
pub trait T8Conversion {
    fn to_ubig(&self) -> UBig;
    fn from_ubig(value: &UBig) -> Self;
}

impl T8Conversion for T8 {
    fn to_ubig(&self) -> UBig {
        UBig::from_t8(self).expect("T8 should always convert to UBig")
    }
    
    fn from_ubig(value: &UBig) -> Self {
        value.to_t8()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ubig_to_t8_roundtrip() {
        let original = UBig::from(0x123456789ABCDEFu64);
        let t8 = original.to_t8();
        let recovered = UBig::from_t8(&t8).unwrap();
        assert_eq!(original, recovered);
    }
    
    #[test]
    fn test_t8_conversion_trait() {
        let original = UBig::from(0xDEADBEEFu64);
        let t8 = T8::from_ubig(&original);
        let recovered = t8.to_ubig();
        assert_eq!(original, recovered);
    }
    
    #[test]
    fn test_zero_conversion() {
        let zero = UBig::from(0u32);
        let t8 = zero.to_t8();
        assert_eq!(t8.values, [0; 8]);
        
        let recovered = UBig::from_t8(&t8).unwrap();
        assert_eq!(zero, recovered);
    }
    
    #[test]
    fn test_large_number_conversion() {
        let large = UBig::from_str_radix("123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", 16).unwrap();
        let t8 = large.to_t8();
        let recovered = UBig::from_t8(&t8).unwrap();
        assert_eq!(large, recovered);
    }
}