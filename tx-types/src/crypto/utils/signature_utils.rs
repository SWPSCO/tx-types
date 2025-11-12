/// Shared utilities for Schnorr signature operations
///
/// This module contains format conversion functions used by both
/// signing and verification operations.
use crate::transaction_types::T8;

/// Convert T8 to 32-byte big-endian array
///
/// T8 stores 8 limbs in little-endian order, each limb is 32 bits stored as u64.
/// This function converts to the big-endian byte representation used for
/// elliptic curve scalar operations.
///
/// # Arguments
/// * `t8` - The T8 value to convert
///
/// # Returns
/// * 32-byte big-endian array suitable for scalar arithmetic
///
/// # Used in Schnorr signatures:
/// - Converting secret keys for scalar multiplication
/// - Converting challenge and signature components for verification
pub fn t8_to_be32(t8: &T8) -> [u8; 32] {
    let mut result = [0u8; 32];
    // T8 stores 8 limbs in little-endian order, each limb is 32 bits
    for i in 0..8 {
        let limb = t8.values[i] as u32;
        let bytes = limb.to_le_bytes();
        // Place in big-endian position: bytes for limb i go to positions [28-4*i..32-4*i]
        for j in 0..4 {
            result[31 - (i * 4 + j)] = bytes[j];
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_t8_to_be32_conversion() {
        // Test with known T8 value
        let t8 = T8 {
            values: [
                0xbbbb_cccc, // LSW
                0x9999_aaaa,
                0x7777_8888,
                0x5555_6666,
                0x3333_4444,
                0x1111_2222,
                0x9abc_def0,
                0x1234_5678, // MSW
            ],
        };

        let be32 = t8_to_be32(&t8);

        // Verify the big-endian representation
        // MSW should be at the beginning
        assert_eq!(be32[0], 0x12);
        assert_eq!(be32[1], 0x34);
        assert_eq!(be32[2], 0x56);
        assert_eq!(be32[3], 0x78);

        // LSW should be at the end
        assert_eq!(be32[28], 0xbb);
        assert_eq!(be32[29], 0xbb);
        assert_eq!(be32[30], 0xcc);
        assert_eq!(be32[31], 0xcc);

        println!("✓ t8_to_be32 conversion works correctly");
    }
}
