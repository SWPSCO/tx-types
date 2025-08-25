#[cfg(test)]
mod tests {
    use super::super::u320::U320;
    use super::super::transaction_types::Hash;

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