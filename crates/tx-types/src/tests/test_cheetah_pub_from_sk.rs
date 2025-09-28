#[cfg(test)]
mod tests {
    use crate::crypto::cheetah::point::cheetah_pub_from_sk;

    #[test]
    fn test_cheetah_pub_from_sk_with_hoon_nonce() {
        // Nonce from Hoon: 0x1234567889abcdef0
        // This is 1,311,768,467,463,790,320 in decimal
        let nonce_bytes: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
        ];

        // Compute R = nonce * G
        let r_point = cheetah_pub_from_sk(nonce_bytes);

        // Expected R point from Hoon (nonce * G):
        // x coordinates:
        let expected_x = [
            678_997_345_617_046_851_u64,   // a0
            6_697_805_442_650_263_525_u64, // a1
            1_219_428_187_040_437_072_u64, // a2
            13_925_251_561_750_205_601_u64, // a3
            6_134_071_847_530_906_636_u64, // a4
            3_388_581_844_409_087_717_u64, // a5
        ];

        // y coordinates:
        let expected_y = [
            8_501_901_520_710_382_098_u64, // a0
            809_534_324_898_488_325_u64,   // a1
            12_309_604_365_482_580_624_u64, // a2
            8_991_226_617_439_460_612_u64, // a3
            8_968_514_865_132_259_927_u64, // a4
            1_312_822_166_383_931_109_u64, // a5
        ];

        // Verify x coordinates match
        for i in 0..6 {
            assert_eq!(
                r_point[0][i], expected_x[i],
                "X coordinate mismatch at index {}: got {}, expected {}",
                i, r_point[0][i], expected_x[i]
            );
        }

        // Verify y coordinates match
        for i in 0..6 {
            assert_eq!(
                r_point[1][i], expected_y[i],
                "Y coordinate mismatch at index {}: got {}, expected {}",
                i, r_point[1][i], expected_y[i]
            );
        }

        println!("✓ cheetah_pub_from_sk correctly computed R = nonce * G");
        println!("  Nonce: 0x1234567889abcdef0");
        println!("  R.x: {:?}", r_point[0]);
        println!("  R.y: {:?}", r_point[1]);
    }
}