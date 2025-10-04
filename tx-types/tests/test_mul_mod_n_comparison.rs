/// Test that compares std and no-std mul_mod_n implementations
use tx_types::crypto::utils::CHEETAH_N;

// Import the std version explicitly
#[cfg(feature = "std")]
fn mul_mod_n_biguint(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    use num_bigint::BigUint;
    let a_big = BigUint::from_bytes_be(a);
    let b_big = BigUint::from_bytes_be(b);
    let n_big = BigUint::from_bytes_be(&CHEETAH_N);
    let prod_big = (a_big * b_big) % n_big;
    let prod_bytes = prod_big.to_bytes_be();
    let mut result = [0u8; 32];
    let offset = 32 - prod_bytes.len();
    result[offset..].copy_from_slice(&prod_bytes);
    result
}

// Manual implementation for comparison
fn mul_mod_n_manual(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Schoolbook multiplication: compute full 64-byte product
    let mut prod = [0u8; 64];

    // Multiply each byte of b by all of a
    for i in 0..32 {
        let mut carry: u16 = 0;
        let b_byte = b[31 - i] as u16; // Process b from LSB to MSB

        for j in 0..32 {
            let a_byte = a[31 - j] as u16; // Process a from LSB to MSB
            let prod_idx = 63 - (i + j); // Result index in prod array

            let temp = a_byte * b_byte + (prod[prod_idx] as u16) + carry;
            prod[prod_idx] = (temp & 0xff) as u8;
            carry = temp >> 8;
        }

        // Propagate remaining carry
        if carry != 0 {
            let mut idx = 63 - (i + 32);
            while carry != 0 && idx < 64 {
                let temp = (prod[idx] as u16) + carry;
                prod[idx] = (temp & 0xff) as u8;
                carry = temp >> 8;
                if idx == 0 {
                    break;
                }
                idx -= 1;
            }
        }
    }

    // Reduce modulo n
    mod_n_from_be_bytes(&prod)
}

fn mod_n_from_be_bytes(bytes_be: &[u8]) -> [u8; 32] {
    let mut rem = [0u8; 32];
    for &b in bytes_be {
        let mut carry = b as u16;
        for i in (0..32).rev() {
            let t = ((rem[i] as u16) << 8) | carry;
            rem[i] = (t & 0xff) as u8;
            carry = (t >> 8) as u16;
        }
        while !be32_lt(&rem, &CHEETAH_N) {
            be32_sub_inplace(&mut rem, &CHEETAH_N);
        }
    }
    rem
}

fn be32_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for k in 0..32 {
        if a[k] != b[k] {
            return a[k] < b[k];
        }
    }
    false
}

fn be32_sub_inplace(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut brw: i16 = 0;
    for k in (0..32).rev() {
        let v = a[k] as i16 - b[k] as i16 - brw;
        if v < 0 {
            a[k] = (v + 256) as u8;
            brw = 1;
        } else {
            a[k] = v as u8;
            brw = 0;
        }
    }
}

#[test]
fn test_compare_implementations() {
    // Known test values
    let chal_be = [
        0x1bu8, 0x6e, 0x2d, 0xba, 0xd3, 0xcb, 0xd8, 0x77, 0x9c, 0xfa, 0xb1, 0x83, 0xf0, 0xa7, 0xea,
        0xd2, 0x76, 0xe3, 0x87, 0x8e, 0xa6, 0xce, 0x47, 0xae, 0x5f, 0xba, 0xa2, 0x7d, 0xeb, 0x8c,
        0x34, 0xbb,
    ];
    let sk_be = [
        0x71u8, 0x02, 0x27, 0xad, 0x8a, 0xf1, 0x85, 0x73, 0xa5, 0x99, 0xe7, 0xdd, 0x94, 0xee, 0xe7,
        0xc1, 0xad, 0xbf, 0x10, 0xc4, 0x26, 0x1b, 0xc8, 0x8c, 0x1d, 0x5e, 0xcd, 0xa6, 0x90, 0x92,
        0x49, 0x4a,
    ];

    let expected = [
        0x2fu8, 0x19, 0x05, 0x84, 0x78, 0x33, 0x73, 0x89, 0x6d, 0x86, 0x40, 0x0d, 0xb6, 0x0c, 0x49,
        0x5d, 0xa9, 0xa2, 0xec, 0xd4, 0x79, 0x96, 0x66, 0xb1, 0x0f, 0xbf, 0x3d, 0x72, 0x43, 0xfe,
        0xf9, 0x2d,
    ];

    println!("\nTesting chal * sk:");
    println!("chal:     {:02x?}", &chal_be[..8]);
    println!("sk:       {:02x?}", &sk_be[..8]);
    println!("expected: {:02x?}", &expected[..8]);

    // Test manual implementation
    let manual_result = mul_mod_n_manual(&chal_be, &sk_be);
    println!("\nManual result:  {:02x?}", &manual_result[..8]);
    println!("Full manual:    {:02x?}", manual_result);

    #[cfg(feature = "std")]
    {
        let biguint_result = mul_mod_n_biguint(&chal_be, &sk_be);
        println!("\nBigUint result: {:02x?}", &biguint_result[..8]);
        println!("Full BigUint:   {:02x?}", biguint_result);

        if manual_result != biguint_result {
            println!("\n❌ MISMATCH between manual and BigUint!");
            for i in 0..32 {
                if manual_result[i] != biguint_result[i] {
                    println!(
                        "  Byte {}: manual={:02x} biguint={:02x}",
                        i, manual_result[i], biguint_result[i]
                    );
                }
            }
            panic!("Manual and BigUint implementations differ!");
        } else {
            println!("\n✓ Manual matches BigUint");
        }
    }

    assert_eq!(
        manual_result, expected,
        "Manual implementation should match expected"
    );
}

#[test]
fn test_simple_multiplication() {
    // Test with small numbers to verify basic logic
    let a = {
        let mut arr = [0u8; 32];
        arr[31] = 5; // a = 5
        arr
    };
    let b = {
        let mut arr = [0u8; 32];
        arr[31] = 7; // b = 7
        arr
    };

    let manual_result = mul_mod_n_manual(&a, &b);

    #[cfg(feature = "std")]
    {
        let biguint_result = mul_mod_n_biguint(&a, &b);
        println!("\nSimple test: 5 * 7");
        println!("Manual:  {:02x?}", &manual_result[28..]);
        println!("BigUint: {:02x?}", &biguint_result[28..]);
        assert_eq!(manual_result, biguint_result, "5 * 7 should match");
    }

    // Expected: 5 * 7 = 35 = 0x23
    assert_eq!(manual_result[31], 0x23, "5 * 7 = 35 (0x23)");
}
