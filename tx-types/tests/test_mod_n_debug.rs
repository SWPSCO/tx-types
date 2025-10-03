/// Debug mod_n_from_be_bytes step by step

use tx_types::crypto::utils::CHEETAH_N;

fn mod_n_debug(bytes_be: &[u8]) -> [u8; 32] {
    let mut rem = [0u8; 32];

    println!("\nProcessing {} bytes", bytes_be.len());
    println!("CHEETAH_N: {:02x?}...", &CHEETAH_N[..8]);

    for (byte_idx, &b) in bytes_be.iter().enumerate() {
        if byte_idx < 5 || byte_idx >= bytes_be.len() - 5 {
            println!("\n--- Byte {} (0x{:02x}) ---", byte_idx, b);
        }

        let mut carry = b as u16;
        for i in (0..32).rev() {
            let t = ((rem[i] as u16) << 8) | carry;
            rem[i] = (t & 0xff) as u8;
            carry = (t >> 8) as u16;
        }

        if byte_idx < 5 || byte_idx >= bytes_be.len() - 5 {
            println!("After shift+add: {:02x?}...", &rem[..8]);
        }

        let mut sub_count = 0;
        while !be32_lt(&rem, &CHEETAH_N) {
            be32_sub_inplace(&mut rem, &CHEETAH_N);
            sub_count += 1;
            if sub_count > 10 {
                println!("ERROR: Too many subtractions at byte {}!", byte_idx);
                break;
            }
        }

        if byte_idx < 5 || byte_idx >= bytes_be.len() - 5 {
            if sub_count > 0 {
                println!("After {} subtractions: {:02x?}...", sub_count, &rem[..8]);
            }
        }
    }

    println!("\nFinal result: {:02x?}", rem);
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
fn test_mod_n_with_debug() {
    use num_bigint::BigUint;

    // The 64-byte product
    let prod_64 = [
        0x0c, 0x1b, 0xdd, 0x4c, 0x34, 0x42, 0x45, 0x56,
        0x11, 0x01, 0xc5, 0xc8, 0x1e, 0x7a, 0xb0, 0x38,
        0xe3, 0x33, 0x6b, 0x97, 0x0b, 0x26, 0x41, 0x79,
        0xd3, 0x37, 0x59, 0x54, 0x8e, 0xa7, 0x33, 0x1c,
        0x6b, 0x6e, 0xd8, 0xb5, 0x1b, 0x70, 0x40, 0x1b,
        0x69, 0xab, 0x6b, 0x35, 0x51, 0x7d, 0xeb, 0xff,
        0x07, 0x0f, 0x63, 0x1a, 0x22, 0x04, 0x86, 0x89,
        0xf3, 0x66, 0x04, 0x72, 0x54, 0x36, 0x91, 0x0e,
    ];

    let prod_big = BigUint::from_bytes_be(&prod_64);
    let n_big = BigUint::from_bytes_be(&CHEETAH_N);
    let expected_big = prod_big % n_big;
    let expected_bytes = expected_big.to_bytes_be();
    let mut expected = [0u8; 32];
    let offset = 32 - expected_bytes.len();
    expected[offset..].copy_from_slice(&expected_bytes);

    println!("Expected: {:02x?}", expected);

    let manual_result = mod_n_debug(&prod_64);

    assert_eq!(manual_result, expected);
}
