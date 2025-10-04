/// Debug multiplication step by step

fn mul_64bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
    let mut prod = [0u8; 64];

    for i in 0..32 {
        let mut carry: u16 = 0;
        let b_byte = b[31 - i] as u16;

        for j in 0..32 {
            let a_byte = a[31 - j] as u16;
            let prod_idx = 63 - (i + j);

            let temp = a_byte * b_byte + (prod[prod_idx] as u16) + carry;
            prod[prod_idx] = (temp & 0xff) as u8;
            carry = temp >> 8;
        }

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

    prod
}

#[test]
fn test_multiplication_product() {
    use num_bigint::BigUint;

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

    // Compute with BigUint to get the correct 64-byte product
    let chal_big = BigUint::from_bytes_be(&chal_be);
    let sk_big = BigUint::from_bytes_be(&sk_be);
    let prod_big = chal_big * sk_big;
    let prod_big_bytes = prod_big.to_bytes_be();

    let mut expected_prod = [0u8; 64];
    let offset = 64 - prod_big_bytes.len();
    expected_prod[offset..].copy_from_slice(&prod_big_bytes);

    println!("\nExpected 64-byte product (BigUint):");
    for i in (0..64).step_by(8) {
        println!(
            "  [{:2}..{:2}]: {:02x?}",
            i,
            i + 7,
            &expected_prod[i..i + 8]
        );
    }

    // Compute with manual implementation
    let manual_prod = mul_64bytes(&chal_be, &sk_be);

    println!("\nManual 64-byte product:");
    for i in (0..64).step_by(8) {
        println!("  [{:2}..{:2}]: {:02x?}", i, i + 7, &manual_prod[i..i + 8]);
    }

    println!("\nComparison:");
    let mut first_diff = None;
    for i in 0..64 {
        if manual_prod[i] != expected_prod[i] {
            println!(
                "  Byte {}: manual={:02x} expected={:02x}",
                i, manual_prod[i], expected_prod[i]
            );
            if first_diff.is_none() {
                first_diff = Some(i);
            }
        }
    }

    if let Some(idx) = first_diff {
        panic!("First difference at byte {}", idx);
    } else {
        println!("✓ 64-byte products match!");
    }
}
