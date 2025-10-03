/// Test the reduction function with debug output

use tx_types::crypto::utils::CHEETAH_N;

#[test]
fn test_simple_reduce() {
    use num_bigint::BigUint;

    // Simple test: reduce 2*n
    let n_big = BigUint::from_bytes_be(&CHEETAH_N);
    let two_n_big = &n_big * 2u32;
    let two_n_bytes = two_n_big.to_bytes_be();

    println!("\n2*n = {:02x?}...", &two_n_bytes[..16]);
    println!("Expected (2*n mod n) = 0");

    // Pad to 64 bytes
    let mut two_n_64 = [0u8; 64];
    let offset = 64 - two_n_bytes.len();
    two_n_64[offset..].copy_from_slice(&two_n_bytes);

    println!("As 64 bytes: {:02x?}...", &two_n_64[..16]);

    // The actual product from our test
    let prod_64 = [
        0x0c, 0x1b, 0xdd, 0x4c, 0x34, 0x42, 0x45, 0x56,
        0x11, 0x01, 0xc5, 0xc8, 0x1e, 0x7a, 0xb0, 0x38,
        0xe3, 0x33, 0x6b, 0x97, 0x0b, 0x26, 0x41, 0x79,
        0xd3, 0x37, 0x59, 0x54, 0x8e, 0xa7, 0x33, 0x1c,
        0x6b, 0x6e, 0xd8, 0xb5, 0x1b, 70, 0x40, 0x1b,
        0x69, 0xab, 0x6b, 0x35, 0x51, 0x7d, 0xeb, 0xff,
        0x07, 0x0f, 0x63, 0x1a, 0x22, 0x04, 0x86, 0x89,
        0xf3, 0x66, 0x04, 0x72, 0x54, 0x36, 0x91, 0x0e,
    ];

    let prod_big = BigUint::from_bytes_be(&prod_64);
    let expected_big = &prod_big % &n_big;
    let expected_bytes = expected_big.to_bytes_be();
    let mut expected = [0u8; 32];
    let exp_offset = 32 - expected_bytes.len();
    expected[exp_offset..].copy_from_slice(&expected_bytes);

    println!("\nActual test case:");
    println!("prod_64:  {:02x?}...", &prod_64[..16]);
    println!("Expected: {:02x?}", expected);

    // Try dividing to see quotient and remainder
    let quotient = &prod_big / &n_big;
    let remainder = &prod_big % &n_big;

    println!("\nprod_64 = quotient * n + remainder");
    println!("quotient  = {}", quotient);
    println!("remainder = {:02x?}", remainder.to_bytes_be());

    // Check: quotient should be small (< 2^256 / n)
    println!("\nQuotient size: {} bits", quotient.bits());
    println!("n size: {} bits", n_big.bits());
}
