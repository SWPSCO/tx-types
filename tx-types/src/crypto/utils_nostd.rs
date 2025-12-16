/// Big-endian 32-byte arithmetic operations modulo curve order (no_std version)
use crate::crypto::cheetah_nostd::T8;
use ibig::UBig;

const GOLDILOCKS_P: u64 = 0xffff_ffff_0000_0001;

/// Group order n as 32-byte big-endian
pub const CHEETAH_N: [u8; 32] = [
    0x7a, 0xf2, 0x59, 0x9b, 0x3b, 0x3f, 0x22, 0xd0, 0x56, 0x3f, 0xbf, 0x0f, 0x99, 0x0a, 0x37, 0xb5,
    0x32, 0x7a, 0xa7, 0x23, 0x30, 0x15, 0x77, 0x22, 0xd4, 0x43, 0x62, 0x3e, 0xae, 0xd4, 0xac, 0xcf,
];

#[inline]
pub fn is_zero32(x: &[u8; 32]) -> bool {
    x.iter().fold(0u8, |z, &b| z | b) == 0
}

#[inline]
pub fn be32_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for k in 0..32 {
        if a[k] != b[k] {
            return a[k] < b[k];
        }
    }
    false
}

#[inline]
pub fn sub_be32(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], u8) {
    let mut out = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let ai = a[i] as u16;
        let bi = b[i] as u16;
        let t = 256 + ai - bi - borrow;
        out[i] = (t & 0xff) as u8;
        borrow = if t >= 256 { 0 } else { 1 };
    }
    (out, borrow as u8)
}

#[inline]
pub fn add_be32(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], u8) {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let t = a[i] as u16 + b[i] as u16 + carry;
        out[i] = (t & 0xff) as u8;
        carry = t >> 8;
    }
    (out, carry as u8)
}

#[inline]
pub fn be32_sub_inplace(a: &mut [u8; 32], b: &[u8; 32]) {
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

#[inline]
pub fn add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (mut sum, carry) = be32_add(a, b);
    if carry == 1 || !be32_lt(&sum, &CHEETAH_N) {
        be32_sub_inplace(&mut sum, &CHEETAH_N);
    }
    sum
}

#[inline]
pub fn mul_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let a_big = UBig::from_be_bytes(a);
    let b_big = UBig::from_be_bytes(b);
    let n_big = UBig::from_be_bytes(&CHEETAH_N);

    let prod_big = (a_big * b_big) % n_big;

    let prod_bytes = prod_big.to_be_bytes();
    let mut result = [0u8; 32];
    if !prod_bytes.is_empty() {
        let offset = 32 - prod_bytes.len();
        result[offset..].copy_from_slice(&prod_bytes);
    }

    result
}

// Old manual implementation - no longer used
#[cfg(all(not(feature = "std"), feature = "never"))]
#[inline]
pub fn mul_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
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

    // Reduce modulo n using simple repeated subtraction
    reduce_64byte_mod_n(&prod)
}

// Old manual implementation - no longer used
#[cfg(all(not(feature = "std"), feature = "never"))]
fn reduce_64byte_mod_n(val: &[u8; 64]) -> [u8; 32] {
    // Copy the value to a mutable buffer
    let mut rem = [0u8; 64];
    rem.copy_from_slice(val);

    // Repeatedly subtract n (shifted appropriately) until rem < n
    // We need to compare the upper 32 bytes to n

    // First, reduce by subtracting n<<256, n<<248, etc. until the upper 32 bytes are zero
    for shift in (0..32).rev() {
        while be64_has_bit_set_above(&rem, 32 * 8 + shift * 8)
            || (shift == 0 && be64_upper32_gte_n(&rem))
        {
            be64_sub_n_shifted(&mut rem, shift);
        }
    }

    // Now the result fits in 32 bytes, extract it
    let mut result = [0u8; 32];
    result.copy_from_slice(&rem[32..]);

    // Final reduction: subtract n while result >= n
    while !be32_lt(&result, &CHEETAH_N) {
        be32_sub_inplace(&mut result, &CHEETAH_N);
    }

    result
}

// Old manual implementation - no longer used
#[cfg(all(not(feature = "std"), feature = "never"))]
fn be64_has_bit_set_above(val: &[u8; 64], bit_pos: usize) -> bool {
    let byte_pos = bit_pos / 8;
    if byte_pos == 0 {
        return false;
    }
    for i in 0..byte_pos {
        if val[i] != 0 {
            return true;
        }
    }
    false
}

// Old manual implementation - no longer used
#[cfg(all(not(feature = "std"), feature = "never"))]
fn be64_upper32_gte_n(val: &[u8; 64]) -> bool {
    for i in 0..32 {
        if val[i] != CHEETAH_N[i] {
            return val[i] > CHEETAH_N[i];
        }
    }
    true // Equal
}

// Old manual implementation - no longer used
#[cfg(all(not(feature = "std"), feature = "never"))]
fn be64_sub_n_shifted(val: &mut [u8; 64], shift: usize) {
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let idx = 32 + i + shift;
        if idx >= 64 {
            continue;
        }
        let v = val[idx] as i16 - CHEETAH_N[i] as i16 - borrow;
        if v < 0 {
            val[idx] = (v + 256) as u8;
            borrow = 1;
        } else {
            val[idx] = v as u8;
            borrow = 0;
        }
    }
    // Propagate borrow to higher bytes
    if borrow != 0 && shift > 0 {
        let mut idx = 32 + shift - 1;
        loop {
            let v = val[idx] as i16 - borrow;
            if v < 0 {
                val[idx] = (v + 256) as u8;
                borrow = 1;
            } else {
                val[idx] = v as u8;
                break;
            }
            if idx == 0 {
                break;
            }
            idx -= 1;
        }
    }
}

#[inline]
pub fn mod_n_from_be_bytes(bytes_be: &[u8]) -> [u8; 32] {
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

#[inline]
pub fn be32_add(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], u8) {
    let mut out = [0u8; 32];
    let mut c: u16 = 0;
    for k in (0..32).rev() {
        let s = a[k] as u16 + b[k] as u16 + c;
        out[k] = (s & 0xff) as u8;
        c = s >> 8;
    }
    (out, c as u8)
}

#[inline]
pub fn be32_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (mut sum, carry) = be32_add(a, b);
    if carry == 1 || !be32_lt(&sum, &CHEETAH_N) {
        be32_sub_inplace(&mut sum, &CHEETAH_N);
    }
    sum
}

/// Truncate TIP5 digest to curve order
pub fn trunc_g_order_to_be32(digest5: [u64; 5]) -> [u8; 32] {
    let a0 = digest5[0];
    let a1 = digest5[1];
    let a2 = digest5[2];
    let a3 = digest5[3];

    // Build v = a0 + P*a1 + P^2*a2 + P^3*a3 as 256-bit little-endian limbs.
    let (p2_hi, p2_lo) = {
        let p2 = (GOLDILOCKS_P as u128) * (GOLDILOCKS_P as u128);
        ((p2 >> 64) as u64, (p2 & 0xffff_ffff_ffff_ffff) as u64)
    };
    let (p3_0, p3_1, p3_2) = mul_u128_by_u64_to_192(p2_hi, p2_lo, GOLDILOCKS_P);

    let mut v = [0u64; 4];

    add64_into(&mut v, 0, a0);

    {
        let (lo, hi) = mul_u64x64(a1, GOLDILOCKS_P);
        add64_into(&mut v, 0, lo);
        add64_into(&mut v, 1, hi);
    }

    {
        let (lo0, lo1, lo2) = mul_u64_by_u128_to_192(a2, p2_hi, p2_lo);
        add64_into(&mut v, 0, lo0);
        add64_into(&mut v, 1, lo1);
        add64_into(&mut v, 2, lo2);
    }

    {
        let (w0, w1, w2, w3) = mul_u64_by_192_to_256(a3, p3_0, p3_1, p3_2);
        add64_into(&mut v, 0, w0);
        add64_into(&mut v, 1, w1);
        add64_into(&mut v, 2, w2);
        add64_into(&mut v, 3, w3);
    }

    let mut be = [0u8; 32];
    for i in 0..4 {
        be[8 * (3 - i)..8 * (3 - i) + 8].copy_from_slice(&v[i].to_be_bytes());
    }
    mod_n_from_be_bytes(&be)
}

// Helper functions for trunc_g_order_to_be32
#[inline]
fn mul_u64x64(a: u64, b: u64) -> (u64, u64) {
    let p = (a as u128) * (b as u128);
    ((p & 0xffff_ffff_ffff_ffff) as u64, (p >> 64) as u64)
}

#[inline]
fn mul_u64_by_u128_to_192(a: u64, hi: u64, lo: u64) -> (u64, u64, u64) {
    let (l0, l1) = mul_u64x64(a, lo);
    let (h0, h1) = mul_u64x64(a, hi);
    let (m, carry) = l1.overflowing_add(h0);
    (l0, m, h1 + (carry as u64))
}

#[inline]
fn mul_u128_by_u64_to_192(hi: u64, lo: u64, b: u64) -> (u64, u64, u64) {
    let (l0, l1) = mul_u64x64(lo, b);
    let (h0, h1) = mul_u64x64(hi, b);
    let (m, carry) = l1.overflowing_add(h0);
    (l0, m, h1 + (carry as u64))
}

#[inline]
fn mul_u64_by_192_to_256(a: u64, w0: u64, w1: u64, w2: u64) -> (u64, u64, u64, u64) {
    let (p0_lo, p0_hi) = mul_u64x64(a, w0);
    let (p1_lo, p1_hi) = mul_u64x64(a, w1);
    let (p2_lo, p2_hi) = mul_u64x64(a, w2);

    let (r1, c1) = p1_lo.overflowing_add(p0_hi);
    let (r2a, c2a) = p2_lo.overflowing_add(p1_hi + (c1 as u64));
    let r3 = p2_hi + (c2a as u64);

    (p0_lo, r1, r2a, r3)
}

#[inline]
fn add64_into(acc: &mut [u64; 4], idx: usize, addend: u64) {
    let (s, c) = acc[idx].overflowing_add(addend);
    acc[idx] = s;
    if c && idx + 1 < 4 {
        let mut k = idx + 1;
        while k < 4 {
            let (s2, c2) = acc[k].overflowing_add(1);
            acc[k] = s2;
            if !c2 {
                break;
            }
            k += 1;
        }
    }
}

/// Convert 32-byte big-endian to T8 format (8x u32 in u64, little-endian byte order)
pub fn be32_atom_to_t8_le(be: &[u8; 32]) -> T8 {
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }

    let mut v = [0u64; 8];
    for i in 0..8 {
        let w =
            u32::from_le_bytes([le[i * 4 + 0], le[i * 4 + 1], le[i * 4 + 2], le[i * 4 + 3]]) as u64;
        v[i] = w;
    }
    T8 { values: v }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_mod_n_large_numbers() {
        // Test with two large 32-byte numbers
        // First number: 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
        let a: [u8; 32] = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC, 0xDE, 0xF0,
        ];

        // Second number: 0xFEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210
        let b: [u8; 32] = [
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];

        // Compute a * b mod n
        let result = mul_mod_n(&a, &b);

        // Print the inputs and result for debugging
        println!("\nTesting mul_mod_n with large numbers:");
        print!("a = 0x");
        for byte in &a {
            print!("{:02x}", byte);
        }
        println!();

        print!("b = 0x");
        for byte in &b {
            print!("{:02x}", byte);
        }
        println!();

        print!("CHEETAH_N = 0x");
        for byte in &CHEETAH_N {
            print!("{:02x}", byte);
        }
        println!();

        print!("a * b mod n = 0x");
        for byte in &result {
            print!("{:02x}", byte);
        }
        println!();

        // Verify result is less than n
        assert!(be32_lt(&result, &CHEETAH_N), "Result should be less than n");

        // Test with smaller numbers that we can manually verify
        // a = 1000 (0x3E8)
        let small_a: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr[30] = 0x03;
            arr[31] = 0xE8;
            arr
        };

        // b = 2000 (0x7D0)
        let small_b: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr[30] = 0x07;
            arr[31] = 0xD0;
            arr
        };

        let small_result = mul_mod_n(&small_a, &small_b);

        // 1000 * 2000 = 2,000,000 (0x1E8480)
        let expected: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr[29] = 0x1E;
            arr[30] = 0x84;
            arr[31] = 0x80;
            arr
        };

        println!("\nTesting mul_mod_n with small numbers:");
        println!(
            "1000 * 2000 = {}",
            u32::from_be_bytes([0, small_result[29], small_result[30], small_result[31]])
        );

        assert_eq!(small_result, expected, "1000 * 2000 should equal 2,000,000");

        // Test commutativity: a * b = b * a (mod n)
        let result_ba = mul_mod_n(&b, &a);
        assert_eq!(result, result_ba, "Multiplication should be commutative");

        println!("✓ mul_mod_n tests passed!");
    }

    #[test]
    fn test_compare_mul_mod_n_implementations() {
        // Test with the same large numbers from Hoon
        let a: [u8; 32] = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC, 0xDE, 0xF0,
        ];

        let b: [u8; 32] = [
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];

        // Expected result from Hoon
        // 0x6b050596453169d3ddcc7af2776cb4a30223c90de6163a9a2ea6897206afcb6a
        let expected: [u8; 32] = [
            0x6b, 0x05, 0x05, 0x96, 0x45, 0x31, 0x69, 0xd3, 0xdd, 0xcc, 0x7a, 0xf2, 0x77, 0x6c,
            0xb4, 0xa3, 0x02, 0x23, 0xc9, 0x0d, 0xe6, 0x16, 0x3a, 0x9a, 0x2e, 0xa6, 0x89, 0x72,
            0x06, 0xaf, 0xcb, 0x6a,
        ];

        // Test with updated implementation
        let result = mul_mod_n(&a, &b);

        println!("\nTesting mul_mod_n with BigUint implementation:");
        print!("Expected (Hoon): 0x");
        for byte in &expected {
            print!("{:02x}", byte);
        }
        println!();

        print!("Result:          0x");
        for byte in &result {
            print!("{:02x}", byte);
        }
        println!();

        // Check if result matches expected
        assert_eq!(result, expected, "mul_mod_n should match Hoon result");
    }
}
