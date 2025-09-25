/// Big-endian 32-byte arithmetic operations modulo curve order
use crate::hashing::hasher::GOLDILOCKS_PRIME as GOLDILOCKS_P;

/// Group order n as 32-byte big-endian
pub const CHEETAH_N: [u8; 32] = [
    0x7a,0xf2,0x59,0x9b,0x3b,0x3f,0x22,0xd0,0x56,0x3f,0xbf,0x0f,0x99,0x0a,0x37,0xb5,
    0x32,0x7a,0xa7,0x23,0x30,0x15,0x77,0x22,0xd4,0x43,0x62,0x3e,0xae,0xd4,0xac,0xcf,
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
    let (mut sum, carry) = add_be32(a, b);
    if carry == 1 || !be32_lt(&sum, &CHEETAH_N) {
        be32_sub_inplace(&mut sum, &CHEETAH_N);
    }
    sum
}

#[inline]
pub fn mul_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut prod = [0u8; 64];
    for i in 0..32 {
        let mut carry: u32 = 0;
        for j in 0..32 {
            let ai = a[31 - i] as u32;
            let bj = b[31 - j] as u32;
            let k = 63 - (i + j);
            let t = ai * bj + prod[k] as u32 + carry;
            prod[k] = (t & 0xff) as u8;
            carry = t >> 8;
        }
        let mut kk = 63 - (i + 32);
        let mut c = carry;
        while c != 0 {
            let t = prod[kk] as u32 + c;
            prod[kk] = (t & 0xff) as u8;
            c = t >> 8;
            if kk == 0 { break; }
            kk -= 1;
        }
    }
    mod_n_from_be_bytes(&prod)
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
        be[8*(3-i) .. 8*(3-i)+8].copy_from_slice(&v[i].to_be_bytes());
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
            if !c2 { break; }
            k += 1;
        }
    }
}

/// Convert 32-byte big-endian to T8 format (8x u32 in u64, little-endian byte order)
pub fn be32_atom_to_t8_le(be: &[u8; 32]) -> crate::transaction_types::T8 {
    let mut le = [0u8; 32];
    for i in 0..32 { 
        le[i] = be[31 - i]; 
    }

    let mut v = [0u64; 8];
    for i in 0..8 {
        let w = u32::from_le_bytes([
            le[i*4 + 0],
            le[i*4 + 1],
            le[i*4 + 2],
            le[i*4 + 3],
        ]) as u64;
        v[i] = w;
    }
    crate::transaction_types::T8 { values: v }
}