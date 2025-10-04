extern crate alloc;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::crypto::goldilocks::{bpegcd_full, tip5_permute, Belt, GOLDILOCKS_P};
use crate::crypto::utils::{add_mod_n, mul_mod_n};

// ---- Constants --------------------------------------------------------------

const F6_ZERO: F6lt = F6lt([Belt(0); 6]);
const F6_ONE: F6lt = F6lt([Belt(1), Belt(0), Belt(0), Belt(0), Belt(0), Belt(0)]);

const A: F6lt = F6lt([Belt(1), Belt(0), Belt(0), Belt(0), Belt(0), Belt(0)]);
const B: F6lt = F6lt([Belt(395), Belt(1), Belt(0), Belt(0), Belt(0), Belt(0)]);

pub const GX: F6lt = F6lt([
    Belt(2_754_611_494_552_410_273),
    Belt(8_599_518_745_794_843_693),
    Belt(10_526_511_002_404_673_680),
    Belt(4_830_863_958_577_994_148),
    Belt(375_185_138_577_093_320),
    Belt(12_938_930_721_685_970_739),
]);
pub const GY: F6lt = F6lt([
    Belt(15_384_029_202_802_550_068),
    Belt(2_774_812_795_997_841_935),
    Belt(14_375_303_400_746_062_753),
    Belt(10_708_493_419_890_101_954),
    Belt(13_187_678_623_570_541_764),
    Belt(9_990_732_138_772_505_951),
]);

pub const G: CheetahPoint = CheetahPoint {
    x: GX,
    y: GY,
    inf: false,
};

/// Group order n as 32-byte big-endian
const CHEETAH_N: [u8; 32] = [
    0x7a, 0xf2, 0x59, 0x9b, 0x3b, 0x3f, 0x22, 0xd0, 0x56, 0x3f, 0xbf, 0x0f, 0x99, 0x0a, 0x37, 0xb5,
    0x32, 0x7a, 0xa7, 0x23, 0x30, 0x15, 0x77, 0x22, 0xd4, 0x43, 0x62, 0x3e, 0xae, 0xd4, 0xac, 0xcf,
];

const A_ID: CheetahPoint = CheetahPoint {
    x: F6_ZERO,
    y: F6_ONE,
    inf: true,
};
const NOCKCHAIN_SLIP10_KEY: &[u8] = b"Nockchain seed";

// ---- Types ------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hash {
    pub values: [u64; 5],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct T8 {
    pub values: [u64; 8],
}

// F_{p^6} element (tower) as six Belt limbs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct F6lt([Belt; 6]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheetahPoint {
    pub x: F6lt,
    pub y: F6lt,
    pub inf: bool,
}

// ---- Field ops over F_{p^6} (with u^6 ≡ +7) --------------------------------

#[inline]
fn f6_mul(a: &F6lt, b: &F6lt) -> F6lt {
    let mut h = [Belt(0); 11];
    for i in 0..6 {
        for j in 0..6 {
            h[i + j] = h[i + j] + (a.0[i] * b.0[j]);
        }
    }
    // u^6 ≡ +7  → fold highs down with +7
    for k in 6..=10 {
        h[k - 6] = h[k - 6] + (Belt(7) * h[k]);
    }
    F6lt([h[0], h[1], h[2], h[3], h[4], h[5]])
}

#[inline]
fn f6_square(a: &F6lt) -> F6lt {
    f6_mul(a, a)
}

#[inline]
fn f6_add(a: &F6lt, b: &F6lt) -> F6lt {
    F6lt([
        a.0[0] + b.0[0],
        a.0[1] + b.0[1],
        a.0[2] + b.0[2],
        a.0[3] + b.0[3],
        a.0[4] + b.0[4],
        a.0[5] + b.0[5],
    ])
}
#[inline]
fn f6_neg(a: &F6lt) -> F6lt {
    F6lt([-a.0[0], -a.0[1], -a.0[2], -a.0[3], -a.0[4], -a.0[5]])
}
#[inline]
fn f6_sub(a: &F6lt, b: &F6lt) -> F6lt {
    f6_add(a, &f6_neg(b))
}
#[inline]
fn f6_scal(a: &F6lt, s: Belt) -> F6lt {
    F6lt([
        a.0[0] * s,
        a.0[1] * s,
        a.0[2] * s,
        a.0[3] * s,
        a.0[4] * s,
        a.0[5] * s,
    ])
}

// inverse via extended GCD wrt μ(t) = t^6 - 7 (matches u^6 ≡ +7)
fn f6_inv(a: &F6lt) -> F6lt {
    if a.0.iter().all(|&x| x == Belt(0)) {
        return *a;
    }

    let mut u = [Belt(0); 7];
    u[..6].copy_from_slice(&a.0);

    // μ(t) = t^6 - 7
    let mu = [
        -Belt(7),
        Belt(0),
        Belt(0),
        Belt(0),
        Belt(0),
        Belt(0),
        Belt(1),
    ];

    let (s, _t, d0) = bpegcd_full(&u, &mu);
    let inv_d0 = d0.inv();
    F6lt([
        s[0] * inv_d0,
        s[1] * inv_d0,
        s[2] * inv_d0,
        s[3] * inv_d0,
        s[4] * inv_d0,
        s[5] * inv_d0,
    ])
}

#[inline]
fn f6_div(a: &F6lt, b: &F6lt) -> F6lt {
    f6_mul(a, &f6_inv(b))
}

// ---- Curve ops --------------------------------------------------------------

#[inline]
fn is_on_curve(p: &CheetahPoint) -> bool {
    let y2 = f6_square(&p.y);
    let x2 = f6_square(&p.x);
    let x3 = f6_mul(&x2, &p.x);
    let ax = f6_mul(&A, &p.x);
    let rhs = f6_add(&f6_add(&x3, &ax), &B); // y^2 = x^3 + A*x + B
    y2 == rhs
}

fn ch_add_unsafe(p: &CheetahPoint, q: &CheetahPoint) -> CheetahPoint {
    let x1 = p.x;
    let y1 = p.y;
    let x2 = q.x;
    let y2 = q.y;

    if p.inf {
        return *q;
    }
    if q.inf {
        return *p;
    }

    if x1 == x2 {
        if y1 == f6_neg(&y2) {
            return A_ID;
        } else {
            return ch_double_unsafe(p);
        }
    }

    let s = f6_div(&f6_sub(&y2, &y1), &f6_sub(&x2, &x1));
    let s2 = f6_square(&s);
    let x3 = f6_sub(&f6_sub(&s2, &x1), &x2);
    let y3 = f6_sub(&f6_mul(&s, &f6_sub(&x1, &x3)), &y1);

    CheetahPoint {
        x: x3,
        y: y3,
        inf: false,
    }
}
#[inline]
fn ch_add(p: &CheetahPoint, q: &CheetahPoint) -> CheetahPoint {
    ch_add_unsafe(p, q)
}

fn ch_double_unsafe(p: &CheetahPoint) -> CheetahPoint {
    if p.inf {
        return *p;
    }
    let x = p.x;
    let y = p.y;
    if y == F6_ZERO {
        return A_ID;
    }

    let three = Belt(3);
    let two = Belt(2);

    // a = 1  → slope = (3*x^2 + A) / (2*y)
    let num = f6_add(&f6_scal(&f6_square(&x), three), &A);
    let den = f6_scal(&y, two);
    let s = f6_div(&num, &den);

    let s2 = f6_square(&s);
    let x3 = f6_sub(&f6_sub(&s2, &x), &x);
    let y3 = f6_sub(&f6_mul(&s, &f6_sub(&x, &x3)), &y);

    CheetahPoint {
        x: x3,
        y: y3,
        inf: false,
    }
}
#[inline]
fn ch_double(p: &CheetahPoint) -> CheetahPoint {
    ch_double_unsafe(p)
}

fn ch_scal_big(k_be: &[u8; 32], p: &CheetahPoint) -> CheetahPoint {
    let mut acc = A_ID;
    let mut base = *p;
    // LSB-first bit walk
    for bit in 0..256 {
        let byte = k_be[31 - (bit / 8)];
        if ((byte >> (bit % 8)) & 1) == 1 {
            acc = ch_add(&acc, &base);
        }
        base = ch_double(&base);
    }
    acc
}

// ---- Basepoint --------------------------------------------------------------

#[inline]
fn basepoint() -> CheetahPoint {
    debug_assert!(is_on_curve(&G), "G not on curve");
    #[cfg(debug_assertions)]
    {
        let nG = ch_scal_big(&CHEETAH_N, &G);
        debug_assert!(nG.inf, "n·G != ∞");
        let a = F6lt([Belt(5), Belt(123), Belt(0), Belt(77), Belt(2), Belt(9999)]);
        let ainv = f6_inv(&a);
        debug_assert_eq!(f6_mul(&a, &ainv), F6_ONE, "f6_inv is wrong");
    }
    G
}

// ---- TIP-5 helpers ----------------------------------------------------------

const RATE: usize = 10; // 10 x u64 words absorbed per block (upstream nockchain)
const DIGEST_LENGTH: usize = 5; // 5 x u64 output

// Montgomery multiplication constants for the Cheetah field
const F_PRIME: u64 = 18446744069414584321;
const F_PRIME_128: u128 = 18446744069414584321;
const F_R2: u128 = 18446744065119617025;
const F_RP: u128 = 340282366841710300967557013911933812736;

/// Montgomery reduction: converts a 128-bit value to a 64-bit field element
#[inline(always)]
fn f_mont_reduction(a: u128) -> u64 {
    debug_assert!(a < F_RP, "element must be inside the field");
    let x1: u128 = (a >> 32) & 0xffffffff;
    let x2: u128 = a >> 64;
    let c: u128 = {
        let x0: u128 = a & 0xffffffff;
        (x0 + x1) << 32
    };
    let f: u128 = c >> 64;
    let d: u128 = c - (x1 + (f * F_PRIME_128));
    if x2 >= d {
        (x2 - d) as u64
    } else {
        (x2 + F_PRIME_128 - d) as u64
    }
}

/// Montify: converts a field element into Montgomery form
#[inline(always)]
fn f_montify(a: u64) -> u64 {
    f_mont_reduction((a as u128) * F_R2)
}

/// TIP5 hash of a variable-length list of u64 words.
/// This follows the upstream nockchain implementation with:
/// - RATE=10, padding with [1, 0, 0, ...], Montgomery form, REPLACE absorption
fn tip5_hash_words(words: &[u64]) -> [u64; DIGEST_LENGTH] {
    let mut state = [0u64; 16];

    // Pad input to be a multiple of RATE
    // Hoon always adds padding, even if len % RATE == 0
    let len = words.len();
    let remainder = len % RATE;
    let padding_needed = RATE - remainder; // Always add at least [1, 0, ..., 0]

    // Create padded input: original + [1, 0, 0, ...]
    // Then montify EVERYTHING (Hoon does padding before montification)
    let mut padded = alloc::vec::Vec::with_capacity(len + padding_needed);
    for &w in words {
        padded.push(w);
    }
    padded.push(1);
    for _ in 1..padding_needed {
        padded.push(0);
    }

    // Now montify all elements
    for i in 0..padded.len() {
        padded[i] = f_montify(padded[i]);
    }

    // Absorb RATE-sized blocks with REPLACE (not XOR)
    let mut offset = 0;
    while offset < padded.len() {
        // Replace first RATE elements of state with input block
        for i in 0..RATE {
            state[i] = padded[offset + i];
        }
        tip5_permute(&mut state);
        offset += RATE;
    }

    // Demontify the digest (convert from Montgomery form back to normal)
    [
        f_mont_reduction(state[0] as u128),
        f_mont_reduction(state[1] as u128),
        f_mont_reduction(state[2] as u128),
        f_mont_reduction(state[3] as u128),
        f_mont_reduction(state[4] as u128),
    ]
}

/// Test helper to expose tip5_hash_words for comparison tests
#[doc(hidden)]
pub fn test_tip5_hash_words(words: &[u64]) -> [u64; DIGEST_LENGTH] {
    tip5_hash_words(words)
}

/// Debug version that prints intermediate state (std-only)
#[doc(hidden)]
#[cfg(feature = "std")]
pub fn test_tip5_hash_words_debug(words: &[u64]) -> [u64; DIGEST_LENGTH] {
    let mut state = [0u64; 16];

    let len = words.len();
    let remainder = len % RATE;
    let padding_needed = RATE - remainder;

    println!("  Input length: {}", len);
    println!("  Remainder: {}", remainder);
    println!("  Padding needed: {}", padding_needed);

    // Create padded input
    let mut padded = alloc::vec::Vec::with_capacity(len + padding_needed);
    for &w in words {
        padded.push(w);
    }
    padded.push(1);
    for _ in 1..padding_needed {
        padded.push(0);
    }

    println!(
        "  After padding ({} elements): {:?}",
        padded.len(),
        &padded[..core::cmp::min(padded.len(), 15)]
    );

    // Montify all elements
    for i in 0..padded.len() {
        padded[i] = f_montify(padded[i]);
    }

    println!(
        "  After montification: {:016x?}",
        &padded[..core::cmp::min(padded.len(), 10)]
    );

    // Absorb blocks
    let mut offset = 0;
    let mut block_num = 0;
    while offset < padded.len() {
        println!(
            "  Block {}: absorbing elements {}..{}",
            block_num,
            offset,
            offset + RATE
        );

        // Replace first RATE elements of state
        for i in 0..RATE {
            state[i] = padded[offset + i];
        }

        println!("    State before permute: {:016x?}", &state[..5]);
        tip5_permute(&mut state);
        println!("    State after permute:  {:016x?}", &state[..5]);

        offset += RATE;
        block_num += 1;
    }

    println!(
        "  State before demontification: {:016x?}",
        &[state[0], state[1], state[2], state[3], state[4]]
    );

    // Demontify the digest
    let digest = [
        f_mont_reduction(state[0] as u128),
        f_mont_reduction(state[1] as u128),
        f_mont_reduction(state[2] as u128),
        f_mont_reduction(state[3] as u128),
        f_mont_reduction(state[4] as u128),
    ];

    println!("  Final output (demontified): {:016x?}", digest);

    digest
}

fn pack_point_words(pt: &([u64; 6], [u64; 6])) -> [u64; 12] {
    // MSW..LSW per limb order, X then Y
    let mut out = [0u64; 12];
    out[..6].copy_from_slice(&pt.0);
    out[6..].copy_from_slice(&pt.1);
    out
}

// ---- Big-endian scalar helpers (mod n) -------------------------------------

type HmacSha512 = Hmac<Sha512>;

#[inline]
fn is_zero32(x: &[u8; 32]) -> bool {
    x.iter().fold(0u8, |z, &b| z | b) == 0
}

#[inline]
fn be32_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for k in 0..32 {
        if a[k] != b[k] {
            return a[k] < b[k];
        }
    }
    false
}

#[inline]
fn sub_be32(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], u8) {
    // (a-b, borrow)
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
fn add_be32(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], u8) {
    // (a+b, carry)
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

// Removed local add_mod_n and mul_mod_n - now using implementations from crypto::utils
// which have proper std/no-std conditional compilation

#[inline]
fn mod_n_from_be_bytes(bytes_be: &[u8]) -> [u8; 32] {
    // remainder by iterative (rem*256 + byte) % n
    let mut rem = [0u8; 32];
    for &b in bytes_be {
        // rem <<= 8; add b
        let mut carry = b as u16;
        for i in (0..32).rev() {
            let t = ((rem[i] as u16) << 8) | carry;
            rem[i] = (t & 0xff) as u8;
            carry = (t >> 8) as u16;
        }
        // reduce while rem >= n
        while !be32_lt(&rem, &CHEETAH_N) {
            be32_sub_inplace(&mut rem, &CHEETAH_N);
        }
    }
    rem
}

// ---- deterministic k (HMAC-SHA256) -----------------------------

fn rfc6979_k(sk_be: &[u8; 32], personalization: &[u8]) -> [u8; 32] {
    // k = HMAC-SHA256(sk, personalization) mod n, reject 0
    let mut mac = Hmac::<Sha256>::new_from_slice(sk_be).expect("hmac key");
    mac.update(personalization);
    let digest = mac.finalize().into_bytes(); // 32
    let mut k = [0u8; 32];
    k.copy_from_slice(&digest);
    let k = mod_n_from_be_bytes(&k);
    if is_zero32(&k) {
        [1u8; 32]
    } else {
        k
    }
}

// ---- HMAC split for SLIP-10 ----------------------------------------------

pub fn hmac_split_512(key: &[u8], data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left.copy_from_slice(&out[..32]);
    right.copy_from_slice(&out[32..]);
    (left, right)
}

// ---- Master-from-seed (rehash-until-valid) ---------------------------------

pub fn master_from_seed(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(NOCKCHAIN_SLIP10_KEY).unwrap();
    mac.update(seed);
    let mut i = mac.finalize().into_bytes(); // 64 bytes

    loop {
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        left.copy_from_slice(&i[..32]);
        right.copy_from_slice(&i[32..]);

        if !is_zero32(&left) && be32_lt(&left, &CHEETAH_N) {
            return (left, right);
        }

        // rehash whole 64B per spec
        let mut mac = HmacSha512::new_from_slice(NOCKCHAIN_SLIP10_KEY).unwrap();
        mac.update(&i);
        i = mac.finalize().into_bytes();
    }
}

// ---- Serialization ----------------------------------------------------------

/// Serialize affine point limbs (x,y) into 97 bytes in Hoon parity:
/// 0x01 sentinel followed by Y then X limbs, most-significant limb first.
pub fn ser_a_pt(pk: &([u64; 6], [u64; 6])) -> [u8; 97] {
    let (x, y) = pk;
    let mut out = [0u8; 97];
    out[0] = 0x01;
    let mut off = 1;

    for &w in y.iter().rev().chain(x.iter().rev()) {
        out[off..off + 8].copy_from_slice(&w.to_be_bytes());
        off += 8;
    }
    out
}

/// Serialize as 8-byte sentinel (=1) || X || Y in the Hoon `rep` format (104 bytes).
pub fn ser_a_pt_rep104(pk: &([u64; 6], [u64; 6])) -> [u8; 104] {
    let mut limbs = [0u64; 13];
    limbs[0] = 1; // LS limb sentinel
    limbs[1..7].copy_from_slice(&pk.1); // y0..y5 (LSW..MSW)
    limbs[7..13].copy_from_slice(&pk.0); // x0..x5

    let mut out = [0u8; 104];
    let mut off = 0;
    for limb in limbs.iter().rev() {
        out[off..off + 8].copy_from_slice(&limb.to_be_bytes());
        off += 8;
    }
    out
}

// ---- Keys & Schnorr ---------------------------------------------------------

/// Compute affine (x,y) for the secret scalar `sk_be` (big-endian).
/// Internal limbs are LSW..MSW; wire/serialized limbs must be MSW..LSW.
pub fn cheetah_pub_from_sk(sk_be: [u8; 32]) -> ([u64; 6], [u64; 6]) {
    let p = ch_scal_big(&sk_be, &basepoint());
    let mut x = [0u64; 6];
    let mut y = [0u64; 6];

    // Return coordinates in LSW..MSW order (index 0 = LSW, index 5 = MSW)
    // Internal limbs are already LSW..MSW, so no reversal needed
    for i in 0..6 {
        x[i] = p.x.0[i].0 as u64;
        y[i] = p.y.0[i].0 as u64;
    }
    (x, y)
}

/// Sign a TIP-5 digest m (5×u64) with Schnorr over Cheetah, Hoon-compatible:
/// - R = k·G  (k from TIP5 hash)
/// - chal = trunc_g_order( TIP5([xR,yR,xP,yP,m]) )
/// - s = (k + chal*sk) mod n
/// - return chal/s as T8 (little-endian limbs), padded to 8 u64.
///
/// Note: this function is the analogue of sign:affine:belt-schnorr:cheetah
/// on line 1799 in nockchain/ztd/three.hoon
pub fn schnorr_sign_digest(sk_be: [u8; 32], pk: ([u64; 6], [u64; 6]), m5: [u64; 5]) -> (T8, T8) {
    // Hoon-compatible Schnorr signature implementation
    // Matches sign:affine:schnorr in three.hoon line 1628

    // Convert secret key to T8 format to validate components
    let sk_t8 = be32_atom_to_t8_le(&sk_be);

    // Validate each T8 component is < 2^32 (matches Hoon line 1634)
    // ?>  (levy sk-as-32-bit-belts |=(n=@ (lth n b-32)))
    for (i, &limb) in sk_t8.values.iter().enumerate() {
        if limb >= (1u64 << 32) {
            panic!(
                "Secret key T8 component {} ({:#x}) must be less than 2^32",
                i, limb
            );
        }
    }

    // Validate that sk_be represents a valid scalar < curve order (line 1637)
    if !be32_lt(&sk_be, &CHEETAH_N) {
        panic!("Secret key must be less than curve order");
    }

    // 1) Generate nonce using TIP5(pubkey || message) - matches Hoon line 1639-1642
    // Create transcript: [(f6lt-to-list x.pubkey) (f6lt-to-list y.pubkey) m ~]
    let mut nonce_transcript = [0u64; 12 + 5];
    nonce_transcript[..6].copy_from_slice(&pk.0); // pubkey.x (6 limbs)
    nonce_transcript[6..12].copy_from_slice(&pk.1); // pubkey.y (6 limbs)
    nonce_transcript[12..].copy_from_slice(&m5); // message (5 limbs)

    // Hash and truncate to get nonce
    let nonce_digest = tip5_hash_words(&nonce_transcript);
    let nonce_be = trunc_g_order_to_be32(nonce_digest);

    // Verify nonce != 0 (line 1643)
    if is_zero32(&nonce_be) {
        panic!("Generated nonce is zero"); // Should be extremely rare
    }

    // 2) Compute R = nonce × G (line 1644)
    let r_pt = cheetah_pub_from_sk(nonce_be);

    // 3) Generate challenge using TIP5([R, pubkey, message]) - matches Hoon line 1645-1647
    // transcript = [(f6lt-to-list x.scalar) (f6lt-to-list y.scalar) transcript]
    let mut chal_transcript = [0u64; 12 + 12 + 5];
    chal_transcript[..6].copy_from_slice(&r_pt.0); // R.x (6 limbs)
    chal_transcript[6..12].copy_from_slice(&r_pt.1); // R.y (6 limbs)
    chal_transcript[12..18].copy_from_slice(&pk.0); // pubkey.x (6 limbs)
    chal_transcript[18..24].copy_from_slice(&pk.1); // pubkey.y (6 limbs)
    chal_transcript[24..].copy_from_slice(&m5); // message (5 limbs)

    // Hash and truncate to get challenge
    let chal_digest = tip5_hash_words(&chal_transcript);
    let chal_be = trunc_g_order_to_be32(chal_digest);

    // Verify challenge != 0 (line 1648)
    if is_zero32(&chal_be) {
        panic!("Generated challenge is zero"); // Should be extremely rare
    }

    // 4) Compute signature s = (nonce + challenge × sk) mod n - matches Hoon line 1649-1652
    let chal_times_sk = mul_mod_n(&chal_be, &sk_be);
    let s_be = add_mod_n(&nonce_be, &chal_times_sk);

    // Verify signature != 0 (line 1653)
    if is_zero32(&s_be) {
        panic!("Generated signature is zero"); // Should be extremely rare
    }

    // 5) Convert challenge and signature to T8 format for return
    let chal_t8 = be32_atom_to_t8_le(&chal_be);
    let sig_t8 = be32_atom_to_t8_le(&s_be);

    (chal_t8, sig_t8)
}

/// Backwards-compatible alias that mirrors the host-side API. The firmware
/// always signs digests, so we simply delegate.
pub fn schnorr_sign_tx(sk_be: [u8; 32], pk: ([u64; 6], [u64; 6]), m5: [u64; 5]) -> (T8, T8) {
    schnorr_sign_digest(sk_be, pk, m5)
}

#[cfg(test)]
mod schnorr_tests {
    use super::*;

    #[test]
    fn test_schnorr_sign_digest_compatibility() {
        // Test vectors from reference implementation (Hoon test)
        let sk_be: [u8; 32] = [
            0x12, 0x34, 0x56, 0x78, // MSB
            0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55,
            0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc,
            0xcc, // LSB
        ];

        let pk = cheetah_pub_from_sk(sk_be);
        let message = [1u64, 2, 3, 4, 5];

        let (challenge, signature) = schnorr_sign_digest(sk_be, pk, message);

        // Expected values from reference implementation
        let expected_challenge: [u64; 8] = [
            0x364619a6, // LSW
            0x6af9178c, 0x46e47b17, 0xf8609591, 0xf4c6b69a, 0x1a511b32, 0xd7e56411,
            0x2f519cb9, // MSW
        ];

        let expected_signature: [u64; 8] = [
            0x0918903a, 0x0e94f5a7, 0x34d7585a, 0xb809abfe, 0x55753257, 0x5b73fced, 0x4ac8fd17,
            0x21b70dda,
        ];

        println!("\nGenerated challenge: {:016x?}", challenge.values);
        println!("Expected challenge:  {:016x?}", expected_challenge);
        println!("\nGenerated signature: {:016x?}", signature.values);
        println!("Expected signature:  {:016x?}", expected_signature);

        assert_eq!(
            challenge.values, expected_challenge,
            "Challenge mismatch - hashing implementation may be incorrect"
        );
        assert_eq!(signature.values, expected_signature, "Signature mismatch");
    }
}
// ---- SLIP-10 child derivation (xprv/xpub) ----------------------------------

#[derive(Clone, Debug)]
pub struct XKey {
    pub depth: u8,
    pub index: u32,
    pub chain_code: [u8; 32],
    pub sk: Option<[u8; 32]>,             // None for xpub
    pub pk: Option<([u64; 6], [u64; 6])>, // present for xpub or when sk present
    pub parent_fingerprint: [u8; 4],
}

#[inline]
fn is_hardened(i: u32) -> bool {
    i & 0x8000_0000 != 0
}
#[inline]
fn ser32_be(i: u32) -> [u8; 4] {
    i.to_be_bytes()
}

fn fingerprint_from_pk(pk: &([u64; 6], [u64; 6])) -> [u8; 4] {
    // TIP-5 over P, take first 4 bytes of digest[0]
    let packed = pack_point_words(pk);
    let digest = tip5_hash_words(&packed);
    digest[0].to_be_bytes()[..4].try_into().unwrap()
}

pub fn xprv_derive_child(parent: &XKey, i: u32) -> XKey {
    let prv = parent.sk.expect("need private key");
    let cc = parent.chain_code;

    const APT_SER_LEN: usize = 97;

    let (mut left, mut right) = if is_hardened(i) {
        // data = 0x00 || ser256(prv) || ser32(i)
        let mut data = [0u8; 1 + 32 + 4];
        data[0] = 0x00;
        data[1..33].copy_from_slice(&prv);
        data[33..].copy_from_slice(&ser32_be(i));
        hmac_split_512(&cc, &data)
    } else {
        // data = ser_a_pt(P) || ser32(i)
        let pk_xy = parent.pk.unwrap_or_else(|| cheetah_pub_from_sk(prv));
        let pub_ser = ser_a_pt(&pk_xy); // 97 bytes
        let mut data = [0u8; APT_SER_LEN + 4];
        data[..APT_SER_LEN].copy_from_slice(&pub_ser);
        data[APT_SER_LEN..].copy_from_slice(&ser32_be(i));
        hmac_split_512(&cc, &data)
    };

    // Retry until 0 < left < n and child != 0 using 0x01 || right || i
    for _ in 0..1024 {
        if !is_zero32(&left) && be32_lt(&left, &CHEETAH_N) {
            let child_sk = be32_add_mod_n(&left, &prv);
            if !is_zero32(&child_sk) {
                let child_pk = cheetah_pub_from_sk(child_sk);
                return XKey {
                    sk: Some(child_sk),
                    pk: Some(child_pk),
                    chain_code: right,
                    depth: parent.depth + 1,
                    index: i,
                    parent_fingerprint: parent.parent_fingerprint,
                };
            }
        }

        // Next attempt seed: 0x01 || right || ser32(i)
        let mut red = [0u8; 1 + 32 + 4];
        red[0] = 0x01;
        red[1..33].copy_from_slice(&right);
        red[33..].copy_from_slice(&ser32_be(i));
        let (l2, r2) = hmac_split_512(&cc, &red);
        left = l2;
        right = r2;
    }

    panic!("xprv_derive_child: too many retries at index {}", i);
}

pub fn xpub_derive_child(parent: &XKey, i: u32) -> XKey {
    assert_eq!(i & 0x8000_0000, 0);

    let mut data = Vec::with_capacity(104 + 4);
    data.extend_from_slice(&ser_a_pt_rep104(parent.pk.as_ref().unwrap()));
    data.extend_from_slice(&ser32_be(i));

    let (mut left, mut right) = hmac_split_512(&parent.chain_code, &data);

    loop {
        if !is_zero32(&left) && be32_lt(&left, &CHEETAH_N) {
            // child P = (left * G) + parent P
            let q = ch_scal_big(&left, &basepoint());
            let pp = parent.pk.unwrap();
            let p = CheetahPoint {
                x: F6lt(pp.0.map(Belt)),
                y: F6lt(pp.1.map(Belt)),
                inf: false,
            };
            let r = ch_add(&q, &p);
            let child_pk = {
                let mut x = [0u64; 6];
                let mut y = [0u64; 6];
                for j in 0..6 {
                    x[j] = r.x.0[j].0 as u64;
                    y[j] = r.y.0[j].0 as u64;
                }
                (x, y)
            };
            return XKey {
                depth: parent.depth.saturating_add(1),
                index: i,
                chain_code: right,
                sk: None,
                pk: Some(child_pk),
                parent_fingerprint: fingerprint_from_pk(&pp),
            };
        }

        // retry seed: 0x01 || right || ser32(i)
        let mut red = [0u8; 1 + 32 + 4];
        red[0] = 0x01;
        red[1..33].copy_from_slice(&right);
        red[33..].copy_from_slice(&ser32_be(i));
        (left, right) = hmac_split_512(&parent.chain_code, &red);
    }
}

impl XKey {
    /// Construct a master extended private key (depth=0, index=0)
    pub fn from_master(sk: [u8; 32], chain_code: [u8; 32]) -> Self {
        let pk = cheetah_pub_from_sk(sk);
        XKey {
            depth: 0,
            index: 0,
            chain_code,
            sk: Some(sk),
            pk: Some(pk),
            parent_fingerprint: [0u8; 4],
        }
    }

    /// convenience for xpub-only view
    #[allow(dead_code)]
    pub fn to_xpub(&self) -> Self {
        let pk = self.pk.expect("xkey must have pk");
        XKey {
            depth: self.depth,
            index: self.index,
            chain_code: self.chain_code,
            sk: None,
            pk: Some(pk),
            parent_fingerprint: self.parent_fingerprint,
        }
    }
}

// ---- 32-byte arithmetic helpers (mod n) ------------------------------------

#[inline]
fn be32_add(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], u8) {
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
fn be32_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (mut sum, carry) = be32_add(a, b);
    if carry == 1 || !be32_lt(&sum, &CHEETAH_N) {
        be32_sub_inplace(&mut sum, &CHEETAH_N);
    }
    sum
}

fn trunc_g_order_to_be32(digest5: [u64; 5]) -> [u8; 32] {
    let a0 = digest5[0];
    let a1 = digest5[1];
    let a2 = digest5[2];
    let a3 = digest5[3];

    // Build v = a0 + P*a1 + P^2*a2 + P^3*a3 as 256-bit little-endian limbs.
    let (p2_hi, p2_lo) = {
        let p2 = (GOLDILOCKS_P as u128) * (GOLDILOCKS_P as u128);
        ((p2 >> 64) as u64, (p2 & 0xffff_ffff_ffff_ffff) as u64)
    };
    // p3 = p2 * P (192-bit) => 3 limbs (lo, mid, hi)
    let (p3_0, p3_1, p3_2) = mul_u128_by_u64_to_192(p2_hi, p2_lo, GOLDILOCKS_P);

    // Accumulator (little-endian 4-limb 256-bit)
    let mut v = [0u64; 4];

    // v += a0
    add64_into(&mut v, 0, a0);

    // v += a1 * P
    {
        let (lo, hi) = mul_u64x64(a1, GOLDILOCKS_P);
        add64_into(&mut v, 0, lo);
        add64_into(&mut v, 1, hi);
    }

    // v += a2 * P^2
    {
        let (lo0, lo1, lo2) = mul_u64_by_u128_to_192(a2, p2_hi, p2_lo);
        add64_into(&mut v, 0, lo0);
        add64_into(&mut v, 1, lo1);
        add64_into(&mut v, 2, lo2);
    }

    // v += a3 * P^3
    {
        let (w0, w1, w2, w3) = mul_u64_by_192_to_256(a3, p3_0, p3_1, p3_2);
        add64_into(&mut v, 0, w0);
        add64_into(&mut v, 1, w1);
        add64_into(&mut v, 2, w2);
        add64_into(&mut v, 3, w3);
    }

    // Convert v (LE limbs) to big-endian bytes and reduce mod n.
    let mut be = [0u8; 32];
    for i in 0..4 {
        be[8 * (3 - i)..8 * (3 - i) + 8].copy_from_slice(&v[i].to_be_bytes());
    }
    mod_n_from_be_bytes(&be)
}

// ----- small limb helpers -----

#[inline]
fn mul_u64x64(a: u64, b: u64) -> (u64, u64) {
    let p = (a as u128) * (b as u128);
    ((p & 0xffff_ffff_ffff_ffff) as u64, (p >> 64) as u64)
}

#[inline]
fn mul_u64_by_u128_to_192(a: u64, hi: u64, lo: u64) -> (u64, u64, u64) {
    // a * (hi<<64 | lo)
    let (l0, l1) = mul_u64x64(a, lo); // 128-bit
    let (h0, h1) = mul_u64x64(a, hi); // 128-bit
                                      // (h0,h1)<<64 + (l0,l1)
    let (m, carry) = l1.overflowing_add(h0);
    (l0, m, h1 + (carry as u64))
}

#[inline]
fn mul_u128_by_u64_to_192(hi: u64, lo: u64, b: u64) -> (u64, u64, u64) {
    // (hi<<64 | lo) * b
    let (l0, l1) = mul_u64x64(lo, b);
    let (h0, h1) = mul_u64x64(hi, b);
    let (m, carry) = l1.overflowing_add(h0);
    (l0, m, h1 + (carry as u64))
}

#[inline]
fn mul_u64_by_192_to_256(a: u64, w0: u64, w1: u64, w2: u64) -> (u64, u64, u64, u64) {
    // a * (w2<<128 | w1<<64 | w0)
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

fn be32_atom_to_t8_le(be: &[u8; 32]) -> T8 {
    // Convert big-endian 32B -> little-endian byte order
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }

    // Split into eight 4-byte LE words; store each in the low 32 bits of a u64.
    let mut v = [0u64; 8];
    for i in 0..8 {
        let w =
            u32::from_le_bytes([le[i * 4 + 0], le[i * 4 + 1], le[i * 4 + 2], le[i * 4 + 3]]) as u64;
        v[i] = w; // upper 32 bits zero
    }
    T8 { values: v }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_sign_digest_with_t8_key() {
        // Test vectors from Hoon with T8 format secret key

        // Secret key as T8 (8 x u32 values, stored as u64)
        // [ 0xbbbb.cccc, 0x9999.aaaa, 0x7777.8888, 0x5555.6666,
        //   0x3333.4444, 0x1111.2222, 0x9abc.def0, 0x1234.5678 ]
        // This is already in T8 format (8 limbs, LSW first)
        // Need to convert to 32-byte big-endian for signing
        let secret_key_t8 = T8 {
            values: [
                0xbbbb_cccc, // Per comment: LSW first
                0x9999_aaaa,
                0x7777_8888,
                0x5555_6666,
                0x3333_4444,
                0x1111_2222,
                0x9abc_def0,
                0x1234_5678, // Per comment: MSW last
            ],
        };

        // Convert T8 to 32-byte big-endian array
        // T8 is little-endian limbs, each limb is 32 bits stored in low half of u64
        let mut secret_key_be = [0u8; 32];
        for i in 0..8 {
            let limb = secret_key_t8.values[i] as u32;
            let limb_bytes = limb.to_le_bytes();
            for j in 0..4 {
                secret_key_be[31 - (i * 4 + j)] = limb_bytes[j];
            }
        }

        // Derive public key from secret key
        let pk = cheetah_pub_from_sk(secret_key_be);

        // Message: [i=1 t=[i=2 t=~[3 4 5]]]
        // This represents a list [1, 2, 3, 4, 5] as 5 u64 values
        let message: [u64; 5] = [1, 2, 3, 4, 5];

        // Expected challenge as T8
        let expected_challenge: [u64; 8] = [
            0x3646_19a6, // LSW
            0x6af9_178c,
            0x46e4_7b17,
            0xf860_9591,
            0xf4c6_b69a,
            0x1a51_1b32,
            0xd7e5_6411,
            0x2f51_9cb9, // MSW
        ];

        // Expected signature as T8
        let expected_signature: [u64; 8] = [
            0x0918_903a, // LSW (note: 0x918.903a with leading zero)
            0x0e94_f5a7, // 0xe94.f5a7 with leading zero
            0x34d7_585a,
            0xb809_abfe,
            0x5575_3257,
            0x5b73_fced,
            0x4ac8_fd17,
            0x21b7_0dda, // MSW
        ];

        // Sign the message
        let (challenge, signature) = schnorr_sign_digest(secret_key_be, pk, message);

        // Debug output to help diagnose mismatches
        println!("\nGenerated challenge: {:016x?}", challenge.values);
        println!("Expected challenge:  {:016x?}", expected_challenge);
        println!("\nGenerated signature: {:016x?}", signature.values);
        println!("Expected signature:  {:016x?}", expected_signature);

        // Verify challenge matches
        assert_eq!(
            challenge.values, expected_challenge,
            "Challenge should match Hoon output"
        );

        // Verify signature matches
        assert_eq!(
            signature.values, expected_signature,
            "Signature should match Hoon output"
        );

        println!("✓ schnorr_sign_digest with T8 key produces expected results!");
    }
}
