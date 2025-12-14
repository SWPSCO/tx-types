#![allow(dead_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::cmp;
use core::ops::{Add, Div, Mul, Neg, Sub};

/// Goldilocks prime used for Belt arithmetic (2^64 - 2^32 + 1)
pub const GOLDILOCKS_P: u64 = 0xffff_ffff_0000_0001;
const PRIME: u64 = GOLDILOCKS_P;
const PRIME_128: u128 = 18446744069414584321;
const STATE_SIZE: usize = 16;
const NUM_SPLIT_AND_LOOKUP: usize = 4;
const NUM_ROUNDS: usize = 7;
const R: u128 = 18446744073709551616;

/// Lookup table used in TIP5 S-box layer
const LOOKUP_TABLE: [u8; 256] = [
    0, 7, 26, 63, 124, 215, 85, 254, 214, 228, 45, 185, 140, 173, 33, 240, 29, 177, 176, 32, 8,
    110, 87, 202, 204, 99, 150, 106, 230, 14, 235, 128, 213, 239, 212, 138, 23, 130, 208, 6, 44,
    71, 93, 116, 146, 189, 251, 81, 199, 97, 38, 28, 73, 179, 95, 84, 152, 48, 35, 119, 49, 88,
    242, 3, 148, 169, 72, 120, 62, 161, 166, 83, 175, 191, 137, 19, 100, 129, 112, 55, 221, 102,
    218, 61, 151, 237, 68, 164, 17, 147, 46, 234, 203, 216, 22, 141, 65, 57, 123, 12, 244, 54, 219,
    231, 96, 77, 180, 154, 5, 253, 133, 165, 98, 195, 205, 134, 245, 30, 9, 188, 59, 142, 186, 197,
    181, 144, 92, 31, 224, 163, 111, 74, 58, 69, 113, 196, 67, 246, 225, 10, 121, 50, 60, 157, 90,
    122, 2, 250, 101, 75, 178, 159, 24, 36, 201, 11, 243, 132, 198, 190, 114, 233, 39, 52, 21, 209,
    108, 238, 91, 187, 18, 104, 194, 37, 153, 34, 200, 143, 126, 155, 236, 118, 64, 80, 172, 89,
    94, 193, 135, 183, 86, 107, 252, 13, 167, 206, 136, 220, 207, 103, 171, 160, 76, 182, 227, 217,
    158, 56, 174, 4, 66, 109, 139, 162, 184, 211, 249, 47, 125, 232, 117, 43, 16, 42, 127, 20, 241,
    25, 149, 105, 156, 51, 53, 168, 145, 247, 223, 79, 78, 226, 15, 222, 82, 115, 70, 210, 27, 41,
    1, 170, 40, 131, 192, 229, 248, 255,
];

/// MDS matrix used in TIP5 linear layer (signed values)
const MDS_MATRIX_I64: [[i64; STATE_SIZE]; STATE_SIZE] = [
    [
        61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454,
        33823, 28750, 1108,
    ],
    [
        1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244,
        7454, 33823, 28750,
    ],
    [
        28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865,
        43244, 7454, 33823,
    ],
    [
        33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034,
        53865, 43244, 7454,
    ],
    [
        7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951,
        12034, 53865, 43244,
    ],
    [
        43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521,
        56951, 12034, 53865,
    ],
    [
        53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901, 41351,
        27521, 56951, 12034,
    ],
    [
        12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021, 40901,
        41351, 27521, 56951,
    ],
    [
        56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689, 12021,
        40901, 41351, 27521,
    ],
    [
        27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798, 59689,
        12021, 40901, 41351,
    ],
    [
        41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845, 26798,
        59689, 12021, 40901,
    ],
    [
        40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402, 17845,
        26798, 59689, 12021,
    ],
    [
        12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108, 61402,
        17845, 26798, 59689,
    ],
    [
        59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108,
        61402, 17845, 26798,
    ],
    [
        26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750,
        1108, 61402, 17845,
    ],
    [
        17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823,
        28750, 1108, 61402,
    ],
];

/// Belt element (field element modulo Goldilocks prime)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Belt(pub u64);

impl Belt {
    #[inline(always)]
    pub fn zero() -> Self {
        Self(0)
    }

    #[inline(always)]
    pub fn one() -> Self {
        Self(1)
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub fn inv(self) -> Self {
        Self(binv(self.0))
    }
}

impl From<u64> for Belt {
    fn from(value: u64) -> Self {
        Belt(value % PRIME)
    }
}

impl From<Belt> for u64 {
    fn from(value: Belt) -> Self {
        value.0
    }
}

impl Add for Belt {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Belt(badd(self.0, rhs.0))
    }
}

impl Sub for Belt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Belt(bsub(self.0, rhs.0))
    }
}

impl Mul for Belt {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Belt(bmul(self.0, rhs.0))
    }
}

impl Div for Belt {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Belt(bmul(self.0, binv(rhs.0)))
    }
}

impl Neg for Belt {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Belt(bneg(self.0))
    }
}

/// Addition modulo GOLDILOCKS_P
#[inline(always)]
pub fn badd(a: u64, b: u64) -> u64 {
    let (res, carry) = a.overflowing_add(b);
    let res = if carry { res.wrapping_sub(PRIME) } else { res };
    if res >= PRIME {
        res - PRIME
    } else {
        res
    }
}

/// Subtraction modulo GOLDILOCKS_P
#[inline(always)]
pub fn bsub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        PRIME - (b - a)
    }
}

/// Negation modulo GOLDILOCKS_P
#[inline(always)]
pub fn bneg(a: u64) -> u64 {
    if a == 0 {
        0
    } else {
        PRIME - a
    }
}

/// Multiplication modulo GOLDILOCKS_P
#[inline(always)]
pub fn bmul(a: u64, b: u64) -> u64 {
    reduce((a as u128) * (b as u128))
}

/// Modular inverse via Fermat's little theorem
#[inline(always)]
pub fn binv(a: u64) -> u64 {
    bpow(a, PRIME - 2)
}

/// Modular exponentiation
#[inline(always)]
pub fn bpow(mut base: u64, mut exp: u64) -> u64 {
    let mut acc: u64 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = bmul(acc, base);
        }
        exp >>= 1;
        if exp > 0 {
            base = bmul(base, base);
        }
    }
    acc
}

/// Reduce a 128-bit product modulo GOLDILOCKS_P
#[inline(always)]
fn reduce(n: u128) -> u64 {
    reduce_159(n as u64, (n >> 64) as u32, (n >> 96) as u64)
}

/// Reduce a 159-bit number modulo GOLDILOCKS_P
#[inline(always)]
fn reduce_159(low: u64, mid: u32, high: u64) -> u64 {
    let (mut low2, carry) = low.overflowing_sub(high);
    if carry {
        low2 = low2.wrapping_add(PRIME);
    }

    let mut product = (mid as u64) << 32;
    product -= product >> 32;

    let (mut result, carry) = product.overflowing_add(low2);
    if carry {
        result = result.wrapping_sub(PRIME);
    }

    if result >= PRIME {
        result - PRIME
    } else {
        result
    }
}

/// Polynomial subtraction res = a - b (element-wise)
#[inline(always)]
pub fn bpsub(a: &[Belt], b: &[Belt], res: &mut [Belt]) {
    let len = cmp::max(a.len(), b.len());
    for i in 0..len {
        res[i] = if i < a.len() { a[i] } else { Belt::zero() }
            - if i < b.len() { b[i] } else { Belt::zero() };
    }
}

/// Polynomial multiplication res = a * b
#[inline(always)]
pub fn bpmul(a: &[Belt], b: &[Belt], res: &mut [Belt]) {
    if poly_is_zero(a) || poly_is_zero(b) {
        res.fill(Belt::zero());
        return;
    }

    res.fill(Belt::zero());

    for (i, &ai) in a.iter().enumerate() {
        if ai.is_zero() {
            continue;
        }
        for (j, &bj) in b.iter().enumerate() {
            res[i + j] = res[i + j] + ai * bj;
        }
    }
}

/// Polynomial division with remainder: a = q * b + res
#[inline(always)]
pub fn bpdvr(a: &[Belt], b: &[Belt], q: &mut [Belt], res: &mut [Belt]) {
    if poly_is_zero(b) {
        panic!("divide by zero in bpdvr");
    }

    q.fill(Belt::zero());
    res.fill(Belt::zero());

    if poly_is_zero(a) {
        return;
    }

    let a_deg = poly_degree(a);
    let mut r = a[..=a_deg].to_vec();
    let deg_b = poly_degree(b);
    let mut i = a_deg;
    let end_b = deg_b;
    let mut deg_r = a_deg;
    let mut q_index = deg_r.saturating_sub(deg_b);

    while deg_r >= deg_b {
        let coeff = r[i] / b[end_b];
        q[q_index] = coeff;
        for k in 0..=deg_b {
            if i >= k {
                r[i - k] = r[i - k] - coeff * b[end_b - k];
            }
        }
        deg_r = deg_r.saturating_sub(1);
        q_index = q_index.saturating_sub(1);

        if deg_r == 0 && r[0].is_zero() {
            break;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }

    let r_len = cmp::min(res.len(), deg_r + 1);
    res[..r_len].copy_from_slice(&r[..r_len]);
}

/// Extended GCD for polynomials over Belt field
pub fn bpegcd_full(a: &[Belt], b: &[Belt]) -> (Vec<Belt>, Vec<Belt>, Belt) {
    let mut d = vec![Belt::zero(); cmp::max(a.len(), b.len())];
    let mut u = vec![Belt::zero(); a.len() + b.len()];
    let mut v = vec![Belt::zero(); a.len() + b.len()];
    bpegcd_impl(a, b, &mut d, &mut u, &mut v);

    let s = u[..12].to_vec();
    let t = v[..2].to_vec();
    let d0 = d[0];
    (s, t, d0)
}

fn bpegcd_impl(a: &[Belt], b: &[Belt], d: &mut [Belt], u: &mut [Belt], v: &mut [Belt]) {
    let mut m1_u = vec![Belt::zero()];
    let mut m2_u = vec![Belt::one()];
    let mut m1_v = vec![Belt::one()];
    let mut m2_v = vec![Belt::zero()];

    d.fill(Belt::zero());
    u.fill(Belt::zero());
    v.fill(Belt::zero());

    let mut a = a.to_vec();
    let mut b = b.to_vec();

    while !poly_is_zero(&b) {
        let deg_a = poly_degree(&a);
        let deg_b = poly_degree(&b);
        let len_q = deg_a.saturating_sub(deg_b) + 1;
        let len_r = deg_b + 1;

        let mut q = vec![Belt::zero(); len_q];
        let mut r = vec![Belt::zero(); len_r];

        bpdvr(&a, &b, &mut q, &mut r);

        a = b;
        b = r;

        let mut res_u = vec![Belt::zero(); q.len() + m1_u.len()];
        bpmul(&q, &m1_u, &mut res_u);
        let mut next_u = vec![Belt::zero(); cmp::max(res_u.len(), m2_u.len())];
        bpsub(&m2_u, &res_u, &mut next_u);
        m2_u = m1_u;
        m1_u = next_u;

        let mut res_v = vec![Belt::zero(); q.len() + m1_v.len()];
        bpmul(&q, &m1_v, &mut res_v);
        let mut next_v = vec![Belt::zero(); cmp::max(res_v.len(), m2_v.len())];
        bpsub(&m2_v, &res_v, &mut next_v);
        m2_v = m1_v;
        m1_v = next_v;
    }

    d[..a.len()].copy_from_slice(&a);
    u[..m2_u.len()].copy_from_slice(&m2_u);
    v[..m2_v.len()].copy_from_slice(&m2_v);
}

#[inline(always)]
fn poly_degree(poly: &[Belt]) -> usize {
    let mut idx = poly.len();
    while idx > 0 {
        if !poly[idx - 1].is_zero() {
            return idx - 1;
        }
        idx -= 1;
    }
    0
}

#[inline(always)]
fn poly_is_zero(poly: &[Belt]) -> bool {
    poly.iter().all(|x| x.is_zero())
}

/// TIP5 permutation over the Goldilocks field
pub fn tip5_permute(state: &mut [u64; STATE_SIZE]) {
    for round in 0..NUM_ROUNDS {
        let a = sbox_layer(state);
        let b = linear_layer(&a);
        for j in 0..STATE_SIZE {
            let rc = (((ROUND_CONSTANTS[round * STATE_SIZE + j] as u128) * R) % PRIME_128) as u64;
            state[j] = badd(rc, b[j]);
        }
    }
}

fn sbox_layer(state: &[u64; STATE_SIZE]) -> [u64; STATE_SIZE] {
    let mut res = [0u64; STATE_SIZE];
    for i in 0..NUM_SPLIT_AND_LOOKUP {
        let mut bytes = state[i].to_le_bytes();
        for b in &mut bytes {
            *b = LOOKUP_TABLE[*b as usize];
        }
        res[i] = u64::from_le_bytes(bytes);
    }
    for j in NUM_SPLIT_AND_LOOKUP..STATE_SIZE {
        res[j] = bpow(state[j], 7);
    }
    res
}

fn linear_layer(state: &[u64; STATE_SIZE]) -> [u64; STATE_SIZE] {
    let mut result = [0u64; STATE_SIZE];
    for i in 0..STATE_SIZE {
        for j in 0..STATE_SIZE {
            let coeff = MDS_MATRIX_I64[i][j] as u64;
            result[i] = badd(result[i], bmul(coeff, state[j]));
        }
    }
    result
}

/// Round constants for TIP5 permutation
const ROUND_CONSTANTS: [u64; NUM_ROUNDS * STATE_SIZE] = [
    1332676891236936200,
    16607633045354064669,
    12746538998793080786,
    15240351333789289931,
    10333439796058208418,
    986873372968378050,
    153505017314310505,
    703086547770691416,
    8522628845961587962,
    1727254290898686320,
    199492491401196126,
    2969174933639985366,
    1607536590362293391,
    16971515075282501568,
    15401316942841283351,
    14178982151025681389,
    2916963588744282587,
    5474267501391258599,
    5350367839445462659,
    7436373192934779388,
    12563531800071493891,
    12265318129758141428,
    6524649031155262053,
    1388069597090660214,
    3049665785814990091,
    5225141380721656276,
    10399487208361035835,
    6576713996114457203,
    12913805829885867278,
    10299910245954679423,
    12980779960345402499,
    593670858850716490,
    12184128243723146967,
    1315341360419235257,
    9107195871057030023,
    4354141752578294067,
    8824457881527486794,
    14811586928506712910,
    7768837314956434138,
    2807636171572954860,
    9487703495117094125,
    13452575580428891895,
    14689488045617615844,
    16144091782672017853,
    15471922440568867245,
    17295382518415944107,
    15054306047726632486,
    5708955503115886019,
    9596017237020520842,
    16520851172964236909,
    8513472793890943175,
    8503326067026609602,
    9402483918549940854,
    8614816312698982446,
    7744830563717871780,
    14419404818700162041,
    8090742384565069824,
    15547662568163517559,
    17314710073626307254,
    10008393716631058961,
    14480243402290327574,
    13569194973291808551,
    10573516815088946209,
    15120483436559336219,
    3515151310595301563,
    1095382462248757907,
    5323307938514209350,
    14204542692543834582,
    12448773944668684656,
    13967843398310696452,
    14838288394107326806,
    13718313940616442191,
    15032565440414177483,
    13769903572116157488,
    17074377440395071208,
    16931086385239297738,
    8723550055169003617,
    590842605971518043,
    16642348030861036090,
    10708719298241282592,
    12766914315707517909,
    11780889552403245587,
    113183285481780712,
    9019899125655375514,
    3300264967390964820,
    12802381622653377935,
    891063765000023873,
    15939045541699412539,
    3240223189948727743,
    4087221142360949772,
    10980466041788253952,
    18199914337033135244,
    7168108392363190150,
    16860278046098150740,
    13088202265571714855,
    4712275036097525581,
    16338034078141228133,
    1455012125527134274,
    5024057780895012002,
    9289161311673217186,
    9401110072402537104,
    11919498251456187748,
    4173156070774045271,
    15647643457869530627,
    15642078237964257476,
    1405048341078324037,
    3059193199283698832,
    1605012781983592984,
    7134876918849821827,
    5796994175286958720,
    7251651436095127661,
    4565856221886323991,
];
