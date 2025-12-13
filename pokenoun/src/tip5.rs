extern crate alloc;

use alloc::vec::Vec;

use crate::arena::{Arena, Noun};

pub const GOLDILOCKS_P: u64 = 0xffff_ffff_0000_0001;

const PRIME_128: u128 = 18446744069414584321;
const STATE_SIZE: usize = 16;
const RATE: usize = 10;
const DIGEST_LENGTH: usize = 5;
const NUM_ROUNDS: usize = 7;
const NUM_SPLIT_AND_LOOKUP: usize = 4;
const R: u128 = 18446744073709551616;

// Montgomery constants for Goldilocks field (see nockchain-math tip5 implementation)
const R2: u64 = 0xffff_fffe_0000_0001;
const R_MOD_P: u64 = 0xffff_ffff;
const RP: u128 = 0xffff_ffff_0000_0001_0000_0000_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tip5Error {
    NotBased,
    BadLength,
}

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

#[inline(always)]
fn based_check(a: u64) -> bool {
    a < GOLDILOCKS_P
}

#[inline(always)]
fn reduce(n: u128) -> u64 {
    reduce_159(n as u64, (n >> 64) as u32, (n >> 96) as u64)
}

#[inline(always)]
fn reduce_159(low: u64, mid: u32, high: u64) -> u64 {
    let (mut low2, carry) = low.overflowing_sub(high);
    if carry {
        low2 = low2.wrapping_add(GOLDILOCKS_P);
    }

    let mut product = (mid as u64) << 32;
    product -= product >> 32;

    let (mut result, carry) = product.overflowing_add(low2);
    if carry {
        result = result.wrapping_sub(GOLDILOCKS_P);
    }

    if result >= GOLDILOCKS_P {
        result -= GOLDILOCKS_P;
    }
    result
}

#[inline(always)]
fn badd(a: u64, b: u64) -> u64 {
    debug_assert!(based_check(a));
    debug_assert!(based_check(b));

    let b = GOLDILOCKS_P.wrapping_sub(b);
    let (r, c) = a.overflowing_sub(b);
    let adj = 0u32.wrapping_sub(c as u32);
    r.wrapping_sub(adj as u64)
}

#[inline(always)]
fn bmul(a: u64, b: u64) -> u64 {
    debug_assert!(based_check(a));
    debug_assert!(based_check(b));
    reduce((a as u128) * (b as u128))
}

#[inline(always)]
fn bpow(mut a: u64, mut b: u64) -> u64 {
    debug_assert!(based_check(a));
    debug_assert!(based_check(b));

    let mut c: u64 = 1;
    if b == 0 {
        return c;
    }

    while b > 1 {
        if b & 1 == 0 {
            a = reduce((a as u128) * (a as u128));
            b /= 2;
        } else {
            c = reduce((c as u128) * (a as u128));
            a = reduce((a as u128) * (a as u128));
            b = (b - 1) / 2;
        }
    }
    reduce((c as u128) * (a as u128))
}

fn sbox_layer(state: &[u64; STATE_SIZE]) -> [u64; STATE_SIZE] {
    let mut res: [u64; STATE_SIZE] = [0; STATE_SIZE];

    for i in 0..NUM_SPLIT_AND_LOOKUP {
        let mut bytes = state[i].to_le_bytes();
        for byte in bytes.iter_mut() {
            *byte = LOOKUP_TABLE[*byte as usize];
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
            let matrix_element = MDS_MATRIX_I64[i][j] as u64;
            let product = bmul(matrix_element, state[j]);
            result[i] = badd(result[i], product);
        }
    }

    result
}

fn tip5_permute(sponge: &mut [u64; 16]) {
    for i in 0..NUM_ROUNDS {
        let a = sbox_layer(&*sponge);
        let b = linear_layer(&a);

        for j in 0..STATE_SIZE {
            let r_cons = (((ROUND_CONSTANTS[i * STATE_SIZE + j] as u128) * R) % PRIME_128) as u64;
            sponge[j] = badd(r_cons, b[j]);
        }
    }
}

#[inline(always)]
fn mont_reduction(x: u128) -> u64 {
    debug_assert!(x < RP);
    let x1: u128 = (x >> 32) & 0xffff_ffff;
    let x2: u128 = x >> 64;
    let c: u128 = {
        let x0: u128 = x & 0xffff_ffff;
        (x0 + x1) << 32
    };
    let f: u128 = c >> 64;
    let d: u128 = c - (x1 + (f * (GOLDILOCKS_P as u128)));
    if x2 >= d {
        (x2 - d) as u64
    } else {
        (x2 + (GOLDILOCKS_P as u128) - d) as u64
    }
}

#[inline(always)]
fn montify(x: u64) -> u64 {
    debug_assert!(x < GOLDILOCKS_P);
    mont_reduction((x as u128) * (R2 as u128))
}

#[inline(always)]
fn is_based(x: u64) -> bool {
    x < GOLDILOCKS_P
}

fn create_init_sponge_variable() -> [u64; STATE_SIZE] {
    [0u64; STATE_SIZE]
}

fn create_init_sponge_fixed() -> [u64; STATE_SIZE] {
    [
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
        R_MOD_P,
        R_MOD_P,
        R_MOD_P,
        R_MOD_P,
        R_MOD_P,
        R_MOD_P,
    ]
}

#[inline(always)]
fn tip5_absorb_rate(sponge: &mut [u64; STATE_SIZE], input: &[u64; RATE]) {
    sponge[..RATE].copy_from_slice(input);
    tip5_permute(sponge);
}

fn tip5_pad(words: &mut Vec<u64>, r: usize) {
    words.push(1);
    for _ in 0..((RATE - r) - 1) {
        words.push(0);
    }
}

fn tip5_montify(words: &mut [u64]) -> Result<(), Tip5Error> {
    for w in words.iter_mut() {
        if !is_based(*w) {
            return Err(Tip5Error::NotBased);
        }
        *w = montify(*w);
    }
    Ok(())
}

fn tip5_calc_digest(sponge: &[u64; STATE_SIZE]) -> [u64; DIGEST_LENGTH] {
    let mut digest = [0u64; DIGEST_LENGTH];
    for i in 0..DIGEST_LENGTH {
        digest[i] = mont_reduction(sponge[i] as u128);
    }
    digest
}

/// TIP5 variable-length sponge hash over a Hoon list of belts.
pub fn hash_varlen_words(words: &[u64]) -> Result<[u64; 5], Tip5Error> {
    let mut input = words.to_vec();
    let r = input.len() % RATE;
    tip5_pad(&mut input, r);
    tip5_montify(&mut input)?;

    let q = words.len() / RATE;
    let mut sponge = create_init_sponge_variable();

    let mut idx = 0usize;
    let mut cnt_q = q;
    loop {
        let block: &[u64] = &input[idx..idx + RATE];
        let block_arr: &[u64; RATE] = block.try_into().expect("slice len RATE");
        tip5_absorb_rate(&mut sponge, block_arr);

        idx += RATE;
        if cnt_q == 0 {
            break;
        }
        cnt_q -= 1;
    }

    Ok(tip5_calc_digest(&sponge))
}

/// TIP5 fixed-length hash over exactly 10 belts.
pub fn hash_10_words(words10: &[u64; 10]) -> Result<[u64; 5], Tip5Error> {
    for &w in words10.iter() {
        if !is_based(w) {
            return Err(Tip5Error::NotBased);
        }
    }
    let mut block = *words10;
    tip5_montify(&mut block)?;
    let mut sponge = create_init_sponge_fixed();
    tip5_absorb_rate(&mut sponge, &block);
    Ok(tip5_calc_digest(&sponge))
}

#[inline(always)]
pub fn hash_ten_cell(left: [u64; 5], right: [u64; 5]) -> Result<[u64; 5], Tip5Error> {
    let words10: [u64; 10] = [
        left[0], left[1], left[2], left[3], left[4], right[0], right[1], right[2], right[3],
        right[4],
    ];
    hash_10_words(&words10)
}

fn leaf_sequence(noun: Noun, arena: &Arena, out: &mut Vec<u64>) -> Result<(), Tip5Error> {
    let mut stack: Vec<Noun> = Vec::new();
    stack.push(noun);
    while let Some(n) = stack.pop() {
        match n {
            Noun::Atom(id) => {
                let Some(v) = arena.atom_u64(id) else {
                    return Err(Tip5Error::NotBased);
                };
                if !is_based(v) {
                    return Err(Tip5Error::NotBased);
                }
                out.push(v);
            }
            Noun::Cell(id) => {
                let cell = arena.cell(id);
                // DFS: head then tail => push tail first.
                stack.push(cell.tail);
                stack.push(cell.head);
            }
        }
    }
    Ok(())
}

fn dyck_sequence(noun: Noun, arena: &Arena, out: &mut Vec<u64>) -> Result<(), Tip5Error> {
    enum Frame {
        Node(Noun),
        AfterHead(Noun),
    }

    let mut stack: Vec<Frame> = Vec::new();
    stack.push(Frame::Node(noun));
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Node(n) => match n {
                Noun::Atom(_) => {}
                Noun::Cell(id) => {
                    let cell = arena.cell(id);
                    out.push(0);
                    stack.push(Frame::AfterHead(cell.tail));
                    stack.push(Frame::Node(cell.head));
                }
            },
            Frame::AfterHead(tail) => {
                out.push(1);
                stack.push(Frame::Node(tail));
            }
        }
    }
    Ok(())
}

/// Hash a noun using the TIP5 `hash-noun-varlen` algorithm.
pub fn hash_noun_varlen(noun: Noun, arena: &Arena) -> Result<[u64; 5], Tip5Error> {
    let mut leaf: Vec<u64> = Vec::new();
    let mut dyck: Vec<u64> = Vec::new();
    leaf_sequence(noun, arena, &mut leaf)?;
    dyck_sequence(noun, arena, &mut dyck)?;

    let mut transcript: Vec<u64> = Vec::with_capacity(1 + leaf.len() + dyck.len());
    let size = leaf.len() as u64;
    if !is_based(size) {
        return Err(Tip5Error::NotBased);
    }
    transcript.push(size);
    transcript.extend_from_slice(&leaf);
    transcript.extend_from_slice(&dyck);

    hash_varlen_words(&transcript)
}

