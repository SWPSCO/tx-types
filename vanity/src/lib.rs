//! Allocation-free raw-key and mnemonic PKH prefix searches.
//!
//! Enable `mnemonic` for BIP39 recovery at path `m` with an empty
//! passphrase, and `export` for private JSON serialization.
//! Browser hosts use the reusable WebGPU/WASM runtime in `vanity/browser`.
//!
//! The host supplies a uniformly random scalar in `1..CHEETAH_N`. Each search
//! walks consecutive scalars with one affine point addition per candidate.
//! Give parallel workers independent random starting scalars. Keep these starts
//! secret: a start and an offset determine every private key in that walk.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

use core::fmt;
pub use zeroize::Zeroizing;

#[cfg(feature = "mnemonic")]
mod mnemonic;
#[cfg(feature = "mnemonic")]
pub use mnemonic::{derive_mnemonic, Mnemonic, MnemonicBatch, MnemonicMatch, MnemonicSearch};

#[cfg(feature = "export")]
mod export;
#[cfg(feature = "export")]
pub use export::{extended_key_json, key_json};

use tx_types::crypto::cheetah_nostd::{
    ch_add, cheetah_pub_from_sk, tip5_hash_words, CheetahPoint, F6lt, G,
};
use tx_types::crypto::goldilocks::{Belt, GOLDILOCKS_P};
use tx_types::crypto::utils_nostd::{be32_lt, is_zero32, CHEETAH_N};

pub const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
pub const MAX_PKH_LEN: usize = 55;
pub type PublicKey = ([u64; 6], [u64; 6]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidSecretKey,
    InvalidPrefix,
    ImpossiblePrefix,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSecretKey => "secret key must be in 1..CHEETAH_N",
            Self::InvalidPrefix => {
                "prefix must contain 1 to 55 characters supported by the matching mode"
            }
            Self::ImpossiblePrefix => "prefix is outside the canonical PKH encoding range",
        })
    }
}

/// Prefix matching rules shared by CPU, WASM, and WebGPU runners.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MatchMode {
    #[default]
    Exact,
    /// Ignore ASCII case and match a/4, b/8, e/3, i/1, l/1, o/0, s/5, t/7, z/2.
    /// The i and l letter groups remain distinct; only the digit 1 matches both.
    Insensitive,
}

impl MatchMode {
    fn normalize(self, byte: u8) -> u8 {
        if self == Self::Exact {
            return byte;
        }
        match byte.to_ascii_lowercase() {
            b'4' => b'a',
            b'8' => b'b',
            b'3' => b'e',
            b'0' => b'o',
            b'5' => b's',
            b'7' => b't',
            b'2' => b'z',
            other => other,
        }
    }

    fn accepts(self, pattern: u8, candidate: u8) -> bool {
        let a = self.normalize(pattern);
        let b = self.normalize(candidate);
        a == b
            || (self == Self::Insensitive
                && ((a == b'1' && matches!(b, b'i' | b'l'))
                    || (b == b'1' && matches!(a, b'i' | b'l'))))
    }
}

/// Prefix of the canonical Base58 PKH, not the public key.
#[derive(Clone, Copy)]
pub struct Prefix {
    bytes: [u8; MAX_PKH_LEN],
    len: usize,
    mode: MatchMode,
}

impl Prefix {
    pub fn new(text: &str) -> Result<Self, Error> {
        Self::with_mode(text, MatchMode::Exact)
    }

    pub fn with_mode(text: &str, mode: MatchMode) -> Result<Self, Error> {
        let input = text.as_bytes();
        if input.is_empty()
            || input.len() > MAX_PKH_LEN
            || !input.iter().all(|&b| {
                BASE58_ALPHABET
                    .iter()
                    .any(|&candidate| mode.accepts(b, candidate))
            })
        {
            return Err(Error::InvalidPrefix);
        }
        let mut bytes = [0; MAX_PKH_LEN];
        for (dest, &source) in bytes.iter_mut().zip(input) {
            *dest = mode.normalize(source);
        }
        let prefix = Self {
            bytes,
            len: input.len(),
            mode,
        };
        // A nonzero integer cannot have a leading '1'. Find the smallest
        // matching numeral to check the 55-character upper bound as well.
        let mut smallest = [0; MAX_PKH_LEN];
        for i in 0..prefix.len {
            let candidate = BASE58_ALPHABET
                .iter()
                .copied()
                .find(|&b| !(i == 0 && prefix.len > 1 && b == b'1') && mode.accepts(bytes[i], b));
            let Some(candidate) = candidate else {
                return Err(Error::ImpossiblePrefix);
            };
            smallest[i] = candidate;
        }
        if prefix.len == MAX_PKH_LEN
            && smallest.as_slice() > encode_pkh([GOLDILOCKS_P - 1; 5]).as_str().as_bytes()
        {
            return Err(Error::ImpossiblePrefix);
        }
        Ok(prefix)
    }

    pub fn matches(&self, address: &EncodedPkh) -> bool {
        let address = address.as_str().as_bytes();
        address.len() >= self.len
            && address
                .iter()
                .zip(&self.bytes[..self.len])
                .all(|(&candidate, &pattern)| self.mode.accepts(pattern, candidate))
    }

    /// Allowed Base58 digit indices at each position, low 32 bits then high 26.
    /// Zero masks terminate the prefix. GPU consumers use the same compiled
    /// matching rules without duplicating case or substitution logic.
    pub fn digit_masks(&self) -> [[u32; 2]; MAX_PKH_LEN] {
        let mut masks = [[0; 2]; MAX_PKH_LEN];
        for (i, mask) in masks[..self.len].iter_mut().enumerate() {
            for (digit, &byte) in BASE58_ALPHABET.iter().enumerate() {
                if self.mode.accepts(self.bytes[i], byte) {
                    mask[digit / 32] |= 1 << (digit % 32);
                }
            }
        }
        masks
    }
}

/// Fixed-capacity canonical Base58 address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedPkh {
    bytes: [u8; MAX_PKH_LEN],
    start: usize,
}

impl EncodedPkh {
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[self.start..]).expect("Base58 is ASCII")
    }
}

impl fmt::Display for EncodedPkh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Encode `sum(digest[i] * p^i)` as an integer in Base58, where p is Goldilocks.
/// Digest elements must be less than p. No checksum or fixed-width byte padding
/// is part of this encoding.
pub fn encode_pkh(digest: [u64; 5]) -> EncodedPkh {
    let mut limbs = [0u64; 5];
    for digit in digest.into_iter().rev() {
        assert!(digit < GOLDILOCKS_P, "PKH limb must be a field element");
        let mut carry = digit as u128;
        for limb in &mut limbs {
            let wide = *limb as u128 * GOLDILOCKS_P as u128 + carry;
            *limb = wide as u64;
            carry = wide >> 64;
        }
        debug_assert_eq!(carry, 0);
    }
    let mut out = EncodedPkh {
        bytes: [0; MAX_PKH_LEN],
        start: MAX_PKH_LEN,
    };
    loop {
        let mut remainder = 0u128;
        for limb in limbs.iter_mut().rev() {
            let wide = (remainder << 64) | *limb as u128;
            *limb = (wide / 58) as u64;
            remainder = wide % 58;
        }
        out.start -= 1;
        out.bytes[out.start] = BASE58_ALPHABET[remainder as usize];
        if limbs == [0; 5] {
            return out;
        }
    }
}

/// Hash a finite Cheetah public key in native limb order (least significant
/// coefficient first). Coordinates must be canonical Goldilocks elements.
pub fn pkh_from_public_key(public_key: &PublicKey) -> [u64; 5] {
    // Noun [[x0 x1 x2 x3 x4 x5] [y0 y1 y2 y3 y4 y5] %.n].
    // hash-noun-varlen absorbs leaf count, leaves, then the Dyck tree shape.
    // Hoon %.n is the atom 1. Each six-tuple has five right-nested cells.
    let mut words = [0u64; 38];
    words[0] = 13;
    words[1..7].copy_from_slice(&public_key.0);
    words[7..13].copy_from_slice(&public_key.1);
    words[13] = 1;
    words[14..].copy_from_slice(&[
        0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1,
    ]);
    tip5_hash_words(&words)
}

/// A winning key. Secret bytes are big-endian and zeroized on drop.
/// This type intentionally does not implement Debug or Clone.
pub struct Match {
    pub secret_key_be: Zeroizing<[u8; 32]>,
    pub public_key: PublicKey,
    pub pkh: [u64; 5],
}

pub struct BatchResult {
    pub attempts: u64,
    pub matched: Option<Match>,
    pub exhausted: bool,
}

/// Resumable search state; no entropy, threads, I/O, or heap allocation.
pub struct Search {
    secret_key: Zeroizing<[u8; 32]>,
    point: CheetahPoint,
    exhausted: bool,
}

impl Search {
    /// The caller must use cryptographic entropy to choose a production key.
    pub fn new(secret_key: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        if is_zero32(&secret_key) || !be32_lt(&secret_key, &CHEETAH_N) {
            return Err(Error::InvalidSecretKey);
        }
        let (x, y) = cheetah_pub_from_sk(*secret_key);
        Ok(Self {
            secret_key,
            point: CheetahPoint {
                x: F6lt(x.map(Belt)),
                y: F6lt(y.map(Belt)),
                inf: false,
            },
            exhausted: false,
        })
    }

    /// Test at most `limit` candidates, stopping at a match or the group order.
    /// State points to the next untested scalar after every call.
    pub fn search_batch(&mut self, prefix: &Prefix, limit: u64) -> BatchResult {
        let mut result = BatchResult {
            attempts: 0,
            matched: None,
            exhausted: self.exhausted,
        };
        while result.attempts < limit && !self.exhausted {
            let public_key = (self.point.x.0.map(|v| v.0), self.point.y.0.map(|v| v.0));
            let pkh = pkh_from_public_key(&public_key);
            result.attempts += 1;
            if prefix.matches(&encode_pkh(pkh)) {
                result.matched = Some(Match {
                    secret_key_be: Zeroizing::new(*self.secret_key),
                    public_key,
                    pkh,
                });
            }
            for byte in self.secret_key.iter_mut().rev() {
                let (next, carry) = byte.overflowing_add(1);
                *byte = next;
                if !carry {
                    break;
                }
            }
            self.exhausted = *self.secret_key == CHEETAH_N;
            if !self.exhausted {
                self.point = ch_add(&self.point, &G);
            }
            result.exhausted = self.exhausted;
            if result.matched.is_some() {
                break;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pokenoun::{Arena, Noun};

    fn secret(value: u64) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0; 32]);
        key[24..].copy_from_slice(&value.to_be_bytes());
        key
    }

    fn tuple(arena: &mut Arena, limbs: &[u64]) -> Noun {
        let mut noun = arena.alloc_atom_u64(*limbs.last().unwrap());
        for &limb in limbs[..limbs.len() - 1].iter().rev() {
            let head = arena.alloc_atom_u64(limb);
            noun = arena.alloc_cell(head, noun);
        }
        noun
    }

    #[test]
    fn pkh_matches_hoon_vector_and_generic_noun_hash() {
        let public_key = (
            [
                9323455886065152710,
                8604621052628066076,
                8724446291889705637,
                15913798201200938686,
                6871293856171770838,
                11532431931696133539,
            ],
            [
                10242415564008566488,
                10485181329625226048,
                8639946714446054618,
                4053240175695272783,
                11730999058788639792,
                14820844833610271254,
            ],
        );
        let digest = pkh_from_public_key(&public_key);
        assert_eq!(
            digest,
            [
                0x9f6b_9852_a2ca_6ef0,
                0x7885_9c43_f58e_b268,
                0xb77f_75f3_fe27_9fc5,
                0x0004_4dd0_c6cc_6166,
                0xf8d7_889d_bf3d_eb9f
            ]
        );
        let mut arena = Arena::new();
        let x = tuple(&mut arena, &public_key.0);
        let y = tuple(&mut arena, &public_key.1);
        let inf = arena.alloc_atom_u64(1);
        let tail = arena.alloc_cell(y, inf);
        let noun = arena.alloc_cell(x, tail);
        assert_eq!(digest, pokenoun::hash_noun_varlen(noun, &arena).unwrap());
    }

    #[test]
    fn encoding_matches_integer_reference() {
        use ibig::UBig;
        for digest in [
            [0; 5],
            [1, 0, 0, 0, 0],
            [57, 0, 0, 0, 0],
            [58, 0, 0, 0, 0],
            [256, 0, 0, 0, 0],
            [0, 1, 0, 0, 0],
            [GOLDILOCKS_P - 1; 5],
            [
                0x9f6b_9852_a2ca_6ef0,
                0x7885_9c43_f58e_b268,
                0xb77f_75f3_fe27_9fc5,
                0x0004_4dd0_c6cc_6166,
                0xf8d7_889d_bf3d_eb9f,
            ],
        ] {
            let mut n = UBig::from(0u8);
            for limb in digest.into_iter().rev() {
                n = n * UBig::from(GOLDILOCKS_P) + UBig::from(limb);
            }
            let mut bytes = Vec::new();
            loop {
                let digit = usize::try_from(&n % UBig::from(58u8)).unwrap();
                bytes.push(BASE58_ALPHABET[digit]);
                n /= UBig::from(58u8);
                if n == UBig::from(0u8) {
                    break;
                }
            }
            bytes.reverse();
            assert_eq!(encode_pkh(digest).as_str().as_bytes(), bytes);
            #[cfg(feature = "std")]
            assert_eq!(
                encode_pkh(digest).as_str(),
                tx_types::Hash { values: digest }.to_b58()
            );
        }
        assert_eq!(encode_pkh([0; 5]).as_str(), "1");
        assert_eq!(encode_pkh([58, 0, 0, 0, 0]).as_str(), "21");
    }

    #[test]
    fn prefixes_validate_and_match_case_sensitively() {
        for invalid in ["", "0", "O", "I", "l", "é", "ab cd", &"a".repeat(56)] {
            assert!(matches!(Prefix::new(invalid), Err(Error::InvalidPrefix)));
        }
        for impossible in ["11", "1abc", &"z".repeat(55)] {
            assert!(matches!(
                Prefix::new(impossible),
                Err(Error::ImpossiblePrefix)
            ));
        }
        let address = encode_pkh([9, 0, 0, 0, 0]); // A
        assert!(Prefix::new("A").unwrap().matches(&address));
        assert!(!Prefix::new("a").unwrap().matches(&address));
        assert!(!Prefix::new("AA").unwrap().matches(&address));
        assert!(Prefix::new("1").unwrap().matches(&encode_pkh([0; 5])));
    }

    #[test]
    fn insensitive_matching_keeps_i_and_capital_l_distinct() {
        fn address(text: &str) -> EncodedPkh {
            assert!(text.bytes().all(|b| BASE58_ALPHABET.contains(&b)));
            let mut bytes = [0; MAX_PKH_LEN];
            let start = MAX_PKH_LEN - text.len();
            bytes[start..].copy_from_slice(text.as_bytes());
            EncodedPkh { bytes, start }
        }
        let insensitive = |text| Prefix::with_mode(text, MatchMode::Insensitive).unwrap();
        for pattern in ["I", "i"] {
            assert!(insensitive(pattern).matches(&address("i")));
            assert!(insensitive(pattern).matches(&address("1")));
            assert!(!insensitive(pattern).matches(&address("L")));
        }
        for pattern in ["L", "l"] {
            assert!(insensitive(pattern).matches(&address("L")));
            assert!(insensitive(pattern).matches(&address("1")));
            assert!(!insensitive(pattern).matches(&address("i")));
        }
        for candidate in ["1", "i", "L"] {
            assert!(insensitive("1").matches(&address(candidate)));
        }
        for candidate in ["5a17", "saL7", "S4Lt"] {
            assert!(insensitive("SALT").matches(&address(candidate)));
        }
        assert!(!insensitive("SALT").matches(&address("sai7")));
        assert!(!Prefix::new("SALT").unwrap().matches(&address("5a17")));
        assert!(insensitive("0").matches(&address("o")));
        assert!(insensitive("1abc").matches(&address("LAbC")));
        assert!(Prefix::with_mode("z".repeat(55).as_str(), MatchMode::Insensitive).is_ok());
        assert!(Prefix::with_mode("!", MatchMode::Insensitive).is_err());
    }

    #[test]
    fn gpu_digit_masks_match_cpu_rules_for_every_character() {
        for mode in [MatchMode::Exact, MatchMode::Insensitive] {
            for pattern in 0u8..=127 {
                let text = String::from(pattern as char);
                let Ok(prefix) = Prefix::with_mode(&text, mode) else {
                    continue;
                };
                let masks = prefix.digit_masks();
                for (digit, &candidate) in BASE58_ALPHABET.iter().enumerate() {
                    let address = encode_pkh([digit as u64, 0, 0, 0, 0]);
                    assert_eq!(address.as_str().as_bytes(), &[candidate]);
                    assert_eq!(
                        prefix.matches(&address),
                        masks[0][digit / 32] & (1 << (digit % 32)) != 0
                    );
                }
                assert_eq!(masks[1..], [[0; 2]; MAX_PKH_LEN - 1]);
            }
        }
    }

    #[test]
    fn search_resumes_and_recovers_exact_secret_and_public_key() {
        let mut search = Search::new(secret(1)).unwrap();
        assert_eq!(
            search.search_batch(&Prefix::new("A").unwrap(), 0).attempts,
            0
        );
        for value in 1..=12 {
            let key = secret(value);
            let public_key = cheetah_pub_from_sk(*key);
            let pkh = pkh_from_public_key(&public_key);
            let full = Prefix::new(encode_pkh(pkh).as_str()).unwrap();
            let result = search.search_batch(&full, 1);
            let found = result
                .matched
                .expect("incremental point matches scalar multiplication");
            assert_eq!(result.attempts, 1);
            assert!(!result.exhausted);
            assert_eq!(*found.secret_key_be, *key);
            assert_eq!(found.public_key, public_key);
            assert_eq!(found.pkh, pkh);
            #[cfg(feature = "std")]
            {
                let reference = tx_types::crypto::cheetah::point::cheetah_pub_from_sk(*key);
                assert_eq!(reference, [public_key.0, public_key.1]);
                let pk = tx_types::SchnorrPubkey {
                    x: tx_types::F6LT {
                        values: public_key.0,
                    },
                    y: tx_types::F6LT {
                        values: public_key.1,
                    },
                    inf: false,
                };
                assert_eq!(pk.to_hash().values, found.pkh);
            }
        }
    }

    #[test]
    fn batch_stops_at_match_and_at_scalar_boundary() {
        let target = pkh_from_public_key(&cheetah_pub_from_sk(*secret(4)));
        let prefix = Prefix::new(encode_pkh(target).as_str()).unwrap();
        let mut search = Search::new(secret(1)).unwrap();
        let first = search.search_batch(&prefix, 2);
        assert_eq!(first.attempts, 2);
        assert!(first.matched.is_none());
        let second = search.search_batch(&prefix, 10);
        assert_eq!(second.attempts, 2);
        assert_eq!(*second.matched.unwrap().secret_key_be, *secret(4));

        assert!(matches!(
            Search::new(secret(0)),
            Err(Error::InvalidSecretKey)
        ));
        assert!(matches!(
            Search::new(Zeroizing::new(CHEETAH_N)),
            Err(Error::InvalidSecretKey)
        ));
        assert!(matches!(
            Search::new(Zeroizing::new([255; 32])),
            Err(Error::InvalidSecretKey)
        ));
        let mut last = Zeroizing::new(CHEETAH_N);
        last[31] -= 1;
        let public_key = cheetah_pub_from_sk(*last);
        let prefix = Prefix::new(encode_pkh(pkh_from_public_key(&public_key)).as_str()).unwrap();
        let mut search = Search::new(last).unwrap();
        let batch = search.search_batch(&prefix, 8);
        assert!(batch.exhausted);
        assert!(batch.matched.is_some());
        assert_eq!(batch.attempts, 1);
        let batch = search.search_batch(&prefix, 8);
        assert_eq!(batch.attempts, 0);
        assert!(batch.exhausted);
        assert!(batch.matched.is_none());
    }
}
