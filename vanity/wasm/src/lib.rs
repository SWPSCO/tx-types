//! Fixed-buffer WASM ABI for the browser's WebGPU runner.
//!
//! JavaScript writes only to `seed_ptr` (32 bytes) and `prefix_ptr` (55 bytes).
//! All other exported pointers are read-only views valid until the next call.
//! Refresh typed-array views after a call: WASM memory can grow. Mnemonic GPU
//! batches expose private HMAC key blocks; callers must erase their copies.

mod mnemonic_gpu;

use std::cell::RefCell;
use tx_types::crypto::cheetah_nostd::cheetah_pub_from_sk;
use tx_types::crypto::utils_nostd::{be32_lt, is_zero32, CHEETAH_N};
use vanity::{
    derive_mnemonic, encode_pkh, extended_key_json, key_json, pkh_from_public_key, Match,
    MatchMode, MnemonicMatch, MnemonicSearch, Prefix, Search,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_LANES: usize = 256;
const POINT_WORDS: usize = 26;

struct Session {
    seed_input: Zeroizing<[u8; 32]>,
    prefix_input: [u8; 55],
    prefix: Option<Prefix>,
    masks: [u32; 110],
    seeds: Vec<Option<Zeroizing<[u8; 32]>>>,
    points: Vec<u32>,
    reference: [u32; 34],
    output: Zeroizing<Vec<u8>>,
    mnemonic: Option<MnemonicSearch>,
    mnemonic_match: Option<MnemonicMatch>,
    gpu_mnemonic: mnemonic_gpu::GpuMnemonic,
    cpu: Option<Search>,
    cpu_total: u32,
    cpu_attempts: u32,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            seed_input: Zeroizing::new([0; 32]),
            prefix_input: [0; 55],
            prefix: None,
            masks: [0; 110],
            seeds: Vec::new(),
            points: Vec::new(),
            reference: [0; 34],
            output: Zeroizing::new(Vec::new()),
            mnemonic: None,
            mnemonic_match: None,
            gpu_mnemonic: mnemonic_gpu::GpuMnemonic::default(),
            cpu: None,
            cpu_total: 0,
            cpu_attempts: 0,
        }
    }
}

thread_local! {
    static SESSION: RefCell<Session> = RefCell::new(Session::default());
}

fn offset_key(key: &[u8; 32], offset: u32) -> Option<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new(*key);
    let mut carry = offset as u64;
    for byte in out.iter_mut().rev() {
        carry += *byte as u64;
        *byte = carry as u8;
        carry >>= 8;
    }
    (carry == 0 && !is_zero32(&out) && be32_lt(&out, &CHEETAH_N)).then_some(out)
}

fn split_words<const N: usize>(words: impl Iterator<Item = u64>, out: &mut [u32; N]) {
    for (word, pair) in words.zip(out.chunks_exact_mut(2)) {
        pair[0] = word as u32;
        pair[1] = (word >> 32) as u32;
    }
}

/// Returns 1 on success, 0 for an invalid lane count. Clears all session keys.
#[no_mangle]
pub extern "C" fn reset(lanes: usize) -> u32 {
    SESSION.with(|cell| {
        let mut session = cell.borrow_mut();
        *session = Session::default();
        if !(1..=MAX_LANES).contains(&lanes) {
            return 0;
        }
        session.seeds.resize_with(lanes, || None);
        session.points.resize(lanes * POINT_WORDS, 0);
        1
    })
}

#[no_mangle]
pub extern "C" fn seed_ptr() -> *mut u8 {
    SESSION.with(|s| s.borrow_mut().seed_input.as_mut_ptr())
}

#[no_mangle]
pub extern "C" fn prefix_ptr() -> *mut u8 {
    SESSION.with(|s| s.borrow_mut().prefix_input.as_mut_ptr())
}

/// Returns 1 for a valid canonical prefix. Clears the selected prefix on error.
#[no_mangle]
pub extern "C" fn set_prefix(len: usize, insensitive: u32) -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        s.prefix = None;
        s.masks.fill(0);
        let mode = match insensitive {
            0 => MatchMode::Exact,
            1 => MatchMode::Insensitive,
            _ => return 0,
        };
        s.prefix = s
            .prefix_input
            .get(..len)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|text| Prefix::with_mode(text, mode).ok());
        if let Some(prefix) = s.prefix {
            for (dest, mask) in s.masks.chunks_exact_mut(2).zip(prefix.digit_masks()) {
                dest.copy_from_slice(&mask);
            }
        }
        u32::from(s.prefix.is_some())
    })
}

#[no_mangle]
pub extern "C" fn masks_ptr() -> *const u32 {
    SESSION.with(|s| s.borrow().masks.as_ptr())
}

/// Rejection sampling: 0 means the caller must draw another seed; 1 accepts it.
/// Reserves u32::MAX offsets below the group order, so GPU walks never wrap.
#[no_mangle]
pub extern "C" fn set_seed(lane: usize) -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        let key = Zeroizing::new(*s.seed_input);
        s.seed_input.zeroize();
        if lane >= s.seeds.len() || is_zero32(&key) || offset_key(&key, u32::MAX).is_none() {
            return 0;
        }
        let public = cheetah_pub_from_sk(*key);
        let mut words = [0; POINT_WORDS];
        split_words(public.0.into_iter().chain(public.1), &mut words);
        s.points[lane * POINT_WORDS..(lane + 1) * POINT_WORDS].copy_from_slice(&words);
        s.seeds[lane] = Some(key);
        1
    })
}

#[no_mangle]
pub extern "C" fn points_ptr() -> *const u32 {
    SESSION.with(|s| s.borrow().points.as_ptr())
}

/// Derive a candidate using the independent Rust path. The 34 returned words
/// are x (12), y (12), and PKH (10), each u64 split low word then high word.
#[no_mangle]
pub extern "C" fn reference_candidate(lane: usize, offset: u32) -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        let Some(Some(seed)) = s.seeds.get(lane) else {
            return 0;
        };
        let Some(key) = offset_key(seed, offset) else {
            return 0;
        };
        let public = cheetah_pub_from_sk(*key);
        let hash = pkh_from_public_key(&public);
        split_words(
            public.0.into_iter().chain(public.1).chain(hash),
            &mut s.reference,
        );
        1
    })
}

#[no_mangle]
pub extern "C" fn reference_ptr() -> *const u32 {
    SESSION.with(|s| s.borrow().reference.as_ptr())
}

/// Start a CPU walk from lane zero, using the shared no_std search core.
#[no_mangle]
pub extern "C" fn cpu_start() -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        s.cpu = None;
        s.cpu_total = 0;
        s.cpu_attempts = 0;
        if s.prefix.is_none() {
            return 0;
        }
        let Some(Some(seed)) = s.seeds.first() else {
            return 0;
        };
        s.cpu = Search::new(Zeroizing::new(**seed)).ok();
        u32::from(s.cpu.is_some())
    })
}

/// Test 1..=256 candidates. Returns 0 (continue), 1 (match), 2 (exhausted),
/// or 3 (invalid state/limit). A bounded batch lets the worker process Stop.
#[no_mangle]
pub extern "C" fn cpu_batch(limit: u32) -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        s.cpu_attempts = 0;
        if !(1..=256).contains(&limit) {
            return 3;
        }
        let Some(prefix) = s.prefix else {
            return 3;
        };
        let limit = limit.min(u32::MAX - s.cpu_total);
        let Some(search) = s.cpu.as_mut() else {
            return 3;
        };
        if limit == 0 {
            return 2;
        }
        let batch = search.search_batch(&prefix, limit as u64);
        s.cpu_attempts = batch.attempts as u32;
        s.cpu_total += s.cpu_attempts;
        if batch.matched.is_some() {
            1
        } else if batch.exhausted || s.cpu_total == u32::MAX {
            2
        } else {
            0
        }
    })
}

#[no_mangle]
pub extern "C" fn cpu_attempts() -> u32 {
    SESSION.with(|s| s.borrow().cpu_attempts)
}

/// Valid after cpu_batch returns 1; pass to verify_match(0, offset).
#[no_mangle]
pub extern "C" fn cpu_match_offset() -> u32 {
    SESSION.with(|s| s.borrow().cpu_total.saturating_sub(1))
}

/// Consume seed_ptr as 256 bits of mnemonic entropy, without scalar rejection.
#[no_mangle]
pub extern "C" fn mnemonic_start() -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        s.mnemonic = None;
        s.mnemonic_match = None;
        s.output.zeroize();
        s.cpu_attempts = 0;
        let entropy = Zeroizing::new(*s.seed_input);
        s.seed_input.zeroize();
        if s.prefix.is_none() {
            return 0;
        }
        s.mnemonic = Some(MnemonicSearch::new(entropy));
        1
    })
}

/// Test one complete mnemonic derivation so the worker can handle cancellation.
/// Status codes match cpu_batch; cpu_attempts returns this call's candidate count.
#[no_mangle]
pub extern "C" fn mnemonic_batch() -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        s.cpu_attempts = 0;
        s.mnemonic_match = None;
        s.output.zeroize();
        let Some(prefix) = s.prefix else {
            return 3;
        };
        let Some(search) = s.mnemonic.as_mut() else {
            return 3;
        };
        let batch = search.search_batch(&prefix, 1);
        s.cpu_attempts = batch.attempts as u32;
        s.mnemonic_match = batch.matched;
        if s.mnemonic_match.is_some() {
            1
        } else if batch.exhausted {
            2
        } else {
            0
        }
    })
}

/// Re-derive the winning phrase before exporting recovery material. The reference
/// buffer receives the verified public point and PKH, with no private data.
#[no_mangle]
pub extern "C" fn mnemonic_verify() -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        s.output.zeroize();
        let Some(prefix) = s.prefix else {
            return 0;
        };
        let Some(found) = &s.mnemonic_match else {
            return 0;
        };
        let key = derive_mnemonic(&found.mnemonic);
        if key.pkh != found.key.pkh
            || *key.secret_key_be != *found.key.secret_key_be
            || !prefix.matches(&encode_pkh(key.pkh))
        {
            return 0;
        }
        let json = key_json(&key, Some(&found.mnemonic));
        split_words(
            key.public_key
                .0
                .into_iter()
                .chain(key.public_key.1)
                .chain(key.pkh),
            &mut s.reference,
        );
        s.output.extend_from_slice(json.as_bytes());
        1
    })
}

/// Verify the prefix from the private scalar, then produce downloadable JSON.
/// Returns zero and clears output for an invalid lane or a false GPU match.
#[no_mangle]
pub extern "C" fn verify_match(lane: usize, offset: u32) -> u32 {
    verify_key(lane, offset, None)
}

/// Consume seed_ptr as a fresh chain code and export a verified match as a zprv.
/// The input is erased on success and failure; the root address is unchanged.
#[no_mangle]
pub extern "C" fn verify_extended_match(lane: usize, offset: u32) -> u32 {
    let chain_code = SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        let chain_code = Zeroizing::new(*s.seed_input);
        s.seed_input.zeroize();
        chain_code
    });
    verify_key(lane, offset, Some(&chain_code))
}

fn verify_key(lane: usize, offset: u32, chain_code: Option<&[u8; 32]>) -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        s.output.zeroize();
        let Some(prefix) = s.prefix else {
            return 0;
        };
        let Some(Some(seed)) = s.seeds.get(lane) else {
            return 0;
        };
        let Some(key) = offset_key(seed, offset) else {
            return 0;
        };
        let public = cheetah_pub_from_sk(*key);
        let hash = pkh_from_public_key(&public);
        let address = encode_pkh(hash);
        if !prefix.matches(&address) {
            return 0;
        }
        let found = Match {
            secret_key_be: key,
            public_key: public,
            pkh: hash,
        };
        let json = match chain_code {
            Some(chain_code) => extended_key_json(&found, chain_code),
            None => key_json(&found, None),
        };
        s.output.extend_from_slice(json.as_bytes());
        1
    })
}

#[no_mangle]
pub extern "C" fn output_ptr() -> *const u8 {
    SESSION.with(|s| s.borrow().output.as_ptr())
}

#[no_mangle]
pub extern "C" fn output_len() -> usize {
    SESSION.with(|s| s.borrow().output.len())
}

/// Erase private session buffers after cancellation or download.
#[no_mangle]
pub extern "C" fn clear() {
    SESSION.with(|s| *s.borrow_mut() = Session::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_export_restores_the_wallet_vector_and_clears_on_reset() {
        use vanity::Mnemonic;
        let phrase = "wedding chef bread absurd leader surge auction access document fiber chunk hurt earn rain swarm cotton leisure ozone drill switch cry jungle soda oxygen";
        // Parsing the known English vector also validates its checksum.
        let mnemonic: Mnemonic = phrase.parse().unwrap();
        let (entropy, len) = mnemonic.to_entropy_array();
        assert_eq!(len, 32);
        reset(1);
        assert_eq!(mnemonic_batch(), 3);
        assert_eq!(mnemonic_verify(), 0);
        assert_eq!(
            prefix(
                "9QnMES6nZnbyqPKfTysvisj1UqvxjSkL4XQaAsMUafGVw2m7rrUHzsW",
                false
            ),
            1
        );
        SESSION.with(|s| s.borrow_mut().seed_input.copy_from_slice(&entropy[..32]));
        assert_eq!(mnemonic_start(), 1);
        SESSION.with(|s| assert_eq!(*s.borrow().seed_input, [0; 32]));
        assert_eq!(mnemonic_batch(), 1);
        assert_eq!(cpu_attempts(), 1);
        assert_eq!(mnemonic_verify(), 1);
        SESSION.with(|s| {
            let s = s.borrow();
            let json: serde_json::Value = serde_json::from_slice(&s.output).unwrap();
            assert_eq!(json["mnemonic"], phrase);
            assert_eq!(json["passphrase"], "");
            assert_eq!(json["derivation_path"], "m");
            let restored = derive_mnemonic(&json["mnemonic"].as_str().unwrap().parse().unwrap());
            assert_eq!(json["pkh"], encode_pkh(restored.pkh).as_str());
            assert_eq!(
                bs58::decode(json["secret_key_base58"].as_str().unwrap())
                    .into_vec()
                    .unwrap(),
                *restored.secret_key_be
            );
        });
        assert_eq!(prefix("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", false), 1);
        assert_eq!(mnemonic_verify(), 0);
        assert_eq!(output_len(), 0);
        clear();
        assert_eq!(mnemonic_batch(), 3);
        assert_eq!(mnemonic_verify(), 0);
    }

    #[test]
    fn extended_match_consumes_chain_code_and_erases_failed_output() {
        reset(1);
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        assert_eq!(seed(scalar), 1);
        let address = encode_pkh(pkh_from_public_key(&cheetah_pub_from_sk(scalar)));
        assert_eq!(prefix(address.as_str(), false), 1);
        SESSION.with(|s| s.borrow_mut().seed_input.fill(7));
        assert_eq!(verify_extended_match(0, 0), 1);
        SESSION.with(|s| {
            let s = s.borrow();
            assert_eq!(*s.seed_input, [0; 32]);
            let json: serde_json::Value = serde_json::from_slice(&s.output).unwrap();
            let payload = bs58::decode(json["zprv"].as_str().unwrap())
                .with_check(None)
                .into_vec()
                .unwrap();
            assert_eq!(&payload[14..46], &[7u8; 32]);
            assert_eq!(&payload[47..], &scalar);
            assert_eq!(json["pkh"], address.as_str());
            assert!(json.get("mnemonic").is_none());
        });
        SESSION.with(|s| s.borrow_mut().seed_input.fill(9));
        assert_eq!(verify_extended_match(0, 1), 0);
        assert_eq!(output_len(), 0);
        SESSION.with(|s| assert_eq!(*s.borrow().seed_input, [0; 32]));
        clear();
    }

    #[test]
    fn cpu_batches_resume_and_produce_a_verified_key() {
        reset(1);
        assert_eq!(cpu_start(), 0);
        assert_eq!(cpu_batch(1), 3);
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(seed(one), 1);
        let mut target = one;
        target[31] = 4;
        let address = encode_pkh(pkh_from_public_key(&cheetah_pub_from_sk(target)));
        assert_eq!(prefix(address.as_str(), false), 1);
        assert_eq!(cpu_start(), 1);
        assert_eq!(cpu_batch(0), 3);
        assert_eq!(cpu_batch(257), 3);
        assert_eq!(cpu_batch(2), 0);
        assert_eq!(cpu_attempts(), 2);
        assert_eq!(cpu_batch(10), 1);
        assert_eq!(cpu_attempts(), 2);
        assert_eq!(cpu_match_offset(), 3);
        assert_eq!(verify_match(0, cpu_match_offset()), 1);
        clear();
        assert_eq!(cpu_batch(1), 3);
    }

    fn seed(bytes: [u8; 32]) -> u32 {
        SESSION.with(|s| *s.borrow_mut().seed_input = bytes);
        set_seed(0)
    }

    pub(super) fn prefix(text: &str, insensitive: bool) -> u32 {
        SESSION
            .with(|s| s.borrow_mut().prefix_input[..text.len()].copy_from_slice(text.as_bytes()));
        set_prefix(text.len(), insensitive as u32)
    }

    #[test]
    fn rejects_invalid_seeds_and_reserves_the_offset_range() {
        assert_eq!(reset(0), 0);
        assert_eq!(reset(MAX_LANES + 1), 0);
        assert_eq!(reset(1), 1);
        assert_eq!(seed([0; 32]), 0);
        assert_eq!(seed(CHEETAH_N), 0);
        assert_eq!(seed([255; 32]), 0);
        let mut near_order = CHEETAH_N;
        near_order[31] -= 1;
        assert_eq!(seed(near_order), 0);
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(seed(one), 1);
        SESSION.with(|s| assert_eq!(*s.borrow().seed_input, [0; 32]));
        assert_eq!(reference_candidate(0, u32::MAX), 1);
        assert_eq!(reference_candidate(1, 0), 0);
        clear();
        assert_eq!(reference_candidate(0, 0), 0);
    }

    #[test]
    fn match_verification_derives_the_key_and_rejects_false_positives() {
        reset(1);
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(seed(one), 1);
        let mut target = one;
        target[31] = 4;
        let public = cheetah_pub_from_sk(target);
        let address = encode_pkh(pkh_from_public_key(&public));
        assert_eq!(prefix(address.as_str(), false), 1);
        assert_eq!(verify_match(0, 2), 0);
        assert_eq!(output_len(), 0);
        assert_eq!(verify_match(0, 3), 1);
        SESSION.with(|s| {
            let s = s.borrow();
            let json: serde_json::Value = serde_json::from_slice(&s.output).unwrap();
            assert_eq!(json["secret_key_hex_be"], format!("{:064x}", 4));
            assert_eq!(json["pkh"], address.as_str());
            assert_eq!(
                bs58::decode(json["secret_key_base58"].as_str().unwrap())
                    .into_vec()
                    .unwrap(),
                target
            );
        });
        assert_eq!(
            prefix(address.as_str().to_ascii_lowercase().as_str(), true),
            1
        );
        assert_eq!(verify_match(0, 3), 1);
        assert_eq!(set_prefix(56, 0), 0);
        assert_eq!(verify_match(0, 3), 0);
        assert_eq!(output_len(), 0);
        clear();
    }

    #[test]
    fn wasm_masks_distinguish_capital_l_from_i() {
        reset(1);
        assert_eq!(prefix("I", false), 0);
        assert_eq!(prefix("I", true), 1);
        SESSION.with(|s| {
            let masks = s.borrow().masks;
            for (digit, &byte) in vanity::BASE58_ALPHABET.iter().enumerate() {
                assert_eq!(
                    masks[digit / 32] & (1 << (digit % 32)) != 0,
                    matches!(byte, b'i' | b'1')
                );
            }
        });
        assert_eq!(set_prefix(1, 2), 0);
        SESSION.with(|s| assert_eq!(s.borrow().masks, [0; 110]));
    }
}
