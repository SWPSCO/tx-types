use super::{split_words, SESSION};
use sha2::{Digest, Sha512};
use tx_types::crypto::vanity::{derive_mnemonic, encode_pkh, key_json, Mnemonic};
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
pub(super) struct GpuMnemonic {
    next: Option<Zeroizing<[u8; 32]>>,
    prepared: Vec<Zeroizing<[u8; 32]>>,
    input: Zeroizing<Vec<u32>>,
}

/// Start mnemonic GPU batches from the 256 entropy bits written to seed_ptr.
#[no_mangle]
pub extern "C" fn mnemonic_gpu_start() -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        s.gpu_mnemonic = GpuMnemonic::default();
        let entropy = Zeroizing::new(*s.seed_input);
        s.seed_input.zeroize();
        s.output.zeroize();
        if s.prefix.is_none() {
            return 0;
        }
        s.gpu_mnemonic.next = Some(entropy);
        1
    })
}

fn hmac_key(mnemonic: &Mnemonic) -> Zeroizing<[u8; 128]> {
    let mut sentence = Zeroizing::new([0u8; 215]);
    let mut length = 0;
    for (index, word) in mnemonic.words().enumerate() {
        if index != 0 {
            sentence[length] = b' ';
            length += 1;
        }
        sentence[length..length + word.len()].copy_from_slice(word.as_bytes());
        length += word.len();
    }
    let mut key = Zeroizing::new([0; 128]);
    if length > 128 {
        let mut digest = Sha512::digest(&sentence[..length]);
        key[..64].copy_from_slice(&digest);
        digest.zeroize();
    } else {
        key[..length].copy_from_slice(&sentence[..length]);
    }
    key
}

/// Prepare up to 4096 independent candidates. Returns the count, zero at entropy
/// exhaustion, or u32::MAX for invalid state/count. Each input is 16 SHA-512
/// words, represented as (low u32, high u32), from the padded HMAC key block.
#[no_mangle]
pub extern "C" fn mnemonic_gpu_prepare(count: usize) -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        let batch = &mut s.gpu_mnemonic;
        batch.prepared.clear();
        batch.input.zeroize();
        if !(1..=4096).contains(&count) {
            return u32::MAX;
        }
        // Grow only while empty/erased so reallocations cannot leave copies of
        // live entropy or HMAC key blocks in abandoned allocations.
        batch.prepared.reserve(count);
        batch.input.reserve(count * 32);
        for _ in 0..count {
            let Some(mut entropy) = batch.next.take() else {
                break;
            };
            let mnemonic = Mnemonic::from_entropy(entropy.as_ref()).expect("256-bit entropy");
            let key = hmac_key(&mnemonic);
            for word in key.chunks_exact(8) {
                let value = u64::from_be_bytes(word.try_into().unwrap());
                batch
                    .input
                    .extend_from_slice(&[value as u32, (value >> 32) as u32]);
            }
            batch.prepared.push(Zeroizing::new(*entropy));
            for byte in entropy.iter_mut().rev() {
                let (next, carry) = byte.overflowing_add(1);
                *byte = next;
                if !carry {
                    batch.next = Some(entropy);
                    break;
                }
            }
        }
        batch.prepared.len() as u32
    })
}

#[no_mangle]
pub extern "C" fn mnemonic_gpu_input_ptr() -> *const u32 {
    SESSION.with(|s| s.borrow().gpu_mnemonic.input.as_ptr())
}

#[no_mangle]
pub extern "C" fn mnemonic_gpu_clear_input() {
    SESSION.with(|s| s.borrow_mut().gpu_mnemonic.input.zeroize());
}

fn candidate(lane: usize, verify: bool) -> u32 {
    SESSION.with(|cell| {
        let mut s = cell.borrow_mut();
        s.output.zeroize();
        let Some(entropy) = s.gpu_mnemonic.prepared.get(lane) else {
            return 0;
        };
        let mnemonic = Mnemonic::from_entropy(entropy.as_ref()).expect("256-bit entropy");
        let key = derive_mnemonic(&mnemonic);
        if verify {
            let Some(prefix) = s.prefix else {
                return 0;
            };
            if !prefix.matches(&encode_pkh(key.pkh)) {
                return 0;
            }
            let json = key_json(&key, Some(&mnemonic));
            s.output.extend_from_slice(json.as_bytes());
        }
        split_words(
            key.public_key
                .0
                .into_iter()
                .chain(key.public_key.1)
                .chain(key.pkh),
            &mut s.reference,
        );
        1
    })
}

/// CPU reference for device self-tests. Returns public data in reference_ptr.
#[no_mangle]
pub extern "C" fn mnemonic_gpu_reference(lane: usize) -> u32 {
    candidate(lane, false)
}

/// Re-derive the selected phrase on CPU, check the prefix, and export its backup.
#[no_mangle]
pub extern "C" fn mnemonic_gpu_verify(lane: usize) -> u32 {
    candidate(lane, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{clear, output_len, reset};

    #[test]
    fn prepared_candidates_resume_and_restore_after_input_is_erased() {
        reset(1);
        assert_eq!(mnemonic_gpu_start(), 0);
        let entropy = [0x42; 32];
        let mut target = entropy;
        target[31] += 2;
        let mnemonic = Mnemonic::from_entropy(&target).unwrap();
        let address = encode_pkh(derive_mnemonic(&mnemonic).pkh);
        assert_eq!(crate::tests::prefix(address.as_str(), false), 1);
        SESSION.with(|s| *s.borrow_mut().seed_input = entropy);
        assert_eq!(mnemonic_gpu_start(), 1);
        assert_eq!(mnemonic_gpu_prepare(0), u32::MAX);
        assert_eq!(mnemonic_gpu_prepare(2), 2);
        assert_eq!(mnemonic_gpu_verify(0), 0);
        assert_eq!(mnemonic_gpu_prepare(1), 1);
        mnemonic_gpu_clear_input();
        assert_eq!(mnemonic_gpu_verify(1), 0);
        assert_eq!(mnemonic_gpu_verify(0), 1);
        SESSION.with(|s| {
            let s = s.borrow();
            let json: serde_json::Value = serde_json::from_slice(&s.output).unwrap();
            assert_eq!(json["mnemonic"], mnemonic.to_string());
            assert_eq!(json["pkh"], address.as_str());
            assert!(s.gpu_mnemonic.input.is_empty());
        });
        clear();
        assert_eq!(output_len(), 0);
        assert_eq!(mnemonic_gpu_verify(0), 0);
    }

    #[test]
    fn entropy_exhaustion_returns_a_partial_batch() {
        reset(1);
        crate::tests::prefix("A", false);
        SESSION.with(|s| *s.borrow_mut().seed_input = [255; 32]);
        assert_eq!(mnemonic_gpu_start(), 1);
        assert_eq!(mnemonic_gpu_prepare(8), 1);
        assert_eq!(mnemonic_gpu_prepare(8), 0);
        clear();
    }
}
