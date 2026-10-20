//! Minimum transaction fees from exact shared word accounting.
use crate::fee::{compute_minimum_fee, FeeBreakdown, FeeInputs};
use crate::word_count::transaction_words;
use crate::{Coins, NName, Spend, ZMap};
use pokenoun::codec::Error;

pub use crate::fee::{BASE_FEE, BYTHOS_PHASE, INPUT_FEE_DIVISOR, MIN_FEE};

pub fn calculate_min_fee(spends: &ZMap<NName, Spend>) -> Coins {
    calculate_min_fee_for_page(spends, BYTHOS_PHASE)
}

pub fn calculate_min_fee_for_page(spends: &ZMap<NName, Spend>, page_num: u64) -> Coins {
    let inputs = FeeInputs {
        seed_words: 0,
        witness_words: 0,
        height: page_num,
        bythos_phase: BYTHOS_PHASE,
        base_fee: BASE_FEE,
        input_fee_divisor: INPUT_FEE_DIVISOR,
        min_fee: MIN_FEE,
    };
    Coins {
        value: calculate_fee(spends, inputs)
            .expect("valid spend noun encoding")
            .minimum_fee,
    }
}

/// Fee rates and activation height come from the caller; word counts come from spends.
pub fn calculate_fee(
    spends: &ZMap<NName, Spend>,
    mut inputs: FeeInputs,
) -> Result<FeeBreakdown, Error> {
    let counts = transaction_words(spends, inputs.height >= inputs.bythos_phase)?;
    inputs.seed_words = counts.seed_words;
    inputs.witness_words = counts.witness_words;
    Ok(compute_minimum_fee(inputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collections::ZSet;
    use crate::generic_noun::UntypedNoun;
    use crate::hashing::Hashable;
    use crate::word_count::{note_data_words, seed_words, witness_words};
    use crate::{Hash, NoteData, SeedV1, SeedsV1, SpendBody, SpendV0ToV1};
    use alloc::{string::ToString, vec, vec::Vec};
    use pokenoun::codec::Encode;
    fn count_note_data_words(data: &NoteData) -> u64 {
        note_data_words(data).unwrap()
    }
    fn count_seed_words_legacy(spends: &ZMap<NName, Spend>) -> u64 {
        seed_words(spends, false).unwrap()
    }
    fn count_seed_words_merged(spends: &ZMap<NName, Spend>) -> u64 {
        seed_words(spends, true).unwrap()
    }
    fn count_witness_words(spends: &ZMap<NName, Spend>) -> u64 {
        witness_words(spends).unwrap()
    }
    fn count_leaves(h: &Hashable) -> u64 {
        match h {
            Hashable::Cell(left, right) => count_leaves(left) + count_leaves(right),
            _ => 1,
        }
    }

    #[test]
    fn test_count_leaves() {
        // Leaf should count as 1
        let leaf = Hashable::Leaf(Vec::new());
        assert_eq!(count_leaves(&leaf), 1);

        // Cell of two leaves should count as 2
        let cell = Hashable::Cell(
            alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
            alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
        );
        assert_eq!(count_leaves(&cell), 2);

        // Nested cell: [[[leaf] leaf] leaf] = 3 leaves
        let nested = Hashable::Cell(
            alloc::boxed::Box::new(Hashable::Cell(
                alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
                alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
            )),
            alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
        );
        assert_eq!(count_leaves(&nested), 3);
    }

    #[test]
    fn test_count_note_data_words_matches_hoon_rep_shape() {
        // Empty note-data: just the terminal ~.
        let empty = NoteData { map: ZMap::new() };
        assert_eq!(count_note_data_words(&empty), 1);

        // One entry: key + value + terminal ~ = 3 words (not the z-map noun's 4).
        let one = note_data(&[("alpha", 1)]);
        assert_eq!(count_note_data_words(&one), 3);

        // Two entries: 2 * (key + atom value) + terminal ~ = 5 words
        // (the z-map noun would count 7).
        let two = note_data(&[("alpha", 1), ("beta", 2)]);
        assert_eq!(count_note_data_words(&two), 5);
    }

    #[test]
    fn test_note_data_words_count_value_cell_leaves() {
        // A cell value contributes one word per leaf of the value noun.
        let mut map = ZMap::new();
        map.put("cell".to_string(), untyped_cell(1, 2));
        let data = NoteData { map };
        assert_eq!(
            count_note_data_words(&data),
            1 /* terminal */ + 1 /* key */ + 2
        );
    }

    #[test]
    fn test_bythos_constants() {
        assert_eq!(BYTHOS_PHASE, 54_000);
        assert_eq!(BASE_FEE, 1u64 << 14);
        assert_eq!(BASE_FEE, 16_384);
        assert_eq!(INPUT_FEE_DIVISOR, 4);
    }

    #[test]
    fn test_min_fee_calculation_empty_spends() {
        let empty_spends = ZMap::new();
        let fee = calculate_min_fee(&empty_spends);
        assert_eq!(fee.value, MIN_FEE);
        assert_eq!(
            calculate_min_fee_for_page(&empty_spends, BYTHOS_PHASE - 1).value,
            MIN_FEE
        );
    }

    #[test]
    fn test_default_fee_calculation_uses_post_bythos_rules() {
        let spends = spends_with_v0_to_v1_seeds(vec![(sample_name(1), Vec::new())]);
        let witness_words = count_witness_words(&spends);

        assert_eq!(
            calculate_min_fee(&spends).value,
            core::cmp::max((witness_words * BASE_FEE) / INPUT_FEE_DIVISOR, MIN_FEE)
        );
    }

    #[test]
    fn test_fee_calculation_merges_note_data_by_lock_root_after_bythos() {
        let lock_root = sample_hash(10);
        let spends = spends_with_v0_to_v1_seeds(vec![
            (
                sample_name(1),
                vec![sample_seed(
                    lock_root.clone(),
                    sample_hash(100),
                    note_data(&[("alpha", 1)]),
                )],
            ),
            (
                sample_name(3),
                vec![sample_seed(
                    lock_root,
                    sample_hash(101),
                    note_data(&[("beta", 2)]),
                )],
            ),
        ]);

        let legacy_seed_words = count_seed_words_legacy(&spends);
        let merged_seed_words = count_seed_words_merged(&spends);
        let witness_words = count_witness_words(&spends);

        assert!(merged_seed_words < legacy_seed_words);

        let pre_fee = calculate_min_fee_for_page(&spends, BYTHOS_PHASE - 1).value;
        let post_fee = calculate_min_fee_for_page(&spends, BYTHOS_PHASE).value;

        assert_eq!(
            pre_fee,
            core::cmp::max((legacy_seed_words + witness_words) * BASE_FEE * 2, MIN_FEE)
        );
        assert_eq!(
            post_fee,
            core::cmp::max(
                (merged_seed_words * BASE_FEE) + ((witness_words * BASE_FEE) / INPUT_FEE_DIVISOR),
                MIN_FEE
            )
        );
        assert!(post_fee < pre_fee);
    }

    fn spends_with_v0_to_v1_seeds(entries: Vec<(NName, Vec<SeedV1>)>) -> ZMap<NName, Spend> {
        let mut spends = ZMap::new();

        for (name, seeds) in entries {
            let mut set = ZSet::new();
            for seed in seeds {
                set.put(seed);
            }

            spends.put(
                name,
                Spend {
                    version: 0,
                    body: SpendBody::V0ToV1(SpendV0ToV1 {
                        signature: ZMap::new(),
                        seeds: SeedsV1 { set },
                        fee: Coins { value: 0 },
                    }),
                },
            );
        }

        spends
    }

    fn note_data(entries: &[(&str, u64)]) -> NoteData {
        let mut map = ZMap::new();
        for (key, value) in entries {
            map.put((*key).to_string(), untyped_atom(*value));
        }
        NoteData { map }
    }

    fn sample_seed(lock_root: Hash, parent_hash: Hash, note_data: NoteData) -> SeedV1 {
        SeedV1 {
            output_source: None,
            lock_root,
            note_data,
            gift: Coins { value: 1 },
            parent_hash,
        }
    }

    fn sample_name(seed: u64) -> NName {
        NName {
            p: vec![sample_hash(seed), sample_hash(seed + 1)],
        }
    }

    fn sample_hash(seed: u64) -> Hash {
        Hash {
            values: [seed, 0, 0, 0, 0],
        }
    }

    fn untyped_atom(value: u64) -> UntypedNoun {
        UntypedNoun {
            p: value.to_jam().unwrap().into(),
        }
    }

    fn untyped_cell(head: u64, tail: u64) -> UntypedNoun {
        UntypedNoun {
            p: (head, tail).to_jam().unwrap().into(),
        }
    }
}
