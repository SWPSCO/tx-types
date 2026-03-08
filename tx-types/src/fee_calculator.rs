//! Transaction Fee Calculator
//!
//! This module implements the current Bythos-aware minimum fee calculation logic for
//! Nockchain transactions.
//!
//! The modern consensus rules are page-aware:
//! - before `BYTHOS_PHASE`, fee accounting uses the legacy 2x base-fee rate
//! - at and after `BYTHOS_PHASE`, the base fee drops to `BASE_FEE`
//! - at and after `BYTHOS_PHASE`, witness inputs are discounted by
//!   `INPUT_FEE_DIVISOR`
//! - at and after `BYTHOS_PHASE`, note-data is charged once per `lock_root`,
//!   matching output construction
//!
//! The canonical implementation lives in `hoon/common/tx-engine.hoon`.

extern crate alloc;

use crate::collections::ZMap;
#[cfg(test)]
use crate::hashing::hashable::Hashable;
use crate::transaction_types::{Coins, Hash, NName, Spend, SpendBody};
use crate::transaction_types_v0::SpendV0;
use crate::transaction_types_v1::{NoteData, SeedV1, SeedsV1, SpendV0ToV1, Witness};
use nockapp::noun::slab::{NockJammer, NounSlab};
use nockvm::noun::Noun;
use noun_serde::NounEncode;

/// Activation height for the Bythos fee and witness-format upgrade.
pub const BYTHOS_PHASE: u64 = 54_000;

/// Base fee per word for witness and note-data storage after Bythos.
pub const BASE_FEE: u64 = 16_384;

/// Inputs pay `1 / INPUT_FEE_DIVISOR` of the output rate at/after Bythos.
pub const INPUT_FEE_DIVISOR: u64 = 4;

/// Minimum fee in nicks (absolute floor)
/// From blockchain-constants: min-fee=256
pub const MIN_FEE: u64 = 256;

const LEGACY_BASE_FEE_MULTIPLIER: u64 = 2;

/// Calculate the minimum required fee for a set of spends using modern mainnet rules.
///
/// For height-sensitive callers, prefer `calculate_min_fee_for_page`.
pub fn calculate_min_fee(spends: &ZMap<NName, Spend>) -> Coins {
    calculate_min_fee_for_page(spends, BYTHOS_PHASE)
}

/// Calculate the minimum required fee for a set of spends at a specific page.
pub fn calculate_min_fee_for_page(spends: &ZMap<NName, Spend>, page_num: u64) -> Coins {
    let bythos_active = page_num >= BYTHOS_PHASE;
    let effective_base_fee = if bythos_active {
        BASE_FEE
    } else {
        BASE_FEE * LEGACY_BASE_FEE_MULTIPLIER
    };

    let seed_word_count = count_seed_words(spends, page_num);
    let witness_word_count = count_witness_words(spends);
    let witness_divisor = if bythos_active { INPUT_FEE_DIVISOR } else { 1 };

    let seed_fee = seed_word_count * effective_base_fee;
    let witness_fee = (witness_word_count * effective_base_fee) / witness_divisor;
    let word_fee = seed_fee + witness_fee;
    let min_fee = core::cmp::max(word_fee, MIN_FEE);

    Coins { value: min_fee }
}

fn count_seed_words(spends: &ZMap<NName, Spend>, page_num: u64) -> u64 {
    if page_num >= BYTHOS_PHASE {
        count_seed_words_merged(spends)
    } else {
        count_seed_words_legacy(spends)
    }
}

fn count_seed_words_legacy(spends: &ZMap<NName, Spend>) -> u64 {
    spends
        .tap()
        .iter()
        .map(|(_name, spend)| match &spend.body {
            SpendBody::V1(body) => count_seeds_v1_words(&body.seeds),
            SpendBody::V0ToV1(body) => count_seeds_v1_words(&body.seeds),
            SpendBody::V0(_) => 0,
        })
        .sum()
}

fn count_seed_words_merged(spends: &ZMap<NName, Spend>) -> u64 {
    let mut note_data_by_lock_root: ZMap<Hash, NoteData> = ZMap::new();

    for (_name, spend) in spends.tap() {
        for seed in v1_seeds(&spend) {
            if let Some(existing) = note_data_by_lock_root.get(&seed.lock_root).cloned() {
                let mut merged = existing.map;
                for (key, value) in seed.note_data.map.tap() {
                    merged.put(key, value);
                }
                note_data_by_lock_root.put(seed.lock_root.clone(), NoteData { map: merged });
            } else {
                note_data_by_lock_root.put(seed.lock_root.clone(), seed.note_data.clone());
            }
        }
    }

    note_data_by_lock_root
        .tap()
        .iter()
        .map(|(_lock_root, note_data)| count_note_data_words(note_data))
        .sum()
}

fn v1_seeds(spend: &Spend) -> Vec<SeedV1> {
    match &spend.body {
        SpendBody::V1(body) => body.seeds.set.tap(),
        SpendBody::V0ToV1(body) => body.seeds.set.tap(),
        SpendBody::V0(_) => Vec::new(),
    }
}

fn count_seeds_v1_words(seeds: &SeedsV1) -> u64 {
    seeds
        .set
        .iter()
        .map(|seed| count_note_data_words(&seed.note_data))
        .sum()
}

fn count_note_data_words(note_data: &NoteData) -> u64 {
    count_leaves_from_encoder(|slab| note_data.to_noun(slab))
}

fn count_witness_words(spends: &ZMap<NName, Spend>) -> u64 {
    spends
        .tap()
        .iter()
        .map(|(_name, spend)| count_spend_witness_words(spend))
        .sum()
}

fn count_spend_witness_words(spend: &Spend) -> u64 {
    match &spend.body {
        SpendBody::V1(body) => count_v1_witness_words(&body.witness),
        SpendBody::V0ToV1(body) => count_v0_to_v1_signature_words(body),
        SpendBody::V0(body) => count_legacy_signature_words(body),
    }
}

fn count_v1_witness_words(witness: &Witness) -> u64 {
    count_leaves_from_encoder(|slab| witness.to_noun(slab))
}

fn count_v0_to_v1_signature_words(spend: &SpendV0ToV1) -> u64 {
    count_leaves_from_encoder(|slab| spend.signature.to_noun(slab))
}

fn count_legacy_signature_words(spend: &SpendV0) -> u64 {
    count_leaves_from_encoder(|slab| spend.signature.to_noun(slab))
}

/// Count the number of leaves in a Hashable tree
///
/// This mirrors the Hoon `num-of-leaves:shape` function.
/// Leaves, Hashes, and Lists each count as 1.
/// Cells recursively sum their left and right subtrees.
#[cfg(test)]
fn count_leaves(h: &Hashable) -> u64 {
    match h {
        // Non-cell cases: Leaf, Hash, and List all count as 1 leaf
        Hashable::Leaf(_) | Hashable::Hash(_) | Hashable::List(_) => 1,
        // Cell case: sum of left and right subtrees
        Hashable::Cell(left, right) => count_leaves(left) + count_leaves(right),
    }
}

fn count_leaves_from_encoder<F>(build: F) -> u64
where
    F: Fn(&mut NounSlab<NockJammer>) -> Noun,
{
    let mut slab = NounSlab::<NockJammer>::new();
    let noun = build(&mut slab);
    count_leaves_from_noun(noun)
}

fn count_leaves_from_noun(noun: Noun) -> u64 {
    if let Ok(cell) = noun.as_cell() {
        count_leaves_from_noun(cell.head()) + count_leaves_from_noun(cell.tail())
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collections::ZSet;
    use crate::generic_noun::UntypedNoun;
    use nockvm::noun::D;

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
            core::cmp::max(
                (legacy_seed_words + witness_words) * BASE_FEE * LEGACY_BASE_FEE_MULTIPLIER,
                MIN_FEE
            )
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
        let mut slab = NounSlab::<NockJammer>::new();
        slab.copy_into(D(value));
        UntypedNoun { p: slab.jam() }
    }
}
