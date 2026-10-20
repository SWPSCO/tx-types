//! Exact noun-leaf accounting for transaction fees.

use crate::{Hash, NName, NoteData, SeedV1, Spend, SpendBody, ZMap};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use pokenoun::codec::{Encode, Error};
use pokenoun::{Arena, Noun};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordCountBreakdown {
    pub seed_words: u64,
    pub witness_words: u64,
}

pub fn noun_words(noun: Noun, arena: &Arena) -> Result<u64, Error> {
    let mut pending = vec![noun];
    let mut words = 0u64;
    let mut visited = 0usize;
    while let Some(noun) = pending.pop() {
        visited += 1;
        if visited > 1 << 20 {
            return Err(Error("noun word count exceeds traversal budget"));
        }
        match noun {
            Noun::Atom(_) => words += 1,
            Noun::Cell(id) => {
                let cell = arena.cell(id);
                pending.extend([cell.tail, cell.head]);
            }
        }
    }
    Ok(words)
}

pub fn encoded_words(value: &impl Encode) -> Result<u64, Error> {
    let mut arena = Arena::new();
    let noun = value.encode(&mut arena)?;
    noun_words(noun, &arena)
}

/// Hoon charges the flattened [key value ... ~] reduction, not the map tree.
pub fn note_data_words(note_data: &NoteData) -> Result<u64, Error> {
    note_data
        .map
        .tap()
        .iter()
        .try_fold(1u64, |total, (_, value)| {
            total
                .checked_add(1 + encoded_words(value)?)
                .ok_or(Error("note-data word count overflow"))
        })
}

pub fn spend_witness_words(spend: &Spend) -> Result<u64, Error> {
    match &spend.body {
        SpendBody::V0(spend) => encoded_words(&spend.signature),
        SpendBody::V0ToV1(spend) => encoded_words(&spend.signature),
        SpendBody::V1(spend) => encoded_words(&spend.witness),
    }
}

pub fn witness_words(spends: &ZMap<NName, Spend>) -> Result<u64, Error> {
    spends.tap().iter().try_fold(0u64, |total, (_, spend)| {
        total
            .checked_add(spend_witness_words(spend)?)
            .ok_or(Error("witness word count overflow"))
    })
}

fn seeds(spend: &Spend) -> Vec<SeedV1> {
    match &spend.body {
        SpendBody::V0(_) => Vec::new(),
        SpendBody::V0ToV1(spend) => spend.seeds.set.tap(),
        SpendBody::V1(spend) => spend.seeds.set.tap(),
    }
}

pub fn seed_words(spends: &ZMap<NName, Spend>, merge_by_lock_root: bool) -> Result<u64, Error> {
    let mut total = 0u64;
    let mut merged = BTreeMap::<Hash, NoteData>::new();
    for (_, spend) in spends.tap() {
        for seed in seeds(&spend) {
            if merge_by_lock_root {
                // z-by uni prefers the incoming map's value for an existing key.
                let data = merged
                    .entry(seed.lock_root)
                    .or_insert_with(|| NoteData { map: ZMap::new() });
                for (key, value) in seed.note_data.map.tap() {
                    data.map
                        .try_put(key, value)
                        .map_err(|_| Error("unbased note-data key"))?;
                }
            } else {
                total = total
                    .checked_add(note_data_words(&seed.note_data)?)
                    .ok_or(Error("seed word count overflow"))?;
            }
        }
    }
    for data in merged.values() {
        total = total
            .checked_add(note_data_words(data)?)
            .ok_or(Error("seed word count overflow"))?;
    }
    Ok(total)
}

pub fn transaction_words(
    spends: &ZMap<NName, Spend>,
    merge_by_lock_root: bool,
) -> Result<WordCountBreakdown, Error> {
    Ok(WordCountBreakdown {
        seed_words: seed_words(spends, merge_by_lock_root)?,
        witness_words: witness_words(spends)?,
    })
}

/// A canonical signature map has one empty branch more than entries.
pub fn signature_map_words(signatures: u64, key_words: u64) -> Result<u64, Error> {
    signatures
        .checked_mul(key_words + 16 + 1)
        .and_then(|count| count.checked_add(1))
        .ok_or(Error("signature word count overflow"))
}
