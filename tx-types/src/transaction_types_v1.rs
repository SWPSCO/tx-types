use noun_serde::NounDecode;

use crate::transaction_types::*;
use crate::generic_noun::UntypedNoun;
use crate::collections::{ZSet, ZMap};

#[derive(Debug, Clone, NounDecode, Ord)]
// , PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NNameV1 {
    pub p: Vec<Hash>,
}

#[derive(Debug, Clone, NounDecode, Ord)]
pub struct NNoteV1 {
    pub version: u64,
    pub origin_page: PageNumber,
    pub name: NNameV1,
    pub note_data: NoteData,
    pub assets: Coins,
}

#[derive(Debug, Clone, NounDecode, Ord)]
pub struct SeedV1 {
    pub output_source: Option<Source>, // if Some, enforces that output note must have precisely this source
    pub lock_root: Hash, // merkle root of lock script
    pub note_data: NoteData, // data to store with note
    pub gift: Coins, // asset quantity
    pub parent_hash: Hash, // check that parent hash of every seed is the hash of the parent note
}

#[derive(Debug, Clone, NounDecode, Ord)]
pub struct SeedsV1 {
    pub set: ZSet<SeedV1>,
}

#[derive(Debug, Clone, NounDecode, Ord)]
pub struct TxV1 {
    pub version: u64,
    pub raw_tx: RawTransactionV1,
    pub total_size: u64,
    pub outputs: OutputsV1,
}

#[derive(Debug, Clone, NounDecode, Ord)]
pub struct OutputsV1 {
    pub set: ZSet<OutputV1>,
}

#[derive(Debug, Clone, NounDecode, Ord)]
pub struct OutputV1 {
    pub note: NNoteV1,
    pub seeds: SeedsV1,
}

#[derive(Debug, Clone, NounDecode, Ord)]
pub struct RawTransactionV1 {
    pub id: Hash,                       // tx-id: hash of the transaction
    pub inputs: InputsV1,                 // inputs map
    pub timelock_range: TimelockRange,  // union of valid page-number ranges
    pub total_fees: Coins,              // sum of all fees paid by all inputs
}

#[derive(Debug, Clone, NounDecode, Ord)]
pub struct NoteData {
    pub map: ZMap<String, UntypedNoun>,
}

#[derive(Debug, Clone, NounDecode, Ord)]
pub struct InputsV1 {
    pub value: i64, // placeholder
}