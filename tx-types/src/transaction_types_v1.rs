use noun_serde::{NounDecode, NounEncode};

use crate::transaction_types::*;
use crate::generic_noun::UntypedNoun;
use crate::collections::{ZSet, ZMap};
use crate::collections::zset::DorTip as ZSetDorTip;

use crate::hashing::hashable::Hashable;

/*
#[derive(Debug, Clone, NounDecode, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NNameV1 {
    pub p: Vec<Hash>,
}
    */

#[derive(Debug, Clone, NounDecode)]
pub struct NNoteV1 {
    pub version: u64,
    pub origin_page: PageNumber,
    pub name: NName,
    pub note_data: NoteData,
    pub assets: Coins,
}

#[derive(Debug, Clone, NounDecode)]
pub struct NoteData {
    pub map: ZMap<String, UntypedNoun>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct SeedV1 {
    pub output_source: Option<Source>, // if Some, enforces that output note must have precisely this source
    pub lock_root: Hash, // merkle root of lock script
    pub note_data: NoteData, // data to store with note
    pub gift: Coins, // asset quantity
    pub parent_hash: Hash, // check that parent hash of every seed is the hash of the parent note
}

#[derive(Debug, Clone, NounDecode)]
pub struct SeedsV1 {
    pub set: ZSet<SeedV1>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct TxV1 {
    pub version: u64,
    pub raw_tx: RawTransactionV1,
    pub total_size: u64,
    pub outputs: OutputsV1,
}

#[derive(Debug, Clone, NounDecode)]
pub struct OutputsV1 {
    pub set: ZSet<OutputV1>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct OutputV1 {
    pub note: NNoteV1,
    pub seeds: SeedsV1,
}

#[derive(Debug, Clone, NounDecode)]
pub struct RawTransactionV1 {
    pub id: Hash,                       // tx-id: hash of the transaction
    pub inputs: InputsV1,                 // inputs map
    pub timelock_range: TimelockRange,  // union of valid page-number ranges
    pub total_fees: Coins,              // sum of all fees paid by all inputs
}

#[derive(Debug, Clone, NounDecode)]
pub struct InputsV1 {
    pub map: ZMap<NName, InputV1>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct InputV1 {
    pub note: NNoteV1,
    pub spend: SpendV1,
}

#[derive(Debug, Clone, NounDecode)]
pub struct SpendV1 {
    pub witness: Witness,
    pub seeds: SeedsV1,
    pub fee: Coins,
}
#[derive(Debug, Clone, NounDecode)]
pub struct NNameV1 {
    pub p: Vec<Hash>,
}

impl NounEncode for NNameV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let items: Vec<nockvm::noun::Noun> = self.p.iter().map(|h| h.to_noun(alloc)).collect();
        T(alloc, &items)
    }
}

impl NounEncode for SeedV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        // Minimal, field-stable encoding; precompute parts to avoid borrow conflicts
        let lock = self.lock_root.to_noun(alloc);
        let gift = self.gift.to_noun(alloc);
        let parent = self.parent_hash.to_noun(alloc);
        T(alloc, &[lock, gift, parent])
    }
}

impl NounEncode for OutputV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::D;
        // Minimal placeholder encoding to satisfy trait requirements without deep encoding
        D(0)
    }
}

// Satisfy ZSet bounds without requiring full Ord on nested fields
impl PartialEq for SeedV1 {
    fn eq(&self, other: &Self) -> bool {
        self.lock_root == other.lock_root && self.parent_hash == other.parent_hash && self.gift == other.gift
    }
}

impl ZSetDorTip for SeedV1 {
    fn dor_tip(&self, other: &Self) -> core::cmp::Ordering {
        self.parent_hash.cmp(&other.parent_hash)
    }
}

impl PartialEq for OutputV1 {
    fn eq(&self, other: &Self) -> bool {
        self.note.origin_page == other.note.origin_page
    }
}

impl ZSetDorTip for OutputV1 {
    fn dor_tip(&self, other: &Self) -> core::cmp::Ordering {
        self.note.origin_page.cmp(&other.note.origin_page)
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct Witness {
    pub lmp: LockMerkleProof,
    pub pkh: PkhSignature,
    pub hax: ZMap<Hash, UntypedNoun>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct LockMerkleProof {
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub merkle_proof: MerkleProof,
}

#[derive(Debug, Clone, NounDecode)]
pub struct SpendCondition {
    pub p: Vec<LockPrimitive>,
}

impl SpendCondition {
    pub fn to_hashable(&self) -> Hashable {
        // Start with the required terminator
        let base = Hashable::leaf_from_atom(&[0]);
        // Build: cell(item_1, cell(item_2, cell(..., leaf([0]))))
        self.p
            .iter()
            .rev()
            .fold(base, |acc, lp| Hashable::cell(lp.to_hashable(), acc))
    }
}

#[derive(Debug, Clone, NounDecode)]
pub enum LockPrimitiveBody {
    Pkh(Pkh),
    Tim(Tim),
    Hax(Hax),
    Brn(Brn),
}

#[derive(Debug, Clone, NounDecode)]
pub struct Pkh {
    pub m: u64,
    pub h: ZSet<Hash>,
}

impl Pkh {
    pub fn to_hashable(&self) -> Hashable {
        let hash_hashable = self.h.to_hashable(|h| Hashable::Hash(h.clone()));
        Hashable::cell(
            Hashable::leaf_from_atom(b"pkh"),
            Hashable::cell(
                Hashable::leaf_from_atom(&self.m.to_le_bytes()),
                hash_hashable
            )
        )
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct Tim { // lockscript timelock
    pub rel: TimelockRange,
    pub abs: TimelockRange,
}

impl Tim {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::cell(
            Hashable::leaf_from_atom(b"tim"),
            Hashable::cell(
                self.rel.to_hashable(),
                self.abs.to_hashable(),
            )
        )
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct Hax {
    pub set: ZSet<Hash>,
}

impl Hax {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::cell(
            Hashable::leaf_from_atom(b"hax"),
            Hashable::leaf_from_atom(b"fake"), // TODO
        )
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct Brn {
    pub value: u64, // this will always be 0
}


impl Brn {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::cell(
            Hashable::leaf_from_atom(b"brn"),
            Hashable::null(),
        )
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct LockPrimitive {
    pub header: String,
    pub body: LockPrimitiveBody,
}

impl LockPrimitive {
    pub fn to_hashable(&self) -> Hashable {
        match &self.body {
            LockPrimitiveBody::Pkh(pkh) => pkh.to_hashable(),
            LockPrimitiveBody::Tim(tim) => tim.to_hashable(),
            LockPrimitiveBody::Hax(hax) => hax.to_hashable(),
            LockPrimitiveBody::Brn(brn) => brn.to_hashable(),
        }
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct MerkleProof {
    pub root: Hash,
    pub path: Vec<Hash>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct PkhSignature {
    pub map: ZMap<SchnorrPubkey, SchnorrSignature>,
}