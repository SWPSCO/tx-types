use noun_serde::{NounDecode, NounEncode};

use crate::collections::zset::DorTip as ZSetDorTip;
use crate::collections::{ZMap, ZSet};
use crate::generic_noun::UntypedNoun;
use crate::transaction_types::*;

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

impl NoteData {
    /// Compute hashable for note-data
    ///
    /// From Hoon, note-data is a z-map of @tas to *
    pub fn to_hashable(&self) -> Hashable {
        // Use ZMap's to_hashable which properly traverses the tree
        self.map.to_hashable(
            |key| {
                // Convert the string key to a tas atom and create a leaf
                use nockapp::noun::slab::NounSlab;
                use nockapp::utils::make_tas;

                let mut slab: NounSlab = NounSlab::new();
                let tas_atom = make_tas(&mut slab, key);
                slab.set_root(tas_atom.as_noun());
                Hashable::Leaf(slab.jam().to_vec())
            },
            |untyped_noun| {
                // The UntypedNoun already contains jammed bytes
                Hashable::Leaf(untyped_noun.p.to_vec())
            },
        )
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct SeedV1 {
    pub output_source: Option<Source>, // if Some, enforces that output note must have precisely this source
    pub lock_root: Hash,               // merkle root of lock script
    pub note_data: NoteData,           // data to store with note
    pub gift: Coins,                   // asset quantity
    pub parent_hash: Hash, // check that parent hash of every seed is the hash of the parent note
}

impl SeedV1 {
    /// Compute the signature hashable for a V1 seed
    ///
    /// From Hoon (tx-engine-1.hoon lines 350-356):
    /// ```hoon
    /// ++  sig-hashable
    ///   |=  sed=form
    ///   ^-  hashable:tip5
    ///   :*  (hashable-unit:source output-source.sed)
    ///       hash+lock-root.sed
    ///       hash+(hash:note-data note-data.sed)
    ///       leaf+gift.sed
    ///       hash+parent-hash.sed
    ///   ==
    /// ```
    pub fn to_sig_hashable(&self) -> Hashable {
        use crate::hashing::hasher::hash_hashable;

        // Compute output_source hashable
        let output_source_hashable = match &self.output_source {
            None => Hashable::null(),
            Some(source) => Hashable::cell(Hashable::null(), source.to_hashable()),
        };

        // Hash the note_data
        let note_data_hash = hash_hashable(&self.note_data.to_hashable());

        // Build the 5-element structure (quint)
        // Using nested cells: [a [b [c [d e]]]]
        Hashable::cell(
            output_source_hashable,
            Hashable::cell(
                Hashable::Hash(self.lock_root.clone()),
                Hashable::cell(
                    Hashable::Hash(note_data_hash),
                    Hashable::cell(
                        self.gift.to_hashable(),
                        Hashable::Hash(self.parent_hash.clone()),
                    ),
                ),
            ),
        )
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct SeedsV1 {
    pub set: ZSet<SeedV1>,
}

impl SeedsV1 {
    /// Compute the signature hashable for V1 seeds
    ///
    /// From Hoon (tx-engine-1.hoon lines 392-398):
    /// ```hoon
    /// ++  sig-hashable
    ///   |=  =form
    ///   ^-  hashable:tip5
    ///   ?~  form  leaf+form
    ///   :+  (sig-hashable:seed n.form)
    ///     $(form l.form)
    ///   $(form r.form)
    /// ```
    pub fn to_sig_hashable(&self) -> Hashable {
        // Use ZSet's to_hashable method with sig_hashable for each seed
        self.set.to_hashable(|seed| seed.to_sig_hashable())
    }
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
    pub version: u64,
    pub id: Hash,
    pub spends: ZMap<NName, Spend>,
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

/// SpendV0ToV1: Spend a V0 note into V1 notes
///
/// This corresponds to `spend-0:v1:transact` in tx-engine-1.hoon.
/// It uses V0 signatures (ZMap<SchnorrPubkey, SchnorrSignature>) but creates V1 seeds.
#[derive(Debug, Clone, NounDecode)]
pub struct SpendV0ToV1 {
    pub signature: ZMap<SchnorrPubkey, SchnorrSignature>,
    pub seeds: SeedsV1,
    pub fee: Coins,
}

impl SpendV0ToV1 {
    /// Compute the signature hash for a V0-to-V1 spend
    ///
    /// From Hoon (tx-engine-1.hoon lines 638-643):
    /// ```hoon
    /// ++  sig-hash
    ///   |=  =form
    ///   ^-  ^hash
    ///   %-  hash-hashable:tip5
    ///   [(sig-hashable:seeds seeds.form) leaf+fee.form]
    /// ```
    pub fn compute_sig_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;

        let hashable = Hashable::cell(self.seeds.to_sig_hashable(), self.fee.to_hashable());

        hash_hashable(&hashable)
    }

    /// Convert to hashable representation
    ///
    /// From Hoon (tx-engine-1.hoon lines 628-630):
    /// ```hoon
    /// ++  hashable
    ///   |=  =form
    ///   ^-  hashable:tip5
    ///   [(hashable:signature:v0 signature.form) (hashable:seeds seeds.form) leaf+fee.form]
    /// ```
    pub fn to_hashable(&self) -> Hashable {
        // For V0 signatures, we need to traverse the ZMap properly
        let sig_hashable = self.signature.to_hashable(
            |pubkey| Hashable::Hash(pubkey.to_hash()),
            |signature| signature.to_hashable(),
        );

        // For seeds, use the regular hashable (not sig_hashable)
        let seeds_hashable = self.seeds.set.to_hashable(|seed| {
            // Regular hashable for seed (without output_source)
            use crate::hashing::hasher::hash_hashable;
            let note_data_hash = hash_hashable(&seed.note_data.to_hashable());

            Hashable::cell(
                Hashable::Hash(seed.lock_root.clone()),
                Hashable::cell(
                    Hashable::Hash(note_data_hash),
                    Hashable::cell(
                        seed.gift.to_hashable(),
                        Hashable::Hash(seed.parent_hash.clone()),
                    ),
                ),
            )
        });

        Hashable::cell(
            sig_hashable,
            Hashable::cell(seeds_hashable, self.fee.to_hashable()),
        )
    }
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
        self.lock_root == other.lock_root
            && self.parent_hash == other.parent_hash
            && self.gift == other.gift
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
    pub tim: u64,
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
                hash_hashable,
            ),
        )
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct Tim {
    // lockscript timelock
    pub rel: TimelockRange,
    pub abs: TimelockRange,
}

impl Tim {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::cell(
            Hashable::leaf_from_atom(b"tim"),
            Hashable::cell(self.rel.to_hashable(), self.abs.to_hashable()),
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
        Hashable::cell(Hashable::leaf_from_atom(b"brn"), Hashable::null())
    }
}

#[derive(Debug, Clone)]
pub struct LockPrimitive {
    pub header: String,
    pub body: LockPrimitiveBody,
}

use nockapp::AtomExt;

impl NounDecode for LockPrimitive {
    fn from_noun(noun: &nockvm::noun::Noun) -> Result<Self, noun_serde::NounDecodeError> {
        let head = noun
            .as_cell()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?
            .head()
            .as_atom()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedAtom)?
            .into_string()?;
        let body = noun
            .as_cell()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?
            .tail();
        match head.as_str() {
            "pkh" => Ok(LockPrimitive {
                header: head,
                body: LockPrimitiveBody::Pkh(Pkh::from_noun(&body)?),
            }),
            "tim" => Ok(LockPrimitive {
                header: head,
                body: LockPrimitiveBody::Tim(Tim::from_noun(&body)?),
            }),
            "hax" => Ok(LockPrimitive {
                header: head,
                body: LockPrimitiveBody::Hax(Hax::from_noun(&body)?),
            }),
            "brn" => Ok(LockPrimitive {
                header: head,
                body: LockPrimitiveBody::Brn(Brn::from_noun(&body)?),
            }),
            _ => Err(noun_serde::NounDecodeError::InvalidEnumVariant),
        }
    }
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
    pub map: ZMap<Hash, PkhSignatureValue>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct PkhSignatureValue {
    pub pk: SchnorrPubkey,
    pub sig: SchnorrSignature,
}
