use noun_serde::{NounDecode, NounEncode};
use crate::transaction_types::*;
use crate::generic_noun::UntypedNoun;
use crate::collections::{ZSet, ZMap};
use crate::collections::zset::DorTip as ZSetDorTip;
use crate::hashing::hashable::Hashable;
use nockapp::AtomExt;

#[derive(Debug, Clone, NounDecode)]
pub struct NNoteV1 {
    pub version: u64,
    pub origin_page: PageNumber,
    pub name: NName,
    pub note_data: NoteData,
    pub assets: Coins,
}

impl NounEncode for NNoteV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let version = self.version.to_noun(alloc);
        let origin = self.origin_page.to_noun(alloc);
        let name = self.name.to_noun(alloc);
        let data = self.note_data.to_noun(alloc);
        let assets = self.assets.to_noun(alloc);
        T(alloc, &[version, origin, name, data, assets])
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct NoteData {
    pub map: ZMap<String, UntypedNoun>,
}

impl NounEncode for NoteData {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        self.map.to_noun(alloc)
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct SeedV1 {
    pub output_source: Option<Source>,
    pub lock_root: Hash,
    pub note_data: NoteData,
    pub gift: Coins,
    pub parent_hash: Hash,
}

impl NounEncode for SeedV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let output_source = self.output_source.to_noun(alloc);
        let lock = self.lock_root.to_noun(alloc);
        let note_data = self.note_data.to_noun(alloc);
        let gift = self.gift.to_noun(alloc);
        let parent = self.parent_hash.to_noun(alloc);
        T(alloc, &[output_source, lock, note_data, gift, parent])
    }
}

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

#[derive(Debug, Clone, NounDecode)]
pub struct SeedsV1 {
    pub set: ZSet<SeedV1>,
}

impl NounEncode for SeedsV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        self.set.to_noun(alloc)
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct TxV1 {
    pub version: u64,
    pub raw_tx: RawTransactionV1,
    pub total_size: u64,
    pub outputs: OutputsV1,
}

impl NounEncode for TxV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let version = self.version.to_noun(alloc);
        let raw = self.raw_tx.to_noun(alloc);
        let size = self.total_size.to_noun(alloc);
        let outputs = self.outputs.to_noun(alloc);
        T(alloc, &[version, raw, size, outputs])
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct OutputsV1 {
    pub set: ZSet<OutputV1>,
}

impl NounEncode for OutputsV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        self.set.to_noun(alloc)
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct OutputV1 {
    pub note: NNoteV1,
    pub seeds: SeedsV1,
}

impl NounEncode for OutputV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let note = self.note.to_noun(alloc);
        let seeds = self.seeds.to_noun(alloc);
        T(alloc, &[note, seeds])
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
pub struct RawTransactionV1 {
    pub version: u64,
    pub id: Hash,
    pub spends: ZMap<NName, Spend>,
}

impl NounEncode for RawTransactionV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let version = self.version.to_noun(alloc);
        let id = self.id.to_noun(alloc);
        let spends = self.spends.to_noun(alloc);
        T(alloc, &[version, id, spends])
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct InputsV1 {
    pub map: ZMap<NName, InputV1>,
}

impl NounEncode for InputsV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        self.map.to_noun(alloc)
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct InputV1 {
    pub note: NNoteV1,
    pub spend: SpendV1,
}

impl NounEncode for InputV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let note = self.note.to_noun(alloc);
        let spend = self.spend.to_noun(alloc);
        T(alloc, &[note, spend])
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct SpendV1 {
    pub witness: Witness,
    pub seeds: SeedsV1,
    pub fee: Coins,
}

impl NounEncode for SpendV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let witness = self.witness.to_noun(alloc);
        let seeds = self.seeds.to_noun(alloc);
        let fee = self.fee.to_noun(alloc);
        T(alloc, &[witness, seeds, fee])
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

#[derive(Debug, Clone, NounDecode)]
pub struct Witness {
    pub lmp: LockMerkleProof,
    pub pkh: PkhSignature,
    pub hax: ZMap<Hash, UntypedNoun>,
    pub tim: u64,
}

impl NounEncode for Witness {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let lmp = self.lmp.to_noun(alloc);
        let pkh = self.pkh.to_noun(alloc);
        let hax = self.hax.to_noun(alloc);
        let tim = self.tim.to_noun(alloc);
        T(alloc, &[lmp, pkh, hax, tim])
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct LockMerkleProof {
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub merkle_proof: MerkleProof,
}

impl NounEncode for LockMerkleProof {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let cond = self.spend_condition.to_noun(alloc);
        let axis = self.axis.to_noun(alloc);
        let proof = self.merkle_proof.to_noun(alloc);
        T(alloc, &[cond, axis, proof])
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct SpendCondition {
    pub p: Vec<LockPrimitive>,
}

impl SpendCondition {
    pub fn to_hashable(&self) -> Hashable {
        let base = Hashable::leaf_from_atom(&[0]);
        self.p
            .iter()
            .rev()
            .fold(base, |acc, lp| Hashable::cell(lp.to_hashable(), acc))
    }
}

impl NounEncode for SpendCondition {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::{D, T};
        self.p.iter().rev().fold(D(0), |acc, prim| {
            let head = prim.to_noun(alloc);
            T(alloc, &[head, acc])
        })
    }
}

#[derive(Debug, Clone, NounDecode)]
pub enum LockPrimitiveBody {
    Pkh(Pkh),
    Tim(Tim),
    Hax(Hax),
    Brn(Brn),
}

#[derive(Debug, Clone)]
pub struct LockPrimitive {
    pub header: String,
    pub body: LockPrimitiveBody,
}

impl NounDecode for LockPrimitive {
    fn from_noun(noun: &nockvm::noun::Noun) -> Result<Self, noun_serde::NounDecodeError> {
        let head = noun.as_cell()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?
            .head()
            .as_atom()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedAtom)?
            .into_string()?;
        let body = noun.as_cell()
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

impl NounEncode for LockPrimitive {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        use nockapp::utils::make_tas;
        let tag = make_tas(alloc, &self.header).as_noun();
        let value = match &self.body {
            LockPrimitiveBody::Pkh(p) => p.to_noun(alloc),
            LockPrimitiveBody::Tim(t) => t.to_noun(alloc),
            LockPrimitiveBody::Hax(h) => h.to_noun(alloc),
            LockPrimitiveBody::Brn(b) => b.to_noun(alloc),
        };
        T(alloc, &[tag, value])
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

impl NounEncode for Pkh {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let m = self.m.to_noun(alloc);
        let h = self.h.to_noun(alloc);
        T(alloc, &[m, h])
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct Tim {
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

impl NounEncode for Tim {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let rel = self.rel.to_noun(alloc);
        let abs = self.abs.to_noun(alloc);
        T(alloc, &[rel, abs])
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
            Hashable::leaf_from_atom(b"fake"),
        )
    }
}

impl NounEncode for Hax {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        self.set.to_noun(alloc)
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct Brn {
    pub value: u64,
}

impl Brn {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::cell(
            Hashable::leaf_from_atom(b"brn"),
            Hashable::null(),
        )
    }
}

impl NounEncode for Brn {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        self.value.to_noun(alloc)
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct MerkleProof {
    pub root: Hash,
    pub path: Vec<Hash>,
}

impl NounEncode for MerkleProof {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::{D, T};
        let root = self.root.to_noun(alloc);
        let path = self.path.iter().rev().fold(D(0), |acc, hash| {
            let head = hash.to_noun(alloc);
            T(alloc, &[head, acc])
        });
        T(alloc, &[root, path])
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct PkhSignature {
    pub map: ZMap<Hash, PkhSignatureValue>,
}

impl NounEncode for PkhSignature {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        self.map.to_noun(alloc)
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct PkhSignatureValue {
    pub pk: SchnorrPubkey,
    pub sig: SchnorrSignature,
}

impl NounEncode for PkhSignatureValue {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;
        let pk = self.pk.to_noun(alloc);
        let sig = self.sig.to_noun(alloc);
        T(alloc, &[pk, sig])
    }
}