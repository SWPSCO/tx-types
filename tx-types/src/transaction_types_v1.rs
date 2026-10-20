use crate::collections::zset::DorTip as ZSetDorTip;
use crate::collections::{ZMap, ZSet};
use crate::generic_noun::UntypedNoun;
use crate::hashing::tip5::Tip5Error;
use crate::hashing::{hash_hashable, Hashable};
use crate::transaction_types::*;
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use pokenoun::codec::{is_null, pair, Decode, Encode, Error, Fields};
use pokenoun::{Arena, Noun};

// The stub format commits to this fixed digest in place of its axis.
const LOCK_MERKLE_AXIS_HASH: Hash = Hash {
    values: [
        1988594973584463658,
        8158631336633700141,
        2161567007650232260,
        460329990575991155,
        8368574252173164961,
    ],
};

#[derive(Debug, Clone)]
pub struct NNoteV1 {
    pub version: u64,
    pub origin_page: PageNumber,
    pub name: NName,
    pub note_data: NoteData,
    pub assets: Coins,
}

impl NNoteV1 {
    pub fn to_hash(&self) -> Result<Hash, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()?)
    }

    pub fn to_hashable(&self) -> Result<Hashable, Tip5Error> {
        /*
            :*  leaf+version.form
                leaf+origin-page.form
                hash+(hash:nname name.form)
                hash+(hash:note-data note-data.form)
                leaf+assets.form
            ==
        */
        Ok(Hashable::cell_chain([
            Hashable::leaf_from_atom(&self.version.to_le_bytes()),
            self.origin_page.to_hashable(),
            Hashable::Hash(self.name.to_hash()),
            Hashable::Hash(self.note_data.to_hash()?),
            self.assets.to_hashable(),
        ]))
    }
}

#[derive(Debug, Clone)]
pub struct NoteData {
    pub map: ZMap<String, UntypedNoun>,
}

impl NoteData {
    pub fn to_hash(&self) -> Result<Hash, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()?)
    }

    /// Compute hashable for note-data
    ///
    /// From Hoon, note-data is a z-map of @tas to *
    pub fn to_hashable(&self) -> Result<Hashable, Tip5Error> {
        self.map.try_to_hashable(
            |key| Ok(Hashable::leaf_from_tas(key)),
            |value| value.to_hashable(),
        )
    }

    /// Return the canonical note-data noun jam used for hashing/debugging.
    pub fn jam_canonical(&self) -> Vec<u8> {
        self.to_jam().expect("note-data noun encoding")
    }
}

#[derive(Debug, Clone)]
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
    pub fn to_sig_hashable(&self) -> Result<Hashable, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;

        // Compute output_source hashable
        let output_source_hashable = match &self.output_source {
            None => Hashable::null(),
            Some(source) => Hashable::cell_chain([Hashable::null(), source.to_hashable()]),
        };

        // Hash the note_data
        let note_data_hash = hash_hashable(&self.note_data.to_hashable()?)?;

        // Build the 5-element structure (quint)
        // Using nested cells: [a [b [c [d e]]]]
        Ok(Hashable::cell_chain([
            output_source_hashable,
            Hashable::Hash(self.lock_root.clone()),
            Hashable::Hash(note_data_hash),
            self.gift.to_hashable(),
            Hashable::Hash(self.parent_hash.clone()),
        ]))
    }

    /// Compute the regular hashable for a V1 seed (used in spend hashable, not signatures)
    ///
    /// From Hoon (tx-engine-1.hoon lines 344-348):
    /// ```hoon
    /// ++  hashable
    ///   |=  sed=form
    ///   ^-  hashable:tip5
    ///   :^    hash+lock-root.sed
    ///       hash+(hash:note-data note-data.sed)
    ///     leaf+gift.sed
    ///   hash+parent-hash.sed
    /// ```
    pub fn to_regular_hashable(&self) -> Result<Hashable, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;

        // Hash the note_data
        let note_data_hash = hash_hashable(&self.note_data.to_hashable()?)?;

        // Build the 4-element structure (quad): [a b c d]
        // In Hoon, :^ creates a quad which is [a [b [c d]]]
        Ok(Hashable::cell(
            Hashable::Hash(self.lock_root.clone()),
            Hashable::cell(
                Hashable::Hash(note_data_hash),
                Hashable::cell(
                    self.gift.to_hashable(),
                    Hashable::Hash(self.parent_hash.clone()),
                ),
            ),
        ))
    }
}

#[derive(Debug, Clone)]
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
    pub fn to_sig_hashable(&self) -> Result<Hashable, Tip5Error> {
        // Use ZSet's fallible hashable builder with sig_hashable for each seed
        self.set.try_to_hashable(|seed| seed.to_sig_hashable())
    }

    /// Compute the regular hashable for V1 seeds (used in spend hashable, not signatures)
    ///
    /// From Hoon (tx-engine-1.hoon lines 384-390):
    /// ```hoon
    /// ++  hashable
    ///   |=  =form
    ///   ^-  hashable:tip5
    ///   ?~  form  leaf+form
    ///   :+  (hashable:seed n.form)
    ///     $(form l.form)
    ///   $(form r.form)
    /// ```
    pub fn to_hashable(&self) -> Result<Hashable, Tip5Error> {
        // Use ZSet's fallible hashable builder with regular hashable for each seed
        self.set.try_to_hashable(|seed| seed.to_regular_hashable())
    }
}

#[derive(Debug, Clone)]
pub struct TxV1 {
    pub version: u64,
    pub raw_tx: RawTransactionV1,
    pub total_size: u64,
    pub outputs: OutputsV1,
}

#[derive(Debug, Clone)]
pub struct OutputsV1 {
    pub set: ZSet<OutputV1>,
}

#[derive(Debug, Clone)]
pub struct OutputV1 {
    pub note: NNoteV1,
    pub seeds: SeedsV1,
}

#[derive(Debug, Clone)]
pub struct RawTransactionV1 {
    pub version: u64,
    pub id: Hash,
    pub spends: SpendsV1,
}

#[derive(Debug, Clone)]
pub struct SpendsV1 {
    pub map: ZMap<NName, Spend>,
}

impl SpendsV1 {
    pub fn valid_stub_axes(&self, fund_firstname: &Hash) -> bool {
        self.map
            .tap()
            .iter()
            .all(|(name, spend)| match &spend.body {
                SpendBody::V1(spend) => crate::lock::valid_stub_axis(
                    &spend.witness.lmp,
                    name.p.first() == Some(fund_firstname),
                ),
                _ => true,
            })
    }

    /// Compute hashable for spends
    ///
    /// From Hoon (tx-engine-1.hoon lines ~800-806):
    /// ```hoon
    /// ++  hashable
    ///   |=  =form
    ///   ^-  hashable:tip5
    ///   |-
    ///   ?~  form  leaf+form
    ///   :+  [(hashable:nname p.n.form) (hashable:spend q.n.form)]
    ///     $(form l.form)
    ///   $(form r.form)
    /// ```
    pub fn to_hashable(&self) -> Result<Hashable, Tip5Error> {
        self.map
            .try_to_hashable(|name| Ok(name.to_hashable()), |spend| spend.to_hashable())
    }

    /// Compute hash of spends
    ///
    /// From Hoon (tx-engine-1.hoon lines ~808-811):
    /// ```hoon
    /// ++  hash
    ///   |=  =form
    ///   %-  hash-hashable:tip5
    ///   (hashable form)
    /// ```
    pub fn to_hash(&self) -> Result<Hash, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()?)
    }

    /// Return the raw spends noun jam used for hashing/debugging.
    pub fn jam_canonical(&self) -> Vec<u8> {
        self.to_jam().expect("spends noun encoding")
    }
}

fn version_leaf_hashable() -> Hashable {
    Hashable::leaf_from_atom(1u64.to_le_bytes())
}

/// Compute a tx-id from an already computed spends hashable structure.
fn compute_tx_id_from_spends_hashable(spends_hashable: Hashable) -> Result<Hash, Tip5Error> {
    let hashable = Hashable::cell(version_leaf_hashable(), spends_hashable);
    hash_hashable(&hashable)
}

/// Compute the tx-id from an in-memory spends map.
pub fn compute_tx_id_v1(spends: &SpendsV1) -> Result<Hash, Tip5Error> {
    compute_tx_id_from_spends_hashable(spends.to_hashable()?)
}

/// Compute the tx-id from the raw noun representation of the spends map.
#[cfg(feature = "std")]
pub fn compute_tx_id_v1_from_noun(
    spends_noun: nockvm::noun::Noun,
    space: &nockvm::noun::NounSpace,
) -> Result<Hash, Tip5Error> {
    let spends: SpendsV1 = crate::noun_codec::decode_runtime(spends_noun, space)
        .map_err(|error| Tip5Error::InvalidNoun(format!("invalid spends: {error}")))?;
    compute_tx_id_v1(&spends)
}

/// Compute the tx-id directly from the jammed noun bytes of the spends map.
pub fn compute_tx_id_v1_from_jam(spends_jam: &[u8]) -> Result<Hash, Tip5Error> {
    let spends = SpendsV1::from_jam(spends_jam)
        .map_err(|error| Tip5Error::InvalidNoun(format!("invalid spends: {error}")))?;
    compute_tx_id_v1(&spends)
}

#[derive(Debug, Clone)]
pub struct InputsV1 {
    pub map: ZMap<NName, InputV1>,
}

#[derive(Debug, Clone)]
pub struct InputV1 {
    pub note: NNoteV1,
    pub spend: SpendV1,
}

#[derive(Debug, Clone)]
pub struct SpendV1 {
    pub witness: Witness,
    pub seeds: SeedsV1,
    pub fee: Coins,
}

impl SpendV1 {
    /// Compute the signature hash for a V1 spend
    ///
    /// From Hoon (tx-engine-1.hoon lines ~738-742):
    /// ```hoon
    /// ++  sig-hash
    ///   |=  sen=form
    ///   ^-  ^hash
    ///   %-  hash-hashable:tip5
    ///   [(sig-hashable:seeds seeds.sen) leaf+fee.sen]
    /// ```
    pub fn compute_sig_hash(&self) -> Result<Hash, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;

        let hashable = Hashable::cell(self.seeds.to_sig_hashable()?, self.fee.to_hashable());

        hash_hashable(&hashable)
    }

    /// Convert to hashable representation
    ///
    /// From Hoon (tx-engine-1.hoon lines ~756-759):
    /// ```hoon
    /// ++  hashable
    ///   |=  sen=form
    ///   ^-  hashable:tip5
    ///   [(hashable:witness witness.sen) (hashable:seeds seeds.sen) leaf+fee.sen]
    /// ```
    pub fn to_hashable(&self) -> Result<Hashable, Tip5Error> {
        // Build the triple: [witness-hashable seeds-hashable fee-leaf]
        // Note: seeds hashable uses regular hashable, not sig-hashable
        Ok(Hashable::triple(
            self.witness.to_hashable()?,
            self.seeds.to_hashable()?,
            self.fee.to_hashable(),
        ))
    }

    pub fn to_hash(&self) -> Result<Hash, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()?)
    }
}

/// SpendV0ToV1: Spend a V0 note into V1 notes
///
/// This corresponds to `spend-0:v1:transact` in tx-engine-1.hoon.
/// It uses V0 signatures (ZMap<SchnorrPubkey, SchnorrSignature>) but creates V1 seeds.
#[derive(Debug, Clone)]
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
    pub fn compute_sig_hash(&self) -> Result<Hash, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;

        let hashable = Hashable::cell(self.seeds.to_sig_hashable()?, self.fee.to_hashable());

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
    pub fn to_hashable(&self) -> Result<Hashable, Tip5Error> {
        // For V0 signatures, we need to traverse the ZMap properly
        let sig_hashable = self.signature.to_hashable(
            |pubkey| Hashable::Hash(pubkey.to_hash()),
            |signature| signature.to_hashable(),
        );

        // For seeds, use the regular hashable (not sig_hashable)
        let seeds_hashable = self.seeds.to_hashable()?;

        Ok(Hashable::cell(
            sig_hashable,
            Hashable::cell(seeds_hashable, self.fee.to_hashable()),
        ))
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

#[derive(Debug, Clone)]
pub struct Witness {
    pub lmp: LockMerkleProof,
    pub pkh: PkhSignature,
    pub hax: ZMap<Hash, UntypedNoun>,
    pub tim: u64,
}

impl Witness {
    /// Compute hashable for witness
    ///
    /// From Hoon (tx-engine-1.hoon lines ~1184-1191):
    /// ```hoon
    /// ++  hashable
    ///   |=  =form
    ///   ^-  hashable:tip5
    ///   :*  hash+(hash:lock-merkle-proof lmp.form)
    ///       hash+(hash:pkh-signature pkh.form)
    ///       hash+(hash-hashable:tip5 (hashable-hax hax.form))
    ///       leaf+tim.form
    ///   ==
    /// ```
    pub fn to_hashable(&self) -> Result<Hashable, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;

        // Hash the lock merkle proof
        let lmp_hash = self.lmp.to_hash();

        // Hash the pkh signature
        let pkh_hash = self.pkh.to_hash();

        // Hash the hax map
        let hax_hashable = self.hashable_hax()?;
        let hax_hash = hash_hashable(&hax_hashable)?;

        Ok(Hashable::cell_chain([
            Hashable::Hash(lmp_hash),
            Hashable::Hash(pkh_hash),
            Hashable::Hash(hax_hash),
            Hashable::leaf_from_atom(&self.tim.to_le_bytes()),
        ]))
    }

    /// Compute hashable for hax map
    ///
    /// From Hoon (tx-engine-1.hoon lines ~1193-1198):
    /// ```hoon
    /// ++  hashable-hax
    ///   |=  m=(z-map ^hash *)
    ///   ^-  hashable:tip5
    ///   ?~  m  leaf+m
    ///   :+  [hash+p.n.m (hashable-noun q.n.m)]
    ///       $(m l.m)
    ///   $(m r.m)
    /// ```
    fn hashable_hax(&self) -> Result<Hashable, Tip5Error> {
        self.hax.try_to_hashable(
            |hash| Ok(Hashable::Hash(hash.clone())),
            |untyped_noun| {
                // hashable-noun recursively builds cells for cells, leaves for atoms
                // But since UntypedNoun is just jammed bytes, we treat it as a leaf
                untyped_noun.to_hashable()
            },
        )
    }

    pub fn to_hash(&self) -> Result<Hash, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()?)
    }
}

#[derive(Debug, Clone)]
pub struct LockMerkleProofStub {
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub merkle_proof: MerkleProof,
}

#[derive(Debug, Clone)]
pub struct LockMerkleProofFull {
    pub version: u64,
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub merkle_proof: MerkleProof,
}

#[derive(Debug, Clone)]
pub enum LockMerkleProof {
    Full(LockMerkleProofFull),
    Stub(LockMerkleProofStub),
}

impl LockMerkleProof {
    pub fn new_full(spend_condition: SpendCondition, axis: u64, merkle_proof: MerkleProof) -> Self {
        Self::Full(LockMerkleProofFull {
            version: u64::from_le_bytes(*b"full\0\0\0\0"),
            spend_condition,
            axis,
            merkle_proof,
        })
    }

    pub fn new_stub(spend_condition: SpendCondition, axis: u64, merkle_proof: MerkleProof) -> Self {
        Self::Stub(LockMerkleProofStub {
            spend_condition,
            axis,
            merkle_proof,
        })
    }

    pub fn spend_condition(&self) -> &SpendCondition {
        match self {
            Self::Full(proof) => &proof.spend_condition,
            Self::Stub(proof) => &proof.spend_condition,
        }
    }

    pub fn axis(&self) -> u64 {
        match self {
            Self::Full(proof) => proof.axis,
            Self::Stub(proof) => proof.axis,
        }
    }

    pub fn proof(&self) -> &MerkleProof {
        match self {
            Self::Full(proof) => &proof.merkle_proof,
            Self::Stub(proof) => &proof.merkle_proof,
        }
    }

    pub fn merkle_proof(&self) -> &MerkleProof {
        self.proof()
    }

    pub fn version(&self) -> Option<u64> {
        match self {
            Self::Full(proof) => Some(proof.version),
            Self::Stub(_) => None,
        }
    }

    pub fn into_parts(self) -> (SpendCondition, u64, MerkleProof) {
        match self {
            Self::Full(proof) => (proof.spend_condition, proof.axis, proof.merkle_proof),
            Self::Stub(proof) => (proof.spend_condition, proof.axis, proof.merkle_proof),
        }
    }

    /// Compute hashable for lock-merkle-proof using the correct stub/full semantics.
    pub fn to_hashable(&self) -> Hashable {
        use crate::hashing::hasher::hash_hashable;

        let spend_condition_hash = hash_hashable(&self.spend_condition().to_hashable())
            .expect("spend-condition hashable is u64-based");

        match self {
            Self::Full(proof) => Hashable::cell_chain([
                Hashable::leaf_from_atom(&proof.version.to_le_bytes()),
                Hashable::Hash(spend_condition_hash),
                Hashable::leaf_from_atom(&proof.axis.to_le_bytes()),
                proof.merkle_proof.to_hashable(),
            ]),
            Self::Stub(proof) => Hashable::triple(
                Hashable::Hash(spend_condition_hash),
                Hashable::Hash(LOCK_MERKLE_AXIS_HASH.clone()),
                proof.merkle_proof.to_hashable(),
            ),
        }
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()).expect("lock-merkle-proof hashable is u64-based")
    }
}

#[derive(Debug, Clone)]
pub struct SpendCondition {
    pub p: Vec<LockPrimitive>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredPkhPolicy {
    pub threshold: usize,
    pub hashes: Vec<Hash>,
}

impl RequiredPkhPolicy {
    pub fn contains(&self, hash: &Hash) -> bool {
        self.hashes.contains(hash)
    }
}

impl SpendCondition {
    pub fn required_pkh_policy(&self) -> Option<RequiredPkhPolicy> {
        self.p.iter().find_map(|primitive| match &primitive.body {
            LockPrimitiveBody::Pkh(pkh) => Some(RequiredPkhPolicy {
                threshold: usize::try_from(pkh.m).ok()?,
                hashes: pkh.h.tap(),
            }),
            _ => None,
        })
    }

    pub fn to_hashable(&self) -> Hashable {
        // From Hoon (tx-engine-1.hoon lines 1145-1150):
        // ```hoon
        // ++  hashable
        //   |=  =form
        //   ^-  hashable:tip5
        //   ?~  form  leaf+~
        //   :-  (hashable:lock-primitive i.form)
        //   $(form t.form)
        // ```
        // This builds: [hash(first), [hash(second), [hash(third), ... leaf(~)]]]
        // WITHOUT reversing

        // Start with the terminator (empty list = leaf+~)
        let base = Hashable::null();

        // Build from RIGHT to LEFT (so we DON'T reverse the iterator)
        // fold processes left-to-right, but we want [first [second [third ...]]]
        // So we need to fold from the right
        self.p
            .iter()
            .rev() // reverse to process from end
            .fold(base, |acc, lp| Hashable::cell(lp.to_hashable(), acc))
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()).expect("spend-condition hashable is u64-based")
    }
}

#[derive(Debug, Clone)]
pub enum LockPrimitiveBody {
    Pkh(Pkh),
    Tim(Tim),
    Hax(Hax),
    Brn(Brn),
}

#[derive(Debug, Clone)]
pub struct Pkh {
    pub m: u64,
    pub h: ZSet<Hash>,
}

impl Pkh {
    pub fn to_hashable(&self) -> Hashable {
        // From Hoon (tx-engine-1.hoon lines 1442-1455):
        // ++  hashable
        //   |=  =form
        //   |^
        //   [leaf+m.form (hashable-hashes h.form)]
        //
        // NOTE: The tag (%pkh) is NOT included here - it's added by
        // LockPrimitive::to_hashable() which wraps this with [leaf+%pkh ...]
        let hash_hashable = self.h.to_hashable(|h| Hashable::Hash(h.clone()));
        Hashable::cell(
            Hashable::leaf_from_atom(&self.m.to_le_bytes()),
            hash_hashable,
        )
    }
}

#[derive(Debug, Clone)]
pub struct Tim {
    // lockscript timelock
    pub rel: TimelockRange,
    pub abs: TimelockRange,
}

impl Tim {
    pub fn to_hashable(&self) -> Hashable {
        // From Hoon (tx-engine-1.hoon lines 1534-1540):
        // ++  hashable
        //   |=  =form
        //   :-  :-  ?~(min.rel.form %leaf^~ [%leaf^~ leaf+u.min.rel.form])
        //           ?~(max.rel.form %leaf^~ [%leaf^~ leaf+u.max.rel.form])
        //       :-  ?~(min.abs.form %leaf^~ [%leaf^~ leaf+u.min.abs.form])
        //           ?~(max.abs.form %leaf^~ [%leaf^~ leaf+u.max.abs.form])
        //
        // This produces: [[min-rel max-rel] [min-abs max-abs]]
        // NOTE: The tag (%tim) is NOT included here - it's added by
        // LockPrimitive::to_hashable() which wraps this with [leaf+%tim ...]
        Hashable::cell(self.rel.to_hashable(), self.abs.to_hashable())
    }
}

#[derive(Debug, Clone)]
pub struct Hax {
    pub set: ZSet<Hash>,
}

impl Hax {
    pub fn to_hashable(&self) -> Hashable {
        // From Hoon (tx-engine-1.hoon lines 1490-1496):
        // ++  hashable
        //   |=  =form
        //   ?~  form  leaf+~
        //   :*  hash+n.form
        //       $(form l.form)
        //       $(form r.form)
        //   ==
        //
        // This produces a tree of hashes without a tag.
        // NOTE: The tag (%hax) is NOT included here - it's added by
        // LockPrimitive::to_hashable() which wraps this with [leaf+%hax ...]
        self.set.to_hashable(|h| Hashable::Hash(h.clone()))
    }
}

#[derive(Debug, Clone)]
pub struct Brn {
    pub value: u64, // this will always be 0
}

impl Brn {
    pub fn to_hashable(&self) -> Hashable {
        // From Hoon (tx-engine-1.hoon lines 1108-1109):
        // %brn  [leaf+%brn leaf+~]
        //
        // The brn primitive just produces leaf+~ (null).
        // NOTE: The tag (%brn) is NOT included here - it's added by
        // LockPrimitive::to_hashable() which wraps this with [leaf+%brn ...]
        Hashable::null()
    }
}

#[derive(Debug, Clone)]
pub struct LockPrimitive {
    pub header: String,
    pub body: LockPrimitiveBody,
}

impl LockPrimitive {
    pub fn to_hashable(&self) -> Hashable {
        // From Hoon (tx-engine-1.hoon lines 1102-1110):
        // ++  hashable
        //   |=  =form
        //   ^-  hashable:tip5
        //   ?-  -.form
        //       %tim  [leaf+%tim (hashable:tim +.form)]
        //       %hax  [leaf+%hax (hashable:hax +.form)]
        //       %pkh  [leaf+%pkh (hashable:pkh +.form)]
        //       %brn  [leaf+%brn leaf+~]
        //   ==
        // The tag is included as a leaf!
        let (tag, body_hashable) = match &self.body {
            LockPrimitiveBody::Pkh(pkh) => ("pkh", pkh.to_hashable()),
            LockPrimitiveBody::Tim(tim) => ("tim", tim.to_hashable()),
            LockPrimitiveBody::Hax(hax) => ("hax", hax.to_hashable()),
            LockPrimitiveBody::Brn(brn) => ("brn", brn.to_hashable()),
        };
        Hashable::cell(Hashable::leaf_from_tas(tag), body_hashable)
    }
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub root: Hash,
    pub path: Vec<Hash>,
}

impl MerkleProof {
    /// Compute hashable for merkle proof
    ///
    /// From Hoon (tx-engine-1.hoon lines ~1405-1411):
    /// ```hoon
    /// ++  hashable-merk-proof
    ///   |=  =merk-proof:merkle
    ///   ^-  hashable:tip5
    ///   :-  hash+root.merk-proof
    ///   |-  ^-  hashable:tip5
    ///   ?~  path.merk-proof
    ///     leaf+~
    ///   :-  hash+i.path.merk-proof
    ///   $(path.merk-proof t.path.merk-proof)
    /// ```
    pub fn to_hashable(&self) -> Hashable {
        // Start with root hash
        let root_hashable = Hashable::Hash(self.root.clone());

        // Build path as a list: [hash+h1 [hash+h2 [... leaf+~]]]
        let path_hashable = self.path.iter().rev().fold(
            Hashable::null(), // leaf+~ (empty list terminator)
            |acc, hash| Hashable::cell(Hashable::Hash(hash.clone()), acc),
        );

        // Pair root with path
        Hashable::cell(root_hashable, path_hashable)
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()).expect("merkle-proof hashable is u64-based")
    }
}

#[derive(Debug, Clone)]
pub struct PkhSignature {
    pub map: ZMap<Hash, PkhSignatureValue>,
}

impl PkhSignature {
    /// Compute hashable for pkh-signature
    ///
    /// From Hoon (tx-engine-1.hoon lines ~1580-1592):
    /// ```hoon
    /// ++  hashable
    ///   |=  =form
    ///   ^-  hashable:tip5
    ///   |^
    ///   ?~  form  leaf+form
    ///   :+  [hash+p.n.form (hashable-val q.n.form)]
    ///       $(form l.form)
    ///   $(form r.form)
    ///   ::
    ///   ++  hashable-val
    ///     |=  [pk=schnorr-pubkey sig=schnorr-signature]
    ///     ^-  hashable:tip5
    ///     [hash+(hash:schnorr-pubkey pk) (hashable:schnorr-signature sig)]
    ///   --
    /// ```
    pub fn to_hashable(&self) -> Hashable {
        self.map
            .to_hashable(|hash| Hashable::Hash(hash.clone()), |val| val.to_hashable())
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()).expect("pkh-signature hashable is u64-based")
    }
}

#[derive(Debug, Clone)]
pub struct PkhSignatureValue {
    pub pk: SchnorrPubkey,
    pub sig: SchnorrSignature,
}

impl PkhSignatureValue {
    /// Compute hashable for pkh-signature value
    ///
    /// From Hoon (tx-engine-1.hoon lines ~1587-1591):
    /// ```hoon
    /// ++  hashable-val
    ///   |=  [pk=schnorr-pubkey sig=schnorr-signature]
    ///   ^-  hashable:tip5
    ///   [hash+(hash:schnorr-pubkey pk) (hashable:schnorr-signature sig)]
    /// ```
    pub fn to_hashable(&self) -> Hashable {
        // Pair: [hash+(pubkey) hashable(signature)]
        Hashable::cell(Hashable::Hash(self.pk.to_hash()), self.sig.to_hashable())
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()).expect("pkh-signature-value hashable is u64-based")
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use nockapp::noun::slab::NounSlab;
    use nockapp::utils::make_tas;
    use nockvm::noun::NounAllocator;
    use nockvm::noun::{D, T};
    use noun_serde::{NounDecode, NounEncode};

    fn sample_primitive() -> LockPrimitive {
        LockPrimitive {
            header: "brn".to_string(),
            body: LockPrimitiveBody::Brn(Brn { value: 0 }),
        }
    }

    fn sample_spend_condition() -> SpendCondition {
        SpendCondition {
            p: vec![sample_primitive()],
        }
    }

    fn sample_merkle_proof() -> MerkleProof {
        MerkleProof {
            root: Hash {
                values: [1, 2, 3, 4, 5],
            },
            path: vec![Hash {
                values: [6, 7, 8, 9, 10],
            }],
        }
    }

    #[test]
    fn lock_merkle_proof_decodes_full_format() {
        let mut slab: NounSlab = NounSlab::new();
        let primitive = sample_primitive();
        let primitive_noun = primitive.to_noun(&mut slab);
        let spend_condition_noun = T(&mut slab, &[primitive_noun, D(0)]);
        let merkle_proof = sample_merkle_proof();
        let version_noun = make_tas(&mut slab, "full").as_noun();
        let merkle_proof_noun = merkle_proof.to_noun(&mut slab);
        let full_lmp = T(
            &mut slab,
            &[version_noun, spend_condition_noun, D(7), merkle_proof_noun],
        );

        let space = slab.noun_space();
        let decoded =
            LockMerkleProof::from_noun(&full_lmp, &space).expect("full lmp should decode");

        match decoded {
            LockMerkleProof::Full(full) => {
                assert_eq!(full.version, u64::from_le_bytes(*b"full\0\0\0\0"));
                assert_eq!(full.axis, 7);
                assert_eq!(full.spend_condition.p.len(), 1);
                match &full.spend_condition.p[0].body {
                    LockPrimitiveBody::Brn(brn) => assert_eq!(brn.value, 0),
                    other => panic!("expected burn primitive, got {:?}", other),
                }
                assert_eq!(full.merkle_proof.root.values, [1, 2, 3, 4, 5]);
                assert_eq!(full.merkle_proof.path.len(), 1);
                assert_eq!(full.merkle_proof.path[0].values, [6, 7, 8, 9, 10]);
            }
            LockMerkleProof::Stub(_) => panic!("expected full lock merkle proof"),
        }
    }

    #[test]
    fn lock_merkle_proof_round_trips_full_format() {
        let full = LockMerkleProof::new_full(sample_spend_condition(), 7, sample_merkle_proof());
        let mut slab: NounSlab = NounSlab::new();
        let encoded = full.to_noun(&mut slab);

        let space = slab.noun_space();
        let decoded =
            LockMerkleProof::from_noun(&encoded, &space).expect("full lmp should round-trip");

        match decoded {
            LockMerkleProof::Full(full) => {
                assert_eq!(full.version, u64::from_le_bytes(*b"full\0\0\0\0"));
                assert_eq!(full.axis, 7);
                assert_eq!(full.spend_condition.p.len(), 1);
                assert_eq!(full.merkle_proof.root.values, [1, 2, 3, 4, 5]);
                assert_eq!(full.merkle_proof.path.len(), 1);
                assert_eq!(full.merkle_proof.path[0].values, [6, 7, 8, 9, 10]);
            }
            LockMerkleProof::Stub(_) => panic!("expected full lock merkle proof"),
        }
    }

    #[test]
    fn lock_merkle_proof_round_trips_stub_format() {
        let stub = LockMerkleProof::new_stub(sample_spend_condition(), 7, sample_merkle_proof());
        let mut slab: NounSlab = NounSlab::new();
        let encoded = stub.to_noun(&mut slab);

        let space = slab.noun_space();
        let decoded =
            LockMerkleProof::from_noun(&encoded, &space).expect("stub lmp should round-trip");

        match decoded {
            LockMerkleProof::Stub(stub) => {
                assert_eq!(stub.axis, 7);
                assert_eq!(stub.spend_condition.p.len(), 1);
                assert_eq!(stub.merkle_proof.root.values, [1, 2, 3, 4, 5]);
                assert_eq!(stub.merkle_proof.path.len(), 1);
                assert_eq!(stub.merkle_proof.path[0].values, [6, 7, 8, 9, 10]);
            }
            LockMerkleProof::Full(_) => panic!("expected stub lock merkle proof"),
        }
    }

    #[test]
    fn spend_condition_rejects_improper_list_without_panicking() {
        let mut slab: NounSlab = NounSlab::new();
        let primitive = sample_primitive();
        let primitive_noun = primitive.to_noun(&mut slab);
        let malformed_list = T(&mut slab, &[primitive_noun, D(1)]);

        let space = slab.noun_space();
        let err = SpendCondition::from_noun(&malformed_list, &space)
            .expect_err("spend-condition decode should reject improper list");

        assert!(err.to_string().contains("expected cell"));
    }

    #[test]
    fn merkle_proof_rejects_improper_path_without_panicking() {
        let mut slab: NounSlab = NounSlab::new();
        let hash_noun = Hash {
            values: [1, 2, 3, 4, 5],
        }
        .to_noun(&mut slab);
        let malformed = T(&mut slab, &[hash_noun, D(1)]);

        let space = slab.noun_space();
        let err = MerkleProof::from_noun(&malformed, &space)
            .expect_err("merkle proof path should reject atom");

        assert!(err.to_string().contains("expected cell"));
    }
}
#[cfg(all(test, feature = "std"))]
mod hardening_tests {
    use super::*;
    use nockapp::noun::slab::NounSlab;
    use nockapp::{AtomExt, Bytes};
    use nockvm::noun::NounAllocator;
    use nockvm::noun::{D, T};
    use noun_serde::{NounDecode, NounEncode};

    fn unbased_note_data() -> NoteData {
        let mut slab: NounSlab = NounSlab::new();
        // A 72-bit atom: legal in a jam, but not belt-based.
        let bytes = Bytes::copy_from_slice(&[1u8; 9]);
        let atom = nockvm::noun::Atom::from_bytes(&mut slab, &bytes).as_noun();
        slab.set_root(atom);

        let mut map = ZMap::new();
        map.put("big".to_string(), UntypedNoun { p: slab.jam() });
        NoteData { map }
    }

    #[test]
    fn note_data_with_unbased_atom_returns_error() {
        let note_data = unbased_note_data();
        let err = note_data
            .to_hash()
            .expect_err("unbased note-data must not fabricate a digest");
        assert!(
            matches!(err, Tip5Error::HashingError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn spends_with_unbased_note_data_return_error() {
        let mut spends = ZMap::new();
        let spend = Spend {
            version: 1,
            body: SpendBody::V1(SpendV1 {
                witness: Witness {
                    lmp: LockMerkleProof::new_stub(
                        SpendCondition { p: Vec::new() },
                        1,
                        MerkleProof {
                            root: Hash { values: [0; 5] },
                            path: Vec::new(),
                        },
                    ),
                    pkh: PkhSignature { map: ZMap::new() },
                    hax: ZMap::new(),
                    tim: 0,
                },
                seeds: SeedsV1 {
                    set: {
                        let seed = SeedV1 {
                            output_source: None,
                            lock_root: Hash { values: [1; 5] },
                            note_data: unbased_note_data(),
                            gift: Coins { value: 1 },
                            parent_hash: Hash { values: [2; 5] },
                        };
                        let jam = pokenoun::codec::Encode::to_jam(&(seed, (0u64, 0u64))).unwrap();
                        <ZSet<SeedV1> as pokenoun::codec::Decode>::from_jam(&jam).unwrap()
                    },
                },
                fee: Coins { value: 1 },
            }),
        };
        let name = NName {
            p: vec![Hash { values: [3; 5] }, Hash { values: [4; 5] }],
        };
        spends.put(name, spend);

        let result = compute_tx_id_v1(&SpendsV1 { map: spends });
        assert!(
            result.is_err(),
            "unbased note-data must error, got {result:?}"
        );
    }

    #[test]
    fn witness_rejects_nonzero_tim() {
        let mut slab: NounSlab = NounSlab::new();
        let witness = Witness {
            lmp: LockMerkleProof::new_stub(
                SpendCondition { p: Vec::new() },
                1,
                MerkleProof {
                    root: Hash { values: [0; 5] },
                    path: Vec::new(),
                },
            ),
            pkh: PkhSignature { map: ZMap::new() },
            hax: ZMap::new(),
            tim: 0,
        };

        let lmp = witness.lmp.to_noun(&mut slab);
        let pkh = witness.pkh.to_noun(&mut slab);
        let hax = witness.hax.to_noun(&mut slab);
        let bad = T(&mut slab, &[lmp, pkh, hax, D(1)]);

        let space = slab.noun_space();
        let err = Witness::from_noun(&bad, &space).expect_err("non-zero tim must be rejected");
        assert!(err.to_string().contains("tim must be 0"));
    }
}

crate::noun_codec::noun_struct!(
    NNoteV1 {
        version,
        origin_page,
        name,
        note_data,
        assets
    },
    NoteData { map },
    SeedV1 {
        output_source,
        lock_root,
        note_data,
        gift,
        parent_hash
    },
    SeedsV1 { set },
    TxV1 {
        version,
        raw_tx,
        total_size,
        outputs
    },
    OutputsV1 { set },
    OutputV1 { note, seeds },
    RawTransactionV1 {
        version,
        id,
        spends
    },
    SpendsV1 { map },
    InputsV1 { map },
    InputV1 { note, spend },
    SpendV1 {
        witness,
        seeds,
        fee
    },
    SpendV0ToV1 {
        signature,
        seeds,
        fee
    },
    LockMerkleProofStub {
        spend_condition,
        axis,
        merkle_proof
    },
    LockMerkleProofFull {
        version,
        spend_condition,
        axis,
        merkle_proof
    },
    SpendCondition { p },
    Pkh { m, h },
    Tim { rel, abs },
    Hax { set },
    MerkleProof { root, path },
    PkhSignature { map },
    PkhSignatureValue { pk, sig }
);

impl Encode for LockPrimitive {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        let (tag, body) = match &self.body {
            LockPrimitiveBody::Pkh(value) => ("pkh", value.encode(arena)?),
            LockPrimitiveBody::Tim(value) => ("tim", value.encode(arena)?),
            LockPrimitiveBody::Hax(value) => ("hax", value.encode(arena)?),
            LockPrimitiveBody::Brn(value) => ("brn", value.encode(arena)?),
        };
        if self.header != tag {
            return Err(Error("lock primitive header disagrees with body"));
        }
        let tag = tag.encode(arena)?;
        Ok(arena.alloc_cell(tag, body))
    }
}
impl Decode for LockPrimitive {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let (tag, body) = pair(noun, arena)?;
        let header = String::decode(tag, arena)?;
        let body = match header.as_str() {
            "pkh" => LockPrimitiveBody::Pkh(Pkh::decode(body, arena)?),
            "tim" => LockPrimitiveBody::Tim(Tim::decode(body, arena)?),
            "hax" => LockPrimitiveBody::Hax(Hax::decode(body, arena)?),
            "brn" => LockPrimitiveBody::Brn(Brn::decode(body, arena)?),
            _ => return Err(Error("invalid lock primitive tag")),
        };
        Ok(Self { header, body })
    }
}
impl Encode for Brn {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        if self.value != 0 {
            return Err(Error("burn payload must be zero"));
        }
        Ok(arena.atom0())
    }
}
impl Decode for Brn {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        if !is_null(noun, arena) {
            return Err(Error("burn payload must be zero"));
        }
        Ok(Self { value: 0 })
    }
}
impl Encode for LockMerkleProof {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        match self {
            Self::Stub(proof) => proof.encode(arena),
            Self::Full(proof) => {
                if proof.version != u64::from_le_bytes(*b"full\0\0\0\0") {
                    return Err(Error("full proof tag must be %full"));
                }
                proof.encode(arena)
            }
        }
    }
}
impl Decode for LockMerkleProof {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let (head, _) = pair(noun, arena)?;
        if let Noun::Atom(id) = head {
            if arena.atom_bytes_trimmed(id) == b"full" {
                return LockMerkleProofFull::decode(noun, arena).map(Self::Full);
            }
            if !is_null(head, arena) {
                return Err(Error("invalid lock proof version"));
            }
        }
        LockMerkleProofStub::decode(noun, arena).map(Self::Stub)
    }
}
impl Encode for Witness {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        if self.tim != 0 {
            return Err(Error("witness tim must be 0 (~)"));
        }
        let fields = [
            self.lmp.encode(arena)?,
            self.pkh.encode(arena)?,
            self.hax.encode(arena)?,
            self.tim.encode(arena)?,
        ];
        pokenoun::codec::tuple(arena, &fields)
    }
}
impl Decode for Witness {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let mut fields = Fields::new(noun, 4);
        let value = Self {
            lmp: Decode::decode(fields.next(arena)?, arena)?,
            pkh: Decode::decode(fields.next(arena)?, arena)?,
            hax: Decode::decode(fields.next(arena)?, arena)?,
            tim: Decode::decode(fields.next(arena)?, arena)?,
        };
        if value.tim != 0 {
            return Err(Error("witness tim must be 0 (~)"));
        }
        Ok(value)
    }
}
crate::noun_codec::runtime_codec!(LockPrimitive, Brn, LockMerkleProof, Witness);
