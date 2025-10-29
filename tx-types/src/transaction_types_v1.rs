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

#[derive(Debug, Clone, NounDecode, NounEncode)]
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

impl NounEncode for NoteData {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        // Simply delegate to ZMap's to_noun implementation
        self.map.to_noun(alloc)
    }
}

impl NoteData {
    /// Compute hashable for note-data
    ///
    /// From Hoon, note-data is a z-map of @tas to *
    pub fn to_hashable(&self) -> Hashable {
        self.map.to_hashable(
            |key| Hashable::leaf_from_tas(key),
            |untyped| hashable_from_untyped(untyped),
        )
    }
}

fn hashable_from_untyped(un: &UntypedNoun) -> Hashable {
    use nockapp::noun::slab::NounSlab;
    use nockvm::noun::Noun;

    fn go(n: Noun) -> Hashable {
        if let Ok(a) = n.as_atom() {
            Hashable::leaf_from_atom(a.as_ne_bytes())
        } else {
            let c = n.as_cell().unwrap();
            Hashable::cell(go(c.head()), go(c.tail()))
        }
    }

    let mut slab: NounSlab = NounSlab::new();
    let noun = slab.cue_into(un.p.clone().into())
        .expect("cue untyped noun");
    go(noun)
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
    pub fn to_regular_hashable(&self) -> Hashable {
        use crate::hashing::hasher::hash_hashable;

        // Hash the note_data
        let note_data_hash = hash_hashable(&self.note_data.to_hashable());

        // Build the 4-element structure (quad): [a b c d]
        // In Hoon, :^ creates a quad which is [a [b [c d]]]
        Hashable::cell(
            Hashable::Hash(self.lock_root.clone()),
            Hashable::cell(
                Hashable::Hash(note_data_hash),
                Hashable::cell(
                    self.gift.to_hashable(),
                    Hashable::Hash(self.parent_hash.clone()),
                ),
            ),
        )
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
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
    pub fn to_hashable(&self) -> Hashable {
        // Use ZSet's to_hashable method with regular hashable for each seed
        self.set.to_hashable(|seed| seed.to_regular_hashable())
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct TxV1 {
    pub version: u64,
    pub raw_tx: RawTransactionV1,
    pub total_size: u64,
    pub outputs: OutputsV1,
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct OutputsV1 {
    pub set: ZSet<OutputV1>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct OutputV1 {
    pub note: NNoteV1,
    pub seeds: SeedsV1,
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct RawTransactionV1 {
    pub version: u64,
    pub id: Hash,
    pub spends: SpendsV1,
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct SpendsV1 {
    pub map: ZMap<NName, Spend>,
}

impl SpendsV1 {
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
    pub fn to_hashable(&self) -> Hashable {
        self.map
            .to_hashable(|nname| nname.to_hashable(), |spend| spend.to_hashable())
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
    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable())
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct InputsV1 {
    pub map: ZMap<NName, InputV1>,
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct InputV1 {
    pub note: NNoteV1,
    pub spend: SpendV1,
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
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
    pub fn compute_sig_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;

        let hashable = Hashable::cell(self.seeds.to_sig_hashable(), self.fee.to_hashable());

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
    pub fn to_hashable(&self) -> Hashable {
        // Build the triple: [witness-hashable seeds-hashable fee-leaf]
        // Note: seeds hashable uses regular hashable, not sig-hashable
        Hashable::triple(
            self.witness.to_hashable(),
            self.seeds.to_hashable(),
            self.fee.to_hashable(),
        )
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable())
    }
}

/// SpendV0ToV1: Spend a V0 note into V1 notes
///
/// This corresponds to `spend-0:v1:transact` in tx-engine-1.hoon.
/// It uses V0 signatures (ZMap<SchnorrPubkey, SchnorrSignature>) but creates V1 seeds.
#[derive(Debug, Clone, NounDecode, NounEncode)]
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

        // Encode all 5 fields: output_source, lock_root, note_data, gift, parent_hash
        let output_source = self.output_source.to_noun(alloc);
        let lock_root = self.lock_root.to_noun(alloc);
        let note_data = self.note_data.to_noun(alloc);
        let gift = self.gift.to_noun(alloc);
        let parent_hash = self.parent_hash.to_noun(alloc);

        T(
            alloc,
            &[output_source, lock_root, note_data, gift, parent_hash],
        )
    }
}

impl NounEncode for OutputV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::T;

        // Encode both fields: note and seeds
        let note = self.note.to_noun(alloc);
        let seeds = self.seeds.to_noun(alloc);

        T(alloc, &[note, seeds])
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

#[derive(Debug, Clone, NounDecode, NounEncode)]
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
    pub fn to_hashable(&self) -> Hashable {
        use crate::hashing::hasher::hash_hashable;

        // Hash the lock merkle proof
        let lmp_hash = self.lmp.to_hash();

        // Hash the pkh signature
        let pkh_hash = self.pkh.to_hash();

        // Hash the hax map
        let hax_hashable = self.hashable_hax();
        let hax_hash = hash_hashable(&hax_hashable);

        // Build the 4-element structure (quad)
        // Using nested cells: [a [b [c d]]]
        Hashable::cell(
            Hashable::Hash(lmp_hash),
            Hashable::cell(
                Hashable::Hash(pkh_hash),
                Hashable::cell(
                    Hashable::Hash(hax_hash),
                    Hashable::leaf_from_atom(&self.tim.to_le_bytes()),
                ),
            ),
        )
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
    fn hashable_hax(&self) -> Hashable {
        self.hax.to_hashable(
            |hash| Hashable::Hash(hash.clone()),
            |untyped| hashable_from_untyped(untyped),
        )
    }

    /// Compute hashable for a noun (represented as UntypedNoun)
    ///
    /// From Hoon (tx-engine-1.hoon lines ~1200-1203):
    /// ```hoon
    /// ++  hashable-noun
    ///   |=  n=*
    ///   ^-  hashable:tip5
    ///   ?^  n  [$(n -.n) $(n +.n)]
    ///   leaf+n
    /// ```
    fn hashable_noun_from_untyped(&self, untyped: &UntypedNoun) -> Hashable {
        // The UntypedNoun contains jammed bytes, which we need to unjam and traverse
        // For now, we'll just use it as a leaf since we don't have easy access to the noun structure
        Hashable::Leaf(untyped.p.to_vec())
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable())
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct LockMerkleProof {
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub merkle_proof: MerkleProof,
}

impl LockMerkleProof {
    /// Compute hashable for lock-merkle-proof
    ///
    /// From Hoon (tx-engine-1.hoon lines ~1392-1403):
    /// ```hoon
    /// ++  hashable
    ///   |=  =form
    ///   ^-  hashable:tip5
    ///   |^
    ///   :+  hash+(hash:spend-condition spend-condition.form)
    ///     leaf+axis
    ///   (hashable-merk-proof merk-proof.form)
    /// ```
    pub fn to_hashable(&self) -> Hashable {
        use crate::hashing::hasher::hash_hashable;

        // Hash the spend condition
        let spend_condition_hash = hash_hashable(&self.spend_condition.to_hashable());

        // Build the triple: [hash+(spend-condition) leaf+axis merkle-proof-hashable]
        Hashable::triple(
            Hashable::Hash(spend_condition_hash),
            Hashable::leaf_from_atom(&self.axis.to_le_bytes()),
            self.merkle_proof.to_hashable(),
        )
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable())
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
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

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct Pkh {
    pub m: u64,
    pub h: ZSet<Hash>,
}

impl Pkh {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::cell(
            Hashable::leaf_from_tas("pkh"),
            Hashable::cell(
                Hashable::leaf_from_atom(&self.m.to_le_bytes()),
                self.h.to_hashable(|h| Hashable::Hash(h.clone())),
            ),
        )
    }
}


#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct Tim {
    // lockscript timelock
    pub rel: TimelockRange,
    pub abs: TimelockRange,
}

impl Tim {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::cell(Hashable::leaf_from_tas("tim"),
            Hashable::cell(self.rel.to_hashable(), self.abs.to_hashable()))
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct Hax {
    pub set: ZSet<Hash>,
}

impl Hax {
    pub fn to_hashable(&self) -> Hashable {
        // replace the placeholder; at minimum tag must be tas:
        Hashable::cell(Hashable::leaf_from_tas("hax"), Hashable::null())
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct Brn {
    pub value: u64, // this will always be 0
}

impl Brn {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::cell(Hashable::leaf_from_tas("brn"), Hashable::null())
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

impl NounEncode for LockPrimitive {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        use nockapp::utils::make_tas;
        use nockvm::noun::T;

        let header_atom = make_tas(alloc, &self.header);
        let body_noun = match &self.body {
            LockPrimitiveBody::Pkh(pkh) => pkh.to_noun(alloc),
            LockPrimitiveBody::Tim(tim) => tim.to_noun(alloc),
            LockPrimitiveBody::Hax(hax) => hax.to_noun(alloc),
            LockPrimitiveBody::Brn(brn) => brn.to_noun(alloc),
        };

        T(alloc, &[header_atom.as_noun(), body_noun])
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
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
        hash_hashable(&self.to_hashable())
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
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
        hash_hashable(&self.to_hashable())
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
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
        hash_hashable(&self.to_hashable())
    }
}
