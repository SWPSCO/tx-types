use noun_serde::{NounDecode, NounEncode};

use crate::collections::zset::DorTip as ZSetDorTip;
use crate::collections::{ZMap, ZSet};
use crate::generic_noun::UntypedNoun;
use crate::transaction_types::*;
use nockapp::noun::slab::{CueError, NounSlab};
use nockapp::utils::make_tas;
use nockapp::Bytes;
use nockvm::noun::{Atom, Noun, D};
use once_cell::sync::Lazy;

use crate::hashing::hashable::Hashable;
use crate::hashing::hasher::{hash_hashable, hash_ten_cell};
use crate::hashing::raw::{
    compute_tx_id_v1_from_raw_noun, hashable_note_data_from_raw, hashable_pkh_signature_direct,
    hashable_pkh_signature_from_raw, hashable_seeds_from_raw, hashable_spend_from_raw,
    hashable_spends_from_raw, hashable_witness_from_raw,
};
use crate::hashing::tip5::Tip5Hasher;

static LOCK_MERKLE_AXIS_HASH: Lazy<Hash> = Lazy::new(|| {
    Hash::from_b58("6mhCSwJQDvbkbiPAUNjetJtVoo1VLtEhmEYoU4hmdGd6ep1F6ayaV4A")
        .expect("valid lock merkle proof axis hash constant")
});

fn hashable_from_noun_recursive(noun: nockvm::noun::Noun) -> Hashable {
    if let Ok(cell) = noun.as_cell() {
        Hashable::cell(
            hashable_from_noun_recursive(cell.head()),
            hashable_from_noun_recursive(cell.tail()),
        )
    } else {
        let atom = noun
            .as_atom()
            .expect("hashable_from_noun_recursive: expected atom or cell");
        match atom.as_u64() {
            Ok(val) => Hashable::leaf_from_atom(&val.to_le_bytes()),
            Err(_) => {
                let mut slab: NounSlab = NounSlab::new();
                slab.copy_into(atom.as_noun());
                Hashable::Leaf(slab.jam().to_vec())
            }
        }
    }
}

fn hashable_from_untyped_noun(untyped: &UntypedNoun) -> Hashable {
    let mut slab: NounSlab = NounSlab::new();
    let noun = match slab.cue_into(untyped.p.clone()) {
        Ok(noun) => noun,
        Err(_) => return Hashable::Leaf(untyped.p.to_vec()),
    };

    hashable_from_noun_recursive(noun)
}

fn hashable_leaf_from_noun(noun: Noun) -> Hashable {
    let mut slab: NounSlab = NounSlab::new();
    let copy = slab.copy_into(noun);
    slab.set_root(copy);
    Hashable::Leaf(slab.jam().to_vec())
}

fn hashable_note_data_from_zmap(noun: Noun) -> Hashable {
    if let Ok(atom) = noun.as_atom() {
        if atom.as_u64().unwrap_or(1) == 0 {
            return Hashable::null();
        }
    }

    let cell = noun.as_cell().expect("note-data node should be a cell");
    let node = cell.head();
    let children = cell
        .tail()
        .as_cell()
        .expect("note-data child tuple should be a cell");
    let left = children.head();
    let right = match children.tail().as_cell() {
        Ok(right_cell) => right_cell.head(),
        Err(_) => children.tail(),
    };

    let pair = node
        .as_cell()
        .expect("note-data key/value node should be a cell");
    let key_noun = pair.head();
    let value_noun = pair.tail();

    let key_leaf = hashable_leaf_from_noun(key_noun);
    let value_hashable = hashable_from_noun_recursive(value_noun);
    let node_hashable = Hashable::cell(key_leaf, value_hashable);

    Hashable::triple(
        node_hashable,
        hashable_note_data_from_zmap(left),
        hashable_note_data_from_zmap(right),
    )
}

pub fn hashable_spends_from_zmap(noun: Noun) -> Hashable {
    if noun_is_null(noun) {
        return Hashable::null();
    }

    let (node, left, right) = decompose_map(noun);
    let (name_noun, spend_noun) = decompose_pair(node);

    let name = NName::from_noun(&name_noun).expect("failed to decode spend name");
    let spend = Spend::from_noun(&spend_noun).expect("failed to decode spend entry");

    let node_hashable = Hashable::cell(name.to_hashable(), spend.to_hashable());

    Hashable::triple(
        node_hashable,
        hashable_spends_from_zmap(left),
        hashable_spends_from_zmap(right),
    )
}

fn noun_is_null(noun: Noun) -> bool {
    unsafe { noun.raw_equals(&D(0)) }
}

fn atom_trimmed_be(atom: Atom) -> Vec<u8> {
    let mut bytes = atom.to_be_bytes();
    let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    if first_non_zero == bytes.len() {
        vec![0]
    } else {
        bytes.split_off(first_non_zero)
    }
}

fn nouns_equal(a: Noun, b: Noun) -> bool {
    if unsafe { a.raw_equals(&b) } {
        return true;
    }

    match (a.as_cell(), b.as_cell()) {
        (Ok(ac), Ok(bc)) => nouns_equal(ac.head(), bc.head()) && nouns_equal(ac.tail(), bc.tail()),
        (Err(_), Err(_)) => {
            let a_atom = a.as_atom().expect("noun should be atom");
            let b_atom = b.as_atom().expect("noun should be atom");
            atom_trimmed_be(a_atom) == atom_trimmed_be(b_atom)
        }
        _ => false,
    }
}

fn atom_less_than(a: Atom, b: Atom) -> bool {
    let a_bytes = atom_trimmed_be(a);
    let b_bytes = atom_trimmed_be(b);
    match a_bytes.len().cmp(&b_bytes.len()) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => a_bytes < b_bytes,
    }
}

fn less_than_hash(a: &[u64; 5], b: &[u64; 5]) -> bool {
    // Compare using Goldilocks polynomial representation, matching Hoon's lth-tip:
    //   digest-to-atom: a + p*b + p²*c + p³*d + p⁴*e
    // where p = 2^64 - 2^32 + 1 (Goldilocks prime)
    let hash_a = Hash { values: *a };
    let hash_b = Hash { values: *b };
    hash_a.to_ubig() < hash_b.to_ubig()
}

fn tip_hash(noun: Noun) -> [u64; 5] {
    Tip5Hasher::hash_noun_varlen(noun)
        .map(|hash| hash.values)
        .unwrap_or([0; 5])
}

fn double_tip_hash(noun: Noun) -> [u64; 5] {
    let tip = tip_hash(noun);
    let hash = Hash { values: tip };
    hash_ten_cell(hash.clone(), hash).values
}

fn dor_tip_compare(a: Noun, b: Noun) -> bool {
    if nouns_equal(a, b) {
        return true;
    }

    match (a.as_cell(), b.as_cell()) {
        (Ok(ac), Ok(bc)) => {
            if nouns_equal(ac.head(), bc.head()) {
                dor_tip_compare(ac.tail(), bc.tail())
            } else {
                dor_tip_compare(ac.head(), bc.head())
            }
        }
        (Ok(_), Err(_)) => false,
        (Err(_), Ok(_)) => false,
        (Err(_), Err(_)) => {
            let a_atom = a.as_atom().expect("noun should be atom");
            let b_atom = b.as_atom().expect("noun should be atom");
            atom_less_than(a_atom, b_atom)
        }
    }
}

fn gor_tip_compare(a: Noun, b: Noun) -> bool {
    let a_tip = tip_hash(a);
    let b_tip = tip_hash(b);
    if a_tip == b_tip {
        dor_tip_compare(a, b)
    } else {
        less_than_hash(&a_tip, &b_tip)
    }
}

fn mor_tip_compare(a: Noun, b: Noun) -> bool {
    let a_tip = double_tip_hash(a);
    let b_tip = double_tip_hash(b);
    if a_tip == b_tip {
        dor_tip_compare(a, b)
    } else {
        less_than_hash(&a_tip, &b_tip)
    }
}

fn decompose_map(noun: Noun) -> (Noun, Noun, Noun) {
    let cell = noun.as_cell().expect("map node should be a cell");
    let node = cell.head();
    let tail = cell.tail();

    if let Ok(children) = tail.as_cell() {
        let left = children.head();
        let right = children.tail();
        (node, left, right)
    } else {
        (node, tail, D(0))
    }
}

fn decompose_pair(noun: Noun) -> (Noun, Noun) {
    let cell = noun.as_cell().expect("pair should be a cell");
    let key = cell.head();
    let value = cell.tail();
    (key, value)
}

fn canonical_zmap_put<A: nockvm::noun::NounAllocator>(
    alloc: &mut A,
    map: Noun,
    key: Noun,
    value: Noun,
) -> Noun {
    if noun_is_null(map) {
        let kv = nockvm::noun::T(alloc, &[key, value]);
        let children = nockvm::noun::T(alloc, &[D(0), D(0)]);
        return nockvm::noun::T(alloc, &[kv, children]);
    }

    let (node, left, right) = decompose_map(map);
    let (node_key, node_value) = decompose_pair(node);

    if nouns_equal(key, node_key) {
        if nouns_equal(value, node_value) {
            map
        } else {
            let new_node = nockvm::noun::T(alloc, &[key, value]);
            nockvm::noun::T(alloc, &[new_node, left, right])
        }
    } else if gor_tip_compare(key, node_key) {
        let new_left = canonical_zmap_put(alloc, left, key, value);
        let (new_left_node, new_left_left, new_left_right) = decompose_map(new_left);
        let (new_left_key, _) = decompose_pair(new_left_node);

        if mor_tip_compare(node_key, new_left_key) {
            let children = nockvm::noun::T(alloc, &[new_left, right]);
            nockvm::noun::T(alloc, &[node, children])
        } else {
            let right_children = nockvm::noun::T(alloc, &[new_left_right, right]);
            let new_right_branch = nockvm::noun::T(alloc, &[node, right_children]);
            let left_children = nockvm::noun::T(alloc, &[new_left_left, new_right_branch]);
            nockvm::noun::T(alloc, &[new_left_node, left_children])
        }
    } else {
        let new_right = canonical_zmap_put(alloc, right, key, value);
        let (new_right_node, new_right_left, new_right_right) = decompose_map(new_right);
        let (new_right_key, _) = decompose_pair(new_right_node);

        if mor_tip_compare(node_key, new_right_key) {
            let children = nockvm::noun::T(alloc, &[left, new_right]);
            nockvm::noun::T(alloc, &[node, children])
        } else {
            let left_children = nockvm::noun::T(alloc, &[left, new_right_left]);
            let new_left_branch = nockvm::noun::T(alloc, &[node, left_children]);
            let right_children = nockvm::noun::T(alloc, &[new_left_branch, new_right_right]);
            nockvm::noun::T(alloc, &[new_right_node, right_children])
        }
    }
}

fn build_canonical_zmap_from_pairs<A, I, K, V, KF, VF>(
    alloc: &mut A,
    entries: I,
    mut key_fn: KF,
    mut value_fn: VF,
) -> Noun
where
    A: nockvm::noun::NounAllocator,
    I: IntoIterator<Item = (K, V)>,
    KF: FnMut(&mut A, K) -> Noun,
    VF: FnMut(&mut A, V) -> Noun,
{
    let mut root = D(0);
    for (key, value) in entries {
        let key_noun = key_fn(alloc, key);
        let value_noun = value_fn(alloc, value);
        root = canonical_zmap_put(alloc, root, key_noun, value_noun);
    }
    root
}

fn build_canonical_note_data_noun<A: nockvm::noun::NounAllocator>(
    alloc: &mut A,
    map: &ZMap<String, UntypedNoun>,
) -> Noun {
    build_canonical_zmap_from_pairs(
        alloc,
        map.tap().into_iter(),
        |alloc, key: String| make_tas(alloc, &key).as_noun(),
        |alloc, value: UntypedNoun| value.to_noun(alloc),
    )
}

fn build_canonical_spends_noun<A: nockvm::noun::NounAllocator>(
    alloc: &mut A,
    map: &ZMap<NName, Spend>,
) -> Noun {
    build_canonical_zmap_from_pairs(
        alloc,
        map.tap().into_iter(),
        |alloc, key: NName| key.to_noun(alloc),
        |alloc, value: Spend| value.to_noun(alloc),
    )
}

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

impl NNoteV1 {
    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable())
    }

    pub fn to_hashable(&self) -> Hashable {
        /*
            :*  leaf+version.form
                leaf+origin-page.form
                hash+(hash:nname name.form)
                hash+(hash:note-data note-data.form)
                leaf+assets.form
            ==
        */
        Hashable::cell_chain([
            Hashable::leaf_from_atom(&self.version.to_le_bytes()),
            self.origin_page.to_hashable(),
            Hashable::Hash(self.name.to_hash()),
            Hashable::Hash(self.note_data.to_hash()),
            self.assets.to_hashable(),
        ])
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct NoteData {
    pub map: ZMap<String, UntypedNoun>,
}

impl NounEncode for NoteData {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        build_canonical_note_data_noun(alloc, &self.map)
    }
}

impl NoteData {
    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable())
    }

    /// Compute hashable for note-data
    ///
    /// From Hoon, note-data is a z-map of @tas to *
    pub fn to_hashable(&self) -> Hashable {
        let mut slab: NounSlab = NounSlab::new();
        let noun = build_canonical_note_data_noun(&mut slab, &self.map);
        hashable_note_data_from_zmap(noun)
    }

    /// Return the canonical note-data noun jam used for hashing/debugging.
    pub fn jam_canonical(&self) -> Vec<u8> {
        let mut slab: NounSlab = NounSlab::new();
        let noun = build_canonical_note_data_noun(&mut slab, &self.map);
        slab.set_root(noun);
        slab.jam().to_vec()
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
            Some(source) => Hashable::cell_chain([Hashable::null(), source.to_hashable()]),
        };

        // Hash the note_data
        let note_data_hash = hash_hashable(&self.note_data.to_hashable());

        // Build the 5-element structure (quint)
        // Using nested cells: [a [b [c [d e]]]]
        Hashable::cell_chain([
            output_source_hashable,
            Hashable::Hash(self.lock_root.clone()),
            Hashable::Hash(note_data_hash),
            self.gift.to_hashable(),
            Hashable::Hash(self.parent_hash.clone()),
        ])
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

#[derive(Debug, Clone, NounDecode)]
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
        let mut slab: NounSlab = NounSlab::new();
        let noun = build_canonical_spends_noun(&mut slab, &self.map);
        hashable_spends_from_raw(noun).expect("invalid spends noun")
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

    /// Return the raw spends noun jam used for hashing/debugging.
    pub fn jam_canonical(&self) -> Vec<u8> {
        let mut slab: NounSlab = NounSlab::new();
        let noun = build_canonical_spends_noun(&mut slab, &self.map);
        slab.set_root(noun);
        slab.jam().to_vec()
    }
}

impl NounEncode for SpendsV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> Noun {
        build_canonical_spends_noun(alloc, &self.map)
    }
}

fn version_leaf_hashable() -> Hashable {
    Hashable::leaf_from_atom(1u64.to_le_bytes())
}

/// Compute a tx-id from an already computed spends hashable structure.
fn compute_tx_id_from_spends_hashable(spends_hashable: Hashable) -> Hash {
    let hashable = Hashable::cell(version_leaf_hashable(), spends_hashable);
    hash_hashable(&hashable)
}

/// Compute the tx-id from an in-memory spends map.
pub fn compute_tx_id_v1(spends: &SpendsV1) -> Hash {
    compute_tx_id_from_spends_hashable(spends.to_hashable())
}

/// Compute the tx-id from the raw noun representation of the spends map.
pub fn compute_tx_id_v1_from_noun(spends_noun: Noun) -> Hash {
    let spends = SpendsV1::from_noun(&spends_noun).expect("invalid spends noun");
    compute_tx_id_v1(&spends)
}

/// Compute the tx-id directly from the jammed noun bytes of the spends map.
pub fn compute_tx_id_v1_from_jam(spends_jam: &[u8]) -> Result<Hash, CueError> {
    let mut slab: NounSlab = NounSlab::new();
    let noun = slab.cue_into(Bytes::copy_from_slice(spends_jam))?;
    Ok(compute_tx_id_v1_from_noun(noun))
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

        Hashable::cell_chain([
            Hashable::Hash(lmp_hash),
            Hashable::Hash(pkh_hash),
            Hashable::Hash(hax_hash),
            Hashable::leaf_from_atom(&self.tim.to_le_bytes()),
        ])
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
            |untyped_noun| {
                // hashable-noun recursively builds cells for cells, leaves for atoms
                // But since UntypedNoun is just jammed bytes, we treat it as a leaf
                hashable_from_untyped_noun(untyped_noun)
            },
        )
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable())
    }
}

fn decode_hoon_list<T, F>(
    noun: &Noun,
    context: &'static str,
    mut decode_item: F,
) -> Result<Vec<T>, noun_serde::NounDecodeError>
where
    F: FnMut(&Noun) -> Result<T, noun_serde::NounDecodeError>,
{
    let mut items = Vec::new();
    let mut current = *noun;

    loop {
        if let Ok(cell) = current.as_cell() {
            items.push(decode_item(&cell.head())?);
            current = cell.tail();
            continue;
        }

        let atom = current
            .as_atom()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedAtom)?;
        match atom.as_u64()? {
            0 => return Ok(items),
            _ => {
                return Err(noun_serde::NounDecodeError::Custom(
                    format!("{context} must be a list").into(),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, NounEncode)]
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
    ///     hash+(from-b58:^hash '6mhCSwJQDvbkbiPAUNjetJtVoo1VLtEhmEYoU4hmdGd6ep1F6ayaV4A')
    ///   (hashable-merk-proof merk-proof.form)
    /// ```
    pub fn to_hashable(&self) -> Hashable {
        use crate::hashing::hasher::hash_hashable;

        // Hash the spend condition
        let spend_condition_hash = hash_hashable(&self.spend_condition.to_hashable());
        // Build the triple: [hash+(spend-condition) axis-constant merkle-proof-hashable]
        Hashable::triple(
            Hashable::Hash(spend_condition_hash),
            Hashable::Hash(LOCK_MERKLE_AXIS_HASH.clone()),
            self.merkle_proof.to_hashable(),
        )
    }

    pub fn to_hash(&self) -> Hash {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable())
    }
}

impl NounDecode for LockMerkleProof {
    fn from_noun(noun: &Noun) -> Result<Self, noun_serde::NounDecodeError> {
        let cell = noun
            .as_cell()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?;

        if let Ok(version_atom) = cell.head().as_atom() {
            if version_atom.into_string()? == "full" {
                let rest = cell
                    .tail()
                    .as_cell()
                    .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?;
                let spend_condition = SpendCondition::from_noun(&rest.head())?;
                let rest_tail = rest
                    .tail()
                    .as_cell()
                    .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?;
                let axis = u64::from_noun(&rest_tail.head())?;
                let merkle_proof = MerkleProof::from_noun(&rest_tail.tail())?;

                return Ok(Self {
                    spend_condition,
                    axis,
                    merkle_proof,
                });
            }
        }

        let spend_condition = SpendCondition::from_noun(&cell.head())?;
        let tail = cell
            .tail()
            .as_cell()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?;
        let axis = u64::from_noun(&tail.head())?;
        let merkle_proof = MerkleProof::from_noun(&tail.tail())?;

        Ok(Self {
            spend_condition,
            axis,
            merkle_proof,
        })
    }
}

#[derive(Debug, Clone, NounEncode)]
pub struct SpendCondition {
    pub p: Vec<LockPrimitive>,
}

impl SpendCondition {
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
        hash_hashable(&self.to_hashable())
    }
}

impl NounDecode for SpendCondition {
    fn from_noun(noun: &Noun) -> Result<Self, noun_serde::NounDecodeError> {
        Ok(Self {
            p: decode_hoon_list(noun, "spend-condition", LockPrimitive::from_noun)?,
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

#[derive(Debug, Clone, NounDecode, NounEncode)]
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

#[derive(Debug, Clone, NounDecode, NounEncode)]
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

#[derive(Debug, Clone, NounDecode, NounEncode)]
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

#[derive(Debug, Clone, NounDecode, NounEncode)]
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

#[derive(Debug, Clone, NounEncode)]
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

impl NounDecode for MerkleProof {
    fn from_noun(noun: &Noun) -> Result<Self, noun_serde::NounDecodeError> {
        let cell = noun
            .as_cell()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?;
        let root = Hash::from_noun(&cell.head())?;
        let path = decode_hoon_list(&cell.tail(), "merkle proof path", Hash::from_noun)?;
        Ok(Self { root, path })
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

#[cfg(test)]
mod tests {
    use super::*;
    use nockvm::noun::{D, T};
    use noun_serde::NounEncode;

    #[test]
    fn lock_merkle_proof_decodes_full_format() {
        let mut slab = NounSlab::new();
        let primitive = LockPrimitive {
            header: "brn".to_string(),
            body: LockPrimitiveBody::Brn(Brn { value: 0 }),
        };
        let spend_condition_noun = T(&mut slab, &[primitive.to_noun(&mut slab), D(0)]);
        let merkle_proof = MerkleProof {
            root: Hash {
                values: [1, 2, 3, 4, 5],
            },
            path: vec![Hash {
                values: [6, 7, 8, 9, 10],
            }],
        };
        let full_lmp = T(
            &mut slab,
            &[
                make_tas(&mut slab, "full").as_noun(),
                spend_condition_noun,
                D(7),
                merkle_proof.to_noun(&mut slab),
            ],
        );

        let decoded = LockMerkleProof::from_noun(&full_lmp).expect("full lmp should decode");

        assert_eq!(decoded.axis, 7);
        assert_eq!(decoded.spend_condition.p.len(), 1);
        match &decoded.spend_condition.p[0].body {
            LockPrimitiveBody::Brn(brn) => assert_eq!(brn.value, 0),
            other => panic!("expected burn primitive, got {:?}", other),
        }
        assert_eq!(decoded.merkle_proof.root.values, [1, 2, 3, 4, 5]);
        assert_eq!(decoded.merkle_proof.path.len(), 1);
        assert_eq!(decoded.merkle_proof.path[0].values, [6, 7, 8, 9, 10]);
    }

    #[test]
    fn spend_condition_rejects_improper_list_without_panicking() {
        let mut slab = NounSlab::new();
        let primitive = LockPrimitive {
            header: "brn".to_string(),
            body: LockPrimitiveBody::Brn(Brn { value: 0 }),
        };
        let malformed_list = T(&mut slab, &[primitive.to_noun(&mut slab), D(1)]);

        let err = SpendCondition::from_noun(&malformed_list)
            .expect_err("spend-condition decode should reject improper list");

        assert!(err.to_string().contains("spend-condition must be a list"));
    }

    #[test]
    fn merkle_proof_rejects_improper_path_without_panicking() {
        let mut slab = NounSlab::new();
        let malformed = T(
            &mut slab,
            &[
                Hash {
                    values: [1, 2, 3, 4, 5],
                }
                .to_noun(&mut slab),
                D(1),
            ],
        );

        let err =
            MerkleProof::from_noun(&malformed).expect_err("merkle proof path should reject atom");

        assert!(err.to_string().contains("merkle proof path must be a list"));
    }
}
