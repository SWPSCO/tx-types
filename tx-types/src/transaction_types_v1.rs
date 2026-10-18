use noun_serde::{NounDecode, NounEncode};

use crate::collections::zset::DorTip as ZSetDorTip;
use crate::collections::{ZMap, ZSet};
use crate::generic_noun::UntypedNoun;
use crate::transaction_types::*;
use nockapp::noun::slab::NounSlab;
use nockapp::utils::make_tas;
use nockapp::Bytes;
use nockvm::noun::{Noun, NounAllocator, NounSpace, D};
use once_cell::sync::Lazy;

use crate::hashing::hashable::Hashable;
use crate::hashing::hasher::{hash_hashable, hash_ten_cell};
use crate::hashing::raw::hashable_spends_from_raw;
use crate::hashing::tip5::{Tip5Error, Tip5Hasher};

static LOCK_MERKLE_AXIS_HASH: Lazy<Hash> = Lazy::new(|| {
    Hash::from_b58("6mhCSwJQDvbkbiPAUNjetJtVoo1VLtEhmEYoU4hmdGd6ep1F6ayaV4A")
        .expect("valid lock merkle proof axis hash constant")
});

fn hashable_from_noun_recursive(
    noun: nockvm::noun::Noun,
    space: &NounSpace,
) -> Result<Hashable, Tip5Error> {
    if let Ok(cell) = noun.in_space(space).as_cell() {
        Ok(Hashable::cell(
            hashable_from_noun_recursive(cell.head().noun(), space)?,
            hashable_from_noun_recursive(cell.tail().noun(), space)?,
        ))
    } else {
        let atom = noun.in_space(space).as_atom().map_err(|_| {
            Tip5Error::InvalidNoun("hashable_from_noun_recursive: expected atom or cell".into())
        })?;
        match atom.as_u64() {
            Ok(val) => Ok(Hashable::leaf_from_atom(&val.to_le_bytes())),
            Err(_) => {
                let mut slab: NounSlab = NounSlab::new();
                slab.copy_into(atom.as_noun().noun(), space);
                Ok(Hashable::Leaf(slab.jam().to_vec()))
            }
        }
    }
}

fn hashable_from_untyped_noun(untyped: &UntypedNoun) -> Result<Hashable, Tip5Error> {
    let mut slab: NounSlab = NounSlab::new();
    let noun = slab
        .cue_into(untyped.p.clone())
        .map_err(|e| Tip5Error::SerializationError(format!("failed to cue noun: {:?}", e)))?;

    let space = slab.noun_space();
    hashable_from_noun_recursive(noun, &space)
}

fn hashable_leaf_from_noun(noun: Noun, space: &NounSpace) -> Hashable {
    let mut slab: NounSlab = NounSlab::new();
    let copy = slab.copy_into(noun, space);
    slab.set_root(copy);
    Hashable::Leaf(slab.jam().to_vec())
}

fn hashable_note_data_from_zmap(noun: Noun, space: &NounSpace) -> Result<Hashable, Tip5Error> {
    if let Ok(atom) = noun.in_space(space).as_atom() {
        if atom.as_u64().unwrap_or(1) == 0 {
            return Ok(Hashable::null());
        }
    }

    let invalid = || Tip5Error::InvalidNoun("malformed note-data node".into());
    let cell = noun.in_space(space).as_cell().map_err(|_| invalid())?;
    let node = cell.head();
    let children = cell.tail().as_cell().map_err(|_| invalid())?;
    let left = children.head();
    let right = match children.tail().as_cell() {
        Ok(right_cell) => right_cell.head(),
        Err(_) => children.tail(),
    };

    let pair = node.as_cell().map_err(|_| invalid())?;
    let key_noun = pair.head();
    let value_noun = pair.tail();

    let key_leaf = hashable_leaf_from_noun(key_noun.noun(), space);
    let value_hashable = hashable_from_noun_recursive(value_noun.noun(), space)?;
    let node_hashable = Hashable::cell(key_leaf, value_hashable);

    Ok(Hashable::triple(
        node_hashable,
        hashable_note_data_from_zmap(left.noun(), space)?,
        hashable_note_data_from_zmap(right.noun(), space)?,
    ))
}

pub fn hashable_spends_from_zmap(noun: Noun, space: &NounSpace) -> Result<Hashable, Tip5Error> {
    if noun_is_null(noun) {
        return Ok(Hashable::null());
    }

    let (node, left, right) = decompose_map(noun, space)?;
    let (name_noun, spend_noun) = decompose_pair(node, space)?;

    let name = NName::from_noun(&name_noun, space)
        .map_err(|e| Tip5Error::InvalidNoun(format!("failed to decode spend name: {:?}", e)))?;
    let spend = Spend::from_noun(&spend_noun, space)
        .map_err(|e| Tip5Error::InvalidNoun(format!("failed to decode spend entry: {:?}", e)))?;

    let node_hashable = Hashable::cell(name.to_hashable(), spend.to_hashable()?);

    Ok(Hashable::triple(
        node_hashable,
        hashable_spends_from_zmap(left, space)?,
        hashable_spends_from_zmap(right, space)?,
    ))
}

fn noun_is_null(noun: Noun) -> bool {
    unsafe { noun.raw_equals(&D(0)) }
}

fn atom_trimmed_be(atom: nockvm::noun::AtomHandle) -> Vec<u8> {
    let mut bytes = atom.to_be_bytes();
    let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    if first_non_zero == bytes.len() {
        vec![0]
    } else {
        bytes.split_off(first_non_zero)
    }
}

fn nouns_equal(a: Noun, b: Noun, space: &NounSpace) -> bool {
    if unsafe { a.raw_equals(&b) } {
        return true;
    }

    match (a.in_space(space).as_cell(), b.in_space(space).as_cell()) {
        (Ok(ac), Ok(bc)) => {
            nouns_equal(ac.head().noun(), bc.head().noun(), space)
                && nouns_equal(ac.tail().noun(), bc.tail().noun(), space)
        }
        (Err(_), Err(_)) => {
            if let (Ok(a_atom), Ok(b_atom)) =
                (a.in_space(space).as_atom(), b.in_space(space).as_atom())
            {
                atom_trimmed_be(a_atom) == atom_trimmed_be(b_atom)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn atom_less_than(a: nockvm::noun::AtomHandle, b: nockvm::noun::AtomHandle) -> bool {
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

fn tip_hash(noun: Noun, space: &NounSpace) -> Result<[u64; 5], Tip5Error> {
    Tip5Hasher::hash_noun_varlen(noun, space).map(|hash| hash.values)
}

fn double_tip_hash(noun: Noun, space: &NounSpace) -> Result<[u64; 5], Tip5Error> {
    let tip = tip_hash(noun, space)?;
    let hash = Hash { values: tip };
    Ok(hash_ten_cell(hash.clone(), hash).values)
}

fn dor_tip_compare(a: Noun, b: Noun, space: &NounSpace) -> bool {
    if nouns_equal(a, b, space) {
        return true;
    }

    match (a.in_space(space).as_cell(), b.in_space(space).as_cell()) {
        (Ok(ac), Ok(bc)) => {
            if nouns_equal(ac.head().noun(), bc.head().noun(), space) {
                dor_tip_compare(ac.tail().noun(), bc.tail().noun(), space)
            } else {
                dor_tip_compare(ac.head().noun(), bc.head().noun(), space)
            }
        }
        (Ok(_), Err(_)) => false,
        (Err(_), Ok(_)) => false,
        (Err(_), Err(_)) => {
            if let (Ok(a_atom), Ok(b_atom)) =
                (a.in_space(space).as_atom(), b.in_space(space).as_atom())
            {
                atom_less_than(a_atom, b_atom)
            } else {
                false
            }
        }
    }
}

fn gor_tip_compare(a: Noun, b: Noun, space: &NounSpace) -> Result<bool, Tip5Error> {
    let a_tip = tip_hash(a, space)?;
    let b_tip = tip_hash(b, space)?;
    if a_tip == b_tip {
        Ok(dor_tip_compare(a, b, space))
    } else {
        Ok(less_than_hash(&a_tip, &b_tip))
    }
}

fn mor_tip_compare(a: Noun, b: Noun, space: &NounSpace) -> Result<bool, Tip5Error> {
    let a_tip = double_tip_hash(a, space)?;
    let b_tip = double_tip_hash(b, space)?;
    if a_tip == b_tip {
        Ok(dor_tip_compare(a, b, space))
    } else {
        Ok(less_than_hash(&a_tip, &b_tip))
    }
}

fn decompose_map(noun: Noun, space: &NounSpace) -> Result<(Noun, Noun, Noun), Tip5Error> {
    let cell = noun
        .in_space(space)
        .as_cell()
        .map_err(|_| Tip5Error::InvalidNoun("map node must be a cell".into()))?;
    let node = cell.head().noun();
    let tail = cell.tail();

    if let Ok(children) = tail.as_cell() {
        let left = children.head().noun();
        let right = children.tail().noun();
        Ok((node, left, right))
    } else {
        Ok((node, tail.noun(), D(0)))
    }
}

fn decompose_pair(noun: Noun, space: &NounSpace) -> Result<(Noun, Noun), Tip5Error> {
    let cell = noun
        .in_space(space)
        .as_cell()
        .map_err(|_| Tip5Error::InvalidNoun("pair must be a cell".into()))?;
    let key = cell.head().noun();
    let value = cell.tail().noun();
    Ok((key, value))
}

fn canonical_zmap_put<A: nockvm::noun::NounAllocator>(
    alloc: &mut A,
    map: Noun,
    key: Noun,
    value: Noun,
) -> Result<Noun, Tip5Error> {
    if noun_is_null(map) {
        let kv = nockvm::noun::T(alloc, &[key, value]);
        let children = nockvm::noun::T(alloc, &[D(0), D(0)]);
        return Ok(nockvm::noun::T(alloc, &[kv, children]));
    }

    // Refresh the space after any prior allocation; a stack-backed space holds
    // an epoch snapshot that allocations advance.
    let space = alloc.noun_space();
    let (node, left, right) = decompose_map(map, &space)?;
    let (node_key, node_value) = decompose_pair(node, &space)?;

    if nouns_equal(key, node_key, &space) {
        if nouns_equal(value, node_value, &space) {
            Ok(map)
        } else {
            let new_node = nockvm::noun::T(alloc, &[key, value]);
            Ok(nockvm::noun::T(alloc, &[new_node, left, right]))
        }
    } else if gor_tip_compare(key, node_key, &space)? {
        let new_left = canonical_zmap_put(alloc, left, key, value)?;
        let space = alloc.noun_space();
        let (new_left_node, new_left_left, new_left_right) = decompose_map(new_left, &space)?;
        let (new_left_key, _) = decompose_pair(new_left_node, &space)?;

        if mor_tip_compare(node_key, new_left_key, &space)? {
            let children = nockvm::noun::T(alloc, &[new_left, right]);
            Ok(nockvm::noun::T(alloc, &[node, children]))
        } else {
            let right_children = nockvm::noun::T(alloc, &[new_left_right, right]);
            let new_right_branch = nockvm::noun::T(alloc, &[node, right_children]);
            let left_children = nockvm::noun::T(alloc, &[new_left_left, new_right_branch]);
            Ok(nockvm::noun::T(alloc, &[new_left_node, left_children]))
        }
    } else {
        let new_right = canonical_zmap_put(alloc, right, key, value)?;
        let space = alloc.noun_space();
        let (new_right_node, new_right_left, new_right_right) = decompose_map(new_right, &space)?;
        let (new_right_key, _) = decompose_pair(new_right_node, &space)?;

        if mor_tip_compare(node_key, new_right_key, &space)? {
            let children = nockvm::noun::T(alloc, &[left, new_right]);
            Ok(nockvm::noun::T(alloc, &[node, children]))
        } else {
            let left_children = nockvm::noun::T(alloc, &[left, new_right_left]);
            let new_left_branch = nockvm::noun::T(alloc, &[node, left_children]);
            let right_children = nockvm::noun::T(alloc, &[new_left_branch, new_right_right]);
            Ok(nockvm::noun::T(alloc, &[new_right_node, right_children]))
        }
    }
}

fn build_canonical_zmap_from_pairs<A, I, K, V, KF, VF>(
    alloc: &mut A,
    entries: I,
    mut key_fn: KF,
    mut value_fn: VF,
) -> Result<Noun, Tip5Error>
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
        root = canonical_zmap_put(alloc, root, key_noun, value_noun)?;
    }
    Ok(root)
}

fn build_canonical_note_data_noun<A: nockvm::noun::NounAllocator>(
    alloc: &mut A,
    map: &ZMap<String, UntypedNoun>,
) -> Result<Noun, Tip5Error> {
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
) -> Result<Noun, Tip5Error> {
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

#[derive(Debug, Clone, NounDecode)]
pub struct NoteData {
    pub map: ZMap<String, UntypedNoun>,
}

impl NounEncode for NoteData {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        build_canonical_note_data_noun(alloc, &self.map)
            .expect("note-data z-map keys are u64-based")
    }
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
        let mut slab: NounSlab = NounSlab::new();
        let noun = build_canonical_note_data_noun(&mut slab, &self.map)?;
        let space = slab.noun_space();
        hashable_note_data_from_zmap(noun, &space)
    }

    /// Return the canonical note-data noun jam used for hashing/debugging.
    pub fn jam_canonical(&self) -> Vec<u8> {
        let mut slab: NounSlab = NounSlab::new();
        let noun = build_canonical_note_data_noun(&mut slab, &self.map)
            .expect("note-data z-map keys are u64-based");
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
    pub fn to_hashable(&self) -> Result<Hashable, Tip5Error> {
        let mut slab: NounSlab = NounSlab::new();
        let noun = build_canonical_spends_noun(&mut slab, &self.map)?;
        let space = slab.noun_space();
        hashable_spends_from_raw(noun, &space)
            .map_err(|e| Tip5Error::InvalidNoun(format!("invalid spends noun: {:?}", e)))
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
        let mut slab: NounSlab = NounSlab::new();
        let noun = build_canonical_spends_noun(&mut slab, &self.map)
            .expect("spend z-map keys are u64-based");
        slab.set_root(noun);
        slab.jam().to_vec()
    }
}

impl NounEncode for SpendsV1 {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> Noun {
        build_canonical_spends_noun(alloc, &self.map).expect("spend z-map keys are u64-based")
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
pub fn compute_tx_id_v1_from_noun(spends_noun: Noun, space: &NounSpace) -> Result<Hash, Tip5Error> {
    let spends = SpendsV1::from_noun(&spends_noun, space)
        .map_err(|e| Tip5Error::InvalidNoun(format!("invalid spends noun: {:?}", e)))?;
    compute_tx_id_v1(&spends)
}

/// Compute the tx-id directly from the jammed noun bytes of the spends map.
pub fn compute_tx_id_v1_from_jam(spends_jam: &[u8]) -> Result<Hash, Tip5Error> {
    let mut slab: NounSlab = NounSlab::new();
    let noun = slab
        .cue_into(Bytes::copy_from_slice(spends_jam))
        .map_err(|e| Tip5Error::SerializationError(format!("failed to cue spends: {:?}", e)))?;
    let space = slab.noun_space();
    compute_tx_id_v1_from_noun(noun, &space)
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

#[derive(Debug, Clone, NounEncode)]
pub struct Witness {
    pub lmp: LockMerkleProof,
    pub pkh: PkhSignature,
    pub hax: ZMap<Hash, UntypedNoun>,
    pub tim: u64,
}

impl NounDecode for Witness {
    fn from_noun(noun: &Noun, space: &NounSpace) -> Result<Self, noun_serde::NounDecodeError> {
        use noun_serde::NounDecodeError;

        let cell = noun
            .in_space(space)
            .as_cell()
            .map_err(|_| NounDecodeError::ExpectedCell)?;
        let lmp = LockMerkleProof::from_noun(&cell.head().noun(), space)?;

        let rest = cell
            .tail()
            .as_cell()
            .map_err(|_| NounDecodeError::ExpectedCell)?;
        let pkh = PkhSignature::from_noun(&rest.head().noun(), space)?;

        let rest = rest
            .tail()
            .as_cell()
            .map_err(|_| NounDecodeError::ExpectedCell)?;
        let hax = ZMap::<Hash, UntypedNoun>::from_noun(&rest.head().noun(), space)?;

        let tim = rest
            .tail()
            .as_atom()
            .map_err(|_| NounDecodeError::ExpectedAtom)?
            .as_u64()
            .map_err(|_| NounDecodeError::Custom("witness tim must fit in u64".into()))?;

        // Upstream `Witness::from_noun` hardcodes `tim: 0` and Hoon requires
        // `~`; a non-zero value is not a valid witness encoding.
        if tim != 0 {
            return Err(NounDecodeError::Custom("witness tim must be 0 (~)".into()));
        }

        Ok(Self { lmp, pkh, hax, tim })
    }
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
                hashable_from_untyped_noun(untyped_noun)
            },
        )
    }

    pub fn to_hash(&self) -> Result<Hash, Tip5Error> {
        use crate::hashing::hasher::hash_hashable;
        hash_hashable(&self.to_hashable()?)
    }
}

fn decode_hoon_list<T, F>(
    noun: &Noun,
    space: &NounSpace,
    context: &'static str,
    mut decode_item: F,
) -> Result<Vec<T>, noun_serde::NounDecodeError>
where
    F: FnMut(&Noun) -> Result<T, noun_serde::NounDecodeError>,
{
    let mut items = Vec::new();
    let mut current = *noun;

    loop {
        let handle = current.in_space(space);
        if let Ok(cell) = handle.as_cell() {
            items.push(decode_item(&cell.head().noun())?);
            current = cell.tail().noun();
            continue;
        }

        let atom = handle
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

#[derive(Debug, Clone, NounDecode)]
pub struct LockMerkleProofStub {
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub merkle_proof: MerkleProof,
}

#[derive(Debug, Clone, NounDecode)]
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
            version: nockvm_macros::tas!(b"full"),
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

impl NounDecode for LockMerkleProof {
    fn from_noun(noun: &Noun, space: &NounSpace) -> Result<Self, noun_serde::NounDecodeError> {
        if let Ok(full) = LockMerkleProofFull::from_noun(noun, space) {
            if full.version != nockvm_macros::tas!(b"full") {
                return Err(noun_serde::NounDecodeError::Custom(
                    "lock-merkle-proof version must be %full".into(),
                ));
            }
            return Ok(Self::Full(full));
        }

        Ok(Self::Stub(LockMerkleProofStub::from_noun(noun, space)?))
    }
}

impl NounEncode for LockMerkleProofStub {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        let spend_condition = self.spend_condition.to_noun(alloc);
        let axis = self.axis.to_noun(alloc);
        let merkle_proof = self.merkle_proof.to_noun(alloc);
        nockvm::noun::T(alloc, &[spend_condition, axis, merkle_proof])
    }
}

impl NounEncode for LockMerkleProofFull {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        let version = self.version.to_noun(alloc);
        let spend_condition = self.spend_condition.to_noun(alloc);
        let axis = self.axis.to_noun(alloc);
        let merkle_proof = self.merkle_proof.to_noun(alloc);
        nockvm::noun::T(alloc, &[version, spend_condition, axis, merkle_proof])
    }
}

impl NounEncode for LockMerkleProof {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        match self {
            Self::Full(proof) => proof.to_noun(alloc),
            Self::Stub(proof) => proof.to_noun(alloc),
        }
    }
}

#[derive(Debug, Clone)]
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
        hash_hashable(&self.to_hashable()).expect("spend-condition hashable is u64-based")
    }
}

impl NounDecode for SpendCondition {
    fn from_noun(noun: &Noun, space: &NounSpace) -> Result<Self, noun_serde::NounDecodeError> {
        Ok(Self {
            p: decode_hoon_list(noun, space, "spend-condition", |item| {
                LockPrimitive::from_noun(item, space)
            })?,
        })
    }
}

impl NounEncode for SpendCondition {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        self.p.iter().rev().fold(D(0), |acc, primitive| {
            let head = primitive.to_noun(alloc);
            nockvm::noun::T(alloc, &[head, acc])
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

impl NounDecode for LockPrimitive {
    fn from_noun(
        noun: &nockvm::noun::Noun,
        space: &nockvm::noun::NounSpace,
    ) -> Result<Self, noun_serde::NounDecodeError> {
        let cell = noun
            .in_space(space)
            .as_cell()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?;
        let head = cell
            .head()
            .as_atom()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedAtom)?
            .into_string()?;
        let body = cell.tail().noun();
        match head.as_str() {
            "pkh" => Ok(LockPrimitive {
                header: head,
                body: LockPrimitiveBody::Pkh(Pkh::from_noun(&body, space)?),
            }),
            "tim" => Ok(LockPrimitive {
                header: head,
                body: LockPrimitiveBody::Tim(Tim::from_noun(&body, space)?),
            }),
            "hax" => Ok(LockPrimitive {
                header: head,
                body: LockPrimitiveBody::Hax(Hax::from_noun(&body, space)?),
            }),
            "brn" => Ok(LockPrimitive {
                header: head,
                body: LockPrimitiveBody::Brn(Brn::from_noun(&body, space)?),
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

impl NounDecode for MerkleProof {
    fn from_noun(noun: &Noun, space: &NounSpace) -> Result<Self, noun_serde::NounDecodeError> {
        let cell = noun
            .in_space(space)
            .as_cell()
            .map_err(|_| noun_serde::NounDecodeError::ExpectedCell)?;
        let root = Hash::from_noun(&cell.head().noun(), space)?;
        let path = decode_hoon_list(&cell.tail().noun(), space, "merkle proof path", |item| {
            Hash::from_noun(item, space)
        })?;
        Ok(Self { root, path })
    }
}

impl NounEncode for MerkleProof {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        let root = self.root.to_noun(alloc);
        let path = self.path.iter().rev().fold(D(0), |acc, hash| {
            let head = hash.to_noun(alloc);
            nockvm::noun::T(alloc, &[head, acc])
        });
        nockvm::noun::T(alloc, &[root, path])
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
        hash_hashable(&self.to_hashable()).expect("pkh-signature hashable is u64-based")
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
        hash_hashable(&self.to_hashable()).expect("pkh-signature-value hashable is u64-based")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nockvm::noun::{D, T};
    use noun_serde::NounEncode;

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
                assert_eq!(full.version, nockvm_macros::tas!(b"full"));
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
                assert_eq!(full.version, nockvm_macros::tas!(b"full"));
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

        assert!(err.to_string().contains("spend-condition must be a list"));
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

        assert!(err.to_string().contains("merkle proof path must be a list"));
    }
}
#[cfg(test)]
mod hardening_tests {
    use super::*;
    use nockapp::AtomExt;
    use nockvm::noun::{D, T};

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
                        let mut set = ZSet::new();
                        set.put(SeedV1 {
                            output_source: None,
                            lock_root: Hash { values: [1; 5] },
                            note_data: unbased_note_data(),
                            gift: Coins { value: 1 },
                            parent_hash: Hash { values: [2; 5] },
                        });
                        set
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
