use crate::hashing::hashable::Hashable;
use crate::hashing::hasher::hash_hashable;
use crate::transaction_types::{Hash, SchnorrPubkey, SchnorrSignature};
use crate::transaction_types_v1::LockMerkleProof;
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{CellHandle, Noun, NounSpace};
use noun_serde::{NounDecode, NounDecodeError};

fn tip5_decode_error(err: crate::hashing::tip5::Tip5Error) -> NounDecodeError {
    NounDecodeError::Custom(format!("tip5 hashing failed: {}", err))
}

fn noun_to_hex(noun: Noun, space: &NounSpace) -> String {
    let mut slab: NounSlab = NounSlab::new();
    let copy = slab.copy_into(noun, space);
    slab.set_root(copy);
    let jam = slab.jam();
    jam.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn expect_cell<'a>(
    noun: Noun,
    space: &'a NounSpace,
    ctx: &str,
) -> Result<CellHandle<'a>, NounDecodeError> {
    noun.in_space(space).as_cell().map_err(|_| {
        NounDecodeError::Custom(format!(
            "{}: expected cell, found {}",
            ctx,
            noun_to_hex(noun, space)
        ))
    })
}

fn noun_is_null(noun: Noun, space: &NounSpace) -> bool {
    if let Ok(atom) = noun.in_space(space).as_atom() {
        atom.as_u64().map(|v| v == 0).unwrap_or(false)
    } else {
        false
    }
}

fn hashable_leaf_from_noun(noun: Noun, space: &NounSpace) -> Hashable {
    let mut slab: NounSlab = NounSlab::new();
    let copy = slab.copy_into(noun, space);
    slab.set_root(copy);
    Hashable::Leaf(slab.jam().to_vec())
}

fn hashable_any_noun(noun: Noun, space: &NounSpace) -> Hashable {
    if let Ok(cell) = noun.in_space(space).as_cell() {
        Hashable::cell(
            hashable_any_noun(cell.head().noun(), space),
            hashable_any_noun(cell.tail().noun(), space),
        )
    } else {
        hashable_leaf_from_noun(noun, space)
    }
}

fn extract_spend_payload(spend_noun: Noun, space: &NounSpace) -> Option<(u64, Noun)> {
    let cell = spend_noun.in_space(space).as_cell().ok()?;
    let head_atom = cell.head().as_atom().ok()?.as_u64().ok()?;
    if head_atom <= 1 {
        Some((head_atom, cell.tail().noun()))
    } else {
        let body = cell.tail();
        let body_cell = body.as_cell().ok()?;
        let variant = body_cell.head().as_atom().ok()?.as_u64().ok()?;
        Some((variant, body_cell.tail().noun()))
    }
}

fn hashable_note_data_from_noun(
    noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(noun, space) {
        return Ok(hashable_leaf_from_noun(noun, space));
    }
    let cell = expect_cell(noun, space, "note-data node")?;
    let node = expect_cell(cell.head().noun(), space, "note-data key-value pair")?;
    let key = hashable_leaf_from_noun(node.head().noun(), space);
    let value = hashable_any_noun(node.tail().noun(), space);
    let children = expect_cell(cell.tail().noun(), space, "note-data children")?;
    let left = hashable_note_data_from_noun(children.head().noun(), space)?;
    let right = hashable_note_data_from_noun(children.tail().noun(), space)?;
    Ok(Hashable::triple(Hashable::cell(key, value), left, right))
}

fn hashable_seed_regular_from_noun(
    noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    let cell = expect_cell(noun, space, "seed node")?;
    let tail1 = expect_cell(cell.tail().noun(), space, "seed tail1")?;
    let lock_root = Hash::from_noun(&tail1.head().noun(), space)?;
    let tail2 = expect_cell(tail1.tail().noun(), space, "seed tail2")?;
    let note_data = tail2.head().noun();
    let tail3 = expect_cell(tail2.tail().noun(), space, "seed tail3")?;
    let gift = tail3.head().noun();
    let parent_hash = Hash::from_noun(&tail3.tail().noun(), space)?;

    let note_data_hash = hash_hashable(&hashable_note_data_from_noun(note_data, space)?)
        .map_err(tip5_decode_error)?;
    let gift_leaf = hashable_leaf_from_noun(gift, space);

    Ok(Hashable::cell(
        Hashable::Hash(lock_root),
        Hashable::cell(
            Hashable::Hash(note_data_hash),
            Hashable::cell(gift_leaf, Hashable::Hash(parent_hash)),
        ),
    ))
}

fn hashable_seeds_regular_from_noun(
    noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(noun, space) {
        return Ok(hashable_leaf_from_noun(noun, space));
    }
    let cell = expect_cell(noun, space, "seeds node")?;
    let seed_hashable = hashable_seed_regular_from_noun(cell.head().noun(), space)?;
    let children = expect_cell(cell.tail().noun(), space, "seeds children")?;
    let left = hashable_seeds_regular_from_noun(children.head().noun(), space)?;
    let right = hashable_seeds_regular_from_noun(children.tail().noun(), space)?;
    Ok(Hashable::triple(seed_hashable, left, right))
}

fn split_witness_noun(
    noun: Noun,
    space: &NounSpace,
) -> Result<(Noun, Noun, Noun, Noun), NounDecodeError> {
    let cell = expect_cell(noun, space, "witness root")?;
    let lmp = cell.head().noun();
    let rest = expect_cell(cell.tail().noun(), space, "witness tail")?;
    let pkh = rest.head().noun();
    let tail = expect_cell(rest.tail().noun(), space, "witness tail tail")?;
    let hax = tail.head().noun();
    let tim = tail.tail().noun();
    Ok((lmp, pkh, hax, tim))
}

fn hashable_hax_from_noun(noun: Noun, space: &NounSpace) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(noun, space) {
        return Ok(hashable_leaf_from_noun(noun, space));
    }
    let cell = expect_cell(noun, space, "hax node")?;
    let pair = expect_cell(cell.head().noun(), space, "hax pair")?;
    let key = Hash::from_noun(&pair.head().noun(), space)?;
    let value_hashable = hashable_any_noun(pair.tail().noun(), space);
    let children = expect_cell(cell.tail().noun(), space, "hax children")?;
    let left = hashable_hax_from_noun(children.head().noun(), space)?;
    let right = hashable_hax_from_noun(children.tail().noun(), space)?;
    Ok(Hashable::triple(
        Hashable::cell(Hashable::Hash(key), value_hashable),
        left,
        right,
    ))
}

fn hashable_witness_from_noun(noun: Noun, space: &NounSpace) -> Result<Hashable, NounDecodeError> {
    let (lmp_noun, pkh_noun, hax_noun, tim_noun) = split_witness_noun(noun, space)?;
    let lmp = LockMerkleProof::from_noun(&lmp_noun, space)?;
    let hax_hash =
        hash_hashable(&hashable_hax_from_noun(hax_noun, space)?).map_err(tip5_decode_error)?;
    let tim_leaf = hashable_leaf_from_noun(tim_noun, space);
    let pkh_hash = hash_hashable(&hashable_pkh_signature_from_noun(pkh_noun, space)?)
        .map_err(tip5_decode_error)?;

    Ok(Hashable::cell_chain([
        Hashable::Hash(lmp.to_hash()),
        Hashable::Hash(pkh_hash),
        Hashable::Hash(hax_hash),
        tim_leaf,
    ]))
}

fn hashable_nname_from_noun(noun: Noun, space: &NounSpace) -> Result<Hashable, NounDecodeError> {
    let cell = expect_cell(noun, space, "nname pair root")?;
    let first = Hash::from_noun(&cell.head().noun(), space)?;
    let tail = expect_cell(cell.tail().noun(), space, "nname tail")?;
    let second = Hash::from_noun(&tail.head().noun(), space)?;
    let end = tail.tail().noun();
    Ok(Hashable::triple(
        Hashable::Hash(first),
        Hashable::Hash(second),
        hashable_leaf_from_noun(end, space),
    ))
}

fn hashable_spend_v1_from_noun(
    spend_noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    let (variant, payload) =
        extract_spend_payload(spend_noun, space).ok_or(NounDecodeError::ExpectedCell)?;
    if variant != 1 {
        return Err(NounDecodeError::Custom("unsupported spend variant".into()));
    }

    let parts = expect_cell(payload, space, "spend parts")?;
    let witness_noun = parts.head().noun();
    let tail = expect_cell(parts.tail().noun(), space, "spend tail (seeds+fee)")?;
    let seeds_noun = tail.head().noun();
    let fee_noun = tail.tail().noun();

    let witness_hashable = hashable_witness_from_noun(witness_noun, space)?;
    let seeds_hashable = hashable_seeds_regular_from_noun(seeds_noun, space)?;
    let fee_leaf = hashable_leaf_from_noun(fee_noun, space);

    Ok(Hashable::cell(
        Hashable::leaf_from_atom(1u64.to_le_bytes()),
        Hashable::triple(witness_hashable, seeds_hashable, fee_leaf),
    ))
}

fn split_children(children: Noun, space: &NounSpace) -> Result<(Noun, Noun), NounDecodeError> {
    if noun_is_null(children, space) {
        return Ok((children, children));
    }

    let child_cell = expect_cell(children, space, "spends children pair")?;
    Ok((child_cell.head().noun(), child_cell.tail().noun()))
}

fn hashable_spends_from_noun(spends: Noun, space: &NounSpace) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(spends, space) {
        return Ok(hashable_leaf_from_noun(spends, space));
    }

    let cell = expect_cell(spends, space, "spends node")?;
    let node = cell.head().noun();
    let (left, right) = split_children(cell.tail().noun(), space)?;

    let pair = expect_cell(node, space, "spends node key/value pair")?;
    let name_noun = pair.head().noun();
    let spend_noun = pair.tail().noun();

    let node_hashable = Hashable::cell(
        hashable_nname_from_noun(name_noun, space)?,
        hashable_spend_v1_from_noun(spend_noun, space)?,
    );

    Ok(Hashable::triple(
        node_hashable,
        hashable_spends_from_noun(left, space)?,
        hashable_spends_from_noun(right, space)?,
    ))
}

fn hashable_pkh_signature_from_noun(
    noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(noun, space) {
        return Ok(hashable_leaf_from_noun(noun, space));
    }

    let cell = expect_cell(noun, space, "pkh-signature node")?;
    let node = cell.head().noun();
    let (left, right) = split_children(cell.tail().noun(), space)?;

    let pair = expect_cell(node, space, "pkh-signature kv pair")?;
    let key_hash = Hash::from_noun(&pair.head().noun(), space)?;
    let value_hashable = hashable_pkh_signature_value_from_noun(pair.tail().noun(), space)?;
    let node_hashable = Hashable::cell(Hashable::Hash(key_hash), value_hashable);

    Ok(Hashable::triple(
        node_hashable,
        hashable_pkh_signature_from_noun(left, space)?,
        hashable_pkh_signature_from_noun(right, space)?,
    ))
}

fn hashable_pkh_signature_value_from_noun(
    noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    let value_cell = expect_cell(noun, space, "pkh-signature value")?;
    let pk_noun = value_cell.head().noun();
    let sig_noun = value_cell.tail().noun();
    let pk = SchnorrPubkey::from_noun(&pk_noun, space)?;
    let sig = SchnorrSignature::from_noun(&sig_noun, space)?;
    Ok(Hashable::cell(
        Hashable::Hash(pk.to_hash()),
        sig.to_hashable(),
    ))
}

pub fn hashable_spend_from_raw(
    spend_noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    hashable_spend_v1_from_noun(spend_noun, space)
}

pub fn hashable_witness_from_raw(
    witness_noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    hashable_witness_from_noun(witness_noun, space)
}

pub fn hashable_seeds_from_raw(
    seeds_noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    hashable_seeds_regular_from_noun(seeds_noun, space)
}

pub fn hashable_note_data_from_raw(
    noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    hashable_note_data_from_noun(noun, space)
}

pub fn hashable_pkh_signature_from_raw(
    noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    hashable_pkh_signature_from_noun(noun, space)
}

pub fn hashable_pkh_signature_direct(noun: Noun, space: &NounSpace) -> Hashable {
    hashable_leaf_from_noun(noun, space)
}

pub fn hashable_spends_from_raw(
    spends_noun: Noun,
    space: &NounSpace,
) -> Result<Hashable, NounDecodeError> {
    hashable_spends_from_noun(spends_noun, space)
}

pub fn compute_tx_id_v1_from_raw_noun(
    spends_noun: Noun,
    space: &NounSpace,
) -> Result<Hash, NounDecodeError> {
    let spends_hashable = hashable_spends_from_noun(spends_noun, space)?;
    let version_leaf = Hashable::leaf_from_atom(1u64.to_le_bytes());
    let hashable = Hashable::cell(version_leaf, spends_hashable);
    hash_hashable(&hashable).map_err(tip5_decode_error)
}
