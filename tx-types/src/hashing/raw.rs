use crate::hashing::hashable::Hashable;
use crate::hashing::hasher::hash_hashable;
use crate::transaction_types::{Hash, SchnorrPubkey, SchnorrSignature};
use crate::transaction_types_v1::LockMerkleProof;
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{Atom, Cell, Noun, D};
use noun_serde::{NounDecode, NounDecodeError};

fn noun_to_hex(noun: Noun) -> String {
    let mut slab: NounSlab = NounSlab::new();
    let copy = slab.copy_into(noun);
    slab.set_root(copy);
    let jam = slab.jam();
    jam.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn expect_cell(noun: Noun, ctx: &str) -> Result<Cell, NounDecodeError> {
    noun.as_cell().map_err(|_| {
        NounDecodeError::Custom(format!(
            "{}: expected cell, found {}",
            ctx,
            noun_to_hex(noun)
        ))
    })
}

fn noun_is_null(noun: Noun) -> bool {
    if let Ok(atom) = noun.as_atom() {
        atom.as_u64().map(|v| v == 0).unwrap_or(false)
    } else {
        false
    }
}

fn hashable_leaf_from_noun(noun: Noun) -> Hashable {
    let mut slab: NounSlab = NounSlab::new();
    let copy = slab.copy_into(noun);
    slab.set_root(copy);
    Hashable::Leaf(slab.jam().to_vec())
}

fn hashable_any_noun(noun: Noun) -> Hashable {
    if let Ok(cell) = noun.as_cell() {
        Hashable::cell(
            hashable_any_noun(cell.head()),
            hashable_any_noun(cell.tail()),
        )
    } else {
        hashable_leaf_from_noun(noun)
    }
}

fn extract_spend_payload(spend_noun: Noun) -> Option<(u64, Noun)> {
    let cell = spend_noun.as_cell().ok()?;
    let head_atom = cell.head().as_atom().ok()?.as_u64().ok()?;
    if head_atom <= 1 {
        Some((head_atom, cell.tail()))
    } else {
        let body = cell.tail();
        let body_cell = body.as_cell().ok()?;
        let variant = body_cell.head().as_atom().ok()?.as_u64().ok()?;
        Some((variant, body_cell.tail()))
    }
}

fn hashable_note_data_from_noun(noun: Noun) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(noun) {
        return Ok(hashable_leaf_from_noun(noun));
    }
    let cell = expect_cell(noun, "note-data node")?;
    let node = expect_cell(cell.head(), "note-data key-value pair")?;
    let key = hashable_leaf_from_noun(node.head());
    let value = hashable_any_noun(node.tail());
    let children = expect_cell(cell.tail(), "note-data children")?;
    let left = hashable_note_data_from_noun(children.head())?;
    let right = hashable_note_data_from_noun(children.tail())?;
    Ok(Hashable::triple(Hashable::cell(key, value), left, right))
}

fn hashable_seed_regular_from_noun(noun: Noun) -> Result<Hashable, NounDecodeError> {
    let cell = expect_cell(noun, "seed node")?;
    let tail1 = expect_cell(cell.tail(), "seed tail1")?;
    let lock_root = Hash::from_noun(&tail1.head())?;
    let tail2 = expect_cell(tail1.tail(), "seed tail2")?;
    let note_data = tail2.head();
    let tail3 = expect_cell(tail2.tail(), "seed tail3")?;
    let gift = tail3.head();
    let parent_hash = Hash::from_noun(&tail3.tail())?;

    let note_data_hash = hash_hashable(&hashable_note_data_from_noun(note_data)?);
    let gift_leaf = hashable_leaf_from_noun(gift);

    Ok(Hashable::cell(
        Hashable::Hash(lock_root),
        Hashable::cell(
            Hashable::Hash(note_data_hash),
            Hashable::cell(gift_leaf, Hashable::Hash(parent_hash)),
        ),
    ))
}

fn hashable_seeds_regular_from_noun(noun: Noun) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(noun) {
        return Ok(hashable_leaf_from_noun(noun));
    }
    let cell = expect_cell(noun, "seeds node")?;
    let seed_hashable = hashable_seed_regular_from_noun(cell.head())?;
    let children = expect_cell(cell.tail(), "seeds children")?;
    let left = hashable_seeds_regular_from_noun(children.head())?;
    let right = hashable_seeds_regular_from_noun(children.tail())?;
    Ok(Hashable::triple(seed_hashable, left, right))
}

fn split_witness_noun(noun: Noun) -> Result<(Noun, Noun, Noun, Noun), NounDecodeError> {
    let cell = expect_cell(noun, "witness root")?;
    let lmp = cell.head();
    let rest = expect_cell(cell.tail(), "witness tail")?;
    let pkh = rest.head();
    let tail = expect_cell(rest.tail(), "witness tail tail")?;
    let hax = tail.head();
    let tim = tail.tail();
    Ok((lmp, pkh, hax, tim))
}

fn hashable_hax_from_noun(noun: Noun) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(noun) {
        return Ok(hashable_leaf_from_noun(noun));
    }
    let cell = expect_cell(noun, "hax node")?;
    let pair = expect_cell(cell.head(), "hax pair")?;
    let key = Hash::from_noun(&pair.head())?;
    let value_hashable = hashable_any_noun(pair.tail());
    let children = expect_cell(cell.tail(), "hax children")?;
    let left = hashable_hax_from_noun(children.head())?;
    let right = hashable_hax_from_noun(children.tail())?;
    Ok(Hashable::triple(
        Hashable::cell(Hashable::Hash(key), value_hashable),
        left,
        right,
    ))
}

fn hashable_witness_from_noun(noun: Noun) -> Result<Hashable, NounDecodeError> {
    let (lmp_noun, pkh_noun, hax_noun, tim_noun) = split_witness_noun(noun)?;
    let lmp = LockMerkleProof::from_noun(&lmp_noun)?;
    let hax_hash = hash_hashable(&hashable_hax_from_noun(hax_noun)?);
    let tim_leaf = hashable_leaf_from_noun(tim_noun);
    let pkh_hash = hash_hashable(&hashable_pkh_signature_from_noun(pkh_noun)?);

    Ok(Hashable::cell_chain([
        Hashable::Hash(lmp.to_hash()),
        Hashable::Hash(pkh_hash),
        Hashable::Hash(hax_hash),
        tim_leaf,
    ]))
}

fn hashable_nname_from_noun(noun: Noun) -> Result<Hashable, NounDecodeError> {
    let cell = expect_cell(noun, "nname pair root")?;
    let first = Hash::from_noun(&cell.head())?;
    let tail = expect_cell(cell.tail(), "nname tail")?;
    let second = Hash::from_noun(&tail.head())?;
    let end = tail.tail();
    Ok(Hashable::triple(
        Hashable::Hash(first),
        Hashable::Hash(second),
        hashable_leaf_from_noun(end),
    ))
}

fn hashable_spend_v1_from_noun(spend_noun: Noun) -> Result<Hashable, NounDecodeError> {
    let (variant, payload) =
        extract_spend_payload(spend_noun).ok_or(NounDecodeError::ExpectedCell)?;
    if variant != 1 {
        return Err(NounDecodeError::Custom("unsupported spend variant".into()));
    }

    let parts = expect_cell(payload, "spend parts")?;
    let witness_noun = parts.head();
    let tail = expect_cell(parts.tail(), "spend tail (seeds+fee)")?;
    let seeds_noun = tail.head();
    let fee_noun = tail.tail();

    let witness_hashable = hashable_witness_from_noun(witness_noun)?;
    let seeds_hashable = hashable_seeds_regular_from_noun(seeds_noun)?;
    let fee_leaf = hashable_leaf_from_noun(fee_noun);

    Ok(Hashable::cell(
        Hashable::leaf_from_atom(1u64.to_le_bytes()),
        Hashable::triple(witness_hashable, seeds_hashable, fee_leaf),
    ))
}

fn split_children(children: Noun) -> Result<(Noun, Noun), NounDecodeError> {
    if noun_is_null(children) {
        return Ok((children, children));
    }

    let child_cell = expect_cell(children, "spends children pair")?;
    Ok((child_cell.head(), child_cell.tail()))
}

fn hashable_spends_from_noun(spends: Noun) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(spends) {
        return Ok(hashable_leaf_from_noun(spends));
    }

    let cell = expect_cell(spends, "spends node")?;
    let node = cell.head();
    let (left, right) = split_children(cell.tail())?;

    let pair = expect_cell(node, "spends node key/value pair")?;
    let name_noun = pair.head();
    let spend_noun = pair.tail();

    let node_hashable = Hashable::cell(
        hashable_nname_from_noun(name_noun)?,
        hashable_spend_v1_from_noun(spend_noun)?,
    );

    Ok(Hashable::triple(
        node_hashable,
        hashable_spends_from_noun(left)?,
        hashable_spends_from_noun(right)?,
    ))
}

fn hashable_pkh_signature_from_noun(noun: Noun) -> Result<Hashable, NounDecodeError> {
    if noun_is_null(noun) {
        return Ok(hashable_leaf_from_noun(noun));
    }

    let cell = expect_cell(noun, "pkh-signature node")?;
    let node = cell.head();
    let (left, right) = split_children(cell.tail())?;

    let pair = expect_cell(node, "pkh-signature kv pair")?;
    let key_hash = Hash::from_noun(&pair.head())?;
    let value_hashable = hashable_pkh_signature_value_from_noun(pair.tail())?;
    let node_hashable = Hashable::cell(Hashable::Hash(key_hash), value_hashable);

    Ok(Hashable::triple(
        node_hashable,
        hashable_pkh_signature_from_noun(left)?,
        hashable_pkh_signature_from_noun(right)?,
    ))
}

fn hashable_pkh_signature_value_from_noun(noun: Noun) -> Result<Hashable, NounDecodeError> {
    let value_cell = expect_cell(noun, "pkh-signature value")?;
    let pk_noun = value_cell.head();
    let sig_noun = value_cell.tail();
    let pk = SchnorrPubkey::from_noun(&pk_noun)?;
    let sig = SchnorrSignature::from_noun(&sig_noun)?;
    Ok(Hashable::cell(
        Hashable::Hash(pk.to_hash()),
        sig.to_hashable(),
    ))
}

pub fn hashable_spend_from_raw(spend_noun: Noun) -> Result<Hashable, NounDecodeError> {
    hashable_spend_v1_from_noun(spend_noun)
}

pub fn hashable_witness_from_raw(witness_noun: Noun) -> Result<Hashable, NounDecodeError> {
    hashable_witness_from_noun(witness_noun)
}

pub fn hashable_seeds_from_raw(seeds_noun: Noun) -> Result<Hashable, NounDecodeError> {
    hashable_seeds_regular_from_noun(seeds_noun)
}

pub fn hashable_note_data_from_raw(noun: Noun) -> Result<Hashable, NounDecodeError> {
    hashable_note_data_from_noun(noun)
}

pub fn hashable_pkh_signature_from_raw(noun: Noun) -> Result<Hashable, NounDecodeError> {
    hashable_pkh_signature_from_noun(noun)
}

pub fn hashable_pkh_signature_direct(noun: Noun) -> Hashable {
    hashable_leaf_from_noun(noun)
}

pub fn hashable_spends_from_raw(spends_noun: Noun) -> Result<Hashable, NounDecodeError> {
    hashable_spends_from_noun(spends_noun)
}

pub fn compute_tx_id_v1_from_raw_noun(spends_noun: Noun) -> Result<Hash, NounDecodeError> {
    let spends_hashable = hashable_spends_from_noun(spends_noun)?;
    let version_leaf = Hashable::leaf_from_atom(1u64.to_le_bytes());
    let hashable = Hashable::cell(version_leaf, spends_hashable);
    Ok(hash_hashable(&hashable))
}
