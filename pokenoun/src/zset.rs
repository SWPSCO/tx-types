use crate::arena::{Arena, Noun};
use crate::tip5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZSetError {
    Tip5(tip5::Tip5Error),
    Malformed,
}

impl From<tip5::Tip5Error> for ZSetError {
    fn from(e: tip5::Tip5Error) -> Self {
        Self::Tip5(e)
    }
}

fn noun_is_null(noun: Noun, arena: &Arena) -> bool {
    matches!(noun, Noun::Atom(id) if arena.atom_u64(id) == Some(0))
}

fn nouns_equal(a: Noun, b: Noun, arena: &Arena) -> bool {
    match (a, b) {
        (Noun::Atom(x), Noun::Atom(y)) => arena.atom_bytes(x) == arena.atom_bytes(y),
        (Noun::Cell(ac), Noun::Cell(bc)) => {
            let a_cell = arena.cell(ac);
            let b_cell = arena.cell(bc);
            nouns_equal(a_cell.head, b_cell.head, arena) && nouns_equal(a_cell.tail, b_cell.tail, arena)
        }
        _ => false,
    }
}

fn atom_less_than(a: Noun, b: Noun, arena: &Arena) -> bool {
    let (Noun::Atom(a), Noun::Atom(b)) = (a, b) else {
        return false;
    };
    let ab = arena.atom_bytes(a);
    let bb = arena.atom_bytes(b);
    if ab.len() != bb.len() {
        return ab.len() < bb.len();
    }
    for i in (0..ab.len()).rev() {
        if ab[i] != bb[i] {
            return ab[i] < bb[i];
        }
    }
    false
}

fn dor_tip_compare(a: Noun, b: Noun, arena: &Arena) -> bool {
    if nouns_equal(a, b, arena) {
        return true;
    }

    match (a, b) {
        (Noun::Cell(ac), Noun::Cell(bc)) => {
            let ac = arena.cell(ac);
            let bc = arena.cell(bc);
            if nouns_equal(ac.head, bc.head, arena) {
                dor_tip_compare(ac.tail, bc.tail, arena)
            } else {
                dor_tip_compare(ac.head, bc.head, arena)
            }
        }
        (Noun::Atom(_), Noun::Cell(_)) => false,
        (Noun::Cell(_), Noun::Atom(_)) => false,
        (Noun::Atom(_), Noun::Atom(_)) => atom_less_than(a, b, arena),
    }
}

fn less_than_hash(a: &[u64; 5], b: &[u64; 5]) -> bool {
    // Compare digits in base P from most significant to least significant.
    for i in (0..5).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

fn tip_hash(noun: Noun, arena: &Arena) -> Result<[u64; 5], ZSetError> {
    Ok(tip5::hash_noun_varlen(noun, arena)?)
}

fn double_tip_hash(noun: Noun, arena: &Arena) -> Result<[u64; 5], ZSetError> {
    let tip = tip_hash(noun, arena)?;
    Ok(tip5::hash_ten_cell(tip, tip)?)
}

fn gor_tip_compare(a: Noun, b: Noun, arena: &Arena) -> Result<bool, ZSetError> {
    let a_tip = tip_hash(a, arena)?;
    let b_tip = tip_hash(b, arena)?;
    if a_tip == b_tip {
        Ok(dor_tip_compare(a, b, arena))
    } else {
        Ok(less_than_hash(&a_tip, &b_tip))
    }
}

fn mor_tip_compare(a: Noun, b: Noun, arena: &Arena) -> Result<bool, ZSetError> {
    let a_tip = double_tip_hash(a, arena)?;
    let b_tip = double_tip_hash(b, arena)?;
    if a_tip == b_tip {
        Ok(dor_tip_compare(a, b, arena))
    } else {
        Ok(less_than_hash(&a_tip, &b_tip))
    }
}

fn tuple(arena: &mut Arena, elems: &[Noun]) -> Noun {
    if elems.is_empty() {
        return arena.atom0();
    }
    let mut res = *elems.last().unwrap();
    for &n in elems[..elems.len() - 1].iter().rev() {
        res = arena.alloc_cell(n, res);
    }
    res
}

fn decompose_set(set: Noun, arena: &Arena) -> Result<(Noun, Noun, Noun), ZSetError> {
    let Noun::Cell(id) = set else {
        return Err(ZSetError::Malformed);
    };
    let cell = arena.cell(id);
    let value = cell.head;
    let tail = cell.tail;

    if let Noun::Cell(children_id) = tail {
        let children = arena.cell(children_id);
        Ok((value, children.head, children.tail))
    } else {
        Ok((value, tail, arena.atom0()))
    }
}

/// Insert a value into a canonical z-set noun.
///
/// This mirrors `ZSet::put` in `tx-types`, but operates on our no_std noun arena.
pub fn canonical_zset_put(arena: &mut Arena, set: Noun, value: Noun) -> Result<Noun, ZSetError> {
    if noun_is_null(set, arena) {
        return Ok(tuple(arena, &[value, arena.atom0(), arena.atom0()]));
    }

    let (node_value, left, right) = decompose_set(set, arena)?;

    if nouns_equal(value, node_value, arena) {
        return Ok(set);
    }

    if gor_tip_compare(value, node_value, arena)? {
        let new_left = canonical_zset_put(arena, left, value)?;
        let (left_value, left_left, left_right) = decompose_set(new_left, arena)?;

        if mor_tip_compare(node_value, left_value, arena)? {
            Ok(tuple(arena, &[node_value, new_left, right]))
        } else {
            let new_right_branch = tuple(arena, &[node_value, left_right, right]);
            Ok(tuple(arena, &[left_value, left_left, new_right_branch]))
        }
    } else {
        let new_right = canonical_zset_put(arena, right, value)?;
        let (right_value, right_left, right_right) = decompose_set(new_right, arena)?;

        if mor_tip_compare(node_value, right_value, arena)? {
            Ok(tuple(arena, &[node_value, left, new_right]))
        } else {
            let new_left_branch = tuple(arena, &[node_value, left, right_left]);
            Ok(tuple(arena, &[right_value, new_left_branch, right_right]))
        }
    }
}

