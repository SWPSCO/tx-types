//! V1 tagged lock trees and proofs of whole spend conditions.

use crate::hashing::{hash_hashable, hash_ten_cell, Hashable};
use crate::transaction_types::Hash;
use crate::transaction_types_v1::{
    Brn, LockMerkleProof, LockPrimitive, LockPrimitiveBody, MerkleProof, SpendCondition,
};
use alloc::{vec, vec::Vec};
use pokenoun::codec::{pair, Decode, Encode, Error};
use pokenoun::{Arena, Noun};

#[derive(Debug, Clone)]
pub enum Lock {
    SpendCondition(SpendCondition),
    V2(LockV2),
    V4(LockV4),
    V8(LockV8),
    V16(LockV16),
}

#[derive(Debug, Clone)]
pub struct LockV2 {
    pub p: SpendCondition,
    pub q: SpendCondition,
}

#[derive(Debug, Clone)]
pub struct LockV4 {
    pub p: LockV2,
    pub q: LockV2,
}

#[derive(Debug, Clone)]
pub struct LockV8 {
    pub p: LockV4,
    pub q: LockV4,
}

#[derive(Debug, Clone)]
pub struct LockV16 {
    pub p: LockV8,
    pub q: LockV8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    InvalidLeafCount(usize),
    InvalidLeafIndex(u64),
    EmptySpendCondition,
    StubTreeProof,
    InvalidEncoding,
}

impl core::fmt::Display for LockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLeafCount(n) => {
                write!(f, "a lock requires 1 through 16 conditions, got {n}")
            }
            Self::InvalidLeafIndex(n) => write!(f, "lock leaf index {n} is out of range"),
            Self::EmptySpendCondition => f.write_str("an empty spend condition cannot authorize"),
            Self::InvalidEncoding => f.write_str("lock contains invalid or unbased data"),
            Self::StubTreeProof => f.write_str("stub proofs require a single spend condition"),
        }
    }
}

impl core::error::Error for LockError {}

impl Lock {
    /// Build a balanced lock, padding to the next power of two with burn leaves.
    pub fn from_list(mut conditions: Vec<SpendCondition>) -> Result<Self, LockError> {
        if conditions.is_empty() || conditions.len() > 16 {
            return Err(LockError::InvalidLeafCount(conditions.len()));
        }
        if conditions.iter().any(|condition| condition.p.is_empty()) {
            return Err(LockError::EmptySpendCondition);
        }
        conditions.resize_with(conditions.len().next_power_of_two(), || SpendCondition {
            p: vec![LockPrimitive {
                header: "brn".into(),
                body: LockPrimitiveBody::Brn(Brn { value: 0 }),
            }],
        });
        fn pair(sc: &[SpendCondition]) -> LockV2 {
            LockV2 {
                p: sc[0].clone(),
                q: sc[1].clone(),
            }
        }
        fn four(sc: &[SpendCondition]) -> LockV4 {
            LockV4 {
                p: pair(sc),
                q: pair(&sc[2..]),
            }
        }
        fn eight(sc: &[SpendCondition]) -> LockV8 {
            LockV8 {
                p: four(sc),
                q: four(&sc[4..]),
            }
        }
        Ok(match conditions.len() {
            1 => Self::SpendCondition(conditions.remove(0)),
            2 => Self::V2(pair(&conditions)),
            4 => Self::V4(four(&conditions)),
            8 => Self::V8(eight(&conditions)),
            16 => Self::V16(LockV16 {
                p: eight(&conditions),
                q: eight(&conditions[8..]),
            }),
            _ => unreachable!(),
        })
    }

    pub fn spend_condition_count(&self) -> u64 {
        match self {
            Self::SpendCondition(_) => 1,
            Self::V2(_) => 2,
            Self::V4(_) => 4,
            Self::V8(_) => 8,
            Self::V16(_) => 16,
        }
    }

    pub fn flatten_spend_conditions(&self) -> Vec<SpendCondition> {
        fn two(lock: &LockV2, out: &mut Vec<SpendCondition>) {
            out.extend([lock.p.clone(), lock.q.clone()]);
        }
        fn four(lock: &LockV4, out: &mut Vec<SpendCondition>) {
            two(&lock.p, out);
            two(&lock.q, out);
        }
        fn eight(lock: &LockV8, out: &mut Vec<SpendCondition>) {
            four(&lock.p, out);
            four(&lock.q, out);
        }
        let mut out = Vec::with_capacity(self.spend_condition_count() as usize);
        match self {
            Self::SpendCondition(sc) => out.push(sc.clone()),
            Self::V2(lock) => two(lock, &mut out),
            Self::V4(lock) => four(lock, &mut out),
            Self::V8(lock) => eight(lock, &mut out),
            Self::V16(lock) => {
                eight(&lock.p, &mut out);
                eight(&lock.q, &mut out);
            }
        }
        out
    }

    /// Only the outer arity is tagged; inner pairs have no arity tags.
    pub fn to_hashable(&self) -> Hashable {
        fn tree(leaves: &[SpendCondition]) -> Hashable {
            if leaves.len() == 1 {
                Hashable::Hash(leaves[0].to_hash())
            } else {
                let mid = leaves.len() / 2;
                Hashable::cell(tree(&leaves[..mid]), tree(&leaves[mid..]))
            }
        }
        let leaves = self.flatten_spend_conditions();
        let body = tree(&leaves);
        if leaves.len() == 1 {
            body
        } else {
            Hashable::cell(
                Hashable::leaf_from_atom((leaves.len() as u64).to_le_bytes()),
                body,
            )
        }
    }

    pub fn hash(&self) -> Hash {
        hash_hashable(&self.to_hashable()).expect("lock hashable contains based atoms")
    }
}

/// Build the proof version admitted at the candidate height.
pub fn build_lock_merkle_proof(
    form: &Lock,
    leaf_number: u64,
    page: u64,
) -> Result<LockMerkleProof, LockError> {
    if page >= crate::fee::BYTHOS_PHASE {
        build_lock_merkle_proof_full(form, leaf_number)
    } else {
        if form.spend_condition_count() != 1 {
            return Err(LockError::StubTreeProof);
        }
        build_lock_merkle_proof_stub(form, leaf_number)
    }
}

fn prove_lock(
    form: &Lock,
    leaf_number: u64,
) -> Result<(SpendCondition, u64, MerkleProof), LockError> {
    if leaf_number == 0 || leaf_number > form.spend_condition_count() {
        return Err(LockError::InvalidLeafIndex(leaf_number));
    }
    crate::noun_codec::validate_based(form).map_err(|_| LockError::InvalidEncoding)?;
    let leaves = form.flatten_spend_conditions();
    let condition = leaves[(leaf_number - 1) as usize].clone();
    if condition.p.is_empty() {
        return Err(LockError::EmptySpendCondition);
    }
    let index = leaf_number + u64::from(leaves.len() > 1);
    let (axis, proof) = prove_hashable_by_index(&form.to_hashable(), index)?;
    Ok((condition, axis, proof))
}

/// Produce Hoon's stub representation. Tree stubs are not admitted for ordinary spends.
pub fn build_lock_merkle_proof_stub(
    form: &Lock,
    leaf_number: u64,
) -> Result<LockMerkleProof, LockError> {
    let (condition, axis, proof) = prove_lock(form, leaf_number)?;
    Ok(LockMerkleProof::new_stub(condition, axis, proof))
}

pub fn build_lock_merkle_proof_full(
    form: &Lock,
    leaf_number: u64,
) -> Result<LockMerkleProof, LockError> {
    let (condition, axis, proof) = prove_lock(form, leaf_number)?;
    Ok(LockMerkleProof::new_full(condition, axis, proof))
}

/// Prove a one-based index. Lists are hashable leaves, not Merkle branches.
pub fn prove_hashable_by_index(
    form: &Hashable,
    index: u64,
) -> Result<(u64, MerkleProof), LockError> {
    fn count(node: &Hashable) -> u64 {
        match node {
            Hashable::Cell(left, right) => count(left) + count(right),
            _ => 1,
        }
    }
    fn descend(node: &Hashable, index: u64, axis: u64, path: &mut Vec<Hash>) -> u64 {
        match node {
            Hashable::Cell(left, right) => {
                let left_count = count(left);
                let (child, sibling, index, axis) = if index <= left_count {
                    (left, right, index, axis * 2)
                } else {
                    (right, left, index - left_count, axis * 2 + 1)
                };
                let axis = descend(child, index, axis, path);
                path.push(hash_hashable(sibling).expect("lock sibling is hashable"));
                axis
            }
            _ => axis,
        }
    }
    if index == 0 || index > count(form) {
        return Err(LockError::InvalidLeafIndex(index));
    }
    let mut path = Vec::new();
    let axis = descend(form, index, 1, &mut path);
    Ok((
        axis,
        MerkleProof {
            root: hash_hashable(form).expect("lock is hashable"),
            path,
        },
    ))
}

/// Authenticate the arity tag at the end of a leaf-to-root path.
pub fn authorization_leaf(axis: u64, path: &[Hash]) -> bool {
    let arity: u64 = match axis {
        1 => return true,
        6..=7 => 2,
        12..=15 => 4,
        24..=31 => 8,
        48..=63 => 16,
        _ => return false,
    };
    path.last()
        == Some(
            &hash_hashable(&Hashable::leaf_from_atom(arity.to_le_bytes()))
                .expect("arity is a based atom"),
        )
}

/// Admission rule for V1 inputs; the protocol fund uses a separate recovery policy.
pub fn valid_stub_axis(proof: &LockMerkleProof, is_protocol_fund: bool) -> bool {
    is_protocol_fund || matches!(proof, LockMerkleProof::Full(_)) || proof.axis() == 1
}

impl MerkleProof {
    pub fn verify(&self, mut leaf: Hash, mut axis: u64) -> bool {
        if axis == 0 {
            return false;
        }
        for sibling in &self.path {
            if axis == 1 {
                return false;
            }
            leaf = if axis & 1 == 0 {
                hash_ten_cell(leaf, sibling.clone())
            } else {
                hash_ten_cell(sibling.clone(), leaf)
            };
            axis >>= 1;
        }
        axis == 1 && leaf == self.root
    }
}

impl LockMerkleProof {
    /// Verify inclusion, whole-condition authorization, and the parent commitment.
    /// Primitive signatures, preimages and timelocks require the spending context.
    pub fn check(&self, parent_firstname: &Hash) -> bool {
        if self.spend_condition().p.is_empty() || crate::noun_codec::validate_based(self).is_err() {
            return false;
        }
        let firstname = hash_hashable(&Hashable::cell(
            Hashable::null(),
            Hashable::Hash(self.proof().root.clone()),
        ))
        .expect("firstname is hashable");
        if &firstname != parent_firstname {
            return false;
        }
        let authorized = match self {
            Self::Stub(_) => self.axis() == 1,
            Self::Full(proof) => {
                proof.version == u64::from_le_bytes(*b"full\0\0\0\0")
                    && authorization_leaf(self.axis(), &self.proof().path)
            }
        };
        authorized
            && self
                .proof()
                .verify(self.spend_condition().to_hash(), self.axis())
    }
}

crate::noun_codec::noun_struct!(
    LockV2 { p, q },
    LockV4 { p, q },
    LockV8 { p, q },
    LockV16 { p, q }
);
impl Encode for Lock {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        let (tag, body): (u64, _) = match self {
            Self::SpendCondition(sc) => return sc.encode(arena),
            Self::V2(lock) => (2, lock.encode(arena)?),
            Self::V4(lock) => (4, lock.encode(arena)?),
            Self::V8(lock) => (8, lock.encode(arena)?),
            Self::V16(lock) => (16, lock.encode(arena)?),
        };
        let tag = tag.encode(arena)?;
        Ok(arena.alloc_cell(tag, body))
    }
}
impl Decode for Lock {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let (head, body) = pair(noun, arena)?;
        if matches!(head, Noun::Cell(_)) {
            return SpendCondition::decode(noun, arena).map(Self::SpendCondition);
        }
        match u64::decode(head, arena)? {
            2 => LockV2::decode(body, arena).map(Self::V2),
            4 => LockV4::decode(body, arena).map(Self::V4),
            8 => LockV8::decode(body, arena).map(Self::V8),
            16 => LockV16::decode(body, arena).map(Self::V16),
            _ => Err(Error("invalid lock arity")),
        }
    }
}
crate::noun_codec::runtime_codec!(Lock);

#[cfg(test)]
#[path = "tests/test_lock_reference.rs"]
mod tests;
