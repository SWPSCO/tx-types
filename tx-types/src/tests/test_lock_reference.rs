use crate::hashing::{hash_hashable, Hashable};
use crate::lock::*;
use crate::{Brn, Hash, LockPrimitive, LockPrimitiveBody, NName, SpendCondition};
use pokenoun::codec::{Decode, Encode};

struct LockFixture {
    lock: Lock,
    root: Hash,
    proofs: Vec<ProofFixture>,
}

struct ProofFixture {
    index: u64,
    stub: crate::LockMerkleProof,
    full: crate::LockMerkleProof,
    stub_hash: Hash,
    full_hash: Hash,
    stub_valid: bool,
    full_valid: bool,
}

crate::noun_codec::noun_struct!(
    LockFixture { lock, root, proofs },
    ProofFixture {
        index,
        stub,
        full,
        stub_hash,
        full_hash,
        stub_valid,
        full_valid
    }
);

fn jam(value: &impl Encode) -> Vec<u8> {
    value.to_jam().unwrap()
}

fn fixtures() -> Vec<LockFixture> {
    Vec::<LockFixture>::from_jam(include_bytes!("../../tests/reference/lock-proofs.jam")).unwrap()
}

#[test]
fn every_lock_leaf_matches_official_hoon_jam_hash_and_validation() {
    let fixtures = fixtures();
    assert_eq!(fixtures.len(), 5);
    for (arity, fixture) in [1, 2, 4, 8, 16].into_iter().zip(fixtures) {
        assert_eq!(fixture.lock.spend_condition_count(), arity);
        assert_eq!(fixture.proofs.len() as u64, arity);
        assert_eq!(fixture.lock.hash(), fixture.root);
        let leaves = fixture.lock.flatten_spend_conditions();
        assert_eq!(
            jam(&Lock::from_list(leaves.clone()).unwrap()),
            jam(&fixture.lock)
        );
        let firstname = NName::first_v1(fixture.root);
        for expected in fixture.proofs {
            let stub = build_lock_merkle_proof_stub(&fixture.lock, expected.index).unwrap();
            let full = build_lock_merkle_proof_full(&fixture.lock, expected.index).unwrap();
            assert_eq!(
                jam(&stub),
                jam(&expected.stub),
                "stub arity={arity} leaf={}",
                expected.index
            );
            assert_eq!(
                jam(&full),
                jam(&expected.full),
                "full arity={arity} leaf={}",
                expected.index
            );
            assert_eq!(stub.to_hash(), expected.stub_hash);
            assert_eq!(full.to_hash(), expected.full_hash);
            assert_eq!(stub.check(&firstname), expected.stub_valid);
            assert_eq!(full.check(&firstname), expected.full_valid);
            assert_eq!(
                jam(full.spend_condition()),
                jam(&leaves[(expected.index - 1) as usize])
            );
            assert_eq!(
                full.axis(),
                if arity == 1 {
                    1
                } else {
                    3 * arity + expected.index - 1
                }
            );
            assert!(authorization_leaf(full.axis(), &full.proof().path));
            assert_eq!(valid_stub_axis(&stub, false), arity == 1);
            assert!(valid_stub_axis(&stub, true));
        }
    }
}

#[test]
fn proofs_reject_modified_paths_axes_roots_conditions_and_parent() {
    for fixture in fixtures() {
        let firstname = NName::first_v1(fixture.root);
        for item in fixture.proofs {
            let proof = item.full;
            for axis in [0, 2, 3, 4, 5, 8, 11, 16, 23, 32, 47, 64, u64::MAX] {
                let mut bad = proof.clone();
                if let crate::LockMerkleProof::Full(ref mut full) = bad {
                    full.axis = axis;
                }
                assert!(!bad.check(&firstname), "axis={axis}");
            }
            let mut full = match proof {
                crate::LockMerkleProof::Full(full) => full,
                _ => unreachable!(),
            };
            let mut wrong_parent = firstname.clone();
            wrong_parent.values[0] ^= 1;
            assert!(!crate::LockMerkleProof::Full(full.clone()).check(&wrong_parent));
            let root = full.merkle_proof.root.clone();
            full.merkle_proof.root.values[0] ^= 1;
            assert!(!crate::LockMerkleProof::Full(full.clone()).check(&firstname));
            full.merkle_proof.root = root;
            let path = full.merkle_proof.path.clone();
            for i in 0..path.len() {
                full.merkle_proof.path[i].values[0] ^= 1;
                assert!(!crate::LockMerkleProof::Full(full.clone()).check(&firstname));
                full.merkle_proof.path = path.clone();
            }
            full.merkle_proof.path.push(Hash { values: [0; 5] });
            assert!(!crate::LockMerkleProof::Full(full.clone()).check(&firstname));
            full.merkle_proof.path = path;
            if !full.merkle_proof.path.is_empty() {
                full.merkle_proof.path.pop();
                assert!(!crate::LockMerkleProof::Full(full.clone()).check(&firstname));
            }
            full.spend_condition.p.clear();
            assert!(!crate::LockMerkleProof::Full(full).check(&firstname));
        }
    }
}

#[test]
fn arity_sibling_must_authenticate_the_axis_depth() {
    for (axis, arity) in [(6, 2u64), (12, 4), (24, 8), (48, 16)] {
        let tag = hash_hashable(&Hashable::leaf_from_atom(arity.to_le_bytes())).unwrap();
        assert!(authorization_leaf(axis, &[tag.clone()]));
        assert!(!authorization_leaf(axis, &[]));
        for wrong in [2u64, 4, 8, 16].into_iter().filter(|n| *n != arity) {
            let wrong_tag = hash_hashable(&Hashable::leaf_from_atom(wrong.to_le_bytes())).unwrap();
            assert!(!authorization_leaf(axis, &[wrong_tag]));
        }
    }
}

#[test]
fn build_boundaries_reject_empty_and_out_of_range_and_pad_with_burn() {
    let leaf = fixtures()
        .remove(0)
        .lock
        .flatten_spend_conditions()
        .remove(0);
    assert!(matches!(
        Lock::from_list(vec![]),
        Err(LockError::InvalidLeafCount(0))
    ));
    assert!(Lock::from_list(vec![leaf.clone(); 17]).is_err());
    assert!(Lock::from_list(vec![SpendCondition { p: vec![] }]).is_err());
    let empty = Lock::SpendCondition(SpendCondition { p: vec![] });
    assert!(build_lock_merkle_proof_full(&empty, 1).is_err());
    for length in 1usize..=16 {
        let lock = Lock::from_list(vec![leaf.clone(); length]).unwrap();
        assert_eq!(
            lock.spend_condition_count() as usize,
            length.next_power_of_two()
        );
        assert!(build_lock_merkle_proof_full(&lock, 0).is_err());
        assert!(build_lock_merkle_proof_full(&lock, lock.spend_condition_count() + 1).is_err());
        for padded in &lock.flatten_spend_conditions()[length..] {
            assert_eq!(
                jam(padded),
                jam(&SpendCondition {
                    p: vec![LockPrimitive {
                        header: "brn".into(),
                        body: LockPrimitiveBody::Brn(Brn { value: 0 })
                    }],
                })
            );
        }
        let before = build_lock_merkle_proof(&lock, 1, crate::fee::BYTHOS_PHASE - 1);
        assert_eq!(before.is_ok(), length == 1);
        assert!(matches!(
            build_lock_merkle_proof(&lock, 1, crate::fee::BYTHOS_PHASE).unwrap(),
            crate::LockMerkleProof::Full(_)
        ));
    }
}
