use crate::lock::{build_lock_merkle_proof_full, Lock as V1Lock};
use crate::lock_resolver::*;
use crate::planner::*;
use crate::*;
use pokenoun::codec::Encode;

fn hash(n: u64) -> Hash {
    Hash { values: [n; 5] }
}
fn matcher() -> SigningKeyLockMatcher {
    SigningKeyLockMatcher {
        signer_pkh: hash(1),
        public_key: None,
        coinbase_relative_min: Some(100),
    }
}
fn note(id: u64, amount: u64, lock: &V1Lock) -> NNote {
    NNote::V1(NNoteV1 {
        version: 1,
        origin_page: PageNumber { value: 1000 },
        name: NName {
            p: vec![NName::first_v1(lock.hash()), hash(id)],
        },
        assets: Coins { value: amount },
        note_data: NoteData::from_lock(lock.clone()).unwrap(),
    })
}
fn simple_note(id: u64, amount: u64) -> NNote {
    note(id, amount, &V1Lock::SpendCondition(simple_pkh(hash(1))))
}
fn chain() -> ChainContext {
    ChainContext {
        base_fee: 1,
        min_fee: 1,
        ..ChainContext::at_height(60_000)
    }
}
fn request<'a>(
    notes: &'a [NNote],
    outputs: &'a [PlannedOutput],
    refund: &'a PlannedOutput,
) -> PlanRequest<'a> {
    PlanRequest {
        candidates: notes,
        outputs,
        refund,
        selection: SelectionMode::Auto,
        order: SelectionOrder::Descending,
        version: CandidateVersionPolicy::V1Only,
        mode: PlanningMode::Standard,
        fee: FeePolicy::Minimum,
        chain: chain(),
    }
}
fn refund() -> PlannedOutput {
    PlannedOutput::payment(hash(1), 0, false).unwrap()
}
fn output(amount: u64) -> PlannedOutput {
    PlannedOutput::payment(hash(2), amount, false).unwrap()
}

fn check_conservation(result: &PlanResult, notes: &[NNote]) {
    let mut fee = 0;
    for (name, spend) in result.spends.map.tap() {
        let input = notes
            .iter()
            .find(|note| match note {
                NNote::V0(note) => note.name == name,
                NNote::V1(note) => note.name == name,
            })
            .unwrap();
        let (assets, parent_hash) = match input {
            NNote::V0(note) => (note.assets.value, note.to_hash()),
            NNote::V1(note) => (note.assets.value, note.to_hash().unwrap()),
        };
        let (seeds, input_fee) = match spend.body {
            SpendBody::V1(spend) => {
                assert!(spend.witness.lmp.check(&name.p[0]));
                (spend.seeds, spend.fee.value)
            }
            SpendBody::V0ToV1(spend) => (spend.seeds, spend.fee.value),
            _ => panic!(),
        };
        assert!(seeds.set.wyt() > 0);
        assert!(seeds
            .set
            .tap()
            .iter()
            .all(|seed| seed.gift.value > 0 && seed.parent_hash == parent_hash));
        assert_eq!(
            assets,
            input_fee
                + seeds
                    .set
                    .tap()
                    .iter()
                    .map(|seed| seed.gift.value)
                    .sum::<u64>()
        );
        fee += input_fee;
    }
    assert_eq!(fee, result.final_fee);
    assert_eq!(
        result.selected_total,
        fee + result
            .outputs
            .iter()
            .map(|output| output.amount)
            .sum::<u64>()
    );
}

#[test]
fn selection_is_permutation_invariant_and_every_input_balances() {
    let mut notes = vec![
        simple_note(3, 100),
        simple_note(4, 100),
        simple_note(5, 100),
    ];
    let outputs = [output(230)];
    let refund = refund();
    let a = plan(request(&notes, &outputs, &refund), &matcher()).unwrap();
    assert!(a.final_fee >= a.minimum_fee);
    check_conservation(&a, &notes);
    notes.reverse();
    let b = plan(request(&notes, &outputs, &refund), &matcher()).unwrap();
    assert_eq!(a.spends.to_jam().unwrap(), b.spends.to_jam().unwrap());
    assert_eq!(a.selected, b.selected);
}

#[test]
fn signed_word_estimate_matches_actual_signature_map_shape() {
    let notes = [simple_note(3, 1000), simple_note(4, 1000)];
    let refund = refund();
    let outputs = [output(1800)];
    let result = plan(request(&notes, &outputs, &refund), &matcher()).unwrap();
    let mut signed = ZMap::new();
    for (name, mut spend) in result.spends.map.tap() {
        let SpendBody::V1(ref mut body) = spend.body else {
            panic!()
        };
        body.witness.pkh.map.put(
            hash(1),
            PkhSignatureValue {
                pk: SchnorrPubkey {
                    x: F6LT { values: [1; 6] },
                    y: F6LT { values: [2; 6] },
                    inf: false,
                },
                sig: SchnorrSignature {
                    chal: Chal {
                        values: T8 { values: [3; 8] },
                    },
                    sig: Sig {
                        values: T8 { values: [4; 8] },
                    },
                },
            },
        );
        signed.put(name, spend);
    }
    assert_eq!(
        word_count::transaction_words(&signed, true).unwrap(),
        result.word_counts
    );
}

#[test]
fn exact_fee_allocation_keeps_a_seed_on_fee_funding_inputs() {
    let notes = [simple_note(3, 100), simple_note(4, 90), simple_note(5, 80)];
    let refund = refund();
    let outputs = [output(110)];
    let mut req = request(&notes, &outputs, &refund);
    req.fee = FeePolicy::Exact(130);
    let result = plan(req, &matcher()).unwrap();
    check_conservation(&result, &notes);
}

#[test]
fn duplicate_inputs_manual_missing_inputs_and_overflow_fail() {
    let notes = [simple_note(3, 1000), simple_note(3, 1000)];
    let refund = refund();
    let outputs = [output(100)];
    assert!(plan(request(&notes, &outputs, &refund), &matcher()).is_err());
    let mut req = request(&notes[..1], &outputs, &refund);
    req.selection = SelectionMode::Manual(vec![NName {
        p: vec![hash(99), hash(100)],
    }]);
    assert!(plan(req, &matcher()).is_err());
    assert!(plan(
        request(&notes[..1], &[output(u64::MAX), output(1)], &refund),
        &matcher()
    )
    .is_err());
    let p = pokenoun::GOLDILOCKS_P;
    let large = [simple_note(3, p - 100), simple_note(4, 500)];
    assert!(plan(
        request(&large, &[output(p / 2), output(p - p / 2)], &refund),
        &matcher()
    )
    .is_err());
}

#[test]
fn change_fee_boundary_spends_the_remainder_when_change_is_unaffordable() {
    let refund = refund();
    let outputs = [output(100)];
    let base = [simple_note(3, 1000)];
    let generous = plan(request(&base, &outputs, &refund), &matcher()).unwrap();
    for remainder in 1..generous.final_fee {
        let notes = [simple_note(3, 100 + remainder)];
        if let Ok(result) = plan(request(&notes, &outputs, &refund), &matcher()) {
            assert_eq!(result.final_fee, remainder);
            assert!(result.final_fee >= result.minimum_fee);
            assert_eq!(result.outputs.len(), 1);
            check_conservation(&result, &notes);
            return;
        }
    }
    panic!("expected a fee boundary with no change");
}

#[test]
fn one_of_many_and_tagged_lock_authorize_the_effective_signer() {
    let condition = SpendCondition {
        p: vec![LockPrimitive {
            header: "pkh".into(),
            body: LockPrimitiveBody::Pkh(Pkh {
                m: 1,
                h: ZSet::gas(vec![hash(1), hash(8)]),
            }),
        }],
    };
    let lock = V1Lock::from_list(vec![simple_pkh(hash(9)), condition]).unwrap();
    let notes = [note(3, 1000, &lock)];
    let result = plan(request(&notes, &[output(100)], &refund()), &matcher()).unwrap();
    let SpendBody::V1(body) = &result.spends.map.tap()[0].1.body else {
        panic!()
    };
    assert_eq!(body.witness.lmp.axis(), 7);
    assert_eq!(
        body.witness.lmp.to_jam().unwrap(),
        build_lock_merkle_proof_full(&lock, 2)
            .unwrap()
            .to_jam()
            .unwrap()
    );
}

#[test]
fn timelocks_use_candidate_height_and_both_endpoints() {
    let lock = V1Lock::SpendCondition(coinbase_pkh(hash(1), 100));
    let notes = [note(3, 1000, &lock)];
    let outputs = [output(100)];
    let refund = refund();
    for (height, expected) in [
        (None, false),
        (Some(999), false),
        (Some(1099), false),
        (Some(1100), true),
    ] {
        let mut req = request(&notes, &outputs, &refund);
        req.chain.candidate_height = height;
        assert_eq!(plan(req, &matcher()).is_ok(), expected);
    }
    let range = TimelockRange {
        min: Some(PageNumber { value: 10 }),
        max: Some(PageNumber { value: 20 }),
    };
    let empty = TimelockRange {
        min: None,
        max: None,
    };
    for (height, expected) in [(9, false), (10, true), (20, true), (21, false)] {
        assert_eq!(timelock_admits(&range, &empty, 0, Some(height)), expected);
    }
}

#[test]
fn fund_recovery_pins_identity_and_keeps_maturity_outside_the_multisig() {
    let condition = SpendCondition {
        p: vec![LockPrimitive {
            header: "pkh".into(),
            body: LockPrimitiveBody::Pkh(Pkh {
                m: 2,
                h: ZSet::gas(vec![hash(1), hash(2), hash(3)]),
            }),
        }],
    };
    let lock = V1Lock::SpendCondition(condition.clone());
    let root = lock.hash();
    let NNote::V1(mut fund) = note(3, 1000, &lock) else {
        panic!()
    };
    fund.name.p[0] = hash(90);
    fund.origin_page.value = 169_950;
    let policy = FundMaturityPolicy {
        activation_height: 170_000,
        minimum: 100,
    };
    assert_eq!(policy.fund_minimum_at(169_999), None);
    for (height, expected) in [
        (169_999, true),
        (170_000, false),
        (170_049, false),
        (170_050, true),
        (170_051, true),
    ] {
        let matcher = LockRootLockMatcher::from_lock_root(root.clone())
            .with_spend_condition(condition.clone())
            .with_fund_notes(&root, hash(90), policy.at(height));
        let resolved = matcher.resolve(&fund).unwrap();
        assert_eq!(resolved.admits(&fund, Some(height)), expected);
        assert_eq!(
            resolved.spend_condition().unwrap().to_jam().unwrap(),
            condition.to_jam().unwrap()
        );
        assert!(!resolved.admits(&fund, Some(height + 1)));
        let notes = [NNote::V1(fund.clone())];
        let outputs = [output(100)];
        let refund = refund();
        let mut req = request(&notes, &outputs, &refund);
        req.chain.candidate_height = Some(height);
        let planned = plan(req, &matcher);
        assert_eq!(planned.is_ok(), expected);
        if let Ok(planned) = planned {
            let SpendBody::V1(body) = &planned.spends.map.tap()[0].1.body else {
                panic!()
            };
            assert_eq!(body.witness.lmp.proof().root, root);
            assert_eq!(
                body.witness.lmp.spend_condition().to_jam().unwrap(),
                condition.to_jam().unwrap()
            );
        }
    }
    assert!(FundMaturity {
        candidate_height: 1,
        minimum: None
    }
    .admits(2));
    assert!(!FundMaturity {
        candidate_height: 1,
        minimum: Some(0)
    }
    .admits(2));
    let wrong = LockRootLockMatcher::from_lock_root(root.clone())
        .with_spend_condition(condition)
        .with_fund_notes(&hash(99), hash(90), policy.at(170_050));
    assert!(wrong.resolve(&fund).is_none());
}

#[test]
fn v0_sweep_uses_full_note_parents_and_preserves_value() {
    let key = SchnorrPubkey {
        x: F6LT { values: [1; 6] },
        y: F6LT { values: [2; 6] },
        inf: false,
    };
    let lock = crate::Lock {
        m: 1,
        pubkeys: ZSet::gas(vec![key.clone()]),
    };
    let matcher = SigningKeyLockMatcher {
        signer_pkh: key.to_hash(),
        public_key: Some(key),
        coinbase_relative_min: None,
    };
    let notes: Vec<_> = [3, 4]
        .into_iter()
        .map(|id| {
            NNote::V0(NNoteV0 {
                meta: NNoteHead {
                    version: 0,
                    origin_page: PageNumber { value: 1000 },
                    timelock: Timelock { intent: None },
                },
                name: NName {
                    p: vec![NName::first_v0(lock.clone(), false), hash(id)],
                },
                lock: lock.clone(),
                source: Source {
                    p: hash(9),
                    is_coinbase: false,
                },
                assets: Coins { value: 1000 },
            })
        })
        .collect();
    let refund = refund();
    let mut req = request(&notes, &[], &refund);
    req.version = CandidateVersionPolicy::V0Only;
    req.mode = PlanningMode::Sweep {
        destination: output(0),
    };
    let result = plan(req, &matcher).unwrap();
    assert_eq!(result.selected.len(), 2);
    assert_eq!(result.outputs.len(), 1);
    check_conservation(&result, &notes);
}
