//! Lock discovery and admission policies for a spending candidate.

use crate::lock::Lock;
use crate::note_data::DecodedNoteData;
use crate::{
    Hash, LockPrimitive, LockPrimitiveBody, NName, NNoteV0, NNoteV1, PageNumber, Pkh,
    SchnorrPubkey, SpendCondition, Tim, TimelockRange, UntypedNoun, ZMap, ZSet,
};
use alloc::{vec, vec::Vec};

pub const CONSENSUS_BATCH_PHASE: u64 = 170_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundMaturityPolicy {
    pub activation_height: u64,
    pub minimum: u64,
}

impl FundMaturityPolicy {
    pub fn fund_minimum_at(self, candidate_height: u64) -> Option<u64> {
        (candidate_height >= self.activation_height).then_some(self.minimum)
    }

    pub fn at(self, candidate_height: u64) -> FundMaturity {
        FundMaturity {
            candidate_height,
            minimum: self.fund_minimum_at(candidate_height),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundMaturity {
    pub candidate_height: u64,
    /// An inactive minimum admits all origins; zero still rejects future origins.
    pub minimum: Option<u64>,
}

impl FundMaturity {
    pub fn admits(self, origin_height: u64) -> bool {
        self.minimum.is_none_or(|minimum| {
            self.candidate_height
                .checked_sub(origin_height)
                .is_some_and(|age| age >= minimum)
        })
    }
}

#[derive(Debug, Clone)]
pub struct LockResolution {
    pub lock: Lock,
    /// One-based index of the authorized condition.
    pub leaf_number: u64,
    pub signature_count: u64,
    pub preimages: ZMap<Hash, UntypedNoun>,
    pub fund_maturity: Option<FundMaturity>,
}

impl LockResolution {
    pub fn spend_condition(&self) -> Option<SpendCondition> {
        self.leaf_number.checked_sub(1).and_then(|index| {
            self.lock
                .flatten_spend_conditions()
                .get(index as usize)
                .cloned()
        })
    }

    pub fn admits(&self, note: &NNoteV1, candidate_height: Option<u64>) -> bool {
        if crate::noun_codec::validate_based(&self.lock).is_err() {
            return false;
        }
        let Some(condition) = self.spend_condition() else {
            return false;
        };
        if let Some(maturity) = self.fund_maturity {
            if candidate_height != Some(maturity.candidate_height)
                || !maturity.admits(note.origin_page.value)
            {
                return false;
            }
        } else if note.name.p.first() != Some(&NName::first_v1(self.lock.hash())) {
            return false;
        }
        !condition.p.is_empty()
            && condition.p.iter().all(|primitive| match &primitive.body {
                LockPrimitiveBody::Pkh(pkh) => {
                    pkh.m > 0 && pkh.m <= pkh.h.wyt() as u64 && self.signature_count >= pkh.m
                }
                LockPrimitiveBody::Tim(tim) => {
                    timelock_admits(&tim.abs, &tim.rel, note.origin_page.value, candidate_height)
                }
                LockPrimitiveBody::Hax(hax) => hax.set.tap().iter().all(|hash| {
                    self.preimages
                        .get(hash)
                        .and_then(|noun| noun.to_hashable().ok())
                        .and_then(|value| crate::hash_hashable(&value).ok())
                        .as_ref()
                        == Some(hash)
                }),
                LockPrimitiveBody::Brn(_) => false,
            })
    }
}

pub fn timelock_admits(
    absolute: &TimelockRange,
    relative: &TimelockRange,
    origin_height: u64,
    candidate_height: Option<u64>,
) -> bool {
    let Some(height) = candidate_height else {
        return false;
    };
    let Some(age) = height.checked_sub(origin_height) else {
        return false;
    };
    [(absolute, height), (relative, age)]
        .into_iter()
        .all(|(range, value)| {
            range.min.as_ref().is_none_or(|min| value >= min.value)
                && range.max.as_ref().is_none_or(|max| value <= max.value)
        })
}

/// Consumers supply their signing and unlock context without performing IO here.
pub trait LockMatcher {
    fn resolve(&self, note: &NNoteV1) -> Option<LockResolution>;

    fn v0_signature_count(&self, _note: &NNoteV0) -> Option<u64> {
        None
    }
}

pub fn simple_pkh(pkh: Hash) -> SpendCondition {
    SpendCondition {
        p: vec![LockPrimitive {
            header: "pkh".into(),
            body: LockPrimitiveBody::Pkh(Pkh {
                m: 1,
                h: ZSet::gas(vec![pkh]),
            }),
        }],
    }
}

pub fn coinbase_pkh(pkh: Hash, relative_minimum: u64) -> SpendCondition {
    let mut condition = simple_pkh(pkh);
    condition.p.push(LockPrimitive {
        header: "tim".into(),
        body: LockPrimitiveBody::Tim(Tim {
            rel: TimelockRange {
                min: Some(PageNumber {
                    value: relative_minimum,
                }),
                max: None,
            },
            abs: TimelockRange {
                min: None,
                max: None,
            },
        }),
    });
    condition
}

/// A signer can satisfy one 1-of-N PKH primitive and at most one timelock.
#[derive(Debug, Clone)]
pub struct SigningKeyLockMatcher {
    pub signer_pkh: Hash,
    pub public_key: Option<SchnorrPubkey>,
    pub coinbase_relative_min: Option<u64>,
}

fn pkh_policy(condition: &SpendCondition) -> Option<crate::RequiredPkhPolicy> {
    let mut policy = None;
    let mut tim = false;
    for primitive in &condition.p {
        match &primitive.body {
            LockPrimitiveBody::Pkh(pkh)
                if policy.is_none() && pkh.m > 0 && pkh.m <= pkh.h.wyt() as u64 =>
            {
                policy = Some(crate::RequiredPkhPolicy {
                    threshold: pkh.m as usize,
                    hashes: pkh.h.tap(),
                });
            }
            LockPrimitiveBody::Tim(_) if !tim => tim = true,
            _ => return None,
        }
    }
    policy
}

fn resolution(
    lock: Lock,
    accept: impl Fn(&crate::RequiredPkhPolicy) -> bool,
) -> Option<LockResolution> {
    lock.flatten_spend_conditions()
        .iter()
        .enumerate()
        .find_map(|(index, condition)| {
            let policy = pkh_policy(condition)?;
            accept(&policy).then(|| LockResolution {
                lock: lock.clone(),
                leaf_number: index as u64 + 1,
                signature_count: policy.threshold as u64,
                preimages: ZMap::new(),
                fund_maturity: None,
            })
        })
}

impl LockMatcher for SigningKeyLockMatcher {
    fn resolve(&self, note: &NNoteV1) -> Option<LockResolution> {
        let disclosed = DecodedNoteData::from_note_data(&note.note_data)
            .ok()
            .and_then(|data| data.lock().cloned());
        let mut locks: Vec<Lock> = disclosed.into_iter().collect();
        locks.push(Lock::SpendCondition(simple_pkh(self.signer_pkh.clone())));
        if let Some(minimum) = self.coinbase_relative_min {
            locks.push(Lock::SpendCondition(coinbase_pkh(
                self.signer_pkh.clone(),
                minimum,
            )));
        }
        locks
            .into_iter()
            .filter(|lock| note.name.p.first() == Some(&NName::first_v1(lock.hash())))
            .find_map(|lock| {
                resolution(lock, |policy| {
                    policy.threshold == 1 && policy.contains(&self.signer_pkh)
                })
            })
    }

    fn v0_signature_count(&self, note: &NNoteV0) -> Option<u64> {
        let key = self.public_key.as_ref()?;
        (key.to_hash() == self.signer_pkh && note.lock.m == 1 && note.lock.pubkeys.has(key))
            .then_some(1)
    }
}

/// Match a committed lock root for multisig planning, including partial signing.
#[derive(Debug, Clone)]
pub struct LockRootLockMatcher {
    pub lock_root: Hash,
    planning_lock: Option<Lock>,
    fund_note: Option<(Hash, FundMaturity)>,
}

impl LockRootLockMatcher {
    pub fn from_lock_root(lock_root: Hash) -> Self {
        Self {
            lock_root,
            planning_lock: None,
            fund_note: None,
        }
    }

    pub fn with_lock(mut self, lock: Lock) -> Self {
        self.planning_lock = Some(lock);
        self
    }

    pub fn with_spend_condition(self, condition: SpendCondition) -> Self {
        self.with_lock(Lock::SpendCondition(condition))
    }

    pub fn with_fund_notes(
        mut self,
        fund_lock_root: &Hash,
        fund_firstname: Hash,
        maturity: FundMaturity,
    ) -> Self {
        self.fund_note = (self.lock_root == *fund_lock_root).then_some((fund_firstname, maturity));
        self
    }
}

impl LockMatcher for LockRootLockMatcher {
    fn resolve(&self, note: &NNoteV1) -> Option<LockResolution> {
        let firstname = note.name.p.first()?;
        let direct = firstname == &NName::first_v1(self.lock_root.clone());
        let maturity = self
            .fund_note
            .as_ref()
            .filter(|(name, _)| name == firstname)
            .map(|(_, maturity)| *maturity);
        if !direct && maturity.is_none() {
            return None;
        }
        let disclosed = direct
            .then(|| DecodedNoteData::from_note_data(&note.note_data).ok())
            .flatten()
            .and_then(|data| data.lock().cloned());
        let lock = disclosed
            .filter(|lock| lock.hash() == self.lock_root)
            .or_else(|| {
                self.planning_lock
                    .clone()
                    .filter(|lock| lock.hash() == self.lock_root)
            })?;
        // Fund recovery authenticates the real multisig preimage independently of the committed wrapper.
        if !direct && lock.spend_condition_count() != 1 {
            return None;
        }
        let mut resolved = resolution(lock, |_| true)?;
        resolved.fund_maturity = if direct { None } else { maturity };
        Some(resolved)
    }
}
