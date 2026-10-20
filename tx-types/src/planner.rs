//! Deterministic selection, fee solving and per-input conservation without IO.

use crate::fee::{compute_minimum_fee, FeeInputs};
use crate::lock::{build_lock_merkle_proof_full, build_lock_merkle_proof_stub, Lock};
use crate::lock_resolver::{simple_pkh, timelock_admits, LockMatcher, LockResolution};
use crate::word_count::{signature_map_words, transaction_words, WordCountBreakdown};
use crate::{
    Coins, Hash, NName, NNote, NoteData, PkhSignature, SeedV1, SeedsV1, Spend, SpendBody,
    SpendV0ToV1, SpendV1, SpendsV1, Witness, ZMap, ZSet,
};
use alloc::{collections::BTreeSet, vec::Vec};
use pokenoun::codec::{Encode, Error};

#[derive(Debug, Clone)]
pub struct PlannedOutput {
    pub lock_root: Hash,
    pub note_data: NoteData,
    pub amount: u64,
}

impl PlannedOutput {
    pub fn payment(pkh: Hash, amount: u64, private: bool) -> Result<Self, Error> {
        crate::noun_codec::validate_based(&pkh)?;
        let lock = Lock::SpendCondition(simple_pkh(pkh));
        Ok(Self {
            lock_root: lock.hash(),
            note_data: if private {
                NoteData { map: ZMap::new() }
            } else {
                NoteData::from_lock(lock)?
            },
            amount,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionOrder {
    Ascending,
    Descending,
}

#[derive(Debug, Clone)]
pub enum SelectionMode {
    Auto,
    Manual(Vec<NName>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateVersionPolicy {
    V0Only,
    V1Only,
}

#[derive(Debug, Clone)]
pub enum PlanningMode {
    Standard,
    /// Spend every admitted candidate, setting the destination amount after fees.
    Sweep {
        destination: PlannedOutput,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePolicy {
    /// Construct at a specified fee; the result includes the required minimum.
    Exact(u64),
    Minimum,
}

#[derive(Debug, Clone)]
pub struct ChainContext {
    /// Unknown height admits only conditions without timelocks or fund maturity.
    pub candidate_height: Option<u64>,
    pub fee_height: u64,
    pub bythos_phase: u64,
    pub base_fee: u64,
    pub input_fee_divisor: u64,
    pub min_fee: u64,
}

impl ChainContext {
    pub fn at_height(height: u64) -> Self {
        Self {
            candidate_height: Some(height),
            fee_height: height,
            bythos_phase: crate::fee::BYTHOS_PHASE,
            base_fee: crate::fee::BASE_FEE,
            input_fee_divisor: crate::fee::INPUT_FEE_DIVISOR,
            min_fee: crate::fee::MIN_FEE,
        }
    }

    pub fn minimum_fee(&self, words: WordCountBreakdown) -> u64 {
        compute_minimum_fee(FeeInputs {
            seed_words: words.seed_words,
            witness_words: words.witness_words,
            height: self.fee_height,
            bythos_phase: self.bythos_phase,
            base_fee: self.base_fee,
            input_fee_divisor: self.input_fee_divisor,
            min_fee: self.min_fee,
        })
        .minimum_fee
    }
}

pub struct PlanRequest<'a> {
    pub candidates: &'a [NNote],
    pub outputs: &'a [PlannedOutput],
    /// Its amount is assigned by the planner.
    pub refund: &'a PlannedOutput,
    pub selection: SelectionMode,
    pub order: SelectionOrder,
    pub version: CandidateVersionPolicy,
    pub mode: PlanningMode,
    pub fee: FeePolicy,
    pub chain: ChainContext,
}

#[derive(Debug, Clone)]
pub struct PlanResult {
    pub spends: SpendsV1,
    pub selected: Vec<NName>,
    pub selected_total: u64,
    pub outputs: Vec<PlannedOutput>,
    pub refunds: Vec<(NName, u64)>,
    pub final_fee: u64,
    pub minimum_fee: u64,
    pub word_counts: WordCountBreakdown,
}

struct Candidate<'a> {
    note: &'a NNote,
    resolution: Option<LockResolution>,
    signatures: u64,
}

fn identity(note: &NNote) -> (&NName, u64) {
    match note {
        NNote::V0(note) => (&note.name, note.assets.value),
        NNote::V1(note) => (&note.name, note.assets.value),
    }
}

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error("transaction amount overflow"))
}

fn normalize_output(output: &PlannedOutput) -> Result<PlannedOutput, Error> {
    if output.amount >= pokenoun::GOLDILOCKS_P {
        return Err(Error("output amount exceeds base field"));
    }
    if output
        .lock_root
        .values
        .iter()
        .any(|limb| *limb >= pokenoun::GOLDILOCKS_P)
    {
        return Err(Error("output root contains an unbased word"));
    }
    Ok(PlannedOutput {
        lock_root: output.lock_root.clone(),
        amount: output.amount,
        note_data: NoteData::normalize(output.note_data.map.tap())?,
    })
}

fn merge_output(outputs: &mut Vec<PlannedOutput>, output: PlannedOutput) -> Result<(), Error> {
    if output.amount == 0 {
        return Ok(());
    }
    if let Some(existing) = outputs
        .iter_mut()
        .find(|item| item.lock_root == output.lock_root)
    {
        if existing.note_data.to_jam()? != output.note_data.to_jam()? {
            return Err(Error("conflicting note data for the same output lock"));
        }
        let amount = add(existing.amount, output.amount)?;
        if amount >= pokenoun::GOLDILOCKS_P {
            return Err(Error("merged output amount exceeds base field"));
        }
        existing.amount = amount;
    } else {
        outputs.push(output);
    }
    Ok(())
}

fn candidates<'a>(
    request: &PlanRequest<'a>,
    matcher: &impl LockMatcher,
) -> Result<Vec<Candidate<'a>>, Error> {
    let mut seen = BTreeSet::new();
    for note in request.candidates {
        let (name, amount) = identity(note);
        if name.p.len() != 2 || amount >= pokenoun::GOLDILOCKS_P {
            return Err(Error("invalid input note"));
        }
        crate::noun_codec::validate_based(note)?;
        if !seen.insert(name.to_jam()?) {
            return Err(Error("duplicate input note"));
        }
    }
    if let SelectionMode::Manual(names) = &request.selection {
        let mut requested = BTreeSet::new();
        for name in names {
            let key = name.to_jam()?;
            if !requested.insert(key.clone()) {
                return Err(Error("duplicate manual input"));
            }
            if !seen.contains(&key) {
                return Err(Error("manual input is missing from snapshot"));
            }
        }
    }
    let mut result = Vec::new();
    for input in request.candidates {
        let (name, amount) = identity(input);
        let manual = matches!(&request.selection, SelectionMode::Manual(_));
        if let SelectionMode::Manual(names) = &request.selection {
            if !names.contains(name) {
                continue;
            }
        }
        let admitted = match (input, request.version) {
            (NNote::V1(note), CandidateVersionPolicy::V1Only) if note.version == 1 => matcher
                .resolve(note)
                .filter(|resolution| resolution.admits(note, request.chain.candidate_height))
                .filter(|resolution| {
                    request.chain.fee_height >= request.chain.bythos_phase
                        || resolution.lock.spend_condition_count() == 1
                })
                .map(|resolution| Candidate {
                    note: input,
                    signatures: resolution.signature_count,
                    resolution: Some(resolution),
                }),
            (NNote::V0(note), CandidateVersionPolicy::V0Only) if note.meta.version == 0 => {
                let timelock = note.meta.timelock.intent.as_ref().is_none_or(|(abs, rel)| {
                    timelock_admits(
                        abs,
                        rel,
                        note.meta.origin_page.value,
                        request.chain.candidate_height,
                    )
                });
                let name_matches = name.p[0]
                    == NName::first_v0(note.lock.clone(), note.meta.timelock.intent.is_some());
                matcher
                    .v0_signature_count(note)
                    .filter(|_| timelock && name_matches)
                    .map(|signatures| Candidate {
                        note: input,
                        signatures,
                        resolution: None,
                    })
            }
            _ => None,
        };
        if let Some(candidate) = admitted.filter(|_| amount > 0) {
            result.push(candidate);
        } else if manual {
            return Err(Error("manual input is not spendable"));
        }
    }
    result.sort_by(|a, b| {
        let (an, aa) = identity(a.note);
        let (bn, ba) = identity(b.note);
        let order = aa.cmp(&ba);
        let order = if request.order == SelectionOrder::Descending {
            order.reverse()
        } else {
            order
        };
        order.then_with(|| crate::determinism::compare_names(an, bn))
    });
    Ok(result)
}

fn assemble(
    selected: &[Candidate<'_>],
    outputs: &[PlannedOutput],
    refund: &PlannedOutput,
    fee: u64,
    chain: &ChainContext,
) -> Result<PlanResult, Error> {
    let selected_total = selected
        .iter()
        .try_fold(0, |sum, candidate| add(sum, identity(candidate.note).1))?;
    let output_total = outputs
        .iter()
        .try_fold(0, |sum, output| add(sum, output.amount))?;
    if add(output_total, fee)? > selected_total {
        return Err(Error("insufficient funds"));
    }
    // Every spend requires a positive seed. Reserve one nick per selected input.
    if fee > selected_total.saturating_sub(selected.len() as u64) {
        return Err(Error("fee leaves an input without a positive seed"));
    }
    let mut remaining: Vec<_> = outputs.iter().map(|output| output.amount).collect();
    let mut remaining_fee = fee;
    let mut spends = ZMap::new();
    let mut emitted = Vec::new();
    let mut refunds = Vec::new();
    let mut signature_words = 0;
    for candidate in selected {
        let (name, assets) = identity(candidate.note);
        let input_fee = remaining_fee.min(assets - 1);
        remaining_fee -= input_fee;
        let mut capacity = assets - input_fee;
        let mut allocated = Vec::new();
        for (output, left) in outputs.iter().zip(&mut remaining) {
            let amount = capacity.min(*left);
            if amount > 0 {
                let mut output = output.clone();
                output.amount = amount;
                merge_output(&mut allocated, output)?;
                *left -= amount;
                capacity -= amount;
            }
        }
        if capacity > 0 {
            refunds.push((name.clone(), capacity));
            let mut change = refund.clone();
            change.amount = capacity;
            merge_output(&mut allocated, change)?;
        }
        let parent_hash = match candidate.note {
            NNote::V0(note) => note.to_hash(),
            NNote::V1(note) => note
                .to_hash()
                .map_err(|_| Error("input note cannot be hashed"))?,
        };
        let mut seeds = ZSet::new();
        for output in allocated {
            seeds
                .try_put(SeedV1 {
                    output_source: None,
                    lock_root: output.lock_root.clone(),
                    note_data: output.note_data.clone(),
                    gift: Coins {
                        value: output.amount,
                    },
                    parent_hash: parent_hash.clone(),
                })
                .map_err(|_| Error("seed cannot be hashed"))?;
            merge_output(&mut emitted, output)?;
        }
        let seeds = SeedsV1 { set: seeds };
        let spend = if let Some(resolved) = &candidate.resolution {
            let proof = if chain.fee_height >= chain.bythos_phase {
                build_lock_merkle_proof_full(&resolved.lock, resolved.leaf_number)
            } else {
                build_lock_merkle_proof_stub(&resolved.lock, resolved.leaf_number)
            }
            .map_err(|_| Error("cannot build lock proof"))?;
            if resolved.fund_maturity.is_none() && !proof.check(&name.p[0]) {
                return Err(Error("lock proof does not authorize the input"));
            }
            signature_words = add(
                signature_words,
                signature_map_words(candidate.signatures, 18)? - 1,
            )?;
            Spend {
                version: 1,
                body: SpendBody::V1(SpendV1 {
                    witness: Witness {
                        lmp: proof,
                        pkh: PkhSignature { map: ZMap::new() },
                        hax: resolved.preimages.clone(),
                        tim: 0,
                    },
                    seeds,
                    fee: Coins { value: input_fee },
                }),
            }
        } else {
            signature_words = add(
                signature_words,
                signature_map_words(candidate.signatures, 13)? - 1,
            )?;
            Spend {
                version: 0,
                body: SpendBody::V0ToV1(SpendV0ToV1 {
                    signature: ZMap::new(),
                    seeds,
                    fee: Coins { value: input_fee },
                }),
            }
        };
        spends
            .try_put(name.clone(), spend)
            .map_err(|_| Error("input name cannot be hashed"))?;
    }
    if remaining_fee != 0 || remaining.iter().any(|amount| *amount != 0) {
        return Err(Error("input allocation does not cover payments and fee"));
    }
    let mut word_counts = transaction_words(&spends, chain.fee_height >= chain.bythos_phase)?;
    word_counts.witness_words = add(word_counts.witness_words, signature_words)?;
    Ok(PlanResult {
        spends: SpendsV1 { map: spends },
        selected: selected
            .iter()
            .map(|c| identity(c.note).0.clone())
            .collect(),
        selected_total,
        outputs: emitted,
        refunds,
        final_fee: fee,
        minimum_fee: chain.minimum_fee(word_counts),
        word_counts,
    })
}

pub fn plan(request: PlanRequest<'_>, matcher: &impl LockMatcher) -> Result<PlanResult, Error> {
    let candidates = candidates(&request, matcher)?;
    if candidates.is_empty() {
        return Err(Error("no spendable inputs"));
    }
    let refund = normalize_output(request.refund)?;
    let mut outputs = Vec::new();
    for output in request.outputs {
        if output.amount == 0 {
            return Err(Error("payment amount must be positive"));
        }
        merge_output(&mut outputs, normalize_output(output)?)?;
    }
    let sweep = match &request.mode {
        PlanningMode::Standard => None,
        PlanningMode::Sweep { destination } => {
            if !outputs.is_empty() {
                return Err(Error("sweep has one planner-assigned destination"));
            }
            Some(normalize_output(destination)?)
        }
    };
    if sweep.is_none() && outputs.is_empty() {
        return Err(Error("at least one payment is required"));
    }
    let output_total = outputs
        .iter()
        .try_fold(0, |sum, output| add(sum, output.amount))?;
    let all = sweep.is_some() || matches!(request.selection, SelectionMode::Manual(_));
    let mut fee = match request.fee {
        FeePolicy::Exact(fee) => fee,
        FeePolicy::Minimum => request.chain.min_fee,
    };
    // Selection grows as fees grow. With a fixed selection only the presence of change
    // affects word counts; testing the no-change boundary handles that discontinuity.
    for _ in 0..candidates.len().saturating_mul(2).saturating_add(8) {
        let needed = add(output_total, fee)?;
        let mut total = 0;
        let mut count = 0;
        for candidate in &candidates {
            total = add(total, identity(candidate.note).1)?;
            count += 1;
            if !all && total >= needed {
                break;
            }
        }
        let selected = &candidates[..count];
        let mut round_outputs = outputs.clone();
        if let Some(destination) = &sweep {
            let mut destination = destination.clone();
            destination.amount = total
                .checked_sub(fee)
                .filter(|amount| *amount > 0)
                .ok_or(Error("balance does not cover the network fee"))?;
            round_outputs.push(destination);
        }
        let result = assemble(selected, &round_outputs, &refund, fee, &request.chain)?;
        if matches!(request.fee, FeePolicy::Exact(_)) || result.minimum_fee <= fee {
            return Ok(result);
        }
        if sweep.is_none() {
            let remainder = total
                .checked_sub(output_total)
                .ok_or(Error("insufficient funds"))?;
            if remainder >= request.chain.min_fee && remainder <= result.minimum_fee {
                if let Ok(exact) =
                    assemble(selected, &round_outputs, &refund, remainder, &request.chain)
                {
                    if exact.minimum_fee <= remainder {
                        return Ok(exact);
                    }
                }
            }
        }
        fee = result.minimum_fee;
    }
    Err(Error("network fee does not converge"))
}
