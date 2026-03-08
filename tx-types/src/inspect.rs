use serde_json::{json, Value};

use crate::collections::ZMap;
use crate::generic_noun::UntypedNoun;
use crate::transaction_types::{Hash, Spend, SpendBody, TimelockRange};
use crate::transaction_types_v1::{
    LockMerkleProof, LockPrimitive, LockPrimitiveBody, NoteData, PkhSignature, RawTransactionV1,
    SeedV1, SeedsV1, SpendCondition, SpendsV1, Witness,
};
use nockapp::noun::slab::NounSlab;
use noun_serde::NounDecode;

#[derive(Debug, Clone, Copy)]
pub struct TransactionStats {
    pub num_spends: usize,
    pub total_fee: u64,
    pub total_seeds: usize,
    pub total_output_value: u64,
}

pub fn transaction_stats(raw_tx: &RawTransactionV1) -> TransactionStats {
    let mut stats = TransactionStats {
        num_spends: raw_tx.spends.map.wyt(),
        total_fee: 0,
        total_seeds: 0,
        total_output_value: 0,
    };

    for (_name, spend) in raw_tx.spends.map.tap().into_iter() {
        if let SpendBody::V1(v1) = &spend.body {
            stats.total_fee += v1.fee.value;
            stats.total_seeds += v1.seeds.set.wyt();
            for seed in v1.seeds.set.tap().into_iter() {
                stats.total_output_value += seed.gift.value;
            }
        }
    }

    stats
}

pub fn transaction_json(raw_tx: &RawTransactionV1, computed_id: &Hash) -> Value {
    let stats = transaction_stats(raw_tx);
    json!({
        "version": raw_tx.version,
        "tx_id": {
            "embedded": raw_tx.id.to_b58(),
            "computed": computed_id.to_b58(),
            "matches": raw_tx.id == *computed_id,
        },
        "summary": {
            "spend_count": stats.num_spends,
            "total_fee": stats.total_fee,
            "total_seeds": stats.total_seeds,
            "total_output_value": stats.total_output_value,
            "total_value": stats.total_output_value + stats.total_fee,
        },
        "spends": spends_dump(&raw_tx.spends),
    })
}

pub fn spends_dump(spends: &SpendsV1) -> Value {
    let entries: Vec<Value> = spends
        .map
        .tap()
        .into_iter()
        .map(|(name, spend)| {
            json!({
                "note_name": name.p.iter().map(|h| h.to_b58()).collect::<Vec<_>>(),
                "spend": spend_to_json(&spend),
            })
        })
        .collect();

    Value::Array(entries)
}

fn spend_to_json(spend: &Spend) -> Value {
    match &spend.body {
        SpendBody::V1(v1) => json!({
            "version": spend.version,
            "body": "v1",
            "fee": v1.fee.value,
            "witness": witness_to_json(&v1.witness),
            "seeds": seeds_to_json(&v1.seeds),
        }),
        other => json!({
            "version": spend.version,
            "body": format!("{other:?}"),
        }),
    }
}

fn witness_to_json(witness: &Witness) -> Value {
    json!({
        "lock_merkle_proof": lock_merkle_proof_to_json(&witness.lmp),
        "pkh": pkh_signature_to_json(&witness.pkh),
        "hax": zmap_hash_untyped_to_json(&witness.hax),
        "tim": witness.tim,
    })
}

fn lock_merkle_proof_to_json(lmp: &LockMerkleProof) -> Value {
    let proof = lmp.proof();
    json!({
        "format": match lmp {
            LockMerkleProof::Full(_) => "full",
            LockMerkleProof::Stub(_) => "stub",
        },
        "spend_condition": spend_condition_to_json(lmp.spend_condition()),
        "axis": lmp.axis(),
        "merkle_proof": {
            "root": proof.root.to_b58(),
            "path": proof.path.iter().map(|h| h.to_b58()).collect::<Vec<_>>(),
        }
    })
}

fn spend_condition_to_json(cond: &SpendCondition) -> Value {
    Value::Array(cond.p.iter().map(lock_primitive_to_json).collect())
}

fn lock_primitive_to_json(lp: &LockPrimitive) -> Value {
    let body = match &lp.body {
        LockPrimitiveBody::Pkh(pkh) => json!({
            "type": "pkh",
            "threshold": pkh.m,
            "hashes": pkh.h.tap().into_iter().map(|h| h.to_b58()).collect::<Vec<_>>(),
        }),
        LockPrimitiveBody::Tim(tim) => json!({
            "type": "tim",
            "rel": timelock_range_to_json(&tim.rel),
            "abs": timelock_range_to_json(&tim.abs),
        }),
        LockPrimitiveBody::Hax(hax) => json!({
            "type": "hax",
            "hashes": hax.set.tap().iter().map(|h| h.to_b58()).collect::<Vec<_>>(),
        }),
        LockPrimitiveBody::Brn(brn) => json!({
            "type": "brn",
            "value": brn.value,
        }),
    };

    json!({
        "header": lp.header,
        "body": body,
    })
}

fn timelock_range_to_json(range: &TimelockRange) -> Value {
    json!({
        "min": range.min.as_ref().map(|p| p.value),
        "max": range.max.as_ref().map(|p| p.value),
    })
}

fn pkh_signature_to_json(pkh: &PkhSignature) -> Value {
    let entries: Vec<Value> = pkh
        .map
        .tap()
        .into_iter()
        .map(|(hash, value)| {
            json!({
                "hash": hash.to_b58(),
                "pubkey": {
                    "x": value.pk.x.values,
                    "y": value.pk.y.values,
                    "infinite": value.pk.inf,
                },
                "signature": {
                    "chal": value.sig.chal.values.values,
                    "sig": value.sig.sig.values.values,
                }
            })
        })
        .collect();

    Value::Array(entries)
}

fn zmap_hash_untyped_to_json(map: &ZMap<Hash, UntypedNoun>) -> Value {
    let entries: Vec<Value> = map
        .tap()
        .into_iter()
        .map(|(hash, value)| {
            json!({
                "hash": hash.to_b58(),
                "bytes": value.p.len(),
            })
        })
        .collect();

    Value::Array(entries)
}

fn seeds_to_json(seeds: &SeedsV1) -> Value {
    Value::Array(seeds.set.tap().into_iter().map(seed_to_json).collect())
}

fn seed_to_json(seed: SeedV1) -> Value {
    json!({
        "gift": seed.gift.value,
        "lock_root": seed.lock_root.to_b58(),
        "parent_hash": seed.parent_hash.to_b58(),
        "note_data": note_data_to_json(&seed.note_data),
    })
}

fn note_data_to_json(note_data: &NoteData) -> Value {
    let entries: Vec<Value> = note_data
        .map
        .tap()
        .into_iter()
        .map(|(key, value)| {
            let value_json = if key == "lock" {
                decode_lock_entry(&value)
            } else {
                json!({
                    "type": "raw",
                    "bytes": value.p.len(),
                })
            };
            json!({
                "key": key,
                "value": value_json,
            })
        })
        .collect();

    Value::Array(entries)
}

fn decode_lock_entry(untyped: &UntypedNoun) -> Value {
    let mut slab: NounSlab = NounSlab::new();
    let noun = match slab.cue_into(untyped.p.clone()) {
        Ok(noun) => noun,
        Err(_) => {
            return json!({
                "type": "lock",
                "error": "invalid noun",
            })
        }
    };

    let cell = match noun.as_cell() {
        Ok(cell) => cell,
        Err(_) => {
            return json!({
                "type": "lock",
                "error": "expected cell",
            })
        }
    };

    let version = cell
        .head()
        .as_atom()
        .ok()
        .and_then(|atom| atom.as_u64().ok())
        .unwrap_or(0);

    match SpendCondition::from_noun(&cell.tail()) {
        Ok(cond) => json!({
            "type": "lock",
            "version": version,
            "spend_condition": spend_condition_to_json(&cond),
        }),
        Err(_) => json!({
            "type": "lock",
            "error": "failed to decode spend condition",
        }),
    }
}
