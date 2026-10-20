//! Normalize RPC note-data JSON into its canonical on-chain noun.

use crate::lock::Lock;
use crate::note_data::{BridgeDepositDataPayload, LockData};
use crate::{
    Brn, Hash, Hax, LockPrimitive, LockPrimitiveBody, NoteData, PageNumber, Pkh, SpendCondition,
    Tim, TimelockRange, UntypedNoun, ZSet,
};
use base64::Engine;
use serde_json::Value;

fn hash(value: &Value) -> Result<Hash, String> {
    Hash::from_b58(value.as_str().ok_or("hash must be a base58 string")?)
}

fn hashes(value: &Value) -> Result<ZSet<Hash>, String> {
    let values = value.as_array().ok_or("hashes must be an array")?;
    let mut set = ZSet::new();
    for value in values {
        set.put(hash(value)?);
    }
    Ok(set)
}

fn range(value: Option<&Value>) -> Result<TimelockRange, String> {
    let bound = |name: &str| -> Result<Option<PageNumber>, String> {
        match value.and_then(|value| value.get(name)) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => Ok(Some(PageNumber {
                value: value
                    .as_u64()
                    .ok_or("timelock bound must be a non-negative integer")?,
            })),
        }
    };
    Ok(TimelockRange {
        min: bound("min")?,
        max: bound("max")?,
    })
}

fn condition(value: &Value) -> Result<SpendCondition, String> {
    let primitives = value.as_array().ok_or("lock condition must be an array")?;
    if primitives.is_empty() {
        return Err("lock condition must not be empty".into());
    }
    let mut result = Vec::new();
    for primitive in primitives {
        let object = primitive
            .as_object()
            .ok_or("lock primitive must be an object")?;
        if object.len() != 1 {
            return Err("lock primitive requires one tag".into());
        }
        let (tag, value) = object.iter().next().unwrap();
        let body = match tag.as_str() {
            "pkh" => {
                let m = value
                    .get("m")
                    .and_then(Value::as_u64)
                    .ok_or("pkh.m is missing")?;
                let h = hashes(value.get("h").ok_or("pkh.h is missing")?)?;
                if m == 0 || m > h.wyt() as u64 {
                    return Err("invalid PKH threshold".into());
                }
                LockPrimitiveBody::Pkh(Pkh { m, h })
            }
            "tim" => LockPrimitiveBody::Tim(Tim {
                rel: range(value.get("relative"))?,
                abs: range(value.get("absolute"))?,
            }),
            "hax" => LockPrimitiveBody::Hax(Hax {
                set: hashes(value)?,
            }),
            "brn" => LockPrimitiveBody::Brn(Brn { value: 0 }),
            _ => return Err("unsupported lock primitive".into()),
        };
        result.push(LockPrimitive {
            header: tag.clone(),
            body,
        });
    }
    Ok(SpendCondition { p: result })
}

pub fn lock_from_json(value: &Value) -> Result<Lock, String> {
    if value.get("version").and_then(Value::as_u64) != Some(0) {
        return Err("unsupported lock-data version".into());
    }
    let lock = if let Some(branches) = value.get("branches") {
        let branches = branches
            .as_array()
            .ok_or("lock branches must be an array")?;
        Lock::from_list(branches.iter().map(condition).collect::<Result<_, _>>()?)
            .map_err(|error| error.to_string())?
    } else {
        Lock::SpendCondition(condition(value.get("data").ok_or("lock.data is missing")?)?)
    };
    if let Some(expected) = value.get("lockRoot") {
        if lock.hash() != hash(expected)? {
            return Err("lock data does not match its root".into());
        }
    }
    Ok(lock)
}

pub fn note_data_from_json(value: &Value) -> Result<NoteData, String> {
    let entries = value.as_object().ok_or("note data must be an object")?;
    let mut decoded = Vec::new();
    for (key, value) in entries {
        // Reconstructed spending metadata is outside the input-note commitment.
        if key == "lock" && value.get("source").and_then(Value::as_str) == Some("reconstructed") {
            continue;
        }
        let noun = if key == "lock" && value.is_object() {
            UntypedNoun::from_value(&LockData::V0(lock_from_json(value)?))
                .map_err(|error| error.to_string())?
        } else if key == "bridge" && value.as_str().is_some_and(|value| value.starts_with("0x")) {
            let text = value.as_str().unwrap();
            if text.len() != 42 || !text.is_ascii() {
                return Err("bridge address must be 20 bytes".into());
            }
            let mut address = [0; 20];
            for (index, byte) in address.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&text[2 + 2 * index..4 + 2 * index], 16)
                    .map_err(|_| "invalid bridge address")?;
            }
            UntypedNoun::from_value(&BridgeDepositDataPayload::from_evm_address(address))
                .map_err(|error| error.to_string())?
        } else {
            let encoded = value
                .as_str()
                .ok_or("opaque note data requires a base64 JAM string")?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "invalid note-data base64")?;
            UntypedNoun { p: bytes.into() }
        };
        decoded.push((key.clone(), noun));
    }
    NoteData::normalize(decoded).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pokenoun::codec::Encode;
    use serde_json::json;

    #[test]
    fn rpc_trees_encode_the_complete_tagged_lock() {
        let pkh = Hash { values: [7; 5] };
        let condition = crate::lock_resolver::simple_pkh(pkh.clone());
        for size in [1, 2, 4, 8, 16] {
            let lock = Lock::from_list(vec![condition.clone(); size]).unwrap();
            let branches: Vec<_> = (0..size)
                .map(|_| json!([{"pkh": {"m": 1, "h": [pkh.to_b58()]}}]))
                .collect();
            let value = if size == 1 {
                json!({"version": 0, "data": branches[0], "lockRoot": lock.hash().to_b58()})
            } else {
                json!({"version": 0, "branches": branches, "lockRoot": lock.hash().to_b58()})
            };
            let data = note_data_from_json(&json!({"lock": value})).unwrap();
            assert_eq!(
                data.to_jam().unwrap(),
                NoteData::from_lock(lock).unwrap().to_jam().unwrap()
            );
        }
    }

    #[test]
    fn rpc_metadata_is_excluded_and_opaque_note_data_is_preserved() {
        let opaque = UntypedNoun::from_value(&(42u64, 99u64)).unwrap();
        let raw = base64::engine::general_purpose::STANDARD.encode(&opaque.p);
        let data = note_data_from_json(&json!({
            "lock": {"source": "reconstructed"}, "custom": raw,
            "bridge": "0x1234567890abcdef1234567890abcdef12345678",
        }))
        .unwrap();
        assert!(!data.map.has(&"lock".into()));
        assert_eq!(data.map.get(&"custom".into()).unwrap().p, opaque.p);
        let payload = data
            .map
            .get(&"bridge".into())
            .unwrap()
            .decode_as::<BridgeDepositDataPayload>()
            .unwrap();
        assert_eq!(
            payload.to_evm_address().unwrap(),
            [
                0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
                0xcd, 0xef, 0x12, 0x34, 0x56, 0x78
            ]
        );
        assert!(note_data_from_json(&Value::Null).is_err());
        assert!(note_data_from_json(&json!({"custom": "invalid!"})).is_err());
        assert!(lock_from_json(
            &json!({"version": 0, "data": [], "lockRoot": Hash { values: [0; 5] }.to_b58()})
        )
        .is_err());
    }
}
