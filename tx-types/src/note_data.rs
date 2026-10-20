//! Canonical note-data and typed lock/bridge payloads.

use crate::lock::Lock;
use crate::{Hash, NoteData, UntypedNoun, ZMap};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use pokenoun::codec::{is_null, pair, Decode, Encode, Error, Fields};
use pokenoun::{Arena, Noun};

pub const NOTE_DATA_KEY_LOCK: &str = "lock";
pub const NOTE_DATA_KEY_BRIDGE_DEPOSIT: &str = "bridge";
pub const NOTE_DATA_KEY_BRIDGE_WITHDRAWAL: &str = "bridge-w";

#[derive(Debug, Clone)]
pub enum LockData {
    V0(Lock),
}

impl LockData {
    pub fn lock(&self) -> &Lock {
        match self {
            Self::V0(lock) => lock,
        }
    }
}

impl Encode for LockData {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        let lock = self.lock().encode(arena)?;
        Ok(arena.alloc_cell(arena.atom0(), lock))
    }
}

impl Decode for LockData {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let (version, lock) = pair(noun, arena)?;
        if !is_null(version, arena) {
            return Err(Error("unsupported lock-data version"));
        }
        Lock::decode(lock, arena).map(Self::V0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeDepositDataPayload {
    /// Little-endian base-p digits, where p is the Goldilocks prime.
    pub evm_address_based: [u64; 3],
}

impl BridgeDepositDataPayload {
    /// Convert a 20-byte, big-endian EVM address to Hoon's three based words.
    pub fn from_evm_address(mut bytes: [u8; 20]) -> Self {
        let mut digits = [0; 3];
        for digit in &mut digits {
            let mut remainder = 0u128;
            for byte in &mut bytes {
                let value = (remainder << 8) | u128::from(*byte);
                *byte = (value / u128::from(pokenoun::GOLDILOCKS_P)) as u8;
                remainder = value % u128::from(pokenoun::GOLDILOCKS_P);
            }
            *digit = remainder as u64;
        }
        Self {
            evm_address_based: digits,
        }
    }

    pub fn to_evm_address(&self) -> Result<[u8; 20], Error> {
        let p = ibig::UBig::from(pokenoun::GOLDILOCKS_P);
        let mut address = ibig::UBig::from(0u8);
        for digit in self.evm_address_based.iter().rev() {
            if *digit >= pokenoun::GOLDILOCKS_P {
                return Err(Error("unbased address digit"));
            }
            address = address * &p + ibig::UBig::from(*digit);
        }
        let bytes = address.to_be_bytes();
        if bytes.len() > 20 {
            return Err(Error("EVM address exceeds 160 bits"));
        }
        let mut out = [0; 20];
        out[20 - bytes.len()..].copy_from_slice(&bytes);
        Ok(out)
    }
}

impl Encode for BridgeDepositDataPayload {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        self.to_evm_address()?;
        let version = arena.atom0();
        let network = "base".encode(arena)?;
        let address = self.evm_address_based.encode(arena)?;
        pokenoun::codec::tuple(arena, &[version, network, address])
    }
}

impl Decode for BridgeDepositDataPayload {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let mut fields = Fields::new(noun, 3);
        if !is_null(fields.next(arena)?, arena) {
            return Err(Error("unsupported bridge version"));
        }
        if String::decode(fields.next(arena)?, arena)? != "base" {
            return Err(Error("unsupported bridge network"));
        }
        let value = Self {
            evm_address_based: Decode::decode(fields.next(arena)?, arena)?,
        };
        value.to_evm_address()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeWithdrawalDataPayload {
    pub beid: Vec<u64>,
    pub base_hash: Hash,
    pub lock_root: Hash,
    pub base_batch_end: u64,
}

impl Encode for BridgeWithdrawalDataPayload {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        if self
            .beid
            .iter()
            .chain(self.base_hash.values.iter())
            .chain(self.lock_root.values.iter())
            .chain(core::iter::once(&self.base_batch_end))
            .any(|word| *word >= pokenoun::GOLDILOCKS_P)
        {
            return Err(Error("withdrawal payload contains an unbased word"));
        }
        let fields = [
            arena.atom0(),
            self.beid.encode(arena)?,
            self.base_hash.encode(arena)?,
            self.lock_root.encode(arena)?,
            self.base_batch_end.encode(arena)?,
        ];
        pokenoun::codec::tuple(arena, &fields)
    }
}

impl Decode for BridgeWithdrawalDataPayload {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let mut fields = Fields::new(noun, 5);
        if !is_null(fields.next(arena)?, arena) {
            return Err(Error("unsupported bridge withdrawal version"));
        }
        let value = Self {
            beid: Decode::decode(fields.next(arena)?, arena)?,
            base_hash: Decode::decode(fields.next(arena)?, arena)?,
            lock_root: Decode::decode(fields.next(arena)?, arena)?,
            base_batch_end: Decode::decode(fields.next(arena)?, arena)?,
        };
        value.encode(&mut Arena::new())?;
        Ok(value)
    }
}

#[derive(Debug, Clone)]
pub enum DecodedNoteDataPayload {
    Lock(LockData),
    BridgeDeposit(BridgeDepositDataPayload),
    BridgeWithdrawal(BridgeWithdrawalDataPayload),
    Raw(UntypedNoun),
}

#[derive(Debug, Clone)]
pub struct DecodedNoteDataEntry {
    pub key: String,
    pub payload: DecodedNoteDataPayload,
}

impl DecodedNoteDataEntry {
    /// Preserve unknown keys, versions and networks as raw based nouns.
    pub fn from_raw(key: String, value: UntypedNoun) -> Result<Self, Error> {
        validate_value(&value)?;
        let payload = match key.as_str() {
            NOTE_DATA_KEY_LOCK => value
                .decode_as::<LockData>()
                .ok()
                .map(DecodedNoteDataPayload::Lock),
            NOTE_DATA_KEY_BRIDGE_DEPOSIT => value
                .decode_as::<BridgeDepositDataPayload>()
                .ok()
                .map(DecodedNoteDataPayload::BridgeDeposit),
            NOTE_DATA_KEY_BRIDGE_WITHDRAWAL => value
                .decode_as::<BridgeWithdrawalDataPayload>()
                .ok()
                .map(DecodedNoteDataPayload::BridgeWithdrawal),
            _ => None,
        }
        .unwrap_or(DecodedNoteDataPayload::Raw(value));
        Ok(Self { key, payload })
    }

    pub fn raw_value(&self) -> Result<UntypedNoun, Error> {
        match &self.payload {
            DecodedNoteDataPayload::Lock(value) => UntypedNoun::from_value(value),
            DecodedNoteDataPayload::BridgeDeposit(value) => UntypedNoun::from_value(value),
            DecodedNoteDataPayload::BridgeWithdrawal(value) => UntypedNoun::from_value(value),
            DecodedNoteDataPayload::Raw(value) => Ok(value.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecodedNoteData(pub Vec<DecodedNoteDataEntry>);

impl DecodedNoteData {
    pub fn from_note_data(note_data: &NoteData) -> Result<Self, Error> {
        let mut entries = note_data
            .map
            .tap()
            .into_iter()
            .map(|(key, value)| DecodedNoteDataEntry::from_raw(key, value))
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(Self(entries))
    }

    pub fn lock(&self) -> Option<&Lock> {
        self.0.iter().find_map(|entry| match &entry.payload {
            DecodedNoteDataPayload::Lock(data) => Some(data.lock()),
            _ => None,
        })
    }
}

fn validate_value(value: &UntypedNoun) -> Result<(), Error> {
    let mut arena = Arena::new();
    let noun = value.encode(&mut arena)?;
    pokenoun::hash_noun_varlen(noun, &arena)
        .map_err(|_| Error("note-data must contain based atoms"))?;
    Ok(())
}

impl NoteData {
    /// Trim keys, validate based payloads, and reject conflicting duplicate keys.
    pub fn normalize(
        entries: impl IntoIterator<Item = (String, UntypedNoun)>,
    ) -> Result<Self, Error> {
        let mut map = ZMap::<String, UntypedNoun>::new();
        for (key, value) in entries {
            let key = key.trim().to_string();
            if key.is_empty() {
                return Err(Error("empty note-data key"));
            }
            validate_value(&value)?;
            let canonical = UntypedNoun::from_value(&value)?;
            if let Some(existing) = map
                .try_get(&key)
                .map_err(|_| Error("note-data key is not based"))?
            {
                if existing != &canonical {
                    return Err(Error("conflicting note-data values"));
                }
            }
            map.try_put(key, canonical)
                .map_err(|_| Error("note-data key is not based"))?;
        }
        Ok(Self { map })
    }

    pub fn from_lock(lock: Lock) -> Result<Self, Error> {
        Self::normalize([(
            NOTE_DATA_KEY_LOCK.into(),
            UntypedNoun::from_value(&LockData::V0(lock))?,
        )])
    }

    pub fn insert_bridge_deposit(
        &mut self,
        payload: &BridgeDepositDataPayload,
    ) -> Result<(), Error> {
        self.map.put(
            NOTE_DATA_KEY_BRIDGE_DEPOSIT.into(),
            UntypedNoun::from_value(payload)?,
        );
        Ok(())
    }

    pub fn insert_bridge_withdrawal(
        &mut self,
        payload: &BridgeWithdrawalDataPayload,
    ) -> Result<(), Error> {
        self.map.put(
            NOTE_DATA_KEY_BRIDGE_WITHDRAWAL.into(),
            UntypedNoun::from_value(payload)?,
        );
        Ok(())
    }
}

pub fn lock_data_to_untyped_noun(data: &LockData) -> Result<UntypedNoun, Error> {
    UntypedNoun::from_value(data)
}

crate::noun_codec::runtime_codec!(
    LockData,
    BridgeDepositDataPayload,
    BridgeWithdrawalDataPayload
);
