use crate::transaction_types::{Hash, Lock, Coins};
use crate::collections::zset::ZSet;
use crate::collections::zmap::ZMap;

use std::collections::{HashSet, HashMap};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, TimeZone};
use num_bigint::BigUint;

use nockvm::noun::{Noun, FullDebugCell};
use noun_serde::{NounDecode, NounDecodeError};

#[derive(Debug, Clone, NounDecode)]
pub struct Page {
    pub digest: Hash,
    // everything below this is what is hashed for the digest: +.page
    pub pow: Noun,
    // everything below this is what is hashed for the block commitment: +>.page
    pub parent: Hash,
    pub tx_ids: ZSet<Hash>,
    pub coinbase: ZMap<Lock, Coins>,
    pub timestamp: Timestamp,
    pub epoch_counter: u64,
    pub target: BigNum,
    pub accumulated_work: BigNum,
    pub height: u64,
    pub msg: Vec<u64>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct Pages {
    pub pages: ZMap<Hash, Page>,
}

#[derive(NounDecode, Debug, Clone)]
pub struct BigNum {
    pub header: String,
    pub body: Vec<u32>,
}

impl BigNum {
    pub fn to_decimal_string(&self) -> String {
        let le_u32 = self.body.clone();
        if le_u32.is_empty() { return "0".into(); }
        let bytes: Vec<u8> = le_u32.iter().flat_map(|w| w.to_le_bytes()).collect();
        BigUint::from_bytes_le(&bytes).to_str_radix(10)
    }
}

#[derive(Debug, Clone)]
pub struct Timestamp {
    pub value: DateTime<Utc>,
}

impl NounDecode for Timestamp {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        let base_urbit_epoch = 0x8000000cce9e0d80u64;
        let raw_value = u64::from_noun(noun)?;
        let unix_timestamp = (raw_value - base_urbit_epoch) as i64;
        let datetime_utc = Utc.timestamp_opt(unix_timestamp, 0)
            .single()
            .ok_or_else(|| NounDecodeError::Custom("Invalid timestamp".to_string()))?;
        Ok(Timestamp { value: datetime_utc })
    }
}
