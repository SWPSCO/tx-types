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

impl Page {
    pub fn to_postgres(&self) -> PostgresPage {
        let digest = self.digest.to_b58();
        let pow = format!("https://placeholder.url/bucket/{}", self.height);
        let parent = self.parent.to_b58();
        let tx_ids = self.tx_ids.tap().iter().map(|tx_id| tx_id.to_b58()).collect();
        let coinbase = self.coinbase.tap().iter().map(|(lock, coins)| PostgresCoinbase {
            m: lock.m,
            pubkeys: lock.pubkeys.tap().iter().map(|pubkey| pubkey.to_b58()).collect(),
            coins: coins.value,
        }).collect();
        let timestamp = self.timestamp.value;
        let epoch_counter = self.epoch_counter;
        let target = self.target.to_decimal_string();
        let accumulated_work = self.accumulated_work.to_decimal_string();
        let height = self.height;
        let msg = (!self.msg.is_empty()).then(|| {
            let mut out = String::with_capacity(self.msg.len() * 8); // upper bound
            for &w in &self.msg {
                let bytes = w.to_le_bytes();
                // Trim trailing NULs within this 8-byte LE chunk
                let used = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
                if let Ok(s) = std::str::from_utf8(&bytes[..used]) { out.push_str(s); }
            }
            out
        });
        PostgresPage {
            digest,
            pow,
            parent,
            tx_ids,
            coinbase,
            timestamp,
            epoch_counter,
            target,
            accumulated_work,
            height,
            msg,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoinbaseSplit {
    pub recipients: u64,
}

impl NounDecode for CoinbaseSplit {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        tracing::info!("CoinbaseSplit noun: {:?}", noun);
        Ok(CoinbaseSplit { recipients: 0 })
    }
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

#[derive(Debug, Clone)]
pub struct PostgresPage {
    pub digest: String,
    // everything below this is what is hashed for the digest: +.page
    pub pow: String, // link to s3 bucket
    // everything below this is what is hashed for the block commitment: +>.page
    pub parent: String, // link to s3 bucket
    pub tx_ids: Vec<String>,
    pub coinbase: Vec<PostgresCoinbase>,
    pub timestamp: DateTime<Utc>,
    pub epoch_counter: u64,
    pub target: String,
    pub accumulated_work: String,
    pub height: u64,
    pub msg: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PostgresCoinbase {
    pub m: u64,
    pub pubkeys: Vec<String>,
    pub coins: u64,

}