use chrono::{DateTime, Utc, TimeZone};
use serde::{Deserialize, Serialize};
// use crate::transaction_types::Transaction;
use crate::transaction_types::{Hash, Lock, Coins};
use crate::collections::zset::ZSet;
use noun_serde::{NounDecode, NounDecodeError};
use nockvm::noun::{Noun, FullDebugCell};
use crate::collections::zmap::ZMap;
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
    pub msg: PageMsg,
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
pub struct PageMsg {
    pub message: Vec<Hash>,
}

#[derive(NounDecode, Debug, Clone)]
pub struct BigNum {
    pub header: String,
    pub body: Vec<u32>,
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