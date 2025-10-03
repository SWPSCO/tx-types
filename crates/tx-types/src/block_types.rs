use crate::transaction_types::*;
use crate::collections::zset::ZSet;
use crate::collections::zmap::ZMap;

use std::collections::{HashSet, HashMap};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, TimeZone};
use num_bigint::BigUint;

use nockvm::noun::{Noun, FullDebugCell};
use nockapp::noun::slab::NounSlab;
use noun_serde::{NounDecode, NounDecodeError, NounEncode};
use bytes::Bytes;

#[derive(Debug, Clone, NounDecode)]
pub struct Page {
    pub digest: Hash,
    // everything below this is what is hashed for the digest: +.page
    pub pow: Pow,
    // everything below this is what is hashed for the block commitment: +>.page
    pub parent: Hash,
    pub tx_ids: ZSet<Hash>,
    pub coinbase: ZMap<Lock, Coins>,
    pub timestamp: Timestamp,
    pub epoch_counter: u64,
    pub target: BigNum,
    pub accumulated_work: BigNum,
    pub height: PageNumber,
    pub msg: Vec<u64>,
}

use tracing::info;

impl Page {
    pub fn coinbase_notes(&self) -> Vec<NNote> {
        // init the notes vector
        let mut notes: Vec<NNote> = Vec::new();

        // get the locks coinbases
        let locks: Vec<(Lock, Coins)> = self.coinbase.tap()
            .into_iter().map(|(lock, coins)| (lock, coins)).collect();

        for (lock, assets) in locks {
            let page = self.clone();

            let timelock = Self::coinbase_timelock(self.height.clone());

            let meta = NNoteHead {
                version: 0, // TODO
                origin_page: page.height,
                timelock: timelock.clone(),
            };

            let source = Source { p: self.parent.clone(), is_coinbase: true };
            let name = NName::new_default(lock.clone(), source.clone(), timelock.clone());

            let note = NNote { meta, name, lock, source, assets };

            notes.push(note);
        }
        notes
    }
    pub fn coinbase_timelock(height: PageNumber) -> Timelock {
        const first_month_coinbase_min: u64 = 4383;
        const coinbase_timelock_min: u64 = 100;

        let val = if height.value < first_month_coinbase_min {
            Some(PageNumber { value: first_month_coinbase_min })
        } else {
            Some(PageNumber { value: coinbase_timelock_min })
        };
        Timelock::new_unchecked(Some((
            TimelockRange { min: None, max: None },
            TimelockRange { min: val, max: None },
        )))
    }
}

#[derive(Debug, Clone, NounDecode)]
pub struct Pages {
    pub pages: ZMap<Hash, Page>,
}

#[derive(NounDecode, Debug, Clone)]
pub struct PageSummary {
    pub digest: Hash,
    pub timestamp: Timestamp,
    pub epoch_counter: u64,
    pub target: BigNum,
    pub accumulated_work: BigNum,
    pub height: u64,
    pub parent: Hash,
}

impl Timestamp {
    pub fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
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
pub struct Pow {
    pub p: Bytes,
}

impl NounDecode for Pow {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        let mut slab: NounSlab = NounSlab::new();
        slab.copy_into(*noun);
        let noun_bytes: Bytes = slab.jam();
        Ok(Pow { p: noun_bytes })
    }
}

#[derive(NounDecode, NounEncode, Debug, Clone)]
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
