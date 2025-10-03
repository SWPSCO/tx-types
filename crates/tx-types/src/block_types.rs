use chrono::{DateTime, Utc, TimeZone};
use serde::{Deserialize, Serialize};
use crate::transaction_types::{Transaction, Hash, Lock, Coins};
use crate::collections::zset::ZSet;
use crate::collections::zmap::ZMap;
use num_bigint::BigUint;
use nockvm::noun::Noun;
use nockapp::noun::slab::NounSlab;
use noun_serde::{NounDecode, NounDecodeError, NounEncode};
use bytes::Bytes;

// ============================================================================
// Simple RPC Types (from main branch)
// Used for high-level RPC responses and API
// ============================================================================

/// High-level block representation for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPage {
    pub height: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: DateTime<Utc>,
    pub transactions: Vec<SimpleTransaction>,
    pub target: String,
    pub coinbase: Vec<CoinbaseRecipient>,
}

/// Simplified transaction for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleTransaction {
    pub id: String,
    pub inputs: Vec<SimpleTransactionInput>,
    pub outputs: Vec<SimpleTransactionOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleTransactionInput {
    pub tx_id: String,
    pub index: u32,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleTransactionOutput {
    pub index: u32,
    pub amount: u64,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinbaseRecipient {
    pub address: String,
    pub amount: u64,
}

// ============================================================================
// Full Noun-Based Types (from nallux/rpc branch)
// Used for direct noun decoding from blockchain data
// ============================================================================

/// Full page structure with noun decoding
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
    pub height: u64,
    pub msg: Vec<u64>,
}

/// Collection of pages
#[derive(Debug, Clone, NounDecode)]
pub struct Pages {
    pub pages: ZMap<Hash, Page>,
}

/// Summarized page information
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

/// Proof-of-work stored as pre-jammed bytes
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

/// Big number representation for targets and work
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

/// Timestamp with Urbit epoch conversion
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

// ============================================================================
// Conversions and Utility Implementations
// ============================================================================

impl BlockPage {
    /// Create a mock BlockPage for testing
    pub fn mock(height: u64) -> Self {
        BlockPage {
            height,
            hash: format!("hash_{}", height),
            parent_hash: if height > 0 {
                format!("hash_{}", height - 1)
            } else {
                "genesis".to_string()
            },
            timestamp: Utc::now(),
            transactions: vec![],
            target: "00000000ffff0000000000000000000000000000000000000000000000000000".to_string(),
            coinbase: vec![
                CoinbaseRecipient {
                    address: "mock_miner".to_string(),
                    amount: 5000000000,
                }
            ],
        }
    }
}

impl TryFrom<nockapp::Noun> for BlockPage {
    type Error = String;

    fn try_from(_noun: nockapp::Noun) -> Result<Self, Self::Error> {
        // For now, return a simple mock-like structure
        // TODO: Implement actual Noun parsing based on kernel's data format
        Ok(BlockPage {
            height: 0,
            hash: "from_noun".to_string(),
            parent_hash: "parent".to_string(),
            timestamp: Utc::now(),
            transactions: vec![],
            target: "target".to_string(),
            coinbase: vec![],
        })
    }
}

// Conversion utilities between low-level and high-level types
impl From<Transaction> for SimpleTransaction {
    fn from(tx: Transaction) -> Self {
        // TODO: Implement proper conversion from Transaction to SimpleTransaction
        SimpleTransaction {
            id: tx.name,
            inputs: vec![],
            outputs: vec![],
        }
    }
}
