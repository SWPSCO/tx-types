// temporary module to handle nockchain node inner.hoon peeks
use crate::collections::ZMap;
use crate::collections::ZSet;
use crate::transaction_types::*;
use crate::transaction_types_v1::*;
use crate::block_types::*;
use noun_serde::{NounDecode, NounEncode};

#[derive(Debug, Clone, NounDecode)]
pub struct BalanceByFirstName {
    pub page_number: PageNumber,
    pub block_id: Hash,
    pub balance: Balance,
}

#[derive(Debug, Clone, NounDecode)]
pub struct Balance {
    pub map: ZMap<NName, NNote>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct MiningPubkeys {
    pub values: Vec<MiningPubkey>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct MiningPubkey {
    pub m: u64,
    pub pks: Vec<String>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct RawTxHeardAt {
    pub raw_tx: RawTransaction,
    pub heard_at: PageNumber,
}

#[derive(Debug, Clone, NounDecode)]
pub struct RawTransactions {
    pub map: ZMap<Hash, RawTxHeardAt>
}

#[derive(Debug, Clone, NounDecode)]
pub struct ExcludedRawTransactions {
    pub set: ZSet<Hash>
}

#[derive(Debug, Clone, NounDecode)]
pub struct HeaviestChainBlock {
    pub height: PageNumber,
    pub block_id: Hash,
    pub block: Page,
    pub map: ZMap<Hash, Tx>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct HeaviestChainBlockRange {
    pub list: Vec<HeaviestChainBlock>
}
