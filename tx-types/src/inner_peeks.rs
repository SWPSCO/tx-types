// temporary module to handle nockchain node inner.hoon peeks
use crate::collections::ZMap;
use crate::transaction_types::*;
use crate::transaction_types_v1::*;
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
