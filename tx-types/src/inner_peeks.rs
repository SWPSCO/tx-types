// temporary module to handle nockchain node inner.hoon peeks
use crate::transaction_types::*;
use crate::transaction_types_v1::*;
use crate::collections::ZMap;
use noun_serde::{NounDecode, NounEncode};

#[derive(Debug, Clone, NounDecode)]
pub struct BalanceByFirstName {
    pub page_number: PageNumber,
    pub block_id: Hash,
    pub map: ZMap<NName, NNoteV1>
}