use noun_serde::{NounDecode, NounDecodeError};
use nockvm::noun::Noun;
use nockapp::noun::slab::NounSlab;
use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct UntypedNoun {
    pub p: Bytes,
}

impl NounDecode for UntypedNoun {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        let mut slab: NounSlab = NounSlab::new();
        slab.copy_into(*noun);
        let noun_bytes: Bytes = slab.jam();
        Ok(UntypedNoun { p: noun_bytes })
    }
}