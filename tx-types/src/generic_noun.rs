use noun_serde::{NounDecode, NounDecodeError, NounEncode};
use nockvm::noun::Noun;
use nockapp::noun::slab::{NockJammer, NounSlab};
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

impl NounEncode for UntypedNoun {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, _alloc: &mut A) -> nockvm::noun::Noun {
        let mut slab: NounSlab<NockJammer> = NounSlab::new();
        slab.cue_into(self.p.clone())
            .expect("failed to cue UntypedNoun");
        unsafe { *slab.root() }
    }
}