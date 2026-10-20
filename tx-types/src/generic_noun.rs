use alloc::{
    format,
    string::{String, ToString},
};
use bytes::Bytes;
use pokenoun::codec::{Decode, Encode, Error};
use pokenoun::{Arena, Noun};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UntypedNoun {
    pub p: Bytes,
}

impl UntypedNoun {
    pub fn from_value(value: &impl Encode) -> Result<Self, Error> {
        Ok(Self {
            p: value.to_jam()?.into(),
        })
    }

    pub fn decode_as<T: Decode>(&self) -> Result<T, Error> {
        T::from_jam(&self.p)
    }

    pub fn to_hashable(&self) -> Result<crate::hashing::Hashable, crate::hashing::Tip5Error> {
        let mut arena = Arena::new();
        let noun = pokenoun::cue(&self.p, &mut arena).map_err(|error| {
            crate::hashing::Tip5Error::SerializationError(format!("invalid noun jam: {error:?}"))
        })?;
        Ok(crate::hashing::Hashable::from_value(noun, &arena))
    }

    #[cfg(feature = "std")]
    pub fn to_typed<T: noun_serde::NounDecode>(&self) -> Result<T, String> {
        use nockvm::noun::NounAllocator;
        let mut slab: nockapp::noun::slab::NounSlab = nockapp::noun::slab::NounSlab::new();
        let noun = slab
            .cue_into(self.p.clone())
            .map_err(|error| format!("invalid jam: {error:?}"))?;
        T::from_noun(&noun, &slab.noun_space()).map_err(|error| error.to_string())
    }
}

impl Encode for UntypedNoun {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        let mut source = Arena::new();
        let noun = pokenoun::cue(&self.p, &mut source).map_err(|_| Error("invalid noun jam"))?;
        Ok(pokenoun::codec::copy(noun, &source, arena))
    }
}

impl Decode for UntypedNoun {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        Ok(Self {
            p: pokenoun::jam(noun, arena).into(),
        })
    }
}

crate::noun_codec::runtime_codec!(UntypedNoun);
