use bytes::Bytes;
use nockapp::noun::slab::NounSlab;
use nockvm::noun::Noun;
use noun_serde::{NounDecode, NounDecodeError};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UntypedNoun {
    pub p: Bytes,
}

impl UntypedNoun {
    /// Deserialize the UntypedNoun back to a typed value
    ///
    /// This method cues (unjams) the stored bytes and then decodes them
    /// into the target type T.
    ///
    /// # Type Parameters
    /// * `T` - The type to decode into. Must implement `NounDecode`.
    ///
    /// # Returns
    /// * `Ok(T)` - Successfully deserialized value
    /// * `Err(String)` - Error message if deserialization failed
    ///
    /// # Example
    /// ```ignore
    /// let untyped: UntypedNoun = ...;
    /// let lock_data: LockData = untyped.to_typed()?;
    /// ```
    pub fn to_typed<T: NounDecode>(&self) -> Result<T, String> {
        // Create a new slab for cueing
        let mut slab: NounSlab = NounSlab::new();

        // Cue (unjam) the bytes to get back the noun
        let noun = slab
            .cue_into(self.p.clone())
            .map_err(|e| format!("Failed to cue noun: {:?}", e))?;

        // Decode the noun into type T
        T::from_noun(&noun).map_err(|e| format!("Failed to decode noun: {:?}", e))
    }
}

impl NounDecode for UntypedNoun {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        let mut slab: NounSlab = NounSlab::new();
        slab.copy_into(*noun);
        let noun_bytes: Bytes = slab.jam();
        Ok(UntypedNoun { p: noun_bytes })
    }
}
