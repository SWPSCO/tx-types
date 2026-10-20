//! Runtime adapters for the shared allocation-only noun codec.

pub use pokenoun::codec::{Decode, Encode, Error};

/// Validate that every encoded atom fits the protocol's base field.
pub fn validate_based(value: &impl Encode) -> Result<(), Error> {
    let mut arena = pokenoun::Arena::new();
    let noun = value.encode(&mut arena)?;
    pokenoun::hash_noun_varlen(noun, &arena).map_err(|_| Error("noun contains an unbased atom"))?;
    Ok(())
}

macro_rules! runtime_codec {
    ($($ty:ty),+ $(,)?) => {$(
        #[cfg(feature = "std")]
        impl noun_serde::NounEncode for $ty {
            fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
                $crate::noun_codec::encode_runtime(self, alloc)
            }
        }
        #[cfg(feature = "std")]
        impl noun_serde::NounDecode for $ty {
            fn from_noun(noun: &nockvm::noun::Noun, space: &nockvm::noun::NounSpace)
                -> Result<Self, noun_serde::NounDecodeError>
            {
                $crate::noun_codec::decode_runtime(*noun, space)
            }
        }
    )+};
}
pub(crate) use runtime_codec;

/// Named structs encode as right-associated tuples; wrappers encode transparently.
macro_rules! noun_struct {
    ($($ty:ty { $($field:ident),+ $(,)? }),+ $(,)?) => {$(
        impl pokenoun::codec::Encode for $ty {
            fn encode(&self, arena: &mut pokenoun::Arena) -> Result<pokenoun::Noun, pokenoun::codec::Error> {
                let fields = [$(pokenoun::codec::Encode::encode(&self.$field, arena)?),+];
                pokenoun::codec::tuple(arena, &fields)
            }
        }
        impl pokenoun::codec::Decode for $ty {
            fn decode(noun: pokenoun::Noun, arena: &pokenoun::Arena) -> Result<Self, pokenoun::codec::Error> {
                let count = [$(stringify!($field)),+].len();
                let mut fields = pokenoun::codec::Fields::new(noun, count);
                Ok(Self { $($field: pokenoun::codec::Decode::decode(fields.next(arena)?, arena)?),+ })
            }
        }
        $crate::noun_codec::runtime_codec!($ty);
    )+};
}
pub(crate) use noun_struct;

#[cfg(feature = "std")]
pub fn encode_runtime<T: Encode, A: nockvm::noun::NounAllocator>(
    value: &T,
    alloc: &mut A,
) -> nockvm::noun::Noun {
    use nockapp::AtomExt;
    use nockvm::noun::{Atom, T};
    let mut arena = pokenoun::Arena::new();
    let root = value
        .encode(&mut arena)
        .expect("value must have a valid noun encoding");
    let mut copies = alloc::collections::BTreeMap::new();
    let mut pending = alloc::vec![(root, false)];
    while let Some((noun, visited)) = pending.pop() {
        if copies.contains_key(&noun) {
            continue;
        }
        let copied = match noun {
            pokenoun::Noun::Atom(id) => {
                let bytes = arena.atom_bytes_trimmed(id);
                if bytes.is_empty() {
                    nockvm::noun::D(0)
                } else {
                    Atom::from_bytes(alloc, &bytes::Bytes::copy_from_slice(bytes)).as_noun()
                }
            }
            pokenoun::Noun::Cell(id) => {
                let cell = arena.cell(id);
                if !visited {
                    pending.extend([(noun, true), (cell.tail, false), (cell.head, false)]);
                    continue;
                }
                T(alloc, &[copies[&cell.head], copies[&cell.tail]])
            }
        };
        copies.insert(noun, copied);
    }
    copies[&root]
}

#[cfg(feature = "std")]
pub fn decode_runtime<T: Decode>(
    noun: nockvm::noun::Noun,
    space: &nockvm::noun::NounSpace,
) -> Result<T, noun_serde::NounDecodeError> {
    let mut slab: nockapp::noun::slab::NounSlab = nockapp::noun::slab::NounSlab::new();
    let copied = slab.copy_into(noun, space);
    slab.set_root(copied);
    T::from_jam(&slab.jam()).map_err(|error| noun_serde::NounDecodeError::Custom(error.to_string()))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    #[test]
    fn runtime_adapter_preserves_shared_subtrees() {
        let mut arena = pokenoun::Arena::new();
        let mut noun = arena.alloc_atom_u64(42);
        for _ in 0..40 {
            noun = arena.alloc_cell(noun, noun);
        }
        let jam = pokenoun::jam(noun, &arena);
        let value = crate::UntypedNoun {
            p: jam.clone().into(),
        };
        let mut slab: nockapp::noun::slab::NounSlab = nockapp::noun::slab::NounSlab::new();
        let noun = encode_runtime(&value, &mut slab);
        slab.set_root(noun);
        assert_eq!(slab.jam().as_ref(), jam.as_slice());
    }
}
