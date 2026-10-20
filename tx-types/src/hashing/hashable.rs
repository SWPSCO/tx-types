//! Hoon's hashable representation, shared by hosted and embedded builds.

use crate::transaction_types::Hash;
use alloc::{boxed::Box, string::String, vec::Vec};
use pokenoun::codec::{pair, Decode, Encode, Error};
use pokenoun::{Arena, Noun};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hashable {
    /// JAM of a noun to hash as one leaf.
    Leaf(Vec<u8>),
    Hash(Hash),
    Cell(Box<Hashable>, Box<Hashable>),
    List(Vec<Hashable>),
}

impl Hashable {
    pub fn leaf_from_atom(data: impl AsRef<[u8]>) -> Self {
        let mut arena = Arena::new();
        let noun = arena.alloc_atom_bytes(data.as_ref());
        Self::Leaf(pokenoun::jam(noun, &arena))
    }

    pub fn leaf_from_tas(text: &str) -> Self {
        Self::leaf_from_atom(text.as_bytes())
    }
    pub fn null() -> Self {
        Self::Leaf(alloc::vec![2])
    }
    pub fn hash(digest: Hash) -> Self {
        Self::Hash(digest)
    }
    pub fn cell(left: Self, right: Self) -> Self {
        Self::Cell(Box::new(left), Box::new(right))
    }
    pub fn triple(first: Self, second: Self, third: Self) -> Self {
        Self::cell(first, Self::cell(second, third))
    }
    pub fn list(items: Vec<Self>) -> Self {
        Self::List(items)
    }

    pub fn cons_list<I: IntoIterator<Item = Self>>(elements: I) -> Self {
        let mut tail = Self::null();
        let items: Vec<_> = elements.into_iter().collect();
        for item in items.into_iter().rev() {
            tail = Self::cell(item, tail);
        }
        tail
    }

    pub fn cell_chain<I: IntoIterator<Item = Self>>(elements: I) -> Self {
        let mut items: Vec<_> = elements.into_iter().collect();
        let mut tail = items.pop().unwrap_or_else(Self::null);
        while let Some(item) = items.pop() {
            tail = Self::cell(item, tail);
        }
        tail
    }

    /// Expand arbitrary noun cells into hashable cells, leaving atoms as leaves.
    pub fn from_value(noun: Noun, arena: &Arena) -> Self {
        match noun {
            Noun::Atom(_) => Self::Leaf(pokenoun::jam(noun, arena)),
            Noun::Cell(id) => {
                let cell = arena.cell(id);
                Self::cell(
                    Self::from_value(cell.head, arena),
                    Self::from_value(cell.tail, arena),
                )
            }
        }
    }

    pub fn to_jam(&self) -> Vec<u8> {
        Encode::to_jam(self).expect("hashable contains valid leaf jams")
    }

    #[cfg(feature = "std")]
    pub fn to_noun(&self, slab: &mut nockapp::noun::slab::NounSlab) -> nockvm::noun::Noun {
        crate::noun_codec::encode_runtime(self, slab)
    }

    #[cfg(feature = "std")]
    pub fn from_noun(
        noun: &nockvm::noun::Noun,
        space: &nockvm::noun::NounSpace,
    ) -> Result<Self, String> {
        crate::noun_codec::decode_runtime(*noun, space).map_err(|error| error.to_string())
    }
}

impl Encode for Hashable {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        let (tag, value) = match self {
            Self::Leaf(jam) => {
                let mut source = Arena::new();
                let noun = pokenoun::cue(jam, &mut source)
                    .map_err(|_| Error("invalid hashable leaf jam"))?;
                ("leaf", pokenoun::codec::copy(noun, &source, arena))
            }
            Self::Hash(hash) => ("hash", hash.encode(arena)?),
            Self::List(items) => ("list", items.encode(arena)?),
            Self::Cell(left, right) => {
                let head = left.encode(arena)?;
                let tail = right.encode(arena)?;
                return Ok(arena.alloc_cell(head, tail));
            }
        };
        let tag = tag.encode(arena)?;
        Ok(arena.alloc_cell(tag, value))
    }
}

impl Decode for Hashable {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let (head, tail) = pair(noun, arena)?;
        if let Noun::Atom(id) = head {
            return match arena.atom_bytes_trimmed(id) {
                b"leaf" => Ok(Self::Leaf(pokenoun::jam(tail, arena))),
                b"hash" => Ok(Self::Hash(Hash::decode(tail, arena)?)),
                b"list" => Ok(Self::List(Vec::decode(tail, arena)?)),
                _ => Err(Error("invalid hashable tag")),
            };
        }
        Ok(Self::cell(
            Self::decode(head, arena)?,
            Self::decode(tail, arena)?,
        ))
    }
}
