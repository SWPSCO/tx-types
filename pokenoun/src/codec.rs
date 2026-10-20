//! Typed noun encoding over an allocation-only arena.

use crate::{Arena, Noun};
use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl core::error::Error for Error {}

pub trait Encode {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error>;

    fn to_jam(&self) -> Result<Vec<u8>, Error> {
        let mut arena = Arena::new();
        let noun = self.encode(&mut arena)?;
        Ok(crate::jam(noun, &arena))
    }
}

pub trait Decode: Sized {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error>;

    fn from_jam(bytes: &[u8]) -> Result<Self, Error> {
        let mut arena = Arena::new();
        let noun = crate::cue(bytes, &mut arena).map_err(|_| Error("invalid jam"))?;
        Self::decode(noun, &arena)
    }
}

pub fn pair(noun: Noun, arena: &Arena) -> Result<(Noun, Noun), Error> {
    match noun {
        Noun::Cell(id) => {
            let cell = arena.cell(id);
            Ok((cell.head, cell.tail))
        }
        _ => Err(Error("expected cell")),
    }
}

pub fn is_null(noun: Noun, arena: &Arena) -> bool {
    matches!(noun, Noun::Atom(id) if arena.atom_u64(id) == Some(0))
}

/// Encode a Hoon tuple: the last element is the tail, without a list terminator.
pub fn tuple(arena: &mut Arena, items: &[Noun]) -> Result<Noun, Error> {
    let mut items = items.iter().rev();
    let mut tail = *items.next().ok_or(Error("empty tuple"))?;
    for head in items {
        tail = arena.alloc_cell(*head, tail);
    }
    Ok(tail)
}

pub struct Fields {
    noun: Noun,
    remaining: usize,
}

impl Fields {
    pub fn new(noun: Noun, count: usize) -> Self {
        Self {
            noun,
            remaining: count,
        }
    }

    pub fn next(&mut self, arena: &Arena) -> Result<Noun, Error> {
        if self.remaining == 0 {
            return Err(Error("no remaining tuple fields"));
        }
        self.remaining -= 1;
        if self.remaining == 0 {
            return Ok(self.noun);
        }
        let (head, tail) = pair(self.noun, arena)?;
        self.noun = tail;
        Ok(head)
    }
}

impl Encode for u64 {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        Ok(arena.alloc_atom_u64(*self))
    }
}

impl Decode for u64 {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        match noun {
            Noun::Atom(id) => arena.atom_u64(id).ok_or(Error("atom exceeds u64")),
            _ => Err(Error("expected atom")),
        }
    }
}

impl Encode for bool {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        u64::from(!self).encode(arena)
    }
}

impl Decode for bool {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        match u64::decode(noun, arena)? {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(Error("boolean must be 0 or 1")),
        }
    }
}

impl Encode for str {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        Ok(arena.alloc_atom_bytes(self.as_bytes()))
    }
}

impl Encode for String {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        self.as_str().encode(arena)
    }
}

impl Decode for String {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        match noun {
            Noun::Atom(id) => String::from_utf8(arena.atom_bytes_trimmed(id).to_vec())
                .map_err(|_| Error("atom is not UTF-8")),
            _ => Err(Error("expected string atom")),
        }
    }
}

impl<T: Encode + ?Sized> Encode for &T {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        (*self).encode(arena)
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        match self {
            None => Ok(arena.atom0()),
            Some(value) => {
                let value = value.encode(arena)?;
                Ok(arena.alloc_cell(arena.atom0(), value))
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        if is_null(noun, arena) {
            return Ok(None);
        }
        let (tag, value) = pair(noun, arena)?;
        if !is_null(tag, arena) {
            return Err(Error("unit tag must be zero"));
        }
        T::decode(value, arena).map(Some)
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        let mut tail = arena.atom0();
        for value in self.iter().rev() {
            let head = value.encode(arena)?;
            tail = arena.alloc_cell(head, tail);
        }
        Ok(tail)
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(mut noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let mut out = Vec::new();
        while !is_null(noun, arena) {
            let (head, tail) = pair(noun, arena)?;
            out.push(T::decode(head, arena)?);
            noun = tail;
        }
        Ok(out)
    }
}

impl<T: Encode, const N: usize> Encode for [T; N] {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        let items: Result<Vec<_>, _> = self.iter().map(|value| value.encode(arena)).collect();
        tuple(arena, &items?)
    }
}

impl<T: Decode, const N: usize> Decode for [T; N] {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let mut fields = Fields::new(noun, N);
        (0..N)
            .map(|_| T::decode(fields.next(arena)?, arena))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error("wrong array length"))
    }
}

impl<A: Encode, B: Encode> Encode for (A, B) {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        let left = self.0.encode(arena)?;
        let right = self.1.encode(arena)?;
        Ok(arena.alloc_cell(left, right))
    }
}

impl<A: Decode, B: Decode> Decode for (A, B) {
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        let (left, right) = pair(noun, arena)?;
        Ok((A::decode(left, arena)?, B::decode(right, arena)?))
    }
}

/// Copy a noun between arenas, preserving sharing without recursive expansion.
pub fn copy(noun: Noun, source: &Arena, target: &mut Arena) -> Noun {
    use alloc::collections::BTreeMap;
    fn key(noun: Noun) -> (bool, u32) {
        match noun {
            Noun::Atom(id) => (false, id.0),
            Noun::Cell(id) => (true, id.0),
        }
    }
    let mut copies = BTreeMap::new();
    let mut pending = alloc::vec![(noun, false)];
    while let Some((current, visited)) = pending.pop() {
        if copies.contains_key(&key(current)) {
            continue;
        }
        match current {
            Noun::Atom(id) => {
                copies.insert(
                    key(current),
                    target.alloc_atom_bytes(source.atom_bytes_trimmed(id)),
                );
            }
            Noun::Cell(id) => {
                let cell = source.cell(id);
                if visited {
                    copies.insert(
                        key(current),
                        target.alloc_cell(copies[&key(cell.head)], copies[&key(cell.tail)]),
                    );
                } else {
                    pending.extend([(current, true), (cell.tail, false), (cell.head, false)]);
                }
            }
        }
    }
    copies[&key(noun)]
}
