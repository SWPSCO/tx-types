use crate::transaction_types::Hash;
use nockapp::noun::slab::NounSlab;
use nockapp::utils::make_tas;
use nockapp::Bytes;
use nockvm::noun::{Noun, NounAllocator, NounSpace, D, T};
use noun_serde::{NounDecode, NounEncode};
/// Hashable enum mirroring Hoon's hashable type
/// This is an intermediate representation for hashing complex structures
use std::fmt::Debug;

/// Hashable representation matching Hoon's hashable type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hashable {
    /// Jammed noun bytes to be hashed (equivalent to [%leaf p=*])
    ///
    /// The Vec<u8> contains a jammed (serialized) noun that will be
    /// cued (deserialized) before hashing.
    ///
    /// For simple atoms, use `Hashable::leaf_from_atom()`.
    ///
    /// For arbitrary nouns (cells, lists, etc.), build the noun and jam it:
    /// ```rust,ignore
    /// let mut slab: NounSlab = NounSlab::new();
    /// let noun = build_your_noun(&mut slab);  // Could be cell, list, etc.
    /// slab.set_root(noun);
    /// Hashable::Leaf(slab.jam().to_vec())
    /// ```
    Leaf(Vec<u8>),

    /// Pre-computed hash (equivalent to [%hash p=noun-digest])
    Hash(Hash),

    /// Binary cell structure (equivalent to [p=hashable q=hashable])
    Cell(Box<Hashable>, Box<Hashable>),

    /// List of hashables (equivalent to [%list p=(list hashable)])
    List(Vec<Hashable>),
}

impl Hashable {
    /// Create a leaf from atom data by jamming it as a noun
    ///
    /// **This function is for atoms only.** For complex nouns (cells, lists),
    /// build the noun structure directly, jam it, and wrap in `Hashable::Leaf`.
    ///
    /// This function interprets the byte slice as atom data (little-endian),
    /// creates an atom noun from it, jams (serializes) the noun, and stores
    /// the jammed bytes in a Leaf variant.
    pub fn leaf_from_atom(data: impl AsRef<[u8]>) -> Self {
        use nockapp::noun::slab::NounSlab;
        use nockapp::{AtomExt, Bytes};
        use nockvm::noun::Atom;

        let bytes = data.as_ref();
        let mut slab: NounSlab = NounSlab::new();

        // Create an atom from the bytes (same logic as hash_noun_varlen)
        let noun = if bytes.is_empty() {
            Atom::new(&mut slab, 0).as_noun()
        } else if bytes.len() <= 8 {
            // For small data, convert directly to u64
            let mut value = 0u64;
            for (i, &byte) in bytes.iter().enumerate() {
                value |= (byte as u64) << (i * 8);
            }
            Atom::new(&mut slab, value).as_noun()
        } else {
            // For larger data, use Atom::from_bytes
            let b = Bytes::copy_from_slice(bytes);
            Atom::from_bytes(&mut slab, &b).as_noun()
        };

        // Set the noun as the slab root and jam it
        slab.set_root(noun);
        Hashable::Leaf(slab.jam().to_vec())
    }

    /// Create a leaf from an @tas (ASCII) string, matching Hoon's `leaf+%foo`.
    pub fn leaf_from_tas(text: &str) -> Self {
        let mut slab: NounSlab = NounSlab::new();
        let noun = make_tas(&mut slab, text).as_noun();
        slab.set_root(noun);
        Hashable::Leaf(slab.jam().to_vec())
    }

    /// Create a leaf representing null/empty
    ///
    /// In Hoon, null (0) is represented as leaf+0. This creates
    /// a noun (atom with value 0), jams it, and stores the jammed bytes.
    pub fn null() -> Self {
        use nockapp::noun::slab::NounSlab;
        use nockvm::noun::Atom;

        let mut slab: NounSlab = NounSlab::new();
        let noun = Atom::new(&mut slab, 0).as_noun();
        slab.set_root(noun);
        Hashable::Leaf(slab.jam().to_vec())
    }

    /// Create a pre-computed hash node
    pub fn hash(digest: Hash) -> Self {
        Hashable::Hash(digest)
    }

    /// Create a cell from two hashables
    pub fn cell(left: Hashable, right: Hashable) -> Self {
        Hashable::Cell(Box::new(left), Box::new(right))
    }

    /// Create a triple (syntactic sugar for nested cells)
    /// Equivalent to Hoon's :+ operator
    pub fn triple(first: Hashable, second: Hashable, third: Hashable) -> Self {
        Hashable::Cell(
            Box::new(first),
            Box::new(Hashable::Cell(Box::new(second), Box::new(third))),
        )
    }

    /// Create a list of hashables
    pub fn list(items: Vec<Hashable>) -> Self {
        Hashable::List(items)
    }

    /// Build a proper Hoon list (right-associated cells ending in null)
    /// from the provided hashable elements.
    pub fn cons_list<I>(elements: I) -> Self
    where
        I: IntoIterator<Item = Hashable>,
    {
        let mut tail = Hashable::null();
        let mut items: Vec<Hashable> = elements.into_iter().collect();
        while let Some(elem) = items.pop() {
            tail = Hashable::cell(elem, tail);
        }
        tail
    }

    /// Build nested cells without a terminating null (Hoon `:* ... ==`).
    ///
    /// For example, `cell_chain([a, b, c, d])` produces `[a [b [c d]]]`.
    /// If no elements are provided, this returns `Hashable::null()`.
    pub fn cell_chain<I>(elements: I) -> Self
    where
        I: IntoIterator<Item = Hashable>,
    {
        let mut items: Vec<Hashable> = elements.into_iter().collect();
        match items.pop() {
            None => Hashable::null(),
            Some(mut acc) => {
                while let Some(elem) = items.pop() {
                    acc = Hashable::cell(elem, acc);
                }
                acc
            }
        }
    }

    /// Convert this hashable structure into a Hoon noun representation.
    /// Primarily used for debugging to compare with the wallet's hashable output.
    pub fn to_noun(&self, slab: &mut NounSlab) -> Noun {
        match self {
            Hashable::Leaf(bytes) => {
                let tag = make_tas(slab, "leaf").as_noun();
                let mut cue_slab: NounSlab = NounSlab::new();
                let value_noun = cue_slab
                    .cue_into(Bytes::copy_from_slice(bytes))
                    .expect("Hashable::Leaf must contain valid jam bytes");
                let cue_space = cue_slab.noun_space();
                let copied = slab.copy_into(value_noun, &cue_space);
                T(slab, &[tag, copied])
            }
            Hashable::Hash(hash) => {
                let tag = make_tas(slab, "hash").as_noun();
                let hash_noun = hash.to_noun(slab);
                T(slab, &[tag, hash_noun])
            }
            Hashable::Cell(left, right) => {
                let l = left.to_noun(slab);
                let r = right.to_noun(slab);
                T(slab, &[l, r])
            }
            Hashable::List(items) => {
                let tag = make_tas(slab, "list").as_noun();
                let mut tail = D(0);
                for item in items.iter().rev() {
                    let noun = item.to_noun(slab);
                    tail = T(slab, &[noun, tail]);
                }
                T(slab, &[tag, tail])
            }
        }
    }

    /// Reject leaves whose stored jam bytes cannot be decoded, so hashing can
    /// return a real error instead of a fabricated digest.
    pub(crate) fn validate_leaves(&self) -> Result<(), crate::hashing::tip5::Tip5Error> {
        use crate::hashing::tip5::Tip5Error;

        match self {
            Hashable::Leaf(bytes) => {
                let mut slab: NounSlab = NounSlab::new();
                slab.cue_into(Bytes::copy_from_slice(bytes))
                    .map(|_| ())
                    .map_err(|err| {
                        Tip5Error::SerializationError(format!(
                            "Hashable::Leaf contains invalid jam bytes: {:?}",
                            err
                        ))
                    })
            }
            Hashable::Cell(left, right) => {
                left.validate_leaves()?;
                right.validate_leaves()
            }
            Hashable::List(items) => {
                for item in items {
                    item.validate_leaves()?;
                }
                Ok(())
            }
            Hashable::Hash(_) => Ok(()),
        }
    }

    /// Serialize the hashable structure into jammed bytes of the underlying noun.
    pub fn to_jam(&self) -> Vec<u8> {
        let mut slab: NounSlab = NounSlab::new();
        let noun = self.to_noun(&mut slab);
        slab.set_root(noun);
        slab.jam().to_vec()
    }

    /// Reconstruct a `Hashable` structure from a noun that follows the Hoon
    /// `%hashable` encoding (used by tx-engine and TIP5 hashing).
    pub fn from_noun(noun: &Noun, space: &NounSpace) -> Result<Self, String> {
        let handle = noun.in_space(space);
        if let Ok(cell) = handle.as_cell() {
            if let Ok(tag_atom) = cell.head().as_atom() {
                if tag_atom.eq_bytes(b"leaf") {
                    let jam = jam_noun(cell.tail().noun(), space);
                    return Ok(Hashable::Leaf(jam));
                } else if tag_atom.eq_bytes(b"hash") {
                    let digest = Hash::from_noun(&cell.tail().noun(), space)
                        .map_err(|e| format!("hash decode: {e}"))?;
                    return Ok(Hashable::Hash(digest));
                } else if tag_atom.eq_bytes(b"list") {
                    let items = decode_hashable_list(cell.tail().noun(), space)?;
                    return Ok(Hashable::List(items));
                }
            }

            Ok(Hashable::Cell(
                Box::new(Hashable::from_noun(&cell.head().noun(), space)?),
                Box::new(Hashable::from_noun(&cell.tail().noun(), space)?),
            ))
        } else {
            Err("hashable noun must be a cell".into())
        }
    }
}

fn jam_noun(noun: Noun, space: &NounSpace) -> Vec<u8> {
    let mut slab: NounSlab = NounSlab::new();
    let copied = slab.copy_into(noun, space);
    slab.set_root(copied);
    slab.jam().to_vec()
}

fn decode_hashable_list(noun: Noun, space: &NounSpace) -> Result<Vec<Hashable>, String> {
    let mut items = Vec::new();
    let mut cursor = noun;
    loop {
        let handle = cursor.in_space(space);
        if let Ok(atom) = handle.as_atom() {
            let end = atom
                .as_u64()
                .map_err(|e| format!("list terminator decode: {e}"))?;
            if end != 0 {
                return Err("hashable list not properly terminated".into());
            }
            break;
        }

        let cell = handle
            .as_cell()
            .map_err(|_| "expected cell while decoding hashable list".to_string())?;
        items.push(Hashable::from_noun(&cell.head().noun(), space)?);
        cursor = cell.tail().noun();
    }
    Ok(items)
}
