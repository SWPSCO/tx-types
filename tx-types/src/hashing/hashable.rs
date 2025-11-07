use crate::transaction_types::Hash;
/// Hashable enum mirroring Hoon's hashable type
/// This is an intermediate representation for hashing complex structures
use std::fmt::Debug;

/// Hashable representation matching Hoon's hashable type
#[derive(Debug, Clone)]
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
}
