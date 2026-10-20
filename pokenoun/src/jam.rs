extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use crate::arena::{Arena, CellId, Noun};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    UnexpectedEof,
    AtomTooLarge,
    InvalidBackref,
    InvalidEncoding,
}

struct BitReader<'a> {
    bytes: &'a [u8],
    bit: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit: 0 }
    }

    fn pos(&self) -> u64 {
        self.bit as u64
    }

    /// Number of unread bits remaining in the input.
    fn remaining_bits(&self) -> u64 {
        let total = (self.bytes.len() as u64).saturating_mul(8);
        total.saturating_sub(self.bit as u64)
    }

    fn read_bit(&mut self) -> Result<bool, CodecError> {
        let byte_i = self.bit / 8;
        if byte_i >= self.bytes.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let bit_i = self.bit % 8;
        let b = (self.bytes[byte_i] >> bit_i) & 1;
        self.bit += 1;
        Ok(b == 1)
    }

    fn read_bits_u64(&mut self, n: usize) -> Result<u64, CodecError> {
        if n > 64 {
            return Err(CodecError::AtomTooLarge);
        }
        let mut out = 0u64;
        for i in 0..n {
            if self.read_bit()? {
                out |= 1u64 << i;
            }
        }
        Ok(out)
    }
}

fn get_size(reader: &mut BitReader<'_>) -> Result<u64, CodecError> {
    let mut zeros = 0u32;
    loop {
        let b = reader.read_bit()?;
        if b {
            break;
        }
        zeros += 1;
        if zeros > 64 {
            return Err(CodecError::InvalidEncoding);
        }
    }
    if zeros == 0 {
        return Ok(0);
    }
    let low = reader.read_bits_u64((zeros - 1) as usize)?;
    // `zeros` is at most 64, so `zeros - 1` is at most 63 and the shift is
    // well-defined for u64 on every target (including 32-bit ESP32 where a
    // `usize` shift of 63 would overflow).
    let high = 1u64
        .checked_shl(zeros - 1)
        .ok_or(CodecError::AtomTooLarge)?;
    high.checked_add(low).ok_or(CodecError::AtomTooLarge)
}

fn rub_backref(reader: &mut BitReader<'_>) -> Result<u64, CodecError> {
    let size = get_size(reader)?;
    if size == 0 {
        return Ok(0);
    }
    if size > 64 {
        return Err(CodecError::InvalidBackref);
    }
    reader.read_bits_u64(size as usize)
}

fn met0_u64(x: u64) -> usize {
    if x == 0 {
        0
    } else {
        64 - (x.leading_zeros() as usize)
    }
}

fn lookup_backref(backrefs: &[(u64, Noun)], key: u64) -> Option<Noun> {
    backrefs
        .binary_search_by(|(k, _)| k.cmp(&key))
        .ok()
        .map(|idx| backrefs[idx].1)
}

enum Slot {
    Root,
    Head(CellId),
    Tail(CellId),
    Complete(u64, Noun),
}

/// Decode a jammed noun (little-endian bytes, LSB-first bits) into an in-memory noun tree.
pub fn cue(bytes: &[u8], arena: &mut Arena) -> Result<Noun, CodecError> {
    let mut reader = BitReader::new(bytes);
    let mut backrefs: Vec<(u64, Noun)> = Vec::new();
    let mut root: Option<Noun> = None;

    let mut stack: Vec<Slot> = Vec::new();
    stack.push(Slot::Root);

    while let Some(slot) = stack.pop() {
        if let Slot::Complete(position, noun) = slot {
            let index = backrefs
                .binary_search_by_key(&position, |entry| entry.0)
                .unwrap_err();
            backrefs.insert(index, (position, noun));
            continue;
        }
        let start = reader.pos();
        let first = reader.read_bit()?;
        if !first {
            let size = get_size(&mut reader)?;
            let noun = if size == 0 {
                arena.atom0()
            } else {
                // Never allocate based on an unchecked size header: the atom
                // bits must actually be present in the remaining input.
                if size > reader.remaining_bits() {
                    return Err(CodecError::UnexpectedEof);
                }
                let nbytes = (size + 7) / 8;
                let nbytes = usize::try_from(nbytes).map_err(|_| CodecError::AtomTooLarge)?;
                let off = arena.atom_data.len();
                let new_len = off.checked_add(nbytes).ok_or(CodecError::AtomTooLarge)?;
                // `size <= remaining_bits` bounds the allocation by the input
                // size; `try_reserve` still reports allocation failure instead
                // of aborting on tiny targets.
                arena
                    .atom_data
                    .try_reserve(nbytes)
                    .map_err(|_| CodecError::AtomTooLarge)?;
                arena.atom_data.resize(new_len, 0u8);
                for i in 0..size {
                    if reader.read_bit()? {
                        let byte_i = (i / 8) as usize;
                        arena.atom_data[off + byte_i] |= 1u8 << (i % 8);
                    }
                }
                let id = arena.push_atom_slice(off as u32, nbytes as u32);
                Noun::Atom(id)
            };
            backrefs.push((start, noun));
            match slot {
                Slot::Root => root = Some(noun),
                Slot::Head(id) => arena.cell_mut(id).head = noun,
                Slot::Tail(id) => arena.cell_mut(id).tail = noun,
                Slot::Complete(_, _) => unreachable!(),
            }
            continue;
        }

        let second = reader.read_bit()?;
        if second {
            let backref = rub_backref(&mut reader)?;
            let noun = lookup_backref(&backrefs, backref).ok_or(CodecError::InvalidBackref)?;
            match slot {
                Slot::Root => root = Some(noun),
                Slot::Head(id) => arena.cell_mut(id).head = noun,
                Slot::Tail(id) => arena.cell_mut(id).tail = noun,
                Slot::Complete(_, _) => unreachable!(),
            }
            continue;
        }

        // cell (10)
        let cell_noun = arena.alloc_cell(arena.atom0(), arena.atom0());
        match slot {
            Slot::Root => root = Some(cell_noun),
            Slot::Head(id) => arena.cell_mut(id).head = cell_noun,
            Slot::Tail(id) => arena.cell_mut(id).tail = cell_noun,
            Slot::Complete(_, _) => unreachable!(),
        }
        let Noun::Cell(cell_id) = cell_noun else {
            unreachable!();
        };

        // Decode head then tail; stack is LIFO so push tail first.
        stack.push(Slot::Complete(start, cell_noun));
        stack.push(Slot::Tail(cell_id));
        stack.push(Slot::Head(cell_id));
    }

    root.ok_or(CodecError::InvalidEncoding)
}

struct BitWriter {
    bytes: Vec<u8>,
    bit: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        let byte_i = self.bit / 8;
        if byte_i == self.bytes.len() {
            self.bytes.push(0);
        }
        let bit_i = self.bit % 8;
        if bit {
            self.bytes[byte_i] |= 1u8 << bit_i;
        }
        self.bit += 1;
    }

    fn write_bits_u64(&mut self, mut value: u64, n: usize) {
        for _ in 0..n {
            self.write_bit((value & 1) == 1);
            value >>= 1;
        }
    }
}

fn met0_bytes(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let last = bytes[bytes.len() - 1];
    let bits = 8 - (last.leading_zeros() as usize);
    (bytes.len() - 1) * 8 + bits
}

fn mat(writer: &mut BitWriter, atom_bits: usize, atom_bytes: &[u8]) -> Result<(), CodecError> {
    let b_atom_size = atom_bits;
    if b_atom_size == 0 {
        writer.write_bit(true);
        return Ok(());
    }

    let b_atom_size_atom: u64 = b_atom_size
        .try_into()
        .map_err(|_| CodecError::AtomTooLarge)?;
    let c_b_size = met0_u64(b_atom_size_atom);

    // c_b_size zeros, then a 1
    for _ in 0..c_b_size {
        writer.write_bit(false);
    }
    writer.write_bit(true);

    // size bits (excluding MSB)
    if c_b_size > 1 {
        writer.write_bits_u64(b_atom_size_atom, c_b_size - 1);
    }

    // atom bits
    for i in 0..b_atom_size {
        let bit = (atom_bytes[i / 8] >> (i % 8)) & 1;
        writer.write_bit(bit == 1);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Value<'a> {
    Atom(&'a [u8]),
    Cell(usize, usize),
}

fn noun_key(noun: Noun) -> (bool, u32) {
    match noun {
        Noun::Atom(id) => (false, id.0),
        Noun::Cell(id) => (true, id.0),
    }
}

/// Assign equal nouns the same ID, independently of arena allocation and sharing.
fn intern(noun: Noun, arena: &Arena) -> Result<(usize, Vec<Value<'_>>), CodecError> {
    let mut ids = BTreeMap::new();
    let mut values = Vec::new();
    let mut interned = BTreeMap::new();
    let mut active = BTreeSet::new();
    let mut pending = alloc::vec![(noun, false)];
    while let Some((current, visited)) = pending.pop() {
        let key = noun_key(current);
        if ids.contains_key(&key) {
            continue;
        }
        let value = match current {
            Noun::Atom(id) => Value::Atom(arena.atom_bytes_trimmed(id)),
            Noun::Cell(id) => {
                let cell = arena.cell(id);
                if !visited {
                    if !active.insert(key) {
                        return Err(CodecError::InvalidEncoding);
                    }
                    pending.extend([(current, true), (cell.tail, false), (cell.head, false)]);
                    continue;
                }
                active.remove(&key);
                Value::Cell(ids[&noun_key(cell.head)], ids[&noun_key(cell.tail)])
            }
        };
        let next = values.len();
        let id = *interned.entry(value).or_insert(next);
        if id == next {
            values.push(value);
        }
        ids.insert(key, id);
    }
    Ok((ids[&noun_key(noun)], values))
}

fn jam_noun(writer: &mut BitWriter, arena: &Arena, noun: Noun) -> Result<(), CodecError> {
    let (root, values) = intern(noun, arena)?;
    let mut backrefs = BTreeMap::<usize, u64>::new();
    let mut pending = alloc::vec![root];
    while let Some(id) = pending.pop() {
        if let Some(&position) = backrefs.get(&id) {
            let use_backref = match values[id] {
                Value::Cell(_, _) => true,
                Value::Atom(bytes) => met0_bytes(bytes) > met0_u64(position),
            };
            if use_backref {
                writer.write_bit(true);
                writer.write_bit(true);
                mat(writer, met0_u64(position), &position.to_le_bytes())?;
                continue;
            }
        } else {
            backrefs.insert(id, writer.bit as u64);
        }
        match values[id] {
            Value::Atom(bytes) => {
                writer.write_bit(false);
                mat(writer, met0_bytes(bytes), bytes)?;
            }
            Value::Cell(head, tail) => {
                writer.write_bit(true);
                writer.write_bit(false);
                pending.extend([tail, head]);
            }
        }
    }
    Ok(())
}

/// Encode a finite noun as canonical JAM, using the first occurrence for backreferences.
pub fn jam(noun: Noun, arena: &Arena) -> Vec<u8> {
    let mut writer = BitWriter::new();
    jam_noun(&mut writer, arena, noun).expect("JAM requires a finite noun");
    writer.bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cue_rejects_empty_input_without_panicking() {
        let mut arena = Arena::new();
        assert!(matches!(
            cue(&[], &mut arena),
            Err(CodecError::UnexpectedEof)
        ));
    }

    #[test]
    fn cue_rejects_size_larger_than_remaining_bits() {
        // Atom tag (0), then a size header claiming 1024 atom bits, then EOF.
        let mut writer = BitWriter::new();
        writer.write_bit(false); // atom
        for _ in 0..11 {
            writer.write_bit(false); // met0(1024) == 11
        }
        writer.write_bit(true);
        for _ in 0..10 {
            writer.write_bit(false); // low size bits
        }

        let mut arena = Arena::new();
        assert!(matches!(
            cue(&writer.bytes, &mut arena),
            Err(CodecError::UnexpectedEof)
        ));
    }

    #[test]
    fn cue_rejects_oversized_atom_header_before_allocating() {
        // Header claims ~2^32 bits; the decoder must reject it before any
        // multi-gigabyte allocation.
        let mut writer = BitWriter::new();
        writer.write_bit(false);
        for _ in 0..33 {
            writer.write_bit(false);
        }
        writer.write_bit(true);

        let mut arena = Arena::new();
        let err = cue(&writer.bytes, &mut arena).unwrap_err();
        assert!(matches!(
            err,
            CodecError::UnexpectedEof | CodecError::AtomTooLarge
        ));
        assert!(arena.atom_data.len() < 1024);
    }

    #[test]
    fn cue_round_trips_atoms_and_cells() {
        let mut arena = Arena::new();
        let atom = arena.alloc_atom_u64(42);
        let bytes_atom = arena.alloc_atom_bytes(b"hello");
        let cell = arena.alloc_cell(atom, bytes_atom);
        let encoded = jam(cell, &arena);

        let mut decoded_arena = Arena::new();
        let decoded = cue(&encoded, &mut decoded_arena).expect("valid jam must cue");
        let Noun::Cell(id) = decoded else {
            panic!("expected cell");
        };
        let cell = decoded_arena.cell(id);
        assert_eq!(
            decoded_arena.atom_u64(match cell.head {
                Noun::Atom(a) => a,
                _ => panic!("expected atom head"),
            }),
            Some(42)
        );
    }

    #[test]
    fn cue_rejects_a_backreference_to_an_incomplete_cell() {
        let mut arena = Arena::new();
        assert!(matches!(
            cue(&[0xf1, 0x01], &mut arena),
            Err(CodecError::InvalidBackref)
        ));
    }

    #[test]
    fn equal_cells_use_the_same_backreference_without_shared_allocation() {
        let mut arena = Arena::new();
        let a = arena.alloc_atom_u64(123456);
        let b = arena.alloc_atom_u64(789012);
        let first = arena.alloc_cell(a, b);
        let shared = arena.alloc_cell(first, first);
        let a = arena.alloc_atom_u64(123456);
        let b = arena.alloc_atom_u64(789012);
        let second = arena.alloc_cell(a, b);
        let distinct = arena.alloc_cell(first, second);
        assert_eq!(jam(shared, &arena), jam(distinct, &arena));
        let encoded = jam(distinct, &arena);
        let mut decoded = Arena::new();
        let value = cue(&encoded, &mut decoded).unwrap();
        assert_eq!(jam(value, &decoded), encoded);
    }
}
