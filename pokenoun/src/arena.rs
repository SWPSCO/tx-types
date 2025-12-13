extern crate alloc;

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Noun {
    Atom(AtomId),
    Cell(CellId),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AtomId(pub(crate) u32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CellId(pub(crate) u32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub head: Noun,
    pub tail: Noun,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct AtomSlice {
    off: u32,
    len: u32,
}

#[derive(Debug, Default)]
pub struct Arena {
    atoms: Vec<AtomSlice>,
    pub(crate) atom_data: Vec<u8>,
    cells: Vec<Cell>,
}

impl Arena {
    pub fn new() -> Self {
        // AtomId(0) is always the canonical `0` atom with an empty byte slice.
        let mut atoms = Vec::new();
        atoms.push(AtomSlice { off: 0, len: 0 });
        Self {
            atoms,
            atom_data: Vec::new(),
            cells: Vec::new(),
        }
    }

    #[inline]
    pub fn atom0(&self) -> Noun {
        Noun::Atom(AtomId(0))
    }

    #[inline]
    pub fn atom_bytes(&self, id: AtomId) -> &[u8] {
        let s = self.atoms[id.0 as usize];
        let start = s.off as usize;
        let end = start + (s.len as usize);
        &self.atom_data[start..end]
    }

    #[inline]
    pub fn atom_u64(&self, id: AtomId) -> Option<u64> {
        let bytes = self.atom_bytes(id);
        if bytes.len() > 8 {
            return None;
        }
        let mut out = 0u64;
        for (i, &b) in bytes.iter().enumerate() {
            out |= (b as u64) << (8 * i);
        }
        Some(out)
    }

    #[inline]
    pub fn atom_eq_bytes(&self, id: AtomId, bytes: &[u8]) -> bool {
        self.atom_bytes(id) == bytes
    }

    pub fn alloc_atom_bytes(&mut self, bytes: &[u8]) -> Noun {
        let mut len = bytes.len();
        while len > 0 && bytes[len - 1] == 0 {
            len -= 1;
        }
        if len == 0 {
            return self.atom0();
        }

        let off = self.atom_data.len();
        self.atom_data.extend_from_slice(&bytes[..len]);
        let id = self.atoms.len();
        self.atoms.push(AtomSlice {
            off: off as u32,
            len: len as u32,
        });
        Noun::Atom(AtomId(id as u32))
    }

    pub fn alloc_atom_u64(&mut self, v: u64) -> Noun {
        if v == 0 {
            return self.atom0();
        }
        let bytes = v.to_le_bytes();
        let mut len = 8usize;
        while len > 0 && bytes[len - 1] == 0 {
            len -= 1;
        }
        self.alloc_atom_bytes(&bytes[..len])
    }

    pub fn alloc_cell(&mut self, head: Noun, tail: Noun) -> Noun {
        let id = self.cells.len();
        self.cells.push(Cell { head, tail });
        Noun::Cell(CellId(id as u32))
    }

    pub fn cell(&self, id: CellId) -> &Cell {
        &self.cells[id.0 as usize]
    }

    pub fn cell_mut(&mut self, id: CellId) -> &mut Cell {
        &mut self.cells[id.0 as usize]
    }

    pub(crate) fn push_atom_slice(&mut self, off: u32, len: u32) -> AtomId {
        let id = self.atoms.len();
        self.atoms.push(AtomSlice { off, len });
        AtomId(id as u32)
    }
}

