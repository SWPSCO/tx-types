pub mod bytes;
pub mod error;

pub use bytes::ToBytes;
pub use error::{CrownError, Result};
use nockvm::noun::{Atom, IndirectAtom, NounAllocator};

pub fn make_tas<A: NounAllocator>(allocator: &mut A, tas: &str) -> Atom {
    let tas_bytes: &[u8] = tas.as_bytes();
    unsafe {
        let mut tas_atom =
            IndirectAtom::new_raw_bytes(allocator, tas_bytes.len(), tas_bytes.as_ptr());
        tas_atom.normalize_as_atom()
    }
}
