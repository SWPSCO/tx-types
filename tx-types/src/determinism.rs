//! Stable wallet ordering, identical with and without std.
use crate::NName;
use core::cmp::Ordering;

pub fn compare_names(a: &NName, b: &NName) -> Ordering {
    let key = |name: &NName| {
        name.p
            .iter()
            .map(|hash| bs58::encode(hash.to_ubig().to_be_bytes()).into_string())
            .collect::<alloc::vec::Vec<_>>()
    };
    key(a).cmp(&key(b))
}
