use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use tx_types::crypto::cheetah_nostd::cheetah_pub_from_sk;
use tx_types::crypto::vanity::{encode_pkh, pkh_from_public_key, Prefix, Search};
use zeroize::Zeroizing;

struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

fn record_allocation() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(n) = count.get() {
            count.set(Some(n + 1));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        System.realloc(ptr, layout, size)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn initialization_and_search_allocate_nothing() {
    // A full-width starting scalar exercises all scalar-multiplication bits.
    let start = [0x35; 32];
    let mut target = start;
    target[31] += 8;
    let target_public_key = cheetah_pub_from_sk(target);
    let pkh = pkh_from_public_key(&target_public_key);
    let address = encode_pkh(pkh);

    ALLOCATIONS.with(|count| count.set(Some(0)));
    let prefix = Prefix::new(address.as_str()).unwrap();
    let mut search = Search::new(Zeroizing::new(start)).unwrap();
    let result = search.search_batch(&prefix, 10);
    let allocations = ALLOCATIONS.with(|count| count.replace(None).unwrap());

    assert_eq!(allocations, 0);
    assert_eq!(result.attempts, 9);
    let found = result.matched.unwrap();
    assert_eq!(*found.secret_key_be, target);
    assert_eq!(found.public_key, target_public_key);
    assert_eq!(found.pkh, pkh);
}

#[cfg(feature = "vanity-mnemonic")]
#[test]
fn mnemonic_derivation_allocates_nothing() {
    use tx_types::crypto::vanity::MnemonicSearch;
    let prefix = Prefix::new("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap();
    ALLOCATIONS.with(|count| count.set(Some(0)));
    let mut search = MnemonicSearch::new(Zeroizing::new([0x42; 32]));
    let batch = search.search_batch(&prefix, 1);
    let allocations = ALLOCATIONS.with(|count| count.replace(None).unwrap());
    assert_eq!(batch.attempts, 1);
    assert_eq!(allocations, 0);
}
