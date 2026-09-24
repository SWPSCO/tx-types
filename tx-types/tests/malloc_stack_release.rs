#![cfg(feature = "std")]

use nockvm::mem::Memory;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

const STACK_WORDS: usize = 1 << 20;
const STACK_BYTES: usize = STACK_WORDS * 8;
static LIVE_STACKS: AtomicUsize = AtomicUsize::new(0);
struct TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && layout.size() == STACK_BYTES {
            LIVE_STACKS.fetch_add(1, Ordering::SeqCst);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == STACK_BYTES {
            LIVE_STACKS.fetch_sub(1, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[test]
fn temporary_malloc_stacks_release_their_owned_allocation() {
    let baseline = LIVE_STACKS.load(Ordering::SeqCst);
    for _ in 0..32 {
        let layout = Layout::from_size_align(STACK_BYTES, align_of::<u64>()).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };
        assert!(!ptr.is_null());
        let memory = Memory::Malloc(ptr, STACK_WORDS);
        assert_eq!(LIVE_STACKS.load(Ordering::SeqCst), baseline + 1);
        drop(memory);
        assert_eq!(LIVE_STACKS.load(Ordering::SeqCst), baseline);
    }
}
