# NockVM Safe-to-Delete Files List

Based on thorough analysis of tx-types and its dependencies, here are the files and directories that can be safely deleted from the nockvm crate.

## Summary of What's Actually Used

tx-types and its dependencies only use:
- **Core noun types**: Noun, Atom, Cell, DirectAtom, IndirectAtom, NounAllocator, D, T, YES, NO, NONE, DIRECT_MAX
- **Memory management**: NockStack
- **Serialization**: jam, cue, met0_u64_to_usize, met0_usize
- **Mug hashing**: calc_atom_mug_u32, calc_cell_mug_u32, get_mug, set_mug
- **Interpreter**: Context, interpret (used by nockapp and zkvm-jetpack)
- **Jets utilities**: JetErr, Result, specific utility functions from bits, list, math, sort modules
- **Unifying equality**: unifying_equality function
- **HAMT**: Used internally
- **Site**: Used for jet caching

## Files and Directories Safe to Delete

### 1. Subject Knowledge (Hoon files)
```
nockchain-core/crates/nockvm/subject-knowledge/
├── gen/
│   ├── wash.hoon
│   └── pull.hoon
└── lib/
    └── subject-knowledge.hoon
```
**Reason**: These are Hoon source files not used by Rust code.

### 2. Trace Module (Complete directory)
```
nockchain-core/crates/nockvm/rust/nockvm/src/trace/
├── filter.rs
├── json.rs
├── mod.rs
└── tracing_backend.rs
```
**Reason**: No imports of `trace::` found anywhere in tx-types or dependencies.

### 3. Substantive Module (Complete directory)
```
nockchain-core/crates/nockvm/rust/nockvm/src/substantive/
├── convert.rs
└── mod.rs
```
**Reason**: No imports of `substantive::` found anywhere in tx-types or dependencies.

### 4. Flog Module
```
nockchain-core/crates/nockvm/rust/nockvm/src/flog.rs
```
**Reason**: Not imported anywhere in tx-types or dependencies.

### 5. Unused Jets Modules

The following jets modules are completely unused:
```
nockchain-core/crates/nockvm/rust/nockvm/src/jets/
├── cold.rs     # Not imported anywhere
├── form.rs     # Not imported anywhere  
├── hash.rs     # Not imported anywhere
├── hot.rs      # Not imported anywhere
├── lock.rs     # Already emptied of crypto jets
├── lute.rs     # Not imported anywhere
├── nock.rs     # Not imported anywhere
├── parse.rs    # Not imported anywhere
├── serial.rs   # Not imported anywhere
├── tree.rs     # Not imported anywhere
└── warm.rs     # Not imported anywhere
```

**Note**: Keep these jets modules as they ARE used:
- `bits.rs` - Used for rep, rip, lsh utilities
- `list.rs` - Used for flop, lent, weld, zing, reap, snip utilities
- `math.rs` - Used for add utility
- `sort.rs` - Used for gor utility

### 6. Lock Directory (Already mostly empty)
```
nockchain-core/crates/nockvm/rust/nockvm/src/jets/lock/
```
**Reason**: Already removed crypto jets; directory can be fully deleted if lock.rs is removed.

### 7. ibig Integration Tests
```
nockchain-core/crates/nockvm/rust/ibig/integration-tests-renamed-for-nonexecution/
```
**Reason**: Test files not executed, already renamed to prevent execution.

### 8. ibig Dev Tools
```
nockchain-core/crates/nockvm/rust/ibig/dev-tools/
```
**Reason**: Development utilities not needed for compilation or runtime.

### 9. Nix Configuration
```
nockchain-core/crates/nockvm/rust/nix/
```
**Reason**: Nix build configuration not used in Cargo builds.

### 10. NockVM Macros (if not used)
```
nockchain-core/crates/nockvm/rust/nockvm_macros/
```
**Reason**: Check if any macros are actually used. If not, entire crate can be removed.

## Files that MUST BE KEPT

### Core Functionality (Required)
- `nockchain-core/crates/nockvm/rust/nockvm/src/noun.rs` - Core noun types
- `nockchain-core/crates/nockvm/rust/nockvm/src/mem.rs` - NockStack
- `nockchain-core/crates/nockvm/rust/nockvm/src/serialization.rs` - jam/cue
- `nockchain-core/crates/nockvm/rust/nockvm/src/mug.rs` - Mug hashing
- `nockchain-core/crates/nockvm/rust/nockvm/src/interpreter.rs` - Interpreter/Context
- `nockchain-core/crates/nockvm/rust/nockvm/src/jets.rs` - Main jets module
- `nockchain-core/crates/nockvm/rust/nockvm/src/unifying_equality.rs` - Equality function
- `nockchain-core/crates/nockvm/rust/nockvm/src/hamt.rs` - Used internally
- `nockchain-core/crates/nockvm/rust/nockvm/src/site.rs` - Jet caching
- `nockchain-core/crates/nockvm/rust/nockvm/src/lib.rs` - Module exports

### Used Jets Modules
- `nockchain-core/crates/nockvm/rust/nockvm/src/jets/bits.rs`
- `nockchain-core/crates/nockvm/rust/nockvm/src/jets/list.rs`
- `nockchain-core/crates/nockvm/rust/nockvm/src/jets/math.rs`
- `nockchain-core/crates/nockvm/rust/nockvm/src/jets/sort.rs`

### ibig (Modified for WASM)
Keep entire ibig crate as it's been heavily modified for WASM compatibility.

## Recommended Deletion Order

1. First delete directories with no dependencies:
   - subject-knowledge/
   - trace/
   - substantive/
   - nix/
   - ibig dev-tools and tests

2. Then delete unused jets:
   - Individual unused jets files
   - lock/ directory

3. Finally delete standalone files:
   - flog.rs

4. After deletion, update lib.rs to remove module declarations for deleted modules.

## Estimated Space Savings

- Subject knowledge: ~10KB
- Trace module: ~20KB
- Unused jets: ~200KB
- Other files: ~50KB

Total: ~280KB of source code removed

## Testing After Deletion

After deleting these files:
1. Run `cargo build` to ensure compilation succeeds
2. Run `cargo test` to ensure all tests pass
3. Run `cargo build --target wasm32-unknown-unknown` to ensure WASM compilation still works