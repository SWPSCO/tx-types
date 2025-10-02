# Nockchain Dependency Version

## Current Version

This project uses nockchain dependencies from git revision: **e2d96bc8421b724ca84c4e93aad6e97ee9b7f4ad** (committed August 8, 2025)

## CAN We Update to Master? YES! (Updated Analysis)

**Previous assessment was INCORRECT.** The zkvm-jetpack code was not removed - it was **reorganized into a new crate**.

### What Really Happened in Master (865a6f7)

The nockchain team **refactored** zkvm-jetpack to extract mathematical functions into a new standalone crate called **nockchain-math**. This is a common Rust pattern for improving modularity and reusability.

#### Architecture Before (e2d96bc)
```
zkvm-jetpack/
  └── form/
      ├── poly.rs         → Belt type defined here
      ├── belt.rs
      ├── felt.rs
      ├── mary.rs
      └── math/
          ├── base.rs     → bneg() function
          └── bpoly.rs    → bpegcd(), bpscal() functions
```

#### Architecture After (865a6f7)
```
zkvm-jetpack/
  └── form/
      └── math/
          └── mod.rs      → pub use nockchain_math::{belt, bpoly, ...}

nockchain-math/          ← NEW STANDALONE CRATE
  ├── belt.rs            → Belt type + bneg() moved here
  ├── bpoly.rs           → bpegcd(), bpscal() moved here
  ├── poly.rs
  └── ... (other math modules)
```

**Key insight:** zkvm-jetpack still re-exports everything from nockchain-math, so the functions ARE available through zkvm-jetpack, just at different import paths.

## Breaking Changes (Both are Fixable)

### 1. NounDecode Trait Signature Change (Easy Fix)

**Current version (e2d96bc):**
```rust
trait NounDecode {
    fn from_noun<A: NounAllocator>(allocator: &mut A, noun: &Noun) -> Result<Self, NounDecodeError>;
}
```

**Master version (865a6f7):**
```rust
trait NounDecode {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError>;
}
```

**Migration:** Remove allocator parameter from all implementations and call sites (already attempted, straightforward).

### 2. zkvm-jetpack Import Path Changes (Easy Fix)

The code still exists, just at different paths.

**Our current imports (work with e2d96bc):**
```rust
use zkvm_jetpack::form::poly::Belt;
use zkvm_jetpack::form::math::base::bneg;
use zkvm_jetpack::form::math::bpoly::{bpegcd, bpscal};
```

**Required new imports (for 865a6f7):**
```rust
// Option 1: Through zkvm-jetpack's re-exports
use zkvm_jetpack::form::math::belt::Belt;
use zkvm_jetpack::form::math::belt::bneg;
use zkvm_jetpack::form::math::bpoly::{bpegcd, bpscal};

// Option 2: Direct from nockchain-math (if we add it to workspace)
use nockchain_math::belt::Belt;
use nockchain_math::belt::bneg;
use nockchain_math::bpoly::{bpegcd, bpscal};
```

**Files that need import updates:**
- `tx-types/src/crypto/cheetah/point.rs:3`
- `tx-types/src/crypto/cheetah/constants.rs:3`
- `tx-types/src/crypto/cheetah/field.rs:2-4`

## What We Need (All Functions Still Exist!)

### Belt Type
- **Old location:** `zkvm_jetpack::form::poly::Belt`
- **New location:** `nockchain_math::belt::Belt` (re-exported via `zkvm_jetpack::form::math::belt`)
- **Status:** ✅ Still exists, same definition

### bneg() Function
- **Old location:** `zkvm_jetpack::form::math::base::bneg`
- **New location:** `nockchain_math::belt::bneg` (re-exported via `zkvm_jetpack::form::math::belt`)
- **Signature:** `pub fn bneg(a: u64) -> u64`
- **Status:** ✅ Still exists, same API

### bpegcd() Function
- **Old location:** `zkvm_jetpack::form::math::bpoly::bpegcd`
- **New location:** `nockchain_math::bpoly::bpegcd` (re-exported via `zkvm_jetpack::form::math::bpoly`)
- **Signature:** `pub fn bpegcd(a: &[Belt], b: &[Belt], d: &mut [Belt], u: &mut [Belt], v: &mut [Belt])`
- **Status:** ✅ Still exists, same API

### bpscal() Function
- **Old location:** `zkvm_jetpack::form::math::bpoly::bpscal`
- **New location:** `nockchain_math::bpoly::bpscal` (re-exported via `zkvm_jetpack::form::math::bpoly`)
- **Signature:** `pub fn bpscal(scalar: Belt, b: &[Belt], res: &mut [Belt])`
- **Status:** ✅ Still exists, same API

## Benefits of Upgrading

1. **Simplified NounDecode API** - No more allocator parameter
2. **ibig memory leak fix** - Should resolve our test_derivation_path failure
3. **Faster proof verification** - eval_composition_poly jet optimization
4. **Improved Schnorr verification speed**
5. **30+ commits** of performance improvements and bug fixes
6. **Better code organization** - Math functions in dedicated crate

## Migration Path

### Step 1: Add nockchain-math to Workspace (if using direct imports)

If we want to import directly from nockchain-math rather than through zkvm-jetpack re-exports:

```toml
# In Cargo.toml [workspace.dependencies]
nockchain-math = { git = "https://github.com/SWPSCO/nockchain.git", rev = "865a6f7..." }
```

### Step 2: Update Import Paths

Update 3 files with new import paths:

**tx-types/src/crypto/cheetah/field.rs:**
```rust
// Old
use zkvm_jetpack::form::poly::Belt;
use zkvm_jetpack::form::math::base::bneg;
use zkvm_jetpack::form::math::bpoly::{bpegcd, bpscal};

// New (Option 1: via zkvm-jetpack re-exports)
use zkvm_jetpack::form::math::belt::Belt;
use zkvm_jetpack::form::math::belt::bneg;
use zkvm_jetpack::form::math::bpoly::{bpegcd, bpscal};

// New (Option 2: direct from nockchain-math)
use nockchain_math::belt::{Belt, bneg};
use nockchain_math::bpoly::{bpegcd, bpscal};
```

**tx-types/src/crypto/cheetah/point.rs & constants.rs:**
```rust
// Old
use zkvm_jetpack::form::poly::Belt;

// New
use zkvm_jetpack::form::math::belt::Belt;
// or
use nockchain_math::belt::Belt;
```

### Step 3: Update NounDecode Implementations

Remove allocator parameter (already attempted in previous migration):
- Remove `<A: NounAllocator>(allocator: &mut A, ...)` → `(noun: &Noun)`
- Remove allocator from all `from_noun()` call sites
- Files: transaction_types.rs, zmap.rs, zset.rs, signer.rs

### Step 4: Update Cargo.toml

```toml
[workspace.dependencies]
# Update all nockchain dependencies to master
noun-serde = { git = "https://github.com/SWPSCO/nockchain.git", rev = "865a6f70b0bb8c44989839f19b288587c5c37b17" }
nockvm = { git = "https://github.com/SWPSCO/nockchain.git", rev = "865a6f70b0bb8c44989839f19b288587c5c37b17" }
zkvm-jetpack = { git = "https://github.com/SWPSCO/nockchain.git", rev = "865a6f70b0bb8c44989839f19b288587c5c37b17" }
# ... (all other nockchain deps)

# Optional: Add nockchain-math for direct imports
nockchain-math = { git = "https://github.com/SWPSCO/nockchain.git", rev = "865a6f70b0bb8c44989839f19b288587c5c37b17" }
```

### Step 5: Verify Tests

- Unignore test_derivation_path (should be fixed by ibig improvements)
- Run full test suite
- Verify Cheetah curve crypto still works

## Current Known Issues

### test_derivation_path Failure

Currently marked as `#[ignore]` due to ibig buffer overflow in multi-level BIP-44 paths:

```
assertion failed: self.len() < self.capacity() at buffer.rs:109
```

**Expected resolution:** Master branch includes ibig memory leak fix that should resolve this issue.

## Recommendations

1. **DO attempt migration to master (865a6f7)** - It's simpler than originally thought
2. **Use Option 1 (zkvm-jetpack re-exports)** to minimize dependencies
3. **Test thoroughly** - Especially Cheetah curve operations and key derivation
4. **Verify test_derivation_path passes** after upgrade

## Commit References

- **Current revision:** e2d96bc8421b724ca84c4e93aad6e97ee9b7f4ad (August 8, 2025)
- **Target revision:** 865a6f70b0bb8c44989839f19b288587c5c37b17 (latest master)
- **Changes between:** ~30 commits with refactoring and performance improvements

## Technical Details: How Our Cheetah Crypto Uses These Functions

Our F^6 extension field implementation (`crypto/cheetah/field.rs`) uses:

1. **Belt:** Field element type representing u64 values modulo PRIME (18446744069414584321)
   - Used as base type for F6Element: `pub struct F6Element(pub [Belt; 6]);`
   - Supports arithmetic: `+`, `-`, `*`, `/`, negation, inversion

2. **bneg(a: u64):** Field negation - returns `PRIME - a` for non-zero values
   - Used in F6Element::neg() via Belt's Neg trait implementation

3. **bpegcd():** Extended Euclidean algorithm for polynomials
   - Used in F6Element::invert() to compute multiplicative inverse
   - Computes GCD with reduction polynomial x^6 - 7
   - Returns Bézout coefficients needed for inversion

4. **bpscal():** Polynomial scalar multiplication
   - Used in F6Element::invert() to scale the result by inverse of GCD
   - Multiplies each polynomial coefficient by a scalar field element

All these functions remain available in master, just at different import paths.
