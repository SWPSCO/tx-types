# Building tx-types

`tx-types` can be built against two different Nockchain runtime sources:

- `embedded` (default): the vendored `nockchain-minimal` crates in this
  repository. Use this for WASM, embedded targets, and offline builds.
- `native`: upstream `SWPSCO/nockchain` at the pinned revision. Use this for
  server-side native builds that already depend on the full runtime.

Both dependency sets are declared in `tx-types/Cargo.toml` and aliased onto the
canonical crate names in `tx-types/src/lib.rs`, so the same source compiles
against either one. No `[patch]` section is needed.

## Feature matrix

| Consumer | Features |
| --- | --- |
| ESP32 / no_std (crypto only) | `default-features = false` |
| WASM wallet (`wasm32-unknown-unknown`) | `default-features = false, features = ["std", "embedded"]` |
| Native server | `default-features = false, features = ["std", "native"]` |

`embedded` and `native` are mutually exclusive, and `std` requires exactly one
of them. Enabling both, or enabling `std` with neither, produces a
`compile_error!`.

`pokenoun` is re-exported in every configuration, including the crypto-only
no_std build.

## Examples

Default (embedded + std):

```bash
cargo build -p tx-types
cargo test -p tx-types --lib
```

WASM (embedded):

```bash
cargo build -p tx-types \
  --no-default-features --features std,embedded \
  --target wasm32-unknown-unknown
```

Native upstream runtime:

```bash
cargo build -p tx-types --no-default-features --features std,native
```

Crypto-only no_std:

```bash
cargo build -p tx-types --no-default-features
cargo build -p tx-types --no-default-features --target thumbv7em-none-eabihf
```
