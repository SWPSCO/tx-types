# tx-types

Transaction types and utilities for Nockchain.

## Overview

This crate provides core transaction types and serialization utilities for the Nockchain blockchain, including:

- Transaction data structures
- Noun serialization/deserialization
- Hashing utilities (Tip5, transaction IDs)
- Collections (ZMap, ZSet)
- Base58 encoding/decoding
- Schnorr signature support

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tx-types = { git = "https://github.com/SWPSCO/tx-types" }
```

## Shared wallet construction

The pure transaction core runs with `no_std + alloc`. Both runtime backends use
its noun codecs, TIP5 hashes, lock trees, proof builders, note-data normalization,
fee accounting, lock admission, and deterministic planner.

| Module | Responsibility |
| --- | --- |
| `lock` | Tagged 1/2/4/8/16-condition locks, Merkle proofs, authorization siblings, stub-axis admission |
| `note_data` | Canonical lock and bridge payloads, based-atom validation, opaque payload preservation |
| `lock_resolver` | Effective signer selection, disclosed/reconstructed locks, candidate-height timelocks and configured fund maturity |
| `planner` | Candidate ordering, manual selection, exact/minimum fees, refunds, and V0-to-V1 sweeps |
| `word_count`, `fee` | Encoded witness words, merged output note data, activation-dependent fee rates |
| `tx_builder` (`std`) | Software signatures applied to a shared plan |
| `rpc_note_data` (`std`) | RPC JSON converted to the actual on-chain note-data commitment |

Call `planner::plan(PlanRequest { ... }, &matcher)` with notes, outputs, a refund
lock, and explicit chain/fee configuration. The result includes unsigned spends,
selected inputs, refunds, exact signed word estimates, and the required fee.
A `LockMatcher` supplies ownership/unlock context. Consumers own snapshot IO,
key storage, signing transport, and submission. Input notes retain their actual
note data; RPC lock metadata marked `reconstructed` is outside that commitment.

`lock::Lock` is the V1 tree. `transaction_types::Lock` is the V0 signature lock.
Portable noun IO uses `pokenoun::codec::{Encode, Decode}`; `std` adds
`noun-serde` adapters for the selected `embedded` or `native` runtime.

The [reference fixtures](tx-types/tests/reference/) record the official source
pin, generation commands, and byte/hash/fee comparisons. Run the core matrix:

```sh
cargo test -p tx-types --lib
cargo test -p tx-types --no-default-features --lib
cargo build -p tx-types --no-default-features --target thumbv7em-none-eabihf
cargo build -p tx-types --no-default-features --features std,embedded --target wasm32-unknown-unknown
cargo check -p tx-types --no-default-features --features std,native --lib
```

## Vanity addresses

[`vanity`](vanity/) provides allocation-free
`no_std` prefix searches. Enable `mnemonic` for 24-word recovery phrases
or `export` for private JSON output.

For a Linux Vulkan GPU (including NVIDIA), generate a `zprv` with:

```sh
cargo run --release -p vanity-gpu -- Reid --insensitive --output ./my-key.json
```

See the [native GPU setup and options](vanity/#native-gpu-runner-linux).
For CPU generation:

```sh
cargo run --release -p vanity-pkh -- Reid --insensitive --output ./my-key.json
```

The CLI defaults to a seed phrase at path `m` with an empty passphrase.
`--raw-key` searches faster but produces no phrase. Keep the output private;
use `--help` for search options.

Build the reusable WebGPU/WASM browser library:

```sh
rustup target add wasm32-unknown-unknown
python3 vanity/build-browser.py --out-dir ../my-app/public/vendor/vanity
```

It uses WebGPU with automatic CPU fallback. A live deployment lives on
[nockster.com](https://nockster.com/vanity/).

## License

Licensed under either of

 * Apache License, Version 2.0
 * MIT license

at your option.
