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
