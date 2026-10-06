# Vanity address mining

The `vanity` crate searches for Nockchain address prefixes using the shared
`tx-types` curve and hash primitives. Its raw-key search and mnemonic derivation
run without heap allocation or `std`. Callers supply cryptographic entropy and
choose how often to yield between search batches.

## Rust library

```toml
[dependencies]
vanity = { git = "https://github.com/SWPSCO/tx-types", features = ["export"] }
```

- The default library provides `Prefix`, `Search`, address encoding, and public-key hashing.
- `mnemonic` adds `MnemonicSearch` and 24-word BIP39 recovery at path `m` with an empty passphrase.
- `export` includes mnemonic support and private JSON serialization.
- `std` enables hosted `tx-types` integration and reference checks.

Secret search state and exported JSON use zeroizing buffers. A raw search walks
consecutive scalars from its secret starting key; give parallel workers independent
random starts and keep those starts private.

## Command line

```sh
cargo run --release -p vanity-pkh -- Reid --insensitive --output ./my-key.json
```

The CLI in `cli/` defaults to a 24-word seed phrase. `--raw-key` searches faster
and produces a private key without a recovery phrase. Output files contain private
key material and are created without overwriting existing files. Run `--help`
for thread and attempt limits.

## Browser library

```sh
rustup target add wasm32-unknown-unknown
python3 vanity/build-browser.py --out-dir ../my-app/public/vendor/vanity
```

Serve the output directory as static assets, then import `mineAddress` from
`miner.js`. The `MineOptions` and result types are described in
[browser/miner.d.ts](browser/miner.d.ts). The worker keeps private search state
in the WASM module built from `wasm/`; GPU matches are checked against Rust before
returning private JSON. Preserve the relative asset paths or supply the documented
URL overrides.

Automatic mode uses WebGPU when available and switches to CPU/WASM if the GPU is
unavailable or cannot compile the shaders. GPU self-test and result-verification
failures stop the search. `backend: "cpu"` skips GPU initialization.

## Validation

```sh
cargo test -p vanity --all-features
cargo test -p vanity-pkh -p vanity-pkh-wasm
cargo check -p vanity --features mnemonic --lib --target thumbv7em-none-eabihf
node --experimental-default-type=module --test vanity/tests/*.test.mjs
```
