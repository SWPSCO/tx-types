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

## Native GPU runner (Linux)

Install Rust through rustup, Python 3, a C linker, and the NVIDIA driver with
Vulkan support. CUDA and a browser are not required. Cargo uses the repository's
pinned Rust toolchain; Python runs only during the build.

```sh
git clone https://github.com/SWPSCO/tx-types.git
cd tx-types
cargo build --release -p vanity-gpu
./target/release/vanity-gpu --list-gpus
./target/release/vanity-gpu nock --insensitive --output ./nock-key.json
```

The runner selects a discrete GPU by default. `--adapter N` selects an index from
`--list-gpus`. It uses the browser generator's WGSL shaders through Vulkan and
embeds them in the executable. Every run checks the device against independent
Rust results before generating keys; `--self-test` runs that check on its own.

The default output contains a `zprv` with a fresh random chain code and the mined
address at path `m`. There is no seed phrase. `--raw-key` selects a raw scalar
backup. Only the public address reaches stdout. Two lines on stderr refresh in
place: speed, attempts, and elapsed time every 5 seconds, and an estimated average
duration every 30 seconds. Durations use seconds, minutes, hours, or days as
appropriate. Redirected output uses plain log lines. The estimate uses
the measured candidate rate and prefix probability; it is not a countdown.
Backups use mode 0600 on Unix and never overwrite an existing file.

`--lanes` controls independent GPU walks (default 1024), and `--steps` controls
candidates per lane per dispatch (default 16). `--max-attempts N` bounds the total
work exactly, including partial batches. Ctrl+C stops after the current GPU batch.
An interrupted or exhausted search leaves its reserved output file empty; use a
new output path for the next run. Run `--help` for all options and exit codes.

## Command line

```sh
cargo run --release -p vanity-pkh -- Reid --insensitive --output ./my-key.json
```

The CLI in `cli/` defaults to a 24-word seed phrase. `--raw-key` searches faster
and produces a private key without a recovery phrase. Output files contain private
key material and are created without overwriting existing files. Run `--help`
for thread and attempt limits.

Two terminal lines refresh in place: progress every 5 seconds and an estimated
average duration every 30 seconds. Elapsed time uses minutes and hours as needed.
A final summary appears immediately when the search finishes.

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

The browser defaults to `keyMode: "extended"`: it mines at raw-key speed, then
exports a version-1 master `zprv` with a fresh random chain code at path `m`.
The root address remains the mined address; there is no seed phrase. `mnemonic`
searches recoverable 24-word phrases, and `raw` exports a scalar without HD
metadata. Rust callers use `extended_key_json` with their own random chain code.

`expectedVanityAttempts(prefix, insensitive)` accounts for canonical Base58 and
letter/digit matching. Divide it by the measured candidate rate for an estimated
average time, then format it with `formatVanityDuration`. This is an average,
not a deadline or a countdown.

Automatic mode uses WebGPU when available and switches to CPU/WASM if the GPU is
unavailable or cannot compile the shaders. GPU self-test and result-verification
failures stop the search. `backend: "cpu"` skips GPU initialization.

## Validation

```sh
cargo test -p vanity --all-features
cargo test -p vanity-pkh -p vanity-pkh-wasm -p vanity-gpu
cargo test --release -p vanity-gpu --test cli -- --ignored --test-threads=1 # hardware Vulkan GPU
cargo check -p vanity --features mnemonic --lib --target thumbv7em-none-eabihf
node --experimental-default-type=module --test vanity/tests/*.test.mjs
```
