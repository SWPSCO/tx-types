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

## Vanity address library

The `tx_types::crypto::vanity` module mines Nockchain public-key hash prefixes.
The example CLI in `examples/vanity-pkh` searches a case-sensitive prefix:

```sh
cargo run --release -p vanity-pkh -- nock --output ./nock-key.json
```

Use `--threads 8` to select the worker count and `--max-attempts 1000000` to
bound the total search. The default uses all available CPU workers. Prefixes
use the Base58 alphabet, which excludes `0`, `O`, `I`, and `l` in exact mode.
Each additional exact character usually multiplies the work by about 58; the
distribution of the first character depends on the integer encoding.

Use `--insensitive` to ignore ASCII case and accept letter/digit alternatives:

```sh
cargo run --release -p vanity-pkh -- Reid --insensitive --output ./reid-key.json
```

The pairs are `a/4`, `b/8`, `e/3`, `i/1`, `l/1`, `o/0`, `s/5`, `t/7`, and
`z/2`. The letters `i/I` and `l/L` remain distinct: an `I` prefix matches `i`
or `1`, **never capital `L`**. A typed `1` can match `1`, `i`, or `L`.
The browser library uses the same matching rules. Resulting addresses always use
canonical Base58; alternatives affect matching only.

The default searches 256-bit entropy values and produces a 24-word English
BIP39 mnemonic. Every candidate follows BIP39 seed derivation with an empty
passphrase, then the shared SLIP-10-over-Cheetah master derivation. Restore the
phrase in Nockster at path `m`, with an empty passphrase, to recover the matching
address. The tests pin this behavior to a `nockchain-wallet` mnemonic/address
vector in Nockster.

The program prints only the matching PKH to stdout and progress to stderr. Its
private JSON contains `mnemonic`, `derivation_path` (`m`), `passphrase` (`""`),
`pkh`, `public_key_base58`, `secret_key_hex_be` (a 32-byte big-endian scalar), and
`secret_key_base58` (Base58 of those same 32 bytes). Keep this file private and
backed up. Restore using the phrase; the JSON itself is not a wallet import file.

Use `--raw-key` to search raw private scalars. This is faster because candidates
advance by curve addition instead of repeating BIP39 and master-key derivation.
Raw-key exports omit the mnemonic and its derivation settings; a wallet seed
phrase cannot be recovered from a raw scalar.

The output path must not exist. It is reserved before mining, with mode `0600`
on Unix, and remains empty if the search ends without a match. Exit status is
`0` for success, `2` for reaching the attempt limit, and `1` for an error. Ctrl-C
stops the process; there is no checkpoint file. Each run uses fresh OS entropy
and saves one match.

### Browser: WebGPU and WASM

The reusable browser runtime lives in `tx-types/vanity/browser`, with a thin
WASM bridge in `tx-types/vanity/wasm`. Both mnemonic and raw-key modes select
WebGPU when a device is available and otherwise use the shared `no_std` core
through WASM on CPU. The native CLI uses CPU workers. GPU compilation or
verification errors stop the search.

Build the browser assets into a host application's static directory:

```sh
rustup target add wasm32-unknown-unknown
python3 tx-types/vanity/build-browser.py --out-dir ../my-app/public/vendor/vanity
```

The builder compiles the Rust WASM module, copies the JavaScript runtime and
WGSL shaders, derives shader constants from Rust source, and generates the
public fixed-base curve table with the Rust curve implementation. The runtime
has no DOM, framework, npm, CDN, remote service, or key-upload dependency. Serve
its assets over HTTPS or localhost.

The Nockster page and browser integration tests live in the
[nockster.com repository](https://github.com/SWPSCO/nockster.com). Its build
consumes this library; page markup and styling belong to the host application.

WebCrypto supplies random entropy to WASM. In mnemonic mode, WASM encodes each
entropy value as a BIP39 phrase and prepares the HMAC key block. The GPU performs
all 2048 PBKDF2 rounds, SLIP-10 master derivation, fixed-base scalar multiplication,
PKH hashing, and prefix matching. Scalar multiplication uses a four-bit generator
table and Jacobian mixed additions, requiring only one final extension-field
inversion. PBKDF2 runs in sixteen bounded passes after its initial round.

Mnemonic GPU buffers contain private HMAC key material and derived keys. They
stay on the local device, and the input and intermediate buffers are cleared in
queue order after every batch. Temporary host input copies are erased after
upload. WASM retains the entropy needed to re-derive a winning phrase and
independently verifies its address before export.

In raw-key mode, WASM retains private scalars and uploads only public points to
WebGPU. That shader advances curve points, hashes PKHs, and tests prefixes.
Both modes use portable `u32` pairs for 64-bit arithmetic and shared Rust prefix
masks. Device self-tests compare GPU results with Rust before production entropy
is generated. Compilation and parity failures stop the search.

The browser runs bounded batches in a Web Worker and stops on device loss or a
verification failure. Each raw-key lane reserves at most `u32::MAX` candidate offsets
below the curve order. Raw-key CPU walks use the same bounded offset range.
Mnemonic search increments the entropy and stops before wrapping. There is
no checkpoint. Mnemonic GPU batches use 4,096 lanes by default (configurable
from 1 to 4,096); raw-key batches default to 64 lanes (1 to 256). Smaller batches
reduce latency on slower devices. Throughput depends on the adapter and driver.

### Embed in a wallet or webpage

Import the public `miner.js` API from your generated asset directory:

```js
import { mineAddress } from "/vendor/vanity/miner.js";

const controller = new AbortController();
const result = await mineAddress({
  prefix: "Reid",
  insensitive: true,
  keyMode: "mnemonic", // Default: 24-word phrase, path m, empty passphrase.
  backend: "auto", // Both modes: WebGPU when available, otherwise WASM CPU.
  maxAttempts: 1_000_000, // 0 means unlimited.
  signal: controller.signal,
  onProgress(event) {
    // status, backend selection, or attempts/rate/elapsed time; no private keys.
    updateMiningProgress(event);
  },
});

if (result) {
  // result.pkh is public. result.keyJson contains the private recovery material.
  await savePrivateKey(result.keyJson);
  result.keyJson.fill(0);
}
// Call controller.abort() from your Cancel action. Rejection has name AbortError.
```

The promise returns `null` when the attempt limit is reached. Results contain
`pkh`, `keyJson` (UTF-8 bytes), `attempts`, and `backend`. TypeScript declarations
ship in `miner.d.ts`. Asset overrides are `workerUrl`, `wasmUrl`, `shaderUrls`
(raw-key shaders), `mnemonicShaderUrls`, and `tableUrl` (generator table). Raw
shader order is field, constants, Cheetah, TIP5, encoding, search. Mnemonic shader
order is field, constants, Cheetah, TIP5, encoding, SHA-512, fixed-base, mnemonic.
`lanes` tunes GPU batch size; `steps` applies only to raw-key GPU mining. Neither
affects CPU search. Private results are delivered to your application, with no
automatic downloads or storage.

Native Rust consumers enable mnemonic mining without the convenience CLI:

```toml
[dependencies]
tx-types = { git = "https://github.com/SWPSCO/tx-types", default-features = false, features = ["vanity-mnemonic"] }
```

```rust
use tx_types::crypto::vanity::{MatchMode, MnemonicBatch, MnemonicSearch, Prefix, Zeroizing};

fn start_search(entropy: [u8; 32]) -> MnemonicSearch {
    // Supply 32 bytes from a cryptographic random-number generator.
    MnemonicSearch::new(Zeroizing::new(entropy))
}

fn search_batch(search: &mut MnemonicSearch) -> Result<MnemonicBatch, tx_types::crypto::vanity::Error> {
    let prefix = Prefix::with_mode("Reid", MatchMode::Insensitive)?;
    Ok(search.search_batch(&prefix, 1))
}
```

The Rust library is `no_std` and allocation-free along the search path. The
native CLI uses CPU workers; browser GPU selection belongs to the JavaScript
host and WGSL backend. The `vanity-export` feature adds `key_json` for private
JSON serialization and includes `vanity-mnemonic`. Without optional features,
`tx_types::crypto::vanity` exposes the raw-key `Search` API. The example CLI
is a separate workspace package, invoked with `cargo run -p vanity-pkh`.

### Search core

`tx_types::crypto::vanity` supplies `Prefix`, `Search::new`,
`Search::search_batch`, `pkh_from_public_key`, and `encode_pkh`. The CPU runner
depends on `tx-types` with `default-features = false`. The core always uses
`cheetah_nostd`, including when Cargo unifies features with a `std` consumer.

In raw-key mode, each worker samples an independent nonzero scalar uniformly below the Cheetah
group order. Initialization multiplies the generator by that scalar; each
candidate thereafter takes one affine point addition. The PKH hashes the
public-key noun with TIP5 and encodes the digest as a base-Goldilocks integer
in Base58, using fixed-size buffers throughout. A batch tests a bounded number
of candidates, returns a match and attempt count, and retains the next untested
scalar. It stops at the group order instead of wrapping through zero.

The search path, including initialization and extension-field inversion, uses
no allocator, host entropy, I/O, threads, or noun arena. Other library functions
can use `alloc`. The WebGPU backend implements the arithmetic in WGSL, while
WASM uses these Rust primitives for key generation and verification. Starting
scalars, mnemonic entropy, and search states are secret, since they determine
every private key in their search. Mnemonic search also uses fixed-size buffers
and erases its entropy, phrase, and scalar buffers when dropped.

Run the focused checks with:

```sh
cargo test -p tx-types --no-default-features --features vanity-export
cargo test -p tx-types --features vanity-export --lib
cargo test -p vanity-pkh
cargo test -p vanity-pkh-wasm
```

## License

Licensed under either of

 * Apache License, Version 2.0
 * MIT license

at your option.
