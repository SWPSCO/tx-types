# Wallet transaction builder migration

Status: design/handoff, not implemented.

Audience: someone who has not worked in this repository. This document explains
what is missing, why it matters, where to look, and how to validate a fix.

## TL;DR

`tx-types` is a partial fork of two upstream things:

1. Nockchain's transaction types and hashing
   (`crates/nockchain-types`).
2. Nockchain's wallet transaction builder utilities
   (`crates/wallet-tx-builder`).

The type/hashing side is present, but simplified. The wallet-builder side is
mostly absent, and the pieces that do exist are not the same algorithm as Hoon.
The highest-risk gap is the lock Merkle proof builder: it does not model the
tagged lock tree, so it cannot produce the proofs required for multi-condition
locks or for the post-170,000 validation rules.

The target is one shared implementation in `tx-types` with as much logic as
possible compiled for both `std` and `no_std`; version and IO differences belong
behind small traits/adapters, not copied modules.

## Repositories and source of truth

Local checkout:

- `~/gits/np/tx-types` — this repository.
- Current HEAD when this was written: `f225b52` ("Wasm space api").
- Feature matrix: `embedded` (vendored `nockchain-minimal`), `native` (upstream
  Nockchain git pin), `std` (serde/JSON/base58/CLI conveniences).
- `embedded` is the default. `native` exists mostly for the RPC server.

Upstream references:

- `~/gits/nockchain`
- Types baseline used by this fork: `73877be29bd1fafeeade1be7b95aebb0f64d8382`.
- Newer consensus baseline: `9bcc26c6` (2026-10-19, "Security batch 3:
  coordinated consensus upgrade at height 170,000").
- Original type crate: `crates/nockchain-types`.
- Original wallet builder: `crates/wallet-tx-builder`.
- Hoon transaction engine: `hoon/common/tx-engine.hoon`,
  `hoon/common/tx-engine-1.hoon`.
- Protocol notes: `changelog/protocol/017-anthropos.md`.

Do not assume the local names match upstream. Local V1 types are in
`src/transaction_types_v1.rs`, while upstream uses
`src/tx_engine/v1/{note.rs,tx.rs,signatures.rs,hashable.rs}`.

## What is already here

- V0/V1 note, seed, spend, input, output and raw-transaction shapes.
- Tip5 hashing and transaction-id helpers.
- `ZMap`/`ZSet` collections.
- Cheetah/Schnorr crypto and signing.
- Fee calculation (simplified but present).
- Noun encode/decode via `noun-serde` plus handwritten encoders.
- A simplified `build_spends`/`create_spends_0`/`create_spends_1`.
- A simplified lock Merkle proof builder.

## What is missing or incomplete

### 1. Tagged lock tree (highest priority)

Local:

- `src/transaction_types_v1.rs`
  - `SpendCondition { p: Vec<LockPrimitive> }`
  - `LockPrimitiveBody::{Pkh, Tim, Hax, Brn}`
  - `MerkleProof { root, path }`

Upstream:

- `crates/nockchain-types/src/tx_engine/v1/tx.rs`
  - `Lock::{SpendCondition, V2(LockV2), V4(LockV4), V8(LockV8), V16(LockV16)}`
  - `LockV2 { p, q }`, `LockV4 { p: LockV2, q: LockV2 }`, etc.
  - `spend_condition_count`, `flatten_spend_conditions`, `Lock::hash`.

Why it matters:

Hoon's `$lock` is not just a list. A note can commit to a single spend
condition or a tagged balanced OR tree (`%2`, `%4`, `%8`, `%16`). A flat
`Vec<LockPrimitive>` cannot represent that tree, so it cannot hash or prove it.

Needed:

- Port the `Lock` tree and its `NounEncode`/`NounDecode`.
- Keep `SpendCondition` as the leaf/list primitive.
- Expose flattening, count, and `hash()` with the same domain/tag rules as
  upstream.
- Preserve V0 compatibility separately; do not force V0 into the V1 tree.

### 2. Lock Merkle proof builder is a stub, not a tree proof

Local:

- `src/block_types.rs`
  - `build_lock_merkle_proof(form, leaf_number, page)`
  - `build_lock_merkle_proof_stub`
  - `build_lock_merkle_proof_full`
  - `prove_hashable_by_index`

Observed behavior:

- `build_lock_merkle_proof_stub` wraps the whole condition in
  `Hashable::Hash(form.to_hash())`, then calls `prove_hashable_by_index`.
  Because that is a single leaf, the resulting axis is `1` and the path is
  empty.
- `build_lock_merkle_proof_full` simply wraps the stub result in the `Full`
  variant. It does not recompute anything over a lock tree.
- The local builder does not implement Hoon's leaf-number adjustment
  (`?^ -.form` -> `+(leaf-number)`) or the `%2/%4/%8/%16` traversal.

Upstream Hoon:

- `hoon/common/tx-engine-1.hoon`
  - `build-lock-merkle-proof-stub`
  - `build-lock-merkle-proof-full`
  - `lock-merkle-proof-stub::check` (requires axis `1`)
  - `lock-merkle-proof-full::check`
  - `authorization-leaf` (final sibling must authenticate the arity tag)

Why it matters:

- A `Full` proof with axis `1` and an empty path may pass only through the
  `axis == 1` short-circuit. Anything with a real tree/axis cannot be built.
- After 170,000, full proofs also require the authorization sibling:
  `leaf+2`, `leaf+4`, `leaf+8`, or `leaf+16` at the matching depth. The local
  type/builder has no representation for that check.
- This is consensus-critical. A wallet can build a transaction that a node
  rejects, or fail to build one the node would accept.

Needed:

- Build the hashable tree over `Lock`, not over one hash of the whole condition.
- Adjust index exactly like Hoon for a tagged head.
- Test both stub and full forms for:
  - one `%pkh` condition (axis `1`, empty path),
  - a `%2` tree,
  - nested `%4`/`%8`/`%16`,
  - invalid `axis`/`path` cases.
- Port `authorization-leaf` as a local validation helper and add tests that
  compare root/path/axis against expected values.

Do not just wrap the current stub in `Full` and call it fixed.

### 3. Post-170,000 validation rules

Hoon `9bcc26c6` added/changed, and says validation applies immediately, not at
170,000:

- `valid-stub-axes`: for `%1` spends that are not the protocol fund, a stub
  proof must have axis `1`.
- `authorization-leaf`: a full proof's final path sibling must authenticate the
  arity tag at that depth.
- Full proofs reject an empty spend condition (`?~ spend-condition.form`).
- At 170,000, protocol-fund recovery applies the configured minimum maturity at
  the spending candidate height (`fund-minimum-at`, `FundMaturity`).
- `consensus-batch-phase` is 170,000, and AI-PoW gains `%consrule`. The AI-PoW
  rule is **not** tx-types' job; do not port it here.

Why it matters:

`tx-types` is used by wallets to plan and sign. If it does not mirror these
validation rules, it will plan invalid spends, especially around the protocol
fund and multisig/multi-condition locks.

Needed:

- Add `authorization_leaf` validation for local proofs.
- Add `valid_stub_axis` validation.
- Reject empty spend conditions at build/validate boundaries.
- Add fund maturity as data in the planner; do not bake a current height into a
  type.
- Keep activation heights as constants/config, not `#[cfg]`.

### 4. Wallet builder utilities are not shared

Upstream `crates/wallet-tx-builder` is ~6,600 lines and contains the layer that
is missing here:

| Upstream file | Purpose | Local status |
|---|---|---|
| `types.rs` | Candidate notes, planned outputs, plan requests, selection mode | Missing |
| `determinism.rs` | Canonical note ordering, spend-condition canonicalization | Missing |
| `fee.rs` | `compute_minimum_fee`, `FeeBreakdown`, `witness_divisor`, bridge fee | Partial in `fee_calculator.rs` |
| `lock_resolver.rs` | `FundMaturity`, `LockMatcher`, `LockRootLockMatcher`, multisig/fund policy | Missing |
| `note_data.rs` | Note-data normalization, lock/bridge payloads, decoded note data | Missing (local uses `UntypedNoun`) |
| `word_count.rs` | Seed/witness/note-data word accounting | Partial/inline |
| `adapter.rs` | Snapshot normalization, single-snapshot enforcement | Consumer-specific |
| `planner.rs` | Candidate selection, v0→v1 migration, refunds, conservation | Partial in `tx_builder_v1.rs`/`tx_builder_batch.rs` |

Why it matters:

Consumers currently reimplement selection/fee/refund rules. The recent wallet
change (`9bcc26c6`) added an effective signer choice and fund maturity policy;
those decisions belong in a shared planner, not in each wallet.

Needed:

- Move the pure parts into `tx-types`.
- Keep snapshot fetch, persistence, hardware signing, and transport behind
  traits in consumers.
- Parameterize V0/V1 differences with `Version`/`LockData`/policy arguments.
- Do not copy the planner twice.

### 5. Note-data: bridge deposit/withdrawal are untyped

Local:

- `NoteData { map: ZMap<String, UntypedNoun> }`
  - Callers insert raw nouns.
  - No typed bridge payload.
  - No normalization/validation of the canonical note-data map.

Upstream `wallet-tx-builder::note_data`:

- `BridgeDepositDataPayload`
- `BridgeWithdrawalDataPayload`
- `DecodedNoteData` / `DecodedNoteDataEntry`
- `LockDataPayload` / `ParsedLockForm`
- key constants for `lock`, `bridge`, `bridge-w`.

Why it matters:

Bridge deposits need canonical note-data encoding. Without it, callers can
construct a shape that hashes differently from Hoon. Base/Ethereum transaction
construction itself is **out of scope**; only note-data encoding for deposits
matters.

Needed:

- Add typed bridge deposit/withdrawal note-data payloads.
- Add canonical encode/decode and round-trip tests.
- Add `EthAddress` only if deposit encoding needs it. Do not port Ethereum
  transaction types, Base L1 transactions, or bridge contracts.

### 6. Lower-priority types from `nockchain-types`

These are present upstream but absent locally:

- `RequiredPkhPolicy` and `SpendCondition::required_pkh_policy()`.
  Useful for wallet signer selection; easy to add.
- `TransactionMetadata`, `LockMetadata`, `VersionedLockMetadata`,
  `LegacyLockMetadata`, `InputMetadata`, `OutputLockMap`, `WitnessData`,
  `SignatureMap`, `SpendConditionMap`.
  Mostly node/explorer metadata; add only if a consumer needs them.
- `BlockchainConstants`, `AsertParams`, `NoteDataConstraints`, `Seconds`.
  Consensus configuration, not transaction construction. Keep out unless this
  crate is meant to own consensus params.
- `EthAddress`.
  Only for bridge deposit encoding; no Base/Ethereum tx construction.

Do not port `nockchain-types` wholesale just for parity. Port what the shared
builder consumes.

### 7. `std`/`no_std` split is wrong for sharing

Local `src/lib.rs` gates nearly everything on `std`:

- `fee_calculator`, `tx_builder_v1`, `tx_builder_batch`,
  `transaction_types*`, `hashing`, `validation` are std-only.
- `no_std` gets only `crypto` and `pokenoun`.

That means the fee/planner/note-data logic cannot be shared with embedded/wasm
no_std consumers, even though it is pure Rust.

Needed:

- Make pure modules available under `alloc`/no_std.
- Gate only serde/JSON/base58/CLI/noun-slab adapters on `std` (or introduce a
  separate `serde` feature).
- Avoid serde derives on core types if they prevent no_std; use separate DTOs
  or `cfg_attr`.
- Compile the matrix below on every change.

## Target architecture

```text
tx-types core (no_std + alloc)
  transaction_types{,_v0,_v1}
  lock tree
  hashing
  fee + word_count
  note_data normalize/encode
  lock_resolver (traits only)
  planner core (pure, version-parameterized)

tx-types std
  serde / serde_json / bs58 / chrono / CLI
  NounSlab helpers that require std conveniences

consumer (wallet-engine, nockster-esp, RPC server, CLI)
  snapshot fetch
  persistence
  signing transport / hardware
  concrete LockMatcher / SnapshotPageFetcher impls
```

Rules:

1. `std` means "convenience/IO available", not "planning available".
2. Version differences are arguments/enums, not duplicate functions.
3. Traits at the IO boundaries; pure functions in the middle.
4. No `#[cfg(feature = "native")]` duplicate implementation. One shared source,
   aliased embedded/upstream dependencies only if the native build is retained.
5. Consensus heights and reference rates are data/config, not hard-coded in
   tests or types.

## Work plan

Do these as separate PRs; each should keep the whole matrix green.

### Slice 1: Lock tree + real LMP

- Port `Lock` tree types and hashing.
- Replace the local `build_lock_merkle_proof_*` with the Hoon algorithm.
- Add `authorization_leaf` and `valid_stub_axis` validation helpers.
- Add tests for leaf, `%2`, `%4`, nested trees, bad axis/path.
- Acceptance: roots/paths/axes match Hoon for at least the fixtures used by
  `hoon/tests/dumb/mod/unit/lock-merkle-proof.hoon`; no full proof is just a
  wrapped stub.

### Slice 2: Shared fee + word counting

- Move `FeeBreakdown`, `witness_divisor`, bridge fee, and word counting into
  shared modules.
- Keep `calculate_min_fee` behavior; add parity tests against Hoon fee cases.
- Acceptance: V0/V1, below/at Bythos, witness divisor, multi-input counts all
  match Hoon.

### Slice 3: Note-data normalization + bridge payloads

- Add typed note-data normalization and canonical encoding.
- Add bridge deposit (`bridge`) and withdrawal (`bridge-w`) payloads.
- Do not add Base/Ethereum transaction construction.
- Acceptance: canonical note-data for lock + bridge deposit/withdrawal
  round-trips and hashes match Hoon.

### Slice 4: Lock resolver + fund maturity

- Port `FundMaturity`, `LockMatcher`, `LockRootLockMatcher` semantics.
- Add `fund_minimum_at(height)`/candidate-height handling as data.
- Acceptance: protocol-fund and multisig selection match the wallet planner
  tests in upstream `crates/nockchain-wallet/src/tests.rs`.

### Slice 5: Pure planner core

- Extract selection, conservation, refund, and v0→v1 migration from the
  consumers/current builder.
- Keep async snapshot fetch and signing transport in consumers.
- Acceptance: a pure plan can be tested without a browser, node, or hardware;
  the wallet and embedded consumers produce the same plan for the same input.

### Slice 6: Feature split

- Move pure modules out of `#[cfg(feature = "std")]`.
- Gate only serde/JSON/CLI and noun-slab adapters.
- Acceptance: all commands in the feature matrix compile; no duplicated
  planner.

## How to investigate

Start from the current local code:

```sh
cd ~/gits/np/tx-types

sed -n '80,170p' tx-types/src/block_types.rs
sed -n '1150,1420p' tx-types/src/transaction_types_v1.rs
sed -n '1,120p' tx-types/src/fee_calculator.rs
sed -n '240,620p' tx-types/src/tx_builder_v1.rs
```

Read the upstream algorithms:

```sh
cd ~/gits/nockchain

sed -n '610,780p' crates/nockchain-types/src/tx_engine/v1/tx.rs
sed -n '1770,2075p' hoon/common/tx-engine-1.hoon
sed -n '440,560p' hoon/common/tx-engine.hoon
sed -n '1080,1130p' hoon/common/tx-engine.hoon

# Full new wallet builder layer
ls crates/wallet-tx-builder/src
sed -n '1,220p' crates/wallet-tx-builder/src/fee.rs
sed -n '1,260p' crates/wallet-tx-builder/src/lock_resolver.rs
sed -n '1,340p' crates/wallet-tx-builder/src/note_data.rs
```

Read the 170,000 consensus change:

```sh
cd ~/gits/nockchain
git show 9bcc26c6 -- hoon/common/tx-engine.hoon hoon/common/tx-engine-1.hoon
git show 9bcc26c6 -- crates/nockchain-wallet/src/create_tx.rs
sed -n '1,120p' changelog/protocol/017-anthropos.md
```

Note that commit did **not** change `crates/nockchain-types`. The Rust type
layout is not the new consensus change; the validation semantics and wallet
planning are.

## How to validate

Current matrix:

```sh
cd ~/gits/np/tx-types

cargo test -p tx-types --lib

cargo build -p tx-types \
  --no-default-features --target thumbv7em-none-eabihf

cargo build -p tx-types \
  --no-default-features --features std,embedded \
  --target wasm32-unknown-unknown
```

When the pure modules move out of `std`, adapt those commands:

```sh
# no_std pure core
cargo build -p tx-types --no-default-features \
  --target thumbv7em-none-eabihf

# no_std + serde/JSON if you introduce a serde feature
cargo build -p tx-types --no-default-features --features serde
```

Consumer checks (depends on how they pin this crate):

```sh
cargo check --manifest-path ~/gits/np/nockchain-rpc-server/Cargo.toml
cargo check --manifest-path ~/gits/np/siger-esp/packages/wallet-engine/Cargo.toml
cargo test --manifest-path ~/gits/np/siger-esp/packages/wallet-engine/Cargo.toml
cargo check --manifest-path ~/gits/np/siger-esp/nockster-esp/Cargo.toml
```

Do not rely on tests alone. For LMP/planning, build a small scenario and
compare the local output against a Hoon-produced fixture or the upstream Rust
builder. A round-trip test only proves self-consistency, not consensus.

## Tests to add

- `SpendCondition` with one `%pkh`: stub and full proof, axis, path.
- `%2`, `%4`, `%8`, `%16` trees: flatten order, count, root.
- Index adjustment for a tagged head.
- `authorization_leaf`: accepts correct final sibling, rejects wrong tag/depth.
- `valid_stub_axis`: ordinary `%1` spend requires axis `1`.
- Empty spend condition rejected.
- Fund maturity: protocol-fund spend before/at/after the candidate-height
  minimum.
- Fee parity: single/multiple inputs, V0/V1, Bythos on/off, witness divisor.
- Note-data: lock and bridge deposit/withdrawal canonical round-trip and hash.
- V0→V1 migration and refund conservation.
- `std` and `no_std` produce the same hashes/plans.

## Pitfalls

- `HashMap`/`ZMap` iteration order is not stable. Wallet lists and spend maps
  must be explicitly sorted/canonicalized before planning or UI selection.
- Do not treat a successful noun round-trip as proof of consensus validity.
- Do not use the current chain height inside a type or constant. Pass the
  candidate height into planning/validation.
- Do not port AI-PoW `%consrule`, ASERT anchors, or node gRPC policy. Those are
  not transaction-builder concerns.
- Do not port Base/Ethereum transaction construction. Only bridge note-data
  encoding for deposits is relevant.
- Keep V0 behavior frozen. The v0→v1 migration is the only place where the two
  should meet.
- The fork's `native`/`embedded` split must not become two implementations.
  Alias dependencies if needed; share the source.

## Definition of done

- One lock/type implementation, with `Lock` trees and V0/V1 differences explicit.
- LMP builder produces real tree proofs and validates them locally.
- Post-170,000 validation semantics mirrored and tested.
- Shared fee/word/note-data/lock-resolver/planner logic available to both
  `std` and `no_std` consumers.
- Consumers only supply IO: snapshots, persistence, signing, transport.
- The full compile/test matrix passes.
- A new contributor can point to a single module for each rule and find tests
  for it.

## File map

Local:

- `tx-types/src/lib.rs` — feature gates and aliases.
- `tx-types/src/transaction_types.rs` — legacy/common types.
- `tx-types/src/transaction_types_v0.rs` — V0 types.
- `tx-types/src/transaction_types_v1.rs` — V1 types, `SpendCondition`,
  `LockPrimitive`, `MerkleProof`, `LockMerkleProof`.
- `tx-types/src/block_types.rs` — coinbase/page plus LMP builder.
- `tx-types/src/fee_calculator.rs` — fee constants and minimum fee.
- `tx-types/src/tx_builder_v1.rs` — simplified spend builder.
- `tx-types/src/tx_builder_batch.rs` — simplified batch builder.
- `tx-types/src/hashing/` — Tip5, tx-id, hashable.
- `tx-types/src/crypto/` — Cheetah, Goldilocks, SLIP-10.
- `tx-types/src/validation/` — signature/transaction validation.

Upstream:

- `crates/nockchain-types/src/tx_engine/v1/tx.rs`
- `crates/nockchain-types/src/tx_engine/v1/note.rs`
- `crates/nockchain-types/src/tx_engine/v1/signatures.rs`
- `crates/nockchain-types/src/tx_engine/v1/hashable.rs`
- `crates/nockchain-types/src/blockchain_constants.rs`
- `crates/wallet-tx-builder/src/*`
- `hoon/common/tx-engine.hoon`
- `hoon/common/tx-engine-1.hoon`
