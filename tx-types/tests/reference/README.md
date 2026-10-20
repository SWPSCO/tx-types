# Transaction reference fixtures

The reference is the official Nockchain checkout at
`9bcc26c6c57019dfde7f83aad9a9dd4ed5cd7902`. The `.jam` files contain public test
values. The tests decode them using the same portable codecs in hosted and
`no_std` builds. Portable JAM output matches the official bytes, including
canonical backreferences; comparisons remove only the generator files’ terminal
eight-byte-word padding.

| Fixture | Oracle and assertions |
| --- | --- |
| `lock-proofs.jam` | `lock-proofs.hoon` invokes `common/tx-engine-1.hoon` lock hashing, stub/full proof builders, proof hashing, and verification. It covers every leaf of 1/2/4/8/16-condition locks using the official `tests/dumb/mod/unit/lock-merkle-proof.hoon` cases. Tests compare exact JAMs, hashes, axes, sibling order, and validation verdicts. |
| `note-data-oracle.jam` | `note-data-oracle.hoon` uses payloads from `tests/wallet/mod/note-data-fixtures.hoon`. Official note-data hashing and `num-of-leaves` produce the expected hashes and word counts for tagged locks, bridge deposits/withdrawals, and opaque versions/networks. |
| `fee-oracle.jam` | `fee-oracle.hoon` uses the official raw V1 transaction plus duplicate-input and V0 migration variants. The note-data aggregation/count gates come from `common/tx-engine.hoon`; fees use its formula with Bythos 10, base fee 257, divisor 3, and minimum 100. Twelve cases cover heights 9/10/11 and single/multiple V0/V1 witness shapes. These synthetic fee cases do not assert spend authorization. |
| `raw-tx-v0.jam`, `raw-tx-v1.jam` | Copied from `crates/nockchain-types/jams/v{0,1}/raw-tx.jam`; compare transaction IDs embedded by the reference. |
| `spend1-sig-hash.jam` | Copied from the official V1 JAM directory; compares per-spend signature hashes. |
| `withdrawal-transactions.jam` | Copied from `crates/wallet-tx-builder/tests/fixtures`; compares unsigned withdrawal fee estimates, including the required signature-map words. These fixtures use their own Bythos/base/minimum configuration. |

Seed fees count the flattened note-data key/value reduction, including its
terminal zero. They do not count the branching map representation. Full witness
fees include the arity-tag sibling in each Merkle proof. The Hoon oracles pin
these details independently of Rust round-trip tests.

Install the official `hoon` and `hoonc` binaries from the reference checkout,
then reproduce and compare every fixture:

```sh
python3 tx-types/tests/reference/regenerate.py /path/to/nockchain --check
(cd tx-types/tests/reference && sha256sum --check SHA256SUMS)
cargo test -p tx-types --lib
cargo test -p tx-types --no-default-features --lib
```

Omit `--check` to replace fixtures and checksums. The generator runs in an
isolated temporary directory and requires successful compilation before copying
output. This also isolates the compiler's `out.jam` intermediate.
