#!/usr/bin/env python3
"""Reproduce the reference fixtures with the pinned official Hoon tools."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

PIN = "9bcc26c6c57019dfde7f83aad9a9dd4ed5cd7902"
HERE = Path(__file__).resolve().parent
COPIES = {
    "raw-tx-v0.jam": "crates/nockchain-types/jams/v0/raw-tx.jam",
    "raw-tx-v1.jam": "crates/nockchain-types/jams/v1/raw-tx.jam",
    "spend1-sig-hash.jam": "crates/nockchain-types/jams/v1/raw-tx-spend1-sig-hash-oracle.jam",
    "withdrawal-transactions.jam": "crates/wallet-tx-builder/tests/fixtures/withdrawal_tx_fixtures.jam",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path, help="official nockchain checkout at the documented pin")
    parser.add_argument("--check", action="store_true", help="compare without replacing fixtures")
    args = parser.parse_args()
    reference = args.reference.resolve()
    head = subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip()
    if head != PIN:
        raise SystemExit(f"reference HEAD must be {PIN}, got {head}")
    if not shutil.which("hoon"):
        raise SystemExit("install the official hoon and hoonc binaries from the pinned checkout")
    generated = {}
    for name, source in COPIES.items():
        generated[name] = (reference / source).read_bytes()
    for source in sorted(HERE.glob("*.hoon")):
        # hoon uses out.jam in its working directory. An isolated directory makes
        # a failed compilation unable to reuse another generator's output.
        with tempfile.TemporaryDirectory(prefix="tx-types-reference-") as directory:
            root = Path(directory)
            result = subprocess.run(
                ["hoon", str(source), str(reference / "hoon"), "--out-dir", str(root)],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            target = root / source.with_suffix(".jam").name
            if result.returncode or not target.is_file() or "build failed" in result.stdout:
                print(result.stdout)
                raise SystemExit(f"reference generation failed: {source.name}")
            generated[target.name] = target.read_bytes()
    for name, data in sorted(generated.items()):
        target = HERE / name
        if args.check:
            if target.read_bytes() != data:
                raise SystemExit(f"fixture differs: {name}")
        else:
            target.write_bytes(data)
        print(f"{name}: {len(data)} bytes")
    checksums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(generated.items()))
    if args.check:
        if (HERE / "SHA256SUMS").read_text() != checksums:
            raise SystemExit("SHA256SUMS differs")
    else:
        (HERE / "SHA256SUMS").write_text(checksums)


if __name__ == "__main__":
    main()
