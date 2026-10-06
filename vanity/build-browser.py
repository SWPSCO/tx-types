#!/usr/bin/env python3
"""Build the WASM module and WGSL constants from tx-types' Rust source."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(__file__).resolve().parent / "browser"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out-dir", type=Path, required=True, help="Browser library asset destination")
args = parser.parse_args()
DEST = args.out_dir.resolve()
OUT = DEST / "generated"


def values(source, name):
    match = re.search(rf"(?:pub )?const {name}:.*?=\s*(?:F6lt\()?\[(.*?)\]\)?;", source, re.S)
    if not match:
        raise ValueError(f"Missing Rust constant: {name}")
    body = re.sub(r"//[^\n]*", "", match[1])
    return [int(number.replace("_", ""), 0) for number in
            re.findall(r"\b(?:0x[0-9a-fA-F_]+|[0-9][0-9_]*)\b", body)]


def u64(value):
    return f"U64({value & 0xffffffff}u, {value >> 32}u)"


def generate():
    gold = (ROOT / "tx-types/src/crypto/goldilocks.rs").read_text()
    curve = (ROOT / "tx-types/src/crypto/cheetah_nostd.rs").read_text()
    lookup = values(gold, "LOOKUP_TABLE")
    matrix = values(gold, "MDS_MATRIX_I64")
    rounds = values(gold, "ROUND_CONSTANTS")
    gx, gy = values(curve, "GX"), values(curve, "GY")
    order_bytes = bytes(values(curve, "CHEETAH_N"))
    order = [int.from_bytes(order_bytes[i:i+8], "big") for i in range(0, 32, 8)]
    assert (len(lookup), len(matrix), len(rounds), len(gx), len(gy)) == (256, 256, 112, 6, 6)
    first = matrix[:16]
    assert all(matrix[i*16:(i+1)*16] == first[-i:] + first[:-i] if i else
               matrix[:16] == first for i in range(16))
    prime = 2**64 - 2**32 + 1
    mont_r = pow(2, 64, prime)
    lines = ["// Generated from tx-types Rust constants by build-browser.py."]
    for name, entries, kind, formatter in [
        ("LOOKUP", lookup, "u32", lambda n: f"{n}u"),
        ("MDS", first, "u32", lambda n: f"{n}u"),
        ("ROUND_CONSTANTS", [n * mont_r % prime for n in rounds], "U64", u64),
        ("GX", gx, "U64", u64), ("GY", gy, "U64", u64),
        ("CHEETAH_ORDER", order, "U64", u64),
        ("DYCK", [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1] * 2, "u32", lambda n: f"{n}u"),
    ]:
        lines.append(f"const {name} = array<{kind}, {len(entries)}>(\n" +
                     ",\n".join("    " + formatter(n) for n in entries) + "\n);")
    lines += [f"const MONT_R = {u64(mont_r)};",
              f"const MONT_R_INVERSE = {u64(pow(mont_r, -1, prime))};"]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "constants.wgsl").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    shutil.copytree(SOURCE, DEST, dirs_exist_ok=True)
    generate()
    cargo = os.environ.get("CARGO", "cargo")
    subprocess.run([cargo, "build", "--release", "-p", "vanity-pkh-wasm",
                    "--target", "wasm32-unknown-unknown"], cwd=ROOT, check=True)
    # Cargo metadata respects CARGO_TARGET_DIR and local Cargo configuration.
    import json
    metadata = json.loads(subprocess.check_output(
        [cargo, "metadata", "--no-deps", "--format-version", "1"], cwd=ROOT))
    artifact = Path(metadata["target_directory"]) / "wasm32-unknown-unknown/release/vanity_pkh_wasm.wasm"
    shutil.copyfile(artifact, OUT / "vanity_pkh.wasm")
    subprocess.run([cargo, "run", "--quiet", "--release", "-p", "vanity", "--no-default-features",
                    "--example", "gpu_table", "--", str(OUT / "generator-table.bin")],
                   cwd=ROOT, check=True)
    print(f"Built browser library assets in {DEST}")
