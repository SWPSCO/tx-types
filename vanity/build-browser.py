#!/usr/bin/env python3
"""Build the WASM module and WGSL constants from tx-types' Rust source."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
from shader_constants import generate

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(__file__).resolve().parent / "browser"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out-dir", type=Path, required=True, help="Browser library asset destination")
args = parser.parse_args()
DEST = args.out_dir.resolve()
OUT = DEST / "generated"


if __name__ == "__main__":
    shutil.copytree(SOURCE, DEST, dirs_exist_ok=True)
    generate(OUT)
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
