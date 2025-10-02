#!/bin/bash
# Script to enable local nockchain dependencies for WASM compilation

set -e

CARGO_TOML="Cargo.toml"

if [ ! -f "$CARGO_TOML" ]; then
    echo "Error: $CARGO_TOML not found in current directory"
    exit 1
fi

echo "Enabling local nockchain dependencies..."

# Uncomment the [patch."https://github.com/SWPSCO/nockchain.git"] section
sed -i.bak '/^# \[patch\."https:\/\/github\.com\/SWPSCO\/nockchain\.git"\]/,/^# ibig = { path/s/^# //' "$CARGO_TOML"

echo "Local dependencies enabled. Run 'cargo clean' to ensure a fresh build."
echo "To revert, run: ./use-git-nockchain.sh"
