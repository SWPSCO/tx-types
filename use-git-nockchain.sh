#!/bin/bash
# Script to switch back to git nockchain dependencies (default)

set -e

CARGO_TOML="Cargo.toml"

if [ ! -f "$CARGO_TOML" ]; then
    echo "Error: $CARGO_TOML not found in current directory"
    exit 1
fi

if [ -f "$CARGO_TOML.bak" ]; then
    echo "Restoring git dependencies..."
    mv "$CARGO_TOML.bak" "$CARGO_TOML"
    echo "Git dependencies restored. Run 'cargo clean' to ensure a fresh build."
else
    echo "No backup found. Commenting out [patch] section..."
    # Comment out the [patch."https://github.com/SWPSCO/nockchain.git"] section
    sed -i.bak '/^\[patch\."https:\/\/github\.com\/SWPSCO\/nockchain\.git"\]/,/^ibig = { path/s/^\([^#]\)/# \1/' "$CARGO_TOML"
    rm "$CARGO_TOML.bak"
    echo "Git dependencies enabled. Run 'cargo clean' to ensure a fresh build."
fi
