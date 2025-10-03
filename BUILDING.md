# Building tx-types

This document explains how to build the tx-types library with different dependency configurations.

## Default Build (Git Dependencies)

By default, the project uses nockchain dependencies from the git repository:

```bash
cargo build
cargo test
```

This configuration matches the main branch and is suitable for most development work.

## WASM Compilation (Local Dependencies)

For WASM compilation, you need to use local path dependencies from the `nockchain-minimal` submodule. This is required because WASM targets need access to the full source code.

### Switching to Local Dependencies

Run the provided script:

```bash
./use-local-nockchain.sh
```

This will uncomment the `[patch]` section in `Cargo.toml` to override git dependencies with local paths.

After switching, clean and rebuild:

```bash
cargo clean
cargo build
```

### Switching Back to Git Dependencies

To switch back to git dependencies:

```bash
./use-git-nockchain.sh
```

Then clean and rebuild:

```bash
cargo clean
cargo build
```

## How It Works

The `Cargo.toml` file is configured with:

1. **Default dependencies**: Git references to the nockchain repository
   ```toml
   noun-serde = { git = "https://github.com/SWPSCO/nockchain.git", rev = "..." }
   ```

2. **Patch section (commented by default)**: Local path overrides
   ```toml
   # [patch."https://github.com/SWPSCO/nockchain.git"]
   # noun-serde = { path = "./nockchain-minimal/crates/noun-serde" }
   ```

When the patch section is uncommented, Cargo will use the local paths instead of fetching from git. This allows the same codebase to work in both configurations.

## Why Two Configurations?

- **Git dependencies**: Standard Rust practice, compatible with main branch, easier dependency management
- **Local dependencies**: Required for WASM compilation, allows local modifications to nockchain during development

This approach avoids having separate branches for different build configurations.
