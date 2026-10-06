use std::{env, path::PathBuf, process::Command};

fn main() {
    let vanity = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("..");
    for file in [
        "shader_constants.py",
        "../tx-types/src/crypto/goldilocks.rs",
        "../tx-types/src/crypto/cheetah_nostd.rs",
        "browser/shaders",
    ] {
        println!("cargo:rerun-if-changed={}", vanity.join(file).display());
    }
    println!("cargo:rerun-if-env-changed=PYTHON");
    let status = Command::new(env::var_os("PYTHON").unwrap_or_else(|| "python3".into()))
        .arg(vanity.join("shader_constants.py"))
        .arg(env::var_os("OUT_DIR").unwrap())
        .status()
        .expect("Python 3 is required to generate the shared GPU constants");
    assert!(status.success(), "GPU constant generation failed");
}
