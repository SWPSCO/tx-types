use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use tx_types::crypto::cheetah_nostd::cheetah_pub_from_sk;
use vanity::{encode_pkh, pkh_from_public_key};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "vanity-gpu-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vanity-gpu"))
}

fn assert_private(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn preserves_existing_backup_before_starting_gpu_work() {
    let dir = TempDir::new();
    let path = dir.0.join("key.json");
    std::fs::write(&path, "keep this key").unwrap();
    let result = command()
        .args(["abc", "--output"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(std::fs::read_to_string(path).unwrap(), "keep this key");
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8(result.stderr).unwrap().contains("GPU:"));
}

#[test]
#[ignore = "requires a hardware Vulkan GPU"]
fn partial_gpu_batch_obeys_exact_limit() {
    let dir = TempDir::new();
    let path = dir.0.join("key.json");
    let result = command()
        .args(["zzzzzzzzzzzz", "--max-attempts", "7", "--output"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8(result.stderr)
        .unwrap()
        .contains("Tested 7 candidates"));
    assert!(result.stdout.is_empty());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    assert_private(&path);
}

#[test]
#[ignore = "requires a hardware Vulkan GPU"]
fn gpu_backups_restore_the_verified_address() {
    let dir = TempDir::new();
    for raw in [false, true] {
        let path = dir.0.join(if raw { "raw.json" } else { "extended.json" });
        let mut cmd = command();
        cmd.args(["2", "--max-attempts", "10000", "--output"])
            .arg(&path);
        if raw {
            cmd.arg("--raw-key");
        }
        let result = cmd.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_private(&path);
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let scalar: [u8; 32] = bs58::decode(json["secret_key_base58"].as_str().unwrap())
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let restored = encode_pkh(pkh_from_public_key(&cheetah_pub_from_sk(scalar)));
        assert!(restored.as_str().starts_with('2'));
        assert_eq!(json["pkh"], restored.as_str());
        assert_eq!(
            String::from_utf8(result.stdout).unwrap().trim(),
            restored.as_str()
        );
        assert!(json.get("mnemonic").is_none());
        assert!(json.get("passphrase").is_none());
        if raw {
            assert!(json.get("zprv").is_none());
        } else {
            assert_eq!(json["derivation_path"], "m");
            let zprv = json["zprv"].as_str().unwrap();
            assert!(zprv.starts_with("zprv"));
            let payload = bs58::decode(zprv).with_check(None).into_vec().unwrap();
            assert_eq!(payload.len(), 79);
            assert_eq!(&payload[..4], &0x0110_6331u32.to_be_bytes());
            assert_eq!(payload[4], 1);
            assert_eq!(&payload[5..14], &[0; 9]);
            assert!(payload[14..46].iter().any(|&b| b != 0));
            assert_eq!(payload[46], 0);
            assert_eq!(&payload[47..], &scalar);
        }
    }
}
