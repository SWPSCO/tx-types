use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "vanity-pkh-test-{}-{}",
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
    Command::new(env!("CARGO_BIN_EXE_vanity-pkh"))
}

#[test]
fn help_and_invalid_arguments() {
    assert!(command().arg("--help").output().unwrap().status.success());
    for args in [
        vec![],
        vec!["0"],
        vec!["abc", "--threads", "0"],
        vec!["abc", "--max-attempts", "0"],
        vec!["abc", "--unknown"],
        vec!["abc", "--output"],
    ] {
        assert_eq!(
            command().args(args).output().unwrap().status.code(),
            Some(1)
        );
    }
}

#[test]
fn preserves_existing_key_file() {
    let dir = TempDir::new();
    let output = dir.0.join("key.json");
    std::fs::write(&output, "keep this key").unwrap();
    let result = command()
        .args(["abc", "--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(std::fs::read_to_string(output).unwrap(), "keep this key");
}

#[test]
fn global_attempt_limit_and_private_permissions() {
    let dir = TempDir::new();
    let output = dir.0.join("key.json");
    let result = command()
        .args([
            "2222222222222222222222222222222222222222222222222222222",
            "--threads",
            "3",
            "--max-attempts",
            "7",
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8(result.stderr)
        .unwrap()
        .contains("Tested 7 candidates"));
    assert!(result.stdout.is_empty());
    assert_eq!(std::fs::metadata(&output).unwrap().len(), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn pattern_searches_save_one_or_multiple_distinct_recoverable_keys() {
    let dir = TempDir::new();
    for flag in ["--suffix", "--contains"] {
        for continuous in [false, true] {
            let path = dir.0.join(format!("{flag}-{continuous}.json"));
            let mut cmd = command();
            cmd.args([flag, "1", "--raw-key", "--max-attempts", "2000", "--output"])
                .arg(&path);
            cmd.args(["--threads", "3"]);
            if continuous {
                cmd.arg("--continuous");
            }
            let result = cmd.output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let items = if continuous {
                saved.as_array().unwrap().clone()
            } else {
                assert!(saved.is_object());
                vec![saved]
            };
            if continuous {
                assert!(items.len() > 1);
                assert!(String::from_utf8_lossy(&result.stderr).contains("Tested 2000 candidates"));
            }
            let mut addresses = std::collections::HashSet::new();
            for item in &items {
                let scalar: [u8; 32] = bs58::decode(item["secret_key_base58"].as_str().unwrap())
                    .into_vec()
                    .unwrap()
                    .try_into()
                    .unwrap();
                let restored = vanity::encode_pkh(vanity::pkh_from_public_key(
                    &tx_types::crypto::cheetah_nostd::cheetah_pub_from_sk(scalar),
                ));
                let address = restored.as_str();
                assert_eq!(item["pkh"], address);
                assert!(if flag == "--suffix" {
                    address.ends_with('1')
                } else {
                    address.contains('1')
                });
                assert!(addresses.insert(address.to_owned()));
                assert!(!String::from_utf8_lossy(&result.stdout)
                    .contains(item["secret_key_hex_be"].as_str().unwrap()));
            }
            assert_eq!(
                String::from_utf8_lossy(&result.stdout).lines().count(),
                items.len()
            );
        }
    }
}
