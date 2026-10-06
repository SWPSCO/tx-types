use alloc::string::String;
use core::fmt::Write;
use tx_types::crypto::cheetah_nostd::ser_a_pt;
use zeroize::Zeroizing;

use super::{encode_pkh, Match, Mnemonic};

/// Private JSON for a verified match. Mnemonic recovery uses path `m` and an
/// empty BIP39 passphrase. The returned buffer erases itself on drop.
pub fn key_json(found: &Match, mnemonic: Option<&Mnemonic>) -> Zeroizing<String> {
    serialize_key(found, mnemonic, None)
}

/// Export the same signing key as a version-1 master zprv at path `m`.
/// The caller supplies a fresh, cryptographically random chain code after mining.
/// This extended key has no associated mnemonic.
pub fn extended_key_json(found: &Match, chain_code: &[u8; 32]) -> Zeroizing<String> {
    // Nockchain SLIP-10: type, version, depth, parent fingerprint, child index,
    // chain code, private-key tag, and big-endian scalar, with Base58Check.
    let mut payload = Zeroizing::new([0u8; 79]);
    payload[..4].copy_from_slice(&0x0110_6331u32.to_be_bytes());
    payload[4] = 1;
    payload[14..46].copy_from_slice(chain_code);
    payload[47..].copy_from_slice(found.secret_key_be.as_ref());
    let zprv = Zeroizing::new(bs58::encode(payload.as_ref()).with_check().into_string());
    serialize_key(found, None, Some(&zprv))
}

fn serialize_key(
    found: &Match,
    mnemonic: Option<&Mnemonic>,
    zprv: Option<&str>,
) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(1024));
    out.push_str("{\n");
    if let Some(zprv) = zprv {
        writeln!(
            &mut *out,
            "  \"zprv\": \"{zprv}\",\n  \"derivation_path\": \"m\","
        )
        .unwrap();
    }
    if let Some(mnemonic) = mnemonic {
        // English BIP39 words need no JSON escaping.
        writeln!(&mut *out, "  \"mnemonic\": \"{mnemonic}\",").unwrap();
        out.push_str("  \"derivation_path\": \"m\",\n  \"passphrase\": \"\",\n");
    }
    out.push_str("  \"secret_key_hex_be\": \"");
    for byte in found.secret_key_be.iter() {
        write!(&mut *out, "{byte:02x}").unwrap();
    }
    let base58 = Zeroizing::new(bs58::encode(found.secret_key_be.as_ref()).into_string());
    writeln!(&mut *out, "\",\n  \"secret_key_base58\": \"{}\",", &*base58).unwrap();
    let public = serde_json::json!({
        "pkh": encode_pkh(found.pkh).as_str(),
        "public_key_base58": bs58::encode(ser_a_pt(&found.public_key)).into_string(),
    });
    let public = serde_json::to_string_pretty(&public).unwrap();
    out.push_str(&public[2..]);
    out.push('\n');
    out
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use tx_types::crypto::cheetah_nostd::cheetah_pub_from_sk;
    use tx_types::crypto::slip10::ExtendedKey;

    #[test]
    fn extended_export_restores_the_same_address_with_the_supplied_chain_code() {
        let mut scalar = [0u8; 32];
        scalar[31] = 4;
        let public_key = cheetah_pub_from_sk(scalar);
        let found = Match {
            secret_key_be: Zeroizing::new(scalar),
            public_key,
            pkh: crate::pkh_from_public_key(&public_key),
        };
        for chain_code in [[7u8; 32], [19u8; 32]] {
            let json = extended_key_json(&found, &chain_code);
            let output: serde_json::Value = serde_json::from_str(&json).unwrap();
            let zprv = output["zprv"].as_str().unwrap();
            assert!(zprv.starts_with("zprv"));
            let mut reference = ExtendedKey::new_master(scalar, chain_code);
            reference.version = 1;
            assert_eq!(zprv, reference.to_zprv_string().unwrap());
            let restored = ExtendedKey::from_extended_key_string(zprv).unwrap();
            assert_eq!(restored.private_key, Some(scalar));
            assert_eq!(restored.chain_code, chain_code);
            assert_eq!(restored.version, 1);
            assert_eq!(restored.depth, 0);
            assert_eq!(restored.index, 0);
            assert_eq!(restored.parent_fingerprint, [0; 4]);
            assert_eq!(
                restored.public_key.to_schnorr_pubkey().to_hash().to_b58(),
                output["pkh"]
            );
            assert_eq!(output["derivation_path"], "m");
            assert!(output.get("mnemonic").is_none());
            assert!(output.get("passphrase").is_none());
        }
        let raw: serde_json::Value = serde_json::from_str(&key_json(&found, None)).unwrap();
        assert!(raw.get("zprv").is_none());
    }
}
