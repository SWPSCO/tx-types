use alloc::string::String;
use core::fmt::Write;
use tx_types::crypto::cheetah_nostd::ser_a_pt;
use zeroize::Zeroizing;

use super::{encode_pkh, Match, Mnemonic};

/// Private JSON for a verified match. Mnemonic recovery uses path `m` and an
/// empty BIP39 passphrase. The returned buffer erases itself on drop.
pub fn key_json(found: &Match, mnemonic: Option<&Mnemonic>) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(1024));
    out.push_str("{\n");
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
