#[cfg(feature = "std")]
use bytes::Bytes;
#[cfg(feature = "std")]
use nockapp::noun::slab::{NockJammer, NounSlab};
#[cfg(feature = "std")]
use noun_serde::{NounDecode, NounEncode};
#[cfg(feature = "std")]
use std::io::{Read, Write};
#[cfg(feature = "std")]
use tx_types::crypto::cheetah::point::cheetah_pub_from_sk;
#[cfg(feature = "std")]
use tx_types::crypto::slip10::ExtendedKey;
#[cfg(feature = "std")]
use tx_types::crypto::utils::be32_atom_to_t8_le;
#[cfg(feature = "std")]
use tx_types::signer::schnorr_sign_digest;
#[cfg(feature = "std")]
use tx_types::transaction_types_v1::compute_tx_id_v1;
#[cfg(feature = "std")]
use tx_types::{
    Chal, F6LT, Hash, LockPrimitiveBody, PkhSignatureValue, RawTransactionV1, SchnorrPubkey,
    SchnorrSignature, Sig, Spend, SpendBody, SpendsV1, T8, ZMap,
};

#[cfg(feature = "std")]
fn main() {

    fn usage(bin_name: &str) -> ! {
        eprintln!("usage: {bin_name} [zprv...] <input.jam|-> [out.jam|-]");
        eprintln!("  input.jam may be jammed `RawTransactionV1`, `SpendsV1`, or `Spend`.");
        eprintln!("  If `zprv` is omitted, uses `TX_ZPRV` env var.");
        eprintln!("  If `out.jam` is omitted, writes `<input>.signed` (or stdout for `-`).");
        std::process::exit(2);
    }

    let mut args = std::env::args();
    let bin_name = args.next().unwrap_or_else(|| "sign_raw_tx".to_string());
    let args: Vec<String> = args.collect();

    let env_zprv = std::env::var("TX_ZPRV").ok();

    let (zprv, input_path, output_path) = match args.len() {
        0 => usage(&bin_name),
        1 => {
            let Some(env_zprv) = env_zprv else {
                eprintln!("error: missing zprv arg and TX_ZPRV env var");
                std::process::exit(2);
            };
            (env_zprv, args[0].clone(), None)
        }
        2 => {
            let arg0 = &args[0];
            let arg1 = &args[1];
            if arg0.starts_with("zprv") || env_zprv.is_none() {
                (arg0.clone(), arg1.clone(), None)
            } else {
                (env_zprv.unwrap(), arg0.clone(), Some(arg1.clone()))
            }
        }
        3 => (args[0].clone(), args[1].clone(), Some(args[2].clone())),
        _ => usage(&bin_name),
    };

    let output_path = output_path.unwrap_or_else(|| {
        if input_path == "-" {
            "-".to_string()
        } else {
            format!("{input_path}.signed")
        }
    });

    let extended_key = match ExtendedKey::from_extended_key_string(&zprv) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("error: invalid zprv: {err}");
            std::process::exit(1);
        }
    };
    let Some(sk_be) = extended_key.private_key else {
        eprintln!("error: expected a `zprv...` (got a public key)");
        std::process::exit(1);
    };

    let signing_key: T8 = be32_atom_to_t8_le(&sk_be);
    let pk_coords = cheetah_pub_from_sk(sk_be);
    let schnorr_pubkey = SchnorrPubkey {
        x: F6LT { values: pk_coords[0] },
        y: F6LT { values: pk_coords[1] },
        inf: false,
    };
    let pubkey_hash = schnorr_pubkey.to_hash();

    let input_bytes = match input_path.as_str() {
        "-" => {
            let mut buf = Vec::new();
            if let Err(err) = std::io::stdin().read_to_end(&mut buf) {
                eprintln!("error: failed to read stdin: {err}");
                std::process::exit(1);
            }
            buf
        }
        path => match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("error: failed to read `{path}`: {err}");
                std::process::exit(1);
            }
        },
    };

    let mut slab = NounSlab::<NockJammer>::new();
    let noun = slab.cue_into(Bytes::from(input_bytes)).unwrap_or_else(|err| {
        eprintln!("error: failed to cue jammed noun: {err}");
        std::process::exit(1);
    });

    let (out_bytes, report_lines) = if let Ok(mut raw_tx) = RawTransactionV1::from_noun(&noun) {
        let (signed_spends, spends_signed) =
            sign_spends_v1(raw_tx.spends, &signing_key, &schnorr_pubkey, &pubkey_hash);
        raw_tx.spends = signed_spends;
        let tx_id_hash = compute_tx_id_v1(&raw_tx.spends);
        raw_tx.id = tx_id_hash.clone();

        let out_bytes = jam_to_vec(&raw_tx);
        let report = vec![
            format!("format: raw-tx-v1"),
            format!("tx_id: {}", tx_id_hash.to_b58()),
            format!("pubkey_hash: {}", pubkey_hash.to_b58()),
            format!("spends_signed: {}", spends_signed),
        ];
        (out_bytes, report)
    } else if let Ok(spends) = SpendsV1::from_noun(&noun) {
        let (signed_spends, spends_signed) =
            sign_spends_v1(spends, &signing_key, &schnorr_pubkey, &pubkey_hash);
        let tx_id_hash = compute_tx_id_v1(&signed_spends);

        let out_bytes = jam_to_vec(&signed_spends);
        let report = vec![
            format!("format: spends-v1"),
            format!("tx_id: {}", tx_id_hash.to_b58()),
            format!("pubkey_hash: {}", pubkey_hash.to_b58()),
            format!("spends_signed: {}", spends_signed),
        ];
        (out_bytes, report)
    } else if let Ok(mut spend) = Spend::from_noun(&noun) {
        let spend_signed = sign_spend_in_place(&mut spend, &signing_key, &schnorr_pubkey, &pubkey_hash);
        let out_bytes = jam_to_vec(&spend);
        let report = vec![
            format!("format: spend"),
            format!("pubkey_hash: {}", pubkey_hash.to_b58()),
            format!("spend_signed: {}", spend_signed),
        ];
        (out_bytes, report)
    } else {
        eprintln!("error: unrecognized noun shape; expected RawTransactionV1, SpendsV1, or Spend");
        std::process::exit(1);
    };

    match output_path.as_str() {
        "-" => {
            let mut stdout = std::io::stdout().lock();
            if let Err(err) = stdout.write_all(&out_bytes) {
                eprintln!("error: failed to write stdout: {err}");
                std::process::exit(1);
            }
        }
        path => {
            if let Err(err) = std::fs::write(path, &out_bytes) {
                eprintln!("error: failed to write `{path}`: {err}");
                std::process::exit(1);
            }
        }
    }

    for line in report_lines {
        eprintln!("{line}");
    }
}

#[cfg(feature = "std")]
fn spend_is_signable(spend: &Spend, pubkey_hash: &Hash) -> bool {
    let SpendBody::V1(body) = &spend.body else {
        return false;
    };

    for primitive in &body.witness.lmp.spend_condition().p {
        if let LockPrimitiveBody::Pkh(pkh) = &primitive.body {
            if pkh.h.has(pubkey_hash) {
                return true;
            }
        }
    }

    false
}

#[cfg(feature = "std")]
fn sign_spend_in_place(
    spend: &mut Spend,
    signing_key: &T8,
    schnorr_pubkey: &SchnorrPubkey,
    pubkey_hash: &Hash,
) -> bool {
    if !spend_is_signable(spend, pubkey_hash) {
        return false;
    }

    let sig_hash = spend.body.sig_hash();
    let (chal, sig) = schnorr_sign_digest(signing_key.clone(), schnorr_pubkey.clone(), sig_hash);
    let schnorr_sig = SchnorrSignature {
        chal: Chal { values: chal },
        sig: Sig { values: sig },
    };

    let SpendBody::V1(body) = &mut spend.body else {
        return false;
    };

    body.witness.pkh.map.put(
        pubkey_hash.clone(),
        PkhSignatureValue {
            pk: schnorr_pubkey.clone(),
            sig: schnorr_sig,
        },
    );
    true
}

#[cfg(feature = "std")]
fn sign_spends_v1(
    spends: SpendsV1,
    signing_key: &T8,
    schnorr_pubkey: &SchnorrPubkey,
    pubkey_hash: &Hash,
) -> (SpendsV1, u64) {
    let mut out = ZMap::new();
    let mut spends_signed = 0u64;

    for (name, mut spend) in spends.map.tap() {
        if sign_spend_in_place(&mut spend, signing_key, schnorr_pubkey, pubkey_hash) {
            spends_signed = spends_signed.saturating_add(1);
        }

        out.put(name, spend);
    }

    (SpendsV1 { map: out }, spends_signed)
}

#[cfg(feature = "std")]
fn jam_to_vec<T: NounEncode>(value: &T) -> Vec<u8> {
    let mut slab = NounSlab::<NockJammer>::new();
    let noun = value.to_noun(&mut slab);
    slab.set_root(noun);
    slab.jam().to_vec()
}

#[cfg(not(feature = "std"))]
fn main() {
    eprintln!("error: this binary requires the `tx-types` `std` feature");
    std::process::exit(1);
}
