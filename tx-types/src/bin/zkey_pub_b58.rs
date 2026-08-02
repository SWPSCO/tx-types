#[cfg(feature = "std")]
fn main() {
    use tx_types::crypto::slip10::ExtendedKey;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mode {
        MyNockKey,
        NockPubkey,
    }

    fn usage(bin_name: &str) -> ! {
        eprintln!("usage: {bin_name} [--my-nock-key|--nock-pubkey] <zprv|zpub>");
        eprintln!();
        eprintln!(
            "  --my-nock-key  Outputs base58 secret key bytes (for bridge `my_nock_key`) [default]"
        );
        eprintln!("  --nock-pubkey  Outputs base58 pubkey bytes (for bridge `nock_pubkey`)");
        std::process::exit(2);
    }

    let mut args = std::env::args();
    let bin_name = args.next().unwrap_or_else(|| "zkey_pub_b58".to_string());

    let mut mode = Mode::MyNockKey;
    let mut zkey: Option<String> = None;

    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => usage(&bin_name),
            "--my-nock-key" | "--sk" | "--secret" => mode = Mode::MyNockKey,
            "--nock-pubkey" | "--pub" | "--pubkey" => mode = Mode::NockPubkey,
            _ if zkey.is_none() => zkey = Some(arg),
            _ => usage(&bin_name),
        }
    }

    let Some(zkey) = zkey else {
        usage(&bin_name);
    };

    let key = match ExtendedKey::from_extended_key_string(&zkey) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };

    match mode {
        Mode::MyNockKey => {
            let Some(sk) = key.private_key else {
                eprintln!("error: need a `zprv...` (zpub has no private key)");
                std::process::exit(1);
            };
            println!("{}", bs58::encode(sk).into_string());
        }
        Mode::NockPubkey => {
            if key.public_key.inf {
                eprintln!("error: public key is point-at-infinity");
                std::process::exit(1);
            }

            let [x_coords, y_coords] = key.public_key.to_coordinates();
            let mut bytes = Vec::with_capacity(97);
            bytes.push(0x01);
            for limb in y_coords.into_iter().rev() {
                bytes.extend_from_slice(&limb.to_be_bytes());
            }
            for limb in x_coords.into_iter().rev() {
                bytes.extend_from_slice(&limb.to_be_bytes());
            }

            println!("{}", bs58::encode(bytes).into_string());
        }
    }
}

#[cfg(not(feature = "std"))]
fn main() {
    eprintln!("error: this binary requires the `tx-types` `std` feature");
    std::process::exit(1);
}
