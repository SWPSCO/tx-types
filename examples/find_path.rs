use bs58;
use tx_types::crypto::cheetah::{master_from_seed, ser_a_pt, xprv_derive_child, XKey};
use tx_types::crypto::slip10::master::bip39_to_seed;

const MNEMONIC: &str = "around squeeze nerve chronic trophy kiwi enroll identify depth bicycle radio gate critic child claim outer detect plug market visual stuff finish crime abuse";
const TARGET_B58: &str = "32bePYRuJ3heGVEbznc6xSCaTymgz9bGFREaZ2dtJdnepjc6RX7cMSP8ATeT8bHTfxFmS7StDTmFHfvt9GP1PUq99pN7DcEFat9SDBpQwJbnwmhn5JHcGpLsRKp4fxfHSRy5";

fn derive_path(seed: &[u8; 64], path: &[u32]) -> XKey {
    let (sk, cc) = master_from_seed(seed);
    let mut xk = XKey::from_master(sk, cc);
    for &index in path {
        xk = xprv_derive_child(&xk, index);
    }
    xk
}

fn path_to_string(path: &[u32]) -> String {
    let mut parts = vec!["m".to_string()];
    for &index in path {
        if index & 0x8000_0000 != 0 {
            parts.push(format!("{}'", index & 0x7fff_ffff));
        } else {
            parts.push(index.to_string());
        }
    }
    parts.join("/")
}

fn search(
    remaining: usize,
    current: &mut Vec<u32>,
    candidates: &[u32],
    seed: &[u8; 64],
    found_flag: &mut bool,
) {
    if *found_flag {
        return;
    }
    if remaining == 0 {
        let xk = derive_path(seed, current);
        if let Some(pk_xy) = xk.pk {
            let ser = ser_a_pt(&pk_xy);
            let b58 = bs58::encode(ser).into_string();
            if b58 == TARGET_B58 {
                println!("found path: {}", path_to_string(current));
                *found_flag = true;
            }
        }
        return;
    }

    for &cand in candidates {
        current.push(cand);
        search(remaining - 1, current, candidates, seed, found_flag);
        current.pop();
        if *found_flag {
            break;
        }
    }
}

fn main() {
    let seed = bip39_to_seed(MNEMONIC, "").expect("seed");

    let mut base_indices: Vec<u32> = (0..16).collect();
    base_indices.extend([32, 33, 44, 45, 60, 61, 62, 63, 64, 65, 99, 128, 1337, 2048]);
    let mut candidates = Vec::new();
    for val in base_indices {
        candidates.push(val);
        candidates.push(val | 0x8000_0000);
    }

    let mut found = false;
    let mut current = Vec::new();

    for depth in 0..=4 {
        search(depth, &mut current, &candidates, &seed, &mut found);
        if found {
            return;
        }
    }

    eprintln!("No matching path found in search range");
}
