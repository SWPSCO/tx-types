use bs58;
use tx_types::crypto::cheetah::{master_from_seed, ser_a_pt, xprv_derive_child, XKey};
use tx_types::crypto::slip10::master::bip39_to_seed;

const MNEMONIC: &str = "around squeeze nerve chronic trophy kiwi enroll identify depth bicycle radio gate critic child claim outer detect plug market visual stuff finish crime abuse";
const TARGET_B58: &str = "32Mn83P3BDJiA8xXXTPh89zPghFa6GfdtHYTaKvELbnJirfxHRtiFDvzcbwPYNVzhXF68e735PHVMEbyCQ97kAnNocgvgKd8NEEpMQJxAnVzNG2SAAaDBqkd5La97gzsmmFP";

fn main() {
    let seed = bip39_to_seed(MNEMONIC, "").expect("seed");

    let mut bases: Vec<u32> = vec![
        0, 1, 2, 3, 4, 5, 32, 33, 44, 45, 57, 58, 60, 61, 62, 63, 64, 99, 1337,
    ];
    bases.sort();
    bases.dedup();

    let mut candidates = Vec::new();
    for b in bases {
        candidates.push(b);
        candidates.push(b | 0x8000_0000);
    }

    let mut current = Vec::new();
    for depth in 0..=5 {
        if let Some(path) = search(depth, &mut current, &candidates, &seed) {
            println!("found path: {}", path_to_string(&path));
            return;
        }
    }

    println!("no matches found");
}

fn search(
    remaining: usize,
    current: &mut Vec<u32>,
    candidates: &[u32],
    seed: &[u8; 64],
) -> Option<Vec<u32>> {
    if remaining == 0 {
        if path_matches(seed, current) {
            return Some(current.clone());
        }
        return None;
    }

    for &cand in candidates {
        current.push(cand);
        if let Some(path) = search(remaining - 1, current, candidates, seed) {
            return Some(path);
        }
        current.pop();
    }
    None
}

fn path_matches(seed: &[u8; 64], path: &[u32]) -> bool {
    let (sk, cc) = master_from_seed(seed);
    let mut xk = XKey::from_master(sk, cc);
    for &index in path {
        xk = xprv_derive_child(&xk, index);
    }
    if let Some(pk_xy) = xk.pk {
        let ser = ser_a_pt(&pk_xy);
        let b58 = bs58::encode(ser).into_string();
        b58 == TARGET_B58
    } else {
        false
    }
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
