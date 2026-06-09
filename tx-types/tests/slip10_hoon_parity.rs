//! Cross-implementation parity for SLIP10-over-Cheetah child derivation.
//!
//! The no_std implementation (`crypto::cheetah_nostd`) is the byte-level
//! mirror of the Hoon slip10 (ser-p unhardened input, 0x01||IR||i retry) and
//! is what the Nockster firmware runs. The std `ExtendedKey` path historically
//! diverged for unhardened derivation. Both cfgs of this test assert the same
//! hard-coded vectors, so any future drift on either side fails CI.

fn seed() -> [u8; 64] {
    core::array::from_fn(|i| i as u8)
}

const UNHARDENED_INDEX: u32 = 5;
const HARDENED_INDEX: u32 = (1 << 31) + 7;

// Expected vectors, generated from the no_std (firmware/Hoon-parity)
// implementation. Regenerate with:
//   cargo test -p tx-types --no-default-features --test slip10_hoon_parity -- --nocapture
const MASTER_SK_HEX: &str = "5ea36e7387f34244fd9930bcc3b5ea495e5d6f78ec4fa9c04722a530e9d03bd1";
const MASTER_CC_HEX: &str = "c8d2d73134c8d510bf6d5e01810291109ad9e263ff4f9bf90a3d5931c6914c7a";
const CHILD_U5_SK_HEX: &str = "2078c6630944a13dc6c426150962ed44a205758703b4abf41c188841dafe4dd3";
const CHILD_U5_CC_HEX: &str = "a2bee59203b607f7d999aeed57df469c45484e7d16263a9ab962043f77f85abe";
const CHILD_H7_SK_HEX: &str = "4d0a3597ddd7a7fa5d31793fd74f9f52cfefa73434ba4357b8b6311bf32266f1";
const CHILD_H7_CC_HEX: &str = "a320ea6501d8800be0a1d84ff69c5953bd3fddbb858d17e7310b7bf905fd4064";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(not(feature = "std"))]
mod nostd_side {
    use super::*;
    use tx_types::crypto::{master_from_seed, xprv_derive_child, xpub_derive_child, XKey};

    #[test]
    fn nostd_matches_pinned_vectors() {
        let (sk, cc) = master_from_seed(&seed());
        println!("MASTER_SK {}", hex(&sk));
        println!("MASTER_CC {}", hex(&cc));
        let master = XKey::from_master(sk, cc);

        let child_u = xprv_derive_child(&master, UNHARDENED_INDEX);
        println!("CHILD_U5_SK {}", hex(&child_u.sk.unwrap()));
        println!("CHILD_U5_CC {}", hex(&child_u.chain_code));

        let child_h = xprv_derive_child(&master, HARDENED_INDEX);
        println!("CHILD_H7_SK {}", hex(&child_h.sk.unwrap()));
        println!("CHILD_H7_CC {}", hex(&child_h.chain_code));

        // Watch-only derivation must agree with private derivation.
        let mut pub_only = master.clone();
        pub_only.sk = None;
        let child_pub = xpub_derive_child(&pub_only, UNHARDENED_INDEX);
        assert_eq!(child_pub.pk, child_u.pk, "public CKD diverges from private CKD");

        assert_eq!(hex(&sk), MASTER_SK_HEX);
        assert_eq!(hex(&cc), MASTER_CC_HEX);
        assert_eq!(hex(&child_u.sk.unwrap()), CHILD_U5_SK_HEX);
        assert_eq!(hex(&child_u.chain_code), CHILD_U5_CC_HEX);
        assert_eq!(hex(&child_h.sk.unwrap()), CHILD_H7_SK_HEX);
        assert_eq!(hex(&child_h.chain_code), CHILD_H7_CC_HEX);
    }
}

#[cfg(feature = "std")]
mod std_side {
    use super::*;
    use tx_types::crypto::ExtendedKey;

    #[test]
    fn std_matches_pinned_vectors() {
        let master = ExtendedKey::from_seed(&seed(), 1).expect("master");
        println!("MASTER_SK {}", hex(&master.private_key.unwrap()));
        println!("MASTER_CC {}", hex(&master.chain_code));

        let child_u = master.derive_child(UNHARDENED_INDEX).expect("child u5");
        println!("CHILD_U5_SK {}", hex(&child_u.private_key.unwrap()));
        println!("CHILD_U5_CC {}", hex(&child_u.chain_code));

        let child_h = master.derive_child(HARDENED_INDEX).expect("child h7");
        println!("CHILD_H7_SK {}", hex(&child_h.private_key.unwrap()));
        println!("CHILD_H7_CC {}", hex(&child_h.chain_code));

        // Watch-only derivation must agree with private derivation.
        let mut pub_only = master.clone();
        pub_only.private_key = None;
        let child_pub = pub_only.derive_child(UNHARDENED_INDEX).expect("pub child");
        assert_eq!(
            child_pub.public_key.to_coordinates(),
            child_u.public_key.to_coordinates(),
            "public CKD diverges from private CKD"
        );

        assert_eq!(hex(&master.private_key.unwrap()), MASTER_SK_HEX);
        assert_eq!(hex(&master.chain_code), MASTER_CC_HEX);
        assert_eq!(hex(&child_u.private_key.unwrap()), CHILD_U5_SK_HEX);
        assert_eq!(hex(&child_u.chain_code), CHILD_U5_CC_HEX);
        assert_eq!(hex(&child_h.private_key.unwrap()), CHILD_H7_SK_HEX);
        assert_eq!(hex(&child_h.chain_code), CHILD_H7_CC_HEX);
    }
}
