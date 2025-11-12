use tx_types::collections::ZSet;
use tx_types::hashing::hasher::hash_hashable;
use tx_types::transaction_types::{Hash, NName};
use tx_types::transaction_types_v1::{LockPrimitive, LockPrimitiveBody, Pkh, SpendCondition};

/// Verify that we can recreate the v1 note first name for a 1-of-1 PKH lock
/// from only the public key string that appears in wallet UIs.
#[test]
fn reproduces_first_name_for_single_signer_lock() {
    // This pubkey appears in the provided note description.
    let signer_b58 = "4Lu3cSW34WPwvDkTwKh7xB6yMZrvh3bFW7w26UDJVdboxADGkr2bTnL";
    let signer_hash = Hash::from_b58(signer_b58).expect("valid pubkey hash");

    // Hash the pubkey and drop it into a 1-of-1 PKH lock.
    let mut hashed_pubkeys = ZSet::new();
    hashed_pubkeys.put(signer_hash);

    let lock = SpendCondition {
        p: vec![LockPrimitive {
            header: "pkh".to_string(),
            body: LockPrimitiveBody::Pkh(Pkh { m: 1, h: hashed_pubkeys }),
        }],
    };

    let lock_root = hash_hashable(&lock.to_hashable());
    // The first component of the note name is just the hash of the lock root.
    let first_name = NName::first_v1(lock_root);

    assert_eq!(
        first_name.to_b58(),
        "4rAzFxcSirx2YWB8ZUrddeAtELH5gE43s1kFpUhErGVX61F7oJ5VcPU"
    );
}
