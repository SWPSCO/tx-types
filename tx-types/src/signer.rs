#![cfg_attr(not(test), no_std)]

extern crate alloc;

use crate::crypto::cheetah::point::cheetah_pub_from_sk;
use crate::crypto::utils::{
    add_mod_n, be32_atom_to_t8_le, be32_lt, is_zero32, mul_mod_n, trunc_g_order_to_be32, CHEETAH_N,
};
use crate::hashing::tip5::Tip5Hasher;
use crate::transaction_types::{
    Chal, Coins, Hash, Input, Inputs, NName, RawTransaction, SchnorrPubkey, SchnorrSignature, Sig,
    Signature, Spend, T8,
};
use nockapp::noun::slab::NounSlab;
use nockvm::noun::Cell;

/// Sign a TIP-5 digest with Schnorr over Cheetah, Hoon-compatible
/// Uses proper transaction types: T8 for secret keys, SchnorrPubkey for public keys, Hash for messages
///
/// - R = k·G  (k from TIP5 transcript hashing)  
/// - chal = trunc_g_order( TIP5([xR,yR,xP,yP,m]) )
/// - s = (k + chal*sk) mod n
/// - return chal/s as T8 (little-endian limbs)
///
/// Note: this function is the analogue of sign:affine:belt-schnorr:cheetah nockchain/ztd/three.hoon:1799
pub fn schnorr_sign_digest(secret_key: T8, public_key: SchnorrPubkey, message: Hash) -> (T8, T8) {
    // Hoon-compatible Schnorr signature implementation
    // Matches sign:affine:schnorr in three.hoon line 1628

    // Validate each T8 component is < 2^32 (matches Hoon line 1634)
    // ?>  (levy sk-as-32-bit-belts |=(n=@ (lth n b-32)))
    for (i, &limb) in secret_key.values.iter().enumerate() {
        if limb >= (1u64 << 32) {
            panic!(
                "Secret key T8 component {} ({:#x}) must be less than 2^32",
                i, limb
            );
        }
    }

    // Convert T8 to 32-byte big-endian for arithmetic operations
    let sk_be = t8_to_be32(&secret_key);

    // Validate that secret key represents a valid scalar < curve order (line 1637)
    if !be32_lt(&sk_be, &CHEETAH_N) {
        panic!("Secret key must be less than curve order");
    }

    // 1) Generate nonce using TIP5(pubkey || message) - matches Hoon line 1639-1642
    // Create transcript list: [x.pubkey y.pubkey message ~]
    let nonce_digest = hash_transcript_list(&[
        &public_key.x.values[..], // 6 elements
        &public_key.y.values[..], // 6 elements
        &message.values[..],      // 5 elements
    ])
    .unwrap_or_else(|_| Hash { values: [0; 5] });

    let nonce_be = trunc_g_order_to_be32(nonce_digest.values);

    // Verify nonce != 0 (line 1643)
    if is_zero32(&nonce_be) {
        panic!("Generated nonce is zero"); // Should be extremely rare
    }

    // 2) Compute R = nonce × G (line 1644)
    let r_pt = cheetah_pub_from_sk(nonce_be);

    // 3) Generate challenge using TIP5([R, pubkey, message]) - matches Hoon line 1645-1647
    // Create transcript list: [x.R y.R x.pubkey y.pubkey message ~]
    let chal_digest = hash_transcript_list(&[
        &r_pt[0],                 // R.x (6 elements)
        &r_pt[1],                 // R.y (6 elements)
        &public_key.x.values[..], // pubkey.x (6 elements)
        &public_key.y.values[..], // pubkey.y (6 elements)
        &message.values[..],      // message (5 elements)
    ])
    .unwrap_or_else(|_| Hash { values: [0; 5] });
    let chal_be = trunc_g_order_to_be32(chal_digest.values);

    // Verify challenge != 0 (line 1648)
    if is_zero32(&chal_be) {
        panic!("Generated challenge is zero"); // Should be extremely rare
    }

    // 4) Compute signature s = (nonce + challenge × sk) mod n - matches Hoon line 1649-1652
    let chal_times_sk = mul_mod_n(&chal_be, &sk_be);
    let s_be = add_mod_n(&nonce_be, &chal_times_sk);

    // Verify signature != 0 (line 1653)
    if is_zero32(&s_be) {
        panic!("Generated signature is zero"); // Should be extremely rare
    }

    // 5) Convert challenge and signature to T8 format for return
    let chal_t8 = be32_atom_to_t8_le(&chal_be);
    let sig_t8 = be32_atom_to_t8_le(&s_be);

    (chal_t8, sig_t8)
}

/// Convert T8 to 32-byte big-endian array
fn t8_to_be32(t8: &T8) -> [u8; 32] {
    let mut result = [0u8; 32];
    // T8 stores 8 limbs in little-endian order, each limb is 32 bits
    for i in 0..8 {
        let limb = t8.values[i] as u32;
        let bytes = limb.to_le_bytes();
        // Place in big-endian position: bytes for limb i go to positions [28-4*i..32-4*i]
        for j in 0..4 {
            result[31 - (i * 4 + j)] = bytes[j];
        }
    }
    result
}

/// Hash a transcript list using TIP5 with proper Hoon list structure
fn hash_transcript_list(
    element_arrays: &[&[u64]],
) -> Result<Hash, crate::hashing::tip5::Tip5Error> {
    let mut slab: NounSlab<nockvm::noun::IndirectAtom> = NounSlab::new();

    // Flatten all elements into a single list
    let mut all_elements = Vec::new();
    for array in element_arrays {
        all_elements.extend_from_slice(array);
    }

    // Build Hoon list structure: [a [b [c [d ... 0]]]]
    let mut list = nockvm::noun::Atom::new(&mut slab, 0).as_noun(); // Start with nil (0)

    // Build list in reverse order (right-associative)
    for &element in all_elements.iter().rev() {
        let atom = nockvm::noun::Atom::new(&mut slab, element).as_noun();
        list = Cell::new(&mut slab, atom, list).as_noun();
    }

    // Hash the list using TIP5
    Tip5Hasher::hash_varlen(list)
}

/// Sign a Spend structure using Schnorr signature
///
/// Takes a Spend, computes its sig_hash, and signs it with the provided keys
/// Returns the signature components (challenge, signature) as T8 values
pub fn sign_spend(spend: Spend, secret_key: T8, public_key: SchnorrPubkey) -> (T8, T8) {
    // Get the sig_hash of the spend (this uses sig_hashable for seeds)
    let message = spend.sig_hash();

    // Sign the hash with Schnorr
    schnorr_sign_digest(secret_key, public_key, message)
}

/// Sign a RawTransaction by signing all spends within it
///
/// Takes a RawTransaction and a secret key, signs all spends in the inputs,
/// and returns a new RawTransaction with signatures and updated transaction ID
pub fn sign_tx(mut tx: RawTransaction, secret_key: T8) -> RawTransaction {
    use crate::collections::zmap::ZMap;
    use crate::hashing::tx_id::compute_tx_id;

    // Derive public key from secret key
    let secret_key_be = t8_to_be32(&secret_key);
    let pk_coords = cheetah_pub_from_sk(secret_key_be);
    let public_key = SchnorrPubkey {
        x: crate::transaction_types::F6LT {
            values: pk_coords[0],
        },
        y: crate::transaction_types::F6LT {
            values: pk_coords[1],
        },
        inf: false,
    };

    // Create a new inputs map with signed spends
    let mut new_inputs = ZMap::new();

    // Iterate through each input and sign its spend
    for (name, input) in tx.inputs.p.tap() {
        let mut signed_input = input.clone();

        // Sign the spend if it doesn't already have a signature
        if signed_input.spend.signature.is_none() {
            let (challenge, sig_s) = sign_spend(
                signed_input.spend.clone(),
                secret_key.clone(),
                public_key.clone(),
            );

            // Create the SchnorrSignature
            let schnorr_sig = SchnorrSignature {
                chal: Chal { values: challenge },
                sig: Sig { values: sig_s },
            };

            // Create the Signature map with our pubkey and signature
            let mut sig_map = ZMap::new();
            sig_map.put(public_key.clone(), schnorr_sig);

            // Set the signature on the spend
            signed_input.spend.signature = Some(Signature { map: sig_map });
        }

        // Add the signed input to the new map
        new_inputs.put(name.clone(), signed_input);
    }

    // Update the transaction with signed inputs
    tx.inputs = Inputs { p: new_inputs };

    // Recalculate the transaction ID with the signed inputs
    tx.id = compute_tx_id(&tx.inputs, &tx.timelock_range, tx.total_fees);

    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_sign_digest() {
        // Test vectors from Hoon with T8 format secret key

        // Secret key as T8 (8 x u32 values, stored as u64)
        // [ 0xbbbb.cccc, 0x9999.aaaa, 0x7777.8888, 0x5555.6666,
        //   0x3333.4444, 0x1111.2222, 0x9abc.def0, 0x1234.5678 ]
        // This is already in T8 format (8 limbs, LSW first)
        // Need to convert to 32-byte big-endian for signing
        let secret_key_t8 = T8 {
            values: [
                0xbbbb_cccc, // Per comment: LSW first
                0x9999_aaaa,
                0x7777_8888,
                0x5555_6666,
                0x3333_4444,
                0x1111_2222,
                0x9abc_def0,
                0x1234_5678, // Per comment: MSW last
            ],
        };

        // Derive public key from secret key (for conversion)
        let secret_key_be = t8_to_be32(&secret_key_t8);
        let pk_coords = cheetah_pub_from_sk(secret_key_be);

        // Create SchnorrPubkey from coordinates
        let public_key = SchnorrPubkey {
            x: crate::transaction_types::F6LT {
                values: pk_coords[0],
            },
            y: crate::transaction_types::F6LT {
                values: pk_coords[1],
            },
            inf: false,
        };

        // Message: [i=1 t=[i=2 t=~[3 4 5]]]
        // This represents a list [1, 2, 3, 4, 5] as 5 u64 values
        let message = Hash {
            values: [1, 2, 3, 4, 5],
        };

        // Expected challenge as T8
        let expected_challenge: [u64; 8] = [
            0x3646_19a6, // LSW
            0x6af9_178c,
            0x46e4_7b17,
            0xf860_9591,
            0xf4c6_b69a,
            0x1a51_1b32,
            0xd7e5_6411,
            0x2f51_9cb9, // MSW
        ];

        // Expected signature as T8
        let expected_signature: [u64; 8] = [
            0x0918_903a, // LSW (note: 0x918.903a with leading zero)
            0x0e94_f5a7, // 0xe94.f5a7 with leading zero
            0x34d7_585a,
            0xb809_abfe,
            0x5575_3257,
            0x5b73_fced,
            0x4ac8_fd17,
            0x21b7_0dda, // MSW
        ];

        // Sign the message
        let (challenge, signature) = schnorr_sign_digest(secret_key_t8, public_key, message);

        // Debug output to help diagnose mismatches
        println!("\nGenerated challenge: {:016x?}", challenge.values);
        println!("Expected challenge:  {:016x?}", expected_challenge);
        println!("\nGenerated signature: {:016x?}", signature.values);
        println!("Expected signature:  {:016x?}", expected_signature);

        // Verify challenge matches
        assert_eq!(
            challenge.values, expected_challenge,
            "Challenge should match Hoon output"
        );

        // Verify signature matches
        assert_eq!(
            signature.values, expected_signature,
            "Signature should match Hoon output"
        );

        println!("✓ schnorr_sign_digest with T8 key produces expected results!");
    }

    #[test]
    fn test_hash_transcript_list() {
        // Test hashing the numbers [1, 2, 3, 0] as a transcript list
        let numbers = [1u64, 2u64, 3u64, 0u64];
        let element_arrays: &[&[u64]] = &[&numbers];

        let result = hash_transcript_list(element_arrays);

        match result {
            Ok(hash) => {
                println!("hash_transcript_list([1, 2, 3, 0]) = {:x?}", hash.values);

                // Verify it produces a valid hash (5 u64 values)
                assert_eq!(hash.values.len(), 5);

                // The hash should be deterministic - calling again should produce same result
                let result2 = hash_transcript_list(element_arrays).unwrap();
                assert_eq!(hash.values, result2.values, "Hash should be deterministic");

                println!("✓ hash_transcript_list produces deterministic hash for [1, 2, 3, 0]");
            }
            Err(e) => {
                panic!("hash_transcript_list failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_hash_transcript_list_simple() {
        // Test hashing the numbers [1, 2, 3] as a transcript list
        let numbers = [1u64, 2u64, 3u64];
        let element_arrays: &[&[u64]] = &[&numbers];

        let result = hash_transcript_list(element_arrays);

        match result {
            Ok(hash) => {
                println!("hash_transcript_list([1, 2, 3]) = {:x?}", hash.values);

                // Verify it produces a valid hash (5 u64 values)
                assert_eq!(hash.values.len(), 5);

                // The hash should be deterministic - calling again should produce same result
                let result2 = hash_transcript_list(element_arrays).unwrap();
                assert_eq!(hash.values, result2.values, "Hash should be deterministic");

                println!("✓ hash_transcript_list produces deterministic hash for [1, 2, 3]");
            }
            Err(e) => {
                panic!("hash_transcript_list failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_sign_spend() {
        use crate::collections::zset::ZSet;
        use crate::transaction_types::{Coins, Lock, Seed, Seeds, Source, Spend, TimelockIntent};

        // Create a test seed
        let seed = Seed {
            output_source: Some(Source {
                p: Hash {
                    values: [1, 2, 3, 4, 5],
                },
                is_coinbase: false,
            }),
            recipient: Lock {
                m: 1,
                pubkeys: ZSet::new(),
            },
            timelock_intent: None,
            gift: Coins { value: 100 },
            parent_hash: Hash {
                values: [10, 11, 12, 13, 14],
            },
        };

        // Create seeds set
        let mut seeds_set = ZSet::new();
        seeds_set.put(seed);

        // Create spend
        let spend = Spend {
            signature: None,
            seeds: Seeds { set: seeds_set },
            fee: Coins { value: 10 },
        };

        // Test secret key
        let secret_key = T8 {
            values: [
                0xbbbb_cccc,
                0x9999_aaaa,
                0x7777_8888,
                0x5555_6666,
                0x3333_4444,
                0x1111_2222,
                0x9abc_def0,
                0x1234_5678,
            ],
        };

        // Derive public key from secret key
        let secret_key_be = t8_to_be32(&secret_key);
        let pk_coords = crate::crypto::cheetah::point::cheetah_pub_from_sk(secret_key_be);
        let public_key = SchnorrPubkey {
            x: crate::transaction_types::F6LT {
                values: pk_coords[0],
            },
            y: crate::transaction_types::F6LT {
                values: pk_coords[1],
            },
            inf: false,
        };

        // Sign the spend
        let (challenge, signature) =
            sign_spend(spend.clone(), secret_key.clone(), public_key.clone());

        // Verify we got non-zero values
        assert!(
            !challenge.values.iter().all(|&v| v == 0),
            "Challenge should not be all zeros"
        );
        assert!(
            !signature.values.iter().all(|&v| v == 0),
            "Signature should not be all zeros"
        );

        println!("✓ sign_spend produces valid signature");
        println!("  Challenge: {:016x?}", challenge.values);
        println!("  Signature: {:016x?}", signature.values);

        // Sign the same spend again to verify deterministic
        let (challenge2, signature2) = sign_spend(spend, secret_key, public_key);
        assert_eq!(challenge, challenge2, "Signatures should be deterministic");
        assert_eq!(signature, signature2, "Signatures should be deterministic");

        println!("✓ sign_spend is deterministic");
    }

    #[test]
    fn test_sign_spend_with_details() {
        use crate::collections::zset::ZSet;
        use crate::transaction_types::{
            Coins, Lock, PageNumber, Seed, Seeds, Source, Spend, TimelockRange,
        };

        println!("\n=== Comprehensive Spend Signing Test ===\n");

        // 1. Create an arbitrary secret key (must be less than curve order)
        let secret_key = T8 {
            values: [
                0x1234_5678, // LSW first
                0x9ABC_DEF0,
                0x1357_9BDF,
                0x2468_ACE0,
                0x369C_F147,
                0x258B_E047,
                0x147A_D036,
                0x0369_CF14, // MSW last - small enough to be < curve order
            ],
        };

        println!("Secret Key (T8 format):");
        println!(
            "  LSW -> MSW: {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
            secret_key.values[0],
            secret_key.values[1],
            secret_key.values[2],
            secret_key.values[3],
            secret_key.values[4],
            secret_key.values[5],
            secret_key.values[6],
            secret_key.values[7]
        );

        // Convert to big-endian for display
        let secret_key_be = t8_to_be32(&secret_key);
        println!(
            "  As hex: 0x{}",
            secret_key_be
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        // 2. Calculate public key from secret key
        let pk_coords = crate::crypto::cheetah::point::cheetah_pub_from_sk(secret_key_be);
        let public_key = SchnorrPubkey {
            x: crate::transaction_types::F6LT {
                values: pk_coords[0],
            },
            y: crate::transaction_types::F6LT {
                values: pk_coords[1],
            },
            inf: false,
        };

        println!("\nPublic Key (derived from secret key):");
        println!("  x: {:016x?}", public_key.x.values);
        println!("  y: {:016x?}", public_key.y.values);

        // 3. Create an arbitrary Spend structure with multiple seeds
        let seed1 = Seed {
            output_source: Some(Source {
                p: Hash {
                    values: [100, 200, 300, 400, 500],
                },
                is_coinbase: false,
            }),
            recipient: Lock {
                m: 2, // 2-of-3 multisig
                pubkeys: {
                    let mut pks = ZSet::new();
                    // Add some dummy pubkeys for testing
                    pks.put(SchnorrPubkey {
                        x: crate::transaction_types::F6LT {
                            values: [1, 2, 3, 4, 5, 6],
                        },
                        y: crate::transaction_types::F6LT {
                            values: [7, 8, 9, 10, 11, 12],
                        },
                        inf: false,
                    });
                    pks.put(SchnorrPubkey {
                        x: crate::transaction_types::F6LT {
                            values: [13, 14, 15, 16, 17, 18],
                        },
                        y: crate::transaction_types::F6LT {
                            values: [19, 20, 21, 22, 23, 24],
                        },
                        inf: false,
                    });
                    pks.put(SchnorrPubkey {
                        x: crate::transaction_types::F6LT {
                            values: [25, 26, 27, 28, 29, 30],
                        },
                        y: crate::transaction_types::F6LT {
                            values: [31, 32, 33, 34, 35, 36],
                        },
                        inf: false,
                    });
                    pks
                },
            },
            timelock_intent: Some((
                TimelockRange {
                    min: Some(PageNumber { value: 1000 }),
                    max: Some(PageNumber { value: 2000 }),
                }, // absolute
                TimelockRange {
                    min: None,
                    max: None,
                }, // relative (no restrictions)
            )),
            gift: Coins { value: 5000 },
            parent_hash: Hash {
                values: [0xAABBCCDD, 0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00],
            },
        };

        let seed2 = Seed {
            output_source: None, // No output source for this seed
            recipient: Lock {
                m: 1, // Simple 1-of-1
                pubkeys: {
                    let mut pks = ZSet::new();
                    pks.put(public_key.clone()); // Use our derived pubkey
                    pks
                },
            },
            timelock_intent: None,
            gift: Coins { value: 3000 },
            parent_hash: Hash {
                values: [0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0, 0x369CF147],
            },
        };

        // Create seeds set
        let mut seeds_set = ZSet::new();
        seeds_set.put(seed1.clone());
        seeds_set.put(seed2.clone());

        // Create spend with fee
        let spend = Spend {
            signature: None, // No signature yet
            seeds: Seeds { set: seeds_set },
            fee: Coins { value: 250 },
        };

        println!("\nSpend Structure:");
        println!("  Number of seeds: 2");
        println!("  Fee: {} nicks", spend.fee.value);
        println!("\n  Seed 1:");
        println!(
            "    Output source: {:?}",
            seed1
                .output_source
                .as_ref()
                .map(|s| format!("Hash: {:x?}", s.p.values))
        );
        println!("    Recipient: {}-of-3 multisig", seed1.recipient.m);
        println!("    Timelock intent: {:?}", seed1.timelock_intent);
        println!("    Gift: {} nicks", seed1.gift.value);
        println!("    Parent hash: {:08x?}", seed1.parent_hash.values);
        println!("\n  Seed 2:");
        println!("    Output source: None");
        println!(
            "    Recipient: {}-of-1 (using our pubkey)",
            seed2.recipient.m
        );
        println!("    Timelock intent: {:?}", seed2.timelock_intent);
        println!("    Gift: {} nicks", seed2.gift.value);
        println!("    Parent hash: {:08x?}", seed2.parent_hash.values);

        // 4. Calculate the sig_hash that will be signed
        let sig_hash = spend.sig_hash();
        println!("\nSig Hash (message to be signed):");
        println!("  {:016x?}", sig_hash.values);

        // 5. Sign the spend
        let (challenge, signature) = sign_spend(spend, secret_key, public_key);

        println!("\nResulting Signature:");
        println!("  Challenge (T8):");
        println!("    {:016x?}", challenge.values);
        println!("  Signature s (T8):");
        println!("    {:016x?}", signature.values);

        // Verify the signature components are valid
        assert!(
            !challenge.values.iter().all(|&v| v == 0),
            "Challenge should not be all zeros"
        );
        assert!(
            !signature.values.iter().all(|&v| v == 0),
            "Signature should not be all zeros"
        );

        println!("\n✓ Successfully signed spend with arbitrary key and structure");
    }

    #[test]
    fn test_sign_tx() {
        use crate::collections::zmap::ZMap;
        use crate::collections::zset::ZSet;
        use crate::transaction_types::{
            Coins, Input, Inputs, Lock, NNote, NNoteHead, PageNumber, RawTransaction, Seed, Seeds,
            Source, Spend, Timelock, TimelockRange,
        };

        println!("\n=== Test sign_tx Function ===\n");

        // Create a test secret key
        let secret_key = T8 {
            values: [
                0x1234_5678,
                0x9ABC_DEF0,
                0x1357_9BDF,
                0x2468_ACE0,
                0x369C_F147,
                0x258B_E047,
                0x147A_D036,
                0x0369_CF14,
            ],
        };

        // Create test inputs
        let mut inputs_map = ZMap::new();

        // Create a test input with a spend that needs signing
        let seed = Seed {
            output_source: None,
            recipient: Lock {
                m: 1,
                pubkeys: ZSet::new(),
            },
            timelock_intent: None,
            gift: Coins { value: 1000 },
            parent_hash: Hash {
                values: [1, 2, 3, 4, 5],
            },
        };

        let mut seeds_set = ZSet::new();
        seeds_set.put(seed);

        let spend = Spend {
            signature: None, // No signature yet
            seeds: Seeds { set: seeds_set },
            fee: Coins { value: 10 },
        };

        let input = Input {
            note: NNote {
                meta: NNoteHead {
                    version: 1,
                    origin_page: PageNumber { value: 1 },
                    timelock: crate::transaction_types::Timelock { intent: None },
                },
                name: crate::transaction_types::NName {
                    p: vec![Hash {
                        values: [1, 0, 0, 0, 0],
                    }],
                },
                lock: Lock {
                    m: 1,
                    pubkeys: ZSet::new(),
                },
                source: Source {
                    p: Hash { values: [0; 5] },
                    is_coinbase: false,
                },
                assets: Coins { value: 1000 },
            },
            spend,
        };

        let name = crate::transaction_types::NName {
            p: vec![Hash {
                values: [1, 0, 0, 0, 0],
            }],
        };
        inputs_map.put(name, input);

        // Create the raw transaction
        let tx = RawTransaction {
            id: Hash { values: [0; 5] }, // Will be recalculated
            inputs: Inputs { p: inputs_map },
            timelock_range: TimelockRange {
                min: None,
                max: None,
            },
            total_fees: Coins { value: 10 },
        };

        println!("Original TX ID: {:016x?}", tx.id.values);

        // Sign the transaction
        let signed_tx = sign_tx(tx, secret_key);

        println!("Signed TX ID: {:016x?}", signed_tx.id.values);

        // Verify that signatures were added
        let signed_inputs = signed_tx.inputs.p.tap();
        assert!(!signed_inputs.is_empty(), "Should have inputs");

        for (name, input) in signed_inputs {
            assert!(
                input.spend.signature.is_some(),
                "Input {:?} should have a signature",
                name
            );

            if let Some(sig) = &input.spend.signature {
                let sigs = sig.map.tap();
                assert!(!sigs.is_empty(), "Signature map should not be empty");

                println!("Input {:?} has {} signature(s)", name, sigs.len());
                for (pubkey, schnorr_sig) in sigs {
                    println!("  Pubkey x[0]: {:016x}", pubkey.x.values[0]);
                    println!("  Challenge[0]: {:016x}", schnorr_sig.chal.values.values[0]);
                    println!("  Signature[0]: {:016x}", schnorr_sig.sig.values.values[0]);
                }
            }
        }

        // Verify the transaction ID changed (due to signatures being added)
        assert_ne!(
            signed_tx.id.values, [0; 5],
            "Transaction ID should have been recalculated"
        );

        println!("\n✓ Successfully signed transaction with sign_tx");
    }
}
