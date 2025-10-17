#![cfg_attr(not(test), no_std)]

extern crate alloc;

use crate::transaction_types::{Hash, T8, SchnorrPubkey, Signature, SchnorrSignature, Chal, Sig, RawTransaction, Inputs, NName, Coins, Spend};
use crate::transaction_types_v0::{InputsV0, InputV0, SpendV0};
use crate::crypto::cheetah::point::cheetah_pub_from_sk;
use crate::crypto::utils::{
    trunc_g_order_to_be32,
    is_zero32,
    mul_mod_n,
    add_mod_n,
    be32_atom_to_t8_le,
    be32_lt,
    CHEETAH_N,
    t8_to_be32,
};
use crate::hashing::hasher::hash_transcript_list;

/// Sign a TIP-5 digest with Schnorr over Cheetah, Hoon-compatible
/// Uses proper transaction types: T8 for secret keys, SchnorrPubkey for public keys, Hash for messages
/// 
/// - R = k·G  (k from TIP5 transcript hashing)  
/// - chal = trunc_g_order( TIP5([xR,yR,xP,yP,m]) )
/// - s = (k + chal*sk) mod n
/// - return chal/s as T8 (little-endian limbs)
/// 
/// Note: this function is the analogue of sign:affine:belt-schnorr:cheetah 
/// on line 1799 in nockchain/ztd/three.hoon
pub fn schnorr_sign_digest(
  secret_key: T8,
  public_key: SchnorrPubkey, 
  message: Hash,
) -> (T8, T8) {
  // Hoon-compatible Schnorr signature implementation
  // Matches sign:affine:schnorr in three.hoon line 1628

  // Validate each T8 component is < 2^32 (matches Hoon line 1634)
  // ?>  (levy sk-as-32-bit-belts |=(n=@ (lth n b-32)))
  for (i, &limb) in secret_key.values.iter().enumerate() {
    if limb >= (1u64 << 32) {
      panic!("Secret key T8 component {} ({:#x}) must be less than 2^32", i, limb);
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
    &public_key.x.values[..],  // 6 elements  
    &public_key.y.values[..],  // 6 elements
    &message.values[..],       // 5 elements  
  ]).unwrap_or_else(|_| Hash { values: [0; 5] });
  
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
    &r_pt[0],                  // R.x (6 elements)
    &r_pt[1],                  // R.y (6 elements)  
    &public_key.x.values[..],  // pubkey.x (6 elements)
    &public_key.y.values[..],  // pubkey.y (6 elements)
    &message.values[..],       // message (5 elements)
  ]).unwrap_or_else(|_| Hash { values: [0; 5] });
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

/// Sign a Spend structure using Schnorr signature
/// 
/// Takes a Spend, computes its sig_hash, and signs it with the provided keys
/// Returns the signature components (challenge, signature) as T8 values
pub fn sign_spend(
    spend: SpendV0,
    secret_key: T8,
    public_key: SchnorrPubkey,
) -> (T8, T8) {
    // Get the sig_hash of the spend (this uses sig_hashable for seeds)
    let message = spend.sig_hash();
    
    // Sign the hash with Schnorr
    schnorr_sign_digest(secret_key, public_key, message)
}

/// Sign a RawTransaction by signing all spends within it
///
/// Takes a RawTransaction and a secret key, signs all spends in the inputs,
/// and returns a new RawTransaction with signatures and updated transaction ID
pub fn sign_tx(
    mut tx: RawTransaction,
    secret_key: T8,
) -> RawTransaction {
    use crate::collections::zmap::ZMap;
    use crate::hashing::tx_id::compute_tx_id;
    
    // Derive public key from secret key
    let secret_key_be = t8_to_be32(&secret_key);
    let pk_coords = cheetah_pub_from_sk(secret_key_be);
    let public_key = SchnorrPubkey {
        x: crate::transaction_types::F6LT { values: pk_coords[0] },
        y: crate::transaction_types::F6LT { values: pk_coords[1] },
        inf: false,
    };
    
    // Create a new inputs map with signed spends
    let mut new_inputs = ZMap::new();
    
    // Iterate through each input and sign its spend
    let mut inputs_handle = match &mut tx {
        RawTransaction::V0(v0) => &mut v0.inputs,
        _ => panic!("sign_tx placeholder only supports V0"),
    };
    for (name, input) in inputs_handle.p.tap() {
        let mut signed_input = input.clone();
        
        // Sign the spend if it doesn't already have a signature
        if signed_input.spend.signature.is_none() {
            let (challenge, sig_s) = sign_spend(
                signed_input.spend.clone(),
                secret_key.clone(),
                public_key.clone()
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
            signed_input.spend.signature = Some(Signature {
                map: sig_map,
            });
        }
        
        // Add the signed input to the new map
        new_inputs.put(name.clone(), signed_input);
    }
    
    // Update the transaction with signed inputs
    if let RawTransaction::V0(v0) = &mut tx { v0.inputs = InputsV0 { p: new_inputs }; }
    
    // Recalculate the transaction ID with the signed inputs
    if let RawTransaction::V0(v0) = &mut tx {
        v0.id = compute_tx_id(&Inputs::V0(v0.inputs.clone()), &v0.timelock_range, v0.total_fees);
    }
    
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
                0xbbbb_cccc,  // Per comment: LSW first
                0x9999_aaaa,
                0x7777_8888,
                0x5555_6666,
                0x3333_4444,
                0x1111_2222,
                0x9abc_def0,
                0x1234_5678,  // Per comment: MSW last
            ]
        };

        // Derive public key from secret key (for conversion)
        let secret_key_be = t8_to_be32(&secret_key_t8);
        let pk_coords = cheetah_pub_from_sk(secret_key_be);

        // Create SchnorrPubkey from coordinates
        let public_key = SchnorrPubkey {
            x: crate::transaction_types::F6LT { values: pk_coords[0] },
            y: crate::transaction_types::F6LT { values: pk_coords[1] },
            inf: false,
        };

        // Message: [i=1 t=[i=2 t=~[3 4 5]]]
        // This represents a list [1, 2, 3, 4, 5] as 5 u64 values
        let message = Hash { values: [1, 2, 3, 4, 5] };

        // Expected challenge as T8
        let expected_challenge: [u64; 8] = [
            0x3646_19a6,  // LSW
            0x6af9_178c,
            0x46e4_7b17,
            0xf860_9591,
            0xf4c6_b69a,
            0x1a51_1b32,
            0xd7e5_6411,
            0x2f51_9cb9,  // MSW
        ];

        // Expected signature as T8
        let expected_signature: [u64; 8] = [
            0x0918_903a,  // LSW (note: 0x918.903a with leading zero)
            0x0e94_f5a7,  // 0xe94.f5a7 with leading zero
            0x34d7_585a,
            0xb809_abfe,
            0x5575_3257,
            0x5b73_fced,
            0x4ac8_fd17,
            0x21b7_0dda,  // MSW
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
        use crate::transaction_types::{Spend, Seeds, Seed, Source, Lock, TimelockIntent, Coins};
        use crate::collections::zset::ZSet;
        
        // Create a test seed
        let seed = Seed {
            output_source: Some(Source {
                p: Hash { values: [1, 2, 3, 4, 5] },
                is_coinbase: false,
            }),
            recipient: Lock {
                m: 1,
                pubkeys: ZSet::new(),
            },
            timelock_intent: None,
            gift: Coins { value: 100 },
            parent_hash: Hash { values: [10, 11, 12, 13, 14] },
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
            ]
        };
        
        // Derive public key from secret key
        let secret_key_be = t8_to_be32(&secret_key);
        let pk_coords = crate::crypto::cheetah::point::cheetah_pub_from_sk(secret_key_be);
        let public_key = SchnorrPubkey {
            x: crate::transaction_types::F6LT { values: pk_coords[0] },
            y: crate::transaction_types::F6LT { values: pk_coords[1] },
            inf: false,
        };
        
        // Sign the spend
        let (challenge, signature) = sign_spend(spend.clone(), secret_key.clone(), public_key.clone());
        
        // Verify we got non-zero values
        assert!(!challenge.values.iter().all(|&v| v == 0), "Challenge should not be all zeros");
        assert!(!signature.values.iter().all(|&v| v == 0), "Signature should not be all zeros");
        
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
        use crate::transaction_types::{Spend, Seeds, Seed, Source, Lock, TimelockRange, PageNumber, Coins};
        use crate::collections::zset::ZSet;
        
        println!("\n=== Comprehensive Spend Signing Test ===\n");
        
        // 1. Create an arbitrary secret key (must be less than curve order)
        let secret_key = T8 {
            values: [
                0x1234_5678,  // LSW first
                0x9ABC_DEF0,
                0x1357_9BDF,
                0x2468_ACE0,
                0x369C_F147,
                0x258B_E047,
                0x147A_D036,
                0x0369_CF14,  // MSW last - small enough to be < curve order
            ]
        };
        
        println!("Secret Key (T8 format):");
        println!("  LSW -> MSW: {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
            secret_key.values[0], secret_key.values[1], secret_key.values[2], secret_key.values[3],
            secret_key.values[4], secret_key.values[5], secret_key.values[6], secret_key.values[7]);
        
        // Convert to big-endian for display
        let secret_key_be = t8_to_be32(&secret_key);
        println!("  As hex: 0x{}", secret_key_be.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        
        // 2. Calculate public key from secret key
        let pk_coords = crate::crypto::cheetah::point::cheetah_pub_from_sk(secret_key_be);
        let public_key = SchnorrPubkey {
            x: crate::transaction_types::F6LT { values: pk_coords[0] },
            y: crate::transaction_types::F6LT { values: pk_coords[1] },
            inf: false,
        };
        
        println!("\nPublic Key (derived from secret key):");
        println!("  x: {:016x?}", public_key.x.values);
        println!("  y: {:016x?}", public_key.y.values);
        
        // 3. Create an arbitrary Spend structure with multiple seeds
        let seed1 = Seed {
            output_source: Some(Source {
                p: Hash { values: [100, 200, 300, 400, 500] },
                is_coinbase: false,
            }),
            recipient: Lock {
                m: 2,  // 2-of-3 multisig
                pubkeys: {
                    let mut pks = ZSet::new();
                    // Add some dummy pubkeys for testing
                    pks.put(SchnorrPubkey {
                        x: crate::transaction_types::F6LT { values: [1, 2, 3, 4, 5, 6] },
                        y: crate::transaction_types::F6LT { values: [7, 8, 9, 10, 11, 12] },
                        inf: false,
                    });
                    pks.put(SchnorrPubkey {
                        x: crate::transaction_types::F6LT { values: [13, 14, 15, 16, 17, 18] },
                        y: crate::transaction_types::F6LT { values: [19, 20, 21, 22, 23, 24] },
                        inf: false,
                    });
                    pks.put(SchnorrPubkey {
                        x: crate::transaction_types::F6LT { values: [25, 26, 27, 28, 29, 30] },
                        y: crate::transaction_types::F6LT { values: [31, 32, 33, 34, 35, 36] },
                        inf: false,
                    });
                    pks
                },
            },
            timelock_intent: Some((
                TimelockRange { 
                    min: Some(PageNumber { value: 1000 }), 
                    max: Some(PageNumber { value: 2000 }) 
                },  // absolute
                TimelockRange { min: None, max: None },  // relative (no restrictions)
            )),
            gift: Coins { value: 5000 },
            parent_hash: Hash { values: [0xAABBCCDD, 0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00] },
        };
        
        let seed2 = Seed {
            output_source: None,  // No output source for this seed
            recipient: Lock {
                m: 1,  // Simple 1-of-1
                pubkeys: {
                    let mut pks = ZSet::new();
                    pks.put(public_key.clone()); // Use our derived pubkey
                    pks
                },
            },
            timelock_intent: None,
            gift: Coins { value: 3000 },
            parent_hash: Hash { values: [0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0, 0x369CF147] },
        };
        
        // Create seeds set
        let mut seeds_set = ZSet::new();
        seeds_set.put(seed1.clone());
        seeds_set.put(seed2.clone());
        
        // Create spend with fee
        let spend = Spend {
            signature: None,  // No signature yet
            seeds: Seeds { set: seeds_set },
            fee: Coins { value: 250 },
        };
        
        println!("\nSpend Structure:");
        println!("  Number of seeds: 2");
        println!("  Fee: {} nicks", spend.fee.value);
        println!("\n  Seed 1:");
        println!("    Output source: {:?}", seed1.output_source.as_ref().map(|s| format!("Hash: {:x?}", s.p.values)));
        println!("    Recipient: {}-of-3 multisig", seed1.recipient.m);
        println!("    Timelock intent: {:?}", seed1.timelock_intent);
        println!("    Gift: {} nicks", seed1.gift.value);
        println!("    Parent hash: {:08x?}", seed1.parent_hash.values);
        println!("\n  Seed 2:");
        println!("    Output source: None");
        println!("    Recipient: {}-of-1 (using our pubkey)", seed2.recipient.m);
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
        assert!(!challenge.values.iter().all(|&v| v == 0), "Challenge should not be all zeros");
        assert!(!signature.values.iter().all(|&v| v == 0), "Signature should not be all zeros");
        
        println!("\n✓ Successfully signed spend with arbitrary key and structure");
    }
    
    #[test]
    fn test_sign_tx() {
        use crate::transaction_types::{RawTransaction, Inputs, Input, NNote, NNoteHead, Spend, Seeds, Seed, Lock, Source, Coins, TimelockRange, PageNumber, Timelock};
        use crate::collections::zset::ZSet;
        use crate::collections::zmap::ZMap;
        
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
            ]
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
            parent_hash: Hash { values: [1, 2, 3, 4, 5] },
        };
        
        let mut seeds_set = ZSet::new();
        seeds_set.put(seed);
        
        let spend = Spend {
            signature: None,  // No signature yet
            seeds: Seeds { set: seeds_set },
            fee: Coins { value: 10 },
        };
        
        let input = Input {
            note: NNote {
                meta: NNoteHead {
                    version: 1,
                    origin_page: PageNumber { value: 1 },
                    timelock: crate::transaction_types::Timelock { 
                        intent: None 
                    },
                },
                name: crate::transaction_types::NName {
                    p: vec![Hash { values: [1, 0, 0, 0, 0] }],
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
            p: vec![Hash { values: [1, 0, 0, 0, 0] }],
        };
        inputs_map.put(name, input);
        
        // Create the raw transaction
        let tx = RawTransaction {
            id: Hash { values: [0; 5] },  // Will be recalculated
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
            assert!(input.spend.signature.is_some(), 
                "Input {:?} should have a signature", name);
            
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
            signed_tx.id.values,
            [0; 5],
            "Transaction ID should have been recalculated"
        );
        
        println!("\n✓ Successfully signed transaction with sign_tx");
    }
    
    // Test data: JAM-encoded unsigned transaction
    const UNSIGNED_TX_JAM: &[u8] = &[
        0x05, 0x10, 0x78, 0x97, 0x33, 0xf1, 0x2e, 0xa8, 0x0b, 0xd9, 0x0d, 0xd0, 0x83, 0x0e, 0x1c, 0x2d,
        0x43, 0xfd, 0x0f, 0xa2, 0x01, 0x04, 0x52, 0xa1, 0x7c, 0x95, 0x6c, 0x52, 0x60, 0x17, 0x03, 0x08,
        0xa4, 0x41, 0xca, 0x85, 0x89, 0x8c, 0x64, 0x80, 0x02, 0x04, 0xa8, 0x74, 0x6d, 0x8f, 0x60, 0x3c,
        0x6b, 0x2d, 0xab, 0x02, 0x08, 0x68, 0xf3, 0x6e, 0xc7, 0x88, 0x9b, 0x26, 0x5f, 0x06, 0xf8, 0x4d,
        0xd3, 0xfa, 0x68, 0x3b, 0xa4, 0x03, 0xf4, 0x01, 0x76, 0xb6, 0x17, 0xb0, 0xff, 0xeb, 0x9e, 0x31,
        0x18, 0xa0, 0x97, 0xbb, 0x49, 0x3e, 0x5a, 0x91, 0x82, 0xae, 0x01, 0x3f, 0xb6, 0x44, 0xa0, 0x30,
        0xaf, 0xb5, 0xe8, 0xbb, 0x00, 0xfd, 0x7d, 0x4b, 0x4c, 0x43, 0x11, 0x14, 0xf5, 0x1e, 0x40, 0x00,
        0x08, 0x45, 0x12, 0x1a, 0x2d, 0x90, 0x5e, 0x32, 0x80, 0x80, 0xfc, 0x28, 0xe7, 0xac, 0xfe, 0xf7,
        0xe8, 0x63, 0x80, 0xde, 0xd0, 0x4c, 0xb3, 0xe6, 0xfc, 0x65, 0xaf, 0x07, 0x08, 0x74, 0xd7, 0xb0,
        0x29, 0xfe, 0x50, 0xb0, 0xc1, 0x5a, 0x19, 0x78, 0x78, 0xb7, 0x0d, 0x73, 0xb9, 0xb8, 0x02, 0xec,
        0x7c, 0xd4, 0x69, 0xcb, 0xbe, 0x61, 0xd6, 0x30, 0xc0, 0x8f, 0x6a, 0xd0, 0x9a, 0x6d, 0xc0, 0x70,
        0xa1, 0x0e, 0x20, 0xa0, 0x00, 0x7f, 0xab, 0x12, 0x28, 0x3a, 0x0f, 0x1b, 0xe0, 0x5f, 0xd0, 0xaa,
        0x56, 0xf2, 0x43, 0x4b, 0x13, 0x06, 0x10, 0x18, 0xe2, 0x06, 0xbe, 0xe6, 0x10, 0x93, 0x5a, 0x06,
        0x08, 0x80, 0xfc, 0x3a, 0x95, 0x80, 0xf0, 0x5f, 0xa9, 0x16, 0x40, 0x20, 0x2d, 0x38, 0xe5, 0x45,
        0x8d, 0x50, 0x88, 0x3f, 0x80, 0x40, 0xbf, 0x76, 0x49, 0x34, 0x41, 0xe8, 0x04, 0x66, 0x80, 0x3d,
        0x3a, 0xc4, 0xf9, 0xb4, 0x90, 0xae, 0x26, 0x06, 0x10, 0x00, 0x62, 0x68, 0x5e, 0x55, 0xd7, 0xbe,
        0x21, 0x0e, 0x20, 0x80, 0xbd, 0x66, 0xf0, 0xed, 0xf0, 0x45, 0xb7, 0x0f, 0xf8, 0x67, 0x4d, 0x90,
        0x03, 0x35, 0x4a, 0xc3, 0xaa, 0x9c, 0x56, 0x80, 0xdf, 0x54, 0xed, 0xd8, 0x1a, 0x5f, 0xe6, 0x7a,
        0x1f, 0xe0, 0x2f, 0x5c, 0x35, 0x5d, 0x80, 0xf6, 0x49, 0xba, 0x06, 0xe8, 0x83, 0x55, 0x9f, 0x67,
        0xbc, 0x4b, 0xa2, 0xf2, 0x00, 0x02, 0x67, 0x9f, 0x1a, 0x9f, 0x70, 0xab, 0x48, 0x8e, 0x80, 0xff,
        0x34, 0xf5, 0xc3, 0xa4, 0x48, 0x1e, 0x67, 0xce, 0xc0, 0x00, 0x00, 0x98, 0x95, 0xc5, 0x15, 0x40,
        0x60, 0x60, 0x15, 0x7a, 0x2a, 0x77, 0xca, 0xc4, 0x33, 0x80, 0xc0, 0x72, 0x68, 0xc9, 0xc7, 0xd6,
        0x10, 0xcc, 0x60, 0x80, 0xff, 0x35, 0xe2, 0x64, 0x31, 0x99, 0xe8, 0x7a, 0x1a, 0xa0, 0x7f, 0x69,
        0x39, 0x77, 0xde, 0xe4, 0xba, 0x27, 0x03, 0xf4, 0x79, 0x29, 0xfa, 0x40, 0x55, 0x79, 0x86, 0x35,
        0xe0, 0x57, 0xe5, 0xb7, 0xa9, 0x79, 0x43, 0x16, 0x21, 0x16, 0x60, 0x8f, 0xe4, 0xd5, 0x41, 0x8f,
        0x8e, 0x37, 0xea, 0x01, 0xfe, 0x53, 0x1a, 0x43, 0x44, 0x71, 0x9b, 0xe6, 0x7f, 0x80, 0xbd, 0xa2,
        0x65, 0xf3, 0x6e, 0x28, 0x67, 0xfd, 0x06, 0x10, 0x38, 0x91, 0x5f, 0xe3, 0x1b, 0x5f, 0x14, 0x85,
        0x0c, 0x20, 0xd0, 0x3b, 0x3b, 0x25, 0xc5, 0xce, 0x13, 0x1a, 0x09, 0x10, 0x38, 0x1f, 0xb3, 0xd9,
        0x28, 0xd4, 0xab, 0x00, 0xe4, 0x21, 0x59, 0x31, 0x83, 0x93, 0x03, 0xfc, 0x4e, 0x40, 0x14, 0x51,
        0x3f, 0x61, 0xfe, 0xc7, 0x00, 0x02, 0xdd, 0x3b, 0x4e, 0xac, 0xa6, 0x26, 0x46, 0x95, 0x01, 0x7e,
        0x3d, 0x1b, 0x08, 0x19, 0x18, 0x33, 0x86, 0x71, 0x00, 0x01, 0x46, 0x5e, 0xa0, 0x94, 0x31, 0xd5,
        0x7d, 0x60, 0xc0, 0x6f, 0x33, 0x5d, 0x1a, 0x6e, 0x80, 0x55, 0x1c, 0xac, 0x6c, 0xb8, 0x73, 0x66,
        0x40, 0xb8, 0xf9, 0x1f, 0x32, 0xca, 0x87, 0x64, 0xc5, 0xb2, 0xb8, 0x02, 0xec, 0x09, 0x0e, 0x68,
        0xf6, 0x98, 0xbf, 0x45, 0x32, 0x80, 0x40, 0x2f, 0x75, 0x93, 0xe9, 0x4c, 0x8c, 0x3e, 0x73, 0x80,
        0xde, 0xdb, 0x1a, 0x02, 0x83, 0x82, 0x93, 0x6c, 0x0f, 0x20, 0xe0, 0xbf, 0xae, 0x55, 0x02, 0x76,
        0xdd, 0x6c, 0x1c, 0xe0, 0x57, 0x1a, 0x91, 0x50, 0xa8, 0xd2, 0x98, 0x4f, 0x02, 0x04, 0x3c, 0xe5,
        0xd1, 0x06, 0xc6, 0x59, 0xbc, 0x25, 0x0b, 0xd0, 0xd7, 0x04, 0xc9, 0x28, 0x23, 0x54, 0xdb, 0xf2,
        0x01, 0x7a, 0xf4, 0x4b, 0x36, 0xf9, 0xab, 0x88, 0xe7, 0x39, 0x40, 0xdc, 0x3f, 0xb9, 0x13, 0x3c,
        0xb7, 0xa1, 0x1c, 0x40, 0x20, 0xf3, 0x1a, 0x88, 0x63, 0x4d, 0x41, 0x01, 0x33, 0x40, 0x4f, 0x67,
        0xc9, 0x36, 0x9d, 0x53, 0x2c, 0x82, 0x03, 0xfa, 0xda, 0x88, 0x63, 0x93, 0xda, 0xc2, 0x3a, 0x9b,
        0x87, 0x64, 0xc5, 0x21, 0x7b, 0x7c, 0x48, 0x56, 0xe4, 0x21, 0x59, 0xb1, 0x21, 0x59, 0x91, 0x01,
    ];

    // Test data: JAM-encoded signed transaction
    const SIGNED_TX_JAM: &[u8] = &[
        0x05, 0xf8, 0xc9, 0x6d, 0xa5, 0xb8, 0xf8, 0x6d, 0x20, 0xa1, 0x01, 0xfa, 0xa7, 0x3d, 0x09, 0x86,
        0x45, 0x12, 0x4d, 0x30, 0x80, 0x40, 0xaa, 0xc8, 0x32, 0x61, 0x67, 0x20, 0x8e, 0x7f, 0x00, 0x81,
        0x42, 0xec, 0xb0, 0x93, 0x1b, 0x17, 0xa8, 0x4f, 0x80, 0x80, 0x14, 0x75, 0x95, 0xcb, 0x3f, 0x6c,
        0x46, 0x61, 0x55, 0x00, 0x01, 0x6d, 0xde, 0xed, 0x18, 0x71, 0xd3, 0xe4, 0xcb, 0x00, 0xbf, 0x69,
        0x5a, 0x1f, 0x6d, 0x87, 0x74, 0x80, 0x3e, 0xc0, 0xce, 0xf6, 0x02, 0xf6, 0x7f, 0xdd, 0x33, 0x06,
        0x03, 0xf4, 0x72, 0x37, 0xc9, 0x47, 0x2b, 0x52, 0xd0, 0x35, 0xe0, 0xc7, 0x96, 0x08, 0x14, 0xe6,
        0xb5, 0x16, 0x7d, 0x17, 0xa0, 0xbf, 0x6f, 0x89, 0x69, 0x28, 0x82, 0xa2, 0xde, 0x03, 0x08, 0x00,
        0xa1, 0x48, 0x42, 0xa3, 0x05, 0xd2, 0x4b, 0x06, 0x10, 0x90, 0x1f, 0xe5, 0x9c, 0xd5, 0xff, 0x1e,
        0x7d, 0x0c, 0xd0, 0x1b, 0x9a, 0x69, 0xd6, 0x9c, 0xbf, 0xec, 0xf5, 0x00, 0x81, 0xee, 0x1a, 0x36,
        0xc5, 0x1f, 0x0a, 0x36, 0x58, 0x2b, 0x03, 0x0f, 0xef, 0xb6, 0x61, 0x28, 0x17, 0x57, 0x80, 0x9d,
        0x8f, 0x3a, 0x6d, 0xd9, 0x37, 0xcc, 0x1a, 0x06, 0xf8, 0x51, 0x0d, 0x5a, 0xb3, 0x0d, 0x18, 0x2e,
        0xd4, 0x01, 0x04, 0x14, 0xe0, 0x6f, 0x55, 0x02, 0x45, 0xe7, 0x61, 0x03, 0xfc, 0x0b, 0x5a, 0xd5,
        0x4a, 0x7e, 0x68, 0x69, 0xc2, 0x00, 0x02, 0x43, 0xdc, 0xc0, 0xd7, 0x1c, 0x62, 0x52, 0xcb, 0x00,
        0x01, 0x90, 0x5f, 0xa7, 0x12, 0x10, 0xfe, 0x2b, 0xd5, 0x02, 0x08, 0xa4, 0x05, 0xa7, 0xbc, 0xa8,
        0x11, 0x0a, 0xf1, 0x07, 0x10, 0xe8, 0xd7, 0x2e, 0x89, 0x26, 0x08, 0x9d, 0xc0, 0x0c, 0xb0, 0x47,
        0x87, 0x38, 0x9f, 0x16, 0xd2, 0xd5, 0xc4, 0x00, 0x02, 0x40, 0x0c, 0xcd, 0xab, 0xea, 0xda, 0x37,
        0xc4, 0x01, 0x04, 0xb0, 0xd7, 0x0c, 0xbe, 0x1d, 0xbe, 0xe8, 0xf6, 0x01, 0xff, 0xac, 0x09, 0x72,
        0xa0, 0x46, 0x69, 0x58, 0x95, 0xd3, 0x0a, 0xf0, 0x9b, 0xaa, 0x1d, 0x5b, 0xe3, 0xcb, 0x5c, 0xef,
        0x03, 0xfc, 0x85, 0xab, 0xa6, 0x0b, 0xd0, 0x3e, 0x49, 0xd7, 0x00, 0x7d, 0xb0, 0xea, 0xf3, 0x8c,
        0x77, 0x49, 0x54, 0x1e, 0x40, 0xe0, 0xec, 0x53, 0xe3, 0x13, 0x6e, 0x15, 0xc9, 0x11, 0xf0, 0x9f,
        0xa6, 0x7e, 0x98, 0x14, 0xc9, 0xe3, 0xcc, 0x19, 0x18, 0x00, 0x00, 0xcb, 0x1a, 0x8e, 0x9d, 0x05,
        0x08, 0x76, 0x69, 0x18, 0xd7, 0x03, 0x7e, 0x9f, 0xa8, 0xee, 0x37, 0x40, 0xe0, 0x7a, 0xe4, 0x6c,
        0x1a, 0xf0, 0x1d, 0x0f, 0xc7, 0xed, 0x01, 0x02, 0x69, 0xf5, 0x53, 0xf8, 0x00, 0xc1, 0x60, 0xac,
        0x3e, 0x67, 0x80, 0xe0, 0x0e, 0x7b, 0x79, 0x1a, 0xd8, 0xba, 0x2d, 0x6e, 0x3b, 0x40, 0x30, 0xd9,
        0xab, 0x86, 0x1c, 0x20, 0x78, 0x7f, 0xc4, 0xd9, 0x0e, 0x10, 0xb0, 0x66, 0x61, 0xd8, 0x07, 0x08,
        0x74, 0x16, 0xc3, 0x3e, 0x03, 0x04, 0x14, 0x3b, 0xc0, 0xd6, 0x01, 0x82, 0xd4, 0x5b, 0x73, 0xd4,
        0x80, 0x0e, 0x49, 0xbb, 0xed, 0x02, 0xdd, 0xee, 0x93, 0xa0, 0x1c, 0x32, 0x15, 0x2b, 0x8b, 0x2b,
        0x80, 0xc0, 0xc0, 0x2a, 0xf4, 0x54, 0xee, 0x94, 0x89, 0x67, 0x00, 0x81, 0xe5, 0xd0, 0x92, 0x8f,
        0xad, 0x21, 0x98, 0xc1, 0x00, 0xff, 0x6b, 0xc4, 0xc9, 0x62, 0x32, 0xd1, 0xf5, 0x34, 0x40, 0xff,
        0xd2, 0x72, 0xee, 0xbc, 0xc9, 0x75, 0x4f, 0x06, 0xe8, 0xf3, 0x52, 0xf4, 0x81, 0xaa, 0xf2, 0x0c,
        0x6b, 0xc0, 0xaf, 0xca, 0x6f, 0x53, 0xf3, 0x86, 0x2c, 0x42, 0x2c, 0xc0, 0x1e, 0xc9, 0xab, 0x83,
        0x1e, 0x1d, 0x6f, 0xd4, 0x03, 0xfc, 0xa7, 0x34, 0x86, 0x88, 0xe2, 0x36, 0xcd, 0xff, 0x00, 0x7b,
        0x45, 0xcb, 0xe6, 0xdd, 0x50, 0xce, 0xfa, 0x0d, 0x20, 0x70, 0x22, 0xbf, 0xc6, 0x37, 0xbe, 0x28,
        0x0a, 0x19, 0x40, 0xa0, 0x77, 0x76, 0x4a, 0x8a, 0x9d, 0x27, 0x34, 0x12, 0x20, 0x70, 0x3e, 0x66,
        0xb3, 0x51, 0xa8, 0x57, 0x01, 0xc8, 0x43, 0xa6, 0x62, 0x06, 0x27, 0x07, 0xf8, 0x9d, 0x80, 0x28,
        0xa2, 0x7e, 0xc2, 0xfc, 0x8f, 0x01, 0x04, 0xba, 0x77, 0x9c, 0x58, 0x4d, 0x4d, 0x8c, 0x2a, 0x03,
        0xfc, 0x7a, 0x36, 0x10, 0x32, 0x30, 0x66, 0x0c, 0xe3, 0x00, 0x02, 0x8c, 0xbc, 0x40, 0x29, 0x63,
        0xaa, 0xfb, 0xc0, 0x80, 0xdf, 0x66, 0xba, 0x34, 0xdc, 0x00, 0xab, 0x38, 0x58, 0xd9, 0x70, 0xe4,
        0xcc, 0x80, 0x70, 0xf3, 0x3f, 0xac, 0x56, 0x1c, 0x32, 0x15, 0xcb, 0xe2, 0x0a, 0xb0, 0x27, 0x38,
        0xa0, 0xd9, 0x63, 0xfe, 0x16, 0xc9, 0x00, 0x02, 0xbd, 0xd4, 0x4d, 0xa6, 0x33, 0x31, 0xfa, 0xcc,
        0x01, 0x7a, 0x6f, 0x6b, 0x08, 0x0c, 0x0a, 0x4e, 0xb2, 0x3d, 0x80, 0x80, 0xff, 0xba, 0x56, 0x09,
        0xd8, 0x75, 0xb3, 0x71, 0x80, 0x5f, 0x69, 0x44, 0x42, 0xa1, 0x4a, 0x63, 0x3e, 0x09, 0x10, 0xf0,
        0x94, 0x47, 0x1b, 0x18, 0x67, 0xf1, 0x96, 0x2c, 0x40, 0x5f, 0x13, 0x24, 0xa3, 0x8c, 0x50, 0x6d,
        0xcb, 0x07, 0xe8, 0xd1, 0x2f, 0xd9, 0xe4, 0xaf, 0x22, 0x9e, 0xe7, 0x00, 0x71, 0xff, 0xe4, 0x4e,
        0xf0, 0xdc, 0x86, 0x72, 0x00, 0x81, 0xcc, 0x6b, 0x20, 0x8e, 0x35, 0x05, 0x05, 0xcc, 0x00, 0x3d,
        0x9d, 0x25, 0xdb, 0x74, 0x4e, 0xb1, 0x08, 0x0e, 0xe8, 0x6b, 0x23, 0x8e, 0x4d, 0x6a, 0x0b, 0xeb,
        0x6c, 0x1e, 0x32, 0x15, 0x87, 0x35, 0x8a, 0x43, 0xa6, 0x22, 0x0f, 0x99, 0x8a, 0x0d, 0x99, 0x8a,
        0x0c,
    ];

    #[test]
    fn test_sign_tx_with_known_good_data() {
        use nockapp::noun::slab::NounSlab;
        use noun_serde::NounDecode;
        use crate::crypto::slip10::master::master_from_mnemonic;

        println!("\n=== Testing sign_tx with known-good transaction data ===\n");

        // BIP39 mnemonic (hardcoded test data)
        const MNEMONIC: &str = "around squeeze nerve chronic trophy kiwi enroll identify depth bicycle radio gate critic child claim outer detect plug market visual stuff finish crime abuse";

        println!("Using BIP39 mnemonic (hardcoded test data)");
        
        // Derive the master key from the mnemonic (no passphrase)
        let master_key = master_from_mnemonic(MNEMONIC, "")
            .expect("Failed to derive master key from mnemonic");
        
        // Get the private key bytes
        let private_key_bytes = master_key.private_key_bytes()
            .expect("Master key should have private key");
        
        // Convert the 32-byte private key to T8 format (8 x u32 in little-endian)
        let mut t8_values = [0u64; 8];
        for i in 0..8 {
            // Each T8 limb is 4 bytes from the private key, stored as u64
            // The private key is in big-endian, but T8 limbs are in little-endian order
            let offset = 32 - (i + 1) * 4;  // Start from the end for little-endian T8
            let limb_bytes = &private_key_bytes[offset..offset + 4];
            t8_values[i] = u32::from_be_bytes([
                limb_bytes[0],
                limb_bytes[1], 
                limb_bytes[2],
                limb_bytes[3]
            ]) as u64;
        }
        
        let secret_key = T8 { values: t8_values };
        
        println!("Derived secret key from mnemonic:");
        println!("  T8 format: {:016x?}", secret_key.values);
        
        // Calculate the public key from the secret key
        let secret_key_be = t8_to_be32(&secret_key);
        let pk_coords = cheetah_pub_from_sk(secret_key_be);
        let derived_pubkey = SchnorrPubkey {
            x: crate::transaction_types::F6LT { values: pk_coords[0] },
            y: crate::transaction_types::F6LT { values: pk_coords[1] },
            inf: false,
        };
        
        println!("Derived public key:");
        println!("  X: {:016x?}", derived_pubkey.x.values);
        println!("  Y: {:016x?}", derived_pubkey.y.values);
        
        // Decode the unsigned transaction from inline JAM data
        let mut slab: NounSlab = NounSlab::new();
        let noun = slab.cue_into(UNSIGNED_TX_JAM.into())
            .expect("Failed to decode unsigned JAM");
        
        let unsigned_tx = RawTransaction::from_noun(&noun)
            .expect("Failed to decode RawTransaction from noun");
        
        println!("\nLoaded unsigned transaction:");
        println!("  ID: {:016x?}", unsigned_tx.id.values);
        println!("  Inputs count: {}", unsigned_tx.inputs.p.tap().len());
        println!("  Total fees: {}", unsigned_tx.total_fees.value);
        
        // Check that it has no signatures
        let has_any_sig = unsigned_tx.inputs.p.tap()
            .iter()
            .any(|(_, input)| input.spend.signature.is_some());
        assert!(!has_any_sig, "unsigned transaction should have no signatures");
        
        // Decode the signed transaction from inline JAM data for comparison
        let mut slab2: NounSlab = NounSlab::new();
        let noun2 = slab2.cue_into(SIGNED_TX_JAM.into())
            .expect("Failed to decode signed JAM");
        
        let expected_signed_tx = RawTransaction::from_noun(&noun2)
            .expect("Failed to decode signed RawTransaction from noun");
        
        println!("\nExpected signed transaction:");
        println!("  ID: {:016x?}", expected_signed_tx.id.values);
        
        // Sign the unsigned transaction with the derived secret key
        let signed_tx = sign_tx(unsigned_tx.clone(), secret_key);
        
        println!("\nNewly signed transaction:");
        println!("  ID: {:016x?}", signed_tx.id.values);
        println!("  Has signatures: {}", 
            signed_tx.inputs.p.tap()
                .iter()
                .all(|(_, input)| input.spend.signature.is_some()));
        
        // Verify that:
        // 1. All inputs now have signatures
        let all_signed = signed_tx.inputs.p.tap()
            .iter()
            .all(|(_, input)| input.spend.signature.is_some());
        assert!(all_signed, "All inputs should have signatures after signing");
        
        // 2. The transaction ID changed from the unsigned version
        assert_ne!(
            signed_tx.id.values,
            unsigned_tx.id.values,
            "Transaction ID should change after signing"
        );
        
        // 3. The structure is similar to the expected signed transaction
        assert_eq!(
            signed_tx.inputs.p.tap().len(),
            expected_signed_tx.inputs.p.tap().len(),
            "Should have same number of inputs"
        );
        
        // Assert that the transaction IDs match!
        println!("\nComparing transaction IDs:");
        println!("  Generated: {:016x?}", signed_tx.id.values);
        println!("  Expected:  {:016x?}", expected_signed_tx.id.values);

        assert_eq!(
            signed_tx.id.values,
            expected_signed_tx.id.values,
            "Transaction ID after signing should match expected signed transaction ID"
        );

        println!("\n✅ SUCCESS! Transaction IDs MATCH!");
        
        println!("\n✓ Successfully signed known-good transaction");
        
        // Extract the signature details from the expected signed transaction
        if let Some((_, signed_input)) = expected_signed_tx.inputs.p.tap().first() {
            if let Some(ref sig) = signed_input.spend.signature {
                if let Some((pubkey, schnorr_sig)) = sig.map.tap().first() {
                    println!("\n  Expected signature from reference data:");
                    println!("    Public key X: {:016x?}", pubkey.x.values);
                    println!("    Public key Y: {:016x?}", pubkey.y.values);
                    println!("    Challenge:    {:016x?}", schnorr_sig.chal.values.values);
                    println!("    Signature s:  {:016x?}", schnorr_sig.sig.values.values);
                }
            }
        }

        // Extract the signature details from our newly signed transaction
        if let Some((_, signed_input)) = signed_tx.inputs.p.tap().first() {
            if let Some(ref sig) = signed_input.spend.signature {
                if let Some((pubkey, schnorr_sig)) = sig.map.tap().first() {
                    println!("\n  Generated signature from our code:");
                    println!("    Public key X: {:016x?}", pubkey.x.values);
                    println!("    Public key Y: {:016x?}", pubkey.y.values);
                    println!("    Challenge:    {:016x?}", schnorr_sig.chal.values.values);
                    println!("    Signature s:  {:016x?}", schnorr_sig.sig.values.values);
                }
            }
        }
    }
}