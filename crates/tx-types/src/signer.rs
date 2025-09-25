#![cfg_attr(not(test), no_std)]

extern crate alloc;

use crate::transaction_types::{Hash, T8, SchnorrPubkey};
use crate::crypto::cheetah::point::cheetah_pub_from_sk;
use crate::crypto::utils::{
    trunc_g_order_to_be32, 
    is_zero32, 
    mul_mod_n, 
    add_mod_n,
    be32_atom_to_t8_le,
    be32_lt,
    CHEETAH_N
};
use crate::hashing::tip5::Tip5Hasher;
use nockvm::noun::Cell;
use nockapp::noun::slab::NounSlab;

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
fn hash_transcript_list(element_arrays: &[&[u64]]) -> Result<Hash, crate::hashing::tip5::Tip5Error> {
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
    Tip5Hasher::hash_noun(list)
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
}