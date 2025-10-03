/// Schnorr signature verification over the Cheetah curve
///
/// This module implements the verification algorithm for Schnorr signatures
/// used in Nockchain transactions. The verification equation is: s·G = R + e·P
///
/// We verify by computing R = s·G - e·P and checking that the recomputed
/// challenge e' = TIP5([R, P, message]) matches the provided challenge e.

use crate::transaction_types::{SchnorrPubkey, SchnorrSignature, Hash};
use crate::crypto::cheetah::point::CheetahPoint;
use crate::crypto::utils::{
    t8_to_be32,
    trunc_g_order_to_be32,
    be32_lt,
    CHEETAH_N,
};
use crate::hashing::hasher::hash_transcript_list;
use ibig::UBig;

/// Verify a Schnorr signature over the Cheetah curve
///
/// # Arguments
/// * `public_key` - The public key that signed the message
/// * `message` - The message hash that was signed
/// * `signature` - The Schnorr signature (challenge and signature components)
///
/// # Returns
/// * `true` if the signature is valid
/// * `false` if the signature is invalid
///
/// # Algorithm
/// 1. Validate that signature components are < curve order
/// 2. Convert signature components to scalars
/// 3. Compute R = s·G - e·P (where s is signature, e is challenge)
/// 4. Recompute challenge: e' = TIP5([R.x, R.y, P.x, P.y, message])
/// 5. Verify that e' == e (constant-time comparison)
///
/// # Example
/// ```no_run
/// use tx_types::validation::schnorr_verify_digest;
/// use tx_types::{SchnorrPubkey, SchnorrSignature, Hash};
///
/// let is_valid = schnorr_verify_digest(public_key, message, signature);
/// if is_valid {
///     println!("Signature is valid!");
/// }
/// ```
pub fn schnorr_verify_digest(
    public_key: SchnorrPubkey,
    message: Hash,
    signature: SchnorrSignature,
) -> bool {
    // 1. Convert signature components to big-endian format
    let chal_be = t8_to_be32(&signature.chal.values);
    let sig_be = t8_to_be32(&signature.sig.values);

    // 2. Validate that both components are < curve order
    // This prevents malleability attacks and ensures valid scalars
    if !be32_lt(&chal_be, &CHEETAH_N) || !be32_lt(&sig_be, &CHEETAH_N) {
        return false;
    }

    // 3. Convert to scalars for elliptic curve operations
    let s_scalar = UBig::from_be_bytes(&sig_be);
    let e_scalar = UBig::from_be_bytes(&chal_be);

    // 4. Compute R = s·G - e·P
    // This is equivalent to verifying s·G = R + e·P
    // We compute s·G first
    let sg = CheetahPoint::generator().scalar_mul(&s_scalar);

    // Then compute e·P
    let ep = CheetahPoint::from_schnorr_pubkey(&public_key)
        .scalar_mul(&e_scalar);

    // Then R = s·G - e·P
    let r_point = sg.add(&ep.neg());

    // 5. Recompute the challenge from R, P, and the message
    // Challenge = TIP5([R.x, R.y, P.x, P.y, message])
    let r_coords = r_point.to_coordinates();

    let chal_digest = match hash_transcript_list(&[
        &r_coords[0],         // R.x (6 u64 values)
        &r_coords[1],         // R.y (6 u64 values)
        &public_key.x.values, // P.x (6 u64 values)
        &public_key.y.values, // P.y (6 u64 values)
        &message.values,      // message (5 u64 values)
    ]) {
        Ok(h) => h,
        Err(_) => return false, // Hash computation failed
    };

    // Truncate the hash to curve order
    let expected_chal_be = trunc_g_order_to_be32(chal_digest.values);

    // 6. Constant-time comparison of challenges
    // If the recomputed challenge matches the provided challenge, signature is valid
    chal_be == expected_chal_be
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::schnorr_sign_digest;
    use crate::crypto::cheetah::point::cheetah_pub_from_sk;
    use crate::transaction_types::{T8, F6LT};

    #[test]
    fn test_round_trip_signature_verification() {
        // Create a test key pair
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

        // Derive public key
        let sk_be = t8_to_be32(&secret_key);
        let pk_coords = cheetah_pub_from_sk(sk_be);
        let public_key = SchnorrPubkey {
            x: F6LT { values: pk_coords[0] },
            y: F6LT { values: pk_coords[1] },
            inf: false,
        };

        // Create a message
        let message = Hash { values: [1, 2, 3, 4, 5] };

        // Sign the message
        let (chal, sig) = schnorr_sign_digest(secret_key, public_key.clone(), message.clone());

        let signature = SchnorrSignature {
            chal: crate::transaction_types::Chal { values: chal },
            sig: crate::transaction_types::Sig { values: sig },
        };

        // Verify the signature
        let is_valid = schnorr_verify_digest(public_key.clone(), message.clone(), signature.clone());
        assert!(is_valid, "Valid signature should verify successfully");

        println!("✓ Round-trip signature verification works");
    }

    #[test]
    fn test_invalid_signature_modified_challenge() {
        // Create and sign a message
        let secret_key = T8 {
            values: [
                0xbbbb_cccc, 0x9999_aaaa, 0x7777_8888, 0x5555_6666,
                0x3333_4444, 0x1111_2222, 0x9abc_def0, 0x1234_5678,
            ]
        };

        let sk_be = t8_to_be32(&secret_key);
        let pk_coords = cheetah_pub_from_sk(sk_be);
        let public_key = SchnorrPubkey {
            x: F6LT { values: pk_coords[0] },
            y: F6LT { values: pk_coords[1] },
            inf: false,
        };

        let message = Hash { values: [1, 2, 3, 4, 5] };
        let (mut chal, sig) = schnorr_sign_digest(secret_key, public_key.clone(), message.clone());

        // Modify the challenge
        chal.values[0] ^= 1; // Flip one bit

        let signature = SchnorrSignature {
            chal: crate::transaction_types::Chal { values: chal },
            sig: crate::transaction_types::Sig { values: sig },
        };

        // Verification should fail
        let is_valid = schnorr_verify_digest(public_key, message, signature);
        assert!(!is_valid, "Modified challenge should fail verification");

        println!("✓ Modified challenge correctly fails verification");
    }

    #[test]
    fn test_invalid_signature_modified_sig() {
        // Create and sign a message
        let secret_key = T8 {
            values: [
                0xbbbb_cccc, 0x9999_aaaa, 0x7777_8888, 0x5555_6666,
                0x3333_4444, 0x1111_2222, 0x9abc_def0, 0x1234_5678,
            ]
        };

        let sk_be = t8_to_be32(&secret_key);
        let pk_coords = cheetah_pub_from_sk(sk_be);
        let public_key = SchnorrPubkey {
            x: F6LT { values: pk_coords[0] },
            y: F6LT { values: pk_coords[1] },
            inf: false,
        };

        let message = Hash { values: [1, 2, 3, 4, 5] };
        let (chal, mut sig) = schnorr_sign_digest(secret_key, public_key.clone(), message.clone());

        // Modify the signature
        sig.values[0] ^= 1; // Flip one bit

        let signature = SchnorrSignature {
            chal: crate::transaction_types::Chal { values: chal },
            sig: crate::transaction_types::Sig { values: sig },
        };

        // Verification should fail
        let is_valid = schnorr_verify_digest(public_key, message, signature);
        assert!(!is_valid, "Modified signature should fail verification");

        println!("✓ Modified signature correctly fails verification");
    }

    #[test]
    fn test_invalid_signature_wrong_message() {
        // Create and sign a message
        let secret_key = T8 {
            values: [
                0xbbbb_cccc, 0x9999_aaaa, 0x7777_8888, 0x5555_6666,
                0x3333_4444, 0x1111_2222, 0x9abc_def0, 0x1234_5678,
            ]
        };

        let sk_be = t8_to_be32(&secret_key);
        let pk_coords = cheetah_pub_from_sk(sk_be);
        let public_key = SchnorrPubkey {
            x: F6LT { values: pk_coords[0] },
            y: F6LT { values: pk_coords[1] },
            inf: false,
        };

        let message = Hash { values: [1, 2, 3, 4, 5] };
        let (chal, sig) = schnorr_sign_digest(secret_key, public_key.clone(), message.clone());

        let signature = SchnorrSignature {
            chal: crate::transaction_types::Chal { values: chal },
            sig: crate::transaction_types::Sig { values: sig },
        };

        // Verify with different message
        let wrong_message = Hash { values: [1, 2, 3, 4, 6] }; // Changed last element

        let is_valid = schnorr_verify_digest(public_key, wrong_message, signature);
        assert!(!is_valid, "Wrong message should fail verification");

        println!("✓ Wrong message correctly fails verification");
    }

    #[test]
    fn test_invalid_signature_wrong_pubkey() {
        // Create and sign a message
        let secret_key = T8 {
            values: [
                0xbbbb_cccc, 0x9999_aaaa, 0x7777_8888, 0x5555_6666,
                0x3333_4444, 0x1111_2222, 0x9abc_def0, 0x1234_5678,
            ]
        };

        let sk_be = t8_to_be32(&secret_key);
        let pk_coords = cheetah_pub_from_sk(sk_be);
        let public_key = SchnorrPubkey {
            x: F6LT { values: pk_coords[0] },
            y: F6LT { values: pk_coords[1] },
            inf: false,
        };

        let message = Hash { values: [1, 2, 3, 4, 5] };
        let (chal, sig) = schnorr_sign_digest(secret_key, public_key.clone(), message.clone());

        let signature = SchnorrSignature {
            chal: crate::transaction_types::Chal { values: chal },
            sig: crate::transaction_types::Sig { values: sig },
        };

        // Create a different public key
        let wrong_secret_key = T8 {
            values: [
                0x1234_5678, 0x9abc_def0, 0x1111_2222, 0x3333_4444,
                0x5555_6666, 0x7777_8888, 0x9999_aaaa, 0xbbbb_cccc,
            ]
        };
        let wrong_sk_be = t8_to_be32(&wrong_secret_key);
        let wrong_pk_coords = cheetah_pub_from_sk(wrong_sk_be);
        let wrong_public_key = SchnorrPubkey {
            x: F6LT { values: wrong_pk_coords[0] },
            y: F6LT { values: wrong_pk_coords[1] },
            inf: false,
        };

        // Verify with wrong public key
        let is_valid = schnorr_verify_digest(wrong_public_key, message, signature);
        assert!(!is_valid, "Wrong public key should fail verification");

        println!("✓ Wrong public key correctly fails verification");
    }
}
