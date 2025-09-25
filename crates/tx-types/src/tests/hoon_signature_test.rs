/// Test that verifies signature generation matches Hoon output exactly
/// Uses the test secret key to generate and verify signatures

use crate::collections::{ZMap, ZSet};
use crate::transaction_types::*;
use crate::hashing::{compute_tx_id, sig_hash_for_input};
use crate::crypto::cheetah::point::cheetah_pub_from_sk;
use crate::signer::schnorr_sign_digest;

#[test]
fn test_hoon_signature_generation() {
    // ===== Test secret key from Hoon =====
    let secret_key_be: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];

    // ===== Derive public key from secret key =====
    let derived_pk = cheetah_pub_from_sk(secret_key_be);
    
    // Expected sender public key from Hoon (MSW..LSW order)
    let expected_pk: ([u64; 6], [u64; 6]) = (
        [
            11_532_431_931_696_133_539, // MSW (a5 in Hoon)
            6_871_293_856_171_770_838,  // a4
            15_913_798_201_200_938_686, // a3
            8_724_446_291_889_705_637,  // a2
            8_604_621_052_628_066_076,  // a1
            9_323_455_886_065_152_710,  // LSW (a0 in Hoon)
        ],
        [
            14_820_844_833_610_271_254, // MSW (a5 in Hoon)
            11_730_999_058_788_639_792, // a4
            4_053_240_175_695_272_783,  // a3
            8_639_946_714_446_054_618,  // a2
            10_485_181_329_625_226_048, // a1
            10_242_415_564_008_566_488, // LSW (a0 in Hoon)
        ]
    );
    
    println!("Derived public key:");
    println!("  x: {:?}", derived_pk[0]);
    println!("  y: {:?}", derived_pk[1]);
    println!("Expected public key:");
    println!("  x: {:?}", expected_pk.0);
    println!("  y: {:?}", expected_pk.1);
    
    // Verify the derived public key matches (need to reverse order since our function returns LSW first, test expects MSW first)
    let mut derived_x_msw = derived_pk[0];
    derived_x_msw.reverse();
    let mut derived_y_msw = derived_pk[1];
    derived_y_msw.reverse();
    
    assert_eq!(derived_x_msw, expected_pk.0, "Public key X coordinate should match Hoon");
    assert_eq!(derived_y_msw, expected_pk.1, "Public key Y coordinate should match Hoon");

    // ===== Build the transaction exactly as in Hoon =====
    
    // Create sender pubkey for transaction
    let sender_pubkey = SchnorrPubkey {
        x: F6LT { values: derived_x_msw },
        y: F6LT { values: derived_y_msw },
        inf: false,
    };

    // Recipient public key (MSW..LSW order)
    let recipient_pubkey = SchnorrPubkey {
        x: F6LT {
            values: [
                8_416_537_967_201_960_637,  // MSW
                14_509_848_718_396_549_337,
                12_777_071_888_658_526_580,
                9_515_508_946_745_098_356,
                9_770_049_083_337_082_219,
                17_337_564_960_735_776_292, // LSW
            ],
        },
        y: F6LT {
            values: [
                14_531_133_279_166_029_937, // MSW
                3_165_750_163_839_130_116,
                4_212_249_255_414_212_885,
                10_580_055_472_234_038_155,
                8_110_604_973_073_775_867,
                7_464_310_024_560_629_947,  // LSW
            ],
        },
        inf: false,
    };

    // Input note name
    let input_name = NName {
        p: vec![
            Hash {
                values: [
                    0x1823_f2b1_7cba_6a60,
                    0xf21d_6e62_41ad_b7c2,
                    0xcc5a_5597_4af3_8483,
                    0x9552_4fbf_2e34_cb94,
                    0xfd99_8aff_5184_4889,
                ],
            },
            Hash {
                values: [
                    0xb68f_338b_6405_3dc0,
                    0xf2e8_b88c_b1e4_fe55,
                    0xf4d2_edc2_b560_4059,
                    0xcd0e_3527_7397_8c7b,
                    0x24fc_3bc8_ae97_b70e,
                ],
            },
        ],
    };

    // Create input note
    let mut sender_pubkeys = ZSet::new();
    sender_pubkeys.put(sender_pubkey.clone());

    let input_note = NNote {
        meta: NNoteHead {
            version: 0,
            origin_page: PageNumber { value: 1 },
            timelock: Timelock { intent: None },
        },
        name: input_name.clone(),
        lock: Lock {
            m: 1,
            pubkeys: sender_pubkeys.clone(),
        },
        source: Source {
            p: Hash { values: [0, 0, 0, 0, 0] },
            is_coinbase: true,
        },
        assets: Coins { value: 100 },
    };

    // Parent hash for outputs
    let parent_hash = Hash {
        values: [
            0x49d8_ec23_bedb_5ebf,
            0xab86_7316_14a8_95b4,
            0xc945_61ba_adb6_ce58,
            0x8735_8c72_08cc_9c5d,
            0xd048_23a9_eb56_7b2e,
        ],
    };

    // Create seeds (outputs)
    let mut recipient_pubkeys = ZSet::new();
    recipient_pubkeys.put(recipient_pubkey.clone());
    
    let payment_seed = Seed {
        output_source: None,
        recipient: Lock {
            m: 1,
            pubkeys: recipient_pubkeys,
        },
        timelock_intent: TimelockIntent::None,
        gift: Coins { value: 80 },
        parent_hash: parent_hash.clone(),
    };

    let change_seed = Seed {
        output_source: None,
        recipient: Lock {
            m: 1,
            pubkeys: sender_pubkeys.clone(),
        },
        timelock_intent: TimelockIntent::None,
        gift: Coins { value: 5 },
        parent_hash: parent_hash.clone(),
    };

    let mut seeds_set = ZSet::new();
    seeds_set.put(payment_seed);
    seeds_set.put(change_seed);

    // Create spend
    let spend = Spend {
        signature: None,
        seeds: Seeds { set: seeds_set },
        fee: Coins { value: 15 },
    };

    // Create input
    let input = Input {
        note: input_note,
        spend,
    };

    // Create inputs map
    let mut inputs_map = ZMap::new();
    inputs_map.put(input_name.clone(), input);

    // ===== Compute transaction ID and sig hash =====
    let timelock_range = TimelockRange {
        min: None,
        max: None,
    };
    
    let tx_id = compute_tx_id(&inputs_map, &timelock_range, 15);
    
    // Expected transaction ID from Hoon
    let expected_tx_id = Hash {
        values: [
            0x6607_6457_430c_d5c4,
            0x1adf_4e4d_2628_aba8,
            0x6f06_bda8_c947_558c,
            0x8585_e843_461d_e513,
            0xbf15_bf2a_8393_602d,
        ],
    };
    
    println!("\nTransaction IDs:");
    println!("  Computed: {:?}", tx_id.values);
    println!("  Expected: {:?}", expected_tx_id.values);
    assert_eq!(tx_id, expected_tx_id, "Transaction ID should match");

    // ===== Generate signature =====
    
    // Create the raw transaction structure for sig hash computation
    let raw_tx = RawTransaction {
        id: tx_id.clone(),
        inputs: Inputs { p: inputs_map.clone() },
        timelock_range: timelock_range.clone(),
        total_fees: Coins { value: 15 },
    };
    
    // Get the sig hash for this input
    let sig_hash_5 = sig_hash_for_input(&raw_tx, &input_name);
    
    println!("\nSignature hash (5 words): {:?}", sig_hash_5);
    
    // Generate Schnorr signature using Cheetah  
    let (chal_t8, sig_t8) = schnorr_sign_digest(secret_key_be, (derived_x_msw, derived_y_msw), sig_hash_5.values);
    
    // Expected signature from Hoon
    let expected_chal = T8 {
        values: [
            0x8aad_e466,
            0xcc70_593a,
            0x0971_fc7d,  // Note: Hoon has 0x971_fc7d without leading zero
            0x7424_0296,
            0x32b9_fcdc,
            0x6f60_ef62,
            0xaab4_413a,
            0x6414_d6a7,
        ],
    };
    
    let expected_sig = T8 {
        values: [
            0xa51c_2c8c,
            0xa4d1_45e3,
            0xe481_e5cc,
            0x4b7f_f660,
            0xba75_862d,
            0x2335_33c6,
            0x14c1_1d3a,
            0x1649_f662,
        ],
    };
    
    println!("\nGenerated signature:");
    println!("  Challenge: {:?}", chal_t8.values);
    println!("  Response:  {:?}", sig_t8.values);
    println!("\nExpected signature:");
    println!("  Challenge: {:?}", expected_chal.values);
    println!("  Response:  {:?}", expected_sig.values);
    
    // Verify the signature matches
    assert_eq!(chal_t8, expected_chal, "Challenge should match Hoon output");
    assert_eq!(sig_t8, expected_sig, "Response should match Hoon output");
    
    println!("\n✓ All tests passed!");
    println!("✓ Public key derivation matches");
    println!("✓ Transaction ID matches");
    println!("✓ Signature generation matches Hoon exactly");
}

#[test]
fn test_secret_key_format() {
    // Verify the secret key is correctly formatted
    let secret_key_be: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];
    
    // Print as hex for verification
    print!("Secret key (hex): 0x");
    for byte in secret_key_be.iter() {
        print!("{:02x}", byte);
    }
    println!();
    
    // Verify it matches the provided format
    let expected = "0x1234.5678.9abc.def0.1234.5678.9abc.def0.1234.5678.9abc.def0.1234.5678.9abc.def0";
    let mut actual_hex = String::from("0x");
    for byte in secret_key_be.iter() {
        actual_hex.push_str(&format!("{:02x}", byte));
    }
    let expected_clean = expected.replace(".", "");
    
    assert_eq!(actual_hex, expected_clean, "Secret key format should match");
}