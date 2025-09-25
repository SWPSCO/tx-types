/// Test that verifies transaction ID generation matches Hoon output exactly
/// This test creates the same transaction as the Hoon generator and verifies
/// the transaction ID matches exactly.

use crate::collections::{ZMap, ZSet};
use crate::transaction_types::*;
use crate::hashing::tx_id::compute_tx_id;

#[test]
fn signing_test() {
    println!("\n=== Testing Transaction ID Generation Against Hoon ===\n");

    // ===== Sender public key from Hoon =====
    // In a0-a5 (LSW→MSW) order as expected by Hoon
    let sender_pubkey = SchnorrPubkey {
        x: F6LT { values: [
            9_323_455_886_065_152_710,  // a0 (LSW)
            8_604_621_052_628_066_076,  // a1
            8_724_446_291_889_705_637,  // a2
            15_913_798_201_200_938_686, // a3
            6_871_293_856_171_770_838,  // a4
            11_532_431_931_696_133_539, // a5 (MSW)
        ]},
        y: F6LT { values: [
            10_242_415_564_008_566_488, // a0 (LSW)
            10_485_181_329_625_226_048, // a1
            8_639_946_714_446_054_618,  // a2
            4_053_240_175_695_272_783,  // a3
            11_730_999_058_788_639_792, // a4
            14_820_844_833_610_271_254, // a5 (MSW)
        ]},
        inf: false,
    };

    // ===== Recipient public key =====
    // Also in a0-a5 (LSW→MSW) order
    let recipient_pubkey = SchnorrPubkey {
        x: F6LT { values: [
            17_337_564_960_735_776_292, // a0 (LSW)
            9_770_049_083_337_082_219,  // a1
            9_515_508_946_745_098_356,  // a2
            12_777_071_888_658_526_580, // a3
            14_509_848_718_396_549_337, // a4
            8_416_537_967_201_960_637,  // a5 (MSW)
        ]},
        y: F6LT { values: [
            7_464_310_024_560_629_947,  // a0 (LSW)
            8_110_604_973_073_775_867,  // a1
            10_580_055_472_234_038_155, // a2
            4_212_249_255_414_212_885,  // a3
            3_165_750_163_839_130_116,  // a4
            14_531_133_279_166_029_937, // a5 (MSW)
        ]},
        inf: false,
    };

    // ===== Create the input note =====
    let note_name = NName {
        p: vec![
            Hash { values: [
                0x1823_f2b1_7cba_6a60,
                0xf21d_6e62_41ad_b7c2,
                0xcc5a_5597_4af3_8483,
                0x9552_4fbf_2e34_cb94,
                0xfd99_8aff_5184_4889,
            ]},
            Hash { values: [
                0xb68f_338b_6405_3dc0,
                0xf2e8_b88c_b1e4_fe55,
                0xf4d2_edc2_b560_4059,
                0xcd0e_3527_7397_8c7b,
                0x24fc_3bc8_ae97_b70e,
            ]},
        ],
    };

    // Create the lock (m=1, single pubkey)
    let mut lock_pubkeys = ZSet::new();
    lock_pubkeys.put(sender_pubkey.clone());

    let lock = Lock {
        m: 1,
        pubkeys: lock_pubkeys,
    };

    // Create the source (coinbase)
    let source = Source {
        p: Hash { values: [0, 0, 0, 0, 0] },
        is_coinbase: true,
    };

    // Create the note head
    let note_head = NNoteHead {
        version: 0,
        origin_page: PageNumber { value: 1 },
        timelock: Timelock { intent: None },
    };

    // Create the note
    let note = NNote {
        meta: note_head,
        name: note_name.clone(),
        lock: lock.clone(),
        source,
        assets: Coins { value: 100 },
    };

    // ===== Create the seeds (outputs) =====
    let parent_hash = Hash { values: [
        0x49d8_ec23_bedb_5ebf,
        0xab86_7316_14a8_95b4,
        0xc945_61ba_adb6_ce58,
        0x8735_8c72_08cc_9c5d,
        0xd048_23a9_eb56_7b2e,
    ]};

    // Payment output (80 coins to recipient)
    let mut payment_lock_pubkeys = ZSet::new();
    payment_lock_pubkeys.put(recipient_pubkey.clone());

    let payment_seed = Seed {
        output_source: None,
        recipient: Lock {
            m: 1,
            pubkeys: payment_lock_pubkeys,
        },
        timelock_intent: None,
        gift: Coins { value: 80 },
        parent_hash: parent_hash.clone(),
    };

    // Change output (5 coins back to sender)
    let mut change_lock_pubkeys = ZSet::new();
    change_lock_pubkeys.put(sender_pubkey.clone());

    let change_seed = Seed {
        output_source: None,
        recipient: Lock {
            m: 1,
            pubkeys: change_lock_pubkeys,
        },
        timelock_intent: None,
        gift: Coins { value: 5 },
        parent_hash: parent_hash.clone(),
    };

    // Build seeds tree
    let mut seeds_set = ZSet::new();
    seeds_set.put(change_seed);
    seeds_set.put(payment_seed);
    
    let seeds = Seeds { set: seeds_set };

    // ===== Create the signature structure =====
    // Expected signature from Hoon
    let expected_chal = T8 {
        values: [
            0x8aad_e466,
            0xcc70_593a,
            0x0971_fc7d,  // Note: Hoon shows 0x971.fc7d
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

    // Create signature structure
    let schnorr_signature = SchnorrSignature {
        chal: Chal { values: expected_chal },
        sig: Sig { values: expected_sig },
    };

    let mut signature_map = ZMap::new();
    signature_map.put(sender_pubkey.clone(), schnorr_signature);

    let signature = Some(Signature {
        map: signature_map,
    });

    // ===== Create the spend =====
    let spend = Spend {
        signature,
        seeds,
        fee: Coins { value: 15 },
    };

    // ===== Create the input =====
    let input = Input {
        note: note.clone(),
        spend: spend.clone(),
    };

    // ===== Build the transaction =====
    // Create inputs map
    let mut inputs_map = ZMap::new();
    inputs_map.put(note_name.clone(), input);

    // Compute the transaction ID
    let timelock_range = TimelockRange { min: None, max: None };
    let total_fees = 15u64;

    let tx_id = compute_tx_id(&inputs_map, &timelock_range, total_fees);

    println!("Computed transaction ID:");
    println!("  {:016x?}", tx_id.values);

    // Expected transaction ID from Hoon
    let expected_tx_id = Hash { values: [
        0x6607_6457_430c_d5c4,
        0x1adf_4e4d_2628_aba8,
        0x6f06_bda8_c947_558c,
        0x8585_e843_461d_e513,
        0xbf15_bf2a_8393_602d,
    ]};

    println!("Expected transaction ID:");
    println!("  {:016x?}", expected_tx_id.values);

    assert_eq!(tx_id, expected_tx_id, "Transaction ID should match Hoon output exactly");

    println!("✓ Transaction ID generation matches Hoon exactly!");
}

#[test]
fn signing_test_just_txid() {
    println!("\n=== Testing Transaction ID Generation from Hoon Raw Transaction ===\n");

    // ===== Expected transaction ID from Hoon raw transaction =====
    let expected_tx_id = Hash {
        values: [
            0x6607_6457_430c_d5c4,
            0x1adf_4e4d_2628_aba8,
            0x6f06_bda8_c947_558c,
            0x8585_e843_461d_e513,
            0xbf15_bf2a_8393_602d,
        ],
    };

    // ===== Construct the sender pubkey (a0-a5 from Hoon) =====
    let sender_pubkey = SchnorrPubkey {
        x: F6LT {
            values: [
                9_323_455_886_065_152_710,  // a0
                8_604_621_052_628_066_076,  // a1
                8_724_446_291_889_705_637,  // a2
                15_913_798_201_200_938_686, // a3
                6_871_293_856_171_770_838,  // a4
                11_532_431_931_696_133_539, // a5
            ],
        },
        y: F6LT {
            values: [
                10_242_415_564_008_566_488, // a0
                10_485_181_329_625_226_048, // a1
                8_639_946_714_446_054_618,  // a2
                4_053_240_175_695_272_783,  // a3
                11_730_999_058_788_639_792, // a4
                14_820_844_833_610_271_254, // a5
            ],
        },
        inf: false,
    };

    // ===== Construct the recipient pubkey (a0-a5 from Hoon) =====
    let recipient_pubkey = SchnorrPubkey {
        x: F6LT {
            values: [
                17_337_564_960_735_776_292, // a0
                9_770_049_083_337_082_219,  // a1
                9_515_508_946_745_098_356,  // a2
                12_777_071_888_658_526_580, // a3
                14_509_848_718_396_549_337, // a4
                8_416_537_967_201_960_637,  // a5
            ],
        },
        y: F6LT {
            values: [
                7_464_310_024_560_629_947,  // a0
                8_110_604_973_073_775_867,  // a1
                10_580_055_472_234_038_155, // a2
                4_212_249_255_414_212_885,  // a3
                3_165_750_163_839_130_116,  // a4
                14_531_133_279_166_029_937, // a5
            ],
        },
        inf: false,
    };

    // ===== Input note name (two hashes, then empty) =====
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

    // ===== Create input note =====
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

    // ===== Parent hash for outputs =====
    let parent_hash = Hash {
        values: [
            0x49d8_ec23_bedb_5ebf,
            0xab86_7316_14a8_95b4,
            0xc945_61ba_adb6_ce58,
            0x8735_8c72_08cc_9c5d,
            0xd048_23a9_eb56_7b2e,
        ],
    };

    // ===== Create the signature (challenge and response from Hoon) =====
    let challenge = T8 {
        values: [
            0x8aad_e466,
            0xcc70_593a,
            0x0971_fc7d,  // Note: Hoon shows 0x971.fc7d
            0x7424_0296,
            0x32b9_fcdc,
            0x6f60_ef62,
            0xaab4_413a,
            0x6414_d6a7,
        ],
    };

    let response = T8 {
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

    // ===== Create signature structure =====
    let schnorr_signature = SchnorrSignature {
        chal: Chal { values: challenge },
        sig: Sig { values: response },
    };

    let mut signature_map = ZMap::new();
    signature_map.put(sender_pubkey.clone(), schnorr_signature);

    // ===== Create seeds (outputs) =====
    // Change seed (5 coins to sender) - this is 'n' in the Hoon seeds structure
    let change_seed = Seed {
        output_source: None,
        recipient: Lock {
            m: 1,
            pubkeys: sender_pubkeys.clone(),
        },
        timelock_intent: None,
        gift: Coins { value: 5 },
        parent_hash: parent_hash.clone(),
    };

    // Payment seed (80 coins to recipient) - this is in 'l' of the Hoon seeds structure
    let mut recipient_pubkeys = ZSet::new();
    recipient_pubkeys.put(recipient_pubkey.clone());
    
    let payment_seed = Seed {
        output_source: None,
        recipient: Lock {
            m: 1,
            pubkeys: recipient_pubkeys,
        },
        timelock_intent: None,
        gift: Coins { value: 80 },
        parent_hash: parent_hash.clone(),
    };

    // ===== Construct seeds set =====
    let mut seeds_set = ZSet::new();
    seeds_set.put(change_seed);
    seeds_set.put(payment_seed);

    // ===== Create spend =====
    let spend = Spend {
        signature: Some(Signature {
            map: signature_map,
        }),
        seeds: Seeds { set: seeds_set },
        fee: Coins { value: 15 },
    };

    // ===== Create input =====
    let input = Input {
        note: input_note,
        spend,
    };

    // ===== Create inputs map =====
    let mut inputs_map = ZMap::new();
    inputs_map.put(input_name.clone(), input);

    // ===== Compute transaction ID =====
    let timelock_range = TimelockRange {
        min: None,
        max: None,
    };
    
    let computed_tx_id = compute_tx_id(&inputs_map, &timelock_range, 15);
    
    println!("Computed transaction ID:");
    println!("  {:016x?}", computed_tx_id.values);
    println!("Expected transaction ID:");
    println!("  {:016x?}", expected_tx_id.values);
    
    assert_eq!(computed_tx_id, expected_tx_id, "Transaction ID should match Hoon raw transaction output exactly");
    
    println!("✓ Transaction ID generation matches Hoon raw transaction exactly!");
}

#[test]
fn unsigned_tx_id_test() {
    println!("\n=== Testing Unsigned Transaction ID Generation ===\n");

    // ===== Construct the sender pubkey (a0-a5 from Hoon) =====
    let sender_pubkey = SchnorrPubkey {
        x: F6LT {
            values: [
                9_323_455_886_065_152_710,  // a0
                8_604_621_052_628_066_076,  // a1
                8_724_446_291_889_705_637,  // a2
                15_913_798_201_200_938_686, // a3
                6_871_293_856_171_770_838,  // a4
                11_532_431_931_696_133_539, // a5
            ],
        },
        y: F6LT {
            values: [
                10_242_415_564_008_566_488, // a0
                10_485_181_329_625_226_048, // a1
                8_639_946_714_446_054_618,  // a2
                4_053_240_175_695_272_783,  // a3
                11_730_999_058_788_639_792, // a4
                14_820_844_833_610_271_254, // a5
            ],
        },
        inf: false,
    };

    // ===== Construct the recipient pubkey (a0-a5 from Hoon) =====
    let recipient_pubkey = SchnorrPubkey {
        x: F6LT {
            values: [
                17_337_564_960_735_776_292, // a0
                9_770_049_083_337_082_219,  // a1
                9_515_508_946_745_098_356,  // a2
                12_777_071_888_658_526_580, // a3
                14_509_848_718_396_549_337, // a4
                8_416_537_967_201_960_637,  // a5
            ],
        },
        y: F6LT {
            values: [
                7_464_310_024_560_629_947,  // a0
                8_110_604_973_073_775_867,  // a1
                10_580_055_472_234_038_155, // a2
                4_212_249_255_414_212_885,  // a3
                3_165_750_163_839_130_116,  // a4
                14_531_133_279_166_029_937, // a5
            ],
        },
        inf: false,
    };

    // ===== Input note name (two hashes, then empty) =====
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

    // ===== Create input note =====
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

    // ===== Parent hash for outputs =====
    let parent_hash = Hash {
        values: [
            0x49d8_ec23_bedb_5ebf,
            0xab86_7316_14a8_95b4,
            0xc945_61ba_adb6_ce58,
            0x8735_8c72_08cc_9c5d,
            0xd048_23a9_eb56_7b2e,
        ],
    };

    // ===== Create seeds (outputs) =====
    // Change seed (5 coins to sender)
    let change_seed = Seed {
        output_source: None,
        recipient: Lock {
            m: 1,
            pubkeys: sender_pubkeys.clone(),
        },
        timelock_intent: None,
        gift: Coins { value: 5 },
        parent_hash: parent_hash.clone(),
    };

    // Payment seed (80 coins to recipient)
    let mut recipient_pubkeys = ZSet::new();
    recipient_pubkeys.put(recipient_pubkey.clone());
    
    let payment_seed = Seed {
        output_source: None,
        recipient: Lock {
            m: 1,
            pubkeys: recipient_pubkeys,
        },
        timelock_intent: None,
        gift: Coins { value: 80 },
        parent_hash: parent_hash.clone(),
    };

    // ===== Construct seeds set =====
    let mut seeds_set = ZSet::new();
    seeds_set.put(change_seed);
    seeds_set.put(payment_seed);
    
    

    // ===== Create spend WITHOUT signature =====
    let spend = Spend {
        signature: None, // No signature for unsigned transaction
        seeds: Seeds { set: seeds_set },
        fee: Coins { value: 15 },
    };

    // ===== Create input =====
    let input = Input {
        note: input_note,
        spend,
    };

    // ===== Create inputs map =====
    let mut inputs_map = ZMap::new();
    inputs_map.put(input_name.clone(), input);

    // ===== Compute transaction ID =====
    let timelock_range = TimelockRange {
        min: None,
        max: None,
    };
    
    let computed_tx_id = compute_tx_id(&inputs_map, &timelock_range, 15);
    
    println!("Computed unsigned transaction ID:");
    println!("  {:016x?}", computed_tx_id.values);
    
    // Expected base58 encoded transaction ID
    let expected_base58 = "DUrmbK1zV6mcKntLjjsPSRsPsTpuiAthE6LoLK6LzhzRU7PDBanJm8i";
    
    // Convert our computed hash to base58 to compare
    use crate::hashing::hasher::digest_to_base58;
    let computed_base58 = digest_to_base58(&computed_tx_id);
    
    println!("Computed transaction ID (base58): {}", computed_base58);
    println!("Expected transaction ID (base58): {}", expected_base58);
    
    assert_eq!(computed_base58, expected_base58, "Unsigned transaction ID should match expected base58 value");
    
    println!("✓ Unsigned transaction ID generation matches expected base58 value exactly!");
}