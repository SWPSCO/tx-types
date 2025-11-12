//! Tests to capture intermediate values in sig_hash computation
//! These are the "known-good" values from the working CLI implementation

use nockapp::noun::slab::NounSlab;
use nockapp::Bytes;
use noun_serde::{NounDecode, NounEncode};
use std::fs;
use tx_types::hashing::hasher::hash_hashable;
use tx_types::*;

#[test]
fn test_demo_tx_sig_hash_intermediate_values() {
    // Load the demo-tx.draft file
    let draft_bytes = fs::read("../../siger-esp/demo-tx.draft").expect("demo-tx.draft not found");
    let mut slab: NounSlab = NounSlab::new();
    let noun = slab.cue_into(Bytes::from(draft_bytes)).expect("cue failed");

    let tx = Transaction::from_noun(&noun).expect("parse failed");
    let raw = RawTransaction {
        id: Hash { values: [0; 5] },
        inputs: tx.p.clone(),
        timelock_range: TimelockRange {
            min: None,
            max: None,
        },
        total_fees: Coins { value: 1 },
    };

    // Get the first input
    let all_inputs: Vec<_> = raw.inputs.p.tap();
    let (name, input) = all_inputs.first().expect("no inputs");

    println!("\n=== INPUT DETAILS ===");
    println!(
        "Input name: first={}, last={}",
        name.p[0].to_b58(),
        name.p[1].to_b58()
    );

    let mut spend = input.spend.clone();
    spend.signature = None;

    println!("\n=== SPEND DETAILS ===");
    println!("Fee: {}", spend.fee.value);
    println!("Number of seeds: {}", spend.seeds.set.wyt());

    // Get seeds info
    let seeds_vec: Vec<_> = spend.seeds.set.tap();
    for (i, seed) in seeds_vec.iter().enumerate() {
        println!(
            "\nSeed {}: gift={}, parent={}",
            i,
            seed.gift.value,
            format!(
                "{:016x}_{:016x}...",
                seed.parent_hash.values[0], seed.parent_hash.values[1]
            )
        );
        println!(
            "  Recipient: m={}, pubkeys={}",
            seed.recipient.m,
            seed.recipient.pubkeys.wyt()
        );
        let pks: Vec<_> = seed.recipient.pubkeys.tap();
        for (j, pk) in pks.iter().enumerate() {
            println!(
                "    pk[{}]: x[0]={}, y[0]={}",
                j, pk.x.values[0], pk.y.values[0]
            );
        }
    }

    // Compute the sig_hashable structure
    println!("\n=== HASHABLE STRUCTURE ===");
    let seeds_sig_hashable = spend.seeds.to_sig_hashable();
    println!("Seeds sig_hashable structure created");

    // Hash the seeds structure
    let seeds_hash = hash_hashable(&seeds_sig_hashable);
    println!(
        "Seeds hash: {:016x}_{:016x}_{:016x}_{:016x}_{:016x}",
        seeds_hash.values[0],
        seeds_hash.values[1],
        seeds_hash.values[2],
        seeds_hash.values[3],
        seeds_hash.values[4]
    );

    // Compute final sig_hash
    let sig_hash = spend.sig_hash();
    println!("\n=== FINAL SIG_HASH ===");
    println!(
        "sig_hash: {:016x}_{:016x}_{:016x}_{:016x}_{:016x}",
        sig_hash.values[0],
        sig_hash.values[1],
        sig_hash.values[2],
        sig_hash.values[3],
        sig_hash.values[4]
    );

    // Expected value from CLI
    let expected =
        "b5a460c35639f670_5669f17d0d1c673b_7117e0793673d153_08351a9913062377_cf9bbbba73a69824";
    let actual = format!(
        "{:016x}_{:016x}_{:016x}_{:016x}_{:016x}",
        sig_hash.values[0],
        sig_hash.values[1],
        sig_hash.values[2],
        sig_hash.values[3],
        sig_hash.values[4]
    );

    assert_eq!(actual, expected, "sig_hash mismatch!");
}

#[test]
fn test_pubkey_hashing() {
    // Test how a single pubkey gets hashed
    use tx_types::hashing::tip5::Tip5Hasher;

    // Create a test pubkey (the one from demo-tx)
    let pk = SchnorrPubkey {
        x: F6LT {
            values: [
                1213264621707318396,
                7644592116046038696,
                12750713645667184650,
                4785470970688526859,
                14650880413807991875,
                12274556524416646944,
            ],
        },
        y: F6LT {
            values: [
                18177236637613408617,
                10958279360383408893,
                1240025389805216209,
                14139010256592505920,
                18119211718294268888,
                6152380099229918899,
            ],
        },
        inf: false,
    };

    // Hash it the correct way (via noun)
    let mut slab: NounSlab = NounSlab::new();
    let pk_noun = pk.to_noun(&mut slab);
    let pk_hash = Tip5Hasher::hash_noun_varlen(pk_noun).unwrap();

    println!("\n=== PUBKEY HASH ===");
    println!(
        "Pubkey hash: {:016x}_{:016x}_{:016x}_{:016x}_{:016x}",
        pk_hash.values[0],
        pk_hash.values[1],
        pk_hash.values[2],
        pk_hash.values[3],
        pk_hash.values[4]
    );
}
