use std::fs;
use std::env;
use nockapp::noun::slab::NounSlab;
use noun_serde::NounDecode;
use tx_types::transaction_types::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let draft_path = if args.len() > 1 {
        &args[1]
    } else {
        "2025.9.09..16.58.39-tx/known-good.draft"
    };
    
    println!("=== Unpacking Draft Transaction with Nicker ===\n");
    println!("Reading: {}", draft_path);
    
    // Read the draft file
    let draft_bytes = fs::read(draft_path)?;
    println!("File size: {} bytes", draft_bytes.len());
    
    // Create noun allocator and decode JAM
    let mut slab: NounSlab = NounSlab::new();
    let noun = slab.cue_into(draft_bytes.into())?;
    println!("JAM decoded successfully\n");
    
    // Parse as Transaction
    let transaction = Transaction::from_noun(&noun)
        .map_err(|e| format!("Failed to decode transaction: {:?}", e))?;
    
    println!("=== Transaction Contents ===");
    println!("Transaction Name/ID: {}", transaction.name);
    println!();
    
    // Access the inputs through the ZMap
    let inputs = &transaction.p.p;
    
    // The ZMap has a tap() method that gives us an iterator
    let input_vec: Vec<_> = inputs.tap();
    println!("Number of inputs: {}", input_vec.len());
    println!();
    
    // Display each input
    for (idx, (key, input)) in input_vec.iter().enumerate() {
        println!("Input #{} (key: {:?})", idx + 1, key);  // Use {:?} for NName
        println!("  Note details:");
        
        // Note contains the UTXO being spent
        let note = &input.note;
        println!("    Assets: {} coins", note.assets.value);
        
        // Note metadata
        println!("    Meta:");
        println!("      Version: {}", note.meta.version);
        println!("      Origin page: {}", note.meta.origin_page.value);
        
        // Lock shows who can spend this
        println!("    Lock:");
        println!("      M (threshold): {}", note.lock.m);
        
        // Count pubkeys in the lock
        let pubkeys_vec: Vec<_> = note.lock.pubkeys.tap();
        println!("      Required signers: {} of {} pubkeys", note.lock.m, pubkeys_vec.len());
        
        if !pubkeys_vec.is_empty() && idx == 0 {
            // Show first pubkey as example
            let pk = &pubkeys_vec[0];
            println!("      First pubkey:");
            println!("        x: {:?}", pk.x.values);
            println!("        y: {:?}", pk.y.values);
            println!("        inf: {}", pk.inf);
        }
        
        // Spend shows how we're spending it
        println!("    Spend:");
        
        // Check for signature (should be None in draft)
        if let Some(sig) = &input.spend.signature {
            let sig_map: Vec<_> = sig.map.tap();
            println!("      ⚠️ Signatures present: {} (unexpected in draft!)", sig_map.len());
        } else {
            println!("      ✓ No signatures (correct for draft)");
        }
        
        // Seeds (outputs being created)
        let seeds_vec: Vec<_> = input.spend.seeds.set.tap();
        println!("      Seeds (new outputs): {} seeds", seeds_vec.len());
        
        for (seed_idx, seed) in seeds_vec.iter().enumerate() {
            if seed_idx < 2 {  // Show first 2 seeds
                println!("        Seed {}:", seed_idx + 1);
                println!("          Gift amount: {} coins", seed.gift.value);
                println!("          Recipient Lock M: {}", seed.recipient.m);
                
                // Show recipient pubkeys
                let seed_pubkeys: Vec<_> = seed.recipient.pubkeys.tap();
                println!("          Recipients: {} pubkeys", seed_pubkeys.len());
                println!("          Parent hash: {:?}", seed.parent_hash.values);
            }
        }
        
        println!("      Fee: {} coins", input.spend.fee.value);
        println!();
    }
    
    // Calculate totals
    let mut total_input = 0u64;
    let mut total_output = 0u64;
    let mut total_fees = 0u64;
    
    for (_, input) in input_vec.iter() {
        total_input += input.note.assets.value;
        total_fees += input.spend.fee.value;
        
        let seeds: Vec<_> = input.spend.seeds.set.tap();
        for seed in seeds.iter() {
            total_output += seed.gift.value;
        }
    }
    
    println!("=== Transaction Summary ===");
    println!("Total input value:  {} coins", total_input);
    println!("Total output value: {} coins", total_output);
    println!("Transaction fees:   {} coins", total_fees);
    println!("Balance check: {} + {} = {}", total_output, total_fees, total_output + total_fees);
    println!();
    
    println!("This is an UNSIGNED draft transaction.");
    println!("To sign it, use: nicker sign --draft {} --seed <seed_phrase>", draft_path);
    
    Ok(())
}