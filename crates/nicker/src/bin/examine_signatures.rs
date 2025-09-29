use std::fs;
use nockapp::noun::slab::NounSlab;
use noun_serde::NounDecode;
use tx_types::transaction_types::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Examining Signatures in Transaction Files ===\n");
    
    // Load unsigned transaction
    let unsigned_jam = fs::read("tx/known-good.raw.jam")?;
    let mut slab1: NounSlab = NounSlab::new();
    let noun1 = slab1.cue_into(unsigned_jam.into())?;
    let unsigned_tx = RawTransaction::from_noun(&mut slab1, &noun1)?;
    
    // Load signed transaction
    let signed_jam = fs::read("tx/nw.known-good.raw.jam")?;
    let mut slab2: NounSlab = NounSlab::new();
    let noun2 = slab2.cue_into(signed_jam.into())?;
    let signed_tx = RawTransaction::from_noun(&mut slab2, &noun2)?;
    
    println!("Unsigned TX ID: {:016x?}", unsigned_tx.id.values);
    println!("Signed TX ID:   {:016x?}", signed_tx.id.values);
    println!();
    
    // Compare inputs
    let unsigned_inputs = unsigned_tx.inputs.p.tap();
    let signed_inputs = signed_tx.inputs.p.tap();
    
    for (i, ((key1, input1), (key2, input2))) in unsigned_inputs.iter()
        .zip(signed_inputs.iter())
        .enumerate()
    {
        println!("Input #{}", i);
        println!("  Key matches: {}", format!("{:?}", key1) == format!("{:?}", key2));
        
        // Check spend differences
        println!("  Unsigned has signature: {}", input1.spend.signature.is_some());
        println!("  Signed has signature: {}", input2.spend.signature.is_some());
        
        if let Some(ref sig) = input2.spend.signature {
            // Get the first signature (there should be only one in this test)
            if let Some((pubkey, schnorr_sig)) = sig.map.tap().first() {
                println!("\n  Signature details:");
                println!("    Public key X: {:016x?}", pubkey.x.values);
                println!("    Public key Y: {:016x?}", pubkey.y.values);
                println!("    Challenge:    {:016x?}", schnorr_sig.chal.values.values);
                println!("    Signature s:  {:016x?}", schnorr_sig.sig.values.values);
                
                // Compute what the sig_hash should be for this spend
                let sig_hash = input2.spend.sig_hash();
                println!("\n  Computed sig_hash: {:016x?}", sig_hash.values);
            }
        }
        
        // Check that the spends are otherwise identical
        let mut spend1_for_compare = input1.spend.clone();
        let mut spend2_for_compare = input2.spend.clone();
        spend1_for_compare.signature = None;
        spend2_for_compare.signature = None;
        
        println!("  Spends identical (except sig): {}", 
            format!("{:?}", spend1_for_compare) == format!("{:?}", spend2_for_compare));
    }
    
    Ok(())
}