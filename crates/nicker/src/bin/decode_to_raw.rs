use std::fs;
use std::path::Path;
use nockapp::noun::slab::NounSlab;
use noun_serde::{NounDecode, NounEncode};
use tx_types::transaction_types::*;
use tx_types::hashing::tx_id::compute_tx_id;
use serde_json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Decoding Draft and TX Files to RawTransaction ===\n");
    
    // Process known-good.draft
    if let Err(e) = process_file("tx/known-good.draft", "tx/known-good.raw.json") {
        eprintln!("Error processing draft file: {}", e);
    }
    
    // Process nw.known-good.tx 
    if let Err(e) = process_file("tx/nw.known-good.tx", "tx/nw.known-good.raw.json") {
        eprintln!("Error processing tx file: {}", e);
    }
    
    Ok(())
}

fn process_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing: {}", input_path);
    
    // Check if file exists
    if !Path::new(input_path).exists() {
        return Err(format!("File not found: {}", input_path).into());
    }
    
    // Read the file
    let file_bytes = fs::read(input_path)?;
    println!("  File size: {} bytes", file_bytes.len());
    
    // Create noun allocator and decode JAM
    let mut slab: NounSlab = NounSlab::new();
    let noun = slab.cue_into(file_bytes.into())?;
    println!("  JAM decoded successfully");
    
    // Try to parse as Transaction first
    let transaction = Transaction::from_noun(&mut slab, &noun)
        .map_err(|e| format!("Failed to decode as Transaction: {:?}", e))?;
    
    println!("  Transaction Name/ID: {}", transaction.name);
    
    // Convert Transaction to RawTransaction
    let raw_tx = convert_to_raw_transaction(transaction)?;
    
    // Save as JSON for readability
    let json = serde_json::to_string_pretty(&RawTransactionJson::from(&raw_tx))?;
    fs::write(output_path, json)?;
    println!("  Saved to: {}", output_path);
    
    // Also save as JAM-encoded RawTransaction
    let jam_output = output_path.replace(".json", ".jam");
    let mut output_slab: NounSlab = NounSlab::new();
    let raw_noun = raw_tx.to_noun(&mut output_slab);
    output_slab.copy_into(raw_noun);
    let jam_bytes = output_slab.jam();
    fs::write(&jam_output, jam_bytes)?;
    println!("  Also saved JAM to: {}", jam_output);
    
    println!();
    Ok(())
}

fn convert_to_raw_transaction(tx: Transaction) -> Result<RawTransaction, Box<dyn std::error::Error>> {
    // Extract inputs
    let inputs = tx.p; // This is already an Inputs struct
    
    // Calculate total fees
    let total_fees_value: u64 = inputs.p.tap()
        .iter()
        .map(|(_, input)| input.spend.fee.value)
        .sum();
    
    // Calculate timelock range from all inputs
    let timelock_range = calculate_timelock_range_from_inputs(&inputs)?;
    
    // Compute the transaction ID
    let id = compute_tx_id(&inputs.p, &timelock_range, total_fees_value);
    
    Ok(RawTransaction {
        id,
        inputs,
        timelock_range,
        total_fees: Coins { value: total_fees_value },
    })
}

fn calculate_timelock_range_from_inputs(inputs: &Inputs) -> Result<TimelockRange, Box<dyn std::error::Error>> {
    let input_list: Vec<_> = inputs.p.tap();
    
    if input_list.is_empty() {
        return Ok(TimelockRange { min: None, max: None });
    }
    
    // Collect all timelock ranges from inputs
    let mut min_page: Option<u64> = None;
    let mut max_page: Option<u64> = None;
    
    for (_, input) in &input_list {
        // Check note's timelock
        if let Some((abs_range, _rel_range)) = &input.note.meta.timelock.intent {
            // Process absolute range
            if let Some(min) = &abs_range.min {
                min_page = Some(min_page.map_or(min.value, |m| m.min(min.value)));
            }
            if let Some(max) = &abs_range.max {
                max_page = Some(max_page.map_or(max.value, |m| m.max(max.value)));
            }
        }
        
        // Check seeds' timelock intents
        for seed in input.spend.seeds.set.tap() {
            if let Some((abs_range, _rel_range)) = &seed.timelock_intent {
                if let Some(min) = &abs_range.min {
                    min_page = Some(min_page.map_or(min.value, |m| m.min(min.value)));
                }
                if let Some(max) = &abs_range.max {
                    max_page = Some(max_page.map_or(max.value, |m| m.max(max.value)));
                }
            }
        }
    }
    
    Ok(TimelockRange {
        min: min_page.map(|v| PageNumber { value: v }),
        max: max_page.map(|v| PageNumber { value: v }),
    })
}

// JSON-serializable version of RawTransaction for readability
#[derive(serde::Serialize, serde::Deserialize)]
struct RawTransactionJson {
    id: String,  // Hex string
    inputs_count: usize,
    timelock_range: TimelockRangeJson,
    total_fees: u64,
    // Include summary of inputs
    input_summaries: Vec<InputSummary>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TimelockRangeJson {
    min: Option<u64>,
    max: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct InputSummary {
    key: String,  // Debug format of NName
    note_assets: u64,
    spend_fee: u64,
    seeds_count: usize,
    has_signature: bool,
}

impl From<&RawTransaction> for RawTransactionJson {
    fn from(raw: &RawTransaction) -> Self {
        let inputs_list = raw.inputs.p.tap();
        
        let input_summaries: Vec<InputSummary> = inputs_list
            .iter()
            .map(|(key, input)| InputSummary {
                key: format!("{:?}", key),
                note_assets: input.note.assets.value,
                spend_fee: input.spend.fee.value,
                seeds_count: input.spend.seeds.set.tap().len(),
                has_signature: input.spend.signature.is_some(),
            })
            .collect();
        
        RawTransactionJson {
            id: format!("{:016x?}", raw.id.values),
            inputs_count: inputs_list.len(),
            timelock_range: TimelockRangeJson {
                min: raw.timelock_range.min.as_ref().map(|p| p.value),
                max: raw.timelock_range.max.as_ref().map(|p| p.value),
            },
            total_fees: raw.total_fees.value,
            input_summaries,
        }
    }
}