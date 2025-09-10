#!/usr/bin/env rust-script
//! # Transaction Signing Tool for Nockchain
//! 
//! A comprehensive command-line tool for signing Nockchain transactions using
//! the integrated cryptographic primitives.
//! 
//! ## Features
//! - Sign draft transactions from JAM files
//! - Support for BIP39 mnemonic seeds
//! - Raw private key input
//! - SLIP-10 hierarchical key derivation
//! - Compatible with nicker-generated drafts
//! 
//! ## Usage
//! ```bash
//! # Sign with mnemonic
//! cargo run --bin sign-tx -- --mnemonic "abandon abandon abandon..." --draft tx/known-good.draft
//! 
//! # Sign with seed file
//! cargo run --bin sign-tx -- --seed-file tx/seed.txt --draft tx/known-good.draft
//! 
//! # Sign with raw private key
//! cargo run --bin sign-tx -- --private-key 0123456789ABCDEF... --draft tx/known-good.draft
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use nockapp::noun::slab::NounSlab;
use nockapp::Bytes;
use noun_serde::{NounDecode, NounEncode};

// Import our crypto modules
use tx_types::crypto::{TransactionSigner, CryptoError};
use tx_types::transaction_types::*;
use tx_types::collections::ZMap;
use tx_types::tx_to_noun;

#[derive(Parser)]
#[command(name = "sign-tx")]
#[command(about = "Sign Nockchain transactions with integrated cryptography")]
#[command(version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a draft transaction
    Sign {
        /// Path to the draft transaction file (.draft or .jam)
        #[arg(short, long)]
        draft: PathBuf,
        
        /// Output path for signed transaction (defaults to input.tx)
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// BIP39 mnemonic phrase (12/24 words)
        #[arg(short, long, conflicts_with_all = ["seed_file", "private_key"])]
        mnemonic: Option<String>,
        
        /// Path to seed file containing mnemonic or raw seed
        #[arg(short, long, conflicts_with_all = ["mnemonic", "private_key"])]
        seed_file: Option<PathBuf>,
        
        /// Raw private key as hex string (64 hex characters)
        #[arg(short, long, conflicts_with_all = ["mnemonic", "seed_file"])]
        private_key: Option<String>,
        
        /// BIP39 passphrase (optional)
        #[arg(long, default_value = "")]
        passphrase: String,
        
        /// Derivation path for hierarchical keys (e.g., "m/44'/0'/0'/0/0")
        #[arg(long)]
        path: Option<String>,
        
        /// Show detailed transaction information
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Generate a new keypair
    Keygen {
        /// Generate from mnemonic instead of random
        #[arg(short, long)]
        mnemonic: Option<String>,
        
        /// BIP39 passphrase
        #[arg(long, default_value = "")]
        passphrase: String,
        
        /// Derivation path
        #[arg(long)]
        path: Option<String>,
        
        /// Output format: address, private-key, or all
        #[arg(short, long, default_value = "all")]
        format: String,
    },
    
    /// Verify a signed transaction
    Verify {
        /// Path to signed transaction file
        #[arg(short, long)]
        transaction: PathBuf,
        
        /// Show verification details
        #[arg(short, long)]
        verbose: bool,
    },
}

/// Secret source for signing
#[derive(Debug)]
enum SecretSource {
    Mnemonic { phrase: String, passphrase: String },
    SeedFile(PathBuf),
    PrivateKey(String),
}

impl SecretSource {
    /// Create a TransactionSigner from this secret source
    fn to_signer(&self) -> Result<TransactionSigner> {
        match self {
            SecretSource::Mnemonic { phrase, passphrase } => {
                TransactionSigner::from_mnemonic(phrase, passphrase)
                    .map_err(|e| anyhow!("Failed to create signer from mnemonic: {}", e))
            }
            SecretSource::SeedFile(path) => {
                let content = fs::read_to_string(path)
                    .with_context(|| format!("Failed to read seed file: {}", path.display()))?;
                
                let content = content.trim();
                
                // Try to parse as mnemonic first
                if content.split_whitespace().count() >= 12 {
                    TransactionSigner::from_mnemonic(content, "")
                        .map_err(|e| anyhow!("Failed to create signer from mnemonic in file: {}", e))
                } else {
                    // Try as hex seed
                    let seed_bytes = hex_to_bytes(content)
                        .ok_or_else(|| anyhow!("Invalid hex seed in file"))?;
                    TransactionSigner::from_seed(&seed_bytes)
                        .map_err(|e| anyhow!("Failed to create signer from seed: {}", e))
                }
            }
            SecretSource::PrivateKey(hex_key) => {
                let key_bytes = hex_to_bytes(hex_key)
                    .ok_or_else(|| anyhow!("Invalid hex private key"))?;
                if key_bytes.len() != 32 {
                    return Err(anyhow!("Private key must be exactly 32 bytes (64 hex characters)"));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                Ok(TransactionSigner::from_private_key(key))
            }
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Sign { 
            draft, 
            output, 
            mnemonic, 
            seed_file, 
            private_key, 
            passphrase, 
            path, 
            verbose 
        } => {
            sign_transaction(
                draft, output, mnemonic, seed_file, private_key, 
                passphrase, path, verbose
            )
        }
        Commands::Keygen { mnemonic, passphrase, path, format } => {
            generate_keypair(mnemonic, passphrase, path, format)
        }
        Commands::Verify { transaction, verbose } => {
            verify_transaction(transaction, verbose)
        }
    }
}

/// Sign a draft transaction
fn sign_transaction(
    draft_path: PathBuf,
    output_path: Option<PathBuf>,
    mnemonic: Option<String>,
    seed_file: Option<PathBuf>,
    private_key: Option<String>,
    passphrase: String,
    derivation_path: Option<String>,
    verbose: bool,
) -> Result<()> {
    // Determine secret source
    let secret = match (mnemonic, seed_file, private_key) {
        (Some(phrase), None, None) => SecretSource::Mnemonic { phrase, passphrase },
        (None, Some(file), None) => SecretSource::SeedFile(file),
        (None, None, Some(key)) => SecretSource::PrivateKey(key),
        _ => return Err(anyhow!("Must specify exactly one of: --mnemonic, --seed-file, or --private-key")),
    };
    
    // Create signer
    let mut signer = secret.to_signer()?;
    
    // Apply derivation path if specified
    if let Some(path_str) = derivation_path {
        let path = parse_derivation_path(&path_str)?;
        for index in path {
            signer = signer.derive_child(index)
                .map_err(|e| anyhow!("Derivation failed: {}", e))?;
        }
    }
    
    if verbose {
        let pubkey = signer.get_public_key();
        println!("Signer public key: {}", pubkey.to_b58());
    }
    
    // Read and parse draft transaction
    let draft_bytes = fs::read(&draft_path)
        .with_context(|| format!("Failed to read draft file: {}", draft_path.display()))?;
    
    println!("Reading draft: {} ({} bytes)", draft_path.display(), draft_bytes.len());
    
    let mut slab = NounSlab::new();
    let noun = slab.cue_into(Bytes::from(draft_bytes))
        .map_err(|e| anyhow!("Failed to decode JAM: {:?}", e))?;
    
    let mut transaction = Transaction::from_noun(&mut slab, &noun)
        .map_err(|e| anyhow!("Failed to decode transaction: {:?}", e))?;
    
    if verbose {
        println!("Transaction ID: {}", transaction.name);
        println!("Number of inputs: {}", transaction.p.p.wyt());
    }
    
    // Sign the transaction
    let signed_tx = sign_transaction_with_signer(&mut transaction, &signer, verbose)?;
    
    // Encode signed transaction
    let mut out_slab = NounSlab::new();
    let signed_noun = signed_tx.to_noun(&mut out_slab);
    out_slab.copy_into(signed_noun);
    let signed_bytes = out_slab.jam();
    
    // Determine output path
    let output_path = output_path.unwrap_or_else(|| {
        let mut path = draft_path.clone();
        path.set_extension("tx");
        path
    });
    
    // Write signed transaction
    fs::write(&output_path, signed_bytes.as_ref())
        .with_context(|| format!("Failed to write signed transaction: {}", output_path.display()))?;
    
    println!("Signed transaction written to: {}", output_path.display());
    println!("Size: {} bytes", signed_bytes.len());
    
    Ok(())
}

/// Sign a transaction with the given signer
fn sign_transaction_with_signer(
    transaction: &mut Transaction,
    signer: &TransactionSigner,
    verbose: bool,
) -> Result<Transaction> {
    let signer_pubkey = signer.get_public_key();
    let private_key = signer.private_key()
        .ok_or_else(|| anyhow!("Signer does not have private key"))?;
    
    // Generate transaction ID for signing
    let tx_id = tx_to_noun::generate_tx_id(transaction.p.p.clone());
    
    if verbose {
        println!("Signing with transaction ID: {}", tx_id.to_b58());
    }
    
    // Sign each input that requires our signature
    let mut new_inputs = ZMap::new();
    let mut signatures_added = 0;
    
    for (name, mut input) in transaction.p.p.tap() {
        let lock = &input.note.lock;
        
        // Check if our public key is in the lock
        if lock.pubkeys.has(&signer_pubkey) {
            // Generate signature for this input
            let signature = tx_types::crypto::schnorr::sign_hash(
                &private_key,
                &tx_types::crypto::cheetah::CheetahPoint::from_schnorr_pubkey(&signer_pubkey),
                &tx_id,
            ).map_err(|e| anyhow!("Signing failed: {}", e))?;
            
            let schnorr_sig = SchnorrSignature {
                chal: Chal { values: signature.0.values },
                sig: Sig { values: signature.1.values },
            };
            
            // Add signature to input
            match &mut input.spend.signature {
                Some(sig_map) => {
                    sig_map.map.put(signer_pubkey.clone(), schnorr_sig);
                }
                None => {
                    let mut sig_map = ZMap::new();
                    sig_map.put(signer_pubkey.clone(), schnorr_sig);
                    input.spend.signature = Some(Signature { map: sig_map });
                }
            }
            
            signatures_added += 1;
            
            if verbose {
                println!("Added signature for input: {:?}", name);
            }
        }
        
        new_inputs.put(name, input);
    }
    
    if signatures_added == 0 {
        return Err(anyhow!("No inputs found that can be signed with this key"));
    }
    
    println!("Added {} signature(s)", signatures_added);
    
    // Create signed transaction
    let signed_tx = Transaction {
        name: transaction.name.clone(),
        p: Inputs { p: new_inputs },
    };
    
    Ok(signed_tx)
}

/// Generate a new keypair
fn generate_keypair(
    mnemonic: Option<String>,
    passphrase: String,
    derivation_path: Option<String>,
    format: String,
) -> Result<()> {
    let signer = if let Some(phrase) = mnemonic {
        TransactionSigner::from_mnemonic(&phrase, &passphrase)
            .map_err(|e| anyhow!("Failed to create signer from mnemonic: {}", e))?
    } else {
        // Generate random mnemonic
        use bip39::{Mnemonic, Language};
        let mnemonic = Mnemonic::generate_in(Language::English, 24)
            .map_err(|e| anyhow!("Failed to generate mnemonic: {}", e))?;
        
        println!("Generated mnemonic: {}", mnemonic.phrase());
        
        TransactionSigner::from_mnemonic(mnemonic.phrase(), &passphrase)
            .map_err(|e| anyhow!("Failed to create signer: {}", e))?
    };
    
    // Apply derivation path if specified
    let final_signer = if let Some(path_str) = derivation_path {
        let path = parse_derivation_path(&path_str)?;
        let mut current = signer;
        for index in path {
            current = current.derive_child(index)
                .map_err(|e| anyhow!("Derivation failed: {}", e))?;
        }
        current
    } else {
        signer
    };
    
    let pubkey = final_signer.get_public_key();
    
    match format.as_str() {
        "address" => {
            println!("{}", pubkey.to_b58());
        }
        "private-key" => {
            if let Some(private_key) = final_signer.private_key() {
                println!("{}", bytes_to_hex(&private_key));
            } else {
                return Err(anyhow!("No private key available"));
            }
        }
        "all" => {
            println!("Address: {}", pubkey.to_b58());
            if let Some(private_key) = final_signer.private_key() {
                println!("Private Key: {}", bytes_to_hex(&private_key));
            }
            println!("Public Key X: {:?}", pubkey.x.values);
            println!("Public Key Y: {:?}", pubkey.y.values);
        }
        _ => {
            return Err(anyhow!("Invalid format. Use: address, private-key, or all"));
        }
    }
    
    Ok(())
}

/// Verify a signed transaction
fn verify_transaction(transaction_path: PathBuf, verbose: bool) -> Result<()> {
    let tx_bytes = fs::read(&transaction_path)
        .with_context(|| format!("Failed to read transaction: {}", transaction_path.display()))?;
    
    println!("Verifying: {} ({} bytes)", transaction_path.display(), tx_bytes.len());
    
    let mut slab = NounSlab::new();
    let noun = slab.cue_into(Bytes::from(tx_bytes))
        .map_err(|e| anyhow!("Failed to decode JAM: {:?}", e))?;
    
    let transaction = Transaction::from_noun(&mut slab, &noun)
        .map_err(|e| anyhow!("Failed to decode transaction: {:?}", e))?;
    
    if verbose {
        println!("Transaction ID: {}", transaction.name);
        println!("Number of inputs: {}", transaction.p.p.wyt());
    }
    
    // Verify all signatures
    let tx_id = tx_to_noun::generate_tx_id(transaction.p.p.clone());
    let mut total_signatures = 0;
    let mut valid_signatures = 0;
    
    for (name, input) in transaction.p.p.tap() {
        if let Some(signature_map) = &input.spend.signature {
            for (pubkey, signature) in signature_map.map.tap() {
                total_signatures += 1;
                
                let sig_tuple = (
                    T8 { values: signature.chal.values },
                    T8 { values: signature.sig.values },
                );
                
                let is_valid = tx_types::crypto::schnorr::verify_signature(
                    &tx_types::crypto::cheetah::CheetahPoint::from_schnorr_pubkey(&pubkey),
                    &tx_id,
                    &sig_tuple,
                );
                
                if is_valid {
                    valid_signatures += 1;
                    if verbose {
                        println!("✓ Valid signature for input {:?} by {}", name, pubkey.to_b58());
                    }
                } else {
                    if verbose {
                        println!("✗ Invalid signature for input {:?} by {}", name, pubkey.to_b58());
                    }
                }
            }
        }
    }
    
    println!("Verification complete: {}/{} signatures valid", valid_signatures, total_signatures);
    
    if valid_signatures == total_signatures && total_signatures > 0 {
        println!("✓ Transaction is fully signed and valid");
        Ok(())
    } else {
        Err(anyhow!("Transaction has invalid or missing signatures"))
    }
}

/// Parse a derivation path string like "m/44'/0'/0'/0/0"
fn parse_derivation_path(path_str: &str) -> Result<Vec<u32>> {
    let path_str = path_str.trim_start_matches("m/");
    if path_str.is_empty() {
        return Ok(vec![]);
    }
    
    let mut path = Vec::new();
    for component in path_str.split('/') {
        if component.is_empty() {
            continue;
        }
        
        let (index_str, hardened) = if component.ends_with('\'') || component.ends_with('h') {
            (&component[..component.len()-1], true)
        } else {
            (component, false)
        };
        
        let index: u32 = index_str.parse()
            .map_err(|_| anyhow!("Invalid derivation path component: {}", component))?;
        
        let final_index = if hardened {
            index.checked_add(0x80000000)
                .ok_or_else(|| anyhow!("Derivation index overflow: {}", index))?
        } else {
            index
        };
        
        path.push(final_index);
    }
    
    Ok(path)
}

/// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim().trim_start_matches("0x");
    if hex.len() % 2 != 0 {
        return None;
    }
    
    let mut bytes = Vec::new();
    for chunk in hex.chars().collect::<Vec<_>>().chunks(2) {
        let hex_byte: String = chunk.iter().collect();
        if let Ok(byte) = u8::from_str_radix(&hex_byte, 16) {
            bytes.push(byte);
        } else {
            return None;
        }
    }
    
    Some(bytes)
}

/// Convert bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_derivation_path_parsing() {
        assert_eq!(parse_derivation_path("m").unwrap(), vec![]);
        assert_eq!(parse_derivation_path("m/0").unwrap(), vec![0]);
        assert_eq!(parse_derivation_path("m/44'").unwrap(), vec![0x8000002C]);
        assert_eq!(parse_derivation_path("m/44'/0'/0'/0/0").unwrap(), 
                   vec![0x8000002C, 0x80000000, 0x80000000, 0, 0]);
    }
    
    #[test]
    fn test_hex_conversion() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "0123456789abcdef");
        
        let recovered = hex_to_bytes(&hex).unwrap();
        assert_eq!(bytes, recovered);
    }
}