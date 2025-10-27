//! Batch Transaction Builder for Multiple Recipients
//!
//! This module provides functionality to build transactions that send to multiple recipients
//! in a single transaction. It processes orders sequentially, consuming only the notes needed
//! to fulfill all orders plus the transaction fee.
//!
//! # Key Features
//! - Multiple (recipient, amount) pairs in one transaction
//! - Sequential filling: orders processed in order
//! - Efficient: only consumes notes actually needed
//! - Supports both V0 and V1 notes (but not mixed)

extern crate alloc;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::collections::{ZMap, ZSet};
use crate::hashing::hasher::hash_hashable;
use crate::transaction_types::*;
use crate::transaction_types_v0::*;
use crate::transaction_types_v1::*;
use crate::tx_builder_v1::{
    lock_data_to_untyped_noun, sign_spend_v0_to_v1, sign_spend_v1, LockData,
};

/// Batch order structure representing a payment to a recipient
#[derive(Debug, Clone)]
pub struct BatchOrder {
    /// Recipient's pubkey hash
    pub recipient: Hash,
    /// Amount to send to recipient
    pub amount: Coins,
}

/// Build batch spends for multiple recipients from a list of notes
///
/// This function creates a transaction that sends to multiple recipients by
/// sequentially consuming notes until all orders and the fee are satisfied.
/// Notes that aren't needed are not included in the transaction.
///
/// # Arguments
/// * `notes` - List of notes to potentially spend (sorted by value descending recommended)
/// * `orders` - List of (recipient, amount) pairs to fulfill
/// * `fee` - Total transaction fee
/// * `sign_key` - Secret key for signing (T8 format)
/// * `pubkey` - Public key corresponding to sign_key
/// * `refund_pkh` - Optional pubkey hash for refund outputs
///
/// # Returns
/// A ZMap of note names to signed spends (only for notes actually consumed)
///
/// # Errors
/// - If any order has amount <= 0
/// - If notes are mixed versions (some V0, some V1)
/// - If insufficient funds to cover all orders + fee
/// - If V0 notes are used without specifying refund_pkh
///
/// # Algorithm
/// 1. Validate all orders have positive amounts
/// 2. Check all notes are same version
/// 3. Calculate total needed: sum(orders) + fee
/// 4. Process notes sequentially, distributing to orders until all fulfilled
/// 5. Only create spends for notes actually consumed
pub fn build_batch_spends(
    notes: Vec<NNote>,
    orders: Vec<BatchOrder>,
    fee: Coins,
    sign_key: T8,
    pubkey: SchnorrPubkey,
    refund_pkh: Option<Hash>,
) -> Result<ZMap<NName, Spend>, String> {
    // Validate orders
    if orders.is_empty() {
        return Err("Must have at least one order".to_string());
    }

    for order in &orders {
        if order.amount.value == 0 {
            return Err("Cannot create an order with zero amount".to_string());
        }
    }

    // Check if all notes are V0
    let all_v0 = notes.iter().all(|note| matches!(note, NNote::V0(_)));

    if all_v0 {
        // Verify refund_pkh is provided for V0 notes
        if refund_pkh.is_none() {
            return Err("Need to specify a refund address if spending from v0 notes".to_string());
        }

        // Extract V0 notes
        let mut v0_notes: Vec<NNoteV0> = Vec::new();
        for note in notes {
            match note {
                NNote::V0(v0_note) => v0_notes.push(v0_note),
                _ => return Err("Mixed note versions detected".to_string()),
            }
        }

        // Sort by assets descending
        v0_notes.sort_by(|a, b| b.assets.value.cmp(&a.assets.value));

        create_batch_spends_0(v0_notes, orders, fee, sign_key, pubkey, refund_pkh.unwrap())
    } else {
        // Check if all notes are V1
        let all_v1 = notes.iter().all(|note| matches!(note, NNote::V1(_)));

        if all_v1 {
            // Extract V1 notes
            let mut v1_notes: Vec<NNoteV1> = Vec::new();
            for note in notes {
                match note {
                    NNote::V1(v1_note) => v1_notes.push(v1_note),
                    _ => return Err("Mixed note versions detected".to_string()),
                }
            }

            // Sort by assets descending
            v1_notes.sort_by(|a, b| b.assets.value.cmp(&a.assets.value));

            create_batch_spends_1(v1_notes, orders, fee, sign_key, pubkey, refund_pkh)
        } else {
            return Err("Notes must all be the same version".to_string());
        }
    }
}

/// Create batch spends for V0 notes
fn create_batch_spends_0(
    notes: Vec<NNoteV0>,
    orders: Vec<BatchOrder>,
    fee: Coins,
    sign_key: T8,
    pubkey: SchnorrPubkey,
    refund_pkh: Hash,
) -> Result<ZMap<NName, Spend>, String> {
    // Calculate total needed
    let total_orders: u64 = orders.iter().map(|o| o.amount.value).sum();
    let _total_needed = total_orders + fee.value;

    // Track remaining amounts
    let mut remaining_orders: Vec<(Hash, u64)> = orders
        .iter()
        .map(|o| (o.recipient.clone(), o.amount.value))
        .collect();
    let mut remaining_fee = fee.value;
    let mut spends = ZMap::new();

    // Process notes sequentially
    for note in notes {
        // Check if we still need funds
        let still_need_orders: u64 = remaining_orders.iter().map(|(_, amt)| *amt).sum();
        if still_need_orders == 0 && remaining_fee == 0 {
            // All orders and fee satisfied, stop processing notes
            break;
        }

        let available = note.assets.value;
        let mut consumed = 0u64;

        // Build seeds for this note
        let mut seeds_list = Vec::new();

        // Fill orders sequentially
        let mut updated_orders = Vec::new();
        for (recipient, remaining) in remaining_orders {
            if remaining == 0 {
                continue; // Order already filled
            }

            let to_allocate = core::cmp::min(remaining, available - consumed);
            if to_allocate > 0 {
                // Create output lock for recipient
                let mut recipient_set = ZSet::new();
                recipient_set.put(recipient.clone());
                let output_lock = SpendCondition {
                    p: vec![LockPrimitive {
                        header: "pkh".to_string(),
                        body: LockPrimitiveBody::Pkh(Pkh {
                            m: 1,
                            h: recipient_set,
                        }),
                    }],
                };

                // Build note-data
                let lock_data = LockData::V0(output_lock.clone());
                let mut note_data_map = ZMap::new();
                let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
                note_data_map.put("lock".to_string(), lock_data_noun);
                let note_data = NoteData { map: note_data_map };

                // Create seed
                let seed = SeedV1 {
                    output_source: None,
                    lock_root: lock_hash(&output_lock),
                    note_data,
                    gift: Coins { value: to_allocate },
                    parent_hash: note_hash_v0(&note),
                };

                seeds_list.push(seed);
                consumed += to_allocate;
                updated_orders.push((recipient, remaining - to_allocate));
            } else {
                updated_orders.push((recipient, remaining));
            }
        }
        remaining_orders = updated_orders;

        // Handle fee
        if remaining_fee > 0 {
            let to_fee = core::cmp::min(remaining_fee, available - consumed);
            consumed += to_fee;
            remaining_fee -= to_fee;
        }

        // Handle refund if any leftover
        if consumed < available {
            let refund_amount = available - consumed;

            // Create refund seed
            let mut refund_set = ZSet::new();
            refund_set.put(refund_pkh.clone());
            let refund_lock = SpendCondition {
                p: vec![LockPrimitive {
                    header: "pkh".to_string(),
                    body: LockPrimitiveBody::Pkh(Pkh {
                        m: 1,
                        h: refund_set,
                    }),
                }],
            };

            let lock_data = LockData::V0(refund_lock.clone());
            let mut note_data_map = ZMap::new();
            let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
            note_data_map.put("lock".to_string(), lock_data_noun);
            let note_data = NoteData { map: note_data_map };

            let refund_seed = SeedV1 {
                output_source: None,
                lock_root: lock_hash(&refund_lock),
                note_data,
                gift: Coins {
                    value: refund_amount,
                },
                parent_hash: note_hash_v0(&note),
            };

            seeds_list.push(refund_seed);
        }

        // Only create spend if we actually consumed from this note
        if consumed > 0 {
            // Create seeds set
            let mut seeds_set = ZSet::new();
            for seed in seeds_list {
                seeds_set.put(seed);
            }
            let seeds = SeedsV1 { set: seeds_set };

            // Calculate fee portion for this note
            let fee_portion = fee.value - remaining_fee;

            // Create V0ToV1 spend
            let spend_body = SpendV0ToV1 {
                signature: ZMap::new(), // Will be filled by signing
                seeds,
                fee: Coins { value: fee_portion },
            };

            // Sign the spend
            let signed_spend = sign_spend_v0_to_v1(spend_body, sign_key.clone(), pubkey.clone())?;

            spends.put(note.name.clone(), signed_spend);
        }
    }

    // Check if we satisfied all requirements
    let still_need_orders: u64 = remaining_orders.iter().map(|(_, amt)| *amt).sum();
    if still_need_orders > 0 || remaining_fee > 0 {
        return Err(format!(
            "Insufficient funds. Still need: {} for orders, {} for fee",
            still_need_orders, remaining_fee
        ));
    }

    Ok(spends)
}

/// Create batch spends for V1 notes
fn create_batch_spends_1(
    notes: Vec<NNoteV1>,
    orders: Vec<BatchOrder>,
    fee: Coins,
    sign_key: T8,
    pubkey: SchnorrPubkey,
    refund_pkh: Option<Hash>,
) -> Result<ZMap<NName, Spend>, String> {
    // Calculate total needed
    let total_orders: u64 = orders.iter().map(|o| o.amount.value).sum();
    let _total_needed = total_orders + fee.value;

    // Calculate our pkh for default refunds
    let our_pkh = pubkey.to_hash();
    let refund_hash = refund_pkh.unwrap_or(our_pkh);

    // Track remaining amounts
    let mut remaining_orders: Vec<(Hash, u64)> = orders
        .iter()
        .map(|o| (o.recipient.clone(), o.amount.value))
        .collect();
    let mut remaining_fee = fee.value;
    let mut spends = ZMap::new();

    // Process notes sequentially
    for note in notes {
        // Check if we still need funds
        let still_need_orders: u64 = remaining_orders.iter().map(|(_, amt)| *amt).sum();
        if still_need_orders == 0 && remaining_fee == 0 {
            // All orders and fee satisfied, stop processing notes
            break;
        }

        let available = note.assets.value;
        let mut consumed = 0u64;

        // Build seeds for this note
        let mut seeds_list = Vec::new();

        // Fill orders sequentially
        let mut updated_orders = Vec::new();
        for (recipient, remaining) in remaining_orders {
            if remaining == 0 {
                continue; // Order already filled
            }

            let to_allocate = core::cmp::min(remaining, available - consumed);
            if to_allocate > 0 {
                // Create output lock for recipient
                let mut recipient_set = ZSet::new();
                recipient_set.put(recipient.clone());
                let output_lock = SpendCondition {
                    p: vec![LockPrimitive {
                        header: "pkh".to_string(),
                        body: LockPrimitiveBody::Pkh(Pkh {
                            m: 1,
                            h: recipient_set,
                        }),
                    }],
                };

                // Build note-data
                let lock_data = LockData::V0(output_lock.clone());
                let mut note_data_map = ZMap::new();
                let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
                note_data_map.put("lock".to_string(), lock_data_noun);
                let note_data = NoteData { map: note_data_map };

                // Create seed
                let seed = SeedV1 {
                    output_source: None,
                    lock_root: lock_hash(&output_lock),
                    note_data,
                    gift: Coins { value: to_allocate },
                    parent_hash: note_hash_v1(&note),
                };

                seeds_list.push(seed);
                consumed += to_allocate;
                updated_orders.push((recipient, remaining - to_allocate));
            } else {
                updated_orders.push((recipient, remaining));
            }
        }
        remaining_orders = updated_orders;

        // Handle fee
        if remaining_fee > 0 {
            let to_fee = core::cmp::min(remaining_fee, available - consumed);
            consumed += to_fee;
            remaining_fee -= to_fee;
        }

        // Handle refund if any leftover
        if consumed < available {
            let refund_amount = available - consumed;

            // Create refund seed
            let mut refund_set = ZSet::new();
            refund_set.put(refund_hash.clone());
            let refund_lock = SpendCondition {
                p: vec![LockPrimitive {
                    header: "pkh".to_string(),
                    body: LockPrimitiveBody::Pkh(Pkh {
                        m: 1,
                        h: refund_set,
                    }),
                }],
            };

            let lock_data = LockData::V0(refund_lock.clone());
            let mut note_data_map = ZMap::new();
            let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
            note_data_map.put("lock".to_string(), lock_data_noun);
            let note_data = NoteData { map: note_data_map };

            let refund_seed = SeedV1 {
                output_source: None,
                lock_root: lock_hash(&refund_lock),
                note_data,
                gift: Coins {
                    value: refund_amount,
                },
                parent_hash: note_hash_v1(&note),
            };

            seeds_list.push(refund_seed);
        }

        // Only create spend if we actually consumed from this note
        if consumed > 0 {
            // TODO: Extract and validate lock from note-data (similar to create_spends_1)
            // For now, use simplified approach

            // Create seeds set
            let mut seeds_set = ZSet::new();
            for seed in seeds_list {
                seeds_set.put(seed);
            }
            let seeds = SeedsV1 { set: seeds_set };

            // Calculate fee portion for this note
            let fee_portion = fee.value - remaining_fee;

            // TODO: Build proper lock merkle proof
            // For now, create empty witness
            let witness = Witness {
                lmp: LockMerkleProof {
                    spend_condition: SpendCondition { p: Vec::new() },
                    axis: 1,
                    merkle_proof: MerkleProof {
                        root: Hash { values: [0; 5] },
                        path: Vec::new(),
                    },
                },
                pkh: PkhSignature { map: ZMap::new() },
                hax: ZMap::new(),
                tim: 0,
            };

            // Create V1 spend
            let spend_body = SpendV1 {
                seeds,
                fee: Coins { value: fee_portion },
                witness,
            };

            // Sign the spend
            let signed_spend = sign_spend_v1(spend_body, sign_key.clone(), pubkey.clone())?;

            spends.put(note.name.clone(), signed_spend);
        }
    }

    // Check if we satisfied all requirements
    let still_need_orders: u64 = remaining_orders.iter().map(|(_, amt)| *amt).sum();
    if still_need_orders > 0 || remaining_fee > 0 {
        return Err(format!(
            "Insufficient funds. Still need: {} for orders, {} for fee",
            still_need_orders, remaining_fee
        ));
    }

    Ok(spends)
}

// Helper functions

fn lock_hash(spend_condition: &SpendCondition) -> Hash {
    let hashable = spend_condition.to_hashable();
    hash_hashable(&hashable)
}

fn note_hash_v0(note: &NNoteV0) -> Hash {
    let hashable = note.to_hashable();
    hash_hashable(&hashable)
}

fn note_hash_v1(note: &NNoteV1) -> Hash {
    note.name.to_hash()
}

pub fn build_simple_batch_spends(
    mut notes: Vec<NNoteV1>,
    orders: Vec<BatchOrder>,
    fee: Coins,
    refund_pkh: Hash,
) -> Result<ZMap<NName, Spend>, String> {
    // Validate orders
    if orders.is_empty() {
        return Err("Must have at least one order".to_string());
    }

    for order in &orders {
        if order.amount.value == 0 {
            return Err("Cannot create an order with zero amount".to_string());
        }
    }

    // Sort by assets descending
    notes.sort_by(|a, b| b.assets.value.cmp(&a.assets.value));
    create_unsigned_batch_spends_1(notes, orders, fee, refund_pkh)
}

/// Create batch spends for V1 notes
fn create_unsigned_batch_spends_1(
    notes: Vec<NNoteV1>,
    orders: Vec<BatchOrder>,
    fee: Coins,
    refund_pkh: Hash,
) -> Result<ZMap<NName, Spend>, String> {
    // Calculate total needed
    let total_orders: u64 = orders.iter().map(|o| o.amount.value).sum();
    let _total_needed = total_orders + fee.value;

    // Track remaining amounts
    let mut remaining_orders: Vec<(Hash, u64)> = orders
        .iter()
        .map(|o| (o.recipient.clone(), o.amount.value))
        .collect();
    let mut remaining_fee = fee.value;
    let mut spends = ZMap::new();

    // Process notes sequentially
    for note in notes {
        // Check if we still need funds
        let still_need_orders: u64 = remaining_orders.iter().map(|(_, amt)| *amt).sum();
        if still_need_orders == 0 && remaining_fee == 0 {
            // All orders and fee satisfied, stop processing notes
            break;
        }

        let available = note.assets.value;
        let mut consumed = 0u64;

        // Build seeds for this note
        let mut seeds_list = Vec::new();

        // Fill orders sequentially
        let mut updated_orders = Vec::new();
        for (recipient, remaining) in remaining_orders {
            if remaining == 0 {
                continue; // Order already filled
            }

            let to_allocate = core::cmp::min(remaining, available - consumed);
            if to_allocate > 0 {
                // Create output lock for recipient
                let mut recipient_set = ZSet::new();
                recipient_set.put(recipient.clone());
                let output_lock = SpendCondition {
                    p: vec![LockPrimitive {
                        header: "pkh".to_string(),
                        body: LockPrimitiveBody::Pkh(Pkh {
                            m: 1,
                            h: recipient_set,
                        }),
                    }],
                };

                // Build note-data
                let lock_data = LockData::V0(output_lock.clone());
                let mut note_data_map = ZMap::new();
                let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
                note_data_map.put("lock".to_string(), lock_data_noun);
                let note_data = NoteData { map: note_data_map };

                // Create seed
                let seed = SeedV1 {
                    output_source: None,
                    lock_root: lock_hash(&output_lock),
                    note_data,
                    gift: Coins { value: to_allocate },
                    parent_hash: note_hash_v1(&note),
                };

                seeds_list.push(seed);
                consumed += to_allocate;
                updated_orders.push((recipient, remaining - to_allocate));
            } else {
                updated_orders.push((recipient, remaining));
            }
        }
        remaining_orders = updated_orders;

        // Handle fee
        if remaining_fee > 0 {
            let to_fee = core::cmp::min(remaining_fee, available - consumed);
            consumed += to_fee;
            remaining_fee -= to_fee;
        }

        // Handle refund if any leftover
        if consumed < available {
            let refund_amount = available - consumed;

            // Create refund seed
            let mut refund_set = ZSet::new();
            refund_set.put(refund_pkh.clone());
            let refund_lock = SpendCondition {
                p: vec![LockPrimitive {
                    header: "pkh".to_string(),
                    body: LockPrimitiveBody::Pkh(Pkh {
                        m: 1,
                        h: refund_set,
                    }),
                }],
            };

            let lock_data = LockData::V0(refund_lock.clone());
            let mut note_data_map = ZMap::new();
            let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
            note_data_map.put("lock".to_string(), lock_data_noun);
            let note_data = NoteData { map: note_data_map };

            let refund_seed = SeedV1 {
                output_source: None,
                lock_root: lock_hash(&refund_lock),
                note_data,
                gift: Coins {
                    value: refund_amount,
                },
                parent_hash: note_hash_v1(&note),
            };

            seeds_list.push(refund_seed);
        }

        // Only create spend if we actually consumed from this note
        if consumed > 0 {
            // TODO: Extract and validate lock from note-data (similar to create_spends_1)
            // For now, use simplified approach

            // Create seeds set
            let mut seeds_set = ZSet::new();
            for seed in seeds_list {
                seeds_set.put(seed);
            }
            let seeds = SeedsV1 { set: seeds_set };

            // Calculate fee portion for this note
            let fee_portion = fee.value - remaining_fee;

            // TODO: Build proper lock merkle proof
            // For now, create empty witness
            let witness = Witness {
                lmp: LockMerkleProof {
                    spend_condition: SpendCondition { p: Vec::new() },
                    axis: 1,
                    merkle_proof: MerkleProof {
                        root: Hash { values: [0; 5] },
                        path: Vec::new(),
                    },
                },
                pkh: PkhSignature { map: ZMap::new() },
                hax: ZMap::new(),
                tim: 0,
            };

            // Create V1 spend
            let spend_body = SpendV1 {
                seeds,
                fee: Coins { value: fee_portion },
                witness,
            };

            spends.put(note.name.clone(), Spend { version: 1, body: SpendBody::V1(spend_body) });
        }
    }

    // Check if we satisfied all requirements
    let still_need_orders: u64 = remaining_orders.iter().map(|(_, amt)| *amt).sum();
    if still_need_orders > 0 || remaining_fee > 0 {
        return Err(format!(
            "Insufficient funds. Still need: {} for orders, {} for fee",
            still_need_orders, remaining_fee
        ));
    }

    Ok(spends)
}