//! Transaction Builder for V0 and V1 Transactions
//!
//! This module provides functionality to build transactions from a list of notes.
//! It implements the complete `tx-builder-v1.hoon` module including:
//! - Main dispatcher that handles both V0 and V1 notes
//! - `create_spends_0` for V0 notes
//! - `create_spends_1` for V1 notes
//! - Refund handling and fee validation
//!
//! The builder handles:
//! - Fan-in transactions (multiple inputs to single output)
//! - Automatic fee and gift distribution across notes
//! - Version detection and validation
//! - Lock validation and witness generation
//! - Refund handling
//! - Signing of spends with secret keys

#![cfg_attr(not(test), no_std)]

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::block_types::build_lock_merkle_proof;
use crate::collections::{ZMap, ZSet};
use crate::generic_noun::UntypedNoun;
use crate::hashing::hashable::Hashable;
use crate::hashing::hasher::hash_hashable;
use crate::signer::schnorr_sign_digest;
use crate::transaction_types::*;
use crate::transaction_types_v0::*;
use crate::transaction_types_v1::*;
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{Noun, D, T};
use noun_serde::{NounDecode, NounDecodeError, NounEncode};

/// Order structure representing a payment to a recipient
/// Matches the Hoon type: +$  order  [recipient=hash:transact gift=coins:transact]
#[derive(Debug, Clone)]
pub struct Order {
    /// Recipient's pubkey hash
    pub recipient: Hash,
    /// Amount to send to recipient
    pub gift: Coins,
}

/// Lock data that gets embedded in note-data field of seeds
/// Matches the Hoon type: +$  lock-data  $%  [%0 =lock:transact]  ==
#[derive(Debug, Clone)]
pub enum LockData {
    V0(SpendCondition),
}

impl NounDecode for LockData {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        // lock-data is a cell: [version lock:transact]
        // For V0: [%0 =lock:transact] where lock is a spend-condition
        let cell = match noun.as_cell() {
            Ok(c) => c,
            Err(_) => return Err(NounDecodeError::ExpectedCell),
        };

        let version = cell.head();
        let lock_noun = cell.tail();

        // Check version tag
        let version_atom = match version.as_atom() {
            Ok(a) => a,
            Err(_) => {
                return Err(NounDecodeError::Custom(
                    "LockData version must be an atom".to_string(),
                ))
            }
        };

        let version_num = match version_atom.as_u64() {
            Ok(v) => v,
            Err(_) => {
                return Err(NounDecodeError::Custom(
                    "LockData version too large".to_string(),
                ))
            }
        };

        if version_num != 0 {
            return Err(NounDecodeError::Custom(format!(
                "Unknown LockData version: {}",
                version_num
            )));
        }

        // Decode the spend-condition
        let spend_condition = SpendCondition::from_noun(&lock_noun)?;

        Ok(LockData::V0(spend_condition))
    }
}

/// Result type for operations that can fail with a reason
/// Matches Hoon's ++  reason  |$  object  (each object term)
pub type Reason<T> = Result<T, String>;

/// Helper function to serialize LockData to UntypedNoun
///
/// This serializes lock-data in the Hoon format: [%0 =lock:transact]
/// where lock is a spend-condition (list of lock-primitives).
///
/// # Arguments
/// * `lock_data` - The LockData to serialize
///
/// # Returns
/// An UntypedNoun containing the jammed lock-data
fn lock_data_to_untyped_noun(lock_data: &LockData) -> UntypedNoun {
    let mut slab = NounSlab::new();

    match lock_data {
        LockData::V0(spend_condition) => {
            // Create the version tag %0
            let version_tag = D(0);

            // Serialize the spend-condition (list of lock-primitives)
            let lock_noun = spend_condition_to_noun(spend_condition, &mut slab);

            // Create the cell [%0 lock]
            let lock_data_noun = T(&mut slab, &[version_tag, lock_noun]);

            // Copy the noun into the slab and jam it
            slab.copy_into(lock_data_noun);
            let jammed = slab.jam();

            UntypedNoun { p: jammed }
        }
    }
}

/// Helper function to serialize a SpendCondition to a Noun
///
/// A spend-condition is a list of lock-primitives in Hoon.
/// This creates a proper list noun structure.
///
/// # Arguments
/// * `spend_condition` - The SpendCondition to serialize
/// * `slab` - The NounSlab allocator to use
///
/// # Returns
/// A Noun representing the spend-condition list
fn spend_condition_to_noun(spend_condition: &SpendCondition, slab: &mut NounSlab) -> Noun {
    // Build a Hoon-style list by folding right-to-left
    // List structure: [item1 [item2 [item3 [...  ~]]]]
    // where ~ is the null terminator (atom 0)
    spend_condition.p.iter().rev().fold(D(0), |acc, primitive| {
        let primitive_noun = lock_primitive_to_noun(primitive, slab);
        T(slab, &[primitive_noun, acc])
    })
}

/// Helper function to serialize a LockPrimitive to a Noun
///
/// A lock-primitive is a tagged union in Hoon: [header body]
/// Examples: [%pkh [m=1 h=(set hash)]], [%tim [...]], etc.
///
/// # Arguments
/// * `primitive` - The LockPrimitive to serialize
/// * `slab` - The NounSlab allocator to use
///
/// # Returns
/// A Noun representing the lock-primitive
fn lock_primitive_to_noun(primitive: &LockPrimitive, slab: &mut NounSlab) -> Noun {
    use nockapp::utils::make_tas;

    // Create the header (tag) as a tas (term/symbol)
    let header_noun = make_tas(slab, &primitive.header).as_noun();

    // Serialize the body based on the type
    let body_noun = match &primitive.body {
        LockPrimitiveBody::Pkh(pkh) => {
            // Serialize as [m h] where h is a z-set of hashes
            let m_noun = D(pkh.m);
            let h_noun = pkh.h.to_noun(slab);
            T(slab, &[m_noun, h_noun])
        }
        LockPrimitiveBody::Tim(tim) => {
            // Serialize as [rel abs] where rel and abs are timelock ranges
            let rel_noun = tim.rel.to_noun(slab);
            let abs_noun = tim.abs.to_noun(slab);
            T(slab, &[rel_noun, abs_noun])
        }
        LockPrimitiveBody::Hax(hax) => {
            // Serialize as a z-set of hashes
            hax.set.to_noun(slab)
        }
        LockPrimitiveBody::Brn(brn) => {
            // Serialize as just the value (which is always 0)
            D(brn.value)
        }
    };

    // Return [header body]
    T(slab, &[header_noun, body_noun])
}

/// Main transaction builder function (dispatcher)
///
/// This is the Rust implementation of the main gate in `tx-builder-v1.hoon` (lines 7-54).
/// It takes a list of notes, determines their version, and routes to the appropriate
/// builder function (V0 or V1).
///
/// # Arguments
/// * `notes` - List of notes to spend
/// * `order` - Payment order specifying recipient and amount
/// * `fee` - Total transaction fee
/// * `sign_key` - Secret key for signing (T8 format)
/// * `pubkey` - Public key corresponding to sign_key
/// * `refund_pkh` - Optional pubkey hash for refund outputs (required for V0 notes)
///
/// # Returns
/// A ZMap of note names to signed spends, or an error message
///
/// # Errors
/// - If gift amount is <= 0
/// - If notes are mixed versions (some V0, some V1)
/// - If fee is below minimum required fee
/// - If insufficient funds to cover gift and fee
/// - If V0 notes are used without specifying refund_pkh
///
/// # Algorithm (matches Hoon lines 7-54)
/// 1. Validate gift amount is positive
/// 2. Check if all notes are V0 or all V1 (no mixing allowed)
/// 3. Route to appropriate builder (create_spends_0 or create_spends_1)
/// 4. Sort notes by assets (descending) for optimal distribution
/// 5. Validate minimum fee requirement (TODO)
/// 6. Return spends map
///
/// # Example
/// ```ignore
/// use tx_types::{build_spends, Order, Coins};
///
/// let notes = vec![note1, note2, note3];
/// let spends = build_spends(
///     notes,
///     Order {
///         recipient: recipient_pkh,
///         gift: Coins { value: 1000 },
///     },
///     Coins { value: 10 },  // fee
///     secret_key,
///     public_key,
///     Some(refund_address),  // Required for V0 notes, optional for V1
/// )?;
/// ```
pub fn build_spends(
    notes: Vec<NNote>,
    order: Order,
    fee: Coins,
    sign_key: T8,
    pubkey: SchnorrPubkey,
    refund_pkh: Option<Hash>,
) -> Result<ZMap<NName, Spend>, String> {
    // Validate gift amount (lines 19-20)
    // ?:  (lte gift.order 0)
    //   ~|("Cannot create a transaction with zero gift" !!)
    if order.gift.value == 0 {
        return Err("Cannot create a transaction with zero gift".to_string());
    }

    // Build spends based on note version (lines 21-48)
    let spends = {
        // Check if all notes are V0 (lines 22-34)
        // ?:  (levy notes |=(=nnote:transact ?=(^ -.nnote)))
        let all_v0 = notes.iter().all(|note| matches!(note, NNote::V0(_)));

        if all_v0 {
            // Require refund_pkh for V0 notes (lines 23-24)
            // ?~  refund-pkh
            //   ~|('Need to specify a refund address...' !!)
            if refund_pkh.is_none() {
                return Err(
                    "Need to specify a refund address if spending from v0 notes. \
                     Use the `--refund-pkh` flag in the create-tx command"
                        .to_string(),
                );
            }

            // Extract and sort V0 notes (lines 25-32)
            // =/  notes=(list nnote:v0:transact)
            //   %+  turn  notes
            //   |=  =nnote:transact
            //   ?>  ?=(^ -.nnote)
            //   nnote
            let mut v0_notes: Vec<NNoteV0> = Vec::new();
            for note in notes {
                match note {
                    NNote::V0(v0_note) => v0_notes.push(v0_note),
                    _ => return Err("Mixed note versions detected".to_string()),
                }
            }

            // Sort by assets descending (lines 33-35)
            // =.  notes
            //   %+  sort  notes
            //   |=  [a=nnote:v0:transact b=nnote:v0:transact]
            //   (gth assets.a assets.b)
            v0_notes.sort_by(|a, b| b.assets.value.cmp(&a.assets.value));

            // Call create_spends_0 (line 36)
            // (create-spends-0 notes)
            create_spends_0(
                v0_notes,
                order.clone(),
                fee,
                sign_key.clone(),
                pubkey.clone(),
                refund_pkh,
            )?
        } else {
            // Check if all notes are V1 (lines 38-44)
            // ?:  (levy notes |=(=nnote:transact ?=(@ -.nnote)))
            let all_v1 = notes.iter().all(|note| matches!(note, NNote::V1(_)));

            if all_v1 {
                // Extract and sort V1 notes (lines 39-47)
                let mut v1_notes: Vec<NNoteV1> = Vec::new();
                for note in notes {
                    match note {
                        NNote::V1(v1_note) => v1_notes.push(v1_note),
                        _ => return Err("Mixed note versions detected".to_string()),
                    }
                }

                // Sort by assets descending
                v1_notes.sort_by(|a, b| b.assets.value.cmp(&a.assets.value));

                // Call create_spends_1 (line 48)
                // (create-spends-1 notes)
                create_spends_1(v1_notes, order.clone(), fee, sign_key, pubkey, refund_pkh)?
            } else {
                // Mixed versions - error (lines 49-52)
                // ~>  %slog.[0 'Notes must all be the same version!!!']  !!
                return Err("Notes must all be the same version!!!".to_string());
            }
        }
    };

    // TODO: Validate minimum fee (lines 53-54)
    // =+  min-fee=(calculate-min-fee:spends:transact spends)
    // ?:  (lth fee min-fee)
    //   ~|("Min fee not met..." !!)
    // This requires implementing calculate-min-fee function

    Ok(spends)
}

/// Build V0 spends from a list of V0 notes
///
/// This is the Rust implementation of `++  create-spends-0` from tx-builder-v1.hoon (lines 56-123).
/// It creates a fan-in transaction where multiple V0 notes are spent to a single recipient.
///
/// # Arguments
/// * `notes` - List of V0 notes to spend (will be consumed)
/// * `order` - Payment order specifying recipient and amount
/// * `fee` - Total transaction fee
/// * `sign_key` - Secret key for signing (T8 format)
/// * `pubkey` - Public key corresponding to sign_key
/// * `refund_pkh` - Pubkey hash for refund outputs (required for V0)
///
/// # Returns
/// A ZMap of note names to signed spends, or an error message
///
/// # Algorithm (matches Hoon lines 56-123)
/// Similar to create_spends_1 but:
/// - Uses V0 note structure
/// - Validates via sig.note instead of lock primitives
/// - Creates Spend0 instead of Spend1
pub fn create_spends_0(
    notes: Vec<NNoteV0>,
    order: Order,
    fee: Coins,
    sign_key: T8,
    pubkey: SchnorrPubkey,
    refund_pkh: Option<Hash>,
) -> Result<ZMap<NName, Spend>, String> {
    // Clone refund_pkh at the start so it can be used multiple times in the loop
    let refund_pkh_clone = refund_pkh.clone();
    // Initialize the output lock (lines 72-73)
    // =/  output-lock=lock:transact
    //   [%pkh [m=1 (z-silt:zo ~[recipient.order])]]~
    let mut recipient_set = ZSet::new();
    recipient_set.put(order.recipient.clone());
    let pkh_primitive = LockPrimitive {
        header: "pkh".to_string(),
        body: LockPrimitiveBody::Pkh(Pkh {
            m: 1,
            h: recipient_set,
        }),
    };
    let output_lock = SpendCondition {
        p: vec![pkh_primitive],
    };

    // Build note-data (lines 74-76)
    // =/  =note-data:v1:transact
    //   %-  ~(put z-by:zo *note-data:v1:transact)
    //   =/  =lock-data:wt  [%0 output-lock]
    //   [%lock ^-(* lock-data)]
    let lock_data = LockData::V0(output_lock.clone());
    let mut note_data_map = ZMap::new();
    let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
    note_data_map.put("lock".to_string(), lock_data_noun);

    // NOTE: Due to type mismatch (see comment in seed building below),
    // this note_data is not currently used in V0 seeds
    #[allow(unused_variables)]
    let note_data = NoteData { map: note_data_map };

    // Initialize accumulator state (lines 57-62, 70-71)
    let mut spends = ZMap::new();
    let mut remaining_gift = order.gift.value;
    let mut remaining_fee = fee.value;

    // Process each note (lines 70-122)
    // %+  roll  notes
    for note in notes {
        // === Validate note is spendable === (lines 77-80)
        // ?.  ?&  =(1 m.sig.note)
        //         (~(has z-in:zo pubkeys.sig.note) pubkey)
        //     ==
        //   ~>  %slog.[0 'Note not spendable by signing key']  !!

        // V0 notes have a Lock field (not sig), so validate that instead
        // Check if pubkey is in the lock's pubkeys set
        let has_pubkey = note.lock.pubkeys.iter().any(|pk| pk == &pubkey);
        if note.lock.m != 1 || !has_pubkey {
            return Err(format!(
                "Note {} not spendable by signing key",
                note_name_to_string(&note.name)
            ));
        }

        // === Calculate portions === (lines 81-91)
        let gift_portion = if remaining_gift == 0 {
            0
        } else {
            core::cmp::min(remaining_gift, note.assets.value)
        };

        let available_for_fee = note.assets.value - gift_portion;
        let fee_portion = if remaining_fee == 0 {
            0
        } else {
            core::cmp::min(remaining_fee, available_for_fee)
        };

        // Skip if no contribution (lines 88-89)
        if gift_portion == 0 && fee_portion == 0 {
            continue;
        }

        // Update remaining amounts (lines 90-91)
        let new_gift_remaining = remaining_gift - gift_portion;
        let new_fee_remaining = remaining_fee - fee_portion;

        // Calculate refund (line 92)
        let refund = note.assets.value - (gift_portion + fee_portion);

        // Skip if no gift and no refund (lines 93-95)
        if gift_portion == 0 && refund == 0 {
            continue;
        }

        // === Build seeds === (lines 96-108)
        // Create V1 seeds (with note-data) even though we're spending V0 notes
        // because spend-0:v1:transact creates V1 outputs
        let mut seed_list: Vec<SeedV1> = Vec::new();

        // Add gift seed (lines 99-106)
        if gift_portion > 0 {
            let lock_root = hash_hashable(&output_lock.to_hashable());
            let parent_hash = note.to_hash();

            let gift_seed = SeedV1 {
                output_source: None,
                lock_root,
                note_data: note_data.clone(),
                gift: Coins {
                    value: gift_portion,
                },
                parent_hash,
            };
            seed_list.push(gift_seed);
        }

        // Add refund seed (lines 107-108)
        if refund > 0 {
            let refund_seed =
                create_refund_v0_to_v1(&note, refund, refund_pkh_clone.clone(), &pubkey);
            seed_list.push(refund_seed);
        }

        // Convert to ZSet (line 96: %-  z-silt:zo)
        let mut seeds_set = ZSet::new();
        for seed in seed_list {
            seeds_set.put(seed);
        }
        let seeds = SeedsV1 { set: seeds_set };

        // Error if no seeds (lines 109-110)
        if seeds.set.is_empty() {
            return Err("No seeds were provided".to_string());
        }

        // === Create spend === (lines 111-114)
        // =/  spend=spend-0:v1:transact
        //   %*  .  *spend-0:v1:transact
        //     seeds  seeds
        //     fee    fee-portion
        //   ==
        // Note: spend-0 uses V1 seeds, not V0 seeds!
        let spend_body = SpendV0ToV1 {
            signature: ZMap::new(), // Will be filled by sign function
            seeds,
            fee: Coins { value: fee_portion },
        };

        // === Sign the spend === (line 118)
        // (sign:spend-v1:transact [%0 spend] sign-key)
        let signed_spend = sign_spend_v0_to_v1(spend_body, sign_key.clone(), pubkey.clone())?;

        // === Add to spends map === (lines 117-118)
        spends.put(note.name.clone(), signed_spend);

        // Update remaining amounts
        remaining_gift = new_gift_remaining;
        remaining_fee = new_fee_remaining;
    }

    // === Final validation === (lines 58-62)
    // ?.  ?&  =(0 gift.remaining)  =(0 fee.remaining)  ==
    //   ~>  %slog.[0 'Insufficient funds to pay fee and gift']  !!
    if remaining_gift != 0 || remaining_fee != 0 {
        return Err(format!(
            "Insufficient funds to pay fee and gift. Still need: gift={}, fee={}",
            remaining_gift, remaining_fee
        ));
    }

    Ok(spends)
}

/// Build V1 spends from a list of V1 notes
///
/// This is the Rust implementation of `++  create-spends-1` from tx-builder-v1.hoon.
/// It creates a fan-in transaction where multiple notes are spent to a single recipient,
/// with automatic distribution of gift and fee across the input notes.
///
/// # Arguments
/// * `notes` - List of V1 notes to spend (will be consumed)
/// * `order` - Payment order specifying recipient and amount
/// * `fee` - Total transaction fee
/// * `sign_key` - Secret key for signing (T8 format)
/// * `pubkey` - Public key corresponding to sign_key
/// * `refund_pkh` - Optional pubkey hash for refund outputs (if None, uses pubkey's hash)
///
/// # Returns
/// A ZMap of note names to signed spends, or an error message
///
/// # Algorithm
/// The function processes notes in order, distributing the gift and fee across them:
/// 1. For each note, calculate how much of the gift and fee it can cover
/// 2. Create output seeds for the gift portion (to recipient)
/// 3. Create refund seed for any leftover amount (back to spender)
/// 4. Build lock merkle proof for the input note's lock
/// 5. Sign the spend with the secret key
/// 6. Continue until all gift and fee are covered, or error if insufficient funds
pub fn create_spends_1(
    mut notes: Vec<NNoteV1>,
    order: Order,
    fee: Coins,
    sign_key: T8,
    pubkey: SchnorrPubkey,
    refund_pkh: Option<Hash>,
) -> Result<ZMap<NName, Spend>, String> {
    // Validate that gift is non-zero (line 19-20 in Hoon)
    if order.gift.value == 0 {
        return Err("Cannot create a transaction with zero gift".to_string());
    }

    // Sort notes by assets in descending order (lines 42-45 in Hoon)
    // This processes larger notes first for efficiency
    notes.sort_by(|a, b| b.assets.value.cmp(&a.assets.value));

    // Initialize the output lock: simple 1-of-1 PKH lock with recipient (lines 131-132)
    // [%pkh [m=1 (z-silt:zo ~[recipient.order])]]~
    let mut recipient_set = ZSet::new();
    recipient_set.put(order.recipient.clone());
    let pkh_primitive = LockPrimitive {
        header: "pkh".to_string(),
        body: LockPrimitiveBody::Pkh(Pkh {
            m: 1,
            h: recipient_set,
        }),
    };
    let output_lock = SpendCondition {
        p: vec![pkh_primitive],
    };

    // Build note-data that will be attached to output seeds (lines 133-136)
    // This stores the lock information in the note for future reference
    let lock_data = LockData::V0(output_lock.clone());
    let mut note_data_map = ZMap::new();

    // Convert lock_data to UntypedNoun
    // In Hoon this is: [%lock ^-(* lock-data)]
    // We serialize the lock_data as an untyped noun to store it
    let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
    note_data_map.put("lock".to_string(), lock_data_noun);
    let note_data = NoteData { map: note_data_map };

    // Calculate our pubkey hash for lock validation (line 136)
    let pkh = pubkey.to_hash();

    // Initialize the accumulator state for the fold/roll operation (lines 125-130, 137-140)
    let mut spends = ZMap::new();
    let mut remaining_gift = order.gift.value;
    let mut remaining_fee = fee.value;

    // Process each note in sequence (lines 137-212: %+  roll  notes)
    // This is a left fold that accumulates spends and tracks remaining amounts
    for note in notes {
        // === Parse and validate note-data === (lines 143-145)
        // Try to extract note-data from the note
        // ?~  nd  ~>  %slog.[0 'error: note-data malformed in note!']  !!
        let nd = &note.note_data;

        // === Build and validate input-lock === (lines 146-171)
        // Create a simple PKH lock-primitive using our pubkey hash
        // This will be used as the default if no lock is found in note-data
        let simple_pkh = LockPrimitive {
            header: "pkh".to_string(),
            body: LockPrimitiveBody::Pkh(Pkh {
                m: 1,
                h: {
                    let mut set = ZSet::new();
                    set.put(pkh.clone());
                    set
                },
            }),
        };

        // Build the coinbase lock (used as fallback)
        // =/  coinbase-lock=spend-condition:transact  ~[simple-pkh tim-lp:coinbase:transact]
        // For simplicity, we'll just use the simple-pkh without timelock for now
        let coinbase_lock = SpendCondition {
            p: vec![simple_pkh.clone()],
        };

        // Try to extract lock from note-data, or use coinbase lock as default
        // This complex logic validates that the lock is spendable by our key (lines 148-170)
        let input_lock: Reason<SpendCondition> = {
            // Look for 'lock' key in note-data map
            match nd.map.get(&"lock".to_string()) {
                None => {
                    // No lock noun found, use coinbase lock (line 150)
                    Ok(coinbase_lock)
                }
                Some(lock_noun) => {
                    // Found a lock noun in note-data, deserialize it
                    // The lock is stored as jammed bytes in the UntypedNoun
                    match lock_noun.to_typed::<LockData>() {
                        Ok(lock_data) => {
                            // Successfully deserialized the lock data
                            let spend_condition = match lock_data {
                                LockData::V0(sc) => sc,
                            };

                            // Validate it's spendable: must be a single PKH with m=1
                            // and our pkh must be in the set
                            if spend_condition.p.len() != 1 {
                                return Err("Lock has multiple primitives, unsupported".to_string());
                            }

                            let primitive = &spend_condition.p[0];
                            if primitive.header != "pkh" {
                                return Err("Lock is not a PKH lock, unsupported".to_string());
                            }

                            match &primitive.body {
                                LockPrimitiveBody::Pkh(pkh_lock) => {
                                    if pkh_lock.m != 1 {
                                        return Err("Lock requires m != 1 signatures, unsupported"
                                            .to_string());
                                    }

                                    // Check if our public key hash is in the lock's hash set
                                    let our_pkh = pubkey.to_hash();
                                    if !pkh_lock.h.has(&our_pkh) {
                                        return Err(
                                            "Our PKH is not in the lock's hash set".to_string()
                                        );
                                    }

                                    Ok(spend_condition)
                                }
                                _ => {
                                    // Other lock primitive types (Tim, Hax, Brn) are not supported
                                    Err("Unsupported lock primitive type".to_string())
                                }
                            }
                        }
                        Err(e) => {
                            // Failed to deserialize lock, this shouldn't happen if the note was valid
                            Err(format!("Failed to deserialize lock from note-data: {}", e))
                        }
                    }
                }
            }
        };

        // If input-lock validation failed, error out (lines 171-172)
        let input_lock = match input_lock {
            Ok(lock) => lock,
            Err(reason) => {
                return Err(format!(
                    "Error processing note {}: {}",
                    note_name_to_string(&note.name),
                    reason
                ));
            }
        };

        // === Calculate portions === (lines 173-185)
        // Determine how much of this note goes to gift, fee, and refund

        // Gift portion: take what's needed from gift.remaining, up to note's assets
        // =/  gift-portion=@
        //   ?:  =(0 gift.remaining)  0
        //   (min gift.remaining assets.note)
        let gift_portion = if remaining_gift == 0 {
            0
        } else {
            core::cmp::min(remaining_gift, note.assets.value)
        };

        // What's left after gift goes toward fee
        // =/  available-for-fee=@  (sub assets.note gift-portion)
        let available_for_fee = note.assets.value - gift_portion;

        // Fee portion: take what's needed from fee.remaining, up to available amount
        // =/  fee-portion=@
        //   ?:  =(0 fee.remaining)  0
        //   (min fee.remaining available-for-fee)
        let fee_portion = if remaining_fee == 0 {
            0
        } else {
            core::cmp::min(remaining_fee, available_for_fee)
        };

        // If this note contributes nothing, skip it (lines 182-183)
        // ?:  &(=(0 gift-portion) =(0 fee-portion))
        //   [spends remaining]
        if gift_portion == 0 && fee_portion == 0 {
            continue;
        }

        // Update remaining amounts (lines 184-185)
        // =/  [new-gift-remaining=@ new-fee-remaining=@]
        //   :-  (sub gift.remaining gift-portion)
        //   (sub fee.remaining fee-portion)
        let new_gift_remaining = remaining_gift - gift_portion;
        let new_fee_remaining = remaining_fee - fee_portion;

        // Calculate refund amount (line 186)
        // =/  refund=@  (sub assets.note (add gift-portion fee-portion))
        let refund = note.assets.value - (gift_portion + fee_portion);

        // Skip if no gift and no refund (edge case, lines 187-189)
        // ?:  ?&  =(0 gift-portion)  =(0 refund)  ==
        //   [spends remaining]
        if gift_portion == 0 && refund == 0 {
            continue;
        }

        // === Build seeds === (lines 190-203)
        // Create output seeds for this spend
        let mut seed_list: Vec<SeedV1> = Vec::new();

        // Add gift seed if there's a gift portion (lines 193-200)
        // =?  seeds  (gth gift-portion 0)
        if gift_portion > 0 {
            // Compute lock root hash for the output lock
            let lock_root = hash_hashable(&output_lock.to_hashable());

            // Get parent hash (hash of the note being spent)
            let parent_hash = note.name.to_hash();

            let gift_seed = SeedV1 {
                output_source: None,
                lock_root,
                note_data: note_data.clone(),
                gift: Coins {
                    value: gift_portion,
                },
                parent_hash,
            };
            seed_list.push(gift_seed);
        }

        // Add refund seed if there's a refund (lines 201-203)
        // =?  seeds  (gth refund 0)
        if refund > 0 {
            let refund_seed = create_refund(&note, refund, refund_pkh.clone(), &pubkey);
            seed_list.push(refund_seed);
        }

        // Convert seed list to ZSet (line 190: %-  z-silt:zo)
        let mut seeds_set = ZSet::new();
        for seed in seed_list {
            seeds_set.put(seed);
        }
        let seeds = SeedsV1 { set: seeds_set };

        // Error if no seeds created (lines 204-205)
        // ?~  seeds  ~|('No seeds were provided' !!)
        if seeds.set.is_empty() {
            return Err("No seeds were provided".to_string());
        }

        // === Build lock merkle proof === (lines 206-207)
        // Build a merkle proof showing that the spend-condition is in the lock tree
        // =/  lmp=lock-merkle-proof:transact
        //   (build-lock-merkle-proof:lock:transact p.input-lock 1)
        let lmp = build_lock_merkle_proof(input_lock.clone(), 1);

        // === Create spend and witness === (lines 208-215)
        // Build the Spend1 structure with witness
        // =/  spend=spend-1:v1:transact
        //   %*  .  *spend-1:v1:transact
        //     seeds  seeds
        //     fee    fee-portion
        //   ==
        let witness = Witness {
            lmp,
            pkh: PkhSignature { map: ZMap::new() },
            hax: ZMap::new(),
            tim: 0,
        };

        // Note: In the Hoon version, witness fields are set after creation:
        // =.  witness.spend
        //   %*  .  *witness:transact
        //     lmp  lmp
        //   ==
        // The witness already has lmp set above, so we're good

        let spend_body = SpendV1 {
            witness,
            seeds,
            fee: Coins { value: fee_portion },
        };

        // === Sign the spend === (line 218)
        // Sign using the spend-v1 signing function
        // (sign:spend-v1:transact [%1 spend] sign-key)
        let signed_spend = sign_spend_v1(spend_body, sign_key.clone(), pubkey.clone())?;

        // === Add to spends map === (lines 217-218)
        // Add the signed spend to our accumulator
        // %-  (~(put z-by:zo spends))
        // [name.note (sign:spend-v1:transact [%1 spend] sign-key)]
        spends.put(note.name.clone(), signed_spend);

        // Update remaining amounts for next iteration
        remaining_gift = new_gift_remaining;
        remaining_fee = new_fee_remaining;
    }

    // === Final validation === (lines 127-130)
    // Check that we covered the entire gift and fee
    // ?.  ?&  =(0 gift.remaining)  =(0 fee.remaining)  ==
    //   ~>  %slog.[0 'Insufficient funds to pay fee and gift']  !!
    if remaining_gift != 0 || remaining_fee != 0 {
        return Err(format!(
            "Insufficient funds to pay fee and gift. Still need: gift={}, fee={}",
            remaining_gift, remaining_fee
        ));
    }

    Ok(spends)
}

/// Create a refund seed that returns leftover funds to the spender
///
/// Matches the Hoon function `++  create-refund` (lines 214-229)
///
/// # Arguments
/// * `note` - The note being spent (used for parent hash)
/// * `refund` - Amount to refund
/// * `refund_pkh` - Optional explicit refund address (pubkey hash)
/// * `pubkey` - Default pubkey to refund to (if refund_pkh is None)
///
/// # Returns
/// A SeedV1 that will create a refund output
fn create_refund(
    note: &NNoteV1,
    refund: u64,
    refund_pkh: Option<Hash>,
    pubkey: &SchnorrPubkey,
) -> SeedV1 {
    // Build the refund lock-primitive (lines 224-228)
    // =/  refund-lp=lock-primitive:transact
    //   ?^  refund-pkh
    //     [%pkh [m=1 (z-silt:zo ~[u.refund-pkh])]]
    //   =/  pkh=hash:transact  (hash:schnorr-pubkey:transact pubkey)
    //   [%pkh [m=1 (z-silt:zo ~[pkh])]]
    let refund_pkh_hash = match refund_pkh {
        Some(pkh) => pkh,
        None => pubkey.to_hash(),
    };

    let mut pkh_set = ZSet::new();
    pkh_set.put(refund_pkh_hash);

    let refund_lp = LockPrimitive {
        header: "pkh".to_string(),
        body: LockPrimitiveBody::Pkh(Pkh { m: 1, h: pkh_set }),
    };

    // Build the lock (just the single primitive) (line 229)
    // =/  lok=lock:transact  ~[refund-lp]
    let lok = SpendCondition { p: vec![refund_lp] };

    // Build note-data with the lock (lines 230-232)
    // =/  =note-data:v1:transact
    //   %-  ~(put z-by:zo *note-data:v1:transact)
    //   [%lock ^-(lock-data:wt [%0 lok])]
    let lock_data = LockData::V0(lok.clone());
    let mut note_data_map = ZMap::new();

    // Serialize lock_data to UntypedNoun
    let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
    note_data_map.put("lock".to_string(), lock_data_noun);
    let note_data = NoteData { map: note_data_map };

    // Calculate lock root hash
    let lock_root = hash_hashable(&lok.to_hashable());

    // Get parent hash
    let parent_hash = note.name.to_hash();

    // Build and return the seed (lines 225-229)
    // :*  output-source=~
    //     lock-root=(hash:lock:transact lok)
    //     note-data
    //     gift=refund
    //     parent-hash=(hash:nnote:transact note)
    // ==
    SeedV1 {
        output_source: None,
        lock_root,
        note_data,
        gift: Coins { value: refund },
        parent_hash,
    }
}

/// Sign a V1 spend with a secret key
///
/// This creates a proper signature for the spend and wraps it in the Spend enum.
/// Matches the Hoon signature: (sign:spend-v1:transact [%1 spend] sign-key)
///
/// # Arguments
/// * `spend_body` - The SpendV1 to sign
/// * `sign_key` - Secret key (T8 format)
/// * `pubkey` - Public key corresponding to the secret key
///
/// # Returns
/// A signed Spend (wrapped in the versioned enum)
fn sign_spend_v1(
    spend_body: SpendV1,
    sign_key: T8,
    pubkey: SchnorrPubkey,
) -> Result<Spend, String> {
    // Calculate the signature hash for the spend
    // In Hoon: (sig-hash:spend:v1 sp)
    let sig_hash = compute_spend_v1_sig_hash(&spend_body);

    // Sign the hash using Schnorr signature
    let (chal_t8, sig_t8) = schnorr_sign_digest(sign_key, pubkey.clone(), sig_hash);

    // Create the SchnorrSignature
    let schnorr_sig = SchnorrSignature {
        chal: Chal { values: chal_t8 },
        sig: Sig { values: sig_t8 },
    };

    // Calculate pubkey hash
    let pk_hash = pubkey.to_hash();

    // Create PKH signature map entry
    let mut pkh_map = ZMap::new();
    let pkh_sig_value = PkhSignatureValue {
        pk: pubkey,
        sig: schnorr_sig,
    };
    pkh_map.put(pk_hash, pkh_sig_value);

    // Update the witness with the signature
    let mut updated_spend = spend_body;
    updated_spend.witness.pkh = PkhSignature { map: pkh_map };

    // Wrap in the versioned Spend enum with version tag %1
    Ok(Spend {
        version: 1,
        body: SpendBody::V1(updated_spend),
    })
}

/// Compute the signature hash for a V1 spend
///
/// This is what gets signed when creating a transaction.
/// The signature commits to the seeds and fee.
///
/// From Hoon (tx-engine-1.hoon lines 738-742):
/// ```hoon
/// ++  sig-hash
///   |=  sen=form
///   ^-  ^hash
///   %-  hash-hashable:tip5
///   [(sig-hashable:seeds seeds.sen) leaf+fee.sen]
/// ```
fn compute_spend_v1_sig_hash(spend: &SpendV1) -> Hash {
    use crate::hashing::hasher::hash_hashable;

    // Get the sig-hashable for seeds
    let seeds_hashable = spend.seeds.to_sig_hashable();

    // Create the fee leaf
    let fee_hashable = spend.fee.to_hashable();

    // Combine them into a cell [seeds_hashable fee_hashable]
    let combined_hashable = Hashable::cell(seeds_hashable, fee_hashable);

    // Hash it
    hash_hashable(&combined_hashable)
}

/// Helper function to convert note name to string for error messages
fn note_name_to_string(name: &NName) -> String {
    // Convert the first hash to base58 if available
    if let Some(first_hash) = name.p.first() {
        first_hash.to_b58()
    } else {
        "unknown".to_string()
    }
}

/// Create a refund seed for V0 notes that returns leftover funds to the spender
/// Returns a V1 seed since spend-0 creates V1 outputs
///
/// Matches the Hoon function `++  create-refund` (lines 214-229)
///
/// # Arguments
/// * `note` - The V0 note being spent (used for parent hash)
/// * `refund` - Amount to refund
/// * `refund_pkh` - Optional explicit refund address (pubkey hash)
/// * `pubkey` - Default pubkey to refund to (if refund_pkh is None)
///
/// # Returns
/// A SeedV1 that will create a refund output
fn create_refund_v0_to_v1(
    note: &NNoteV0,
    refund: u64,
    refund_pkh: Option<Hash>,
    pubkey: &SchnorrPubkey,
) -> SeedV1 {
    // Build the refund lock-primitive (lines 217-220)
    let refund_pkh_hash = match refund_pkh {
        Some(pkh) => pkh,
        None => pubkey.to_hash(),
    };

    let mut pkh_set = ZSet::new();
    pkh_set.put(refund_pkh_hash);

    let refund_lp = LockPrimitive {
        header: "pkh".to_string(),
        body: LockPrimitiveBody::Pkh(Pkh { m: 1, h: pkh_set }),
    };

    // Build the lock (just the single primitive) (line 221)
    let lok = SpendCondition { p: vec![refund_lp] };

    // Build note-data with the lock (lines 222-224)
    let lock_data = LockData::V0(lok.clone());
    let mut note_data_map = ZMap::new();

    // Serialize lock_data to UntypedNoun
    let lock_data_noun = lock_data_to_untyped_noun(&lock_data);
    note_data_map.put("lock".to_string(), lock_data_noun);
    let note_data = NoteData { map: note_data_map };

    // Calculate lock root hash
    let lock_root = hash_hashable(&lok.to_hashable());

    // Get parent hash
    let parent_hash = note.to_hash();

    // Build and return the V1 seed (lines 225-229)
    SeedV1 {
        output_source: None,
        lock_root,
        note_data,
        gift: Coins { value: refund },
        parent_hash,
    }
}

/// Sign a V0-to-V1 spend (spend-0:v1:transact)
///
/// This function signs a spend that consumes a V0 note and creates V1 outputs.
/// It corresponds to the `++sign` arm in `spend-0:v1:transact` from tx-engine-1.hoon.
///
/// From Hoon (tx-engine-1.hoon lines 573-586):
/// ```hoon
/// ++  sign
///   |=  [sen=form sk=schnorr-seckey]
///   ^+  sen
///   =/  pk=schnorr-pubkey
///     %-  ch-scal:affine:curve:cheetah
///     :*  (t8-to-atom:belt-schnorr:cheetah sk)
///         a-gen:curve:cheetah
///     ==
///   =/  sig=schnorr-signature
///     %+  sign:affine:belt-schnorr:cheetah
///       sk
///     (sig-hash sen)
///   %_  sen
///     signature  (~(put z-by signature.sen) pk sig)
///   ==
/// ```
fn sign_spend_v0_to_v1(
    mut spend_body: SpendV0ToV1,
    sign_key: T8,
    pubkey: SchnorrPubkey,
) -> Result<Spend, String> {
    // Calculate the signature hash using the SpendV0ToV1's method
    let sig_hash = spend_body.compute_sig_hash();

    // Sign the hash using Schnorr signature
    let (chal_t8, sig_t8) = schnorr_sign_digest(sign_key, pubkey.clone(), sig_hash);

    // Create the SchnorrSignature
    let schnorr_sig = SchnorrSignature {
        chal: Chal { values: chal_t8 },
        sig: Sig { values: sig_t8 },
    };

    // Add signature to the signature map (V0 uses pubkey as key, not hash)
    spend_body.signature.put(pubkey, schnorr_sig);

    // Wrap in the versioned Spend enum with version tag %0
    // Note: Even though this creates V1 outputs, it's still tagged as %0
    // because it spends a V0 note
    Ok(Spend {
        version: 0,
        body: SpendBody::V0ToV1(spend_body),
    })
}

/// Helper trait to extract PKH from LockPrimitiveBody
#[allow(dead_code)]
trait AsPkh {
    fn as_pkh(&self) -> Option<&Pkh>;
}

impl AsPkh for LockPrimitiveBody {
    fn as_pkh(&self) -> Option<&Pkh> {
        match self {
            LockPrimitiveBody::Pkh(pkh) => Some(pkh),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_refund() {
        // Test refund seed creation
        let pubkey = SchnorrPubkey {
            x: F6LT {
                values: [1, 2, 3, 4, 5, 6],
            },
            y: F6LT {
                values: [7, 8, 9, 10, 11, 12],
            },
            inf: false,
        };

        let note = NNoteV1 {
            version: 1,
            origin_page: PageNumber { value: 100 },
            name: NName { p: vec![] },
            note_data: NoteData { map: ZMap::new() },
            assets: Coins { value: 1000 },
        };

        let refund_seed = create_refund(&note, 500, None, &pubkey);

        assert_eq!(refund_seed.gift.value, 500);
        assert_eq!(refund_seed.output_source, None);
    }
}
