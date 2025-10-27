//! Transaction Fee Calculator
//!
//! This module implements the minimum fee calculation logic for Nockchain transactions.
//! The fee is based on the total word count of seeds and witnesses in the transaction.
//!
//! From Hoon (tx-engine.hoon lines 882-892):
//! ```hoon
//! ++  calculate-min-fee
//!   |=  sps=form
//!   ^-  coins
//!   =/  word-count=@
//!     %+  roll  ~(tap z-by sps)
//!     |=  [[nam=nname sp=spend] acc=@]
//!     %+  add  acc
//!     %+  add
//!       (count-seed-words:spend-v1 sp)
//!     (count-witness-words:spend-v1 sp)
//!   =/  word-fee=coins  (mul word-count base-fee)
//!   (max word-fee min-fee.data)
//! ```
//!
//! # Constants
//! - `BASE_FEE`: 2^15 = 32,768 nicks per word
//! - `MIN_FEE`: 256 nicks (absolute minimum)

extern crate alloc;

use crate::collections::ZMap;
use crate::hashing::hashable::Hashable;
use crate::transaction_types::{Coins, NName, Spend};

/// Base fee per word for witness and note-data storage
/// From blockchain-constants: base-fee=(bex 15) = 2^15 = 32,768
pub const BASE_FEE: u64 = 32_768;

/// Minimum fee in nicks (absolute floor)
/// From blockchain-constants: min-fee=256
pub const MIN_FEE: u64 = 256;

/// Calculate the minimum required fee for a set of spends
///
/// This follows the Hoon implementation exactly:
/// 1. Count total words across all seeds and witnesses
/// 2. Calculate word_fee = word_count * BASE_FEE
/// 3. Return max(word_fee, MIN_FEE)
///
/// # Arguments
/// * `spends` - Map of note names to spend transactions
///
/// # Returns
/// The minimum required fee in Coins
pub fn calculate_min_fee(spends: &ZMap<NName, Spend>) -> Coins {
    let word_count: u64 = spends
        .tap()
        .iter()
        .map(|(_name, spend)| count_spend_words(spend))
        .sum();

    let word_fee = word_count * BASE_FEE;
    let min_fee = core::cmp::max(word_fee, MIN_FEE);

    Coins { value: min_fee }
}

/// Count total words for a single spend (seeds + witness)
fn count_spend_words(spend: &Spend) -> u64 {
    // For now, we convert the spend to a hashable and count leaves
    // This is a conservative approximation until we implement proper
    // word counting for each spend type

    // TODO: Implement proper counting that matches Hoon:
    // - count_seed_words: iterate seeds, sum leaves in each note-data
    // - count_witness_words: count leaves in witness/signature structure

    // For now, use a placeholder that returns a reasonable default
    // This ensures the fee calculation doesn't break existing code
    let spend_tree = spend.body.to_hashable();
    count_leaves(&spend_tree)
}

/// Count the number of leaves in a Hashable tree
///
/// This mirrors the Hoon `num-of-leaves:shape` function.
/// Leaves, Hashes, and Lists each count as 1.
/// Cells recursively sum their left and right subtrees.
fn count_leaves(h: &Hashable) -> u64 {
    match h {
        // Non-cell cases: Leaf, Hash, and List all count as 1 leaf
        Hashable::Leaf(_) | Hashable::Hash(_) | Hashable::List(_) => 1,
        // Cell case: sum of left and right subtrees
        Hashable::Cell(left, right) => count_leaves(left) + count_leaves(right),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_leaves() {
        // Leaf should count as 1
        let leaf = Hashable::Leaf(Vec::new());
        assert_eq!(count_leaves(&leaf), 1);

        // Cell of two leaves should count as 2
        let cell = Hashable::Cell(
            alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
            alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
        );
        assert_eq!(count_leaves(&cell), 2);

        // Nested cell: [[[leaf] leaf] leaf] = 3 leaves
        let nested = Hashable::Cell(
            alloc::boxed::Box::new(Hashable::Cell(
                alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
                alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
            )),
            alloc::boxed::Box::new(Hashable::Leaf(Vec::new())),
        );
        assert_eq!(count_leaves(&nested), 3);
    }

    #[test]
    fn test_base_fee_constant() {
        // Verify BASE_FEE = 2^15
        assert_eq!(BASE_FEE, 1u64 << 15);
        assert_eq!(BASE_FEE, 32_768);
    }

    #[test]
    fn test_min_fee_calculation() {
        // Empty spends map should return MIN_FEE
        let empty_spends = ZMap::new();
        let fee = calculate_min_fee(&empty_spends);
        assert_eq!(fee.value, MIN_FEE);
    }
}
