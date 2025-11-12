/// Transaction validation module
///
/// This module contains comprehensive transaction validation logic:
/// - Signature verification (Schnorr over Cheetah curve)
/// - Input/output balance validation
/// - Timelock constraint validation
/// - Fee validation
/// - Transaction ID validation
use super::signature_verification::schnorr_verify_digest;
use crate::hashing::tx_id::compute_tx_id;
use crate::transaction_types::RawTransaction;

/// Transaction validator
pub struct TransactionValidator;

impl TransactionValidator {
    /// Validate a complete RawTransaction
    ///
    /// This performs comprehensive validation of all transaction components:
    /// 1. Signature verification - all inputs must be properly signed
    /// 2. Funds balance - inputs must cover outputs + fees
    /// 3. Timelock constraints - timelock ranges must be consistent
    /// 4. Fee validation - total fees must match sum of input fees
    /// 5. Transaction ID - ID must match computed hash
    ///
    /// # Arguments
    /// * `transaction` - The transaction to validate
    ///
    /// # Returns
    /// * `Ok(())` if validation succeeds
    /// * `Err(TransactionValidationError)` with details if validation fails
    pub fn validate_transaction(
        transaction: &RawTransaction,
    ) -> Result<(), TransactionValidationError> {
        // 1. Validate all signatures
        Self::validate_signatures(transaction)?;

        // 2. Validate funds balance
        Self::validate_funds(transaction)?;

        // 3. Validate timelock constraints
        Self::validate_timelocks(transaction)?;

        // 4. Validate fees
        Self::validate_fees(transaction)?;

        // 5. Validate transaction ID
        Self::validate_tx_id(transaction)?;

        Ok(())
    }

    /// Validate all signatures in the transaction
    ///
    /// For each input:
    /// - Signature must exist
    /// - Signature map must not be empty
    /// - Must have enough signatures to meet the m-of-n threshold
    /// - Each signing pubkey must be authorized (in the lock's pubkey set)
    /// - Each Schnorr signature must be cryptographically valid
    fn validate_signatures(tx: &RawTransaction) -> Result<(), TransactionValidationError> {
        let inputs = match tx {
            RawTransaction::V0(v0) => &v0.inputs,
            _ => return Ok(()),
        };
        for (name, input) in inputs.p.tap() {
            // Get the sig_hash for this spend (the message that was signed)
            let sig_hash = input.spend.sig_hash();

            // Check if signature exists
            let signature = input.spend.signature.as_ref().ok_or_else(|| {
                TransactionValidationError::InvalidSignature(format!(
                    "Input {:?} has no signature",
                    name
                ))
            })?;

            // Verify each signature in the map
            let sig_count = signature.map.tap().len();
            if sig_count == 0 {
                return Err(TransactionValidationError::InvalidSignature(format!(
                    "Input {:?} has empty signature map",
                    name
                )));
            }

            // Check we have enough signatures for the lock (m-of-n threshold)
            if (sig_count as u64) < input.note.lock.m {
                return Err(TransactionValidationError::InvalidSignature(format!(
                    "Input {:?} needs {} signatures but has {}",
                    name, input.note.lock.m, sig_count
                )));
            }

            // Verify each signature with its corresponding pubkey
            for (pubkey, schnorr_sig) in signature.map.tap() {
                // Check pubkey is in the lock's authorized pubkey set
                if !input.note.lock.pubkeys.has(&pubkey) {
                    return Err(TransactionValidationError::InvalidSignature(format!(
                        "Pubkey not authorized for input {:?}",
                        name
                    )));
                }

                // Verify the Schnorr signature cryptographically
                if !schnorr_verify_digest(pubkey.clone(), sig_hash.clone(), schnorr_sig.clone()) {
                    return Err(TransactionValidationError::InvalidSignature(format!(
                        "Invalid Schnorr signature for input {:?}",
                        name
                    )));
                }
            }
        }
        Ok(())
    }

    /// Validate input/output funds balance
    ///
    /// The sum of all inputs must be >= sum of all outputs + fees
    /// This ensures no coins are created out of thin air.
    fn validate_funds(tx: &RawTransaction) -> Result<(), TransactionValidationError> {
        let mut total_input: u64 = 0;
        let mut total_output: u64 = 0;

        let inputs = match tx {
            RawTransaction::V0(v0) => &v0.inputs,
            _ => return Ok(()),
        };
        for (_, input) in inputs.p.tap() {
            // Input amount from the note being spent
            total_input = total_input
                .checked_add(input.note.assets.value)
                .ok_or_else(|| {
                    TransactionValidationError::InsufficientFunds(
                        "Input amount overflow".to_string(),
                    )
                })?;

            // Output amounts from all seeds (new coins being created)
            for seed in input.spend.seeds.set.tap() {
                total_output = total_output.checked_add(seed.gift.value).ok_or_else(|| {
                    TransactionValidationError::InsufficientFunds(
                        "Output amount overflow".to_string(),
                    )
                })?;
            }

            // Fee from this input
            total_output = total_output
                .checked_add(input.spend.fee.value)
                .ok_or_else(|| {
                    TransactionValidationError::InsufficientFunds("Fee overflow".to_string())
                })?;
        }

        // Verify total_input >= total_output
        if total_input < total_output {
            return Err(TransactionValidationError::InsufficientFunds(format!(
                "Inputs {} < Outputs + Fees {}",
                total_input, total_output
            )));
        }

        Ok(())
    }

    /// Validate timelock constraints
    ///
    /// The transaction's timelock_range must be compatible with all input timelocks.
    /// Each input may have absolute and relative timelock constraints that restrict
    /// when the transaction can be included in a block.
    fn validate_timelocks(tx: &RawTransaction) -> Result<(), TransactionValidationError> {
        // Check that tx.timelock_range is consistent with all input timelocks
        // The transaction can only be included in blocks that satisfy ALL inputs

        let inputs = match tx {
            RawTransaction::V0(v0) => &v0.inputs,
            _ => return Ok(()),
        };
        for (name, input) in inputs.p.tap() {
            let intent = &input.note.meta.timelock.intent;

            if let Some((abs_range, _rel_range)) = intent {
                // Validate absolute timelock compatibility
                if let Some(abs_min) = abs_range.min {
                    // If input has minimum absolute timelock, check against tx maximum
                    if let Some(tx_max) = match tx {
                        RawTransaction::V0(v0) => v0.timelock_range.max,
                        _ => None,
                    } {
                        if abs_min.value > tx_max.value {
                            return Err(TransactionValidationError::InvalidTimelock(format!(
                                "Input {:?} absolute min {} > tx max {}",
                                name, abs_min.value, tx_max.value
                            )));
                        }
                    }
                }

                if let Some(abs_max) = abs_range.max {
                    // If input has maximum absolute timelock, check against tx minimum
                    if let Some(tx_min) = match tx {
                        RawTransaction::V0(v0) => v0.timelock_range.min,
                        _ => None,
                    } {
                        if abs_max.value < tx_min.value {
                            return Err(TransactionValidationError::InvalidTimelock(format!(
                                "Input {:?} absolute max {} < tx min {}",
                                name, abs_max.value, tx_min.value
                            )));
                        }
                    }
                }

                // Note: Relative timelocks require additional context (parent block page numbers)
                // which we don't have in this validation context. They would be validated
                // at block inclusion time.
            }
        }

        Ok(())
    }

    /// Validate fee amounts
    ///
    /// The total_fees field must exactly match the sum of all input fees.
    fn validate_fees(tx: &RawTransaction) -> Result<(), TransactionValidationError> {
        let mut calculated_fees: u64 = 0;

        let inputs = match tx {
            RawTransaction::V0(v0) => &v0.inputs,
            _ => return Ok(()),
        };
        for (_, input) in inputs.p.tap() {
            calculated_fees = calculated_fees
                .checked_add(input.spend.fee.value)
                .ok_or_else(|| {
                    TransactionValidationError::InvalidFee("Fee calculation overflow".to_string())
                })?;
        }

        if calculated_fees
            != match tx {
                RawTransaction::V0(v0) => v0.total_fees.value,
                _ => 0,
            }
        {
            return Err(TransactionValidationError::InvalidFee(format!(
                "Total fees mismatch: calculated {} != stored {}",
                calculated_fees,
                match tx {
                    RawTransaction::V0(v0) => v0.total_fees.value,
                    _ => 0,
                }
            )));
        }

        Ok(())
    }

    /// Validate transaction ID is correctly computed
    ///
    /// The transaction ID must match the hash of its contents.
    /// This prevents transaction malleability.
    fn validate_tx_id(tx: &RawTransaction) -> Result<(), TransactionValidationError> {
        if let RawTransaction::V0(v0) = tx {
            let computed_id = compute_tx_id(
                &crate::transaction_types::Inputs::V0(v0.inputs.clone()),
                &v0.timelock_range,
                v0.total_fees,
            );
            if computed_id != v0.id {
                return Err(TransactionValidationError::ValidationError(
                    "Transaction ID mismatch - computed hash doesn't match stored ID".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Errors that can occur during transaction validation
#[derive(Debug, Clone)]
pub enum TransactionValidationError {
    /// Invalid signature
    InvalidSignature(String),
    /// Insufficient funds
    InsufficientFunds(String),
    /// Invalid timelock constraints
    InvalidTimelock(String),
    /// Invalid fee amount
    InvalidFee(String),
    /// General validation error
    ValidationError(String),
}

impl std::fmt::Display for TransactionValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionValidationError::InvalidSignature(msg) => {
                write!(f, "Invalid signature: {}", msg)
            }
            TransactionValidationError::InsufficientFunds(msg) => {
                write!(f, "Insufficient funds: {}", msg)
            }
            TransactionValidationError::InvalidTimelock(msg) => {
                write!(f, "Invalid timelock: {}", msg)
            }
            TransactionValidationError::InvalidFee(msg) => write!(f, "Invalid fee: {}", msg),
            TransactionValidationError::ValidationError(msg) => {
                write!(f, "Validation error: {}", msg)
            }
        }
    }
}

impl std::error::Error for TransactionValidationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::slip10::master::master_from_mnemonic;
    use crate::signer::sign_tx;
    use crate::transaction_types::T8;
    use nockapp::noun::slab::NounSlab;
    use noun_serde::NounDecode;

    // Test data: JAM-encoded unsigned transaction
    const UNSIGNED_TX_JAM: &[u8] = &[
        0x05, 0x10, 0x78, 0x97, 0x33, 0xf1, 0x2e, 0xa8, 0x0b, 0xd9, 0x0d, 0xd0, 0x83, 0x0e, 0x1c,
        0x2d, 0x43, 0xfd, 0x0f, 0xa2, 0x01, 0x04, 0x52, 0xa1, 0x7c, 0x95, 0x6c, 0x52, 0x60, 0x17,
        0x03, 0x08, 0xa4, 0x41, 0xca, 0x85, 0x89, 0x8c, 0x64, 0x80, 0x02, 0x04, 0xa8, 0x74, 0x6d,
        0x8f, 0x60, 0x3c, 0x6b, 0x2d, 0xab, 0x02, 0x08, 0x68, 0xf3, 0x6e, 0xc7, 0x88, 0x9b, 0x26,
        0x5f, 0x06, 0xf8, 0x4d, 0xd3, 0xfa, 0x68, 0x3b, 0xa4, 0x03, 0xf4, 0x01, 0x76, 0xb6, 0x17,
        0xb0, 0xff, 0xeb, 0x9e, 0x31, 0x18, 0xa0, 0x97, 0xbb, 0x49, 0x3e, 0x5a, 0x91, 0x82, 0xae,
        0x01, 0x3f, 0xb6, 0x44, 0xa0, 0x30, 0xaf, 0xb5, 0xe8, 0xbb, 0x00, 0xfd, 0x7d, 0x4b, 0x4c,
        0x43, 0x11, 0x14, 0xf5, 0x1e, 0x40, 0x00, 0x08, 0x45, 0x12, 0x1a, 0x2d, 0x90, 0x5e, 0x32,
        0x80, 0x80, 0xfc, 0x28, 0xe7, 0xac, 0xfe, 0xf7, 0xe8, 0x63, 0x80, 0xde, 0xd0, 0x4c, 0xb3,
        0xe6, 0xfc, 0x65, 0xaf, 0x07, 0x08, 0x74, 0xd7, 0xb0, 0x29, 0xfe, 0x50, 0xb0, 0xc1, 0x5a,
        0x19, 0x78, 0x78, 0xb7, 0x0d, 0x73, 0xb9, 0xb8, 0x02, 0xec, 0x7c, 0xd4, 0x69, 0xcb, 0xbe,
        0x61, 0xd6, 0x30, 0xc0, 0x8f, 0x6a, 0xd0, 0x9a, 0x6d, 0xc0, 0x70, 0xa1, 0x0e, 0x20, 0xa0,
        0x00, 0x7f, 0xab, 0x12, 0x28, 0x3a, 0x0f, 0x1b, 0xe0, 0x5f, 0xd0, 0xaa, 0x56, 0xf2, 0x43,
        0x4b, 0x13, 0x06, 0x10, 0x18, 0xe2, 0x06, 0xbe, 0xe6, 0x10, 0x93, 0x5a, 0x06, 0x08, 0x80,
        0xfc, 0x3a, 0x95, 0x80, 0xf0, 0x5f, 0xa9, 0x16, 0x40, 0x20, 0x2d, 0x38, 0xe5, 0x45, 0x8d,
        0x50, 0x88, 0x3f, 0x80, 0x40, 0xbf, 0x76, 0x49, 0x34, 0x41, 0xe8, 0x04, 0x66, 0x80, 0x3d,
        0x3a, 0xc4, 0xf9, 0xb4, 0x90, 0xae, 0x26, 0x06, 0x10, 0x00, 0x62, 0x68, 0x5e, 0x55, 0xd7,
        0xbe, 0x21, 0x0e, 0x20, 0x80, 0xbd, 0x66, 0xf0, 0xed, 0xf0, 0x45, 0xb7, 0x0f, 0xf8, 0x67,
        0x4d, 0x90, 0x03, 0x35, 0x4a, 0xc3, 0xaa, 0x9c, 0x56, 0x80, 0xdf, 0x54, 0xed, 0xd8, 0x1a,
        0x5f, 0xe6, 0x7a, 0x1f, 0xe0, 0x2f, 0x5c, 0x35, 0x5d, 0x80, 0xf6, 0x49, 0xba, 0x06, 0xe8,
        0x83, 0x55, 0x9f, 0x67, 0xbc, 0x4b, 0xa2, 0xf2, 0x00, 0x02, 0x67, 0x9f, 0x1a, 0x9f, 0x70,
        0xab, 0x48, 0x8e, 0x80, 0xff, 0x34, 0xf5, 0xc3, 0xa4, 0x48, 0x1e, 0x67, 0xce, 0xc0, 0x00,
        0x00, 0x98, 0x95, 0xc5, 0x15, 0x40, 0x60, 0x60, 0x15, 0x7a, 0x2a, 0x77, 0xca, 0xc4, 0x33,
        0x80, 0xc0, 0x72, 0x68, 0xc9, 0xc7, 0xd6, 0x10, 0xcc, 0x60, 0x80, 0xff, 0x35, 0xe2, 0x64,
        0x31, 0x99, 0xe8, 0x7a, 0x1a, 0xa0, 0x7f, 0x69, 0x39, 0x77, 0xde, 0xe4, 0xba, 0x27, 0x03,
        0xf4, 0x79, 0x29, 0xfa, 0x40, 0x55, 0x79, 0x86, 0x35, 0xe0, 0x57, 0xe5, 0xb7, 0xa9, 0x79,
        0x43, 0x16, 0x21, 0x16, 0x60, 0x8f, 0xe4, 0xd5, 0x41, 0x8f, 0x8e, 0x37, 0xea, 0x01, 0xfe,
        0x53, 0x1a, 0x43, 0x44, 0x71, 0x9b, 0xe6, 0x7f, 0x80, 0xbd, 0xa2, 0x65, 0xf3, 0x6e, 0x28,
        0x67, 0xfd, 0x06, 0x10, 0x38, 0x91, 0x5f, 0xe3, 0x1b, 0x5f, 0x14, 0x85, 0x0c, 0x20, 0xd0,
        0x3b, 0x3b, 0x25, 0xc5, 0xce, 0x13, 0x1a, 0x09, 0x10, 0x38, 0x1f, 0xb3, 0xd9, 0x28, 0xd4,
        0xab, 0x00, 0xe4, 0x21, 0x59, 0x31, 0x83, 0x93, 0x03, 0xfc, 0x4e, 0x40, 0x14, 0x51, 0x3f,
        0x61, 0xfe, 0xc7, 0x00, 0x02, 0xdd, 0x3b, 0x4e, 0xac, 0xa6, 0x26, 0x46, 0x95, 0x01, 0x7e,
        0x3d, 0x1b, 0x08, 0x19, 0x18, 0x33, 0x86, 0x71, 0x00, 0x01, 0x46, 0x5e, 0xa0, 0x94, 0x31,
        0xd5, 0x7d, 0x60, 0xc0, 0x6f, 0x33, 0x5d, 0x1a, 0x6e, 0x80, 0x55, 0x1c, 0xac, 0x6c, 0xb8,
        0x73, 0x66, 0x40, 0xb8, 0xf9, 0x1f, 0x32, 0xca, 0x87, 0x64, 0xc5, 0xb2, 0xb8, 0x02, 0xec,
        0x09, 0x0e, 0x68, 0xf6, 0x98, 0xbf, 0x45, 0x32, 0x80, 0x40, 0x2f, 0x75, 0x93, 0xe9, 0x4c,
        0x8c, 0x3e, 0x73, 0x80, 0xde, 0xdb, 0x1a, 0x02, 0x83, 0x82, 0x93, 0x6c, 0x0f, 0x20, 0xe0,
        0xbf, 0xae, 0x55, 0x02, 0x76, 0xdd, 0x6c, 0x1c, 0xe0, 0x57, 0x1a, 0x91, 0x50, 0xa8, 0xd2,
        0x98, 0x4f, 0x02, 0x04, 0x3c, 0xe5, 0xd1, 0x06, 0xc6, 0x59, 0xbc, 0x25, 0x0b, 0xd0, 0xd7,
        0x04, 0xc9, 0x28, 0x23, 0x54, 0xdb, 0xf2, 0x01, 0x7a, 0xf4, 0x4b, 0x36, 0xf9, 0xab, 0x88,
        0xe7, 0x39, 0x40, 0xdc, 0x3f, 0xb9, 0x13, 0x3c, 0xb7, 0xa1, 0x1c, 0x40, 0x20, 0xf3, 0x1a,
        0x88, 0x63, 0x4d, 0x41, 0x01, 0x33, 0x40, 0x4f, 0x67, 0xc9, 0x36, 0x9d, 0x53, 0x2c, 0x82,
        0x03, 0xfa, 0xda, 0x88, 0x63, 0x93, 0xda, 0xc2, 0x3a, 0x9b, 0x87, 0x64, 0xc5, 0x21, 0x7b,
        0x7c, 0x48, 0x56, 0xe4, 0x21, 0x59, 0xb1, 0x21, 0x59, 0x91, 0x01,
    ];

    // Test data: JAM-encoded signed transaction
    const SIGNED_TX_JAM: &[u8] = &[
        0x05, 0xf8, 0xc9, 0x6d, 0xa5, 0xb8, 0xf8, 0x6d, 0x20, 0xa1, 0x01, 0xfa, 0xa7, 0x3d, 0x09,
        0x86, 0x45, 0x12, 0x4d, 0x30, 0x80, 0x40, 0xaa, 0xc8, 0x32, 0x61, 0x67, 0x20, 0x8e, 0x7f,
        0x00, 0x81, 0x42, 0xec, 0xb0, 0x93, 0x1b, 0x17, 0xa8, 0x4f, 0x80, 0x80, 0x14, 0x75, 0x95,
        0xcb, 0x3f, 0x6c, 0x46, 0x61, 0x55, 0x00, 0x01, 0x6d, 0xde, 0xed, 0x18, 0x71, 0xd3, 0xe4,
        0xcb, 0x00, 0xbf, 0x69, 0x5a, 0x1f, 0x6d, 0x87, 0x74, 0x80, 0x3e, 0xc0, 0xce, 0xf6, 0x02,
        0xf6, 0x7f, 0xdd, 0x33, 0x06, 0x03, 0xf4, 0x72, 0x37, 0xc9, 0x47, 0x2b, 0x52, 0xd0, 0x35,
        0xe0, 0xc7, 0x96, 0x08, 0x14, 0xe6, 0xb5, 0x16, 0x7d, 0x17, 0xa0, 0xbf, 0x6f, 0x89, 0x69,
        0x28, 0x82, 0xa2, 0xde, 0x03, 0x08, 0x00, 0xa1, 0x48, 0x42, 0xa3, 0x05, 0xd2, 0x4b, 0x06,
        0x10, 0x90, 0x1f, 0xe5, 0x9c, 0xd5, 0xff, 0x1e, 0x7d, 0x0c, 0xd0, 0x1b, 0x9a, 0x69, 0xd6,
        0x9c, 0xbf, 0xec, 0xf5, 0x00, 0x81, 0xee, 0x1a, 0x36, 0xc5, 0x1f, 0x0a, 0x36, 0x58, 0x2b,
        0x03, 0x0f, 0xef, 0xb6, 0x61, 0x28, 0x17, 0x57, 0x80, 0x9d, 0x8f, 0x3a, 0x6d, 0xd9, 0x37,
        0xcc, 0x1a, 0x06, 0xf8, 0x51, 0x0d, 0x5a, 0xb3, 0x0d, 0x18, 0x2e, 0xd4, 0x01, 0x04, 0x14,
        0xe0, 0x6f, 0x55, 0x02, 0x45, 0xe7, 0x61, 0x03, 0xfc, 0x0b, 0x5a, 0xd5, 0x4a, 0x7e, 0x68,
        0x69, 0xc2, 0x00, 0x02, 0x43, 0xdc, 0xc0, 0xd7, 0x1c, 0x62, 0x52, 0xcb, 0x00, 0x01, 0x90,
        0x5f, 0xa7, 0x12, 0x10, 0xfe, 0x2b, 0xd5, 0x02, 0x08, 0xa4, 0x05, 0xa7, 0xbc, 0xa8, 0x11,
        0x0a, 0xf1, 0x07, 0x10, 0xe8, 0xd7, 0x2e, 0x89, 0x26, 0x08, 0x9d, 0xc0, 0x0c, 0xb0, 0x47,
        0x87, 0x38, 0x9f, 0x16, 0xd2, 0xd5, 0xc4, 0x00, 0x02, 0x40, 0x0c, 0xcd, 0xab, 0xea, 0xda,
        0x37, 0xc4, 0x01, 0x04, 0xb0, 0xd7, 0x0c, 0xbe, 0x1d, 0xbe, 0xe8, 0xf6, 0x01, 0xff, 0xac,
        0x09, 0x72, 0xa0, 0x46, 0x69, 0x58, 0x95, 0xd3, 0x0a, 0xf0, 0x9b, 0xaa, 0x1d, 0x5b, 0xe3,
        0xcb, 0x5c, 0xef, 0x03, 0xfc, 0x85, 0xab, 0xa6, 0x0b, 0xd0, 0x3e, 0x49, 0xd7, 0x00, 0x7d,
        0xb0, 0xea, 0xf3, 0x8c, 0x77, 0x49, 0x54, 0x1e, 0x40, 0xe0, 0xec, 0x53, 0xe3, 0x13, 0x6e,
        0x15, 0xc9, 0x11, 0xf0, 0x9f, 0xa6, 0x7e, 0x98, 0x14, 0xc9, 0xe3, 0xcc, 0x19, 0x18, 0x00,
        0x00, 0xcb, 0x1a, 0x8e, 0x9d, 0x05, 0x08, 0x76, 0x69, 0x18, 0xd7, 0x03, 0x7e, 0x9f, 0xa8,
        0xee, 0x37, 0x40, 0xe0, 0x7a, 0xe4, 0x6c, 0x1a, 0xf0, 0x1d, 0x0f, 0xc7, 0xed, 0x01, 0x02,
        0x69, 0xf5, 0x53, 0xf8, 0x00, 0xc1, 0x60, 0xac, 0x3e, 0x67, 0x80, 0xe0, 0x0e, 0x7b, 0x79,
        0x1a, 0xd8, 0xba, 0x2d, 0x6e, 0x3b, 0x40, 0x30, 0xd9, 0xab, 0x86, 0x1c, 0x20, 0x78, 0x7f,
        0xc4, 0xd9, 0x0e, 0x10, 0xb0, 0x66, 0x61, 0xd8, 0x07, 0x08, 0x74, 0x16, 0xc3, 0x3e, 0x03,
        0x04, 0x14, 0x3b, 0xc0, 0xd6, 0x01, 0x82, 0xd4, 0x5b, 0x73, 0xd4, 0x80, 0x0e, 0x49, 0xbb,
        0xed, 0x02, 0xdd, 0xee, 0x93, 0xa0, 0x1c, 0x32, 0x15, 0x2b, 0x8b, 0x2b, 0x80, 0xc0, 0xc0,
        0x2a, 0xf4, 0x54, 0xee, 0x94, 0x89, 0x67, 0x00, 0x81, 0xe5, 0xd0, 0x92, 0x8f, 0xad, 0x21,
        0x98, 0xc1, 0x00, 0xff, 0x6b, 0xc4, 0xc9, 0x62, 0x32, 0xd1, 0xf5, 0x34, 0x40, 0xff, 0xd2,
        0x72, 0xee, 0xbc, 0xc9, 0x75, 0x4f, 0x06, 0xe8, 0xf3, 0x52, 0xf4, 0x81, 0xaa, 0xf2, 0x0c,
        0x6b, 0xc0, 0xaf, 0xca, 0x6f, 0x53, 0xf3, 0x86, 0x2c, 0x42, 0x2c, 0xc0, 0x1e, 0xc9, 0xab,
        0x83, 0x1e, 0x1d, 0x6f, 0xd4, 0x03, 0xfc, 0xa7, 0x34, 0x86, 0x88, 0xe2, 0x36, 0xcd, 0xff,
        0x00, 0x7b, 0x45, 0xcb, 0xe6, 0xdd, 0x50, 0xce, 0xfa, 0x0d, 0x20, 0x70, 0x22, 0xbf, 0xc6,
        0x37, 0xbe, 0x28, 0x0a, 0x19, 0x40, 0xa0, 0x77, 0x76, 0x4a, 0x8a, 0x9d, 0x27, 0x34, 0x12,
        0x20, 0x70, 0x3e, 0x66, 0xb3, 0x51, 0xa8, 0x57, 0x01, 0xc8, 0x43, 0xa6, 0x62, 0x06, 0x27,
        0x07, 0xf8, 0x9d, 0x80, 0x28, 0xa2, 0x7e, 0xc2, 0xfc, 0x8f, 0x01, 0x04, 0xba, 0x77, 0x9c,
        0x58, 0x4d, 0x4d, 0x8c, 0x2a, 0x03, 0xfc, 0x7a, 0x36, 0x10, 0x32, 0x30, 0x66, 0x0c, 0xe3,
        0x00, 0x02, 0x8c, 0xbc, 0x40, 0x29, 0x63, 0xaa, 0xfb, 0xc0, 0x80, 0xdf, 0x66, 0xba, 0x34,
        0xdc, 0x00, 0xab, 0x38, 0x58, 0xd9, 0x70, 0xe4, 0xcc, 0x80, 0x70, 0xf3, 0x3f, 0xac, 0x56,
        0x1c, 0x32, 0x15, 0xcb, 0xe2, 0x0a, 0xb0, 0x27, 0x38, 0xa0, 0xd9, 0x63, 0xfe, 0x16, 0xc9,
        0x00, 0x02, 0xbd, 0xd4, 0x4d, 0xa6, 0x33, 0x31, 0xfa, 0xcc, 0x01, 0x7a, 0x6f, 0x6b, 0x08,
        0x0c, 0x0a, 0x4e, 0xb2, 0x3d, 0x80, 0x80, 0xff, 0xba, 0x56, 0x09, 0xd8, 0x75, 0xb3, 0x71,
        0x80, 0x5f, 0x69, 0x44, 0x42, 0xa1, 0x4a, 0x63, 0x3e, 0x09, 0x10, 0xf0, 0x94, 0x47, 0x1b,
        0x18, 0x67, 0xf1, 0x96, 0x2c, 0x40, 0x5f, 0x13, 0x24, 0xa3, 0x8c, 0x50, 0x6d, 0xcb, 0x07,
        0xe8, 0xd1, 0x2f, 0xd9, 0xe4, 0xaf, 0x22, 0x9e, 0xe7, 0x00, 0x71, 0xff, 0xe4, 0x4e, 0xf0,
        0xdc, 0x86, 0x72, 0x00, 0x81, 0xcc, 0x6b, 0x20, 0x8e, 0x35, 0x05, 0x05, 0xcc, 0x00, 0x3d,
        0x9d, 0x25, 0xdb, 0x74, 0x4e, 0xb1, 0x08, 0x0e, 0xe8, 0x6b, 0x23, 0x8e, 0x4d, 0x6a, 0x0b,
        0xeb, 0x6c, 0x1e, 0x32, 0x15, 0x87, 0x35, 0x8a, 0x43, 0xa6, 0x22, 0x0f, 0x99, 0x8a, 0x0d,
        0x99, 0x8a, 0x0c,
    ];

    #[test]
    fn test_validate_signed_transaction() {
        const MNEMONIC: &str = "around squeeze nerve chronic trophy kiwi enroll identify depth bicycle radio gate critic child claim outer detect plug market visual stuff finish crime abuse";

        // Load unsigned transaction
        let mut slab: NounSlab = NounSlab::new();
        let noun = slab
            .cue_into(UNSIGNED_TX_JAM.into())
            .expect("Failed to decode unsigned transaction JAM");
        let unsigned_tx =
            RawTransaction::from_noun(&noun).expect("Failed to decode RawTransaction from noun");

        // Derive key from mnemonic
        let master_key =
            master_from_mnemonic(MNEMONIC, "").expect("Failed to derive master key from mnemonic");

        let private_key_bytes = master_key
            .private_key_bytes()
            .expect("Master key should have private key");

        // Convert to T8 format (same as in signer.rs test)
        let mut t8_values = [0u64; 8];
        for i in 0..8 {
            let offset = 32 - (i + 1) * 4;
            let limb_bytes = &private_key_bytes[offset..offset + 4];
            t8_values[i] =
                u32::from_be_bytes([limb_bytes[0], limb_bytes[1], limb_bytes[2], limb_bytes[3]])
                    as u64;
        }
        let secret_key = T8 { values: t8_values };

        // Sign the transaction
        let signed_tx = sign_tx(unsigned_tx, secret_key);

        // Validation should succeed
        let result = TransactionValidator::validate_transaction(&signed_tx);
        assert!(
            result.is_ok(),
            "Valid signed transaction should pass validation: {:?}",
            result.err()
        );

        println!("✓ Valid signed transaction passes all validation checks");
    }

    #[test]
    fn test_invalid_signature_modified_challenge() {
        use crate::collections::zmap::ZMap;
        use crate::transaction_types::{Chal, Input, Inputs, SchnorrSignature, Sig};

        // Load the pre-signed transaction
        let mut slab: NounSlab = NounSlab::new();
        let noun = slab
            .cue_into(SIGNED_TX_JAM.into())
            .expect("Failed to decode signed transaction JAM");
        let mut tx =
            RawTransaction::from_noun(&noun).expect("Failed to decode RawTransaction from noun");

        // Modify the challenge in the first signature by rebuilding the inputs map
        let mut new_inputs = ZMap::new();
        let mut modified = false;

        for (name, input) in tx.inputs.p.tap() {
            let mut new_input = input.clone();

            if !modified {
                if let Some(ref sig) = new_input.spend.signature {
                    // Rebuild signature map with modified challenge
                    let mut new_sig_map = ZMap::new();

                    for (pubkey, schnorr_sig) in sig.map.tap() {
                        if !modified {
                            // Modify this signature
                            let mut modified_sig = schnorr_sig.clone();
                            modified_sig.chal.values.values[0] ^= 1; // Flip one bit
                            new_sig_map.put(pubkey.clone(), modified_sig);
                            modified = true;
                        } else {
                            new_sig_map.put(pubkey.clone(), schnorr_sig.clone());
                        }
                    }

                    new_input.spend.signature =
                        Some(crate::transaction_types::Signature { map: new_sig_map });
                }
            }

            new_inputs.put(name.clone(), new_input);
        }

        tx.inputs = Inputs { p: new_inputs };

        assert!(modified, "Should have modified a signature");

        // Validation should fail with InvalidSignature
        let result = TransactionValidator::validate_transaction(&tx);
        assert!(result.is_err(), "Modified challenge should fail validation");

        match result.unwrap_err() {
            TransactionValidationError::InvalidSignature(_) => {
                println!("✓ Modified challenge correctly fails with InvalidSignature");
            }
            other => panic!("Expected InvalidSignature, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_signature_modified_sig() {
        use crate::collections::zmap::ZMap;
        use crate::transaction_types::Inputs;

        // Load the pre-signed transaction
        let mut slab: NounSlab = NounSlab::new();
        let noun = slab
            .cue_into(SIGNED_TX_JAM.into())
            .expect("Failed to decode signed transaction JAM");
        let mut tx =
            RawTransaction::from_noun(&noun).expect("Failed to decode RawTransaction from noun");

        // Modify the signature component by rebuilding the inputs map
        let mut new_inputs = ZMap::new();
        let mut modified = false;

        for (name, input) in tx.inputs.p.tap() {
            let mut new_input = input.clone();

            if !modified {
                if let Some(ref sig) = new_input.spend.signature {
                    // Rebuild signature map with modified sig component
                    let mut new_sig_map = ZMap::new();

                    for (pubkey, schnorr_sig) in sig.map.tap() {
                        if !modified {
                            // Modify this signature's sig component
                            let mut modified_sig = schnorr_sig.clone();
                            modified_sig.sig.values.values[0] ^= 1; // Flip one bit
                            new_sig_map.put(pubkey.clone(), modified_sig);
                            modified = true;
                        } else {
                            new_sig_map.put(pubkey.clone(), schnorr_sig.clone());
                        }
                    }

                    new_input.spend.signature =
                        Some(crate::transaction_types::Signature { map: new_sig_map });
                }
            }

            new_inputs.put(name.clone(), new_input);
        }

        tx.inputs = Inputs { p: new_inputs };

        assert!(modified, "Should have modified a signature");

        // Validation should fail with InvalidSignature
        let result = TransactionValidator::validate_transaction(&tx);
        assert!(result.is_err(), "Modified signature should fail validation");

        match result.unwrap_err() {
            TransactionValidationError::InvalidSignature(_) => {
                println!("✓ Modified signature correctly fails with InvalidSignature");
            }
            other => panic!("Expected InvalidSignature, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_tx_id() {
        // Load the pre-signed transaction
        let mut slab: NounSlab = NounSlab::new();
        let noun = slab
            .cue_into(SIGNED_TX_JAM.into())
            .expect("Failed to decode signed transaction JAM");
        let mut tx =
            RawTransaction::from_noun(&noun).expect("Failed to decode RawTransaction from noun");

        // Modify the transaction ID
        tx.id.values[0] ^= 1;

        // Validation should fail with ValidationError
        let result = TransactionValidator::validate_transaction(&tx);
        assert!(result.is_err(), "Modified TX ID should fail validation");

        match result.unwrap_err() {
            TransactionValidationError::ValidationError(_) => {
                println!("✓ Modified TX ID correctly fails with ValidationError");
            }
            other => panic!("Expected ValidationError, got {:?}", other),
        }
    }
}
