//! BIP39 English phrases, empty passphrase, Cheetah master path `m`.

pub use bip39::Mnemonic;
use tx_types::crypto::cheetah_nostd::{cheetah_pub_from_sk, master_from_seed};
use zeroize::{Zeroize, Zeroizing};

use super::{encode_pkh, pkh_from_public_key, Match, Prefix};

/// Derive the address Nockster displays when importing this phrase with an
/// empty passphrase. This uses the shared SLIP-10-over-Cheetah implementation.
pub fn derive_mnemonic(mnemonic: &Mnemonic) -> Match {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let (mut scalar, mut chain_code) = master_from_seed(seed.as_ref());
    let secret_key_be = Zeroizing::new(scalar);
    scalar.zeroize();
    chain_code.zeroize();
    let public_key = cheetah_pub_from_sk(*secret_key_be);
    Match {
        secret_key_be,
        pkh: pkh_from_public_key(&public_key),
        public_key,
    }
}

/// Private recovery material. The mnemonic and scalar erase themselves on drop.
pub struct MnemonicMatch {
    pub mnemonic: Mnemonic,
    pub key: Match,
}

pub struct MnemonicBatch {
    pub attempts: u64,
    pub matched: Option<MnemonicMatch>,
    pub exhausted: bool,
}

/// Allocation-free search through 256-bit entropy values. Each candidate runs
/// the complete BIP39 and Cheetah derivation; no scalar offsets are used.
pub struct MnemonicSearch {
    entropy: Zeroizing<[u8; 32]>,
    exhausted: bool,
}

impl MnemonicSearch {
    /// Start from 32 bytes supplied by a cryptographic random-number generator.
    pub fn new(entropy: Zeroizing<[u8; 32]>) -> Self {
        Self {
            entropy,
            exhausted: false,
        }
    }

    pub fn search_batch(&mut self, prefix: &Prefix, limit: u64) -> MnemonicBatch {
        let mut batch = MnemonicBatch {
            attempts: 0,
            matched: None,
            exhausted: self.exhausted,
        };
        while batch.attempts < limit && !self.exhausted {
            let mnemonic = Mnemonic::from_entropy(self.entropy.as_ref()).expect("256-bit entropy");
            let key = derive_mnemonic(&mnemonic);
            batch.attempts += 1;
            self.advance();
            if prefix.matches(&encode_pkh(key.pkh)) {
                batch.matched = Some(MnemonicMatch { mnemonic, key });
                break;
            }
        }
        batch.exhausted = self.exhausted;
        batch
    }

    fn advance(&mut self) {
        for byte in self.entropy.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                return;
            }
        }
        self.exhausted = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nockchain_wallet_master_address_vector() {
        // Public throwaway vector in nockster-core/src/extended_key.rs.
        let phrase = "wedding chef bread absurd leader surge auction access document fiber chunk hurt earn rain swarm cotton leisure ozone drill switch cry jungle soda oxygen";
        let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, phrase).unwrap();
        let key = derive_mnemonic(&mnemonic);
        assert_eq!(
            encode_pkh(key.pkh).as_str(),
            "9QnMES6nZnbyqPKfTysvisj1UqvxjSkL4XQaAsMUafGVw2m7rrUHzsW"
        );
    }

    #[test]
    fn batches_resume_and_phrase_restores_the_winner() {
        let mut entropy = [0x42; 32];
        entropy[31] += 2;
        let target = Mnemonic::from_entropy(&entropy).unwrap();
        let expected = derive_mnemonic(&target);
        let prefix = Prefix::new(encode_pkh(expected.pkh).as_str()).unwrap();
        let mut search = MnemonicSearch::new(Zeroizing::new([0x42; 32]));
        assert_eq!(search.search_batch(&prefix, 0).attempts, 0);
        assert!(search.search_batch(&prefix, 2).matched.is_none());
        let batch = search.search_batch(&prefix, 3);
        assert_eq!(batch.attempts, 1);
        let found = batch.matched.unwrap();
        assert_eq!(found.mnemonic, target);
        assert_eq!(
            *derive_mnemonic(&found.mnemonic).secret_key_be,
            *expected.secret_key_be
        );
        assert_eq!(found.key.pkh, expected.pkh);
    }

    #[test]
    fn entropy_exhaustion_does_not_wrap() {
        let mut search = MnemonicSearch::new(Zeroizing::new([255; 32]));
        let prefix = Prefix::new("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap();
        let batch = search.search_batch(&prefix, 2);
        assert_eq!(batch.attempts, 1);
        assert!(batch.exhausted);
        assert_eq!(search.search_batch(&prefix, 1).attempts, 0);
    }
}
