use noun_serde::{NounDecode, NounDecodeError, NounEncode};
use crate::{ZSet, ZMap};

use crate::hashing::hashable::Hashable;
use crate::hashing::hasher::hash_hashable;
use crate::transaction_types::*;

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct NNoteV0 {
    pub meta: NNoteHead,
    pub name: NName,
    pub lock: Lock,
    pub source: Source,
    pub assets: Coins,
}

impl NNoteV0 {
    /// Convert the NNote to a hashable structure and hash it
    pub fn to_hash(&self) -> Hash {
        // Convert to hashable structure
        let hashable = self.to_hashable();
        
        // Hash the structure
        hash_hashable(&hashable)
    }
    
    pub fn to_hashable(&self) -> Hashable {
        // NNote hashable matches Hoon implementation in tx-engine.hoon lines 1462-1472
        // Structure: [[version origin-page timelock-hash] [name-hash lock-hash source-hash assets]]
        Hashable::cell(
            // First part: [version origin-page timelock-hash]
            Hashable::triple(
                Hashable::leaf_from_atom(&self.meta.version.to_le_bytes()),
                self.meta.origin_page.to_hashable(),
                Hashable::Hash(hash_hashable(&self.meta.timelock.to_hashable())),
            ),
            // Second part: [name-hash lock-hash source-hash assets]
            // Note: In Hoon this is a quad (4-element structure)
            Hashable::cell(
                Hashable::Hash(hash_hashable(&self.name.to_hashable())),
                Hashable::cell(
                    Hashable::Hash(hash_hashable(&self.lock.to_hashable())),
                    Hashable::cell(
                        Hashable::Hash(hash_hashable(&self.source.to_hashable())),
                        self.assets.to_hashable(),
                    ),
                ),
            ),
        )
    }
}

// Note structure
#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct NNoteHead {
    pub version: u64,
    pub origin_page: PageNumber,
    pub timelock: Timelock,
}

// Seed structure
#[derive(Debug, Clone, NounEncode, NounDecode, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SeedV0 {
    pub output_source: Option<Source>,
    pub recipient: Lock,
    pub timelock_intent: TimelockIntent,
    pub gift: Coins,
    pub parent_hash: Hash,
}

impl SeedV0 {
    pub fn to_hashable(&self) -> Hashable {
        // Seed hashable from Hoon (excluding output-source):
        // :^    (hashable:lock recipient.sed)
        //     (hashable:timelock-intent timelock-intent.sed)
        //   leaf+gift.sed
        // hash+parent-hash.sed
        
        // This is a 4-element structure (quad)
        // Using nested cells to represent it
        Hashable::cell(
            self.recipient.to_hashable(),
            Hashable::cell(
                to_hashable_timelock_intent(&self.timelock_intent),
                Hashable::cell(
                    self.gift.to_hashable(),
                    Hashable::Hash(self.parent_hash.clone())
                )
            )
        )
    }
    
    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }

    pub fn to_sig_hashable(&self) -> Hashable {
        // Seed sig-hashable from Hoon (including output-source):
        // :*  (hashable-unit:source output-source.sed)
        //     (hashable:lock recipient.sed)
        //     (hashable:timelock-intent timelock-intent.sed)
        //     leaf+gift.sed
        //     hash+parent-hash.sed
        // ==

        // This is a 5-element structure represented as nested cells
        // First element is the hashable-unit for output-source
        let output_source_hashable = match &self.output_source {
            None => Hashable::null(),  // ?~  s  leaf+~
            Some(source) => {
                // :-  leaf+~
                // (hashable u.s)
                Hashable::cell(
                    Hashable::null(),
                    source.to_hashable()
                )
            }
        };

        // Create the 5-tuple structure
        Hashable::cell(
            output_source_hashable,
            Hashable::cell(
                self.recipient.to_hashable(),
                Hashable::cell(
                    to_hashable_timelock_intent(&self.timelock_intent),
                    Hashable::cell(
                        self.gift.to_hashable(),
                        Hashable::Hash(self.parent_hash.clone())
                    )
                )
            )
        )
    }
}

// Seeds structure
#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct SeedsV0 {
    pub set: ZSet<SeedV0>,
}

impl SeedsV0 {
    pub fn to_hashable(&self) -> Hashable {
        // Seeds is a z-set of Seed
        // From Hoon:
        // ?~  form  leaf+form
        // :+  (hashable:seed n.form)
        //   $(form l.form)
        // $(form r.form)

        // Use ZSet's to_hashable method which properly traverses the tree
        self.set.to_hashable(|seed| seed.to_hashable())
    }

    pub fn to_sig_hashable(&self) -> Hashable {
        // Seeds sig-hashable is a z-set of Seed using sig-hashable
        // From Hoon:
        // ++  sig-hashable
        //   |=  =form
        //   ^-  hashable:tip5
        //   ?~  form  leaf+form
        //   :+  (sig-hashable:seed n.form)
        //     $(form l.form)
        //   $(form r.form)

        // Use ZSet's to_hashable method with sig_hashable for each seed
        self.set.to_hashable(|seed| seed.to_sig_hashable())
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}

// ===================== V0 signature/spend/input/raw-tx wrappers =====================

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct Signature {
    pub map: ZMap<SchnorrPubkey, SchnorrSignature>,
}

impl Signature {
    pub fn to_hashable(&self) -> Hashable {
        // Signature is just a ZMap, so delegate to its to_hashable method
        self.map.to_hashable(
            |pubkey| pubkey.to_hashable(),
            |sig| sig.to_hashable(),
        )
    }

    pub fn to_hash(&self) -> Hash {
        match self.to_hashable() {
            Hashable::Hash(h) => h,
            _ => hash_hashable(&self.to_hashable()),
        }
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct SpendV0 {
    pub signature: Option<Signature>,
    pub seeds: SeedsV0,
    pub fee: Coins,
}

impl SpendV0 {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::triple(
            match &self.signature {
                None => Hashable::null(),
                Some(sig) => Hashable::cell(Hashable::null(), sig.to_hashable()),
            },
            self.seeds.to_hashable(),
            self.fee.to_hashable(),
        )
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }

    pub fn sig_hash(&self) -> Hash {
        let sig_hashable = Hashable::cell(self.seeds.to_sig_hashable(), self.fee.to_hashable());
        hash_hashable(&sig_hashable)
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct InputV0 {
    pub note: NNoteV0,
    pub spend: SpendV0,
}

impl InputV0 {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::cell(self.note.to_hashable(), self.spend.to_hashable())
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }

    pub fn calculate_timelock_range(&self) -> (Option<u64>, Option<u64>) {
        let origin_page = self.note.meta.origin_page.value;
        let timelock_intent = &self.note.meta.timelock.intent;
        if let Some((absolute, relative)) = timelock_intent {
            Self::calculate_input_timelock_range(
                origin_page,
                &Some(absolute.clone()),
                &Some(relative.clone()),
            )
        } else {
            (None, None)
        }
    }

    fn calculate_input_timelock_range(
        origin_page: u64,
        absolute: &Option<TimelockRange>,
        relative: &Option<TimelockRange>,
    ) -> (Option<u64>, Option<u64>) {
        let mut min = None;
        let mut max = None;

        if let Some(abs) = absolute {
            min = abs.min.as_ref().map(|p| p.value);
            max = abs.max.as_ref().map(|p| p.value);
        }

        if let Some(rel) = relative {
            let rel_min = rel.min.as_ref().map(|p| origin_page + p.value);
            let rel_max = rel.max.as_ref().map(|p| origin_page + p.value);

            min = match (min, rel_min) {
                (None, rm) => rm,
                (am, None) => am,
                (Some(am), Some(rm)) => Some(am.max(rm)),
            };

            max = match (max, rel_max) {
                (None, rm) => rm,
                (am, None) => am,
                (Some(am), Some(rm)) => Some(am.min(rm)),
            };
        }

        (min, max)
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct InputsV0 {
    pub p: ZMap<NName, InputV0>,
}

impl InputsV0 {
    pub fn to_hashable(&self) -> Hashable {
        self.p.to_hashable(|name| name.to_hashable(), |input| input.to_hashable())
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct OutputV0 {
    pub note: NNoteV0,
    pub seeds: SeedsV0,
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct OutputsV0 {
    pub map: ZMap<Lock, OutputV0>,
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct RawTransactionV0 {
    pub id: Hash,
    pub inputs: InputsV0,
    pub timelock_range: TimelockRange,
    pub total_fees: Coins,
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct TxV0 {
    pub version: u64,
    pub raw_tx: RawTransactionV0,
    pub total_size: u64,
    pub outputs: OutputsV0,
}