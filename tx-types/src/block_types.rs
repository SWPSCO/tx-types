use chrono::{DateTime, Utc, TimeZone};
use serde::{Deserialize, Serialize};
use crate::transaction_types::*;
use crate::transaction_types_v0::*;
use crate::transaction_types_v1::*;
use crate::collections::zset::ZSet;
use crate::collections::zmap::ZMap;
use crate::hashing::hashable::Hashable;
use crate::hashing::hasher::hash_hashable;
use num_bigint::BigUint;
use nockvm::noun::Noun;
use nockapp::noun::slab::NounSlab;
use noun_serde::{NounDecode, NounDecodeError, NounEncode};
use bytes::Bytes;

// ============================================================================
// Block Type Wrapper Types
// ============================================================================

/// Wrapper for coinbase rewards mapping locks to coin amounts
#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct Coinbase {
    pub map: ZMap<Lock, Coins>,
}

impl Coinbase {
    pub fn new() -> Self { Coinbase { map: ZMap::new() } }

    pub fn to_hashable(&self) -> Hashable {
        // Coinbase is a ZMap<Lock, Coins>
        // Delegate to ZMap's to_hashable which handles the tree structure
        self.map.to_hashable(
            |lock| lock.to_hashable(),
            |coins| coins.to_hashable(),
        )
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}

#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct CoinbaseV1 {
    pub map: ZMap<Hash, Coins>,
}

/// Wrapper for transaction ID set
#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct TransactionIds {
    pub set: ZSet<Hash>,
}

impl TransactionIds {
    pub fn new() -> Self {
        TransactionIds {
            set: ZSet::new(),
        }
    }

    pub fn to_hashable(&self) -> Hashable {
        // TransactionIds is a ZSet<Hash>
        // Delegate to ZSet's to_hashable which handles the tree structure
        self.set.to_hashable(|hash| Hashable::Hash(hash.clone()))
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}

/// Wrapper for epoch counter values
#[derive(Debug, Clone, Copy, PartialEq, Eq, NounDecode, NounEncode)]
pub struct EpochCounter {
    pub value: u64,
}

impl EpochCounter {
    pub fn new(value: u64) -> Self {
        EpochCounter { value }
    }

    pub fn to_hashable(&self) -> Hashable {
        Hashable::leaf_from_atom(&self.value.to_le_bytes())
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}

/// Wrapper for page message data
#[derive(Debug, Clone, NounDecode, NounEncode)]
pub struct PageMsg {
    pub values: Vec<u64>,
}

impl PageMsg {
    pub fn new() -> Self {
        PageMsg { values: Vec::new() }
    }

    pub fn to_hashable(&self) -> Hashable {
        let mut slab: NounSlab = NounSlab::new();
        use nockvm::noun::{Atom, Cell};

        // Build Hoon list structure: [a [b [c [d ... 0]]]]
        let mut list = Atom::new(&mut slab, 0).as_noun(); // Start with nil
        for &value in self.values.iter().rev() {
            let atom = Atom::new(&mut slab, value).as_noun();
            list = Cell::new(&mut slab, atom, list).as_noun();
        }

        Hashable::Leaf(slab.jam().to_vec())
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}

/// Full page structure with noun decoding
#[derive(Debug, Clone, NounDecode)]
pub struct PageV0 {
    pub digest: Hash,
    // everything below this is what is hashed for the digest: +.page
    pub pow: Pow,
    // everything below this is what is hashed for the block commitment: +>.page
    pub parent: Hash,
    pub tx_ids: TransactionIds,
    pub coinbase: Coinbase,
    pub timestamp: Timestamp,
    pub epoch_counter: EpochCounter,
    pub target: BigNum,
    pub accumulated_work: BigNum,
    pub height: PageNumber,
    pub msg: PageMsg,
}

/// Collection of pages
#[derive(Debug, Clone, NounDecode)]
pub struct Pages {
    pub pages: ZMap<Hash, Page>,
}

#[derive(Debug, Clone, NounDecode)]
pub struct PageV1 {
    pub version: u64,
    pub digest: Hash,
    // everything below this is what is hashed for the digest: +.page
    pub pow: Pow,
    // everything below this is what is hashed for the block commitment: +>.page
    pub parent: Hash,
    pub tx_ids: TransactionIds,
    pub coinbase: CoinbaseV1,
    pub timestamp: Timestamp,
    pub epoch_counter: EpochCounter,
    pub target: BigNum,
    pub accumulated_work: BigNum,
    pub height: PageNumber,
    pub msg: PageMsg,
}

#[derive(Debug, Clone)]
pub enum Page {
    V0(PageV0),
    V1(PageV1),
}

impl NounDecode for Page {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        if let Ok(v0) = PageV0::from_noun(noun) {
            return Ok(Page::V0(v0));
        }
        if let Ok(v1) = PageV1::from_noun(noun) {
            return Ok(Page::V1(v1));
        }
        Err(NounDecodeError::Custom("Page enum decode: unsupported format".to_string()))
    }
}

impl Page {
    pub fn coinbase_notes(&self) -> Vec<NNote> {
        match self {
            Page::V0(v) => v.coinbase_notes(),
            Page::V1(v) => v.coinbase_notes(),
        }
    }
}

/// Summarized page information
#[derive(NounDecode, Debug, Clone)]
pub struct PageSummary {
    pub digest: Hash,
    pub timestamp: Timestamp,
    pub epoch_counter: EpochCounter,
    pub target: BigNum,
    pub accumulated_work: BigNum,
    pub height: PageNumber,
    pub parent: Hash,
}

/// Proof-of-work stored as pre-jammed bytes
#[derive(Debug, Clone)]
pub struct Pow {
    pub p: Option<Bytes>,
}

impl NounDecode for Pow {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        /*
        let mut slab: NounSlab = NounSlab::new();
        slab.copy_into(*noun);
        let noun_bytes: Bytes = slab.jam();
        Ok(Pow { p: Some(noun_bytes) })
        */
        Ok(Pow { p: None })
    }
}

/// Big number representation for targets and work
#[derive(NounDecode, NounEncode, Debug, Clone)]
pub struct BigNum {
    pub header: String,
    pub body: Vec<u32>,
}

impl BigNum {
    pub fn to_decimal_string(&self) -> String {
        let le_u32 = self.body.clone();
        if le_u32.is_empty() { return "0".into(); }
        let bytes: Vec<u8> = le_u32.iter().flat_map(|w| w.to_le_bytes()).collect();
        BigUint::from_bytes_le(&bytes).to_str_radix(10)
    }

    pub fn to_hashable(&self) -> Hashable {
        // Jam the full BigNum noun structure (including header tag)
        // This matches how Hoon treats leaf+target.form where target.form is the full noun
        let mut slab: NounSlab = NounSlab::new();
        let noun = self.to_noun(&mut slab);
        slab.set_root(noun);
        Hashable::Leaf(slab.jam().to_vec())
    }
}

/// Timestamp with Urbit epoch conversion
#[derive(Debug, Clone)]
pub struct Timestamp {
    pub value: DateTime<Utc>,
}

impl Timestamp {
    /// Convert DateTime back to Urbit epoch format (u64)
    pub fn to_urbit_u64(&self) -> u64 {
        const BASE_URBIT_EPOCH: u64 = 0x8000000cce9e0d80u64;
        self.value.timestamp() as u64 + BASE_URBIT_EPOCH
    }

    pub fn to_hashable(&self) -> Hashable {
        // For hashing purposes, use Unix timestamp (seconds since epoch)
        // The Hoon page structure stores timestamps as Unix timestamps, not Urbit epoch format
        Hashable::leaf_from_atom(&(self.value.timestamp() as u64).to_le_bytes())
    }
}

impl NounDecode for Timestamp {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        let base_urbit_epoch = 0x8000000cce9e0d80u64;
        let raw_value = u64::from_noun(noun)?;
        let unix_timestamp = (raw_value - base_urbit_epoch) as i64;
        let datetime_utc = Utc.timestamp_opt(unix_timestamp, 0)
            .single()
            .ok_or_else(|| NounDecodeError::Custom("Invalid timestamp".to_string()))?;
        Ok(Timestamp { value: datetime_utc })
    }
}

// PageV0 coinbase functionality
impl PageV0 {
    /// Generate coinbase reward notes for this page
    ///
    /// Converts the coinbase Coinbase wrapper into actual NNote instances
    /// that can be spent by the recipients. Each coinbase recipient gets a
    /// separate note with appropriate timelock constraints.
    pub fn coinbase_notes(&self) -> Vec<NNote> {
        let mut notes: Vec<NNote> = Vec::new();

        // Get the locks and their coinbase rewards
        let locks: Vec<(Lock, Coins)> = self.coinbase.map.tap()
            .into_iter()
            .map(|(lock, coins)| (lock, coins))
            .collect();

        for (lock, assets) in locks {
            let timelock = Self::coinbase_timelock(self.height);

            let meta = NNoteHead {
                version: 0,
                origin_page: self.height,
                timelock: timelock.clone(),
            };

            let source = Source {
                p: self.parent.clone(),
                is_coinbase: true
            };

            let name = NName::new_default_v0(
                lock.clone(),
                source.clone(),
                timelock.clone()
            );

            let note = NNote::V0(NNoteV0 {
                meta,
                name,
                lock,
                source,
                assets
            });

            notes.push(note);
        }

        notes
    }

    /// Calculate the timelock for coinbase rewards at a given height
    pub fn coinbase_timelock(height: PageNumber) -> Timelock {
        const FIRST_MONTH_COINBASE_MIN: u64 = 4383;
        const COINBASE_TIMELOCK_MIN: u64 = 100;

        let val = if height.value < FIRST_MONTH_COINBASE_MIN {
            Some(PageNumber { value: FIRST_MONTH_COINBASE_MIN })
        } else {
            Some(PageNumber { value: COINBASE_TIMELOCK_MIN })
        };

        Timelock::new_unchecked(Some((
            TimelockRange { min: None, max: None },
            TimelockRange { min: val, max: None },
        )))
    }

    /// Convert block commitment (everything after PoW in +>.page) to hashable
    ///
    /// Matches Hoon structure hashable-block-commitment on line 478 of tx-engine.hoon
    /// :*  hash+parent.form
    ///     hash+(hash-hashable:tip5 (hashable-tx-ids tx-ids.form))
    ///     hash+(hash:coinbase-split coinbase.form)
    ///     leaf+timestamp.form
    ///     leaf+epoch-counter.form
    ///     leaf+target.form
    ///     leaf+accumulated-work.form
    ///     leaf+height.form
    ///     leaf+msg.form
    /// ==
    pub fn to_hashable_block_commitment(&self) -> Hashable {
        // Build the structure using nested cells for the Hoon tuple
        // :* a b c d e f g h i == creates [a [b [c [d [e [f [g [h i]]]]]]]]
        Hashable::cell(
            Hashable::Hash(self.parent.clone()),
            Hashable::cell(
                Hashable::Hash(self.tx_ids.to_hash()),
                Hashable::cell(
                    Hashable::Hash(self.coinbase.to_hash()),
                    Hashable::cell(
                        self.timestamp.to_hashable(),
                        Hashable::cell(
                            self.epoch_counter.to_hashable(),
                            Hashable::cell(
                                self.target.to_hashable(),
                                Hashable::cell(
                                    self.accumulated_work.to_hashable(),
                                    Hashable::cell(
                                        self.height.to_hashable(),
                                        self.msg.to_hashable()
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    }

  /// Hash the block commitment to produce the commitment hash
    ///
    /// Corresponds to ++ block-commitment on line 502 of tx-engine.hoon
    /// This is the hash of the block commitment structure (everything after PoW)
    pub fn hash_block_commitment(&self) -> Hash {
        hash_hashable(&self.to_hashable_block_commitment())
    }
}

impl PageV1 {
    pub fn coinbase_notes(&self) -> Vec<NNote> {
        let mut notes: Vec<NNote> = Vec::new();
        // =/  cb-split=coinbase-split  ~(coinbase get:^page page)
        let cb = self.coinbase.map.tap().into_iter();
        /*
        %+  turn  ~(tap z-in ~(key z-by +.cb))
        |=  h=hash:t
        (new:coinbase:t pag (~(put z-in *(z-set hash:t)) h))
        */
        let pkh_hashes: Vec<Hash> = cb.clone().map(|(hash, _)| hash).collect();
        for h in pkh_hashes.clone() {
            let vec_wrapped_hash = vec![h];
            // sum rewards for all provided hashes
            /*
            =/  reward=coins
            %+  roll  ~(tap z-in pkh-hashes)
            |=  [h=hash acc=coins]
            (add acc (~(got z-by +.cb-split) h))
            */

            let mut reward_sum: u64 = 0;

            for hash in vec_wrapped_hash {
                for (key, value) in cb.clone() {
                    if key == hash {
                        reward_sum += value.value;
                    }
                }
            }

            let assets = Coins { value: reward_sum };

            let parent_hash = self.parent.clone();
            let pkh_hashes_clone = pkh_hashes.clone();

            let m = pkh_hashes_clone.len() as u64;
            let mut pkh_set = ZSet::new();
            for hash in pkh_hashes_clone {
                pkh_set.put(hash)
            }
            let spend_condition = SpendCondition {
                p: vec![
                    LockPrimitive {
                        header: "pkh".to_string(),
                        body: LockPrimitiveBody::Pkh(Pkh {
                            m,
                            h: pkh_set,
                        }),
                    },
                    LockPrimitive {
                        header: "tim".to_string(),   
                        body: LockPrimitiveBody::Tim(Tim {
                            rel: TimelockRange { min: Some(PageNumber { value: 100 }), max: None },
                            abs: TimelockRange { min: None, max: None },
                        }),
                    }
                ]
            };

            notes.push(NNote::V1(NNoteV1 {
                version: 1,
                origin_page: self.height,
                name: NName::new_v1(),
                note_data: NoteData { map: ZMap::new() },
                assets,
            }));
        }
        /*
        %*  .  *nnote-1:v1
        version      %1
        origin-page  ~(height get:^page page)
        name         (make-name pkh-hashes ~(parent get:^page page))
        note-data    *(z-map @tas *)
        assets       reward
        ==

        */

        notes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collections::ZSet;

    #[test]
    fn test_hash_block_commitment_hoon_match() {
        use chrono::TimeZone;

        // Construct the exact pubkey from the Hoon output
        let pubkey = SchnorrPubkey {
            x: F6LT {
                values: [
                    6018047867890916910,
                    13629606561563978646,
                    16714202712061028570,
                    18221141046980165181,
                    17285182256924832167,
                    17916413408934731545,
                ],
            },
            y: F6LT {
                values: [
                    8949707339495969553,
                    16865412520827993473,
                    3894619518122606319,
                    7515667091311868396,
                    17328656136466179356,
                    15281684859516971703,
                ],
            },
            inf: false,
        };

        // Create the lock with m=1 and the pubkey
        let mut pubkeys = ZSet::new();
        pubkeys.put(pubkey);
        let lock = Lock { m: 1, pubkeys };

        // Create the coins (50,000,000)
        let coins = Coins { value: 50000000 };

        // Create the coinbase ZMap with one entry
        let mut coinbase_map = ZMap::new();
        coinbase_map.put(lock, coins);
        let coinbase = Coinbase { map: coinbase_map };

        // Create other page fields matching Hoon output
        let parent = Hash { values: [0x1, 0x2, 0x3, 0x4, 0x5] };
        let tx_ids = TransactionIds::new();

        // Timestamp: 1704067200 is Jan 1, 2024 00:00:00 UTC
        let timestamp = Timestamp {
            value: chrono::Utc.timestamp_opt(1704067200, 0).unwrap()
        };

        let epoch_counter = EpochCounter::new(42);

        // BigNum target - list starts with 4293656576, then the tail
        let target = BigNum {
            header: "bn".to_string(),
            body: vec![
                4293656576, 3932159, 4287102976, 11796479, 4281597952,
                11796479, 4287102976, 3932159, 4293656576, 262143
            ],
        };

        // Accumulated work - same as target in this test
        let accumulated_work = BigNum {
            header: "bn".to_string(),
            body: vec![
                4293656576, 3932159, 4287102976, 11796479, 4281597952,
                11796479, 4287102976, 3932159, 4293656576, 262143
            ],
        };

        let height = PageNumber { value: 100 };
        let msg = PageMsg::new();

        // Create the page with all fields
        let page = Page {
            digest: Hash { values: [0xa, 0xb, 0xc, 0xd, 0xe] },
            pow: Pow { p: bytes::Bytes::new() },
            parent,
            tx_ids,
            coinbase,
            timestamp,
            epoch_counter,
            target,
            accumulated_work,
            height,
            msg,
        };

        // Hash the block commitment
        let commitment_hash = page.hash_block_commitment();

        // Expected hash from Hoon output
        let expected_hash = Hash {
            values: [
                0xb3de55f5a625d03b,
                0x22a16ae38a170e39,
                0xeeaafb68d3749196,
                0x3dc939cfc714f6f6,
                0x58c1fef56a1656f0,
            ]
        };

        assert_eq!(
            commitment_hash, expected_hash,
            "Block commitment hash should match Hoon output.\nGot:      {:x?}\nExpected: {:x?}",
            commitment_hash.values, expected_hash.values
        );

        println!("✓ Block commitment hash matches Hoon output!");
        println!("  Hash: {:x?}", commitment_hash.values);
    }
}
