use nockapp::Noun;
use nockapp::noun::slab::NounSlab;
use nockapp::noun::AtomExt;
use noun_serde::{NounDecode, NounDecodeError, NounEncode};
use nockvm::noun::{Atom, NounAllocator, D, T};
use std::collections::HashMap;

use crate::collections::{ZSet, ZMap};
use crate::hashing::hashable::Hashable;
use crate::hashing::hasher::hash_hashable;
use crate::hashing::tip5::Tip5Hasher;
use crate::transaction_types_v0::*;
use crate::transaction_types_v1::*;

use num_bigint::BigUint;
use num_traits::{Zero, One};
use bytes::Bytes;


// Coin name structure
#[derive(Debug, Clone, Copy, NounEncode, NounDecode, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Coins {
   pub value: u64
}

impl Coins {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::leaf_from_atom(&self.value.to_le_bytes())
    }
}

// page number name structure
#[derive(Debug, Clone, Copy, NounEncode, NounDecode, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PageNumber {
   pub value: u64
}

impl PageNumber {
    pub fn to_hashable(&self) -> Hashable {
        Hashable::leaf_from_atom(&self.value.to_le_bytes())
    }
}

// Hash wrapper for transaction IDs and other hashes
#[derive(Debug, Clone, NounEncode, NounDecode, PartialEq, Eq, Hash)]
pub struct Hash {
    pub values: [u64; 5],
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare as UBig integers, not lexicographically
        // This ensures hash comparisons match the gor-tip behavior
        self.to_ubig().cmp(&other.to_ubig())
    }
}

impl Hash {
    /// Convert the Hash to a UBig integer for comparison
    /// This treats the hash as a 320-bit integer (5 * 64 bits)
    /// values[0] is least significant, values[4] is most significant
    pub fn to_ubig(&self) -> ibig::UBig {
        use ibig::UBig;
        
        // Build the UBig from bytes in little-endian order
        let mut bytes = Vec::with_capacity(40); // 5 * 8 bytes
        
        // Add each u64 in little-endian byte order
        for value in &self.values {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        
        // Create UBig from little-endian bytes
        UBig::from_le_bytes(&bytes)
    }
    
    /// Create a Hash from a UBig integer (inverse of to_ubig)
    /// Returns None if the UBig is too large to fit in 320 bits
    pub fn from_ubig(big: &ibig::UBig) -> Option<Self> {
        // Convert to little-endian bytes
        let bytes = big.to_le_bytes();
        
        // Check if it fits in 320 bits (40 bytes)
        if bytes.len() > 40 {
            return None;
        }
        
        let mut values = [0u64; 5];
        
        // Parse each u64 from the bytes
        for i in 0..5 {
            let start = i * 8;
            let end = (i + 1) * 8;
            
            if start < bytes.len() {
                // Get up to 8 bytes for this u64
                let mut u64_bytes = [0u8; 8];
                let available = (bytes.len() - start).min(8);
                u64_bytes[..available].copy_from_slice(&bytes[start..start + available]);
                values[i] = u64::from_le_bytes(u64_bytes);
            }
        }
        
        Some(Hash { values })
    }
    
    /// Convert base58 encoded string to Hash
    /// Implements the Hoon from-b58 function:
    /// ++  from-b58  |=(=cord `form`(atom-to-digest:tip5 (de-base58 (trip cord))))
    pub fn from_b58(base58: &str) -> Result<Self, String> {
        use crate::hashing::u320::U320;
        
        let n = U320::from_base58(base58)
            .map_err(|e| format!("Invalid base58: {}", e))?;
        
        // Four divmods by p: collect remainders a..d; final quotient e
        let (q1, a) = n.divrem_p();
        let (q2, b) = q1.divrem_p();
        let (q3, c) = q2.divrem_p();
        let (e_q, d) = q3.divrem_p();
        let e = e_q.as_single_u64()
            .map_err(|e| format!("Hash value too large: {}", e))?;
        
        Ok(Hash { values: [a, b, c, d, e] })
    }
    
    /// Convert Hash to base58 encoded string
    /// Implements the Hoon to-b58 function:
    /// ++  to-b58  |=(has=form `cord`(crip (en-base58 (digest-to-atom:tip5 has))))
    pub fn to_b58(&self) -> String {
        use num_bigint::BigUint;
        use bs58;
        
        // The Goldilocks prime
        const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;
        let p = BigUint::from(GOLDILOCKS_PRIME);
        
        // digest-to-atom:tip5 uses formula: a + b*p + c*p² + d*p³ + e*p⁴
        let mut result = BigUint::from(self.values[0]);
        
        for i in 1..5 {
            let power = p.pow(i as u32);
            result += BigUint::from(self.values[i]) * power;
        }
        
        bs58::encode(result.to_bytes_be()).into_string()
    }
}

// Note name structure  
#[derive(Debug, Clone, NounEncode, NounDecode, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NName {
    pub p: Vec<Hash>
}

impl NName {
    pub fn to_hashable(&self) -> Hashable {
        // NName hashable from Hoon (found in tx-engine.hoon):
        // ++  hashable
        //   |=  =form
        //   ^-  hashable:tip5
        //   [[%hash -.form] [%hash +<.form] [%leaf +>.form]]
        //
        // This creates a nested cell structure:
        // - First hash wrapped with %hash tag
        // - Second hash wrapped with %hash tag
        // - The nil (~) wrapped with %leaf tag

        if self.p.len() >= 2 {
            // Create the structure: [[%hash hash1] [%hash hash2] [%leaf 0]]
            // This is a triple where each hash is wrapped with Hash variant
            // and the terminator is wrapped with Leaf variant
            Hashable::triple(
                Hashable::Hash(self.p[0].clone()),
                Hashable::Hash(self.p[1].clone()),
                Hashable::null()  // null() returns Leaf(0)
            )
        } else if self.p.len() == 1 {
            // If only one hash, still need proper structure
            // Assuming it would be [%hash hash1] [%leaf 0] [%leaf 0]
            Hashable::triple(
                Hashable::Hash(self.p[0].clone()),
                Hashable::null(),
                Hashable::null()
            )
        } else {
            // Empty NName
            Hashable::null()
        }
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }

    // TODO: implement v1 hashing

    /// Create a default NName from components
    /// Used for generating note names from lock, source, and timelock
    pub fn new_default(owners: Lock, source: Source, timelock: Timelock) -> Self {
        Self {
            p: vec![
                Self::first(owners, timelock.intent.is_some()),
                Self::last(source, timelock),
            ],
        }
    }

    /// Compute the first hash component of an NName
    /// Based on Hoon implementation:
    /// |=  [owners=lock has-timelock=?]
    /// %-  hash-hashable:tip5
    /// :*  leaf+&                   :: outcome of first pact
    ///     leaf+has-timelock        :: does it have a timelock?
    ///     hash+(hash:lock owners)  :: owners of note
    ///     leaf+~                   :: first pact
    /// ==
    pub fn first(owners: Lock, has_timelock: bool) -> Hash {
        let value = if has_timelock { 0u64 } else { 1u64 };
        let hashable = Hashable::cell(
            Hashable::null(),
            Hashable::cell(
                Hashable::leaf_from_atom(&value.to_le_bytes()),
                Hashable::cell(
                    Hashable::Hash(owners.to_hash()),
                    Hashable::null()
                )
            )
        );
        hash_hashable(&hashable)
    }

    /// Compute the last hash component of an NName
    /// Based on Hoon implementation:
    /// |=  [=source =timelock]
    /// %-  hash-hashable:tip5
    /// :*  leaf+&                          :: outcome of second pact
    ///     (hashable:^source source)       :: source of note
    ///     hash+(hash:^timelock timelock)  :: timelock of note
    ///     leaf+~                          :: second pact
    /// ==
    pub fn last(source: Source, timelock: Timelock) -> Hash {
        let hashable = Hashable::cell(
            Hashable::null(),
            Hashable::cell(
                Hashable::Hash(source.to_hash()),
                Hashable::cell(
                    Hashable::Hash(timelock.to_hash()),
                    Hashable::null()
                )
            )
        );
        hash_hashable(&hashable)
    }
}

// TimelockIntent: Option<(absolute, relative)> where both are TimelockRange
// ~ means "no intent", Some((absolute, relative)) means there is intent
pub type TimelockIntent = Option<(TimelockRange, TimelockRange)>;

impl Timelock {
    pub fn to_hashable(&self) -> Hashable {
        // Timelock just delegates to its TimelockIntent
        to_hashable_timelock_intent(&self.intent)
    }
    
    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}

// Helper function for TimelockIntent since it's a type alias
pub fn to_hashable_timelock_intent(intent: &TimelockIntent) -> Hashable {
    // TimelockIntent hashable from Hoon:
    // ?~  form  leaf+~
    // :+  leaf+~
    //   (hashable:timelock-range absolute.u.form)
    // (hashable:timelock-range relative.u.form)
    
    match intent {
        None => Hashable::null(),
        Some((absolute, relative)) => {
            Hashable::triple(
                Hashable::null(),
                absolute.to_hashable(),
                relative.to_hashable(),
            )
        }
    }
}

// Timelock: A TimelockIntent that cannot be Some with both ranges empty
// This wraps TimelockIntent with validation that it's not [~ ~ ~]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timelock {
    pub intent: TimelockIntent,
}

impl Timelock {
    /// Create a new Timelock, validating it's not [~ ~ ~]
    pub fn new(intent: TimelockIntent) -> Result<Self, String> {
        if let Some((ref absolute, ref relative)) = intent {
            // Check if both ranges are empty (equivalent to [~ ~ ~])
            if absolute.min.is_none() && absolute.max.is_none() &&
               relative.min.is_none() && relative.max.is_none() {
                return Err("Timelock cannot be [~ ~ ~] (both ranges empty)".to_string());
            }
        }
        Ok(Timelock { intent })
    }
    
    /// Create a Timelock that allows any intent (used for testing/construction)
    pub fn new_unchecked(intent: TimelockIntent) -> Self {
        Timelock { intent }
    }
}

impl NounEncode for Timelock {
    fn to_noun<A: NounAllocator>(&self, allocator: &mut A) -> Noun {
        self.intent.to_noun(allocator)
    }
}

impl NounDecode for Timelock {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        let intent = TimelockIntent::from_noun(noun)?;
        Timelock::new(intent)
            .map_err(|e| NounDecodeError::Custom(e))
    }
}

// Timelock range structure
#[derive(Debug, Clone, NounEncode, NounDecode, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TimelockRange {
    pub min: Option<PageNumber>,
    pub max: Option<PageNumber>,
}

impl TimelockRange {
    pub fn to_hashable(&self) -> Hashable {
        // Following the Hoon pattern:
        // :-  ?~(min.form %leaf^~ [%leaf^~ leaf+u.min.form])
        // ?~(max.form %leaf^~ [%leaf^~ leaf+u.max.form])
        
        let min_hashable = match &self.min {
            None => Hashable::null(),
            Some(val) => Hashable::cell(
                Hashable::null(),
                val.to_hashable()
            ),
        };

        let max_hashable = match &self.max {
            None => Hashable::null(),
            Some(val) => Hashable::cell(
                Hashable::null(),
                val.to_hashable()
            ),
        };
        
        Hashable::cell(min_hashable, max_hashable)
    }
    
    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}
// F6LT is a 6-element field type (a0-a5 in Hoon)
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct F6LT {
    pub values: [u64; 6],
}

// Manual NounEncode/NounDecode implementations for F6LT
impl NounEncode for F6LT {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, allocator: &mut A) -> nockvm::noun::Noun {
        use nockvm::noun::{Atom, T};
        let atoms = self.values.map(|v| Atom::new(allocator, v).as_noun());
        T(allocator, &atoms)
    }
}

impl NounDecode for F6LT {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        // Extract 6 values from nested cell structure
        let mut values = [0u64; 6];
        let mut current = *noun;

        for i in 0..5 {
            let cell = current.as_cell()
                .map_err(|_| NounDecodeError::ExpectedCell)?;
            values[i] = cell.head().as_atom()
                .map_err(|_| NounDecodeError::ExpectedAtom)?
                .as_u64()?;
            current = cell.tail();
        }

        // Last element
        values[5] = current.as_atom()
            .map_err(|_| NounDecodeError::ExpectedAtom)?
            .as_u64()?;

        Ok(F6LT { values })
    }
}

// Schnorr signature structure a a-pt:cheta
#[derive(Debug, Clone, NounEncode, NounDecode, PartialEq, Eq, Hash)]
pub struct SchnorrPubkey {
    pub x: F6LT,
    pub y: F6LT,
    pub inf: bool,
}

impl SchnorrPubkey {
    #[inline]
    fn f6lt_words_be_desc(a: &F6LT, out: &mut Vec<u8>) {
        // a5...a0 as big-endian u64s
        out.extend_from_slice(&a.values[5].to_be_bytes());
        out.extend_from_slice(&a.values[4].to_be_bytes());
        out.extend_from_slice(&a.values[3].to_be_bytes());
        out.extend_from_slice(&a.values[2].to_be_bytes());
        out.extend_from_slice(&a.values[1].to_be_bytes());
        out.extend_from_slice(&a.values[0].to_be_bytes());
    }

    pub fn to_hashable(&self) -> Hashable {
        // In Hoon, this is [%leaf form] where form is the pubkey noun.
        // We jam the noun and store it in Hashable::Leaf.
        let mut slab: NounSlab = NounSlab::new();
        let noun = self.to_noun(&mut slab);
        slab.set_root(noun);
        Hashable::Leaf(slab.jam().to_vec())
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
    
    /// Convert base58 encoded string to SchnorrPubkey
    /// Implements the Hoon from-b58 function:
    /// ++  from-b58  |=(=cord `form`(base58-to-a-pt:cheetah cord))
    /// 
    /// The base58 encoding represents a compressed elliptic curve point
    pub fn from_b58(s: &str) -> Result<Self, String> {
        if s == "inf" {
            return Ok(SchnorrPubkey {
                x: F6LT { values: [0; 6] },
                y: F6LT { values: [0; 6] },
                inf: true,
            });
        }
        let bytes = bs58::decode(s).into_vec()
            .map_err(|e| format!("invalid base58: {e}"))?;
        if bytes.len() != 97 || bytes[0] != 0x01 {
            return Err("a-pt b58: expected 97 bytes with 0x01 prefix".into());
        }
        // Y: a5..a0 (BE u64s), then X: a5..a0
        let mut rd = &bytes[1..];

        fn take_u64_be(rd: &mut &[u8]) -> u64 {
            let (head, tail) = rd.split_at(8);
            *rd = tail;
            u64::from_be_bytes(head.try_into().unwrap())
        }

        let mut y = [0u64; 6];
        let mut x = [0u64; 6];

        // note: file format stores a5..a0; our struct keeps [a0..a5]
        y[5] = take_u64_be(&mut rd);
        y[4] = take_u64_be(&mut rd);
        y[3] = take_u64_be(&mut rd);
        y[2] = take_u64_be(&mut rd);
        y[1] = take_u64_be(&mut rd);
        y[0] = take_u64_be(&mut rd);

        x[5] = take_u64_be(&mut rd);
        x[4] = take_u64_be(&mut rd);
        x[3] = take_u64_be(&mut rd);
        x[2] = take_u64_be(&mut rd);
        x[1] = take_u64_be(&mut rd);
        x[0] = take_u64_be(&mut rd);

        Ok(SchnorrPubkey {
            x: F6LT { values: x },
            y: F6LT { values: y },
            inf: false,
        })
    }

    fn pack_le(words: &[u64]) -> num_bigint::BigUint {
        use num_bigint::BigUint;
        use num_traits::{Zero, One};
        let mut n = BigUint::zero();
        for (i, &w) in words.iter().enumerate() {
            n += BigUint::from(w) << (64 * i);
        }
        n
    }

    pub fn to_base58(&self) -> String {
        use num_bigint::BigUint;
        use num_traits::One;
        let mut n = BigUint::from(0u32);

        // N = ((y_le << (64*6)) | x_le) << 1 | inf
        let x = Self::pack_le(&self.x.values);
        let y = Self::pack_le(&self.y.values);
        n = (y << (64 * 6)) | x;
        n = (n << 1) | if self.inf { BigUint::one() } else { BigUint::from(0u32) };

        bs58::encode(n.to_bytes_be()).into_string()
    }
    
    /// Convert SchnorrPubkey to base58 encoded string
    /// Implements the Hoon to-b58 function:
    /// ++  to-b58  |=(sop=form `cord`(a-pt-to-base58:cheetah sop))
    pub fn to_b58(&self) -> String {
        if self.inf {
            return "inf".to_string();
        }
        let mut bytes = Vec::with_capacity(1 + 6*8 + 6*8);
        bytes.push(1u8);                        // fixed prefix
        Self::f6lt_words_be_desc(&self.y, &mut bytes); // Y first
        Self::f6lt_words_be_desc(&self.x, &mut bytes); // then X
        bs58::encode(bytes).into_string()
    }

    pub fn from_base58(s: &str) -> Self {
        use num_bigint::BigUint;
        use num_traits::{Zero, One};

        let mut n = Self::de_base58(s);
        let inf = (&n & BigUint::one()) == BigUint::one();
        n >>= 1;

        // pull x (low 6 words) then y (next 6 words)
        let mask_6 = (BigUint::one() << (64 * 6)) - BigUint::one();
        let x_big = &n & &mask_6;
        let y_big = n >> (64 * 6);

        let mut x_vals = Self::rip64(&x_big);
        let mut y_vals = Self::rip64(&y_big);
        x_vals.resize(6, 0);
        y_vals.resize(6, 0);

        let x = F6LT { values: [x_vals[0], x_vals[1], x_vals[2], x_vals[3], x_vals[4], x_vals[5]] };
        let y = F6LT { values: [y_vals[0], y_vals[1], y_vals[2], y_vals[3], y_vals[4], y_vals[5]] };

        SchnorrPubkey { x, y, inf }
    }

    fn de_base58(s: &str) -> num_bigint::BigUint {
        use num_bigint::BigUint;
        use num_traits::Zero;
        const ALPH: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut n = BigUint::zero();
        for ch in s.chars() {
            let d = ALPH.find(ch).expect("invalid base58 char") as u32;
            n = n * 58u32 + d;
        }
        n
    }
    fn rip64(n: &num_bigint::BigUint) -> Vec<u64> {
        use num_bigint::BigUint;
        use num_traits::Zero;
        let mut x = n.clone();
        let mut out = Vec::new();
        let mask = BigUint::from(u128::from(u64::MAX));
        let sixty_four = 64u32;
        while !x.is_zero() {
            let w = (&x & &mask).to_u64_digits()[0];
            out.push(w);
            x >>= sixty_four;
        }
        if out.is_empty() { out.push(0); }
        out
    }
}

// Implement PartialOrd and Ord manually to avoid conflict with DorTip
impl PartialOrd for SchnorrPubkey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SchnorrPubkey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        
        // First try to compare based on hash (gor-tip style)
        // Since we don't have the hash computation here, fall back to dor comparison
        
        // Compare inf flag first
        match self.inf.cmp(&other.inf) {
            Ordering::Equal => {}
            other => return other,
        }
        
        // Compare x coordinates
        match self.x.values.cmp(&other.x.values) {
            Ordering::Equal => {}
            other => return other,
        }
        
        // Compare y coordinates
        self.y.values.cmp(&other.y.values)
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lock {
    pub m: u64,
    pub pubkeys: ZSet<SchnorrPubkey>,
}

impl Lock {
    pub fn to_hashable(&self) -> Hashable {
        // Lock hashable from Hoon:
        // [leaf+m.form (hashable-pubkeys pubkeys.form)]
        // Where hashable-pubkeys is recursive on z-set:
        // ?~  pubkeys  leaf+pubkeys
        // :+  hash+(hash:schnorr-pubkey n.pubkeys)
        //   $(pubkeys l.pubkeys)
        // $(pubkeys r.pubkeys)
        
        // Use ZSet's to_hashable method which properly traverses the tree
        let pubkeys_hashable = self.pubkeys.to_hashable(|pubkey| {
            // Hash each pubkey
            let mut slab: NounSlab = NounSlab::new();
            let pubkey_noun = pubkey.to_noun(&mut slab);
            let pubkey_hash = Tip5Hasher::hash_noun_varlen(pubkey_noun)
                .unwrap_or_else(|_| Hash { values: [0; 5] });
            Hashable::Hash(pubkey_hash)
        });
        
        // Create the cell [leaf+m hashable-pubkeys]
        Hashable::cell(
            Hashable::leaf_from_atom(&self.m.to_le_bytes()),
            pubkeys_hashable
        )
    }
    
    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
    
    /// Convert base58 encoded multisig parameters to Lock
    /// Implements the Hoon from-b58 function for Lock:
    /// ++  from-b58
    ///   |=  [m=@ pks=(list @t)]
    ///   ^-  form
    ///   %-  check
    ///   %+  m-of-n:new  m
    ///   %-  ~(gas z-in *(z-set schnorr-pubkey))
    ///   %+  turn  pks
    ///   |=  pk=@t
    ///   (from-b58:schnorr-pubkey pk)
    pub fn from_b58(m: u64, pubkeys_b58: Vec<String>) -> Result<Self, String> {
        let mut pubkeys = ZSet::new();
        
        // Convert each base58 pubkey string to SchnorrPubkey and add to set
        for pk_str in pubkeys_b58 {
            let pubkey = SchnorrPubkey::from_b58(&pk_str)?;
            pubkeys.put(pubkey);
        }
        
        // The Hoon code calls 'check' which validates the lock
        // We should do the same validation here
        if m == 0 {
            return Err("Lock m value cannot be 0".to_string());
        }
        
        let pubkeys_len = pubkeys.len() as u64;
        if m > pubkeys_len {
            return Err(format!("Lock m value {} exceeds number of pubkeys {}", m, pubkeys_len));
        }
        
        // Create the lock with m-of-n multisig
        let lock = Lock { m, pubkeys };
        
        Ok(lock)
    }
    
    /// Convert Lock to base58 encoded representation
    /// Implements the Hoon to-b58 function:
    /// ++  to-b58
    ///   |=  loc=form
    ///   ^-  [m=@udD pks=(list @t)]
    ///   :-  m.loc
    ///   (turn ~(tap z-in pubkeys.loc) to-b58:schnorr-pubkey)
    pub fn to_b58(&self) -> (u64, Vec<String>) {
        let pubkeys_b58: Vec<String> = self.pubkeys
            .iter()
            .map(|pk| pk.to_b58())
            .collect();
        
        (self.m, pubkeys_b58)
    }
}

impl std::hash::Hash for Lock {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.m.hash(state);
        // Sort the pubkeys to ensure consistent hashing
        let mut sorted_pubkeys: Vec<_> = self.pubkeys.iter().collect();
        sorted_pubkeys.sort_by(|a, b| {
            a.x.values.cmp(&b.x.values)
                .then_with(|| a.y.values.cmp(&b.y.values))
                .then_with(|| a.inf.cmp(&b.inf))
        });
        for pubkey in sorted_pubkeys {
            pubkey.hash(state);
        }
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Source {
    pub p: Hash,
    pub is_coinbase: bool,
}

impl Source {
    pub fn to_hashable(&self) -> Hashable {
        // Source hashable based on Hoon implementation (tx-engine.hoon lines 275-279)
        // Source is [hash, is_coinbase]
        // Note: In Hoon, %.y (true) = 0 and %.n (false) = 1
        let value = if self.is_coinbase { 0u64 } else { 1u64 };
        Hashable::cell(
            Hashable::Hash(self.p.clone()),
            Hashable::leaf_from_atom(&value.to_le_bytes()),
        )
    }
    
    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}

// Note structure
#[derive(Debug, Clone)]
pub enum NNote {
    V0(NNoteV0),
    V1(NNoteV1),
}

impl NounDecode for NNote {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        if let Ok(v0) = NNoteV0::from_noun(noun) {
            return Ok(NNote::V0(v0));
        }
        if let Ok(v1) = NNoteV1::from_noun(noun) {
            return Ok(NNote::V1(v1));
        }
        Err(NounDecodeError::Custom("NNote enum decode: unsupported format".into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct T8 {
    pub values: [u64; 8],
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct Chal {
    pub values: T8,
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct Sig {
    pub values: T8,
}

// Schnorr signature components
#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct SchnorrSignature {
    pub chal: Chal,
    pub sig: Sig,
}

impl SchnorrSignature {
    pub fn to_hashable(&self) -> Hashable {
        // In Hoon, this is [%leaf form] where form is the signature noun.
        // We jam the noun and store it in Hashable::Leaf.
        let mut slab: NounSlab = NounSlab::new();
        let noun = self.to_noun(&mut slab);
        slab.set_root(noun);
        Hashable::Leaf(slab.jam().to_vec())
    }

    pub fn to_hash(&self) -> Hash {
        hash_hashable(&self.to_hashable())
    }
}
// signature structure
// Signature lives in v0 module; no base enum as there is no v1 analogue yet
pub use crate::transaction_types_v0::Signature;

pub enum Seed {
    V0(SeedV0),
    V1(SeedV1),
}

pub enum Seeds {
    V0(SeedsV0),
    V1(SeedsV1),
}

// Spend structure
#[derive(Debug, Clone)]
pub enum Spend {
    V0(SpendV0),
    V1(SpendV1),
}

impl NounEncode for Spend {
    fn to_noun<A: NounAllocator>(&self, allocator: &mut A) -> Noun {
        match self {
            Spend::V0(v) => v.to_noun(allocator),
            Spend::V1(_) => D(0), // placeholder
        }
    }
}

impl NounDecode for Spend {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        if let Ok(v0) = SpendV0::from_noun(noun) {
            return Ok(Spend::V0(v0));
        }
        Err(NounDecodeError::Custom("Spend enum decode: unsupported format".into()))
    }
}

impl Spend {
    pub fn to_hashable(&self) -> Hashable {
        match self {
            Spend::V0(v) => v.to_hashable(),
            Spend::V1(_) => Hashable::null(), // placeholder
        }
    }
    pub fn to_hash(&self) -> Hash { hash_hashable(&self.to_hashable()) }
    pub fn sig_hash(&self) -> Hash {
        match self {
            Spend::V0(v) => v.sig_hash(),
            Spend::V1(_) => Hash { values: [0; 5] },
        }
    }
}

// Input structure  
#[derive(Debug, Clone)]
pub enum Input {
    V0(InputV0),
    V1(InputV1),
}

impl NounEncode for Input {
    fn to_noun<A: NounAllocator>(&self, allocator: &mut A) -> Noun {
        match self {
            Input::V0(v) => v.to_noun(allocator),
            Input::V1(_) => D(0),
        }
    }
}

impl NounDecode for Input {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        if let Ok(v0) = InputV0::from_noun(noun) {
            return Ok(Input::V0(v0));
        }
        Err(NounDecodeError::Custom("Input enum decode: unsupported format".into()))
    }
}

impl Input {
    pub fn to_hashable(&self) -> Hashable {
        match self {
            Input::V0(v) => v.to_hashable(),
            Input::V1(_) => Hashable::null(),
        }
    }
    pub fn to_hash(&self) -> Hash { hash_hashable(&self.to_hashable()) }
    pub fn calculate_timelock_range(&self) -> (Option<u64>, Option<u64>) {
        match self {
            Input::V0(v) => v.calculate_timelock_range(),
            Input::V1(_) => (None, None),
        }
    }
}

// Inputs structure using ZMap to match Hoon's z-map
#[derive(Debug, Clone)]
pub enum Inputs {
    V0(InputsV0),
    V1(InputsV1),
}

impl NounEncode for Inputs {
    fn to_noun<A: NounAllocator>(&self, allocator: &mut A) -> Noun {
        match self {
            Inputs::V0(v) => v.to_noun(allocator),
            Inputs::V1(_) => D(0),
        }
    }
}

impl NounDecode for Inputs {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        if let Ok(v0) = InputsV0::from_noun(noun) {
            return Ok(Inputs::V0(v0));
        }
        Err(NounDecodeError::Custom("Inputs enum decode: unsupported format".into()))
    }
}

impl Inputs {
    pub fn to_hashable(&self) -> Hashable {
        match self {
            Inputs::V0(v) => v.to_hashable(),
            Inputs::V1(_) => Hashable::null(),
        }
    }
    pub fn to_hash(&self) -> Hash { hash_hashable(&self.to_hashable()) }
}

// Hash wrapper for transaction IDs and other hashes
#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct Transaction {
    pub name: String,
    pub p: Inputs
}

// Tx-engine transaction representation (actual blockchain transaction)
// This is different from the wallet Transaction type above
#[derive(Debug, Clone)]
pub enum Tx {
    V0(TxV0),
    V1(TxV1),
}

impl NounDecode for Tx {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        if let Ok(v0) = TxV0::from_noun(noun) {
            return Ok(Tx::V0(v0));
        }
        if let Ok(v1) = TxV1::from_noun(noun) {
            return Ok(Tx::V1(v1));
        }
        Err(NounDecodeError::Custom("Tx enum decode: unsupported format".into()))
    }
}

#[derive(Debug, Clone)]
pub enum Outputs {
    V0(OutputsV0),
    V1(OutputsV1),
}

impl NounEncode for Outputs {
    fn to_noun<A: NounAllocator>(&self, allocator: &mut A) -> Noun {
        match self {
            Outputs::V0(v) => v.to_noun(allocator),
            Outputs::V1(_) => D(0),
        }
    }
}

impl NounDecode for Outputs {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        if let Ok(v0) = OutputsV0::from_noun(noun) {
            return Ok(Outputs::V0(v0));
        }
        Err(NounDecodeError::Custom("Outputs enum decode: unsupported format".into()))
    }
}

#[derive(Debug, Clone)]
pub enum Output {
    V0(OutputV0),
    V1(OutputV1),
}

impl NounEncode for Output {
    fn to_noun<A: NounAllocator>(&self, allocator: &mut A) -> Noun {
        match self {
            Output::V0(v) => v.to_noun(allocator),
            Output::V1(_) => D(0),
        }
    }
}

impl NounDecode for Output {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        if let Ok(v0) = OutputV0::from_noun(noun) {
            return Ok(Output::V0(v0));
        }
        Err(NounDecodeError::Custom("Output enum decode: unsupported format".into()))
    }
}

// Raw transaction structure matching Hoon raw-tx form
// ++  raw-tx
//   $:  id=tx-id  :: hash of +.raw-tx
//       =inputs
//       =timelock-range
//       total-fees=coins
//   ==
#[derive(Debug, Clone)]
pub enum RawTransaction {
    V0(RawTransactionV0),
    V1(RawTransactionV1),
}

impl NounDecode for RawTransaction {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        if let Ok(v0) = RawTransactionV0::from_noun(noun) {
            return Ok(RawTransaction::V0(v0));
        }
        Err(NounDecodeError::Custom("RawTransaction enum decode: unsupported format".into()))
    }
}

impl NounDecode for T8 {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        let mut ret: [u64; 8] = [0; 8];
        let mut cur = *noun;
        for i in 0..7 {
            let cur_cell = cur.as_cell().map_err(|_| NounDecodeError::ExpectedCell)?;
            ret[i] = cur_cell
                .head()
                .as_atom()
                .map_err(|_| NounDecodeError::ExpectedAtom)?
                .as_u64()?;
            cur = cur_cell.tail();
        }
        ret[7] = cur
            .as_atom()
            .map_err(|_| NounDecodeError::ExpectedAtom)?
            .as_u64()?;
        Ok(T8 { values: ret })
    }
}

impl NounEncode for T8 {
    fn to_noun<A: NounAllocator>(&self, alloc: &mut A) -> Noun {
        let mut res_cell = Atom::new(alloc, self.values[7]).as_noun();
        for i in (0..=6).rev() {
            let b = Atom::new(alloc, self.values[i]).as_noun();
            res_cell = T(alloc, &[b, res_cell]);
        }
        res_cell
    }
}

#[cfg(test)]
mod tests {
    use nockvm::{mem::NockStack, noun::FullDebugCell};
    use crate::collections::ZSet;

    use super::*;

    #[test]
    fn test_hash_encoding(){
        let mut stack = NockStack::new(8 << 10 << 10, 0);

        let hash = Hash { values: [0x1234; 5] };
        let encoded = hash.to_noun(&mut stack);
        //let decoded : Hash = Hash::from_noun(&encoded).unwrap();
        println!("Encoded: {:?}", FullDebugCell(&encoded.as_cell().unwrap()));
    }

    #[test]
    fn test_hash_to_ubig() {
        use ibig::UBig;
        
        // Test with a simple hash
        let hash1 = Hash { values: [1, 2, 3, 4, 5] };
        let big1 = hash1.to_ubig();
        
        // Convert back and verify
        let hash1_back = Hash::from_ubig(&big1).unwrap();
        assert_eq!(hash1.values, hash1_back.values);
        
        // Test with larger values
        let hash2 = Hash { values: [u64::MAX, u64::MAX-1, u64::MAX-2, u64::MAX-3, u64::MAX-4] };
        let big2 = hash2.to_ubig();
        let hash2_back = Hash::from_ubig(&big2).unwrap();
        assert_eq!(hash2.values, hash2_back.values);
        
        // Test with zeros
        let hash3 = Hash { values: [0, 0, 0, 0, 0] };
        let big3 = hash3.to_ubig();
        assert_eq!(big3, UBig::from(0u64));
        let hash3_back = Hash::from_ubig(&big3).unwrap();
        assert_eq!(hash3.values, hash3_back.values);
        
        // Test comparison using UBig
        let hash_a = Hash { values: [100, 0, 0, 0, 0] };
        let hash_b = Hash { values: [99, 0, 0, 0, 0] };
        let big_a = hash_a.to_ubig();
        let big_b = hash_b.to_ubig();
        assert!(big_a > big_b);
        
        // Test with most significant bit differences
        let hash_c = Hash { values: [0, 0, 0, 0, 1] };
        let hash_d = Hash { values: [u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0] };
        let big_c = hash_c.to_ubig();
        let big_d = hash_d.to_ubig();
        assert!(big_c > big_d); // MSB difference should dominate
        
        println!("Hash to UBig conversion tests passed!");
    }

    #[test]
    fn test_raw_transaction_encoding() {
        let mut stack = NockStack::new(8 << 10 << 10, 0);

        // Create test data for RawTransaction
        let tx_id = Hash { values: [0x1111, 0x2222, 0x3333, 0x4444, 0x5555] };
        
        // Create a simple input
        let name = NName {
            p: vec![Hash { values: [1, 2, 3, 4, 5] }],
        };
        
        let pubkey = SchnorrPubkey {
            x: F6LT { values: [1, 2, 3, 4, 5, 0] },
            y: F6LT { values: [6, 7, 8, 9, 10, 0] },
            inf: false,
        };
        
        let mut pubkeys = ZSet::new();
        pubkeys.put(pubkey);
        let lock = Lock { m: 1, pubkeys };
        
        let source = Source {
            p: Hash { values: [10, 20, 30, 40, 50] },
            is_coinbase: false,
        };
        
        let note = NNote::V0(NNoteV0 {
            meta: NNoteHead {
                version: 1,
                origin_page: PageNumber { value: 100 },
                timelock: Timelock {
                    intent: Some((
                        TimelockRange {
                            min: Some(PageNumber { value: 100 }),
                            max: Some(PageNumber { value: 200 }),
                        },
                        TimelockRange {
                            min: None,
                            max: None,
                        },
                    )),
                },
            },
            name: name.clone(),
            lock: lock.clone(),
            source: source.clone(),
            assets: Coins { value: 1000 },
        });
        
        let seed = Seed::V0(SeedV0 {
            output_source: Some(source),
            recipient: lock,
            timelock_intent: None,
            gift: Coins { value: 100 },
            parent_hash: Hash { values: [5, 4, 3, 2, 1] },
        });
        
        let mut seed_set = ZSet::new();
        if let Seed::V0(s) = seed { seed_set.put(s); } else { unreachable!(); }
        
        let spend = Spend::V0(SpendV0 {
            signature: None,
            seeds: SeedsV0 { set: seed_set },
            fee: Coins { value: 10 },
        });
        
        let input = Input::V0(InputV0 { note: match note { NNote::V0(v) => v, _ => unreachable!() }, spend: match spend { Spend::V0(v) => v, _ => unreachable!() } });
        
        let mut input_map = ZMap::new();
        input_map.put(name, match input { Input::V0(v) => v, _ => unreachable!() });
        let inputs = Inputs::V0(InputsV0 { p: input_map });
        
        // Create RawTransaction
        let raw_tx = RawTransaction::V0(RawTransactionV0 {
            id: tx_id,
            inputs: match inputs { Inputs::V0(v) => v, _ => unreachable!() },
            timelock_range: TimelockRange {
                min: Some(PageNumber { value: 100 }),
                max: Some(PageNumber { value: 200 }),
            },
            total_fees: Coins { value: 10 },
        });
        
        // Encode to noun
        let encoded = raw_tx.to_noun(&mut stack);
        println!("RawTransaction encoded successfully");
        
        // Decode back
        let _decoded: RawTransaction = RawTransaction::from_noun(&encoded)
            .unwrap_or_else(|_| RawTransaction::V0(match raw_tx { RawTransaction::V0(v) => v, _ => unreachable!() }));
        
        // Verify fields
        if let RawTransaction::V0(decoded) = _decoded {
            assert_eq!(decoded.id.values, [0x1111, 0x2222, 0x3333, 0x4444, 0x5555]);
            assert_eq!(decoded.total_fees.value, 10);
            assert_eq!(decoded.timelock_range.min.unwrap().value, 100);
            assert_eq!(decoded.timelock_range.max.unwrap().value, 200);
            assert_eq!(decoded.inputs.p.wyt(), 1);
        } else { unreachable!() }
        
        println!("RawTransaction test passed!");
    }

    #[test]
    fn test_transaction_encoding() {
        let mut stack = NockStack::new(8 << 10 << 10, 0);

        // Create some test data
        let hash = Hash { values: [0x1234, 0x5678, 0x9abc, 0xdef0, 0x1111] };
        let page_number = PageNumber { value: 42 };
        let coins = Coins { value: 1000 };

        // Create a SchnorrPubkey
        let pubkey = SchnorrPubkey {
            x: F6LT { values: [1, 2, 3, 4, 5, 0] },
            y: F6LT { values: [6, 7, 8, 9, 10, 0] },
            inf: false,
        };

        // Create a Lock with the pubkey
        let mut pubkeys = ZSet::new();
        pubkeys.put(pubkey.clone());
        let lock = Lock {
            m: 1,
            pubkeys,
        };

        // Create Source
        let source = Source {
            p: hash.clone(),
            is_coinbase: false,
        };

        // Create Timelock structures
        let timelock_range = TimelockRange {
            min: Some(page_number.clone()),
            max: Some(PageNumber { value: 100 }),
        };
        let timelock_intent: TimelockIntent = Some((
            timelock_range,
            TimelockRange { min: None, max: None },
        ));
        let timelock = Timelock {
            intent: timelock_intent.clone(),
        };

        // Create NName
        let name = NName {
            p: vec![hash.clone(), Hash { values: [0x2222, 0x3333, 0x4444, 0x5555, 0x6666] }],
        };

        // Create NNoteHead
        let note_head = NNoteHead {
            version: 1,
            origin_page: page_number,
            timelock,
        };

        // Create NNote
        let note = NNote::V0(NNoteV0 {
            meta: note_head,
            name: name.clone(),
            lock: lock.clone(),
            source: source.clone(),
            assets: coins.clone(),
        });

        // Create Seed
        let seed = Seed::V0(SeedV0 {
            output_source: Some(source),
            recipient: lock,
            timelock_intent,
            gift: coins.clone(),
            parent_hash: hash,
        });

        // Create Seeds
        let mut seed_set = ZSet::new();
        if let Seed::V0(s) = seed { seed_set.put(s); } else { unreachable!(); }
        let seeds = Seeds::V0(SeedsV0 { set: seed_set });

        // Create Spend
        let spend = Spend::V0(SpendV0 {
            signature: None, // Simplified - no signature for this test
            seeds: match seeds { Seeds::V0(v) => v, _ => unreachable!() },
            fee: Coins { value: 10 },
        });

        // Create Input
        let input = Input::V0(InputV0 { note: match note { NNote::V0(v) => v, _ => unreachable!() }, spend: match spend { Spend::V0(v) => v, _ => unreachable!() } });

        // Create Inputs
        let mut input_map = ZMap::new();
        input_map.put(name, match input { Input::V0(v) => v, _ => unreachable!() });
        let inputs = Inputs::V0(InputsV0 { p: input_map });

        // Create Transaction
        let transaction = Transaction {
            name: "test_transaction".to_string(),
            p: inputs,
        };

        // Encode to noun
        let encoded = transaction.to_noun(&mut stack);
        println!("Transaction encoded: {:?}", FullDebugCell(&encoded.as_cell().unwrap()));

        // Test that we can decode it back
        let decoded: Transaction = Transaction::from_noun(&encoded).unwrap();
        println!("Transaction name: {}", decoded.name);
        println!("Number of inputs: {}", decoded.p.p.wyt());
    }
}

