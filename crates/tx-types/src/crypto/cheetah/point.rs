/// Cheetah elliptic curve point operations
use super::field::F6Element;
use super::constants::{GENERATOR_X, GENERATOR_Y, F6_ZERO, F6_ONE, group_order};
use ibig::UBig;
use crate::transaction_types::{SchnorrPubkey, F6LT};

/// Point on the Cheetah elliptic curve
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CheetahPoint {
    pub x: F6Element,
    pub y: F6Element,
    pub inf: bool,  // Point at infinity flag
}

impl CheetahPoint {
    /// Identity element (point at infinity)
    pub fn identity() -> Self {
        CheetahPoint {
            x: F6_ZERO,
            y: F6_ONE,
            inf: true,
        }
    }
    
    /// Generator point
    pub fn generator() -> Self {
        CheetahPoint {
            x: GENERATOR_X,
            y: GENERATOR_Y,
            inf: false,
        }
    }
    
    /// Create point from coordinates (does not validate curve equation)
    pub fn new(x: F6Element, y: F6Element) -> Self {
        CheetahPoint { x, y, inf: false }
    }
    
    /// Check if this is the identity element
    pub fn is_identity(&self) -> bool {
        self.inf
    }
    
    /// Point addition using the group law
    pub fn add(&self, other: &Self) -> Self {
        // Handle identity cases
        if self.inf {
            return *other;
        }
        if other.inf {
            return *self;
        }
        
        // Check if points are equal
        if self.x == other.x && self.y == other.y {
            return self.double();
        }
        
        // Check if points are inverses (same x, different y)
        if self.x == other.x {
            return Self::identity();
        }
        
        // General case: P + Q where P ≠ Q and P ≠ -Q
        // This is a simplified version - full implementation would need
        // proper F^6 field arithmetic for the slope calculation
        
        // For now, return a placeholder
        // TODO: Implement proper elliptic curve addition
        *self
    }
    
    /// Point doubling
    pub fn double(&self) -> Self {
        if self.inf {
            return *self;
        }
        
        // TODO: Implement proper point doubling
        // For now, return a placeholder
        *self
    }
    
    /// Scalar multiplication using double-and-add
    pub fn scalar_mul(&self, scalar: &UBig) -> Self {
        if scalar.is_zero() || self.inf {
            return Self::identity();
        }
        
        let mut result = Self::identity();
        let mut base = *self;
        let mut k = scalar.clone();
        
        while !k.is_zero() {
            if &k & UBig::from(1u32) == UBig::from(1u32) {
                result = result.add(&base);
            }
            base = base.double();
            k >>= 1;
        }
        
        result
    }
    
    /// Generate public key from private key
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        let scalar = UBig::from_be_bytes(private_key) % group_order();
        Self::generator().scalar_mul(&scalar)
    }
    
    /// Convert to SchnorrPubkey format
    pub fn to_schnorr_pubkey(&self) -> SchnorrPubkey {
        if self.inf {
            SchnorrPubkey {
                x: F6LT { values: [0; 6] },
                y: F6LT { values: [0; 6] },
                inf: true,
            }
        } else {
            SchnorrPubkey {
                x: F6LT { values: self.x.to_u64_array() },
                y: F6LT { values: self.y.to_u64_array() },
                inf: false,
            }
        }
    }
    
    /// Create from SchnorrPubkey
    pub fn from_schnorr_pubkey(pk: &SchnorrPubkey) -> Self {
        if pk.inf {
            Self::identity()
        } else {
            CheetahPoint {
                x: F6Element::from_u64_array(pk.x.values),
                y: F6Element::from_u64_array(pk.y.values),
                inf: false,
            }
        }
    }
    
    /// Convert to raw coordinate arrays for compatibility
    pub fn to_coordinates(&self) -> [[u64; 6]; 2] {
        [self.x.to_u64_array(), self.y.to_u64_array()]
    }
    
    /// Create from raw coordinate arrays
    pub fn from_coordinates(coords: [[u64; 6]; 2]) -> Self {
        CheetahPoint {
            x: F6Element::from_u64_array(coords[0]),
            y: F6Element::from_u64_array(coords[1]),
            inf: false,
        }
    }
}

impl Default for CheetahPoint {
    fn default() -> Self {
        Self::identity()
    }
}

/// Fast scalar multiplication using precomputed table
/// This is a stub for the optimized scalar multiplication
pub fn scalar_mul_generator(scalar: &UBig) -> CheetahPoint {
    CheetahPoint::generator().scalar_mul(scalar)
}

/// Convert private key bytes to public key coordinates
pub fn private_key_to_public_key(private_key: [u8; 32]) -> [[u64; 6]; 2] {
    let point = CheetahPoint::from_private_key(&private_key);
    point.to_coordinates()
}