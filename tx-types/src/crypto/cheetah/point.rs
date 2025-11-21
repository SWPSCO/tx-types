/// Cheetah elliptic curve point operations (copied from working siger-esp implementation)
use super::field::{F6Element, F6_ONE, F6_ZERO};
use crate::crypto::{CryptoError, Result};
use crate::transaction_types::{SchnorrPubkey, F6LT};
use ibig::UBig;
use zkvm_jetpack::form::math::belt::Belt;

/// Point on the Cheetah elliptic curve
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheetahPoint {
    pub x: F6Element,
    pub y: F6Element,
    pub inf: bool, // Point at infinity flag
}

/// Identity element constant
pub const A_ID: CheetahPoint = CheetahPoint {
    x: F6_ZERO,
    y: F6_ONE,
    inf: true,
};

/// Generator point constants from working implementation
pub const GX: F6Element = F6Element([
    Belt(2_754_611_494_552_410_273),
    Belt(8_599_518_745_794_843_693),
    Belt(10_526_511_002_404_673_680),
    Belt(4_830_863_958_577_994_148),
    Belt(375_185_138_577_093_320),
    Belt(12_938_930_721_685_970_739),
]);

pub const GY: F6Element = F6Element([
    Belt(15_384_029_202_802_550_068),
    Belt(2_774_812_795_997_841_935),
    Belt(14_375_303_400_746_062_753),
    Belt(10_708_493_419_890_101_954),
    Belt(13_187_678_623_570_541_764),
    Belt(9_990_732_138_772_505_951),
]);

/// Group order constant
pub const GROUP_ORDER_HEX: &str =
    "7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf";

pub fn cheetah_order() -> UBig {
    UBig::from_str_radix(GROUP_ORDER_HEX, 16).expect("valid group order")
}

impl CheetahPoint {
    /// Identity element (point at infinity)
    pub fn identity() -> Self {
        A_ID
    }

    /// Generator point
    pub fn generator() -> Self {
        CheetahPoint {
            x: GX,
            y: GY,
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

    /// Point negation
    pub fn neg(&self) -> Self {
        CheetahPoint {
            x: self.x,
            y: self.y.neg(),
            inf: self.inf,
        }
    }

    /// Point doubling using working implementation
    pub fn double(&self) -> Self {
        if self.inf || self.y == F6_ZERO {
            return A_ID;
        }
        self.double_unsafe()
    }

    /// Unsafe point doubling (assumes point is not at infinity and y != 0)
    fn double_unsafe(&self) -> Self {
        // slope = (3*x^2 + 1) / (2*y)
        let slope = self
            .x
            .square()
            .mul_by_scalar(Belt(3))
            .add(&F6_ONE)
            .div(&self.y.mul_by_scalar(Belt(2)))
            .expect("Division should work for non-zero y");

        let x_out = slope.square().sub(&self.x.mul_by_scalar(Belt(2)));
        let y_out = slope.mul(&self.x.sub(&x_out)).sub(&self.y);

        CheetahPoint {
            x: x_out,
            y: y_out,
            inf: false,
        }
    }

    /// Point addition using working implementation
    pub fn add(&self, other: &Self) -> Self {
        if self.inf {
            return *other;
        }
        if other.inf {
            return *self;
        }
        if *self == other.neg() {
            return A_ID;
        }
        if self == other {
            return self.double();
        }
        self.add_unsafe(*other)
    }

    /// Unsafe point addition (assumes points are distinct and not inverses)
    fn add_unsafe(&self, other: CheetahPoint) -> Self {
        // slope = (p.y - q.y) / (p.x - q.x)
        let slope = self
            .y
            .sub(&other.y)
            .div(&self.x.sub(&other.x))
            .expect("Division should work for distinct x coordinates");

        let x_out = slope.square().sub(&self.x.add(&other.x));
        let y_out = slope.mul(&self.x.sub(&x_out)).sub(&self.y);

        CheetahPoint {
            x: x_out,
            y: y_out,
            inf: false,
        }
    }

    /// Scalar multiplication using binary method from working implementation
    pub fn scalar_mul(&self, scalar: &UBig) -> Self {
        let mut n = scalar.clone();
        let mut q = *self;
        let mut acc = A_ID;

        while n > UBig::from(0u8) {
            if n.bit(0) {
                acc = acc.add(&q);
            }
            q = q.double();
            n >>= 1;
        }
        acc
    }

    /// Generate public key from private key
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        let scalar = UBig::from_be_bytes(private_key) % cheetah_order();
        Self::generator().scalar_mul(&scalar)
    }

    /// Deserialize the `[0x01 | y | x]` representation used by zpub strings
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 97 {
            return Err(CryptoError::InvalidExtendedKeyString);
        }
        if bytes[0] != 0x01 {
            return Err(CryptoError::InvalidExtendedKeyString);
        }

        let mut rd = &bytes[1..];
        let y = Self::read_field_element(&mut rd)?;
        let x = Self::read_field_element(&mut rd)?;

        Ok(CheetahPoint::from_coordinates([x, y]))
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
                x: F6LT {
                    values: self.x.to_u64_array(),
                },
                y: F6LT {
                    values: self.y.to_u64_array(),
                },
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

    fn read_field_element(rd: &mut &[u8]) -> Result<[u64; 6]> {
        let mut out = [0u64; 6];
        for limb in (0..6).rev() {
            out[limb] = Self::read_u64_be(rd)?;
        }
        Ok(out)
    }

    fn read_u64_be(rd: &mut &[u8]) -> Result<u64> {
        if rd.len() < 8 {
            return Err(CryptoError::InvalidExtendedKeyString);
        }
        let (head, tail) = rd.split_at(8);
        *rd = tail;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(head);
        Ok(u64::from_be_bytes(bytes))
    }
}

impl Default for CheetahPoint {
    fn default() -> Self {
        Self::identity()
    }
}

/// Scalar multiplication of generator from working implementation
pub fn scalar_mul_g(s: &UBig) -> [[u64; 6]; 2] {
    let p = CheetahPoint::generator().scalar_mul(s);
    p.to_coordinates()
}

/// Add k*G + P where P is a point and k is a scalar
pub fn add_scalar_times_g_to_point(k: &UBig, pk_xy: &[[u64; 6]; 2]) -> [[u64; 6]; 2] {
    let kg = scalar_mul_g(k);
    let P = CheetahPoint::from_coordinates(*pk_xy);
    let Q = CheetahPoint::from_coordinates(kg);
    let R = P.add(&Q);
    R.to_coordinates()
}

/// Check if point is identity (for compatibility)
pub fn is_identity(_pk_xy: &[[u64; 6]; 2]) -> bool {
    // For compatibility with working implementation
    false
}

/// Convert private key bytes to public key coordinates
pub fn cheetah_pub_from_sk(sk_be32: [u8; 32]) -> [[u64; 6]; 2] {
    let s = UBig::from_be_bytes(&sk_be32) % cheetah_order();
    scalar_mul_g(&s)
}
