use std::ops::{Add, Mul, Neg, Sub};
/// F^6 extension field arithmetic for Cheetah curve (copied from working siger-esp implementation)
use zkvm_jetpack::form::math::belt::{bneg, Belt};
use zkvm_jetpack::form::math::bpoly::{bpegcd, bpscal};

/// Element in F^6 extension field
/// Represented as 6 limbs in little-endian order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F6Element(pub [Belt; 6]);

/// Constants from the working implementation
pub const F6_ZERO: F6Element = F6Element([Belt(0); 6]);
pub const F6_ONE: F6Element = F6Element([Belt(1), Belt(0), Belt(0), Belt(0), Belt(0), Belt(0)]);

impl F6Element {
    /// Zero element
    pub fn zero() -> Self {
        F6_ZERO
    }

    /// One element (1, 0, 0, 0, 0, 0)
    pub fn one() -> Self {
        F6_ONE
    }

    /// Check if element is zero
    pub fn is_zero(&self) -> bool {
        *self == F6_ZERO
    }

    /// Check if element is one
    pub fn is_one(&self) -> bool {
        *self == F6_ONE
    }

    /// Addition in F^6 using working implementation pattern
    pub fn add(&self, other: &Self) -> Self {
        F6Element([
            self.0[0] + other.0[0],
            self.0[1] + other.0[1],
            self.0[2] + other.0[2],
            self.0[3] + other.0[3],
            self.0[4] + other.0[4],
            self.0[5] + other.0[5],
        ])
    }

    /// Subtraction in F^6 using working implementation pattern
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Negation in F^6 using working implementation pattern
    pub fn neg(&self) -> Self {
        F6Element([
            -self.0[0], -self.0[1], -self.0[2], -self.0[3], -self.0[4], -self.0[5],
        ])
    }

    /// Scalar multiplication using working implementation pattern
    pub fn mul_by_scalar(&self, s: Belt) -> Self {
        F6Element([
            self.0[0] * s,
            self.0[1] * s,
            self.0[2] * s,
            self.0[3] * s,
            self.0[4] * s,
            self.0[5] * s,
        ])
    }

    /// Full F^6 multiplication using Karatsuba-like algorithm from working implementation
    pub fn mul(&self, other: &Self) -> Self {
        // Split into two F^3 parts: f = f0 + f1*u^3, g = g0 + g1*u^3
        let f0 = [self.0[0], self.0[1], self.0[2]];
        let f1 = [self.0[3], self.0[4], self.0[5]];
        let g0 = [other.0[0], other.0[1], other.0[2]];
        let g1 = [other.0[3], other.0[4], other.0[5]];

        let f0g0 = karat3(&f0, &g0);
        let f1g1 = karat3(&f1, &g1);
        let foil = karat3(
            &[f0[0] + f1[0], f0[1] + f1[1], f0[2] + f1[2]],
            &[g0[0] + g1[0], g0[1] + g1[1], g0[2] + g1[2]],
        );
        let cross = [
            foil[0] - (f0g0[0] + f1g1[0]),
            foil[1] - (f0g0[1] + f1g1[1]),
            foil[2] - (f0g0[2] + f1g1[2]),
            foil[3] - (f0g0[3] + f1g1[3]),
            foil[4] - (f0g0[4] + f1g1[4]),
        ];

        // Reduction: u^6 = 7, so u^3 * u^3 = 7
        F6Element([
            f0g0[0] + Belt(7) * (cross[3] + f1g1[0]),
            f0g0[1] + Belt(7) * (cross[4] + f1g1[1]),
            f0g0[2] + Belt(7) * f1g1[2],
            f0g0[3] + cross[0] + Belt(7) * f1g1[3],
            f0g0[4] + cross[1] + Belt(7) * f1g1[4],
            cross[2],
        ])
    }

    /// Squaring in F^6
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Multiplicative inverse using extended Euclidean algorithm
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        let mut res = [Belt(0); 6];
        let mut d = [Belt(0); 7];
        let mut u = [Belt(0); 7];
        let mut v = [Belt(0); 6];

        // Extended GCD with the reduction polynomial x^6 - 7
        bpegcd(
            &self.0,
            &[
                Belt(bneg(7)),
                Belt(0),
                Belt(0),
                Belt(0),
                Belt(0),
                Belt(0),
                Belt(1),
            ],
            &mut d,
            &mut u,
            &mut v,
        );

        let inv = d[0].inv();
        bpscal(inv, &u, &mut res);
        Some(F6Element(res))
    }

    /// Division in F^6
    pub fn div(&self, other: &Self) -> Option<Self> {
        other.invert().map(|inv| self.mul(&inv))
    }

    /// Convert to/from [u64; 6] array for compatibility
    pub fn to_u64_array(&self) -> [u64; 6] {
        [
            self.0[0].0,
            self.0[1].0,
            self.0[2].0,
            self.0[3].0,
            self.0[4].0,
            self.0[5].0,
        ]
    }

    pub fn from_u64_array(arr: [u64; 6]) -> Self {
        F6Element([
            Belt(arr[0]),
            Belt(arr[1]),
            Belt(arr[2]),
            Belt(arr[3]),
            Belt(arr[4]),
            Belt(arr[5]),
        ])
    }
}

/// Karatsuba multiplication for F^3 (helper for F^6 multiplication)
fn karat3(a: &[Belt; 3], b: &[Belt; 3]) -> [Belt; 5] {
    let m = [a[0] * b[0], a[1] * b[1], a[2] * b[2]];
    [
        m[0],
        (a[0] + a[1]) * (b[0] + b[1]) - (m[0] + m[1]),
        (a[0] + a[2]) * (b[0] + b[2]) - (m[0] + m[2]) + m[1],
        (a[1] + a[2]) * (b[1] + b[2]) - (m[1] + m[2]),
        m[2],
    ]
}

impl Add for F6Element {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        F6Element([
            self.0[0] + other.0[0],
            self.0[1] + other.0[1],
            self.0[2] + other.0[2],
            self.0[3] + other.0[3],
            self.0[4] + other.0[4],
            self.0[5] + other.0[5],
        ])
    }
}

impl Sub for F6Element {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self + (-other)
    }
}

impl Mul for F6Element {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        // Direct implementation to avoid recursion
        let f0 = [self.0[0], self.0[1], self.0[2]];
        let f1 = [self.0[3], self.0[4], self.0[5]];
        let g0 = [other.0[0], other.0[1], other.0[2]];
        let g1 = [other.0[3], other.0[4], other.0[5]];

        let f0g0 = karat3(&f0, &g0);
        let f1g1 = karat3(&f1, &g1);
        let foil = karat3(
            &[f0[0] + f1[0], f0[1] + f1[1], f0[2] + f1[2]],
            &[g0[0] + g1[0], g0[1] + g1[1], g0[2] + g1[2]],
        );
        let cross = [
            foil[0] - (f0g0[0] + f1g1[0]),
            foil[1] - (f0g0[1] + f1g1[1]),
            foil[2] - (f0g0[2] + f1g1[2]),
            foil[3] - (f0g0[3] + f1g1[3]),
            foil[4] - (f0g0[4] + f1g1[4]),
        ];

        F6Element([
            f0g0[0] + Belt(7) * (cross[3] + f1g1[0]),
            f0g0[1] + Belt(7) * (cross[4] + f1g1[1]),
            f0g0[2] + Belt(7) * f1g1[2],
            f0g0[3] + cross[0] + Belt(7) * f1g1[3],
            f0g0[4] + cross[1] + Belt(7) * f1g1[4],
            cross[2],
        ])
    }
}

impl Neg for F6Element {
    type Output = Self;

    fn neg(self) -> Self {
        F6Element([
            -self.0[0], -self.0[1], -self.0[2], -self.0[3], -self.0[4], -self.0[5],
        ])
    }
}

impl Default for F6Element {
    fn default() -> Self {
        Self::zero()
    }
}
