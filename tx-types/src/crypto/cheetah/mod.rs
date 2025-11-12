/// Cheetah elliptic curve over F^6 extension field
///
/// This module implements the Cheetah curve used in Nockchain:
/// - F^6 extension field arithmetic
/// - Elliptic curve point operations
/// - Scalar multiplication for public key generation
pub mod constants;
pub mod field;
pub mod point;

pub use constants::{GENERATOR_X, GENERATOR_Y, GROUP_ORDER_HEX};
pub use field::F6Element;
pub use point::CheetahPoint;
