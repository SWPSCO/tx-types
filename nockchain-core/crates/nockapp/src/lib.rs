#![feature(slice_pattern)]

//! # Nockapp Core
//!
//! Core Noun functionality and utilities for working with Urbit nouns.
//!
//! ## Modules
//!
//! - `noun`: Extensions and utilities for working with Urbit nouns.
//! - `utils`: Errors and byte conversion utilities.
//!
pub mod noun;
pub mod utils;

pub use bytes::*;
pub use nockvm::noun::Noun;
pub use noun::{AtomExt, JammedNoun, NounExt};
pub use utils::bytes::{ToBytes, ToBytesExt};
pub use utils::error::{CrownError, NockAppError, Result};
