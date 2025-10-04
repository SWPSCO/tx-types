use crate::crypto::cheetah::cheetah_pub_from_sk;
use crate::crypto::cheetah::{xprv_derive_child, xpub_derive_child, XKey};
use crate::crypto::slip10::{CryptoError, Result};

/// Wrapper around `XKey` that provides SLIP-10 API
#[derive(Clone)]
pub struct ExtendedKey {
    inner: XKey,
}

impl ExtendedKey {
    pub fn from_master(private_key: [u8; 32], chain_code: [u8; 32]) -> Self {
        Self {
            inner: XKey::from_master(private_key, chain_code),
        }
    }

    pub fn from_xkey(inner: XKey) -> Self {
        Self { inner }
    }

    pub fn private_key_bytes(&self) -> Option<[u8; 32]> {
        self.inner.sk
    }

    pub fn chain_code(&self) -> [u8; 32] {
        self.inner.chain_code
    }

    pub fn derive_child(&self, index: u32) -> Result<Self> {
        let child = if self.inner.sk.is_some() {
            xprv_derive_child(&self.inner, index)
        } else if index & 0x8000_0000 != 0 {
            return Err(CryptoError::DerivationFailed);
        } else {
            xpub_derive_child(&self.inner, index)
        };
        Ok(Self { inner: child })
    }

    pub fn public_key(&self) -> Option<([u64; 6], [u64; 6])> {
        if let Some(pk) = self.inner.pk {
            Some(pk)
        } else if let Some(sk) = self.inner.sk {
            Some(cheetah_pub_from_sk(sk))
        } else {
            None
        }
    }

    pub fn depth(&self) -> u8 {
        self.inner.depth
    }

    pub fn index(&self) -> u32 {
        self.inner.index
    }

    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.inner.parent_fingerprint
    }

    pub fn as_xkey(&self) -> &XKey {
        &self.inner
    }
}

#[derive(Debug, Clone)]
pub enum DerivationError {
    DerivationFailed,
}

impl core::fmt::Display for DerivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DerivationError::DerivationFailed => write!(f, "key derivation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DerivationError {}
