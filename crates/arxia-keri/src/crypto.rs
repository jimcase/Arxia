//! Cryptographic operations and CryptoBox for KERI key management
//!
//! This module implements the CryptoBox pattern with pre-rotation support.

use keri_core::prefix::{BasicPrefix, SelfSigningPrefix};
use keri_core::signer::CryptoBox;
use crate::error::Error;
use crate::Result;

pub struct ArxiaCryptoBox {
    crypto_box: CryptoBox,
    current_sn: u64,
}

impl ArxiaCryptoBox {
    pub fn new() -> Result<Self> {
        let crypto_box = CryptoBox::new()
            .map_err(|e| Error::SeedError(e.to_string()))?;

        Ok(Self {
            crypto_box,
            current_sn: 0,
        })
    }

    pub fn public_key(&self) -> BasicPrefix {
        use keri_core::signer::KeyManager;
        let pk = self.crypto_box.public_key();
        BasicPrefix::Ed25519(pk)
    }

    pub fn next_public_key(&self) -> Option<BasicPrefix> {
        use keri_core::signer::KeyManager;
        let pk = self.crypto_box.next_public_key();
        Some(BasicPrefix::Ed25519(pk))
    }

    pub fn current_sn(&self) -> u64 {
        self.current_sn
    }

    pub fn increment_sn(&mut self) {
        self.current_sn += 1;
    }

    pub fn rotate_prep(&mut self) -> Result<()> {
        use keri_core::signer::KeyManager;
        self.crypto_box.rotate().map_err(|e| Error::SeedError(e.to_string()))
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use keri_core::signer::KeyManager;
        self.crypto_box.sign(message).unwrap_or_default()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use keri_core::signer::KeyManager;
        self.crypto_box.public_key().verify_ed(message, signature)
    }
}

pub struct ArxiaKeyManager {
    crypto_box: ArxiaCryptoBox,
    threshold: u64,
}

impl ArxiaKeyManager {
    pub fn new(threshold: u64) -> Result<Self> {
        let crypto_box = ArxiaCryptoBox::new()?;
        Ok(Self { crypto_box, threshold })
    }

    pub fn public_key(&self) -> BasicPrefix {
        self.crypto_box.public_key()
    }

    pub fn next_key_hash(&self) -> Result<SelfSigningPrefix> {
        use keri_core::prefix::CesrPrimitive;

        let next_pk = self.crypto_box.next_public_key()
            .ok_or_else(|| Error::CryptoError("Next key not prepared".into()))?;

        let pk_str = next_pk.to_str();
        let hash = blake3::hash(pk_str.as_bytes());

        Ok(SelfSigningPrefix::Ed25519Sha512(hash.as_bytes().to_vec()))
    }

    pub fn prepare_next_key(&mut self) -> Result<()> {
        self.crypto_box.rotate_prep()
    }

    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.crypto_box.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.crypto_box.verify(message, signature)
    }
}