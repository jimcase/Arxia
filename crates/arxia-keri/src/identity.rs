//! KERI Identity Management
//!
//! This module handles KERI identity lifecycle including:
//! - Inception (ICP): Creating a new KERI identity
//! - Rotation (ROT): Rotating keys with pre-rotation
//! - Delegation (DIP/DRT): Hierarchical identity control

use keri_core::prefix::IdentifierPrefix;
use crate::crypto::{ArxiaCryptoBox, ArxiaKeyManager};
use crate::Result;

pub struct IdentityManager {
    crypto_box: ArxiaCryptoBox,
    prefix: IdentifierPrefix,
}

impl IdentityManager {
    pub fn new() -> Result<Self> {
        let crypto_box = ArxiaCryptoBox::new()?;
        let prefix = IdentifierPrefix::Basic(crypto_box.public_key());

        Ok(Self { crypto_box, prefix })
    }

    pub fn prefix(&self) -> &IdentifierPrefix {
        &self.prefix
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.crypto_box.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.crypto_box.verify(message, signature)
    }

    pub fn current_sn(&self) -> u64 {
        self.crypto_box.current_sn()
    }

    pub fn rotate_prep(&mut self) -> Result<()> {
        self.crypto_box.rotate_prep()
    }
}

pub struct KeriIdentity {
    pub prefix: IdentifierPrefix,
    pub key_manager: ArxiaKeyManager,
}

impl KeriIdentity {
    pub fn new(threshold: u64) -> Result<Self> {
        let key_manager = ArxiaKeyManager::new(threshold)?;

        Ok(Self {
            prefix: IdentifierPrefix::Basic(key_manager.public_key()),
            key_manager,
        })
    }

    pub fn prepare_rotation(&mut self) -> Result<()> {
        self.key_manager.prepare_next_key()
    }

    pub fn next_key_hash(&self) -> Result<keri_core::prefix::SelfSigningPrefix> {
        self.key_manager.next_key_hash()
    }
}