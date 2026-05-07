//! Arxia KERI Wallet Implementation
//!
//! This module provides the main wallet interface for Arxia, combining
//! KERI's self-certifying identity with Arxia's mesh consensus.

use keri_core::prefix::{BasicPrefix, IdentifierPrefix};
use crate::crypto::ArxiaCryptoBox;
use crate::events::EventBridge;
use crate::Result;

pub struct KeriConfig {
    pub witnesses: Vec<BasicPrefix>,
    pub witness_threshold: u64,
    pub key_threshold: u64,
}

impl Default for KeriConfig {
    fn default() -> Self {
        Self {
            witnesses: vec![],
            witness_threshold: 0,
            key_threshold: 1,
        }
    }
}

pub struct ArxiaKeriWallet {
    crypto_box: ArxiaCryptoBox,
    prefix: IdentifierPrefix,
    bridge: EventBridge,
    #[allow(dead_code)]
    config: KeriConfig,
}

impl ArxiaKeriWallet {
    pub fn new(config: KeriConfig) -> Result<Self> {
        let crypto_box = ArxiaCryptoBox::new()?;
        let prefix = IdentifierPrefix::Basic(crypto_box.public_key());
        let bridge = EventBridge::new(prefix.clone());

        Ok(Self {
            crypto_box,
            prefix,
            bridge,
            config,
        })
    }

    pub fn from_existing(
        prefix: IdentifierPrefix,
        config: KeriConfig,
    ) -> Result<Self> {
        let crypto_box = ArxiaCryptoBox::new()?;
        let bridge = EventBridge::new(prefix.clone());

        Ok(Self {
            crypto_box,
            prefix,
            bridge,
            config,
        })
    }

    pub fn identifier(&self) -> IdentifierPrefix {
        self.prefix.clone()
    }

    pub fn current_sn(&self) -> u64 {
        self.crypto_box.current_sn()
    }

    pub fn increment_sn(&mut self) {
        self.crypto_box.increment_sn();
    }

    pub fn public_key(&self) -> BasicPrefix {
        self.crypto_box.public_key()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.crypto_box.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.crypto_box.verify(message, signature)
    }

    pub fn rotate_prep(&mut self) -> Result<()> {
        self.crypto_box.rotate_prep()
    }

    pub fn anchor_block(&self, block_hash: &[u8]) -> Vec<u8> {
        self.bridge.compute_block_digest(block_hash)
    }
}

pub mod derivation {
    pub const PURPOSE_IDENTITY: u32 = 44;
    pub const COIN_TYPE_ARXIA: u32 = 617;
    pub const CHANGE_EXTERNAL: u32 = 0;
    pub const CHANGE_INTERNAL: u32 = 1;

    pub fn primary_path() -> [u32; 5] {
        [PURPOSE_IDENTITY, COIN_TYPE_ARXIA, CHANGE_EXTERNAL, 0, 0]
    }

    pub fn recovery_path() -> [u32; 5] {
        [PURPOSE_IDENTITY, COIN_TYPE_ARXIA, CHANGE_EXTERNAL, 0, 1]
    }
}