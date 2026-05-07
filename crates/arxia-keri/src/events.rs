//! Event Bridge between Arxia and KERI
//!
//! This module provides the bridge for anchoring Arxia operations
//! into the KERI event log and mapping KERI events to Arxia operations.

use keri_core::prefix::IdentifierPrefix;

pub struct EventBridge {
    #[allow(dead_code)]
    prefix: IdentifierPrefix,
}

impl EventBridge {
    pub fn new(prefix: IdentifierPrefix) -> Self {
        Self { prefix }
    }

    pub fn compute_block_digest(&self, block_hash: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"arxia_block");
        data.extend_from_slice(block_hash);
        blake3::hash(&data).as_bytes().to_vec()
    }

    pub fn compute_tx_digest(&self, tx_id: &str, amount: u64, recipient: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"arxia_tx");
        data.extend_from_slice(tx_id.as_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(recipient.as_bytes());
        blake3::hash(&data).as_bytes().to_vec()
    }

    pub fn compute_consensus_digest(&self, value: &[u8], round: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"arxia_consensus");
        data.extend_from_slice(value);
        data.extend_from_slice(&round.to_le_bytes());
        blake3::hash(&data).as_bytes().to_vec()
    }
}

pub struct ArxiaSealer;

impl ArxiaSealer {
    pub fn seal_transaction(tx_data: &ArxiaTxData) -> Vec<u8> {
        Self::compute_tx_hash(tx_data)
    }

    pub fn seal_block(block_data: &ArxiaBlockData) -> Vec<u8> {
        Self::compute_block_hash(block_data)
    }

    fn compute_tx_hash(data: &ArxiaTxData) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"arxia_tx");
        hasher.update(&data.tx_id.to_le_bytes());
        hasher.update(&data.amount.to_le_bytes());
        hasher.update(data.recipient.as_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    fn compute_block_hash(data: &ArxiaBlockData) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"arxia_block");
        hasher.update(&data.height.to_le_bytes());
        hasher.update(&data.block_hash);
        hasher.finalize().as_bytes().to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct ArxiaTxData {
    pub tx_id: u64,
    pub amount: u64,
    pub recipient: String,
    pub sender: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
pub struct ArxiaBlockData {
    pub height: u64,
    pub block_hash: Vec<u8>,
    pub timestamp: i64,
    pub tx_count: u64,
}