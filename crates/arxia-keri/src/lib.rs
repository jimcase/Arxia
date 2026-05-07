//! # arxia-keri: KERI Identity and Wallet Integration for Arxia
//!
//! This crate provides KERI-based identity and wallet functionality for Arxia,
//! enabling dynamic key rotation, pre-rotation security, delegation, and
//! cross-ecosystem interoperability.

pub mod error;
pub mod wallet;
pub mod identity;
pub mod events;
pub mod crypto;
pub mod bridge;

pub use error::Error;
pub use wallet::{ArxiaKeriWallet, KeriConfig, derivation};
pub use identity::{IdentityManager, KeriIdentity};
pub use events::{EventBridge, ArxiaSealer, ArxiaTxData, ArxiaBlockData};
pub use crypto::{ArxiaCryptoBox, ArxiaKeyManager};
pub use bridge::{DelegationBridge, DelegationProof, DelegatedInceptionData, Transaction, SignedTransaction, KeriDelegator};

pub type Result<T> = std::result::Result<T, Error>;

pub const KERI_VERSION: &str = env!("CARGO_PKG_VERSION");