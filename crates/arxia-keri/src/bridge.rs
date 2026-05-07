//! Bridge between KERI delegation and Arxia transaction signing
//!
//! This module provides the `DelegationBridge` that allows Arxia accounts
//! to be controlled via KERI delegation, enabling secure key rotation
//! without losing access to funds.

use keri_core::prefix::{BasicPrefix, IdentifierPrefix};
use crate::crypto::ArxiaCryptoBox;
use crate::Result;

#[derive(Debug, Clone)]
pub struct DelegationProof {
    pub delegator: IdentifierPrefix,
    pub delegate_key: BasicPrefix,
    pub dip_hash: Vec<u8>,
    pub rotation_sn: u64,
    pub created_at: u64,
}

impl DelegationProof {
    pub fn new(
        delegator: IdentifierPrefix,
        delegate_key: BasicPrefix,
        dip_hash: Vec<u8>,
        rotation_sn: u64,
    ) -> Self {
        Self {
            delegator,
            delegate_key,
            dip_hash,
            rotation_sn,
            created_at: current_timestamp(),
        }
    }

    pub fn is_valid(&self, delegate_key: &BasicPrefix) -> bool {
        self.delegate_key == *delegate_key
    }
}

#[derive(Debug, Clone)]
pub struct DelegatedInceptionData {
    pub delegator: IdentifierPrefix,
    pub delegate_key: BasicPrefix,
    pub said: Vec<u8>,
    pub sn: u64,
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub fee: u64,
    pub data: Option<Vec<u8>>,
}

impl Transaction {
    pub fn new(to: String, amount: u64, nonce: u64) -> Self {
        Self {
            to,
            amount,
            nonce,
            fee: 0,
            data: None,
        }
    }

    pub fn with_fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(self.to.as_bytes());
        bytes.extend_from_slice(&self.amount.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes.extend_from_slice(&self.fee.to_be_bytes());

        if let Some(ref data) = self.data {
            bytes.extend_from_slice(data);
        }

        bytes
    }
}

pub struct SignedTransaction {
    pub transaction: Transaction,
    pub signature: Vec<u8>,
    pub delegation_proof: Option<DelegationProof>,
    pub chain_id: u32,
}

impl SignedTransaction {
    pub fn new(transaction: Transaction, signature: Vec<u8>) -> Self {
        Self {
            transaction,
            signature,
            delegation_proof: None,
            chain_id: 1,
        }
    }

    pub fn with_delegation(mut self, proof: DelegationProof) -> Self {
        self.delegation_proof = Some(proof);
        self
    }

    pub fn serialize_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.chain_id.to_be_bytes());
        bytes.extend_from_slice(&self.transaction.serialize());

        if let Some(ref proof) = self.delegation_proof {
            bytes.extend_from_slice(&proof.dip_hash);
            bytes.extend_from_slice(&proof.rotation_sn.to_be_bytes());
        }

        bytes
    }
}

pub struct DelegationBridge {
    delegator: IdentifierPrefix,
    arxia_signer: ArxiaCryptoBox,
    dip_data: Option<DelegatedInceptionData>,
    current_sn: u64,
}

impl DelegationBridge {
    pub fn new(delegator: IdentifierPrefix) -> Result<Self> {
        let arxia_signer = ArxiaCryptoBox::new()?;

        Ok(Self {
            delegator,
            arxia_signer,
            dip_data: None,
            current_sn: 0,
        })
    }

    pub fn delegator(&self) -> &IdentifierPrefix {
        &self.delegator
    }

    pub fn delegate_key(&self) -> BasicPrefix {
        self.arxia_signer.public_key()
    }

    pub fn current_sn(&self) -> u64 {
        self.current_sn
    }

    pub fn is_delegation_valid(&self) -> bool {
        self.dip_data.is_some()
    }

    pub fn get_delegation_proof(&self) -> Option<DelegationProof> {
        self.dip_data.as_ref().map(|dip| {
            DelegationProof::new(
                self.delegator.clone(),
                self.arxia_signer.public_key(),
                dip.said.clone(),
                dip.sn,
            )
        })
    }

    pub fn sign_transaction(&self, tx: &Transaction) -> Result<SignedTransaction> {
        let mut signed = SignedTransaction::new(
            tx.clone(),
            self.arxia_signer.sign(&tx.serialize()),
        );

        if let Some(proof) = self.get_delegation_proof() {
            signed = signed.with_delegation(proof);
        }

        Ok(signed)
    }

    pub fn sign_transaction_with_proof(&self, tx: &Transaction, proof: &DelegationProof) -> Result<SignedTransaction> {
        Ok(SignedTransaction::new(
            tx.clone(),
            self.arxia_signer.sign(&tx.serialize()),
        ).with_delegation(proof.clone()))
    }

    pub fn verify_delegation(&self, delegate_key: &BasicPrefix) -> bool {
        self.dip_data
            .as_ref()
            .map(|d| d.delegate_key == *delegate_key)
            .unwrap_or(false)
    }

    pub fn rotation_occurs(&mut self) {
        self.current_sn += 1;
    }

    pub fn set_delegation(&mut self, dip: DelegatedInceptionData) {
        self.dip_data = Some(dip);
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub struct KeriDelegator {
    keri_wallet: crate::ArxiaKeriWallet,
    delegations: Vec<DelegatedInceptionData>,
}

impl KeriDelegator {
    pub fn new(_seed: &[u8]) -> Result<Self> {
        let keri_wallet = crate::ArxiaKeriWallet::new(crate::KeriConfig::default())?;

        Ok(Self {
            keri_wallet,
            delegations: Vec::new(),
        })
    }

    pub fn keri_identifier(&self) -> IdentifierPrefix {
        self.keri_wallet.identifier()
    }

    pub fn create_delegation(&mut self, delegate_key: BasicPrefix) -> DelegatedInceptionData {
        let sn = self.keri_wallet.current_sn();
        let delegator = self.keri_wallet.identifier();

        let dip_hash = self.compute_dip_hash(&delegator, &delegate_key, sn);

        let dip = DelegatedInceptionData {
            delegator,
            delegate_key,
            said: dip_hash.clone(),
            sn,
        };

        self.delegations.push(dip.clone());
        dip
    }

    pub fn get_active_delegation(&self) -> Option<&DelegatedInceptionData> {
        self.delegations.last()
    }

    pub fn verify_delegate(&self, delegate_key: &BasicPrefix) -> bool {
        self.delegations
            .last()
            .map(|d| d.delegate_key == *delegate_key)
            .unwrap_or(false)
    }

    fn compute_dip_hash(&self, delegator: &IdentifierPrefix, delegate_key: &BasicPrefix, sn: u64) -> Vec<u8> {
        use keri_core::prefix::CesrPrimitive;

        let mut data = Vec::new();
        data.extend_from_slice(&delegator.to_str().as_bytes());
        data.extend_from_slice(&delegate_key.to_str().as_bytes());
        data.extend_from_slice(&sn.to_be_bytes());

        blake3::hash(&data).as_bytes().to_vec()
    }

    pub fn rotate_keri(&mut self) -> Result<()> {
        self.keri_wallet.rotate_prep()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_core::keys::PublicKey;
    use keri_core::prefix::{BasicPrefix, IdentifierPrefix};

    fn create_test_prefix() -> IdentifierPrefix {
        let pk = PublicKey::new(vec![0u8; 32]);
        let bp = BasicPrefix::Ed25519(pk);
        IdentifierPrefix::Basic(bp)
    }

    fn create_test_delegate_key() -> BasicPrefix {
        let pk = PublicKey::new(vec![1u8; 32]);
        BasicPrefix::Ed25519(pk)
    }

    #[test]
    fn test_delegation_proof_creation() {
        let delegator = create_test_prefix();
        let delegate_key = create_test_delegate_key();
        let dip_hash = vec![2u8; 32];

        let proof = DelegationProof::new(
            delegator.clone(),
            delegate_key.clone(),
            dip_hash.clone(),
            1,
        );

        assert!(proof.is_valid(&delegate_key));
        assert_eq!(proof.rotation_sn, 1);
    }

    #[test]
    fn test_delegation_proof_invalid_key() {
        let delegator = create_test_prefix();
        let delegate_key = create_test_delegate_key();
        let wrong_key = PublicKey::new(vec![9u8; 32]);

        let proof = DelegationProof::new(
            delegator,
            delegate_key,
            vec![2u8; 32],
            1,
        );

        assert!(!proof.is_valid(&BasicPrefix::Ed25519(wrong_key)));
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction::new("recipient123".to_string(), 1000, 42);
        let serialized = tx.serialize();

        assert!(serialized.len() > 0);
        assert!(serialized.starts_with(b"recipient123"));
    }

    #[test]
    fn test_transaction_with_fee_and_data() {
        let tx = Transaction::new("to456".to_string(), 500, 10)
            .with_fee(5)
            .with_data(b"memo".to_vec());

        assert_eq!(tx.fee, 5);
        assert!(tx.data.is_some());
    }

    #[test]
    fn test_signed_transaction_creation() {
        let tx = Transaction::new("dest".to_string(), 100, 1);
        let signature = vec![3u8; 64];

        let signed = SignedTransaction::new(tx.clone(), signature);

        assert_eq!(signed.signature.len(), 64);
        assert!(signed.delegation_proof.is_none());
    }

    #[test]
    fn test_signed_transaction_with_delegation() {
        let tx = Transaction::new("dest".to_string(), 100, 1);
        let signature = vec![3u8; 64];
        let delegator = create_test_prefix();
        let delegate_key = create_test_delegate_key();
        let proof = DelegationProof::new(delegator, delegate_key, vec![4u8; 32], 5);

        let signed = SignedTransaction::new(tx.clone(), signature)
            .with_delegation(proof.clone());

        assert!(signed.delegation_proof.is_some());
        assert_eq!(signed.delegation_proof.as_ref().unwrap().rotation_sn, 5);
    }

    #[test]
    fn test_delegation_bridge_creation() {
        let delegator = create_test_prefix();

        let bridge = DelegationBridge::new(delegator.clone()).unwrap();

        assert_eq!(bridge.delegator(), &delegator);
        assert!(!bridge.is_delegation_valid());
    }

    #[test]
    fn test_delegation_bridge_sign_transaction() {
        let delegator = create_test_prefix();
        let mut bridge = DelegationBridge::new(delegator.clone()).unwrap();

        let dip = DelegatedInceptionData {
            delegator,
            delegate_key: bridge.delegate_key(),
            said: vec![6u8; 32],
            sn: 1,
        };

        bridge.set_delegation(dip);

        let tx = Transaction::new("recipient".to_string(), 1000, 5);
        let signed = bridge.sign_transaction(&tx).unwrap();

        assert!(signed.signature.len() > 0);
        assert!(signed.delegation_proof.is_some());
    }

    #[test]
    fn test_delegation_bridge_rotation_occurs() {
        let delegator = create_test_prefix();
        let mut bridge = DelegationBridge::new(delegator.clone()).unwrap();

        assert_eq!(bridge.current_sn(), 0);

        bridge.rotation_occurs();
        assert_eq!(bridge.current_sn(), 1);

        bridge.rotation_occurs();
        assert_eq!(bridge.current_sn(), 2);
    }

    #[test]
    fn test_keri_delegator_creation() {
        let delegator = KeriDelegator::new(b"test_seed_for_delegator").unwrap();
        assert!(!delegator.keri_identifier().to_string().is_empty());
    }

    #[test]
    fn test_keri_delegator_create_delegation() {
        let mut delegator = KeriDelegator::new(b"test_seed_for_delegator").unwrap();
        let delegate_key = create_test_delegate_key();

        let dip = delegator.create_delegation(delegate_key.clone());

        assert!(!dip.said.is_empty());
        assert_eq!(dip.delegate_key, delegate_key);
    }

    #[test]
    fn test_keri_delegator_get_active_delegation() {
        let mut delegator = KeriDelegator::new(b"test_seed").unwrap();
        let delegate_key = create_test_delegate_key();

        assert!(delegator.get_active_delegation().is_none());

        delegator.create_delegation(delegate_key.clone());

        let active = delegator.get_active_delegation();
        assert!(active.is_some());
        assert_eq!(active.unwrap().delegate_key, delegate_key);
    }

    #[test]
    fn test_keri_delegator_verify_delegate() {
        let mut delegator = KeriDelegator::new(b"test_seed").unwrap();
        let delegate_key = create_test_delegate_key();

        assert!(!delegator.verify_delegate(&delegate_key));

        delegator.create_delegation(delegate_key.clone());

        assert!(delegator.verify_delegate(&delegate_key));
    }
}