use arxia_keri::{
    ArxiaCryptoBox, ArxiaKeyManager, ArxiaKeriWallet, ArxiaSealer, EventBridge,
    IdentityManager, KeriConfig, KeriIdentity,
};
use arxia_keri::derivation;
use keri_core::keys::PublicKey;
use keri_core::prefix::{BasicPrefix, IdentifierPrefix};

fn create_test_prefix() -> IdentifierPrefix {
    let pk = PublicKey::new(vec![0u8; 32]);
    let bp = BasicPrefix::Ed25519(pk);
    IdentifierPrefix::Basic(bp)
}

#[test]
fn test_crypto_box_creation() {
    let crypto_box = ArxiaCryptoBox::new();
    assert!(crypto_box.is_ok());

    let crypto_box = crypto_box.unwrap();
    assert_eq!(crypto_box.current_sn(), 0);
}

#[test]
fn test_crypto_box_public_key() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let pk = crypto_box.public_key();
    assert!(!format!("{:?}", pk).is_empty());
}

#[test]
fn test_crypto_box_sign_and_verify() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Hello, KERI!";

    let signature = crypto_box.sign(message);
    assert!(!signature.is_empty());

    let is_valid = crypto_box.verify(message, &signature);
    assert!(is_valid);
}

#[test]
fn test_crypto_box_verify_fails_wrong_message() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Hello, KERI!";
    let wrong_message = b"Hello, World!";

    let signature = crypto_box.sign(message);
    let is_valid = crypto_box.verify(wrong_message, &signature);
    assert!(!is_valid);
}

#[test]
fn test_crypto_box_verify_fails_wrong_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Hello, KERI!";
    let wrong_signature = vec![0u8; 64];

    let is_valid = crypto_box.verify(message, &wrong_signature);
    assert!(!is_valid);
}

#[test]
fn test_crypto_box_next_key_available_after_creation() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let next_pk = crypto_box.next_public_key();
    assert!(next_pk.is_some(), "CryptoBox should have next key available after creation");
}

#[test]
fn test_crypto_box_rotate_prep_changes_next_key() {
    let mut crypto_box = ArxiaCryptoBox::new().unwrap();

    let next_pk_before = crypto_box.next_public_key();
    assert!(next_pk_before.is_some());

    crypto_box.rotate_prep().unwrap();

    let next_pk_after = crypto_box.next_public_key();
    assert!(next_pk_after.is_some());

    assert_ne!(format!("{:?}", next_pk_before), format!("{:?}", next_pk_after));
}

#[test]
fn test_crypto_box_increment_sn() {
    let mut crypto_box = ArxiaCryptoBox::new().unwrap();
    assert_eq!(crypto_box.current_sn(), 0);

    crypto_box.increment_sn();
    assert_eq!(crypto_box.current_sn(), 1);

    crypto_box.increment_sn();
    assert_eq!(crypto_box.current_sn(), 2);
}

#[test]
fn test_multiple_crypto_boxes_have_different_keys() {
    let crypto_box1 = ArxiaCryptoBox::new().unwrap();
    let crypto_box2 = ArxiaCryptoBox::new().unwrap();

    let pk1 = crypto_box1.public_key();
    let pk2 = crypto_box2.public_key();

    assert_ne!(format!("{:?}", pk1), format!("{:?}", pk2));
}

#[test]
fn test_key_manager_creation() {
    let key_manager = ArxiaKeyManager::new(2);
    assert!(key_manager.is_ok());

    let key_manager = key_manager.unwrap();
    assert_eq!(key_manager.threshold(), 2);
}

#[test]
fn test_key_manager_sign_and_verify() {
    let key_manager = ArxiaKeyManager::new(1).unwrap();
    let message = b"Test message for signing";

    let signature = key_manager.sign(message);
    assert!(!signature.is_empty());

    let is_valid = key_manager.verify(message, &signature);
    assert!(is_valid);
}

#[test]
fn test_key_manager_prepare_next_key_changes_hash() {
    let mut key_manager = ArxiaKeyManager::new(1).unwrap();

    let hash_before = key_manager.next_key_hash();
    assert!(hash_before.is_ok());

    key_manager.prepare_next_key().unwrap();

    let hash_after = key_manager.next_key_hash();
    assert!(hash_after.is_ok());

    assert_ne!(format!("{:?}", hash_before.unwrap()), format!("{:?}", hash_after.unwrap()));
}

#[test]
fn test_identity_manager_creation() {
    let manager = IdentityManager::new();
    assert!(manager.is_ok());
}

#[test]
fn test_identity_manager_sign_and_verify() {
    let manager = IdentityManager::new().unwrap();
    let message = b"Test identity message";

    let signature = manager.sign(message);
    assert!(!signature.is_empty());

    let is_valid = manager.verify(message, &signature);
    assert!(is_valid);
}

#[test]
fn test_identity_manager_verify_fails_wrong_message() {
    let manager = IdentityManager::new().unwrap();
    let message = b"Original message";
    let wrong_message = b"Modified message";

    let signature = manager.sign(message);
    let is_valid = manager.verify(wrong_message, &signature);
    assert!(!is_valid);
}

#[test]
fn test_identity_manager_current_sn() {
    let manager = IdentityManager::new().unwrap();
    assert_eq!(manager.current_sn(), 0);
}

#[test]
fn test_identity_manager_rotate_prep() {
    let mut manager = IdentityManager::new().unwrap();
    let result = manager.rotate_prep();
    assert!(result.is_ok());
}

#[test]
fn test_identity_manager_different_identities_have_different_prefixes() {
    let manager1 = IdentityManager::new().unwrap();
    let manager2 = IdentityManager::new().unwrap();
    assert_ne!(format!("{:?}", manager1.prefix()), format!("{:?}", manager2.prefix()));
}

#[test]
fn test_keri_identity_creation() {
    let identity = KeriIdentity::new(1);
    assert!(identity.is_ok());
}

#[test]
fn test_keri_identity_sign_and_verify() {
    let identity = KeriIdentity::new(1).unwrap();
    let message = b"KERI identity test message";

    let signature = identity.key_manager.sign(message);
    assert!(!signature.is_empty());

    let is_valid = identity.key_manager.verify(message, &signature);
    assert!(is_valid);
}

#[test]
fn test_keri_identity_prepare_rotation() {
    let mut identity = KeriIdentity::new(1).unwrap();
    let result = identity.prepare_rotation();
    assert!(result.is_ok());
}

#[test]
fn test_keri_identity_next_key_hash_changes_after_rotation() {
    let mut identity = KeriIdentity::new(1).unwrap();

    let hash_before = identity.next_key_hash();
    assert!(hash_before.is_ok());

    identity.prepare_rotation().unwrap();

    let hash_after = identity.next_key_hash();
    assert!(hash_after.is_ok());

    assert_ne!(format!("{:?}", hash_before.unwrap()), format!("{:?}", hash_after.unwrap()));
}

#[test]
fn test_keri_identity_different_identities_have_different_keys() {
    let identity1 = KeriIdentity::new(1).unwrap();
    let identity2 = KeriIdentity::new(1).unwrap();
    assert_ne!(format!("{:?}", identity1.prefix), format!("{:?}", identity2.prefix));
}

#[test]
fn test_keri_identity_with_different_thresholds() {
    let identity1 = KeriIdentity::new(1).unwrap();
    let identity2 = KeriIdentity::new(3).unwrap();
    let identity3 = KeriIdentity::new(5).unwrap();

    assert_eq!(identity1.key_manager.threshold(), 1);
    assert_eq!(identity2.key_manager.threshold(), 3);
    assert_eq!(identity3.key_manager.threshold(), 5);
}

#[test]
fn test_keri_config_default() {
    let config = KeriConfig::default();
    assert!(config.witnesses.is_empty());
    assert_eq!(config.witness_threshold, 0);
    assert_eq!(config.key_threshold, 1);
}

#[test]
fn test_wallet_creation() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config);
    assert!(wallet.is_ok());
}

#[test]
fn test_wallet_identifier() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();
    let identifier = wallet.identifier();
    assert!(!format!("{:?}", identifier).is_empty());
}

#[test]
fn test_wallet_public_key() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();
    let pk = wallet.public_key();
    assert!(!format!("{:?}", pk).is_empty());
}

#[test]
fn test_wallet_current_sn() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();
    assert_eq!(wallet.current_sn(), 0);
}

#[test]
fn test_wallet_sign_and_verify() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();

    let message = b"Arxia KERI wallet test";
    let signature = wallet.sign(message);

    assert!(!signature.is_empty());

    let is_valid = wallet.verify(message, &signature);
    assert!(is_valid);
}

#[test]
fn test_wallet_verify_fails_wrong_message() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();

    let message = b"Original message";
    let wrong_message = b"Different message";

    let signature = wallet.sign(message);
    let is_valid = wallet.verify(wrong_message, &signature);

    assert!(!is_valid);
}

#[test]
fn test_wallet_rotate_prep() {
    let config = KeriConfig::default();
    let mut wallet = ArxiaKeriWallet::new(config).unwrap();

    let result = wallet.rotate_prep();
    assert!(result.is_ok());
}

#[test]
fn test_wallet_anchor_block() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();

    let block_hash = b"test_block_123".to_vec();
    let digest = wallet.anchor_block(&block_hash);

    assert_eq!(digest.len(), 32);
}

#[test]
fn test_wallet_anchor_block_deterministic() {
    let wallet1 = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();
    let wallet2 = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    let block_hash = b"same_block".to_vec();
    let digest1 = wallet1.anchor_block(&block_hash);
    let digest2 = wallet2.anchor_block(&block_hash);

    assert_eq!(digest1, digest2);
}

#[test]
fn test_wallet_anchor_block_different_hashes() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();

    let hash1 = wallet.anchor_block(b"block_1");
    let hash2 = wallet.anchor_block(b"block_2");

    assert_ne!(hash1, hash2);
}

#[test]
fn test_wallet_from_existing() {
    let config = KeriConfig::default();
    let original = ArxiaKeriWallet::new(config).unwrap();
    let original_id = original.identifier().clone();

    let restored = ArxiaKeriWallet::from_existing(original_id.clone(), KeriConfig::default());
    assert!(restored.is_ok());

    let restored_id = restored.unwrap().identifier();
    assert_eq!(format!("{:?}", original_id), format!("{:?}", restored_id));
}

#[test]
fn test_wallet_different_wallets_have_different_identifiers() {
    let wallet1 = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();
    let wallet2 = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    assert_ne!(format!("{:?}", wallet1.identifier()), format!("{:?}", wallet2.identifier()));
}

#[test]
fn test_event_bridge_creation() {
    let prefix = create_test_prefix();
    let _bridge = EventBridge::new(prefix);
}

#[test]
fn test_compute_block_digest() {
    let prefix = create_test_prefix();
    let bridge = EventBridge::new(prefix);

    let block_hash = b"block_123".to_vec();
    let digest = bridge.compute_block_digest(&block_hash);

    assert_eq!(digest.len(), 32);
}

#[test]
fn test_compute_block_digest_deterministic() {
    let prefix = create_test_prefix();
    let bridge = EventBridge::new(prefix.clone());
    let bridge2 = EventBridge::new(prefix);

    let block_hash = b"same_block".to_vec();
    let digest1 = bridge.compute_block_digest(&block_hash);
    let digest2 = bridge2.compute_block_digest(&block_hash);

    assert_eq!(digest1, digest2);
}

#[test]
fn test_compute_block_digest_different_inputs() {
    let prefix = create_test_prefix();
    let bridge = EventBridge::new(prefix);

    let hash1 = bridge.compute_block_digest(b"block_1");
    let hash2 = bridge.compute_block_digest(b"block_2");

    assert_ne!(hash1, hash2);
}

#[test]
fn test_compute_tx_digest() {
    let prefix = create_test_prefix();
    let bridge = EventBridge::new(prefix);

    let digest = bridge.compute_tx_digest("tx_123", 1000, "recipient_address");

    assert_eq!(digest.len(), 32);
}

#[test]
fn test_compute_consensus_digest() {
    let prefix = create_test_prefix();
    let bridge = EventBridge::new(prefix);

    let value = b"consensus_value";
    let digest = bridge.compute_consensus_digest(value, 42);

    assert_eq!(digest.len(), 32);
}

#[test]
fn test_compute_consensus_digest_different_rounds() {
    let prefix = create_test_prefix();
    let bridge = EventBridge::new(prefix);

    let value = b"same_value";
    let digest1 = bridge.compute_consensus_digest(value, 1);
    let digest2 = bridge.compute_consensus_digest(value, 2);

    assert_ne!(digest1, digest2);
}

#[test]
fn test_arxia_sealer_seal_transaction() {
    let tx_data = arxia_keri::ArxiaTxData {
        tx_id: 12345,
        amount: 1000,
        recipient: "recipient_pubkey".to_string(),
        sender: "sender_pubkey".to_string(),
        timestamp: 1700000000,
    };

    let seal = ArxiaSealer::seal_transaction(&tx_data);
    assert_eq!(seal.len(), 32);
}

#[test]
fn test_arxia_sealer_seal_block() {
    let block_data = arxia_keri::ArxiaBlockData {
        height: 100,
        block_hash: b"block_hash_data".to_vec(),
        timestamp: 1700000000,
        tx_count: 50,
    };

    let seal = ArxiaSealer::seal_block(&block_data);
    assert_eq!(seal.len(), 32);
}

#[test]
fn test_arxia_sealer_different_txs_produce_different_seals() {
    let tx1 = arxia_keri::ArxiaTxData {
        tx_id: 1,
        amount: 100,
        recipient: "addr1".to_string(),
        sender: "sender1".to_string(),
        timestamp: 1000,
    };

    let tx2 = arxia_keri::ArxiaTxData {
        tx_id: 2,
        amount: 100,
        recipient: "addr1".to_string(),
        sender: "sender1".to_string(),
        timestamp: 1000,
    };

    let seal1 = ArxiaSealer::seal_transaction(&tx1);
    let seal2 = ArxiaSealer::seal_transaction(&tx2);

    assert_ne!(seal1, seal2);
}

#[test]
fn test_arxia_sealer_same_tx_produces_same_seal() {
    let tx = arxia_keri::ArxiaTxData {
        tx_id: 42,
        amount: 500,
        recipient: "addr".to_string(),
        sender: "sender".to_string(),
        timestamp: 2000,
    };

    let seal1 = ArxiaSealer::seal_transaction(&tx);
    let seal2 = ArxiaSealer::seal_transaction(&tx);

    assert_eq!(seal1, seal2);
}

#[test]
fn test_primary_path_structure() {
    let path = derivation::primary_path();
    assert_eq!(path.len(), 5);
    assert_eq!(path[0], derivation::PURPOSE_IDENTITY);
    assert_eq!(path[1], derivation::COIN_TYPE_ARXIA);
    assert_eq!(path[2], derivation::CHANGE_EXTERNAL);
}

#[test]
fn test_recovery_path_structure() {
    let path = derivation::recovery_path();
    assert_eq!(path.len(), 5);
    assert_eq!(path[0], derivation::PURPOSE_IDENTITY);
    assert_eq!(path[1], derivation::COIN_TYPE_ARXIA);
    assert_eq!(path[2], derivation::CHANGE_EXTERNAL);
}

#[test]
fn test_primary_and_recovery_paths_differ() {
    let primary = derivation::primary_path();
    let recovery = derivation::recovery_path();
    assert_ne!(primary, recovery);
}

#[test]
fn test_derivation_constants() {
    assert_eq!(derivation::PURPOSE_IDENTITY, 44);
    assert_eq!(derivation::COIN_TYPE_ARXIA, 617);
    assert_eq!(derivation::CHANGE_EXTERNAL, 0);
    assert_eq!(derivation::CHANGE_INTERNAL, 1);
}

#[test]
fn test_primary_path_last_indices() {
    let primary = derivation::primary_path();
    assert_eq!(primary[3], 0);
    assert_eq!(primary[4], 0);
}

#[test]
fn test_recovery_path_last_indices() {
    let recovery = derivation::recovery_path();
    assert_eq!(recovery[3], 0);
    assert_eq!(recovery[4], 1);
}