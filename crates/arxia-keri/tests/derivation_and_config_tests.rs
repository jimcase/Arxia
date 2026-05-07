use arxia_keri::{
    derivation,
    ArxiaKeriWallet,
    KeriConfig,
};

#[test]
fn test_primary_path_length() {
    let path = derivation::primary_path();
    assert_eq!(path.len(), 5, "Derivation path should have 5 elements");
}

#[test]
fn test_recovery_path_length() {
    let path = derivation::recovery_path();
    assert_eq!(path.len(), 5, "Recovery path should have 5 elements");
}

#[test]
fn test_primary_path_first_three_elements() {
    let path = derivation::primary_path();
    assert_eq!(path[0], derivation::PURPOSE_IDENTITY);
    assert_eq!(path[1], derivation::COIN_TYPE_ARXIA);
    assert_eq!(path[2], derivation::CHANGE_EXTERNAL);
}

#[test]
fn test_recovery_path_first_three_elements() {
    let path = derivation::recovery_path();
    assert_eq!(path[0], derivation::PURPOSE_IDENTITY);
    assert_eq!(path[1], derivation::COIN_TYPE_ARXIA);
    assert_eq!(path[2], derivation::CHANGE_EXTERNAL);
}

#[test]
fn test_primary_and_recovery_paths_are_different() {
    let primary = derivation::primary_path();
    let recovery = derivation::recovery_path();
    assert_ne!(primary, recovery, "Primary and recovery paths should differ");
}

#[test]
fn test_derivation_constants_values() {
    assert_eq!(derivation::PURPOSE_IDENTITY, 44);
    assert_eq!(derivation::COIN_TYPE_ARXIA, 617);
    assert_eq!(derivation::CHANGE_EXTERNAL, 0);
    assert_eq!(derivation::CHANGE_INTERNAL, 1);
}

#[test]
fn test_primary_path_last_two_elements_are_zero() {
    let path = derivation::primary_path();
    assert_eq!(path[3], 0, "Primary path index 3 should be 0");
    assert_eq!(path[4], 0, "Primary path index 4 should be 0");
}

#[test]
fn test_recovery_path_last_two_elements() {
    let path = derivation::recovery_path();
    assert_eq!(path[3], 0, "Recovery path index 3 should be 0");
    assert_eq!(path[4], 1, "Recovery path index 4 should be 1 for recovery");
}

#[test]
fn test_primary_path_represents_main_identity_key() {
    let path = derivation::primary_path();
    assert_eq!(path[3], 0, "First identity key uses index 0");
    assert_eq!(path[4], 0, "First key in chain is 0");
}

#[test]
fn test_recovery_path_represents_backup_identity_key() {
    let path = derivation::recovery_path();
    assert_eq!(path[3], 0, "Second identity key uses index 0");
    assert_eq!(path[4], 1, "Second key in chain is 1");
}

#[test]
fn test_coin_type_arxia_is_consistent() {
    let primary = derivation::primary_path();
    let recovery = derivation::recovery_path();

    assert_eq!(primary[1], derivation::COIN_TYPE_ARXIA);
    assert_eq!(recovery[1], derivation::COIN_TYPE_ARXIA);
}

#[test]
fn test_purpose_identity_is_bip44() {
    let primary = derivation::primary_path();
    assert_eq!(primary[0], 44, "BIP44 purpose for identity is 44");
}

#[test]
fn test_wallet_with_empty_witnesses() {
    let config = KeriConfig::default();
    assert!(config.witnesses.is_empty());
    assert_eq!(config.witness_threshold, 0);
}

#[test]
fn test_wallet_config_with_witness_threshold() {
    let config = KeriConfig {
        witnesses: vec![],
        witness_threshold: 2,
        key_threshold: 1,
    };

    assert_eq!(config.witness_threshold, 2);
    assert!(config.witnesses.is_empty());
}

#[test]
fn test_wallet_config_with_key_threshold() {
    let config = KeriConfig {
        witnesses: vec![],
        witness_threshold: 0,
        key_threshold: 3,
    };

    assert_eq!(config.key_threshold, 3);
}

#[test]
fn test_multiple_wallet_instances_have_unique_identifiers() {
    let wallet1 = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();
    let wallet2 = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();
    let wallet3 = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    let id1 = wallet1.identifier();
    let id2 = wallet2.identifier();
    let id3 = wallet3.identifier();

    assert_ne!(format!("{:?}", id1), format!("{:?}", id2));
    assert_ne!(format!("{:?}", id2), format!("{:?}", id3));
    assert_ne!(format!("{:?}", id1), format!("{:?}", id3));
}

#[test]
fn test_wallet_identifier_persists_across_sign_operations() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();

    let original_id = wallet.identifier();

    for i in 0..100 {
        let msg = format!("Message {}", i);
        let sig = wallet.sign(msg.as_bytes());
        assert!(wallet.verify(msg.as_bytes(), &sig));
    }

    assert_eq!(format!("{:?}", original_id), format!("{:?}", wallet.identifier()));
}

#[test]
fn test_wallet_public_key_persists_across_sign_operations() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();

    let original_pk = wallet.public_key();

    for _ in 0..50 {
        let sig = wallet.sign(b"test");
        assert!(wallet.verify(b"test", &sig));
    }

    assert_eq!(format!("{:?}", original_pk), format!("{:?}", wallet.public_key()));
}

#[test]
fn test_wallet_sn_starts_at_zero() {
    let wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();
    assert_eq!(wallet.current_sn(), 0);
}

#[test]
fn test_wallet_sn_increments_correctly() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    assert_eq!(wallet.current_sn(), 0);
    wallet.increment_sn();
    assert_eq!(wallet.current_sn(), 1);
    wallet.increment_sn();
    assert_eq!(wallet.current_sn(), 2);
    wallet.increment_sn();
    assert_eq!(wallet.current_sn(), 3);
}

#[test]
fn test_wallet_from_existing_with_different_configs() {
    let original = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();
    let original_id = original.identifier();

    let config2 = KeriConfig {
        witnesses: vec![],
        witness_threshold: 2,
        key_threshold: 2,
    };

    let restored = ArxiaKeriWallet::from_existing(original_id.clone(), config2);
    assert!(restored.is_ok());
    assert_eq!(format!("{:?}", original_id), format!("{:?}", restored.unwrap().identifier()));
}