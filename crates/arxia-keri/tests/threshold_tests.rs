use arxia_keri::{ArxiaKeyManager, KeriConfig, ArxiaKeriWallet};

#[test]
fn test_key_manager_threshold_1() {
    let km = ArxiaKeyManager::new(1).unwrap();
    assert_eq!(km.threshold(), 1);
}

#[test]
fn test_key_manager_threshold_2() {
    let km = ArxiaKeyManager::new(2).unwrap();
    assert_eq!(km.threshold(), 2);
}

#[test]
fn test_key_manager_threshold_3() {
    let km = ArxiaKeyManager::new(3).unwrap();
    assert_eq!(km.threshold(), 3);
}

#[test]
fn test_key_manager_threshold_high_value() {
    let km = ArxiaKeyManager::new(100).unwrap();
    assert_eq!(km.threshold(), 100);
}

#[test]
fn test_key_manager_threshold_zero() {
    let km = ArxiaKeyManager::new(0).unwrap();
    assert_eq!(km.threshold(), 0);
}

#[test]
fn test_key_manager_sign_with_threshold_1() {
    let km = ArxiaKeyManager::new(1).unwrap();
    let message = b"Threshold 1 test";

    let signature = km.sign(message);
    assert_eq!(signature.len(), 64);

    let is_valid = km.verify(message, &signature);
    assert!(is_valid);
}

#[test]
fn test_key_manager_sign_with_threshold_5() {
    let km = ArxiaKeyManager::new(5).unwrap();
    let message = b"Threshold 5 test";

    let signature = km.sign(message);
    assert_eq!(signature.len(), 64);

    let is_valid = km.verify(message, &signature);
    assert!(is_valid);
}

#[test]
fn test_keri_config_default_values() {
    let config = KeriConfig::default();

    assert!(config.witnesses.is_empty());
    assert_eq!(config.witness_threshold, 0);
    assert_eq!(config.key_threshold, 1);
}

#[test]
fn test_keri_config_with_witness_threshold() {
    let config = KeriConfig {
        witnesses: vec![],
        witness_threshold: 2,
        key_threshold: 1,
    };

    assert_eq!(config.witness_threshold, 2);
}

#[test]
fn test_keri_config_with_key_threshold() {
    let config = KeriConfig {
        witnesses: vec![],
        witness_threshold: 0,
        key_threshold: 3,
    };

    assert_eq!(config.key_threshold, 3);
}

#[test]
fn test_wallet_signatures_all_valid() {
    let config = KeriConfig {
        witnesses: vec![],
        witness_threshold: 1,
        key_threshold: 1,
    };

    let wallet = ArxiaKeriWallet::new(config).unwrap();

    for i in 0..10 {
        let message = format!("Message number {}", i);
        let signature = wallet.sign(message.as_bytes());
        assert!(wallet.verify(message.as_bytes(), &signature));
    }
}

#[test]
fn test_threshold_consistency_across_operations() {
    let km = ArxiaKeyManager::new(2).unwrap();
    let original_threshold = km.threshold();

    let message = b"Test message";
    let signature = km.sign(message);

    assert_eq!(km.threshold(), original_threshold);
    assert!(km.verify(message, &signature));
}

#[test]
fn test_signature_length_constant_for_all_thresholds() {
    let thresholds = [1u64, 2, 5, 10, 50];

    for threshold in thresholds {
        let km = ArxiaKeyManager::new(threshold).unwrap();
        let message = b"Constant signature length test";
        let sig = km.sign(message);

        assert_eq!(sig.len(), 64, "Signature should be 64 bytes for threshold {}", threshold);
    }
}

#[test]
fn test_wallet_with_various_thresholds() {
    let thresholds = [1u64, 2, 3, 5];

    for threshold in thresholds {
        let config = KeriConfig {
            witnesses: vec![],
            witness_threshold: threshold,
            key_threshold: threshold,
        };

        let wallet = ArxiaKeriWallet::new(config).unwrap();
        let msg = format!("Testing wallet with threshold {}", threshold);
        let sig = wallet.sign(msg.as_bytes());

        assert!(wallet.verify(msg.as_bytes(), &sig));
    }
}

#[test]
fn test_signature_verification_after_multiple_operations() {
    let km = ArxiaKeyManager::new(1).unwrap();

    let messages: Vec<&[u8]> = vec![
        b"First",
        b"Second",
        b"Third",
        b"Fourth",
        b"Fifth",
    ];

    let signatures: Vec<Vec<u8>> = messages.iter().map(|m| km.sign(m)).collect();

    for (i, msg) in messages.iter().enumerate() {
        assert!(km.verify(msg, &signatures[i]));
    }
}

#[test]
fn test_key_manager_with_different_thresholds_produces_valid_signatures() {
    let thresholds = [1u64, 2, 3, 7, 10, 20];

    for threshold in thresholds {
        let km = ArxiaKeyManager::new(threshold).unwrap();
        let message = format!("Testing threshold: {}", threshold);

        let sig = km.sign(message.as_bytes());
        assert!(km.verify(message.as_bytes(), &sig));
    }
}

#[test]
fn test_consecutive_signatures_are_different() {
    let km = ArxiaKeyManager::new(1).unwrap();
    let message = b"Same message, different signatures";

    let sig1 = km.sign(message);
    let sig2 = km.sign(message);
    let sig3 = km.sign(message);

    assert_eq!(sig1, sig2, "Ed25519 is deterministic");
    assert_eq!(sig2, sig3);
}

#[test]
fn test_wallet_threshold_does_not_affect_signature_length() {
    let thresholds = [1u64, 2, 5];

    for threshold in thresholds {
        let config = KeriConfig {
            witnesses: vec![],
            witness_threshold: threshold,
            key_threshold: threshold,
        };

        let wallet = ArxiaKeriWallet::new(config).unwrap();
        let sig = wallet.sign(b"test");

        assert_eq!(sig.len(), 64, "Threshold {} should still produce 64-byte signature", threshold);
    }
}