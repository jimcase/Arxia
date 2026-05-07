use arxia_keri::{ArxiaCryptoBox, ArxiaKeyManager, ArxiaKeriWallet, KeriConfig};

#[test]
fn test_crypto_box_signature_length() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Test message for signature";

    let signature = crypto_box.sign(message);

    assert_eq!(signature.len(), 64, "Ed25519 signature should be 64 bytes");
}

#[test]
fn test_crypto_box_signature_is_deterministic() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Deterministic message test";

    let sig1 = crypto_box.sign(message);
    let sig2 = crypto_box.sign(message);

    assert_eq!(sig1, sig2, "Same message should produce same signature");
}

#[test]
fn test_crypto_box_different_messages_different_signatures() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message1 = b"Message 1";
    let message2 = b"Message 2";

    let sig1 = crypto_box.sign(message1);
    let sig2 = crypto_box.sign(message2);

    assert_ne!(sig1, sig2, "Different messages should produce different signatures");
}

#[test]
fn test_key_manager_threshold() {
    let km1 = ArxiaKeyManager::new(1).unwrap();
    let km2 = ArxiaKeyManager::new(3).unwrap();
    let km3 = ArxiaKeyManager::new(5).unwrap();

    assert_eq!(km1.threshold(), 1);
    assert_eq!(km2.threshold(), 3);
    assert_eq!(km3.threshold(), 5);
}

#[test]
fn test_signature_with_different_keys_are_different() {
    let crypto_box1 = ArxiaCryptoBox::new().unwrap();
    let crypto_box2 = ArxiaCryptoBox::new().unwrap();
    let message = b"Same message, different keys";

    let sig1 = crypto_box1.sign(message);
    let sig2 = crypto_box2.sign(message);

    assert_ne!(sig1, sig2, "Same message with different keys should produce different signatures");
}

#[test]
fn test_signature_verification_with_public_key() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Verification test message";

    let signature = crypto_box.sign(message);

    let is_valid = crypto_box.verify(message, &signature);
    assert!(is_valid, "Signature should verify with same crypto_box");
}

#[test]
fn test_wallet_identifier_format() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();
    let identifier = wallet.identifier();

    let id_str = format!("{:?}", identifier);
    assert!(id_str.starts_with("Basic"), "Identifier should start with 'Basic'");
}

#[test]
fn test_wallet_anchor_produces_32_bytes() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();

    let hash1 = wallet.anchor_block(b"block_1");
    let hash2 = wallet.anchor_block(b"block_2");

    assert_eq!(hash1.len(), 32, "Anchor should produce 32 byte hash");
    assert_eq!(hash2.len(), 32, "Anchor should produce 32 byte hash");
    assert_ne!(hash1, hash2, "Different blocks should produce different hashes");
}

#[test]
fn test_wallet_anchor_is_deterministic_per_wallet() {
    let wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();
    let block = b"consistent_block";

    let hash1 = wallet.anchor_block(block);
    let hash2 = wallet.anchor_block(block);

    assert_eq!(hash1, hash2, "Same wallet should produce same anchor for same block");
}

#[test]
fn test_arxia_public_key_is_different_after_rotation_prep() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    let pk_before = wallet.public_key();
    wallet.rotate_prep().unwrap();
    let pk_after = wallet.public_key();

    assert_ne!(
        format!("{:?}", pk_before),
        format!("{:?}", pk_after),
        "Public key should change after rotation prep"
    );
}

#[test]
fn test_signature_survives_round_trip() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Round trip test message";

    let signature = crypto_box.sign(message);

    let serialized = signature.clone();
    let deserialized = serialized;

    let is_valid = crypto_box.verify(message, &deserialized);
    assert!(is_valid, "Signature should be valid after round trip");
}

#[test]
fn test_empty_message_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"";

    let signature = crypto_box.sign(message);
    assert_eq!(signature.len(), 64);

    let is_valid = crypto_box.verify(message, &signature);
    assert!(is_valid, "Empty message should verify correctly");
}

#[test]
fn test_large_message_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = vec![0u8; 10000];

    let signature = crypto_box.sign(&message);
    assert_eq!(signature.len(), 64);

    let is_valid = crypto_box.verify(&message, &signature);
    assert!(is_valid, "Large message should verify correctly");
}

#[test]
fn test_binary_message_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message: Vec<u8> = (0..255).collect();

    let signature = crypto_box.sign(&message);
    assert_eq!(signature.len(), 64);

    let is_valid = crypto_box.verify(&message, &signature);
    assert!(is_valid, "Binary message should verify correctly");
}

#[test]
fn test_unicode_message_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = "Hello, KERI! 你好, 世界! 🌍";

    let signature = crypto_box.sign(message.as_bytes());
    assert_eq!(signature.len(), 64);

    let is_valid = crypto_box.verify(message.as_bytes(), &signature);
    assert!(is_valid, "Unicode message should verify correctly");
}

#[test]
fn test_wallet_can_sign_multiple_messages() {
    let config = KeriConfig::default();
    let wallet = ArxiaKeriWallet::new(config).unwrap();

    let msg1 = b"First message";
    let msg2 = b"Second message";
    let msg3 = b"Third message";

    let sig1 = wallet.sign(msg1);
    let sig2 = wallet.sign(msg2);
    let sig3 = wallet.sign(msg3);

    assert!(wallet.verify(msg1, &sig1));
    assert!(wallet.verify(msg2, &sig2));
    assert!(wallet.verify(msg3, &sig3));

    assert_ne!(sig1, sig2);
    assert_ne!(sig2, sig3);
    assert_ne!(sig1, sig3);
}

#[test]
fn test_wallet_sn_increments() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    assert_eq!(wallet.current_sn(), 0);

    wallet.increment_sn();
    assert_eq!(wallet.current_sn(), 1);

    wallet.increment_sn();
    assert_eq!(wallet.current_sn(), 2);
}

#[test]
fn test_multiple_rotations_produce_different_keys() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    let pk0 = wallet.public_key();

    wallet.rotate_prep().unwrap();
    let pk1 = wallet.public_key();

    wallet.rotate_prep().unwrap();
    let pk2 = wallet.public_key();

    wallet.rotate_prep().unwrap();
    let pk3 = wallet.public_key();

    assert_ne!(format!("{:?}", pk0), format!("{:?}", pk1));
    assert_ne!(format!("{:?}", pk1), format!("{:?}", pk2));
    assert_ne!(format!("{:?}", pk2), format!("{:?}", pk3));
}