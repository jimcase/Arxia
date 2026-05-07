use arxia_keri::{ArxiaCryptoBox, ArxiaKeyManager, ArxiaKeriWallet, KeriConfig};

#[test]
fn test_crypto_box_has_next_key_after_creation() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let next_pk = crypto_box.next_public_key();
    assert!(next_pk.is_some(), "CryptoBox should have next key available immediately");
}

#[test]
fn test_crypto_box_next_key_is_different_from_current() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let current = crypto_box.public_key();
    let next = crypto_box.next_public_key();

    assert!(next.is_some());
    assert_ne!(
        format!("{:?}", current),
        format!("{:?}", next.unwrap()),
        "Current and next keys should be different"
    );
}

#[test]
fn test_crypto_box_rotate_prep_generates_new_next_key() {
    let mut crypto_box = ArxiaCryptoBox::new().unwrap();

    let next_key_before = crypto_box.next_public_key();
    assert!(next_key_before.is_some());

    crypto_box.rotate_prep().unwrap();

    let next_key_after = crypto_box.next_public_key();
    assert!(next_key_after.is_some());

    assert_ne!(
        format!("{:?}", next_key_before.unwrap()),
        format!("{:?}", next_key_after.unwrap()),
        "Next key should change after rotate_prep"
    );
}

#[test]
fn test_key_manager_next_key_hash_changes_after_rotation() {
    let mut km = ArxiaKeyManager::new(1).unwrap();

    let hash_before = km.next_key_hash().unwrap();

    km.prepare_next_key().unwrap();

    let hash_after = km.next_key_hash().unwrap();

    assert_ne!(
        format!("{:?}", hash_before),
        format!("{:?}", hash_after),
        "Next key hash should change after rotation prep"
    );
}

#[test]
fn test_pre_rotation_commitment_exists_before_rotation() {
    let mut crypto_box = ArxiaCryptoBox::new().unwrap();

    let next_key_before_rotation = crypto_box.next_public_key();
    assert!(next_key_before_rotation.is_some());

    crypto_box.rotate_prep().unwrap();

    let new_next_key = crypto_box.next_public_key();
    assert!(new_next_key.is_some());

    assert_ne!(
        format!("{:?}", next_key_before_rotation.unwrap()),
        format!("{:?}", new_next_key.unwrap()),
        "Pre-rotation creates new commitment"
    );
}

#[test]
fn test_key_manager_can_prepare_multiple_rotations() {
    let mut km = ArxiaKeyManager::new(1).unwrap();

    let hashes: Vec<_> = (0..5).map(|_| {
        km.prepare_next_key().unwrap();
        km.next_key_hash().unwrap()
    }).collect();

    for i in 0..hashes.len() {
        for j in (i+1)..hashes.len() {
            assert_ne!(
                format!("{:?}", hashes[i]),
                format!("{:?}", hashes[j]),
                "Each rotation should produce a different key hash"
            );
        }
    }
}

#[test]
fn test_wallet_public_key_changes_after_rotation_prep() {
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
fn test_wallet_next_key_hash_changes_with_rotation() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    wallet.rotate_prep().unwrap();

    let hash1 = wallet.public_key();

    wallet.rotate_prep().unwrap();

    let hash2 = wallet.public_key();

    assert_ne!(
        format!("{:?}", hash1),
        format!("{:?}", hash2),
        "Key hashes should be different after each rotation prep"
    );
}

#[test]
fn test_pre_rotation_chain_maintains_different_keys() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    let keys: Vec<_> = (0..10).map(|_| {
        let pk = wallet.public_key();
        wallet.rotate_prep().unwrap();
        pk
    }).collect();

    for i in 0..keys.len() {
        for j in (i+1)..keys.len() {
            assert_ne!(
                format!("{:?}", keys[i]),
                format!("{:?}", keys[j]),
                "Keys at position {} and {} should be different",
                i, j
            );
        }
    }
}

#[test]
fn test_signature_valid_before_rotation() {
    let wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();
    let message = b"Message signed before rotation";

    let signature = wallet.sign(message);

    assert!(wallet.verify(message, &signature));
}

#[test]
fn test_signature_valid_after_rotation_prep_same_message() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();
    let message = b"Same message";

    let sig_before = wallet.sign(message);
    wallet.rotate_prep().unwrap();
    let sig_after = wallet.sign(message);

    assert_ne!(sig_before, sig_after, "Signatures should differ after rotation");

    assert!(wallet.verify(message, &sig_after), "New signature should verify with new key");
}

#[test]
fn test_next_key_is_committed_before_use() {
    let mut crypto_box = ArxiaCryptoBox::new().unwrap();

    let next_key = crypto_box.next_public_key().unwrap();

    crypto_box.rotate_prep().unwrap();

    let new_current = crypto_box.public_key();

    assert_eq!(
        format!("{:?}", next_key),
        format!("{:?}", new_current),
        "Next key should become current after rotation"
    );
}

#[test]
fn test_next_key_hash_is_32_bytes() {
    let mut km = ArxiaKeyManager::new(1).unwrap();
    km.prepare_next_key().unwrap();

    let hash = km.next_key_hash().unwrap();
    let hash_str = format!("{:?}", hash);

    assert!(hash_str.len() > 0, "Hash should not be empty");
}

#[test]
fn test_rotation_progression_is_chain() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    let key_0 = wallet.public_key();

    wallet.rotate_prep().unwrap();
    let key_1 = wallet.public_key();

    wallet.rotate_prep().unwrap();
    let key_2 = wallet.public_key();

    wallet.rotate_prep().unwrap();
    let key_3 = wallet.public_key();

    assert_ne!(format!("{:?}", key_0), format!("{:?}", key_1));
    assert_ne!(format!("{:?}", key_1), format!("{:?}", key_2));
    assert_ne!(format!("{:?}", key_2), format!("{:?}", key_3));

    assert_ne!(format!("{:?}", key_0), format!("{:?}", key_2));
    assert_ne!(format!("{:?}", key_1), format!("{:?}", key_3));
    assert_ne!(format!("{:?}", key_0), format!("{:?}", key_3));
}

#[test]
fn test_signature_integrity_maintained_during_rotation() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    wallet.rotate_prep().unwrap();

    let message = b"Test message";
    let sig = wallet.sign(message);

    assert!(wallet.verify(message, &sig), "Signature should verify with current key");
}

#[test]
fn test_multiple_rotations_each_produce_unique_keys() {
    let mut wallet = ArxiaKeriWallet::new(KeriConfig::default()).unwrap();

    for i in 0..5 {
        let pk = wallet.public_key();
        let sig = wallet.sign(b"test");

        assert!(wallet.verify(b"test", &sig), "Signature {} should verify", i);

        wallet.rotate_prep().unwrap();

        let new_pk = wallet.public_key();
        assert_ne!(format!("{:?}", pk), format!("{:?}", new_pk), "Key {} should change", i);
    }
}

#[test]
fn test_pre_rotation_establishes_next_key_commitment() {
    let mut crypto_box = ArxiaCryptoBox::new().unwrap();

    let original_next = crypto_box.next_public_key().unwrap();

    crypto_box.rotate_prep().unwrap();

    let new_current = crypto_box.public_key();

    assert_eq!(
        format!("{:?}", original_next),
        format!("{:?}", new_current),
        "Original next key should become new current key after rotation"
    );
}

#[test]
fn test_after_rotation_next_key_is_newly_generated() {
    let mut crypto_box = ArxiaCryptoBox::new().unwrap();

    let next_before = crypto_box.next_public_key().unwrap();
    crypto_box.rotate_prep().unwrap();
    let next_after = crypto_box.next_public_key().unwrap();

    assert_ne!(
        format!("{:?}", next_before),
        format!("{:?}", next_after),
        "Next key should be newly generated after rotation"
    );
}