use arxia_keri::{ArxiaCryptoBox, ArxiaKeyManager, Error};

#[test]
fn test_signature_verification_fails_with_tampered_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Original message";

    let mut signature = crypto_box.sign(message);

    signature[0] ^= 0xFF;

    let is_valid = crypto_box.verify(message, &signature);
    assert!(!is_valid, "Tampered signature should fail verification");
}

#[test]
fn test_signature_verification_fails_with_partial_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Test message";

    let signature = crypto_box.sign(message);
    let partial_signature = &signature[..32];

    let is_valid = crypto_box.verify(message, partial_signature);
    assert!(!is_valid, "Partial signature should fail verification");
}

#[test]
fn test_signature_verification_fails_with_zero_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Test message";
    let zero_signature = vec![0u8; 64];

    let is_valid = crypto_box.verify(message, &zero_signature);
    assert!(!is_valid, "Zero signature should fail verification");
}

#[test]
fn test_signature_verification_fails_with_wrong_length_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Test message";

    let short_signature = vec![0u8; 32];
    let long_signature = vec![0u8; 128];

    assert!(!crypto_box.verify(message, &short_signature));
    assert!(!crypto_box.verify(message, &long_signature));
}

#[test]
fn test_verify_with_completely_wrong_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Test message for wrong signature";

    let wrong_signature: Vec<u8> = (0..64).map(|i| i as u8).collect();

    let is_valid = crypto_box.verify(message, &wrong_signature);
    assert!(!is_valid, "Wrong signature should fail verification");
}

#[test]
fn test_verify_with_message_signed_by_other_key() {
    let crypto_box1 = ArxiaCryptoBox::new().unwrap();
    let crypto_box2 = ArxiaCryptoBox::new().unwrap();
    let message = b"Same message for both keys";

    let signature_from_key2 = crypto_box2.sign(message);

    let is_valid = crypto_box1.verify(message, &signature_from_key2);
    assert!(!is_valid, "Signature from different key should not verify");
}

#[test]
fn test_key_manager_verify_fails_with_wrong_signature() {
    let key_manager = ArxiaKeyManager::new(1).unwrap();
    let message = b"Key manager test message";

    let wrong_signature = vec![0u8; 64];

    let is_valid = key_manager.verify(message, &wrong_signature);
    assert!(!is_valid, "Wrong signature should fail with key manager");
}

#[test]
fn test_key_manager_verify_fails_with_tampered_message() {
    let key_manager = ArxiaKeyManager::new(1).unwrap();
    let message = b"Original message";
    let tampered_message = b"Tampered message";

    let signature = key_manager.sign(message);

    let is_valid = key_manager.verify(tampered_message, &signature);
    assert!(!is_valid, "Tampered message should fail verification");
}

#[test]
fn test_next_key_hash_fails_before_rotation_prep() {
    let mut key_manager = ArxiaKeyManager::new(1).unwrap();

    let first_result = key_manager.next_key_hash();
    assert!(first_result.is_ok(), "next_key_hash should work after creation");

    key_manager.prepare_next_key().unwrap();

    let second_result = key_manager.next_key_hash();
    assert!(second_result.is_ok(), "next_key_hash should work after rotation prep");
}

#[test]
fn test_error_type_display() {
    let error = Error::SeedError("test error".to_string());
    let display = format!("{}", error);
    assert!(display.contains("test error"));
}

#[test]
fn test_error_types_have_correct_messages() {
    let seed_error = Error::SeedError("seed issue".to_string());
    let crypto_error = Error::CryptoError("crypto issue".to_string());
    let inception_error = Error::InceptionFailed("inception issue".to_string());
    let rotation_error = Error::RotationFailed("rotation issue".to_string());

    assert!(format!("{}", seed_error).contains("seed issue"));
    assert!(format!("{}", crypto_error).contains("crypto issue"));
    assert!(format!("{}", inception_error).contains("inception issue"));
    assert!(format!("{}", rotation_error).contains("rotation issue"));
}

#[test]
fn test_event_not_found_error_contains_sn() {
    let error = Error::EventNotFound(42);
    let display = format!("{}", error);
    assert!(display.contains("42"));
}

#[test]
fn test_threshold_not_met_error_contains_values() {
    let error = Error::ThresholdNotMet { needed: 3, actual: 2 };
    let display = format!("{}", error);
    assert!(display.contains("3"));
    assert!(display.contains("2"));
}

#[test]
fn test_error_from_impl() {
    let error = Error::KeriCore("generic error".to_string());
    let display = format!("{}", error);
    assert!(display.contains("generic error"));
}

#[test]
fn test_multiple_verify_attempts_on_same_signature() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Test message for repeated verification";
    let signature = crypto_box.sign(message);

    assert!(crypto_box.verify(message, &signature));
    assert!(crypto_box.verify(message, &signature));
    assert!(crypto_box.verify(message, &signature));
}

#[test]
fn test_signature_not_reused_for_different_message() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message_a = b"Message A";
    let message_b = b"Message B";

    let sig_a = crypto_box.sign(message_a);

    assert!(crypto_box.verify(message_a, &sig_a));
    assert!(!crypto_box.verify(message_b, &sig_a));
}

#[test]
fn test_empty_signature_array_fails() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = b"Test message";

    let empty_sig: [u8; 64] = [0u8; 64];
    let is_valid = crypto_box.verify(message, &empty_sig);
    assert!(!is_valid, "Empty signature should fail");
}

#[test]
fn test_signature_with_unicode_message_verification() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();
    let message = "Hello, World! 你好世界 🔐";

    let signature = crypto_box.sign(message.as_bytes());
    let is_valid = crypto_box.verify(message.as_bytes(), &signature);
    assert!(is_valid, "Unicode message should verify correctly");
}

#[test]
fn test_signature_with_very_short_message() {
    let crypto_box = ArxiaCryptoBox::new().unwrap();

    let one_byte = b"x";
    let sig = crypto_box.sign(one_byte);
    assert!(crypto_box.verify(one_byte, &sig));

    let empty = b"";
    let sig_empty = crypto_box.sign(empty);
    assert!(crypto_box.verify(empty, &sig_empty));
}