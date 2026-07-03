//! Compact binary serialization (194 bytes per block) for LoRa transport.
//!
//! Layout: [1B type][32B account][32B prev_hash][8B balance][8B nonce]
//! [8B timestamp][8B amount/initial][32B dest_or_source][64B signature]
//! [1B network_discriminator]
//!
//! Network discriminator: 0x00="", 0x01="local", 0x02="testnet", 0x03="mainnet".
//! Byte 193 (last byte) was added in commit XXX; unknown values decode to "".
//!
//! # Loud failure on malformed hex (HIGH-004)
//!
//! Pre-fix, [`to_compact_bytes`] silently substituted `[0u8; 32]` for
//! any hex-decode failure on the `account` / `previous` / `destination`
//! / `source_hash` fields. An upstream bug producing a malformed hex
//! string would turn into 32 zero bytes on the wire — the receiver
//! would deserialize it, recompute the hash from the same 32 zeros,
//! and the block would "verify" but represent a different semantic
//! object than what was intended. Silent data corruption.
//!
//! Post-fix (commit 032), [`to_compact_bytes`] returns
//! `Result<Vec<u8>, ArxiaError>` and propagates every `hex::decode`
//! failure as `ArxiaError::HexDecode` (or the structurally-equivalent
//! length error). Callers MUST handle the `Err` arm at compile time.

use crate::block::{Block, BlockType};
use arxia_core::{ArxiaError, COMPACT_BLOCK_SIZE};

/// Decode a hex string into a fixed-size 32-byte array. Loud failure
/// on bad input: `Err(ArxiaError::HexDecode)` for non-hex,
/// `Err(ArxiaError::InvalidKey)` for wrong length.
fn hex_decode_32(field_name: &str, s: &str) -> Result<[u8; 32], ArxiaError> {
    let v = hex::decode(s).map_err(ArxiaError::HexDecode)?;
    let len = v.len();
    v.as_slice().try_into().map_err(|_| {
        ArxiaError::InvalidKey(format!(
            "{} must be 64 hex chars (32 bytes), got {} bytes",
            field_name, len
        ))
    })
}

/// Serialize a block to compact binary format (194 bytes).
///
/// # Errors
///
/// Returns `Err(ArxiaError::HexDecode)` if any hex field
/// (`account`, `previous`, `destination`, `source_hash`,
/// `credential_hash`) is not valid hex.
///
/// Returns `Err(ArxiaError::InvalidKey)` if any hex field decodes
/// to other than exactly 32 bytes.
///
/// HIGH-004 (commit 032): this function used to silently substitute
/// `[0u8; 32]` on any hex-decode failure, turning a structural error
/// (malformed upstream input) into wire-level data corruption that
/// downstream `verify_block` could not detect. The current
/// implementation surfaces every such failure to the caller.
pub fn to_compact_bytes(block: &Block) -> Result<Vec<u8>, ArxiaError> {
    let mut buf = Vec::with_capacity(COMPACT_BLOCK_SIZE);
    match &block.block_type {
        BlockType::Open { .. } => buf.push(0x00),
        BlockType::Send { .. } => buf.push(0x01),
        BlockType::Receive { .. } => buf.push(0x02),
        BlockType::Revoke { .. } => buf.push(0x03),
    }

    let account_bytes = hex_decode_32("account", &block.account)?;
    buf.extend_from_slice(&account_bytes);

    if block.previous.is_empty() {
        // Genesis block: previous is conventionally the empty string,
        // serialized as 32 zero bytes. This is NOT a hex-decode
        // fallback — empty-string previous is the documented genesis
        // sentinel.
        buf.extend_from_slice(&[0u8; 32]);
    } else {
        let prev = hex_decode_32("previous", &block.previous)?;
        buf.extend_from_slice(&prev);
    }

    buf.extend_from_slice(&block.balance.to_be_bytes());
    buf.extend_from_slice(&block.nonce.to_be_bytes());
    buf.extend_from_slice(&block.timestamp.to_be_bytes());

    match &block.block_type {
        BlockType::Open { initial_balance } => {
            buf.extend_from_slice(&initial_balance.to_be_bytes())
        }
        BlockType::Send { amount, .. } => buf.extend_from_slice(&amount.to_be_bytes()),
        _ => buf.extend_from_slice(&0u64.to_be_bytes()),
    }

    match &block.block_type {
        BlockType::Send { destination, .. } => {
            let d = hex_decode_32("destination", destination)?;
            buf.extend_from_slice(&d);
        }
        BlockType::Receive { source_hash } => {
            let s = hex_decode_32("source_hash", source_hash)?;
            buf.extend_from_slice(&s);
        }
        BlockType::Revoke { credential_hash } => {
            let r = hex_decode_32("credential_hash", credential_hash)?;
            buf.extend_from_slice(&r);
        }
        BlockType::Open { .. } => buf.extend_from_slice(&[0u8; 32]),
    }

    if block.signature.len() == 64 {
        buf.extend_from_slice(&block.signature);
    } else {
        // Signature length mismatch is a separate concern from hex
        // decoding (the field is a Vec<u8>, not a hex string). The
        // current behavior preserves the pre-fix semantics: pad with
        // zeros so the wire format is still 194 bytes. A
        // missing/wrong-length signature is caught by `verify_block`
        // downstream.
        //
        // LOW-005 (commit 076): callers that want to fail loudly
        // on a wrong-length signature instead of silently padding
        // can use [`to_compact_bytes_strict`]. Both forms produce
        // identical 194-byte output for canonical inputs.
        buf.extend_from_slice(&[0u8; 64]);
    }

    buf.push(network_to_discriminator(&block.network));
    Ok(buf)
}

fn network_to_discriminator(network: &str) -> u8 {
    match network {
        "" => 0x00,
        "local" => 0x01,
        "testnet" => 0x02,
        "mainnet" => 0x03,
        _ => 0x00,
    }
}

fn discriminator_to_network(d: u8) -> &'static str {
    match d {
        0x00 => "",
        0x01 => "local",
        0x02 => "testnet",
        0x03 => "mainnet",
        _ => "",
    }
}

/// Strict variant of [`to_compact_bytes`] that returns an error
/// instead of silently zero-padding a wrong-length signature.
///
/// LOW-005 (commit 076): the lenient form pads with `[0u8; 64]`
/// so the wire format is always 194 bytes ; downstream
/// `verify_block` catches the all-zero signature. Sensitive
/// callers (e.g. those serialising blocks for long-term archival
/// where downstream verify isn't run on every read) can use this
/// strict form to fail at serialisation time instead.
///
/// Returns `Err(ArxiaError::SignatureInvalid)` if
/// `block.signature.len() != 64`. On success, the bytes are
/// byte-identical to [`to_compact_bytes`].
pub fn to_compact_bytes_strict(block: &Block) -> Result<Vec<u8>, ArxiaError> {
    if block.signature.len() != 64 {
        return Err(ArxiaError::SignatureInvalid(format!(
            "compact-bytes serialization requires 64-byte signature, got {}",
            block.signature.len()
        )));
    }
    to_compact_bytes(block)
}

/// Deserialize a block from compact binary format (194 bytes).
pub fn from_compact_bytes(data: &[u8]) -> Result<Block, ArxiaError> {
    if data.len() < COMPACT_BLOCK_SIZE {
        return Err(ArxiaError::DataTooShort {
            got: data.len(),
            expected: COMPACT_BLOCK_SIZE,
        });
    }
    let tag = data[0];
    let account = hex::encode(&data[1..33]);
    let prev_raw = &data[33..65];
    let previous = if prev_raw.iter().all(|&b| b == 0) {
        String::new()
    } else {
        hex::encode(prev_raw)
    };
    // MED-003 (commit 051): typed-error on slice-to-array conversion.
    // The length check above (`data.len() < COMPACT_BLOCK_SIZE`)
    // makes these `try_into` failures unreachable at runtime
    // today. Defense-in-depth: if a future refactor weakens the
    // length check, the panic becomes a typed `DataTooShort`
    // instead of an `unwrap` panic.
    let to_8_bytes = |slice: &[u8]| -> Result<[u8; 8], ArxiaError> {
        try_8_bytes(slice, data.len())
    };
    let balance = u64::from_be_bytes(to_8_bytes(&data[65..73])?);
    let nonce = u64::from_be_bytes(to_8_bytes(&data[73..81])?);
    let timestamp = u64::from_be_bytes(to_8_bytes(&data[81..89])?);
    let amount = u64::from_be_bytes(to_8_bytes(&data[89..97])?);
    let dest_src = hex::encode(&data[97..129]);
    let signature = data[129..193].to_vec();
    let network = discriminator_to_network(data[193]);
    let block_type = match tag {
        0x00 => BlockType::Open {
            initial_balance: amount,
        },
        0x01 => BlockType::Send {
            destination: dest_src,
            amount,
        },
        0x02 => BlockType::Receive {
            source_hash: dest_src,
        },
        0x03 => BlockType::Revoke {
            credential_hash: dest_src,
        },
        t => return Err(ArxiaError::InvalidBlockType(t)),
    };
    // CRITICAL: the hash is recomputed from the timestamp contained in the
    // data bytes, NOT from a fresh SystemTime::now(). This guarantees the
    // hash is a pure function of the serialized payload and is identical
    // across nodes with out-of-sync clocks. Regression tests below pin
    // this property.
    let hash = Block::compute_hash_with_network(
        &account, &previous, &block_type, balance, nonce, timestamp, network,
    )?;
    Ok(Block {
        account,
        previous,
        block_type,
        balance,
        nonce,
        timestamp,
        hash,
        signature,
        network: network.to_string(),
        pq_public_key: None,
        pq_signature: None,
    })
}

fn try_8_bytes(slice: &[u8], data_len: usize) -> Result<[u8; 8], ArxiaError> {
    slice.try_into().map_err(|_| ArxiaError::DataTooShort {
        got: data_len,
        expected: COMPACT_BLOCK_SIZE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{AccountChain, VectorClock};

    #[test]
    fn test_compact_round_trip_open() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let bytes = to_compact_bytes(&block).unwrap();
        assert_eq!(bytes.len(), COMPACT_BLOCK_SIZE);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.balance, block.balance);
        assert_eq!(restored.nonce, block.nonce);
    }

    #[test]
    fn test_compact_round_trip_send() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        chain.open(1_000_000, &mut vc).unwrap();
        let send = chain.send(&"ab".repeat(32), 500_000, &mut vc).unwrap();
        let bytes = to_compact_bytes(&send).unwrap();
        assert_eq!(bytes.len(), COMPACT_BLOCK_SIZE);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.balance, send.balance);
    }

    #[test]
    fn test_compact_size_194_bytes() {
        assert_eq!(COMPACT_BLOCK_SIZE, 194);
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(42, &mut vc).unwrap();
        assert_eq!(to_compact_bytes(&block).unwrap().len(), 194);
    }

    #[test]
    fn test_from_compact_too_short() {
        let data = vec![0u8; 100];
        assert!(from_compact_bytes(&data).is_err());
    }

    // ========================================================================
    // Regression guards for Bug 6 — timestamp-in-hash concern
    //
    // The pre-launch audit raised a concern that nodes with out-of-sync
    // clocks could compute different hashes for the same block. This was
    // NOT true of the code as written: compute_hash takes `timestamp` as
    // a parameter, and from_compact_bytes reads it from the serialized
    // payload. The hash is therefore a pure function of the bytes.
    //
    // The tests below pin that property so any future refactor that
    // replaces `timestamp` with a fresh `SystemTime::now()` call fails
    // loudly.
    // ========================================================================

    #[test]
    fn test_hash_is_deterministic_across_round_trip() {
        // Same bytes in, same hash out. Always.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let original_hash = block.hash.clone();
        let original_ts = block.timestamp;
        let bytes = to_compact_bytes(&block).unwrap();
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.hash, original_hash);
        assert_eq!(restored.timestamp, original_ts);
    }

    #[test]
    fn test_hash_stable_across_delayed_deserialization() {
        // Simulates "same bytes received hours later on a different node":
        // we deserialize multiple times, possibly with a real delay between
        // calls. Every deserialization produces the identical hash.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let bytes = to_compact_bytes(&block).unwrap();
        let h1 = from_compact_bytes(&bytes).unwrap().hash;
        std::thread::sleep(std::time::Duration::from_millis(10));
        let h2 = from_compact_bytes(&bytes).unwrap().hash;
        std::thread::sleep(std::time::Duration::from_millis(10));
        let h3 = from_compact_bytes(&bytes).unwrap().hash;
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
        assert_eq!(h1, block.hash);
    }

    #[test]
    fn test_hash_changes_when_timestamp_bytes_are_mutated() {
        // Adversarial: tamper with only the timestamp bytes in the
        // serialized form. The recomputed hash must differ, which means
        // verify_block (elsewhere) will reject the block on HashMismatch.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let mut bytes = to_compact_bytes(&block).unwrap();
        // Bytes 81..89 are the timestamp. Flip the low-order byte.
        bytes[88] ^= 0xFF;
        let tampered = from_compact_bytes(&bytes).unwrap();
        assert_ne!(tampered.hash, block.hash);
        // The stored signature in tampered is still the original one;
        // verify_block would catch the mismatch on the very next check.
    }

    #[test]
    fn test_two_nodes_compute_same_hash_for_same_bytes() {
        // Explicit multi-"node" simulation: node A serializes, node B
        // deserializes on the same bytes. Hashes match regardless of
        // wall-clock drift between them.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block_a = chain.open(1_000_000, &mut vc).unwrap();
        let wire = to_compact_bytes(&block_a).unwrap();
        // "Node B" deserializes fresh
        let block_b = from_compact_bytes(&wire).unwrap();
        assert_eq!(block_a.hash, block_b.hash);
        assert_eq!(block_a.account, block_b.account);
        assert_eq!(block_a.timestamp, block_b.timestamp);
    }

    #[test]
    fn test_explicit_timestamp_control_produces_stable_hash() {
        // Pin the property even more explicitly: computing the hash
        // directly via Block::compute_hash with a given timestamp yields
        // exactly the hash stored in the corresponding Block struct.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let recomputed = Block::compute_hash(
            &block.account,
            &block.previous,
            &block.block_type,
            block.balance,
            block.nonce,
            block.timestamp,
        )
        .unwrap();
        assert_eq!(recomputed, block.hash);
    }

    // ========================================================================
    // Adversarial tests for HIGH-004 (loud failure on malformed hex)
    //
    // `to_compact_bytes` must propagate every hex-decode failure as
    // `ArxiaError::HexDecode` (or `InvalidKey` for wrong length),
    // never silently substitute `[0u8; 32]`.
    // ========================================================================

    /// Build a base OPEN block. Returns a valid block we can mutate.
    fn base_open_block() -> Block {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        chain.open(1_000_000, &mut vc).unwrap()
    }

    #[test]
    fn test_to_compact_bytes_rejects_malformed_hex_account() {
        // `account` field with non-hex characters. The pre-fix code
        // silently used [0u8; 32]; the post-fix code returns Err.
        let mut block = base_open_block();
        block.account = "GG".repeat(32); // 64 chars, but G is not hex
        let result = to_compact_bytes(&block);
        let msg = format!("expected HexDecode, got {:?}", result);
        assert!(
            matches!(result, Err(ArxiaError::HexDecode(_))),
            "{}",
            msg
        );
    }

    #[test]
    fn test_to_compact_bytes_rejects_wrong_length_hex_account() {
        // `account` field is valid hex but only 16 chars (8 bytes).
        // Pre-fix code would `&account_bytes[..32]` panic; post-fix
        // returns InvalidKey.
        let mut block = base_open_block();
        block.account = "ab".repeat(8); // 16 chars = 8 bytes
        let result = to_compact_bytes(&block);
        let msg = format!("expected InvalidKey, got {:?}", result);
        assert!(
            matches!(result, Err(ArxiaError::InvalidKey(_))),
            "{}",
            msg
        );
    }

    #[test]
    fn test_to_compact_bytes_rejects_malformed_hex_previous() {
        // `previous` non-empty + non-hex must surface as Err.
        let mut block = base_open_block();
        block.previous = "ZZ".repeat(32); // non-hex (Z is not hex)
        let result = to_compact_bytes(&block);
        let msg = format!("expected HexDecode, got {:?}", result);
        assert!(
            matches!(result, Err(ArxiaError::HexDecode(_))),
            "{}",
            msg
        );
    }

    #[test]
    fn test_to_compact_bytes_accepts_empty_previous_as_genesis_sentinel() {
        // Empty string `previous` is the genesis convention — NOT a
        // hex-decode error. Must succeed.
        let block = base_open_block();
        assert_eq!(block.previous, "");
        let bytes = to_compact_bytes(&block).expect("genesis serializes ok");
        assert_eq!(bytes.len(), COMPACT_BLOCK_SIZE);
        // Bytes 33..65 are the previous-hash slot, all zeros for genesis.
        assert!(bytes[33..65].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_to_compact_bytes_rejects_malformed_hex_destination() {
        // SEND.destination with non-hex must surface as Err. We have
        // to construct the SEND manually because AccountChain::send
        // also rejects non-hex destinations downstream — but we
        // explicitly want to test the serialization layer's
        // independent guard.
        let mut block = base_open_block();
        // Force the variant to Send with a non-hex destination.
        block.block_type = BlockType::Send {
            destination: "GG".repeat(32),
            amount: 100,
        };
        let result = to_compact_bytes(&block);
        let msg = format!("expected HexDecode for malformed destination, got {:?}", result);
        assert!(
            matches!(result, Err(ArxiaError::HexDecode(_))),
            "{}",
            msg
        );
    }

    #[test]
    fn test_to_compact_bytes_rejects_malformed_hex_source_hash() {
        // RECEIVE.source_hash with non-hex must surface as Err.
        let mut block = base_open_block();
        block.block_type = BlockType::Receive {
            source_hash: "ZZ".repeat(32),
        };
        let result = to_compact_bytes(&block);
        let msg = format!("expected HexDecode for malformed source_hash, got {:?}", result);
        assert!(
            matches!(result, Err(ArxiaError::HexDecode(_))),
            "{}",
            msg
        );
    }

    #[test]
    fn test_to_compact_bytes_rejects_malformed_hex_credential_hash() {
        // REVOKE.credential_hash with non-hex must surface as Err.
        let mut block = base_open_block();
        block.block_type = BlockType::Revoke {
            credential_hash: "QQ".repeat(32),
        };
        let result = to_compact_bytes(&block);
        let msg = format!("expected HexDecode for malformed credential_hash, got {:?}", result);
        assert!(
            matches!(result, Err(ArxiaError::HexDecode(_))),
            "{}",
            msg
        );
    }

    #[test]
    fn test_to_compact_bytes_succeeds_on_valid_block() {
        // Regression guard: legitimate blocks still serialize cleanly.
        let block = base_open_block();
        assert!(to_compact_bytes(&block).is_ok());
    }

    // ============================================================
    // MED-003 (commit 051) — from_compact_bytes typed-error
    // on slice-to-array conversion. The length-check at
    // function entry makes these conversions unreachable in
    // practice; the typed error is a defense-in-depth against
    // future refactors that weaken the guard.
    // ============================================================

    #[test]
    fn test_from_compact_bytes_round_trips_canonical_block() {
        // Positive regression: a canonical block survives
        // to_compact_bytes → from_compact_bytes round-trip.
        let block = base_open_block();
        let bytes = to_compact_bytes(&block).unwrap();
        let decoded = from_compact_bytes(&bytes).unwrap();
        assert_eq!(decoded.account, block.account);
        assert_eq!(decoded.balance, block.balance);
        assert_eq!(decoded.nonce, block.nonce);
        assert_eq!(decoded.timestamp, block.timestamp);
    }

    #[test]
    fn test_from_compact_bytes_returns_data_too_short_on_short_input() {
        // PRIMARY MED-003 PIN: short input is rejected with
        // typed `DataTooShort` rather than panicking. The
        // length-check at function entry already does this,
        // but we pin it explicitly so the typed-error contract
        // is clear.
        let short = vec![0u8; 100];
        let result = from_compact_bytes(&short);
        assert!(matches!(
            result,
            Err(ArxiaError::DataTooShort {
                got: 100,
                expected: 194
            })
        ));
    }

    #[test]
    fn test_try_8_bytes_errors_on_short_slice() {
        let short = [0u8; 4];
        let result = try_8_bytes(&short, 4);
        assert!(matches!(
            result,
            Err(ArxiaError::DataTooShort { got: 4, expected: 194 })
        ));
    }

    #[test]
    fn test_from_compact_bytes_no_unguarded_expect_in_module() {
        // MED-003 STRUCTURAL PIN (compile-time / source lint).
        // Read this file at compile time and assert the
        // production-code section does NOT contain
        // `.expect("8 bytes")` — the original panic-prone
        // pattern. This catches a future regression that
        // reintroduces the panic-on-slice form.
        //
        // PHASE2-001 fix: split on the bare `#[cfg(test)]`
        // attribute, no whitespace dependence. CRLF-tolerant
        // (the prior literal `"#[cfg(test)]\nmod tests"` marker
        // failed on Windows fresh clones with default
        // `core.autocrlf=true`). Backed by the workspace
        // `.gitattributes` rule `*.rs text eol=lf` for the
        // root-cause fix.
        const SELF_SOURCE: &str = include_str!("serialization.rs");
        let production = SELF_SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("split always yields >=1 segment");
        let msg = "MED-003: production code must use typed `?` propagation \
             instead of .expect(\"8 bytes\") on slice-to-array conversions"
            .to_string();
        assert!(
            !production.contains(".expect(\"8 bytes\")"),
            "{}",
            msg
        );
    }

    // ============================================================
    // LOW-005 (commit 076) — to_compact_bytes_strict.
    //
    // The lenient `to_compact_bytes` zero-pads a wrong-length
    // signature so the wire format is always 193 bytes. Strict
    // callers (long-term archival, where downstream verify is
    // not run on every read) can use `to_compact_bytes_strict`
    // to fail at serialisation time instead.
    // ============================================================

    #[test]
    fn test_to_compact_bytes_lenient_zero_pads_short_signature() {
        // Pin the existing lenient behaviour (regression guard).
        // A block with a 0-byte signature serialises to 194
        // bytes ; the last 64 bytes are all zero.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let mut block = chain.open(1, &mut vc).unwrap();
        block.signature = Vec::new(); // wrong length: 0
        let bytes = to_compact_bytes(&block).unwrap();
        assert_eq!(bytes.len(), 194);
        assert_eq!(&bytes[129..193], &[0u8; 64], "lenient form pads with zeros");
    }

    #[test]
    fn test_to_compact_bytes_strict_rejects_short_signature() {
        // PRIMARY LOW-005 PIN: the strict variant returns
        // SignatureInvalid on a wrong-length signature instead
        // of silently zero-padding.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let mut block = chain.open(1, &mut vc).unwrap();
        block.signature = vec![0xAA; 32]; // wrong length: 32
        let err = to_compact_bytes_strict(&block)
            .expect_err("strict form must reject wrong-length signature");
        match err {
            ArxiaError::SignatureInvalid(msg) => {
                assert!(msg.contains("64"));
                assert!(msg.contains("32"));
            }
            other => {
                let msg = format!("expected SignatureInvalid, got {other:?}");
                panic!("{}", msg);
            }
        }
    }

    #[test]
    fn test_to_compact_bytes_strict_rejects_long_signature() {
        // 65-byte signature: also wrong, also rejected.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let mut block = chain.open(1, &mut vc).unwrap();
        block.signature = vec![0xBB; 65];
        let err =
            to_compact_bytes_strict(&block).expect_err("strict form must reject 65-byte signature");
        assert!(matches!(err, ArxiaError::SignatureInvalid(_)));
    }

    #[test]
    fn test_to_compact_bytes_strict_accepts_canonical_64_byte_signature() {
        // Positive: a freshly-signed block has a 64-byte
        // signature ; strict form succeeds and produces
        // byte-identical output to the lenient form.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1, &mut vc).unwrap();
        assert_eq!(block.signature.len(), 64);
        let lenient = to_compact_bytes(&block).unwrap();
        let strict = to_compact_bytes_strict(&block).unwrap();
        assert_eq!(lenient, strict, "byte-identical for canonical input");
    }

    #[test]
    fn test_to_compact_bytes_strict_zero_signature_still_rejected() {
        // Edge: a 0-length signature (Vec::new). Pre-076 this
        // silently produced zero-padded output ; post-076 the
        // strict form rejects it.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let mut block = chain.open(1, &mut vc).unwrap();
        block.signature = Vec::new();
        assert!(to_compact_bytes_strict(&block).is_err());
        // Lenient form still works (regression guard).
        assert!(to_compact_bytes(&block).is_ok());
    }

    // ============================================================
    // network_to_discriminator / discriminator_to_network coverage
    // ============================================================

    #[test]
    fn test_network_to_discriminator_all_branches() {
        assert_eq!(network_to_discriminator(""), 0x00);
        assert_eq!(network_to_discriminator("local"), 0x01);
        assert_eq!(network_to_discriminator("testnet"), 0x02);
        assert_eq!(network_to_discriminator("mainnet"), 0x03);
        assert_eq!(network_to_discriminator("unknown"), 0x00);
    }

    #[test]
    fn test_discriminator_to_network_all_branches() {
        assert_eq!(discriminator_to_network(0x00), "");
        assert_eq!(discriminator_to_network(0x01), "local");
        assert_eq!(discriminator_to_network(0x02), "testnet");
        assert_eq!(discriminator_to_network(0x03), "mainnet");
        assert_eq!(discriminator_to_network(0xFF), "");
    }

    // ============================================================
    // from_compact_bytes – tag dispatch coverage
    // ============================================================

    #[test]
    fn test_from_compact_bytes_invalid_block_type() {
        let mut data = vec![0u8; COMPACT_BLOCK_SIZE];
        data[0] = 0x04;
        let result = from_compact_bytes(&data);
        assert!(matches!(result, Err(ArxiaError::InvalidBlockType(0x04))));
    }

    #[test]
    fn test_from_compact_bytes_invalid_block_type_high_tag() {
        let mut data = vec![0u8; COMPACT_BLOCK_SIZE];
        data[0] = 0xFF;
        let result = from_compact_bytes(&data);
        assert!(matches!(result, Err(ArxiaError::InvalidBlockType(0xFF))));
    }

    // ============================================================
    // Receive / Revoke block round-trips
    // ============================================================

    #[test]
    fn test_compact_round_trip_receive() {
        let mut block = base_open_block();
        block.block_type = BlockType::Receive {
            source_hash: "ab".repeat(32),
        };
        let bytes = to_compact_bytes(&block).expect("Receive should serialize");
        assert_eq!(bytes[0], 0x02);
        assert_eq!(bytes.len(), COMPACT_BLOCK_SIZE);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.balance, block.balance);
        match &restored.block_type {
            BlockType::Receive { source_hash } => {
                assert_eq!(source_hash, &"ab".repeat(32));
            }
            _ => {
                let msg = "expected Receive".to_string();
                panic!("{}", msg);
            }
        }
    }

    #[test]
    fn test_compact_round_trip_revoke() {
        let mut block = base_open_block();
        block.block_type = BlockType::Revoke {
            credential_hash: "ab".repeat(32),
        };
        let bytes = to_compact_bytes(&block).expect("Revoke should serialize");
        assert_eq!(bytes[0], 0x03);
        assert_eq!(bytes.len(), COMPACT_BLOCK_SIZE);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.balance, block.balance);
        match &restored.block_type {
            BlockType::Revoke { credential_hash } => {
                assert_eq!(credential_hash, &"ab".repeat(32));
            }
            _ => {
                let msg = "expected Revoke".to_string();
                panic!("{}", msg);
            }
        }
    }

    // ============================================================
    // Network discriminator serialization / deserialization
    // ============================================================

    #[test]
    fn test_to_compact_bytes_network_discriminator_empty() {
        let block = base_open_block();
        assert_eq!(block.network, "");
        let bytes = to_compact_bytes(&block).unwrap();
        assert_eq!(bytes[COMPACT_BLOCK_SIZE - 1], 0x00);
    }

    #[test]
    fn test_to_compact_bytes_network_discriminator_local() {
        let mut block = base_open_block();
        block.network = "local".to_string();
        let bytes = to_compact_bytes(&block).unwrap();
        assert_eq!(bytes[COMPACT_BLOCK_SIZE - 1], 0x01);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.network, "local");
    }

    #[test]
    fn test_to_compact_bytes_network_discriminator_testnet() {
        let mut block = base_open_block();
        block.network = "testnet".to_string();
        let bytes = to_compact_bytes(&block).unwrap();
        assert_eq!(bytes[COMPACT_BLOCK_SIZE - 1], 0x02);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.network, "testnet");
    }

    #[test]
    fn test_to_compact_bytes_network_discriminator_mainnet() {
        let mut block = base_open_block();
        block.network = "mainnet".to_string();
        let bytes = to_compact_bytes(&block).unwrap();
        assert_eq!(bytes[COMPACT_BLOCK_SIZE - 1], 0x03);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.network, "mainnet");
    }

    #[test]
    fn test_to_compact_bytes_unknown_network_defaults_to_empty() {
        let mut block = base_open_block();
        block.network = "custom".to_string();
        let bytes = to_compact_bytes(&block).unwrap();
        assert_eq!(bytes[COMPACT_BLOCK_SIZE - 1], 0x00);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.network, "");
    }

    // ============================================================
    // Signature padding: lenient form with long signature
    // ============================================================

    #[test]
    fn test_to_compact_bytes_lenient_zero_pads_long_signature() {
        let mut block = base_open_block();
        block.signature = vec![0xCC; 128];
        let bytes = to_compact_bytes(&block).unwrap();
        assert_eq!(bytes.len(), COMPACT_BLOCK_SIZE);
        assert_eq!(&bytes[129..COMPACT_BLOCK_SIZE - 1], &[0u8; 64]);
    }

    // ============================================================
    // to_compact_bytes_strict with valid Receive / Revoke blocks
    // ============================================================

    #[test]
    fn test_to_compact_bytes_strict_receive_happy() {
        let mut block = base_open_block();
        block.block_type = BlockType::Receive {
            source_hash: "ab".repeat(32),
        };
        let lenient = to_compact_bytes(&block).unwrap();
        let strict = to_compact_bytes_strict(&block).unwrap();
        assert_eq!(lenient, strict);
    }

    #[test]
    fn test_to_compact_bytes_strict_revoke_happy() {
        let mut block = base_open_block();
        block.block_type = BlockType::Revoke {
            credential_hash: "ab".repeat(32),
        };
        let lenient = to_compact_bytes(&block).unwrap();
        let strict = to_compact_bytes_strict(&block).unwrap();
        assert_eq!(lenient, strict);
    }
}
