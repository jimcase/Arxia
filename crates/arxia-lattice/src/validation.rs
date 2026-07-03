//! Block and chain validation.
//!
//! # Strict signature verification
//!
//! `verify_block` routes through [`arxia_crypto::verify`] and
//! [`arxia_crypto::validate_pubkey_strict`]. The first enforces
//! dalek's `verify_strict` (canonical-S enforcement and
//! low-order pubkey rejection), and the second rejects pubkey
//! bytes that decode to a small-subgroup point of Curve25519 at
//! parse time. Routing through `arxia_crypto` ensures the
//! lattice signature path inherits the strict-verify contract
//! documented at the `arxia_crypto::ed25519` module level.

use crate::block::{Block, BlockType};
use arxia_core::ArxiaError;

/// Verify a single block hash and Ed25519 signature.
pub fn verify_block(block: &Block) -> Result<(), ArxiaError> {
    let expected_hash = Block::compute_hash(
        &block.account,
        &block.previous,
        &block.block_type,
        block.balance,
        block.nonce,
        block.timestamp,
    )?;
    if expected_hash != block.hash {
        return Err(ArxiaError::HashMismatch);
    }
    let pubkey_bytes: [u8; 32] = hex::decode(&block.account)
        .map_err(|e| ArxiaError::InvalidKey(e.to_string()))?
        .try_into()
        .map_err(|_| ArxiaError::InvalidKey("bad key length".into()))?;
    // Reject low-order / off-curve pubkeys at parse time, BEFORE
    // any signature work. This is the parse-side mirror of the
    // strict verify below.
    arxia_crypto::validate_pubkey_strict(&pubkey_bytes)?;
    let sig_bytes: [u8; 64] = block
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ArxiaError::SignatureInvalid("bad sig length".into()))?;
    let hash_bytes =
        hex::decode(&block.hash).map_err(|e| ArxiaError::SignatureInvalid(e.to_string()))?;
    // Route through arxia_crypto::verify, which calls dalek's
    // `verify_strict` (canonical-S enforcement + low-order
    // rejection at the equation level).
    arxia_crypto::verify(&pubkey_bytes, &hash_bytes, &sig_bytes)?;

    // Post-Quantum ML-DSA-65 verification
    if let (Some(pq_pub_hex), Some(pq_sig_hex)) = (&block.pq_public_key, &block.pq_signature) {
        use ml_dsa::{MlDsa65, VerifyingKey, Signature, EncodedVerifyingKey, EncodedSignature};
        use ml_dsa::signature::Verifier as PqVerify;
        
        let pq_pub_bytes = hex::decode(pq_pub_hex)
            .map_err(|e| ArxiaError::InvalidKey(format!("Invalid PQ pubkey hex: {e}")))?;
        let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(pq_pub_bytes.as_slice())
            .map_err(|e| ArxiaError::InvalidKey(format!("Malformed PQ public key length: {e}")))?;
        let pq_vk = VerifyingKey::<MlDsa65>::decode(&encoded_key);
            
        let pq_sig_bytes = hex::decode(pq_sig_hex)
            .map_err(|e| ArxiaError::SignatureInvalid(format!("Invalid PQ signature hex: {e}")))?;
        let encoded_sig = EncodedSignature::<MlDsa65>::try_from(pq_sig_bytes.as_slice())
            .map_err(|e| ArxiaError::SignatureInvalid(format!("Malformed PQ signature length: {e}")))?;
        let sig = Signature::<MlDsa65>::decode(&encoded_sig)
            .ok_or_else(|| ArxiaError::SignatureInvalid("Malformed PQ signature encoding".into()))?;
            
        PqVerify::verify(&pq_vk, block.hash.as_bytes(), &sig)
            .map_err(|e| ArxiaError::SignatureInvalid(format!("PQ signature verify failed: {e}")))?;
    }

    Ok(())
}

/// Verify integrity of an entire account chain.
pub fn verify_chain_integrity(chain: &[Block]) -> Result<(), ArxiaError> {
    if chain.is_empty() {
        return Ok(());
    }
    if chain[0].nonce != 1 {
        return Err(ArxiaError::InvalidGenesis(format!(
            "nonce must be 1, got {}",
            chain[0].nonce
        )));
    }
    if !matches!(chain[0].block_type, BlockType::Open { .. }) {
        return Err(ArxiaError::InvalidGenesis(
            "first block must be OPEN".into(),
        ));
    }
    if !chain[0].previous.is_empty() {
        return Err(ArxiaError::InvalidGenesis(
            "genesis must have empty previous".into(),
        ));
    }
    verify_block(&chain[0])?;
    for i in 1..chain.len() {
        if chain[i].nonce != chain[i - 1].nonce + 1 {
            return Err(ArxiaError::NonceGap {
                index: i,
                expected: chain[i - 1].nonce + 1,
                got: chain[i].nonce,
            });
        }
        if chain[i].previous != chain[i - 1].hash {
            return Err(ArxiaError::HashChainBroken(i));
        }
        verify_block(&chain[i])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{AccountChain, VectorClock};

    #[test]
    fn test_verify_block_valid() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        assert!(verify_block(&block).is_ok());
    }

    #[test]
    fn test_verify_chain_integrity_valid() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        let send = alice.send(bob.id(), 100_000, &mut vc).unwrap();
        bob.receive(&send, &mut vc).unwrap();
        assert!(verify_chain_integrity(&alice.chain).is_ok());
        assert!(verify_chain_integrity(&bob.chain).is_ok());
    }

    #[test]
    fn test_verify_chain_empty_is_ok() {
        assert!(verify_chain_integrity(&[]).is_ok());
    }

    #[test]
    fn test_verify_chain_integrity_rejects_non_one_genesis_nonce() {
        let (_sk, vk) = arxia_crypto::generate_keypair();
        let pk = hex::encode(vk.to_bytes());
        let bt = BlockType::Open { initial_balance: 0 };
        let hash = Block::compute_hash(&pk, "", &bt, 0, 0, 0).unwrap();
        let block = Block {
            account: pk,
            previous: String::new(),
            block_type: bt,
            balance: 0,
            nonce: 0,
            timestamp: 0,
            hash,
            signature: vec![],
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let result = verify_chain_integrity(&[block]);
        assert!(matches!(result, Err(ArxiaError::InvalidGenesis(ref msg)) if msg.contains("nonce")));
    }

    #[test]
    fn test_verify_chain_integrity_rejects_non_open_genesis() {
        let (_sk, vk) = arxia_crypto::generate_keypair();
        let pk = hex::encode(vk.to_bytes());
        let bt = BlockType::Send { destination: "x".to_string(), amount: 0 };
        let hash = Block::compute_hash(&pk, "", &bt, 0, 1, 0).unwrap();
        let block = Block {
            account: pk,
            previous: String::new(),
            block_type: bt,
            balance: 0,
            nonce: 1,
            timestamp: 0,
            hash,
            signature: vec![],
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let result = verify_chain_integrity(&[block]);
        assert!(matches!(result, Err(ArxiaError::InvalidGenesis(_))));
    }

    #[test]
    fn test_verify_chain_integrity_rejects_genesis_with_previous() {
        let (_sk, vk) = arxia_crypto::generate_keypair();
        let pk = hex::encode(vk.to_bytes());
        let bt = BlockType::Open { initial_balance: 0 };
        let hash = Block::compute_hash(&pk, "prev", &bt, 0, 1, 0).unwrap();
        let block = Block {
            account: pk,
            previous: "prev".to_string(),
            block_type: bt,
            balance: 0,
            nonce: 1,
            timestamp: 0,
            hash,
            signature: vec![],
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let result = verify_chain_integrity(&[block]);
        assert!(matches!(result, Err(ArxiaError::InvalidGenesis(_))));
    }

    #[test]
    fn test_verify_chain_integrity_rejects_nonce_gap() {
        let (sk, vk) = arxia_crypto::generate_keypair();
        let account = hex::encode(vk.to_bytes());
        let bt = BlockType::Open { initial_balance: 1000 };
        let hash = Block::compute_hash(&account, "", &bt, 1000, 1, 0).unwrap();
        let hb = hex::decode(&hash).unwrap();
        let sig = arxia_crypto::sign(&sk, &hb);
        let genesis = Block {
            account: account.clone(),
            previous: String::new(),
            block_type: bt,
            balance: 1000,
            nonce: 1,
            timestamp: 0,
            hash,
            signature: sig.to_vec(),
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let block2 = Block {
            account,
            previous: genesis.hash.clone(),
            block_type: BlockType::Send { destination: "x".into(), amount: 100 },
            balance: 900,
            nonce: 3,
            timestamp: 1,
            hash: String::new(),
            signature: vec![],
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let result = verify_chain_integrity(&[genesis, block2]);
        assert!(matches!(result, Err(ArxiaError::NonceGap { index: 1, expected: 2, got: 3 })));
    }

    #[test]
    fn test_verify_chain_integrity_rejects_broken_hash_chain() {
        let (sk, vk) = arxia_crypto::generate_keypair();
        let account = hex::encode(vk.to_bytes());
        let bt = BlockType::Open { initial_balance: 1000 };
        let hash = Block::compute_hash(&account, "", &bt, 1000, 1, 0).unwrap();
        let hb = hex::decode(&hash).unwrap();
        let sig = arxia_crypto::sign(&sk, &hb);
        let genesis = Block {
            account: account.clone(),
            previous: String::new(),
            block_type: bt,
            balance: 1000,
            nonce: 1,
            timestamp: 0,
            hash,
            signature: sig.to_vec(),
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let block2 = Block {
            account,
            previous: "wrong-previous".to_string(),
            block_type: BlockType::Send { destination: "x".into(), amount: 100 },
            balance: 900,
            nonce: 2,
            timestamp: 1,
            hash: String::new(),
            signature: vec![],
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let result = verify_chain_integrity(&[genesis, block2]);
        assert!(matches!(result, Err(ArxiaError::HashChainBroken(1))));
    }

    #[test]
    fn test_verify_block_rejects_tampered_hash() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let mut block = chain.open(1_000_000, &mut vc).unwrap();
        block.hash = "0".repeat(64);
        assert!(verify_block(&block).is_err());
    }

    // ============================================================
    // Strict-verify routing: production code MUST call
    // `arxia_crypto::verify` (which enforces `verify_strict` plus
    // low-order pubkey rejection), not dalek's lenient
    // `Verifier::verify` directly. Source-lint regression guard
    // against re-introducing the lenient path.
    // ============================================================

    #[test]
    fn test_validation_rs_routes_via_arxia_crypto_verify() {
        // PRIMARY PIN: production code in this file MUST NOT call
        // dalek lenient `vk.verify(...)` directly. The strict
        // contract (canonical-S + low-order pubkey rejection)
        // requires routing through `arxia_crypto::verify`.
        //
        // Uses the bare `#[cfg(test)]` split marker (CRLF-tolerant)
        // matching the source-lint pattern adopted workspace-wide.
        const SELF_SOURCE: &str = include_str!("validation.rs");
        let production = SELF_SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("split always yields >=1 segment");
        let msg = "production verify_block must use arxia_crypto::verify, \
             not dalek lenient vk.verify"
            .to_string();
        assert!(
            !production.contains("vk.verify("),
            "{}",
            msg
        );
        let msg = "production verify_block must not bypass arxia_crypto via \
             VerifyingKey::verify either"
            .to_string();
        assert!(
            !production.contains("verifying_key().verify("),
            "{}",
            msg
        );
        // Trait-method form bypass guard: a code-toucher could
        // import `Verifier` and call `Verifier::verify(&vk, ...)`
        // or `<VerifyingKey as Verifier>::verify(&vk, ...)`. The
        // earlier two checks would not match this form, so they
        // are extended here.
        let msg = "production verify_block must not call Verifier::verify directly".to_string();
        assert!(
            !production.contains("Verifier::verify("),
            "{}",
            msg
        );
        let msg = "production verify_block must not call <VerifyingKey as Verifier>::verify".to_string();
        assert!(
            !production.contains("as Verifier>::verify"),
            "{}",
            msg
        );
        // Aliased import bypass guard: forbid bringing dalek's
        // `Verifier` trait into scope at all in production.
        let msg = "production verify_block must not import ed25519_dalek::Verifier; \
             route through arxia_crypto::verify instead"
            .to_string();
        assert!(
            !production.contains("ed25519_dalek::Verifier"),
            "{}",
            msg
        );
        let msg = "production verify_block must route through arxia_crypto::verify".to_string();
        assert!(
            production.contains("arxia_crypto::verify"),
            "{}",
            msg
        );
        let msg = "production verify_block must call validate_pubkey_strict at parse time".to_string();
        assert!(
            production.contains("validate_pubkey_strict"),
            "{}",
            msg
        );
    }

    /// Construct a Block that the lenient path would have accepted
    /// pre-fix (identity-pubkey + R=identity, S=0). The strict
    /// `verify_block` must reject it. This is the post-fix
    /// regression guard derived from the audit reproducer.
    #[test]
    fn test_verify_block_rejects_low_order_identity_pubkey_signature() {
        // Identity element of Curve25519 in compressed form: y=1, sign=0.
        let identity_pk: [u8; 32] = {
            let mut p = [0u8; 32];
            p[0] = 0x01;
            p
        };
        // Trivial forged signature for low-order pubkey:
        // R = identity_compressed, S = 0. The verification
        // equation degenerates and ANY message accepts under
        // dalek's lenient verify.
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 0x01;

        // Build a real Block with this account + signature. We
        // don't go through AccountChain::open (that path also
        // rejects low-order at construction post-fix); we
        // construct the Block directly to exercise verify_block.
        let block_proto = Block {
            account: hex::encode(identity_pk),
            previous: String::new(),
            block_type: BlockType::Open {
                initial_balance: u64::MAX,
            },
            balance: u64::MAX,
            nonce: 1,
            timestamp: 0,
            hash: String::new(),
            signature: sig_bytes.to_vec(),
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let result = Block::compute_hash(
            &block_proto.account,
            &block_proto.previous,
            &block_proto.block_type,
            block_proto.balance,
            block_proto.nonce,
            block_proto.timestamp,
        );
        // compute_hash rejects the low-order account (defense-in-depth).
        let msg = "compute_hash must reject identity-pubkey account".to_string();
        assert!(
            result.is_err(),
            "{}",
            msg
        );
    }

    /// E2E pin: a chain whose FIRST block is the identity-pubkey
    /// forged genesis must be rejected by `verify_chain_integrity`.
    /// Closes the open question A2 left unanswered (whether
    /// verify_chain_integrity propagates the strict check).
    #[test]
    fn test_verify_chain_integrity_rejects_low_order_identity_forged_chain() {
        let identity_pk: [u8; 32] = {
            let mut p = [0u8; 32];
            p[0] = 0x01;
            p
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 0x01;
        let block_proto = Block {
            account: hex::encode(identity_pk),
            previous: String::new(),
            block_type: BlockType::Open {
                initial_balance: u64::MAX,
            },
            balance: u64::MAX,
            nonce: 1,
            timestamp: 0,
            hash: String::new(),
            signature: sig_bytes.to_vec(),
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let result = Block::compute_hash(
            &block_proto.account,
            &block_proto.previous,
            &block_proto.block_type,
            block_proto.balance,
            block_proto.nonce,
            block_proto.timestamp,
        );
        // compute_hash rejects the low-order account (defense-in-depth).
        let msg = "compute_hash must reject identity-pubkey account for chain integrity".to_string();
        assert!(
            result.is_err(),
            "{}",
            msg
        );
    }

    /// Boundary pin: regardless of any hash value placed on the
    /// block, `verify_block` MUST error when the account is a
    /// low-order pubkey. Strongest closure: the verify boundary
    /// itself rejects, independently of whether `compute_hash`
    /// defense-in-depth fired. Mirrors the audit reproducer's
    /// E2E call site (`verify_block(&block)` on identity-pk
    /// account + R=identity, S=0 signature).
    #[test]
    fn test_verify_block_rejects_low_order_account_at_verify_boundary() {
        let identity_pk: [u8; 32] = {
            let mut p = [0u8; 32];
            p[0] = 0x01;
            p
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 0x01;
        // Place an arbitrary-but-syntactically-valid hash on the
        // block. The point is: even if the recomputation step
        // didn't reject (hypothetical regression), verify_block
        // must still error. With the current fix the recomputation
        // returns Err(InvalidKey) → verify_block returns Err.
        let bogus_hash = "0".repeat(64);
        let block = Block {
            account: hex::encode(identity_pk),
            previous: String::new(),
            block_type: BlockType::Open { initial_balance: 0 },
            balance: 0,
            nonce: 1,
            timestamp: 0,
            hash: bogus_hash,
            signature: sig_bytes.to_vec(),
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        let result = verify_block(&block);
        let msg = format!(
            "verify_block must reject a low-order pubkey block at \
             the verify boundary (got {:?})",
            result
        );
        assert!(
            result.is_err(),
            "{}",
            msg
        );
    }

    #[test]
    fn test_verify_block_with_post_quantum_signature() {
        use ml_dsa::{MlDsa65, SigningKey, Signer, Generate, KeyExport};
        use ml_dsa::signature::{Keypair, SignatureEncoding};
        let (sk, vk) = arxia_crypto::generate_keypair();
        let pk_hex = hex::encode(vk.to_bytes());
        
        let mut block = Block {
            account: pk_hex,
            previous: String::new(),
            block_type: BlockType::Open { initial_balance: 100 },
            balance: 100,
            nonce: 1,
            timestamp: 12345,
            hash: String::new(),
            signature: Vec::new(),
            network: String::new(),
            pq_public_key: None,
            pq_signature: None,
        };
        block.hash = Block::compute_hash(
            &block.account,
            &block.previous,
            &block.block_type,
            block.balance,
            block.nonce,
            block.timestamp,
        ).unwrap();
        
        let hash_bytes = hex::decode(&block.hash).unwrap();
        block.signature = arxia_crypto::sign(&sk, &hash_bytes).to_vec();
        
        // At this point, classical verification succeeds
        assert!(verify_block(&block).is_ok());
        
        // Generate ML-DSA keypair
        let pq_sk = SigningKey::<MlDsa65>::generate();
        let pq_vk = pq_sk.verifying_key();
        
        // Sign block.hash with ML-DSA
        let pq_sig = pq_sk.sign(block.hash.as_bytes());
        
        block.pq_public_key = Some(hex::encode(pq_vk.to_bytes()));
        block.pq_signature = Some(hex::encode(pq_sig.to_bytes()));
        
        // 1. Valid hybrid signature should succeed
        assert!(verify_block(&block).is_ok());
        
        // 2. Tampering with the PQ signature should fail
        let mut tampered_block = block.clone();
        tampered_block.pq_signature = Some("0".repeat(pq_sig.to_bytes().len() * 2));
        assert!(verify_block(&tampered_block).is_err());
    }
}
