//! WebAssembly bindings for the Arxia wallet.
//!
//! Exposes the three core wallet operations to JavaScript/TypeScript:
//! - [`create_arxia_wallet`]  — generate a fresh Ed25519 keypair + Open block
//! - [`create_send_block`]    — sign a Send block, deduct balance
//! - [`create_receive_block`] — sign a Receive block, add balance
//!
//! All functions accept / return JSON strings so no wasm-bindgen
//! struct serialization is needed on the JS side.

use wasm_bindgen::prelude::*;

use std::sync::{Mutex, OnceLock};

use arxia_lattice::block::Block;
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::validation::{verify_block, verify_chain_integrity};
use arxia_gossip::nonce_registry::{NonceConflict, NonceRegistry};
use arxia_crdt::reconciliation::RejectedGenesis;
use ed25519_dalek::SigningKey;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Convert a hex-encoded private key string into a `SigningKey`.
fn signing_key_from_hex(hex_str: &str) -> Result<SigningKey, String> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("Invalid private key hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Private key must be exactly 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

// ── public API ────────────────────────────────────────────────────────────────

/// Create a brand-new Arxia wallet.
///
/// Generates a fresh Ed25519 keypair with OS/browser CSPRNG, creates the
/// genesis `Open` block, and returns a JSON object:
///
/// ```json
/// {
///   "private_key_hex": "<64 hex chars>",
///   "public_key_hex":  "<64 hex chars>",
///   "open_block":      { ...Block },
///   "vclock":          { "clocks": { "<node_id>": 1 } }
/// }
/// ```
///
/// # Errors
/// Returns a JS string error if block construction fails.
#[wasm_bindgen]
pub fn create_arxia_wallet(initial_balance: u64) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let mut vclock = VectorClock::new();
    let mut chain = AccountChain::new();

    let private_key_hex = hex::encode(chain.signing_key().to_bytes());

    let open_block = chain
        .open(initial_balance, &mut vclock)
        .map_err(|e| format!("open block error: {e:?}"))?;

    let result = serde_json::json!({
        "private_key_hex": private_key_hex,
        "public_key_hex":  chain.public_key_hex,
        "open_block":      open_block,
        "vclock":          vclock,
    });

    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// Create an Arxia wallet from an **existing** private key (hex).
///
/// Used when the frontend generates a BIP39 mnemonic, derives the
/// Ed25519 private key from the mnemonic seed bytes, and then calls
/// this to create the genesis `Open` block with that deterministic key.
///
/// # Arguments
/// - `private_key_hex`  — 64-char hex Ed25519 signing key (first 32 bytes of BIP39 seed)
/// - `initial_balance`  — balance in micro-ARX
///
/// # Returns
/// Same JSON shape as `create_arxia_wallet`.
#[wasm_bindgen]
pub fn create_wallet_from_privkey(private_key_hex: &str, initial_balance: u64) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let signing_key = signing_key_from_hex(private_key_hex)?;
    let mut vclock = VectorClock::new();
    // Start from an empty chain with the given key
    let mut chain = AccountChain::from_key_and_blocks(signing_key, vec![]);

    let pub_key_hex = chain.public_key_hex.clone();
    let open_block = chain
        .open(initial_balance, &mut vclock)
        .map_err(|e| format!("open block error: {e:?}"))?;

    let result = serde_json::json!({
        "private_key_hex": private_key_hex,
        "public_key_hex":  pub_key_hex,
        "open_block":      open_block,
        "vclock":          vclock,
    });

    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// Create a `Send` block.
///
/// # Arguments
/// - `private_key_hex` — 64-char hex Ed25519 signing key
/// - `destination`     — 64-char hex recipient public key
/// - `amount`          — micro-ARX to send (u64)
/// - `chain_json`      — JSON array of existing `Block` objects (the sender's chain)
/// - `vclock_json`     — JSON `VectorClock` object
///
/// # Returns
/// JSON object:
/// ```json
/// {
///   "send_block":  { ...Block },
///   "chain_json":  "[...updated chain]",
///   "vclock_json": "{...updated vclock}"
/// }
/// ```
#[wasm_bindgen]
pub fn create_send_block(
    private_key_hex: &str,
    destination: &str,
    amount: u64,
    chain_json: &str,
    vclock_json: &str,
) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let signing_key = signing_key_from_hex(private_key_hex)?;

    let existing_chain: Vec<Block> = serde_json::from_str(chain_json)
        .map_err(|e| format!("Invalid chain JSON: {e}"))?;

    let mut vclock: VectorClock = serde_json::from_str(vclock_json)
        .map_err(|e| format!("Invalid vclock JSON: {e}"))?;

    let mut account = AccountChain::from_key_and_blocks(signing_key, existing_chain);

    let send_block = account
        .send(destination, amount, &mut vclock)
        .map_err(|e| format!("send error: {e:?}"))?;

    let updated_chain = serde_json::to_string(&account.chain)
        .map_err(|e| e.to_string())?;
    let updated_vclock = serde_json::to_string(&vclock)
        .map_err(|e| e.to_string())?;

    let result = serde_json::json!({
        "send_block":  send_block,
        "chain_json":  updated_chain,
        "vclock_json": updated_vclock,
    });

    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// Create a `Receive` block.
///
/// # Arguments
/// - `private_key_hex` — 64-char hex Ed25519 signing key
/// - `send_block_json` — JSON of the counterparty's `Send` block
/// - `chain_json`      — JSON array of the recipient's existing blocks
/// - `vclock_json`     — JSON `VectorClock` object
///
/// # Returns
/// Same shape as [`create_send_block`] but with `receive_block` key.
#[wasm_bindgen]
pub fn create_receive_block(
    private_key_hex: &str,
    send_block_json: &str,
    chain_json: &str,
    vclock_json: &str,
) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let signing_key = signing_key_from_hex(private_key_hex)?;

    let send_block: Block = serde_json::from_str(send_block_json)
        .map_err(|e| format!("Invalid send_block JSON: {e}"))?;

    let existing_chain: Vec<Block> = serde_json::from_str(chain_json)
        .map_err(|e| format!("Invalid chain JSON: {e}"))?;

    let mut vclock: VectorClock = serde_json::from_str(vclock_json)
        .map_err(|e| format!("Invalid vclock JSON: {e}"))?;

    let mut account = AccountChain::from_key_and_blocks(signing_key, existing_chain);

    let receive_block = account
        .receive(&send_block, &mut vclock)
        .map_err(|e| format!("receive error: {e:?}"))?;

    let updated_chain = serde_json::to_string(&account.chain)
        .map_err(|e| e.to_string())?;
    let updated_vclock = serde_json::to_string(&vclock)
        .map_err(|e| e.to_string())?;

    let result = serde_json::json!({
        "receive_block": receive_block,
        "chain_json":    updated_chain,
        "vclock_json":   updated_vclock,
    });

    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// Expose decentralized identifier generation.
#[wasm_bindgen]
pub fn get_did(public_key_hex: &str) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let key_bytes: [u8; 32] = hex::decode(public_key_hex)
        .map_err(|e| format!("Invalid public key hex: {e}"))?
        .try_into()
        .map_err(|_| "Public key must be 32 bytes".to_string())?;
    let did = arxia_did::ArxiaDid::from_public_key(&key_bytes)
        .map_err(|e| format!("Failed to generate DID: {e:?}"))?;
    Ok(did.to_string())
}

/// Create a Revoke block.
#[wasm_bindgen]
pub fn create_revoke_block(
    private_key_hex: &str,
    credential_hash: &str,
    chain_json: &str,
    vclock_json: &str,
) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let signing_key = signing_key_from_hex(private_key_hex)?;

    let existing_chain: Vec<Block> = serde_json::from_str(chain_json)
        .map_err(|e| format!("Invalid chain JSON: {e}"))?;

    let mut vclock: VectorClock = serde_json::from_str(vclock_json)
        .map_err(|e| format!("Invalid vclock JSON: {e}"))?;

    let mut account = AccountChain::from_key_and_blocks(signing_key, existing_chain);

    let revoke_block = account
        .revoke_credential(credential_hash, &mut vclock)
        .map_err(|e| format!("revoke error: {e:?}"))?;

    let updated_chain = serde_json::to_string(&account.chain)
        .map_err(|e| e.to_string())?;
    let updated_vclock = serde_json::to_string(&vclock)
        .map_err(|e| e.to_string())?;

    let result = serde_json::json!({
        "revoke_block": revoke_block,
        "chain_json":    updated_chain,
        "vclock_json":   updated_vclock,
    });

    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// Validate a list of ORV delegations and compute weight totals.
#[wasm_bindgen]
pub fn validate_delegations(delegations_json: &str) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let delegations: Vec<arxia_consensus::delegation::Delegation> = serde_json::from_str(delegations_json)
        .map_err(|e| format!("Invalid delegations JSON: {e}"))?;

    let mut graph = arxia_consensus::delegation::DelegationGraph::new();

    for d in delegations {
        graph.delegate(d).map_err(|e| format!("Delegation rejected: {e:?}"))?;
    }

    let snap = graph.snapshot();
    serde_json::to_string(&snap).map_err(|e| e.to_string())
}

/// Return the WASM binding version string.
#[wasm_bindgen]
pub fn wasm_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ── integrity: verify a single block (JSON) ───────────────────────────────────

/// Verify a single block: recompute Blake3 hash, validate Ed25519
/// signature under the account pubkey, reject low-order / off-curve
/// pubkeys. Returns `Ok(true)` on success, `Ok(false)` on any
/// validation failure, or `Err` if `block_json` is not a valid
/// `Block` JSON document.
///
/// This is the parse-time + signature-time gate that must run on
/// every block entering the wallet's local chain (from sync, from
/// peer gossip, or from a SQLite read).
#[wasm_bindgen]
pub fn verify_block_json(block_json: &str) -> Result<bool, String> {
    console_error_panic_hook::set_once();
    let block: Block = serde_json::from_str(block_json)
        .map_err(|e| format!("invalid block JSON: {e}"))?;
    Ok(verify_block(&block).is_ok())
}

// ── integrity: verify an entire account chain (JSON) ─────────────────────────

/// Verify the integrity of an account chain. Enforces for every
/// block: hash recomputation, Ed25519 signature, and chain
/// continuity (strictly monotonic nonces, `previous` points at
/// last hash, genesis is OPEN with `previous == ""` and
/// `nonce == 1`).
///
/// Returns `Ok(true)` if the chain is fully valid, `Ok(false)` if
/// any block fails verification or any continuity check fails.
/// `Err` only fires on malformed JSON input.
#[wasm_bindgen]
pub fn verify_chain_json(chain_json: &str) -> Result<bool, String> {
    console_error_panic_hook::set_once();
    let chain: Vec<Block> = serde_json::from_str(chain_json)
        .map_err(|e| format!("invalid chain JSON: {e}"))?;
    Ok(verify_chain_integrity(&chain).is_ok())
}

// ── DID strict parse ─────────────────────────────────────────────────────────

/// Strictly parse an Arxia DID string. Rejects malformed prefix,
/// non-base58 identifier, wrong decoded length. Returns the parsed
/// DID (canonical string + identifier hash hex) on success.
///
/// This is the safe path for DIDs received from untrusted sources
/// (QR codes, peer gossip, user input) — never use
/// `arxia_did::ArxiaDid::identifier()` for received DIDs.
#[wasm_bindgen]
pub fn parse_did_strict(did: &str) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let parsed = arxia_did::parse_did(did).map_err(|e| format!("{e:?}"))?;
    let identifier_hash_hex = hex::encode(parsed.identifier_hash);
    let out = serde_json::json!({
        "did": parsed.did,
        "identifier_hash_hex": identifier_hash_hex,
    });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

// ── finality: assess a single block's finality level ─────────────────────────

/// String-to-SyncResult mapping shared by `assess_block_finality`
/// and the JS-side `FinalityLatch`. The mapping is strict: any
/// other value yields an `Err` so the JS layer cannot silently
/// downgrade to an unintended variant.
fn parse_sync_result(kind: &str, mismatch_count: u64) -> Result<arxia_gossip::SyncResult, String> {
    match kind {
        "success" => Ok(arxia_gossip::SyncResult::Success),
        "mismatch" => Ok(arxia_gossip::SyncResult::Mismatch(
            usize::try_from(mismatch_count)
                .map_err(|_| "mismatch_count does not fit in usize".to_string())?,
        )),
        "no_neighbors" => Ok(arxia_gossip::SyncResult::NoNeighbors),
        other => Err(format!(
            "unknown sync_result kind '{other}' (expected success|mismatch|no_neighbors)"
        )),
    }
}

/// Decode a 64-char hex Blake3 block hash. Returns the 32 raw bytes.
fn decode_block_hash_hex(block_hash_hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(block_hash_hex)
        .map_err(|e| format!("invalid block hash hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "block hash must be exactly 32 bytes".to_string())?;
    Ok(arr)
}

/// Assess the finality level of a single block.
///
/// The function is stateless: it does NOT implement a latch. The
/// wallet maintains a JS-side `Record<blockHashHex, FinalityLevel>`
/// and applies the monotonic max on top of this snapshot.
///
/// `sync_result_kind` is one of `"success"`, `"mismatch"`,
/// `"no_neighbors"`. `sync_mismatch_count` is only used for
/// `"mismatch"`. L2 and L0 require signed votes / confirmations
/// from registered validators; this binding returns `"PENDING"`
/// for both because the current wallet has no validator registry.
/// Wiring a registry is a phase 2 task (gossip real).
///
/// Returns the level as a string: `"PENDING"`, `"L0"`, `"L1"`,
/// `"L2"`. Signature errors from registered validators surface
/// as `Err` (loud failure surface, mirroring the Rust contract).
#[wasm_bindgen]
pub fn assess_block_finality(
    amount_micro_arx: u64,
    block_hash_hex: &str,
    sync_result_kind: &str,
    sync_mismatch_count: u64,
) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let block_hash = decode_block_hash_hex(block_hash_hex)?;
    let sync_result = parse_sync_result(sync_result_kind, sync_mismatch_count)?;
    let registry = arxia_finality::ValidatorRegistry::new();
    let level = arxia_finality::assess_finality(
        amount_micro_arx,
        block_hash,
        &[],
        &sync_result,
        &[],
        &registry,
    )
    .map_err(|e| format!("finality assessment failed: {e}"))?;
    Ok(level.to_string())
}

/// Same as `assess_block_finality` but accepts JSON-encoded
/// confirmations and votes so future phases (when a validator
/// registry is wired) can call it without changing the signature.
///
/// `confirmations_json` and `votes_json` must be JSON arrays. The
/// current implementation ignores both (validator registry is
/// empty), so this binding behaves identically to
/// `assess_block_finality` today. The signature is exposed now so
/// phase 2 callers can swap the empty registry for a real one
/// without changing the JS surface.
#[wasm_bindgen]
#[allow(unused_variables)]
pub fn assess_block_finality_v2(
    amount_micro_arx: u64,
    block_hash_hex: &str,
    sync_result_kind: &str,
    sync_mismatch_count: u64,
    confirmations_json: &str,
    votes_json: &str,
) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let block_hash = decode_block_hash_hex(block_hash_hex)?;
    let sync_result = parse_sync_result(sync_result_kind, sync_mismatch_count)?;
    let registry = arxia_finality::ValidatorRegistry::new();
    let level = arxia_finality::assess_finality(
        amount_micro_arx,
        block_hash,
        &[],
        &sync_result,
        &[],
        &registry,
    )
    .map_err(|e| format!("finality assessment failed: {e}"))?;
    Ok(level.to_string())
}

// ── gossip: signed envelope construction and verification ─────────────────────

/// Build a `SignedGossipMessage::Ping` and return the serialized
/// envelope JSON. The envelope signs the canonical bytes
/// (`arxia-gossip-msg-v1 || pubkey || variant_tag || variant_fields`)
/// under the wallet's Ed25519 signing key. Peers verify before
/// accepting the message.
#[wasm_bindgen]
pub fn build_gossip_ping(sk_hex: &str, node_id: &str, timestamp_ms: u64) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let sk = signing_key_from_hex(sk_hex)?;
    let vk = sk.verifying_key();
    let sender_pubkey = vk.to_bytes();
    let message = arxia_gossip::GossipMessage::Ping {
        node_id: node_id.to_string(),
        timestamp: timestamp_ms,
    };
    let canonical = arxia_gossip::SignedGossipMessage::canonical_bytes(&message, &sender_pubkey);
    let sig = arxia_crypto::sign(&sk, &canonical);
    let envelope = arxia_gossip::SignedGossipMessage {
        message,
        sender_pubkey,
        signature: sig.to_vec(),
    };
    serde_json::to_string(&envelope).map_err(|e| e.to_string())
}

/// Build a `SignedGossipMessage::BlockAnnounce` carrying a single
/// block. The block is serialized to JSON bytes (which match the
/// 193-byte compact form for canonical lattice blocks). The
/// envelope is signed with the wallet's signing key.
///
/// `hops` is clamped to `MAX_BLOCK_ANNOUNCE_HOPS` (16) at the
/// envelope construction site; values above that are rejected
/// before signing, mirroring `GossipMessage::validate`.
#[wasm_bindgen]
pub fn build_gossip_block_announce(
    sk_hex: &str,
    block_json: &str,
    hops: u8,
) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let sk = signing_key_from_hex(sk_hex)?;
    let vk = sk.verifying_key();
    let sender_pubkey = vk.to_bytes();
    let block: Block = serde_json::from_str(block_json)
        .map_err(|e| format!("invalid block JSON: {e}"))?;
    let block_data = serde_json::to_vec(&block)
        .map_err(|e| format!("block serialize: {e}"))?;
    let message = arxia_gossip::GossipMessage::BlockAnnounce { block_data, hops };
    message
        .validate()
        .map_err(|e| format!("envelope invalid: {e}"))?;
    let canonical = arxia_gossip::SignedGossipMessage::canonical_bytes(&message, &sender_pubkey);
    let sig = arxia_crypto::sign(&sk, &canonical);
    let envelope = arxia_gossip::SignedGossipMessage {
        message,
        sender_pubkey,
        signature: sig.to_vec(),
    };
    serde_json::to_string(&envelope).map_err(|e| e.to_string())
}

/// Build a `SignedGossipMessage::ValidatorVote` envelope signed
/// with the given signing key. Returns the JSON envelope string.
#[wasm_bindgen]
pub fn build_gossip_validator_vote(
    sk_hex: &str,
    block_hash_hex: &str,
    delegated_stake_micro_arx: u64,
    vote_nonce: u64,
) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let sk = signing_key_from_hex(sk_hex)?;
    let block_hash = decode_block_hash_hex_v3(block_hash_hex)?;
    let vote = arxia_consensus::cast_vote(&sk, block_hash, delegated_stake_micro_arx, vote_nonce);
    let vk = sk.verifying_key();
    let sender_pubkey = vk.to_bytes();
    let message = arxia_gossip::GossipMessage::ValidatorVote {
        block_hash: hex::encode(vote.block_hash),
        voter_pubkey: hex::encode(vote.voter_pubkey),
        delegated_stake: vote.delegated_stake,
        nonce: vote.nonce,
        signature: hex::encode(vote.signature),
    };
    let canonical = arxia_gossip::SignedGossipMessage::canonical_bytes(&message, &sender_pubkey);
    let sig = arxia_crypto::sign(&sk, &canonical);
    let envelope = arxia_gossip::SignedGossipMessage {
        message,
        sender_pubkey,
        signature: sig.to_vec(),
    };
    serde_json::to_string(&envelope).map_err(|e| e.to_string())
}

/// Verify a signed gossip envelope. Returns `Ok(true)` if the
/// Ed25519 signature is valid under `envelope.sender_pubkey` AND
/// the wrapped message passes structural validation
/// (`MAX_BLOCK_ANNOUNCE_BYTES`, `MAX_BLOCK_ANNOUNCE_HOPS`,
/// `MAX_NONCE_SYNC_RESPONSE_ENTRIES`).
///
/// Throws on malformed JSON input. Returns `Ok(false)` on any
/// verification failure (bad signature, structural cap violation,
/// invalid pubkey, wrong signature length).
#[wasm_bindgen]
pub fn verify_gossip_envelope(envelope_json: &str) -> Result<bool, String> {
    console_error_panic_hook::set_once();
    let env: arxia_gossip::SignedGossipMessage = serde_json::from_str(envelope_json)
        .map_err(|e| format!("invalid envelope JSON: {e}"))?;
    Ok(env.verify().is_ok())
}

/// Return the reason an envelope failed verification, for logging.
/// Empty string on success.
#[wasm_bindgen]
pub fn gossip_envelope_error(envelope_json: &str) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let env: arxia_gossip::SignedGossipMessage = serde_json::from_str(envelope_json)
        .map_err(|e| format!("invalid envelope JSON: {e}"))?;
    Ok(match env.verify() {
        Ok(()) => String::new(),
        Err(e) => format!("{e}"),
    })
}

// ── gossip: singleton GossipNode for the wallet's local mesh state ────────────

/// Process-wide singleton slot for the wallet's `GossipNode`.
/// The wallet has one gossip node; its `known_blocks` and
/// `nonce_registry` are shared between the sync UI, the receive
/// pipeline, and the peer-state listeners. Held as
/// `Mutex<Option<...>>` (not a `OnceLock` of the inner value) so
/// the test harness can clear it between cases; production code
/// always goes through `init_gossip_node` / `reset_gossip_node`.
static GOSSIP_NODE: OnceLock<Mutex<Option<arxia_gossip::GossipNode>>> = OnceLock::new();

fn gossip_slot() -> &'static Mutex<Option<arxia_gossip::GossipNode>> {
    GOSSIP_NODE.get_or_init(|| Mutex::new(None))
}

fn with_gossip_node<R>(
    f: impl FnOnce(&mut arxia_gossip::GossipNode) -> R,
) -> Result<R, String> {
    let slot = gossip_slot();
    let mut guard = slot.lock().map_err(|e| format!("gossip lock poisoned: {e}"))?;
    let node = guard
        .as_mut()
        .ok_or_else(|| "gossip node not initialized; call init_gossip_node first".to_string())?;
    Ok(f(node))
}

/// Initialize the singleton gossip node. Idempotent: a second
/// call with the same `node_id` is a no-op. A second call with a
/// different `node_id` is rejected to keep the singleton stable
/// across the wallet's lifetime.
#[wasm_bindgen]
pub fn init_gossip_node(node_id: &str) -> Result<bool, String> {
    console_error_panic_hook::set_once();
    let slot = gossip_slot();
    let mut guard = slot.lock().map_err(|e| format!("gossip lock poisoned: {e}"))?;
    if let Some(existing) = guard.as_ref() {
        return Ok(existing.node_id == node_id);
    }
    *guard = Some(arxia_gossip::GossipNode::new(node_id.to_string()));
    Ok(true)
}

/// Reset the singleton gossip node (drops all known blocks and
/// the nonce registry, and clears the process-wide slot so a
/// subsequent `init_gossip_node` with a different `node_id` is
/// honored). Intended for sign-out / chain reset flows AND for
/// the test harness which needs a clean slate between cases.
#[wasm_bindgen]
pub fn reset_gossip_node() -> Result<(), String> {
    console_error_panic_hook::set_once();
    let slot = gossip_slot();
    let mut guard = slot.lock().map_err(|e| format!("gossip lock poisoned: {e}"))?;
    *guard = None;
    Ok(())
}

/// Add a block (parsed from `block_json`) to the local gossip
/// node. The block is signature-verified by `GossipNode::add_block`
/// via `verify_block`. Returns `true` if the block was accepted
/// (or was already known — idempotent), `false` if rejected
/// (invalid signature, double-spend, etc.).
#[wasm_bindgen]
pub fn gossip_add_block(block_json: &str) -> Result<bool, String> {
    console_error_panic_hook::set_once();
    let block: Block = serde_json::from_str(block_json)
        .map_err(|e| format!("invalid block JSON: {e}"))?;
    with_gossip_node(|node| node.add_block(block).is_ok())
}

/// Merge a remote nonce registry (JSON) into the local gossip
/// node and run `sync_nonces_before_l1`. Returns one of:
/// - `"success"` — all nonces match
/// - `"mismatch:N"` — N conflicting entries
/// - `"no_neighbors"` — remote registry is empty
///
/// The local node's `pending_conflicts` is also updated as a
/// side-effect of the merge.
#[wasm_bindgen]
pub fn gossip_sync(remote_registry_json: &str) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let remote = registry_from_json(remote_registry_json)?;
    with_gossip_node(|node| {
        let _ = node.merge_registry(&remote);
        let result = arxia_gossip::sync_nonces_before_l1(&node.nonce_registry, &remote);
        match result {
            arxia_gossip::SyncResult::Success => "success".to_string(),
            arxia_gossip::SyncResult::Mismatch(n) => format!("mismatch:{n}"),
            arxia_gossip::SyncResult::NoNeighbors => "no_neighbors".to_string(),
        }
    })
}

/// Return the local gossip node's nonce registry as a JSON
/// array of `{"account": "<hex>", "nonce": <u64>, "hash": "<hex>"}`
/// objects. The flat array shape round-trips through
/// `gossip_sync` on the peer and is friendlier to JS than nested
/// maps (which serde cannot round-trip natively through
/// `BTreeMap<(pubkey, nonce), hash>`).
#[wasm_bindgen]
pub fn gossip_nonce_registry() -> Result<String, String> {
    console_error_panic_hook::set_once();
    let dto = with_gossip_node(|node| {
        node.nonce_registry
            .iter()
            .map(|((account, nonce), hash)| RegistryEntryDto {
                account: hex::encode(account),
                nonce: *nonce,
                hash: hex::encode(hash),
            })
            .collect::<Vec<_>>()
    })?;
    serde_json::to_string(&dto).map_err(|e| e.to_string())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RegistryEntryDto {
    account: String,
    nonce: u64,
    hash: String,
}

fn registry_from_json(s: &str) -> Result<NonceRegistry, String> {
    let entries: Vec<RegistryEntryDto> = serde_json::from_str(s)
        .map_err(|e| format!("invalid registry JSON: {e}"))?;
    let mut out = NonceRegistry::new();
    for e in entries {
        let account_bytes: [u8; 32] = hex::decode(&e.account)
            .map_err(|err| format!("invalid account hex in registry: {err}"))?
            .try_into()
            .map_err(|_| "account must be 32 bytes".to_string())?;
        let hash_bytes: [u8; 32] = hex::decode(&e.hash)
            .map_err(|err| format!("invalid hash hex in registry: {err}"))?
            .try_into()
            .map_err(|_| "hash must be 32 bytes".to_string())?;
        out.insert((account_bytes, e.nonce), hash_bytes);
    }
    Ok(out)
}

/// Drain and return the accumulated `pending_conflicts` from
/// the local gossip node as JSON. Each entry carries the
/// `(account, nonce, local_hash, remote_hash)` so the caller can
/// route it to ORV-based resolution.
#[wasm_bindgen]
pub fn gossip_drain_conflicts() -> Result<String, String> {
    console_error_panic_hook::set_once();
    let drained = with_gossip_node(|node| std::mem::take(&mut node.pending_conflicts))?;
    let dto: Vec<NonceConflictDto> = drained.into_iter().map(NonceConflictDto::from).collect();
    serde_json::to_string(&dto).map_err(|e| e.to_string())
}

/// Serializable view of a [`arxia_gossip::NonceConflict`]. The
/// source type intentionally does not derive `Serialize` (its
/// internal `(account, nonce)` tuple field is opaque to clients);
/// this DTO is the WASM-boundary shape.
#[derive(serde::Serialize)]
struct NonceConflictDto {
    /// Hex-encoded account public key.
    account: String,
    /// The conflicting nonce.
    nonce: u64,
    /// Local registry's recorded hash, hex.
    local_hash: String,
    /// Remote registry's offered hash, hex.
    remote_hash: String,
}

impl From<NonceConflict> for NonceConflictDto {
    fn from(c: NonceConflict) -> Self {
        Self {
            account: hex::encode(c.key.0),
            nonce: c.key.1,
            local_hash: hex::encode(c.local_hash),
            remote_hash: hex::encode(c.remote_hash),
        }
    }
}

/// Number of distinct block hashes the local gossip node is
/// tracking. Useful for UI badges.
#[wasm_bindgen]
pub fn gossip_known_block_count() -> Result<usize, String> {
    console_error_panic_hook::set_once();
    with_gossip_node(|node| node.known_blocks.len())
}

/// Register a peer (node id) with the local gossip node. The
/// wallet's own `node_id` is filtered out by the caller (this
/// binding accepts any id; client code is responsible for not
/// self-registering).
#[wasm_bindgen]
pub fn gossip_add_peer(peer_id: &str) -> Result<bool, String> {
    console_error_panic_hook::set_once();
    with_gossip_node(|node| {
        node.peers.insert(peer_id.to_string());
        true
    })
}

/// Decode a `BlockAnnounce`'s inner `block_data` (the bytes the
/// gossip message carries) and return the block as JSON. The
/// block must still be signature-verified by the caller before
/// it is trusted (the gossip dispatcher does this in
/// `verify_block_json` after the envelope signature passes).
#[wasm_bindgen]
pub fn gossip_block_from_envelope(envelope_json: &str) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let env: arxia_gossip::SignedGossipMessage = serde_json::from_str(envelope_json)
        .map_err(|e| format!("invalid envelope JSON: {e}"))?;
    let block_data = match env.message {
        arxia_gossip::GossipMessage::BlockAnnounce { block_data, .. } => block_data,
        arxia_gossip::GossipMessage::Ping { .. } => {
            return Err("envelope is a Ping, not a BlockAnnounce".to_string());
        }
        arxia_gossip::GossipMessage::NonceSyncRequest { .. } => {
            return Err("envelope is a NonceSyncRequest, not a BlockAnnounce".to_string());
        }
        arxia_gossip::GossipMessage::NonceSyncResponse { .. } => {
            return Err("envelope is a NonceSyncResponse, not a BlockAnnounce".to_string());
        }
        arxia_gossip::GossipMessage::ValidatorVote { .. } => {
            return Err("envelope is a ValidatorVote, not a BlockAnnounce".to_string());
        }
    };
    let block: Block = serde_json::from_slice(&block_data)
        .map_err(|e| format!("invalid block bytes: {e}"))?;
    serde_json::to_string(&block).map_err(|e| e.to_string())
}

// ── validator voting (ORV) ─────────────────────────────────────────────────────

/// Decode a 32-byte hex block hash. Centralized helper.
fn decode_block_hash_hex_v3(block_hash_hex: &str) -> Result<[u8; 32], String> {
    decode_block_hash_hex(block_hash_hex)
}

/// Cast a validator vote on a block. The vote is signed under
/// `sk_hex` over the canonical `compute_vote_hash` bytes
/// (blake3 of `block_hash || voter_pubkey || delegated_stake ||
/// nonce`). The returned JSON has the shape
/// `{ "block_hash": "<hex>", "voter_pubkey": "<hex>",
///   "delegated_stake": <u64>, "nonce": <u64>,
///   "signature": "<hex>" }`.
///
/// The vote's pubkey is the Ed25519 verifying key derived from
/// `sk_hex` — the caller does not have to pass it. The nonce is
/// the validator's per-block monotonic counter (typically
/// `now_millis() / 1000`); replay protection at ingress lives
/// in the gossip dispatcher.
#[wasm_bindgen]
pub fn cast_validator_vote(
    sk_hex: &str,
    block_hash_hex: &str,
    delegated_stake_micro_arx: u64,
    vote_nonce: u64,
) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let sk = signing_key_from_hex(sk_hex)?;
    let block_hash = decode_block_hash_hex_v3(block_hash_hex)?;
    let vote = arxia_consensus::cast_vote(&sk, block_hash, delegated_stake_micro_arx, vote_nonce);
    // The Rust struct has `[u8; 32]` / `[u8; 64]` byte-array
    // fields. Serialise as hex for the JS boundary.
    let value = serde_json::json!({
        "block_hash": hex::encode(vote.block_hash),
        "voter_pubkey": hex::encode(vote.voter_pubkey),
        "delegated_stake": vote.delegated_stake,
        "nonce": vote.nonce,
        "signature": hex::encode(vote.signature),
    });
    serde_json::to_string(&value).map_err(|e| e.to_string())
}

/// Verify a vote for ingress. `vote_json` is the shape produced
/// by `cast_validator_vote`; `known_block_hashes_hex` is a JSON
/// array of 64-char hex strings of the block hashes the local
/// node already knows. A vote whose target is not in
/// `known_block_hashes_hex` is rejected with
/// `ArxiaError::UnknownVoteTarget` (HIGH-006).
///
/// Returns `true` iff the signature is valid AND the target is
/// in the local block store. `false` on any other failure
/// (signature mismatch, malformed input, etc.).
#[wasm_bindgen]
pub fn verify_validator_vote(
    vote_json: &str,
    known_block_hashes_hex_json: &str,
) -> Result<bool, String> {
    console_error_panic_hook::set_once();
    let parsed: serde_json::Value = serde_json::from_str(vote_json)
        .map_err(|e| format!("invalid vote JSON: {e}"))?;
    let block_hash_bytes = hex::decode(
        parsed
            .get("block_hash")
            .and_then(|v| v.as_str())
            .ok_or("vote missing block_hash")?,
    )
    .map_err(|e| format!("block_hash hex: {e}"))?;
    let block_hash: [u8; 32] = block_hash_bytes
        .try_into()
        .map_err(|_| "block_hash must be 32 bytes".to_string())?;
    let voter_pubkey_bytes = hex::decode(
        parsed
            .get("voter_pubkey")
            .and_then(|v| v.as_str())
            .ok_or("vote missing voter_pubkey")?,
    )
    .map_err(|e| format!("voter_pubkey hex: {e}"))?;
    let voter_pubkey: [u8; 32] = voter_pubkey_bytes
        .try_into()
        .map_err(|_| "voter_pubkey must be 32 bytes".to_string())?;
    let delegated_stake = parsed
        .get("delegated_stake")
        .and_then(|v| v.as_u64())
        .ok_or("vote missing delegated_stake (u64)")?;
    let nonce = parsed
        .get("nonce")
        .and_then(|v| v.as_u64())
        .ok_or("vote missing nonce (u64)")?;
    let signature_bytes = hex::decode(
        parsed
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or("vote missing signature")?,
    )
    .map_err(|e| format!("signature hex: {e}"))?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let vote = arxia_consensus::VoteORV {
        block_hash,
        voter_pubkey,
        delegated_stake,
        nonce,
        signature,
    };
    let known: Vec<String> = serde_json::from_str(known_block_hashes_hex_json)
        .map_err(|e| format!("known_block_hashes JSON: {e}"))?;
    let mut set = std::collections::HashSet::new();
    for h in known {
        let bytes: [u8; 32] = hex::decode(&h)
            .map_err(|e| format!("known hash hex: {e}"))?
            .try_into()
            .map_err(|_| "known hash must be 32 bytes".to_string())?;
        set.insert(bytes);
    }
    Ok(arxia_consensus::verify_vote_known(&vote, &set).is_ok())
}

// ── reconciliation: merge two partitions into a single report ──────────────

/// Serializable shape of a [`arxia_crdt::ReconciliationReport`].
/// The source type doesn't derive `Serialize` (its inner maps
/// are opaque to clients); this DTO is the WASM-boundary shape.
#[derive(serde::Serialize)]
struct ReconciliationReportDto {
    balances: std::collections::HashMap<String, i64>,
    conflicts: Vec<ResolvedConflictDto>,
    rejected_receives: Vec<RejectedReceiveDto>,
    rejected_genesis: Vec<RejectedGenesisDto>,
}

#[derive(serde::Serialize)]
struct ResolvedConflictDto {
    account: String,
    nonce: u64,
    winner_hash: String,
    loser_hashes: Vec<String>,
    method: String,
}

#[derive(serde::Serialize)]
struct RejectedReceiveDto {
    account: String,
    nonce: u64,
    receive_hash: String,
    source_hash: String,
    reason: String,
}

#[derive(serde::Serialize)]
struct RejectedGenesisDto {
    account: String,
    nonce: u64,
    block_hash: String,
    reason: String,
}

impl From<arxia_crdt::ResolvedConflict> for ResolvedConflictDto {
    fn from(c: arxia_crdt::ResolvedConflict) -> Self {
        Self {
            account: c.account,
            nonce: c.nonce,
            winner_hash: c.winner_hash,
            loser_hashes: c.loser_hashes,
            method: c.method.to_string(),
        }
    }
}

impl From<arxia_crdt::RejectedReceive> for RejectedReceiveDto {
    fn from(r: arxia_crdt::RejectedReceive) -> Self {
        Self {
            account: r.account,
            nonce: r.nonce,
            receive_hash: r.receive_hash,
            source_hash: r.source_hash,
            reason: r.reason.to_string(),
        }
    }
}

impl From<RejectedGenesis> for RejectedGenesisDto {
    fn from(r: RejectedGenesis) -> Self {
        Self {
            account: r.account,
            nonce: r.nonce,
            block_hash: r.block_hash,
            reason: r.reason.to_string(),
        }
    }
}

impl From<arxia_crdt::ReconciliationReport> for ReconciliationReportDto {
    fn from(r: arxia_crdt::ReconciliationReport) -> Self {
        Self {
            balances: r.balances,
            conflicts: r
                .conflicts
                .into_iter()
                .map(ResolvedConflictDto::from)
                .collect(),
            rejected_receives: r
                .rejected_receives
                .into_iter()
                .map(RejectedReceiveDto::from)
                .collect(),
            rejected_genesis: r
                .rejected_genesis
                .into_iter()
                .map(RejectedGenesisDto::from)
                .collect(),
        }
    }
}

/// Reconcile two partitions of blocks. Each `chain_json` is a
/// JSON array of `Block` objects. The result is a JSON object
/// with the per-account balance map, the resolved conflicts
/// (with their `method`), the rejected receives, and the
/// rejected genesis (MED-016) opens.
///
/// Throws on malformed JSON or when reconciliation produces a
/// negative balance (a per-account defense in the underlying
/// CRDT cascade).
#[wasm_bindgen]
pub fn reconcile_partitions(chain_a_json: &str, chain_b_json: &str) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let a: Vec<Block> = serde_json::from_str(chain_a_json)
        .map_err(|e| format!("invalid chain_a JSON: {e}"))?;
    let b: Vec<Block> = serde_json::from_str(chain_b_json)
        .map_err(|e| format!("invalid chain_b JSON: {e}"))?;
    let report = arxia_crdt::reconcile_partitions(&a, &b)
        .map_err(|e| format!("reconciliation failed: {e:?}"))?;
    let dto: ReconciliationReportDto = report.into();
    serde_json::to_string(&dto).map_err(|e| e.to_string())
}

// ── gossip: NonceSyncResponse envelope builder ───────────────────────────────

/// Build a signed `SignedGossipMessage::NonceSyncResponse`
/// envelope from the local nonce-registry JSON (the shape
/// returned by `gossip_nonce_registry`). The envelope is
/// signed with the wallet's Ed25519 key and the canonical
/// `arxia-gossip-msg-v1` domain.
///
/// The resulting envelope is what the wallet broadcasts in
/// response to a `NonceSyncRequest` from a peer. Receiving
/// peers merge the entries via the gossip dispatcher and run
/// `sync_nonces_before_l1` to detect divergence.
#[wasm_bindgen]
pub fn build_nonce_sync_response(
    sk_hex: &str,
    registry_json: &str,
) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let sk = signing_key_from_hex(sk_hex)?;
    let sender_pubkey = sk.verifying_key().to_bytes();
    let entries: Vec<RegistryEntryDto> = serde_json::from_str(registry_json)
        .map_err(|e| format!("invalid registry JSON: {e}"))?;
    let mut gossip_entries: Vec<([u8; 32], u64, [u8; 32])> =
        Vec::with_capacity(entries.len());
    for e in entries {
        let account: [u8; 32] = hex::decode(&e.account)
            .map_err(|err| format!("invalid account hex: {err}"))?
            .try_into()
            .map_err(|_| "account must be 32 bytes".to_string())?;
        let hash: [u8; 32] = hex::decode(&e.hash)
            .map_err(|err| format!("invalid hash hex: {err}"))?
            .try_into()
            .map_err(|_| "hash must be 32 bytes".to_string())?;
        gossip_entries.push((hash, e.nonce, account));
    }
    let message = arxia_gossip::GossipMessage::NonceSyncResponse {
        entries: gossip_entries,
    };
    let canonical = arxia_gossip::SignedGossipMessage::canonical_bytes(&message, &sender_pubkey);
    let sig = arxia_crypto::sign(&sk, &canonical);
    let envelope = arxia_gossip::SignedGossipMessage {
        message,
        sender_pubkey,
        signature: sig.to_vec(),
    };
    serde_json::to_string(&envelope).map_err(|e| e.to_string())
}

// ── tests (native only) ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_wallet_flow() {
        // Create Alice's wallet
        let alice_json = create_arxia_wallet(500_000_000).unwrap();
        let alice: serde_json::Value = serde_json::from_str(&alice_json).unwrap();
        let alice_priv = alice["private_key_hex"].as_str().unwrap();
        let alice_pub  = alice["public_key_hex"].as_str().unwrap();
        let alice_chain = serde_json::to_string(&serde_json::json!([alice["open_block"]])).unwrap();
        let alice_vclock = serde_json::to_string(&alice["vclock"]).unwrap();

        // Create Bob's wallet
        let bob_json = create_arxia_wallet(0).unwrap();
        let bob: serde_json::Value = serde_json::from_str(&bob_json).unwrap();
        let bob_priv = bob["private_key_hex"].as_str().unwrap();
        let bob_pub  = bob["public_key_hex"].as_str().unwrap();
        let bob_chain = serde_json::to_string(&serde_json::json!([bob["open_block"]])).unwrap();
        let bob_vclock = serde_json::to_string(&bob["vclock"]).unwrap();

        // Alice sends 100 ARX (100_000_000 micro-ARX) to Bob
        let send_result_json = create_send_block(
            alice_priv,
            bob_pub,
            100_000_000,
            &alice_chain,
            &alice_vclock,
        ).unwrap();
        let send_result: serde_json::Value = serde_json::from_str(&send_result_json).unwrap();
        let send_block_json = serde_json::to_string(&send_result["send_block"]).unwrap();

        // Bob receives
        let recv_result_json = create_receive_block(
            bob_priv,
            &send_block_json,
            &bob_chain,
            &bob_vclock,
        ).unwrap();
        let recv_result: serde_json::Value = serde_json::from_str(&recv_result_json).unwrap();
        
        // Check Bob's updated balance
        let updated_chain: Vec<serde_json::Value> = serde_json::from_str(
            recv_result["chain_json"].as_str().unwrap()
        ).unwrap();
        let last_block = updated_chain.last().unwrap();
        assert_eq!(last_block["balance"].as_u64().unwrap(), 100_000_000);
        
        println!("✅ Alice pub: {}", &alice_pub[..16]);
        println!("✅ Bob   pub: {}", &bob_pub[..16]);
        println!("✅ Send block hash: {}", send_result["send_block"]["hash"].as_str().unwrap());
        println!("✅ Bob balance after receive: {} micro-ARX", last_block["balance"]);
    }

    // ── verify_block_json / verify_chain_json ──────────────────────────────

    fn make_alice_open_block_json() -> String {
        let alice_json = create_arxia_wallet(1_000_000).unwrap();
        let alice: serde_json::Value = serde_json::from_str(&alice_json).unwrap();
        serde_json::to_string(&alice["open_block"]).unwrap()
    }

    #[test]
    fn test_verify_block_json_accepts_canonical_block() {
        let block_json = make_alice_open_block_json();
        assert_eq!(verify_block_json(&block_json).unwrap(), true);
    }

    #[test]
    fn test_verify_block_json_rejects_tampered_hash() {
        let mut block: serde_json::Value =
            serde_json::from_str(&make_alice_open_block_json()).unwrap();
        let s = block["hash"].as_str().unwrap().to_string();
        let tampered = format!("{}{}", &s[..s.len() - 1], if s.ends_with('0') { '1' } else { '0' });
        block["hash"] = serde_json::Value::String(tampered);
        let tampered_json = serde_json::to_string(&block).unwrap();
        assert_eq!(verify_block_json(&tampered_json).unwrap(), false);
    }

    #[test]
    fn test_verify_block_json_rejects_zero_signature() {
        let mut block: serde_json::Value =
            serde_json::from_str(&make_alice_open_block_json()).unwrap();
        block["signature"] = serde_json::Value::Array(vec![
            serde_json::Value::from(0u8);
            64
        ]);
        let json = serde_json::to_string(&block).unwrap();
        assert_eq!(verify_block_json(&json).unwrap(), false);
    }

    #[test]
    fn test_verify_block_json_rejects_malformed_json() {
        let err = verify_block_json("not json").unwrap_err();
        assert!(err.contains("invalid block JSON"));
    }

    #[test]
    fn test_verify_chain_json_accepts_legit_send_then_receive() {
        let alice_json = create_arxia_wallet(1_000_000).unwrap();
        let alice: serde_json::Value = serde_json::from_str(&alice_json).unwrap();
        let alice_priv = alice["private_key_hex"].as_str().unwrap();
        let alice_chain = serde_json::to_string(&serde_json::json!([alice["open_block"]])).unwrap();
        let alice_vclock = serde_json::to_string(&alice["vclock"]).unwrap();

        let bob_json = create_arxia_wallet(0).unwrap();
        let bob: serde_json::Value = serde_json::from_str(&bob_json).unwrap();
        let bob_pub = bob["public_key_hex"].as_str().unwrap();
        let bob_priv = bob["private_key_hex"].as_str().unwrap();
        let bob_chain = serde_json::to_string(&serde_json::json!([bob["open_block"]])).unwrap();
        let bob_vclock = serde_json::to_string(&bob["vclock"]).unwrap();

        let send_json = create_send_block(
            alice_priv, bob_pub, 100_000, &alice_chain, &alice_vclock,
        ).unwrap();
        let send_result: serde_json::Value = serde_json::from_str(&send_json).unwrap();
        let send_block_json = serde_json::to_string(&send_result["send_block"]).unwrap();
        let alice_chain_after_send = send_result["chain_json"].as_str().unwrap().to_string();

        let recv_json = create_receive_block(
            bob_priv, &send_block_json, &bob_chain, &bob_vclock,
        ).unwrap();
        let recv_result: serde_json::Value = serde_json::from_str(&recv_json).unwrap();
        let bob_chain_after_recv = recv_result["chain_json"].as_str().unwrap().to_string();

        assert_eq!(
            verify_chain_json(&alice_chain_after_send).unwrap(),
            true,
            "alice's chain (open + send) must verify"
        );
        assert_eq!(
            verify_chain_json(&bob_chain_after_recv).unwrap(),
            true,
            "bob's chain (open + receive) must verify"
        );
    }

    #[test]
    fn test_verify_chain_json_rejects_tampered_block_in_middle() {
        let alice_json = create_arxia_wallet(1_000_000).unwrap();
        let alice: serde_json::Value = serde_json::from_str(&alice_json).unwrap();
        let alice_priv = alice["private_key_hex"].as_str().unwrap();
        let alice_chain = serde_json::to_string(&serde_json::json!([alice["open_block"]])).unwrap();
        let alice_vclock = serde_json::to_string(&alice["vclock"]).unwrap();
        let bob_json = create_arxia_wallet(0).unwrap();
        let bob: serde_json::Value = serde_json::from_str(&bob_json).unwrap();
        let bob_pub = bob["public_key_hex"].as_str().unwrap();
        let bob_priv = bob["private_key_hex"].as_str().unwrap();

        let send_json = create_send_block(
            alice_priv, bob_pub, 100_000, &alice_chain, &alice_vclock,
        ).unwrap();
        let send_result: serde_json::Value = serde_json::from_str(&send_json).unwrap();
        let send_block_json = serde_json::to_string(&send_result["send_block"]).unwrap();
        let alice_chain_after_send = send_result["chain_json"].as_str().unwrap().to_string();

        let recv_json = create_receive_block(
            bob_priv, &send_block_json,
            &serde_json::to_string(&serde_json::json!([bob["open_block"]])).unwrap(),
            &serde_json::to_string(&bob["vclock"]).unwrap(),
        ).unwrap();
        let _ = recv_json;

        let mut chain: serde_json::Value =
            serde_json::from_str(&alice_chain_after_send).unwrap();
        chain[1]["block_type"]["Send"]["amount"] = serde_json::Value::from(999_999u64);
        let tampered = serde_json::to_string(&chain).unwrap();
        assert_eq!(verify_chain_json(&tampered).unwrap(), false);

        assert_eq!(verify_chain_json(&alice_chain_after_send).unwrap(), true);
    }

    // ── parse_did_strict ──────────────────────────────────────────────────

    #[test]
    fn test_parse_did_strict_accepts_canonical_did() {
        let alice_json = create_arxia_wallet(0).unwrap();
        let alice: serde_json::Value = serde_json::from_str(&alice_json).unwrap();
        let pubkey_hex = alice["public_key_hex"].as_str().unwrap();
        let did = get_did(pubkey_hex).unwrap();
        let parsed = parse_did_strict(&did).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&parsed).unwrap();
        assert_eq!(parsed["did"].as_str().unwrap(), did);
        assert_eq!(parsed["identifier_hash_hex"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn test_parse_did_strict_rejects_missing_prefix() {
        let err = parse_did_strict("not-a-did").unwrap_err();
        assert!(err.to_lowercase().contains("prefix"));
    }

    #[test]
    fn test_parse_did_strict_rejects_empty_string() {
        assert!(parse_did_strict("").is_err());
    }

    #[test]
    fn test_parse_did_strict_rejects_wrong_namespace() {
        let err = parse_did_strict("did:other:abc").unwrap_err();
        assert!(err.to_lowercase().contains("prefix"));
    }

    // ── assess_block_finality ─────────────────────────────────────────────

    fn hex_hash(bytes: [u8; 32]) -> String {
        hex::encode(bytes)
    }

    #[test]
    fn test_assess_block_finality_pending_by_default() {
        let h = hex_hash([0x11u8; 32]);
        let level = assess_block_finality(100_000_000, &h, "no_neighbors", 0).unwrap();
        assert_eq!(level, "PENDING");
    }

    #[test]
    fn test_assess_block_finality_l1_when_sync_success() {
        let h = hex_hash([0x22u8; 32]);
        let level = assess_block_finality(100_000_000, &h, "success", 0).unwrap();
        assert_eq!(level, "L1 (gossip)");
    }

    #[test]
    fn test_assess_block_finality_pending_when_sync_mismatch() {
        let h = hex_hash([0x33u8; 32]);
        let level = assess_block_finality(100_000_000, &h, "mismatch", 3).unwrap();
        assert_eq!(level, "PENDING");
    }

    #[test]
    fn test_assess_block_finality_rejects_bad_sync_kind() {
        let h = hex_hash([0x44u8; 32]);
        let err = assess_block_finality(0, &h, "wat", 0).unwrap_err();
        assert!(err.contains("unknown sync_result kind"));
    }

    #[test]
    fn test_assess_block_finality_rejects_bad_hash_length() {
        let err = assess_block_finality(0, "abcd", "success", 0).unwrap_err();
        assert!(err.contains("block hash must be exactly 32 bytes"));
    }

    // ── parse_sync_result helper ──────────────────────────────────────────

    #[test]
    fn test_parse_sync_result_routes_three_kinds() {
        assert!(matches!(
            parse_sync_result("success", 0).unwrap(),
            arxia_gossip::SyncResult::Success
        ));
        assert!(matches!(
            parse_sync_result("mismatch", 5).unwrap(),
            arxia_gossip::SyncResult::Mismatch(5)
        ));
        assert!(matches!(
            parse_sync_result("no_neighbors", 0).unwrap(),
            arxia_gossip::SyncResult::NoNeighbors
        ));
        assert!(parse_sync_result("nope", 0).is_err());
    }

    // ── gossip envelope construction and verification ──────────────────

    /// Static lock that serializes gossip tests. Tests in the same
    /// `cargo test` invocation run in parallel by default and the
    /// gossip singleton is process-wide state; this lock prevents
    /// the test cases from racing each other. Production code
    /// (i.e. the non-test bindings) does not acquire this lock.
    static GOSSIP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Lock the gossip test mutex AND reset the singleton. Every
    /// gossip-touching test calls this once at the top so it
    /// starts from a clean slate AND excludes other gossip tests
    /// for the duration of its run.
    fn lock_gossip_test() -> std::sync::MutexGuard<'static, ()> {
        let guard = GOSSIP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_gossip_node().unwrap();
        guard
    }

    fn fresh_keypair_hex() -> (String, String) {
        let (sk, vk) = arxia_crypto::generate_keypair();
        (hex::encode(sk.to_bytes()), hex::encode(vk.to_bytes()))
    }

    #[test]
    fn test_build_gossip_ping_round_trips_through_verify() {
        let (sk, _vk) = fresh_keypair_hex();
        let envelope_json = build_gossip_ping(&sk, "node-1", 1_700_000_000_000).unwrap();
        assert!(verify_gossip_envelope(&envelope_json).unwrap());
        assert!(gossip_envelope_error(&envelope_json).unwrap().is_empty());
    }

    #[test]
    fn test_build_gossip_ping_rejects_tampered_envelope() {
        let (sk, _vk) = fresh_keypair_hex();
        let envelope_json = build_gossip_ping(&sk, "node-1", 1_700_000_000_000).unwrap();
        let mut env: serde_json::Value = serde_json::from_str(&envelope_json).unwrap();
        env["message"]["Ping"]["node_id"] = serde_json::Value::String("attacker".into());
        let tampered = serde_json::to_string(&env).unwrap();
        assert!(!verify_gossip_envelope(&tampered).unwrap());
        let reason = gossip_envelope_error(&tampered).unwrap();
        assert!(!reason.is_empty());
    }

    #[test]
    fn test_build_gossip_ping_cross_signer_rejected() {
        let (sk_a, _vk_a) = fresh_keypair_hex();
        let (sk_b, _vk_b) = fresh_keypair_hex();
        let envelope_json = build_gossip_ping(&sk_a, "node-a", 100).unwrap();
        // Re-sign with sk_b but keep sk_a's pubkey → must fail.
        let mut env: arxia_gossip::SignedGossipMessage = serde_json::from_str(&envelope_json).unwrap();
        let canonical = arxia_gossip::SignedGossipMessage::canonical_bytes(&env.message, &env.sender_pubkey);
        let sk_b_parsed = signing_key_from_hex(&sk_b).unwrap();
        let sig = arxia_crypto::sign(&sk_b_parsed, &canonical);
        env.signature = sig.to_vec();
        let tampered = serde_json::to_string(&env).unwrap();
        assert!(!verify_gossip_envelope(&tampered).unwrap());
    }

    #[test]
    fn test_build_gossip_block_announce_round_trips() {
        let (sk, _vk) = fresh_keypair_hex();
        let block_json = make_alice_open_block_json();
        let envelope_json = build_gossip_block_announce(&sk, &block_json, 3).unwrap();
        assert!(verify_gossip_envelope(&envelope_json).unwrap());

        let recovered = gossip_block_from_envelope(&envelope_json).unwrap();
        assert!(verify_block_json(&recovered).unwrap());
    }

    #[test]
    fn test_build_gossip_validator_vote_round_trips() {
        let (sk, _vk) = fresh_keypair_hex();
        let bh = "ab".repeat(32);
        let envelope_json = build_gossip_validator_vote(&sk, &bh, 5_000_000, 1).unwrap();
        // The envelope must be a valid signed message.
        assert!(verify_gossip_envelope(&envelope_json).unwrap());
        // The inner message must be a ValidatorVote with the right hash.
        let env: arxia_gossip::SignedGossipMessage =
            serde_json::from_str(&envelope_json).unwrap();
        match env.message {
            arxia_gossip::GossipMessage::ValidatorVote {
                block_hash,
                delegated_stake,
                nonce,
                ..
            } => {
                assert_eq!(block_hash, bh);
                assert_eq!(delegated_stake, 5_000_000);
                assert_eq!(nonce, 1);
            }
            _ => panic!("expected ValidatorVote"),
        }
    }

    #[test]
    fn test_build_gossip_block_announce_rejects_oversize_hops() {
        let (sk, _vk) = fresh_keypair_hex();
        let block_json = make_alice_open_block_json();
        let err = build_gossip_block_announce(&sk, &block_json, 200).unwrap_err();
        assert!(err.contains("envelope invalid"));
    }

    // ── gossip singleton node + sync ───────────────────────────────────

    fn fresh_node_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("node-{t}")
    }

    #[test]
    fn test_gossip_node_init_idempotent() {
        let _g = lock_gossip_test();
        let id = fresh_node_id();
        assert!(init_gossip_node(&id).unwrap());
        assert!(init_gossip_node(&id).unwrap(), "second init with same id is a no-op");
    }

    #[test]
    fn test_gossip_node_rejects_id_change() {
        let _g = lock_gossip_test();
        let id = fresh_node_id();
        let other = fresh_node_id();
        assert_ne!(id, other, "test bug: fresh ids must differ");
        let first = init_gossip_node(&id).unwrap();
        assert!(first, "first init must return true");
        // Verify the singleton actually persists.
        let slot = gossip_slot();
        {
            let guard = slot.lock().unwrap();
            let persisted = guard.as_ref().map(|n| n.node_id.clone());
            assert_eq!(persisted.as_deref(), Some(id.as_str()),
                "singleton must hold the first id before second init");
        }
        // A different id must return false (singleton preserved).
        let second = init_gossip_node(&other).unwrap();
        assert!(!second, "second init with a different id must return false");
        // The persisted id must still be the original.
        let guard = slot.lock().unwrap();
        let persisted = guard.as_ref().map(|n| n.node_id.clone());
        assert_eq!(persisted.as_deref(), Some(id.as_str()),
            "singleton must preserve the first id after a refused re-init");
    }

    #[test]
    fn test_gossip_add_block_round_trip() {
        let _g = lock_gossip_test();
        let id = fresh_node_id();
        init_gossip_node(&id).unwrap();
        let block_json = make_alice_open_block_json();
        assert!(gossip_add_block(&block_json).unwrap());
        // Idempotent: adding the same block twice does not fail.
        assert!(gossip_add_block(&block_json).unwrap());
        assert_eq!(gossip_known_block_count().unwrap(), 1);
    }

    #[test]
    fn test_gossip_add_block_rejects_invalid_signature() {
        let _g = lock_gossip_test();
        let id = fresh_node_id();
        init_gossip_node(&id).unwrap();
        let mut block: serde_json::Value = serde_json::from_str(&make_alice_open_block_json()).unwrap();
        block["signature"] = serde_json::Value::Array(vec![serde_json::Value::from(0u8); 64]);
        let tampered = serde_json::to_string(&block).unwrap();
        assert!(!gossip_add_block(&tampered).unwrap());
    }

    #[test]
    fn test_gossip_sync_returns_mismatch_for_divergent_registry() {
        let _g = lock_gossip_test();
        let id = fresh_node_id();
        init_gossip_node(&id).unwrap();

        // Build a block, add to local, build a divergent block at the
        // same (account, nonce) to model a conflict, then ask the
        // gossip layer to sync.
        let alice_json = create_arxia_wallet(1_000_000).unwrap();
        let alice: serde_json::Value = serde_json::from_str(&alice_json).unwrap();
        let alice_priv = alice["private_key_hex"].as_str().unwrap();
        let alice_chain = serde_json::to_string(&serde_json::json!([alice["open_block"]])).unwrap();
        let alice_vclock = serde_json::to_string(&alice["vclock"]).unwrap();
        let bob_json = create_arxia_wallet(0).unwrap();
        let bob: serde_json::Value = serde_json::from_str(&bob_json).unwrap();
        let bob_pub = bob["public_key_hex"].as_str().unwrap();
        let bob_priv = bob["private_key_hex"].as_str().unwrap();

        // Legit send to Bob.
        let send_json = create_send_block(
            alice_priv, bob_pub, 50_000, &alice_chain, &alice_vclock,
        ).unwrap();
        let send: serde_json::Value = serde_json::from_str(&send_json).unwrap();
        let send_block_json = serde_json::to_string(&send["send_block"]).unwrap();
        let alice_chain_after = send["chain_json"].as_str().unwrap().to_string();
        let alice_vclock_after = send["vclock_json"].as_str().unwrap().to_string();

        assert!(gossip_add_block(&send_block_json).unwrap());
        // Drain — should be empty for a clean add.
        let conflicts = gossip_drain_conflicts().unwrap();
        assert_eq!(conflicts, "[]");

        // Construct a divergent block at the same (account, nonce)
        // by re-signing a competing send to a different destination.
        let bob2_json = create_arxia_wallet(0).unwrap();
        let bob2: serde_json::Value = serde_json::from_str(&bob2_json).unwrap();
        let bob2_pub = bob2["public_key_hex"].as_str().unwrap();
        let _ = bob_priv; // silence unused
        let _ = bob_pub;
        let alt_send = create_send_block(
            alice_priv, bob2_pub, 50_000, &alice_chain, &alice_vclock,
        ).unwrap();
        // alt_send's send block is at nonce=2 with a different hash
        // because the destination differs. Add it → the local
        // gossip node's add_block will see a hash mismatch for the
        // (account, nonce) already in the registry and return
        // DoubleSpend, which `gossip_add_block` reports as Ok(false).
        let alt_send: serde_json::Value = serde_json::from_str(&alt_send).unwrap();
        let alt_send_block_json = serde_json::to_string(&alt_send["send_block"]).unwrap();
        assert!(!gossip_add_block(&alt_send_block_json).unwrap());

        // Now build a remote registry that diverges and run sync.
        let alt_send_block: Block = serde_json::from_str(&alt_send_block_json).unwrap();
        let account_bytes: [u8; 32] = hex::decode(&alt_send_block.account).unwrap().try_into().unwrap();
        let hash_bytes: [u8; 32] = hex::decode(&alt_send_block.hash).unwrap().try_into().unwrap();
        let remote_json = serde_json::to_string(&vec![RegistryEntryDto {
            account: hex::encode(account_bytes),
            nonce: alt_send_block.nonce,
            hash: hex::encode(hash_bytes),
        }]).unwrap();

        let result = gossip_sync(&remote_json).unwrap();
        // After merge_registry, the local registry was updated to
        // match the remote at the divergent (account, nonce). The
        // sync result is therefore "success" (no remaining
        // mismatches) — but conflicts are recorded in
        // pending_conflicts.
        assert!(matches!(result.as_str(), "success" | "mismatch:1"));
        let drained = gossip_drain_conflicts().unwrap();
        let drained: serde_json::Value = serde_json::from_str(&drained).unwrap();
        assert!(drained.as_array().unwrap().len() >= 1);

        let _ = alice_chain_after;
        let _ = alice_vclock_after;
    }

    #[test]
    fn test_gossip_sync_no_neighbors_for_empty_remote() {
        let _g = lock_gossip_test();
        let id = fresh_node_id();
        init_gossip_node(&id).unwrap();
        let result = gossip_sync("[]").unwrap();
        assert_eq!(result, "no_neighbors");
    }

    #[test]
    fn test_gossip_nonce_registry_round_trips_through_sync() {
        let _g = lock_gossip_test();
        let id = fresh_node_id();
        init_gossip_node(&id).unwrap();
        let block_json = make_alice_open_block_json();
        gossip_add_block(&block_json).unwrap();

        let local = gossip_nonce_registry().unwrap();
        let local: serde_json::Value = serde_json::from_str(&local).unwrap();
        // The single (account, 1) entry from the OPEN block is
        // present.
        let entries = local.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]["account"].is_string());
        assert_eq!(entries[0]["nonce"].as_u64().unwrap(), 1);

        // Sync the local registry against itself: must report
        // "success".
        let result = gossip_sync(&local.to_string()).unwrap();
        assert_eq!(result, "success");
    }

    #[test]
    fn test_gossip_add_peer_increments_known_set() {
        let _g = lock_gossip_test();
        let id = fresh_node_id();
        init_gossip_node(&id).unwrap();
        gossip_add_peer("peer-a").unwrap();
        gossip_add_peer("peer-b").unwrap();
        // peers is a HashSet; the gossip_node lock guard confirms
        // membership.
        let slot = gossip_slot();
        let guard = slot.lock().unwrap();
        let node = guard.as_ref().unwrap();
        assert!(node.peers.contains("peer-a"));
        assert!(node.peers.contains("peer-b"));
    }

    #[test]
    fn test_gossip_block_from_envelope_rejects_non_announce() {
        let (sk, _vk) = fresh_keypair_hex();
        let envelope_json = build_gossip_ping(&sk, "node-1", 100).unwrap();
        let err = gossip_block_from_envelope(&envelope_json).unwrap_err();
        assert!(err.contains("Ping"));
    }

    #[test]
    fn test_gossip_node_init_required_before_use() {
        let _g = lock_gossip_test();
        let res = gossip_known_block_count();
        assert!(res.is_err());
    }

    #[test]
    fn test_gossip_node_init_or_count_succeeds_after_init() {
        let _g = lock_gossip_test();
        let id = fresh_node_id();
        init_gossip_node(&id).unwrap();
        assert_eq!(gossip_known_block_count().unwrap(), 0);
    }

    // ── validator voting ──────────────────────────────────────────────

    #[test]
    fn test_cast_validator_vote_round_trips() {
        let (sk, _vk) = fresh_keypair_hex();
        let bh = "ab".repeat(32);
        let vote_json = cast_validator_vote(&sk, &bh, 1_000_000, 7).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&vote_json).unwrap();
        assert_eq!(parsed["block_hash"].as_str().unwrap(), bh);
        assert_eq!(parsed["nonce"].as_u64().unwrap(), 7);
        assert_eq!(parsed["delegated_stake"].as_u64().unwrap(), 1_000_000);
        assert_eq!(parsed["signature"].as_str().unwrap().len(), 128);
    }

    #[test]
    fn test_verify_validator_vote_accepts_self_consistent_vote() {
        let (sk, vk) = fresh_keypair_hex();
        let bh = "ab".repeat(32);
        let vote_json = cast_validator_vote(&sk, &bh, 5_000_000, 1).unwrap();
        let known_json = serde_json::to_string(&vec![bh.clone()]).unwrap();
        assert!(verify_validator_vote(&vote_json, &known_json).unwrap());
        // Sanity: the derived pubkey matches the wallet's.
        let parsed: serde_json::Value = serde_json::from_str(&vote_json).unwrap();
        assert_eq!(parsed["voter_pubkey"].as_str().unwrap(), vk);
    }

    #[test]
    fn test_verify_validator_vote_rejects_unknown_target() {
        // HIGH-006: signature is valid but the targeted block
        // hash is not in the local block store.
        let (sk, _vk) = fresh_keypair_hex();
        let phantom = "de".repeat(32);
        let vote_json = cast_validator_vote(&sk, &phantom, 1_000, 1).unwrap();
        let known_json = serde_json::to_string(&vec!["ab".repeat(32)]).unwrap();
        assert!(!verify_validator_vote(&vote_json, &known_json).unwrap());
    }

    #[test]
    fn test_verify_validator_vote_rejects_tampered_signature() {
        let (sk, _vk) = fresh_keypair_hex();
        let bh = "ab".repeat(32);
        let mut vote_json = cast_validator_vote(&sk, &bh, 1_000, 1).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&vote_json).unwrap();
        // Flip the last hex digit of the signature.
        let sig = parsed["signature"].as_str().unwrap().to_string();
        let tampered = format!("{}{}", &sig[..sig.len() - 1], if sig.ends_with('0') { '1' } else { '0' });
        parsed["signature"] = serde_json::Value::String(tampered);
        vote_json = serde_json::to_string(&parsed).unwrap();
        let known_json = serde_json::to_string(&vec![bh]).unwrap();
        assert!(!verify_validator_vote(&vote_json, &known_json).unwrap());
    }

    // ── reconciliation ───────────────────────────────────────────────

    #[test]
    fn test_reconcile_partitions_balances_match() {
        // Two chains with disjoint accounts; reconciliation
        // should produce the union of balances.
        let alice_json = create_arxia_wallet(1_000_000).unwrap();
        let alice: serde_json::Value = serde_json::from_str(&alice_json).unwrap();
        let bob_json = create_arxia_wallet(0).unwrap();
        let bob: serde_json::Value = serde_json::from_str(&bob_json).unwrap();
        let chain_a = serde_json::to_string(&serde_json::json!([
            alice["open_block"],
        ]))
        .unwrap();
        let chain_b = serde_json::to_string(&serde_json::json!([
            bob["open_block"],
        ]))
        .unwrap();
        let report = reconcile_partitions(&chain_a, &chain_b).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&report).unwrap();
        // The two open blocks have distinct accounts; both
        // balances must be present in the report.
        let balances = parsed["balances"].as_object().unwrap();
        assert!(balances.len() >= 2);
    }

    #[test]
    fn test_reconcile_partitions_detects_conflict() {
        // Same account, same nonce, different SEND destinations
        // → diverging hashes → exactly one conflict entry.
        let alice_json = create_arxia_wallet(1_000_000).unwrap();
        let alice: serde_json::Value = serde_json::from_str(&alice_json).unwrap();
        let alice_priv = alice["private_key_hex"].as_str().unwrap();
        let alice_chain = serde_json::to_string(&serde_json::json!([alice["open_block"]])).unwrap();
        let alice_vclock = serde_json::to_string(&alice["vclock"]).unwrap();
        let bob_json = create_arxia_wallet(0).unwrap();
        let bob: serde_json::Value = serde_json::from_str(&bob_json).unwrap();
        let bob_pub = bob["public_key_hex"].as_str().unwrap();
        let bob2_json = create_arxia_wallet(0).unwrap();
        let bob2: serde_json::Value = serde_json::from_str(&bob2_json).unwrap();
        let bob2_pub = bob2["public_key_hex"].as_str().unwrap();

        let send_a = create_send_block(
            alice_priv, bob_pub, 100_000, &alice_chain, &alice_vclock,
        ).unwrap();
        let send_b = create_send_block(
            alice_priv, bob2_pub, 200_000, &alice_chain, &alice_vclock,
        ).unwrap();
        let send_a: serde_json::Value = serde_json::from_str(&send_a).unwrap();
        let send_b: serde_json::Value = serde_json::from_str(&send_b).unwrap();
        // Partition A: open + send_to_bob1
        let chain_a = serde_json::to_string(&serde_json::json!([
            alice["open_block"],
            send_a["send_block"],
        ]))
        .unwrap();
        // Partition B: open + send_to_bob2
        let chain_b = serde_json::to_string(&serde_json::json!([
            alice["open_block"],
            send_b["send_block"],
        ]))
        .unwrap();
        let report = reconcile_partitions(&chain_a, &chain_b).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&report).unwrap();
        let conflicts = parsed["conflicts"].as_array().unwrap();
        assert!(!conflicts.is_empty(), "expected at least one conflict");
        let first = &conflicts[0];
        assert_eq!(first["method"].as_str().unwrap(), "hash_tiebreaker");
        assert!(first["loser_hashes"].as_array().unwrap().len() >= 1);
    }

    #[test]
    fn test_reconcile_partitions_rejects_malformed_input() {
        let err = reconcile_partitions("not json", "[]").unwrap_err();
        assert!(err.contains("invalid chain_a"));
        let err = reconcile_partitions("[]", "not json").unwrap_err();
        assert!(err.contains("invalid chain_b"));
    }

    // ── NonceSyncResponse builder ─────────────────────────────────────

    #[test]
    fn test_build_nonce_sync_response_round_trips() {
        let (sk, _vk) = fresh_keypair_hex();
        let alice_json = create_arxia_wallet(1_000_000).unwrap();
        let alice: serde_json::Value = serde_json::from_str(&alice_json).unwrap();
        let open_block: Block = serde_json::from_value(alice["open_block"].clone()).unwrap();
        let account_bytes: [u8; 32] = hex::decode(&open_block.account).unwrap().try_into().unwrap();
        let hash_bytes: [u8; 32] = hex::decode(&open_block.hash).unwrap().try_into().unwrap();
        let registry = serde_json::to_string(&vec![RegistryEntryDto {
            account: hex::encode(account_bytes),
            nonce: open_block.nonce,
            hash: hex::encode(hash_bytes),
        }])
        .unwrap();
        let envelope_json = build_nonce_sync_response(&sk, &registry).unwrap();
        assert!(verify_gossip_envelope(&envelope_json).unwrap());
        let env: arxia_gossip::SignedGossipMessage = serde_json::from_str(&envelope_json).unwrap();
        match env.message {
            arxia_gossip::GossipMessage::NonceSyncResponse { entries } => {
                assert_eq!(entries.len(), 1);
                let (hash, nonce, account) = &entries[0];
                assert_eq!(*hash, hash_bytes);
                assert_eq!(*account, account_bytes);
                assert_eq!(*nonce, open_block.nonce);
            }
            other => panic!("expected NonceSyncResponse, got {other:?}"),
        }
    }

    #[test]
    fn test_build_nonce_sync_response_rejects_bad_registry() {
        let (sk, _vk) = fresh_keypair_hex();
        let err = build_nonce_sync_response(&sk, "not json").unwrap_err();
        assert!(err.contains("invalid registry JSON"));
    }
}
