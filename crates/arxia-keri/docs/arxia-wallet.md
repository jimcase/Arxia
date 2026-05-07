# Arxia Wallet: KERI Delegation & KelAnchor Specification

## Overview

This document describes the integration between **Arxia wallets** and **KERI delegation**, enabling KERI identities to control Arxia accounts through a secure delegation mechanism with **KelAnchor** event anchoring.

## Architecture

### Key Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Arxia Wallet                            │
│                                                              │
│  ┌─────────────────┐    ┌─────────────────────────────┐    │
│  │  KERI Identity  │    │      Arxia Account           │    │
│  │                 │    │                              │    │
│  │ - Identifier    │────│ - delegate_key (Arxia key) │    │
│  │ - Current Key   │    │ - delegation_proof          │    │
│  │ - KEL State     │    │ - kel_state                 │    │
│  │ - Signing Key   │    │ - kel_anchor                │    │
│  └─────────────────┘    └─────────────────────────────┘    │
│                                                              │
│  Arxia KeyManager ──────────────────────────────► Signs tx  │
└─────────────────────────────────────────────────────────────┘
```

### Two-Key Model

| Key Type | Owned By | Rotates? | Purpose |
|----------|----------|----------|---------|
| **KERI Signing Key** | KERI Identity | Yes | Signs KEL events |
| **Arxia Account Key** | Arxia Wallet | **No** | Signs Arxia transactions |

**Critical**: The Arxia Account Key is derived via BIP32 (`m/44'/60'/0'/0/0`) and is independent of KERI key rotations.

---

## Delegation Model

### DelegationProof Structure

```rust
pub struct DelegationProof {
    pub delegator: IdentifierPrefix,    // KERI identity (e.g., "EAhFi3V...")
    pub delegate_key: BasicPrefix,       // Arxia Account Key (e.g., "Dm3K7w...")
    pub dip_hash: Vec<u8>,               // Hash of Delegated Inception Event
    pub rotation_sn: u64,                // KERI sn at time of delegation
    pub created_at: u64,                 // Unix timestamp
}
```

### How Delegation Works

```
1. KERI Identity creates Delegated Inception Event (DIP)
   - Specifies delegate_key (Arxia Account Key)
   - DIP is added to KEL (Kernel Event Log)
   - DIP hash computed

2. Arxia Wallet receives and stores:
   - DelegationProof with dip_hash
   - Current KEL state snapshot
   - kel_anchor (block hash where KEL state is anchored)

3. Arxia Wallet can now sign transactions using delegate_key
   - Transactions include DelegationProof
   - Any verifier can validate using the anchored KEL state
```

---

## KelAnchor: Anchoring KEL Events to Arxia Blocks

### Why KelAnchor?

KERI rotations create new events in the KEL. For Arxia to:
1. Know when a delegation is revoked
2. Detect key compromises
3. Verify current KERI state

...it needs access to the latest KEL state. **KelAnchor** provides this by anchoring KEL hashes to Arxia blocks.

### KelAnchor Structure

```rust
pub struct KelAnchor {
    pub delegator: IdentifierPrefix,     // KERI identity
    pub block_height: u64,               // Arxia block number
    pub kel_hash: Vec<u8>,               // Hash of full KEL at this point
    pub events_count: u64,               // Number of events in KEL
    pub last_event_sn: u64,              // Last event sequence number
    pub anchored_at: u64,                // Timestamp
    pub signature: Vec<u8>,               // KERI signature on kel_hash
}
```

### KelAnchor Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│ Block 1000                                                   │
│   └── Transactions                                           │
│       └── [0] KelAnchor {                                   │
│               delegator: "EAhFi3V...",                      │
│               kel_hash: "abc123...",                        │
│               last_event_sn: 5,                             │
│           }                                                  │
└─────────────────────────────────────────────────────────────┘

    ▲ After KERI rotation (sn: 6)

┌─────────────────────────────────────────────────────────────┐
│ Block 1050                                                   │
│   └── Transactions                                           │
│       └── [0] KelAnchor {                                   │
│               delegator: "EAhFi3V...",                      │
│               kel_hash: "def456...",   ← New KEL hash       │
│               last_event_sn: 6,        ← Updated            │
│           }                                                  │
└─────────────────────────────────────────────────────────────┘
```

### Verification Flow

```rust
fn validate_transaction(tx: SignedTransaction) -> bool {
    // 1. Verify Arxia signature
    let delegate_key = tx.delegation_proof.delegate_key;
    if !verify_arxia_signature(&tx, delegate_key) {
        return false;
    }

    // 2. Get KelAnchor from block
    let anchor = get_kel_anchor(tx.delegation_proof.dip_hash, delegator);
    if anchor.is_none() {
        return false; // No anchor = no way to verify
    }

    // 3. Verify KEL state at anchor point
    let kel_state = get_kel_state_at_anchor(anchor);
    if !kel_state.contains_delegation(&tx.delegation_proof) {
        return false; // Delegation not in KEL
    }

    // 4. Check if delegation is still valid (not revoked)
    if kel_state.is_delegation_revoked(delegate_key) {
        return false;
    }

    true
}
```

---

## KEL State Management

### KELState Structure

```rust
pub struct KELState {
    pub delegator: IdentifierPrefix,
    pub current_sn: u64,
    pub current_key: BasicPrefix,        // Changes on rotation
    pub next_key: BasicPrefix,           // Pre-rotated next key
    pub next_key_hash: Vec<u8>,          // Hash committed at rotation time
    pub events: Vec<KERIEvent>,          // Full event history
    pub last_anchor: KelAnchor,
}
```

### KEL State After Rotation

```
BEFORE ROTATION:
┌─────────────────────────────────────────┐
│ KELState (sn: 5)                        │
│   current_key: Key_A                    │
│   next_key: Key_B                       │
│   next_key_hash: hash(Key_B)            │
└─────────────────────────────────────────┘

AFTER ROTATION (sn: 6):
┌─────────────────────────────────────────┐
│ KELState (sn: 6)                        │
│   current_key: Key_B  ← rotated         │
│   next_key: Key_C  ← new next           │
│   next_key_hash: hash(Key_C)            │
│   events: [sn5, sn6]  ← sn6 added       │
└─────────────────────────────────────────┘
```

### Event Propagation After Rotation

```
1. KERI Identity executes rotation
   - KEL now has event at sn: 6
   - New next_key is Key_C

2. Nominated witness/es witness the rotation event

3. KelAnchor transaction created and mined in Arxia block
   - Contains new kel_hash
   - Includes event data or merkle proof

4. Arxia Wallet detects new KelAnchor for its delegator
   - Updates KELState with new event
   - Now knows current_key = Key_B

5. Arxia can now:
   - Verify new KERI signatures using current_key
   - Detect if delegation is revoked
   - Detect if next_key_hash changes (pre-rotation)
```

---

## Security Considerations

### Pre-Rotation Protection

KERI pre-rotation commits to `next_key` before `current_key` is used.
This means:

| Threat | Protected? |
|--------|------------|
| Current key stolen | ✅ Next key is pre-rotated, attacker can't use current |
| Next key stolen | ❌ **Not protected** - attacker can rotate after using next |
| Arxia key stolen | ❌ New delegation required |

### Limitations

1. **Pre-rotation does NOT protect against next key theft** - If the next key is compromised before rotation, the attacker can rotate and control the identity.

2. **KEL state must be kept updated** - If Arxia doesn't receive rotation events, it won't know about key changes.

3. **KelAnchor latency** - There's a delay between KERI rotation and KelAnchor inclusion in an Arxia block.

### Recommendations

- Monitor KEL for delegation changes
- Consider threshold KERI setups (multi-sig)
- Use hardware security modules for Arxia Account Keys
- Set up alerts for unexpected KEL changes

---

## Data Flow Diagrams

### New Delegation Setup

```
KERI Identity                          Arxia Wallet
     │                                      │
     │──── create_delegation() ────────────► │
     │                                      │
     │◄──── return DelegatedInceptionData ──│
     │                                      │
     │──── sign_and_broadcast(DIP) ─────────► │
     │                                      │
     │                        ┌─────────────┴──────┐
     │                        │ Store:              │
     │                        │ - DelegationProof   │
     │                        │ - Initial KEL state│
     │                        │ - KelAnchor (block) │
     │                        └────────────────────┘
```

### Transaction Signing with Delegation

```
User wants to send Arxia transaction
     │
     ▼
Arxia Wallet:
  1. Create Transaction
  2. Sign with delegate_key (Arxia Account Key)
  3. Attach DelegationProof
  4. Broadcast
     │
     ▼
Arxia Network:
  - Verify signature with delegate_key
  - Lookup KelAnchor for delegator
  - Verify delegation exists in KEL at anchor
  - Check delegation not revoked
  - Include in block
```

### KERI Rotation with KelAnchor Update

```
KERI Identity                          Arxia Network
     │                                      │
     │──── rotation_occurs() ──────────────►│
     │                                      │
     │◄──── witness rotation event ─────────│
     │                                      │
     │                        ┌──────────────┴──────┐
     │                        │ Create KelAnchor:   │
     │                        │ - New kel_hash      │
     │                        │ - Updated sn        │
     │                        │ - Block inclusion   │
     │                        └────────────────────┘
     │
     │◄──── Arxia Wallet detects ─────────────│
     │         new KelAnchor                  │
     │         Updates KELState              │
```

---

## Implementation Notes

### ArxiaKeriWallet Module

```rust
pub struct ArxiaKeriWallet {
    keri_identity: IdentityManager,
    arxia_key_manager: ArxiaKeyManager,
    delegation: Option<DelegationProof>,
    kel_state: Option<KELState>,
    kel_anchor: Option<KelAnchor>,
}

impl ArxiaKeriWallet {
    // Create new wallet with KERI identity
    pub fn new(config: KeriConfig) -> Result<Self>;

    // Delegate to an Arxia key
    pub fn delegate_to_arxia(&mut self, arxia_key: BasicPrefix) -> Result<DelegationProof>;

    // Sign Arxia transaction with delegation proof
    pub fn sign_transaction(&self, tx: Transaction) -> Result<SignedTransaction>;

    // Update KEL state from KelAnchor
    pub fn update_kel_state(&mut self, anchor: KelAnchor) -> Result<()>;

    // Get current delegation proof
    pub fn get_delegation_proof(&self) -> Option<&DelegationProof>;
}
```

### KelAnchor Service

```rust
pub struct KelAnchorService {
    kel_store: Arc<dyn KELStore>,
    block_provider: Arc<dyn BlockProvider>,
}

impl KelAnchorService {
    // Anchor KEL state to Arxia block
    pub fn create_anchor(
        &self,
        delegator: &IdentifierPrefix,
        kel_state: &KELState,
    ) -> Result<KelAnchor>;

    // Retrieve KEL state at specific anchor
    pub fn get_kel_at_anchor(
        &self,
        delegator: &IdentifierPrefix,
        block_height: u64,
    ) -> Result<Option<KELState>>;

    // Get latest anchor for delegator
    pub fn get_latest_anchor(
        &self,
        delegator: &IdentifierPrefix,
    ) -> Result<Option<KelAnchor>>;
}
```

---

## Summary

| Concept | Purpose |
|---------|---------|
| **DelegationProof** | Binds KERI identity to Arxia key |
| **KELState** | Tracks current KERI state (keys, events) |
| **KelAnchor** | Anchors KEL state to Arxia blocks for verification |
| **ArxiaKeriWallet** | Unified wallet managing both KERI and Arxia keys |

The system enables KERI identities to control Arxia accounts while maintaining:
- **Independence**: Arxia key doesn't change with KERI rotations
- **Security**: Pre-rotation protects against current key theft
- **Verifiability**: Any party can verify delegation via KelAnchor
- **Persistence**: Delegation survives KERI rotations

---

## References

- [KERI Specification](https://arxiv.org/abs/1907.11743)
- [CESR Prime Specification](cesrPrime)
- [ACDC Protocol](./acdc_protocol.md)
- [Arxia DID Method](./arxia_did_method.md)