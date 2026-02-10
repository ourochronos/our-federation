# our-federation

P2P federation protocol for trust-based knowledge sharing across sovereign Valence nodes.

## Overview

our-federation implements the Valence Federation Protocol (VFP) — a system that enables independent knowledge bases to form trust networks, synchronize beliefs, and collectively resolve contradictions. Nodes discover each other, authenticate via challenge-response, build trust relationships that evolve through phases (observer to anchor), sync beliefs incrementally, manage group encryption via MLS, and coordinate cross-federation consent chains while preserving privacy through differential privacy mechanisms.

## Install

```bash
pip install our-federation
```

Requires `our-db`, `our-models`, `our-confidence`, `our-privacy`, `our-embeddings`, `our-compliance`, `cryptography>=41.0`, `pydantic>=2.0`, `aiohttp>=3.9`, `numpy>=1.24`, `dnspython>=2.4`, and `mcp>=1.0`.

## Usage

### Node Discovery

```python
from our_federation import discover_node, register_node, TrustPhase

# Discover a node by DID
node_doc = await discover_node("did:vkb:web:example.com")

# Register in local federation
node = await register_node(
    node_id=node_id,
    did=did,
    endpoint="https://example.com/federation",
    trust_phase=TrustPhase.OBSERVER,
)
```

### Belief Synchronization

```python
from our_federation import queue_belief_for_sync, SyncManager

# Queue a belief for sync to a peer
await queue_belief_for_sync(belief_id, target_node_id)

# Incremental sync with vector clocks
manager = SyncManager(node_id)
await manager.sync(peer_node_id)
```

### Trust Management

```python
from our_federation import TrustSignal, get_effective_trust

# Process trust signals (corroboration, disputes)
signal = TrustSignal(node_id=node_id, signal_type="corroboration", value=1.0)

# Compute effective trust with time decay and user overrides
trust = await get_effective_trust(node_id)
```

### Trust Phases

Nodes progress through trust phases based on behavior:

| Phase | Description |
|-------|-------------|
| `OBSERVER` | Can read, no write access |
| `CONTRIBUTOR` | Can share beliefs |
| `PARTICIPANT` | Full sync capabilities |
| `ANCHOR` | Trusted for transitive trust propagation |

### Group Encryption (MLS)

```python
from our_federation.groups import (
    create_federation_group,
    encrypt_group_content,
    decrypt_group_content,
)

# Create encrypted group
group, creator_kp = create_federation_group(
    federation_id=federation_id,
    creator_did=creator_did,
    creator_signing_key=signing_key,
)

# Encrypt/decrypt within group
encrypted = encrypt_group_content(content, group_state, sender_index)
plaintext = decrypt_group_content(encrypted, group_state, sender_index)
```

### Cross-Federation Consent

```python
from our_federation import CrossFederationConsentService, RevocationScope

service = CrossFederationConsentService(consent_store, policy_store, signer)

# Validate consent chain across federation boundaries
result = await service.validate_chain(chain, cross_federation_policy)

# Revoke consent (local, downstream, or full chain)
await service.revoke_consent(chain_id, RevocationScope.DOWNSTREAM)
```

### Privacy-Preserving Aggregation

```python
from our_federation import compute_private_aggregate, PrivacyConfig

config = PrivacyConfig(epsilon=0.5, delta=1e-5)

# Aggregate beliefs with differential privacy (Laplace/Gaussian noise)
result = await compute_private_aggregate(
    beliefs_by_federation, topic, config, method="noisy_max"
)
```

## API

### Core

`FederationNode`, `NodeStatus`, `TrustPhase`, `FederatedBelief`, `DID`, `DIDDocument`

### Discovery & Auth

`discover_node()`, `register_node()`, `bootstrap_federation()`, `create_auth_challenge()`, `verify_auth_challenge()`, `NonceTracker`

### Sync

`SyncManager`, `queue_belief_for_sync()`, `SyncState`, `SyncEvent`

### Trust

`TrustManager`, `TrustSignal`, `TrustPropagation`, `compute_transitive_trust()`, `get_effective_trust()`

### Groups

`create_federation_group()`, `add_member()`, `remove_member()`, `encrypt_group_content()`, `decrypt_group_content()`, `rotate_keys()`

### Consent

`CrossFederationConsentChain`, `CrossFederationConsentService`, `FederationConsentPolicy`, `RevocationScope`

### Privacy

`PrivacyBudget`, `PrivacyConfig`, `compute_private_aggregate()`, `add_laplace_noise()`, `add_gaussian_noise()`

### Security

`RingDetector`, `SybilClusterDetector`, `TrustVelocityAnalyzer`, `ChallengeResolver`

### Domain Verification

`verify_domain()`, `verify_dns_txt_record()`, `DomainChallenge`, `DomainAttestation`

## Key Properties

- **Challenge-response auth** with nonce replay protection
- **Cursor-based incremental sync** with vector clocks for conflict detection
- **Multi-hop transitive trust** with ring/Sybil attack detection
- **MLS group encryption** with epoch-based key rotation
- **Differential privacy** with tunable epsilon/delta and budget tracking
- **Cross-federation consent chains** with signature verification and scoped revocation
- **DNS-based domain verification** for node identity
- **1,397 tests** across 33 test modules

## Development

```bash
# Install with dev dependencies
make dev

# Run linters
make lint

# Run tests
make test

# Run tests with coverage
make test-cov

# Auto-format
make format
```

## State Ownership

Owns federation node records, trust edges, sync state (cursors, vector clocks), group state (MLS epochs, membership), consent chains, privacy budgets, and domain attestations.

## Part of Valence

This brick is part of the [Valence](https://github.com/ourochronos/valence) knowledge substrate. See [our-infra](https://github.com/ourochronos/our-infra) for ourochronos conventions.

## License

MIT
