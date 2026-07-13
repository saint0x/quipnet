# QUICNET — Production Cryptographic Peer Fabric

**Document:** `PLAN.md`  
**Project:** Quipnet  
**Status:** Production architecture and execution plan  
**Purpose:** Define the end-to-end design, implementation, security, operations, and rollout of a global cryptographic peer network that serves as the foundational substrate for PersonalCloud, distributed inference, distributed storage, decentralized applications, and optional consensus or blockchain systems.

---

## 0. Executive Summary

Quipnet is a production-grade cryptographic peer fabric: a global, identity-native, encrypted, topology-aware network in which machines join as durable cryptographic peers and communicate over the best available path.

A Quipnet node may run on a laptop, home server, phone, embedded device, VPS, bare-metal host, cloud VM, colocation server, or regional edge point. Once enrolled, the node can discover authorized peers, advertise capabilities, establish direct encrypted sessions through NATs and firewalls when possible, fall back to relays when necessary, measure path quality continuously, and expose a uniform transport API to higher-level distributed applications.

Quipnet is not itself a blockchain, distributed filesystem, model-serving system, or scheduler. It is the common network substrate beneath those systems.

Quipnet owns:

- cryptographic node identity;
- enrollment and membership;
- peer discovery;
- endpoint discovery and NAT traversal;
- direct and relayed connectivity;
- secure session establishment;
- stream, message, datagram, and deadline-aware delivery;
- multipath and path migration;
- traffic prioritization;
- service and protocol negotiation;
- signed peer, service, and provider records;
- topology and capability telemetry;
- policy enforcement;
- observability, debugging, upgrades, and fleet operations.

Applications above Quipnet own:

- distributed inference execution;
- model partitioning and scheduling;
- content addressing and block exchange;
- erasure coding and storage durability;
- files and directories;
- job queues and workflow execution;
- blockchain consensus;
- payments, staking, proofs, and economic incentives;
- application-specific authorization and data semantics.

The critical architectural rule is:

> The packet path must remain fast, local, and decentralized. Global consensus must never be required to establish or use an ordinary peer connection.

Quipnet combines four proven ideas without importing any one existing stack wholesale:

1. Tailscale-style identity, endpoint discovery, NAT traversal, roaming, and relay fallback.
2. QUIC-style encrypted user-space transport, multiplexed streams, datagrams, connection migration, and congestion control.
3. libp2p-style peer identities, protocol negotiation, modular transports, peer routing, and gossip.
4. IPFS-style content identifiers and provider records as optional common services.

The implementation should be written primarily in Rust, use QUIC over UDP as the initial high-performance transport, expose a stable transport-neutral SDK, and support direct UDP, relay, same-host, LAN, and future specialized transports through one connection abstraction.

---

## 1. Product Vision

Quipnet should make any machine deployable as a programmable point in a private or decentralized global network.

A new server should be able to join with an operation similar to:

```bash
quicnet join \
  --network personalcloud-prod \
  --enrollment-token "$TOKEN" \
  --roles relay,storage-cache,inference-worker \
  --region fra
```

After joining, the node should:

1. generate or unlock its node identity;
2. exchange its short-lived enrollment credential for signed membership;
3. discover bootstrap and nearby peers;
4. publish signed endpoint and capability records;
5. characterize NAT and reachability;
6. establish direct paths where possible;
7. maintain relay paths for fallback;
8. measure RTT, jitter, loss, throughput, and stability;
9. accept only authorized protocols and workloads;
10. become schedulable by higher-level applications.

This should allow operators to place edge infrastructure wherever economically or physically useful:

- New York ingress nodes;
- Ashburn compute nodes;
- Frankfurt relays;
- Hetzner storage caches;
- home inference machines;
- mobile or embedded edge devices;
- colocated high-bandwidth model distribution nodes.

The network must support both closed, centrally governed PersonalCloud deployments and more decentralized or permissionless application networks above the same foundational peer layer.

---

## 2. Non-Negotiable Design Principles

### 2.1 Identity is cryptographic, not topological

A node is identified by a key-derived `PeerId`, not by an IP address, hostname, cloud account, or physical location.

```text
PeerId = multihash(canonical_public_identity_key)
```

IP addresses and ports are ephemeral path candidates. They must never be treated as durable identity.

### 2.2 Control and data planes are separate

The control plane distributes small signed records and policy. The data plane carries bulk traffic directly between peers whenever possible.

No coordinator, ledger, DHT, or consensus group should proxy normal application payloads.

### 2.3 Direct paths are preferred; relays guarantee reachability

The path engine must aggressively discover and upgrade to direct UDP or IPv6 paths. Relays exist for bootstrap, hostile networks, failover, and deliberate regional routing—not as the normal high-throughput path.

### 2.4 The transport API expresses intent

Applications must be able to indicate whether traffic is:

- reliable and ordered;
- reliable but message-oriented;
- unreliable;
- deadline-sensitive;
- bulk and resumable;
- latency-critical;
- background;
- redundant across paths.

A single undifferentiated byte stream is insufficient for distributed inference and storage.

### 2.5 The base layer is application-agnostic

Quipnet may know that a peer advertises `inference/1` or `blocks/1`, but it must not know transformer-layer semantics, file-directory semantics, or transaction validation rules.

### 2.6 Decentralization does not mean consensus everywhere

Most peer state should use signed records with expiry and eventual consistency. Strong consensus should be used only by applications that require a globally ordered or Byzantine-resilient state machine.

### 2.7 Measured topology beats declared topology

Peer capabilities and locations may be self-declared, but scheduling-critical attributes must be measured and scored by observers:

- RTT;
- jitter;
- loss;
- sustained throughput;
- relay dependence;
- availability;
- successful transfer rate;
- observed compute performance.

### 2.8 Versioning and migration are designed from day one

Every protocol, record type, handshake extension, and local state schema must be versioned. The production network must support rolling upgrades and mixed-version peers.

### 2.9 Secure by default, observable by design

All peer traffic is authenticated and encrypted. Every important state transition and path decision must be inspectable without exposing plaintext payloads or private keys.

### 2.10 Physics-aware distributed systems

Quipnet should minimize avoidable overhead, but it cannot remove speed-of-light delay, congestion, ISP asymmetry, packet loss, or limited uplink bandwidth. Applications must partition work at network-tolerant boundaries.

---

## 3. Scope

### 3.1 In scope

- node identity and key lifecycle;
- network membership and capability grants;
- private and public network modes;
- peer records and signed advertisements;
- bootstrap discovery;
- local-network discovery;
- distributed peer routing;
- NAT classification and endpoint discovery;
- UDP hole punching;
- IPv6 direct connectivity;
- port mapping where available;
- direct QUIC sessions;
- relay sessions;
- path probing and scoring;
- path migration;
- multipath abstraction;
- streams, datagrams, messages, and partial reliability;
- protocol negotiation;
- network and application traffic classes;
- admission control and quotas;
- node resource and service advertisements;
- SDKs and daemon APIs;
- Linux-first production deployment;
- macOS and Windows clients;
- container and Kubernetes operation;
- metrics, tracing, logs, packet/path diagnostics;
- upgrade, rollback, and compatibility mechanisms;
- threat model and incident response;
- production testing and chaos testing.

### 3.2 Explicitly out of scope for the core

- blockchain execution;
- global transaction consensus;
- storage proof protocols;
- payment settlement;
- model execution;
- tensor partitioning;
- content chunk encoding;
- filesystem semantics;
- orchestration policy beyond generic service/capability routing;
- application data encryption above transport where end-to-end application keys are desired.

These will be separate Quipnet protocols and applications.

---

## 4. System Model

### 4.1 Node

A Quipnet node is a running instance of `quicnetd` with:

- a long-lived identity key or hardware-backed identity;
- one or more network memberships;
- signed capability grants;
- a local peer store;
- endpoint candidates;
- a path engine;
- a secure transport engine;
- registered application protocols;
- optional relay, bootstrap, directory, observer, or authority roles.

### 4.2 Network

A Quipnet network is a cryptographically scoped administrative and routing domain.

Each network has:

- `NetworkId`;
- one or more root or delegated membership authorities;
- membership policy;
- protocol policy;
- discovery policy;
- optional bootstrap infrastructure;
- optional relay map;
- optional DHT namespace;
- optional gossip topics;
- revocation and epoch state.

A node may belong to multiple networks concurrently, but identities, records, addresses, policy, and routing tables must remain isolated by `NetworkId`.

### 4.3 Peer identity hierarchy

Recommended hierarchy:

```text
Account or organization root
  └── network authority
       └── node identity
            ├── daemon session key
            ├── workload identity
            ├── protocol identity
            └── application-specific key
```

Use separate keys for durable identity and transport sessions. A durable node identity signs rotating session credentials; transport keys rotate frequently without changing the node's `PeerId`.

### 4.4 Roles

Roles are capability bundles, not trusted labels.

Initial roles:

- `ordinary-peer`;
- `bootstrap`;
- `relay`;
- `peer-relay`;
- `directory-cache`;
- `network-observer`;
- `membership-authority`;
- `revocation-publisher`;
- `storage-provider`;
- `inference-worker`;
- `ingress-gateway`;
- `consensus-member`.

A node may possess multiple roles, each represented by signed, scoped, expiring grants.

---

## 5. High-Level Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│ Applications                                                 │
│ inference • storage • files • agents • ledger • messaging   │
├──────────────────────────────────────────────────────────────┤
│ Application Protocols                                       │
│ /quicnet/inference/1 • /blocks/1 • /consensus/1 • /rpc/1    │
├──────────────────────────────────────────────────────────────┤
│ Fabric Services                                             │
│ discovery • signed records • DHT • gossip • service routing │
├──────────────────────────────────────────────────────────────┤
│ Session and Delivery Layer                                  │
│ streams • messages • datagrams • deadlines • priorities     │
├──────────────────────────────────────────────────────────────┤
│ Path Engine                                                 │
│ NAT traversal • probing • migration • multipath • relays    │
├──────────────────────────────────────────────────────────────┤
│ Identity, Membership, Policy                                │
│ PeerId • keys • grants • capabilities • revocation          │
├──────────────────────────────────────────────────────────────┤
│ Physical and Host Networking                                │
│ UDP • IPv4 • IPv6 • LAN • WAN • Wi-Fi • cellular • cloud   │
└──────────────────────────────────────────────────────────────┘
```

The production node is divided into components with explicit internal interfaces rather than one monolithic daemon.

---

## 6. Repository and Component Layout

Recommended monorepo:

```text
quicnet/
├── Cargo.toml
├── crates/
│   ├── qn-types/              # canonical IDs, records, enums
│   ├── qn-crypto/             # keys, signatures, certificates
│   ├── qn-identity/           # identity lifecycle, keystores
│   ├── qn-membership/         # enrollment, grants, revocation
│   ├── qn-records/            # signed records and validation
│   ├── qn-peerstore/          # peer and endpoint persistence
│   ├── qn-discovery/          # bootstrap, LAN, DHT, gossip
│   ├── qn-netcheck/           # NAT, STUN, reachability testing
│   ├── qn-path/               # candidate paths and scoring
│   ├── qn-transport/          # transport-neutral interfaces
│   ├── qn-transport-quic/     # QUIC implementation
│   ├── qn-relay-proto/        # relay wire protocol
│   ├── qn-relay/              # relay server and client
│   ├── qn-protocol/           # protocol negotiation and registry
│   ├── qn-policy/             # capability and traffic policy
│   ├── qn-scheduler/          # local traffic/path scheduler
│   ├── qn-observability/      # metrics, tracing, diagnostics
│   ├── qn-control-client/     # optional authority/coordinator client
│   ├── qn-sdk/                # stable Rust SDK
│   ├── qn-ffi/                # C ABI for other languages
│   └── qn-testkit/            # simulation and fault injection
├── cmd/
│   ├── quicnetd/              # node daemon
│   ├── quicnet/               # CLI
│   ├── qn-relay/              # standalone relay service
│   ├── qn-bootstrap/          # bootstrap/directory service
│   ├── qn-authority/          # membership authority
│   └── qn-lab/                # network diagnostics and experiments
├── sdk/
│   ├── go/
│   ├── python/
│   ├── typescript/
│   └── c/
├── proto/                     # canonical schemas and protocol docs
├── deploy/
│   ├── systemd/
│   ├── docker/
│   ├── kubernetes/
│   ├── terraform/
│   └── nix/
├── docs/
│   ├── architecture/
│   ├── protocol/
│   ├── security/
│   ├── operations/
│   └── rfcs/
└── tests/
    ├── interop/
    ├── simulation/
    ├── chaos/
    ├── performance/
    └── security/
```

---

## 7. Identity and Cryptography

### 7.1 Key choices

Initial recommendation:

- Ed25519 for durable node identity signatures;
- X25519 or TLS 1.3-compatible ephemeral key exchange for sessions;
- BLAKE3 for internal content and record hashing where interoperability does not require SHA-256;
- HKDF for domain-separated key derivation;
- ChaCha20-Poly1305 and AES-GCM through TLS 1.3 depending on CPU capabilities;
- OS CSPRNG only.

Avoid inventing cryptographic primitives.

### 7.2 PeerId

```text
PeerId = multicodec || multihash(canonical_identity_public_key)
```

Properties:

- self-certifying;
- compact binary encoding;
- canonical text representation;
- algorithm agility;
- stable across endpoint and session-key changes.

### 7.3 Local keystore

The daemon must support:

- TPM 2.0;
- Apple Secure Enclave where available;
- Windows CNG/TPM;
- PKCS#11/HSM;
- encrypted file keystore fallback;
- ephemeral workload identities;
- recovery and replacement workflows.

Private keys must never be logged, exported by default, or stored unencrypted.

### 7.4 Session credentials

A node identity signs a short-lived session certificate containing:

```text
SessionCredential {
  network_id
  peer_id
  session_public_key
  issued_at
  expires_at
  protocol_versions
  key_epoch
  nonce
  identity_signature
}
```

Session credentials should rotate automatically and be accepted with bounded overlap.

### 7.5 Identity rotation

Support two distinct operations:

1. Session-key rotation: routine, transparent, frequent.
2. Durable identity rotation: explicit, auditable, and linked through a signed transition record.

### 7.6 Workload identities

Applications should not share the daemon's root node key. The daemon issues local workload credentials bound to:

- process identity;
- executable hash or package identity where available;
- protocol namespace;
- allowed peers;
- expiration;
- local user or container identity.

---

## 8. Membership and Trust Model

### 8.1 Closed PersonalCloud mode

Production default:

- one or more offline organization roots;
- online delegated enrollment authorities;
- short-lived single-use enrollment tokens;
- signed node membership certificates;
- capability-based authorization;
- auditable revocation.

### 8.2 Federated mode

Multiple organizations may cross-sign or establish trust bundles. Federation must be explicit and scoped by network, protocol, and capability.

### 8.3 Permissionless mode

Permissionless applications may allow any cryptographic identity to connect to public protocols. This must not imply access to private networks or privileged services.

### 8.4 Capability grants

A capability grant should be a signed object:

```text
CapabilityGrant {
  network_id
  subject_peer_id
  issuer_peer_id
  capabilities[]
  protocol_scopes[]
  resource_limits
  constraints
  not_before
  expires_at
  sequence
  signature
}
```

Examples:

- may relay opaque packets up to 2 Gbps;
- may advertise storage provider records;
- may accept `/quicnet/inference/1` jobs;
- may participate in consensus group X;
- may issue sub-grants for region Y;
- may not receive plaintext model weights.

### 8.5 Revocation

Use layered revocation:

- short credential lifetimes;
- signed revocation records;
- authority-pushed urgent revocations;
- gossip dissemination;
- denylist caching;
- epoch invalidation for catastrophic compromise.

No design should depend on a permanently online global revocation service for every connection.

---

## 9. Signed Record Layer

The signed record layer is the blockchain-like substrate of Quipnet, without imposing blockchain consensus on routine state.

### 9.1 Canonical record envelope

```text
SignedRecord {
  network_id
  namespace
  record_type
  schema_version
  author_peer_id
  sequence
  issued_at
  expires_at
  previous_hash?
  payload_hash
  payload
  signature
}
```

### 9.2 Initial record types

- `PeerRecord` — identity metadata and supported versions;
- `EndpointRecord` — current endpoint candidates;
- `ServiceRecord` — offered protocols and local service IDs;
- `CapabilityRecord` — signed grants or role declarations;
- `ProviderRecord` — peer can provide a content ID or namespace;
- `RelayRecord` — relay endpoints, limits, and region;
- `ObservationRecord` — measured peer/path properties;
- `RevocationRecord` — revoked identity, key, grant, or record;
- `KeyTransitionRecord` — durable key replacement;
- `MembershipRecord` — network membership;
- `PolicyRecord` — scoped policy state;
- `ReceiptRecord` — generic application-verifiable operation receipt.

### 9.3 Consistency rules

Records must define conflict semantics:

- monotonic sequence numbers per author and namespace;
- expiry for soft state;
- highest valid sequence wins for replaceable state;
- append-only chains where auditability matters;
- explicit merge logic for CRDT-like state;
- application consensus for globally ordered state.

### 9.4 Privacy

Do not publish all records globally.

Support distribution scopes:

- local only;
- direct peers;
- authorized network;
- role-scoped group;
- region;
- public DHT;
- application-defined topic.

Capability and provider records should disclose the minimum necessary metadata.

---

## 10. Peer Discovery

Quipnet must combine discovery methods rather than depend on one global mechanism.

### 10.1 Bootstrap discovery

Each network distributes a signed bootstrap set containing several independent nodes across providers and regions.

Bootstrap nodes return signed or verifiable peer hints but do not become trusted authorities merely because they are bootstrap infrastructure.

### 10.2 LAN discovery

Use authenticated mDNS or a custom local discovery exchange to identify nearby Quipnet peers. Never trust LAN discovery without cryptographic verification.

### 10.3 Authority-assisted directory

Closed networks may use a low-latency directory service that returns authorized peer records and relay maps. The directory is an accelerator, not a data-plane dependency.

### 10.4 DHT

Use a Kademlia-derived DHT for decentralized peer and content routing where appropriate.

Requirements:

- network-specific namespaces;
- signed values only;
- strict size limits;
- bounded TTLs;
- provider-record expiry;
- peer diversity requirements;
- Sybil-resistance hooks;
- rate limits;
- query privacy controls;
- no unrestricted arbitrary blob storage.

### 10.5 Gossip

Use a scored gossip mesh for rapidly changing network events:

- revocations;
- relay health;
- membership updates;
- application topics;
- provider announcements;
- consensus messages above the base network.

Gossip is not peer discovery by itself. It operates over an already connected mesh.

### 10.6 Peer store

Persist:

- identity keys;
- validated records;
- endpoint history;
- last successful paths;
- protocol support;
- trust and behavior score;
- backoff state;
- bans and revocations;
- observed network coordinates.

Entries must age out and never override fresher cryptographically valid state.

---

## 11. Endpoint Discovery and NAT Traversal

### 11.1 Candidate types

Each node should gather:

- local IPv4 addresses;
- local IPv6 addresses;
- reflexive UDP endpoints via STUN-like observers;
- port-mapped endpoints through PCP, NAT-PMP, or UPnP where policy permits;
- cloud public endpoints;
- relay endpoints;
- peer-reflexive endpoints learned during communication;
- same-host and shared-memory candidates;
- interface-specific candidates for multipath.

### 11.2 Netcheck service

`qn-netcheck` should continuously characterize:

- UDP availability;
- IPv4/IPv6 reachability;
- NAT mapping behavior;
- port preservation;
- endpoint-dependent filtering;
- hairpinning;
- captive portals;
- MTU and fragmentation behavior;
- nearest relay latency;
- interface changes;
- public IP changes.

### 11.3 Hole punching

The control/discovery layer coordinates simultaneous UDP sends between peers. The path engine must support retries, alternate candidate pairs, randomized pacing, and network-change-triggered reprobes.

### 11.4 Port mapping

Port mapping is opportunistic, policy-controlled, and never required. Cloud and enterprise nodes with public IPv6 or controlled public UDP ports should prefer explicit direct reachability.

### 11.5 Path upgrade

A connection may begin over a relay and later migrate to a direct path without restarting the application session.

### 11.6 Hostile networks

Fallbacks:

1. direct UDP;
2. UDP/443 QUIC;
3. peer relay;
4. managed high-performance relay;
5. HTTPS-compatible or TCP/TLS bootstrap relay for control traffic.

Bulk inference or storage traffic should not silently use a low-capacity fallback relay unless application policy permits it.

---

## 12. Transport Layer

### 12.1 Initial transport

Use standards-compliant QUIC v1 over UDP with TLS 1.3.

Why:

- encrypted handshake;
- connection migration;
- multiplexed streams;
- independent stream loss recovery;
- user-space evolution;
- congestion control;
- unreliable datagrams through RFC 9221;
- deployability over UDP/443;
- strong existing implementations.

### 12.2 Implementation strategy

Use a mature Rust QUIC implementation behind an internal adapter. Do not allow the public Quipnet SDK to expose implementation-specific types.

Create a strict interface boundary:

```rust
pub trait SecureTransport {
    type Connection;
    type Listener;

    async fn connect(&self, target: DialTarget) -> Result<Self::Connection>;
    async fn listen(&self, bind: BindSpec) -> Result<Self::Listener>;
}
```

This permits future substitution or multiple engines.

### 12.3 Connection identity binding

The QUIC TLS identity must be cryptographically bound to:

- `PeerId`;
- network membership;
- current session credential;
- negotiated network and protocol versions.

Do not rely on public Web PKI for peer identity.

### 12.4 Delivery primitives

Expose:

```rust
open_ordered_stream(peer, protocol, class)
open_message_channel(peer, protocol, class)
send_datagram(peer, protocol, class, payload)
send_deadline_message(peer, protocol, deadline, payload)
open_resumable_transfer(peer, protocol, object_id)
```

Semantics:

- ordered stream: reliable byte stream;
- message channel: reliable framed messages with independent processing;
- datagram: unreliable, congestion-controlled delivery;
- deadline message: retransmit only while useful;
- resumable transfer: chunked integrity-checked bulk movement.

### 12.5 Framing

Use a compact canonical binary framing format with:

- varint lengths;
- protocol ID;
- message type;
- schema version;
- flags;
- optional deadline;
- request/response correlation ID;
- optional compression marker;
- bounded metadata.

Never deserialize unbounded attacker-controlled allocations.

### 12.6 Protocol negotiation

Application protocols use versioned identifiers:

```text
/quicnet/control/1
/quicnet/identify/1
/quicnet/records/1
/quicnet/relay/1
/quicnet/blocks/1
/quicnet/inference/1
/quicnet/kv-transfer/1
/quicnet/consensus/1
```

Negotiation should support:

- exact versions;
- compatible ranges;
- required features;
- optional extensions;
- rejection reasons;
- per-protocol authorization.

### 12.7 Connection pooling

Maintain one or a small bounded number of secure logical connections per peer and network. Applications should multiplex protocols rather than create uncontrolled socket fan-out.

Allow dedicated connections for isolation when required by:

- congestion-control independence;
- extremely large bulk transfers;
- security policy;
- different physical paths;
- application-level performance testing.

---

## 13. Traffic Classes and QoS

Initial traffic classes:

1. `NetworkControl`
2. `ConsensusCritical`
3. `InteractiveRpc`
4. `InferenceCritical`
5. `TokenStream`
6. `KvTransfer`
7. `ModelBulk`
8. `StorageInteractive`
9. `StorageReplication`
10. `Background`

Each class defines defaults for:

- queue priority;
- latency target;
- loss/retransmission policy;
- congestion-control share;
- bandwidth cap;
- relay permission;
- multipath mode;
- redundancy;
- idle timeout;
- backpressure behavior.

Example:

```text
InferenceCritical:
  priority: high
  delivery: deadline-aware
  relay: only performance relays
  multipath: latency race or failover
  queue policy: reject before stale

ModelBulk:
  priority: medium-low
  delivery: reliable resumable chunks
  relay: allowed if capacity is reserved
  multipath: stripe across high-throughput paths
  queue policy: backpressure
```

Enforce per-peer and per-protocol quotas to prevent starvation.

---

## 14. Path Engine

The path engine is a first-class Quipnet subsystem, not a hidden transport detail.

### 14.1 Candidate model

```text
PathCandidate {
  local_interface
  local_endpoint
  remote_endpoint
  transport
  relay_id?
  address_family
  discovered_by
  validation_state
}
```

### 14.2 Measurements

Track exponentially weighted and windowed values for:

- handshake latency;
- smoothed RTT;
- minimum RTT;
- jitter;
- packet loss;
- reordering;
- effective throughput;
- queueing delay;
- congestion events;
- MTU;
- path uptime;
- cost;
- relay load;
- recent failure reason.

### 14.3 Path scoring

Use traffic-class-specific scoring rather than one universal score.

```text
score(path, class) =
  w_rtt * normalized_rtt
+ w_jitter * normalized_jitter
+ w_loss * loss_penalty
+ w_bw * inverse_available_bandwidth
+ w_cost * monetary_cost
+ w_relay * relay_penalty
+ w_stability * instability_penalty
+ w_policy * policy_penalty
```

Weights vary by traffic class.

### 14.4 Hysteresis

Prevent oscillation with:

- minimum dwell time;
- improvement threshold;
- path confidence;
- failure fast-path;
- cooldown after failed migrations.

### 14.5 Path policies

Support:

- lowest latency;
- highest throughput;
- lowest cost;
- avoid relay;
- require region;
- redundant send;
- stripe bulk transfer;
- private-only path;
- operator pinning.

### 14.6 Multipath

Design the Quipnet API for multipath immediately, even if initial production uses active/standby and application-level striping before native multipath QUIC is mature.

Modes:

- failover;
- latency racing;
- redundant critical control;
- weighted striping;
- bulk chunk distribution;
- interface bonding.

Native multipath QUIC should be integrated behind feature negotiation when standardized and production-ready.

---

## 15. Relay Architecture

### 15.1 Relay goals

- universal reachability;
- fast bootstrap;
- low-latency fallback;
- opaque forwarding;
- predictable capacity;
- simple regional deployment;
- no application plaintext access.

### 15.2 Relay tiers

#### Bootstrap relay

- broad firewall compatibility;
- control traffic priority;
- modest bandwidth;
- global availability.

#### Performance relay

- UDP/QUIC-native;
- high bandwidth;
- regional placement;
- explicit capacity and admission control;
- suitable for temporary inference and storage traffic.

#### Peer relay

- an authorized Quipnet peer forwards encrypted traffic;
- useful for home labs, private regions, and provider-local routing;
- capability-scoped and metered.

### 15.3 Relay protocol

A relay should route opaque frames using authenticated peer/session identifiers. It must not terminate application encryption.

The relay must enforce:

- source authentication;
- destination authorization;
- bandwidth limits;
- connection limits;
- anti-amplification rules;
- idle timeouts;
- abuse controls;
- observability without payload inspection.

### 15.4 Relay placement

Deploy across independent providers and peering locations. Initial regions should reflect actual user and compute geography, not generic cloud coverage.

Suggested initial footprint:

- New York/New Jersey;
- Ashburn;
- Chicago;
- Dallas;
- Los Angeles;
- London;
- Frankfurt;
- Amsterdam;
- Singapore.

### 15.5 Relay map

Relay maps are signed, versioned, and cached. Nodes probe a subset continuously and select by measured performance.

### 15.6 Relay economics

Track:

- bytes forwarded;
- peak bandwidth;
- connection duration;
- source/destination region;
- traffic class;
- relay saturation;
- cost per delivered GiB.

Higher-level billing may use these metrics, but the base relay protocol remains payment-agnostic.

---

## 16. Addressing and Naming

### 16.1 Peer addressing

Applications address peers by:

```text
quicnet://<network-id>/<peer-id>/<protocol-or-service>
```

### 16.2 Virtual IP compatibility

A TUN-based virtual IP mode may be provided for legacy applications, but it is not the canonical identity model.

Virtual addresses should be deterministic or authority-assigned within a network and map to `PeerId`.

### 16.3 Service naming

```text
service://<network>/<service-name>
```

Service resolution returns eligible peer instances based on:

- authorization;
- protocol support;
- locality;
- health;
- load;
- application-defined constraints.

### 16.4 DNS bridge

Provide optional DNS integration for compatibility:

```text
worker-17.personalcloud.qn
model-cache-fra.personalcloud.qn
```

DNS answers are convenience aliases and must resolve to cryptographically authenticated peers.

---

## 17. Policy and Authorization

### 17.1 Policy evaluation points

Evaluate policy at:

- enrollment;
- record acceptance;
- peer connection;
- protocol negotiation;
- stream creation;
- relay use;
- service advertisement;
- resource access;
- route exposure;
- local workload attachment.

### 17.2 Policy language

Start with a declarative policy model, compiled into deterministic local rules.

Example:

```text
allow protocol /quicnet/inference/1
  from role scheduler
  to role inference-worker
  when network == personalcloud-prod
  and source.region in trusted_regions
  and grant.not_expired
```

### 17.3 Capability-first enforcement

Prefer explicit signed capabilities over implicit role-name trust. Roles are ergonomic groupings; grants are authoritative.

### 17.4 Local override

A node operator may impose stricter local policy than network policy. Network policy must never force a node to accept workloads it locally rejects.

---

## 18. Stable Public SDK

### 18.1 Core API

```rust
pub trait Fabric {
    async fn connect(&self, peer: PeerId) -> Result<PeerConnection>;
    async fn listen(&self, protocol: ProtocolId) -> Result<Listener>;

    async fn open_stream(
        &self,
        peer: PeerId,
        protocol: ProtocolId,
        class: TrafficClass,
    ) -> Result<Stream>;

    async fn send_message(
        &self,
        peer: PeerId,
        protocol: ProtocolId,
        class: TrafficClass,
        message: Bytes,
    ) -> Result<MessageReceipt>;

    async fn send_datagram(
        &self,
        peer: PeerId,
        protocol: ProtocolId,
        class: TrafficClass,
        payload: Bytes,
    ) -> Result<()>;

    async fn publish_record(&self, record: SignedRecord) -> Result<()>;
    async fn resolve_peer(&self, peer: PeerId) -> Result<PeerView>;
    async fn find_providers(&self, cid: ContentId) -> Result<Vec<Provider>>;
    fn watch_peers(&self) -> PeerEventStream;
    fn path_stats(&self, peer: PeerId) -> Vec<PathStats>;
}
```

### 18.2 Daemon API

Applications normally communicate with `quicnetd` through:

- Unix domain socket on Linux/macOS;
- named pipe on Windows;
- shared-memory fast path for local bulk transfer;
- optional gRPC/Cap'n Proto-style local control interface;
- language SDKs.

### 18.3 Embedded mode

Provide an embedded Rust library for appliances and tightly integrated products, but keep wire behavior identical to daemon mode.

### 18.4 Zero-copy and accelerator integration

Plan extension points for:

- io_uring;
- registered buffers;
- pinned memory;
- shared-memory rings;
- GPU staging buffers;
- GPUDirect or vendor-specific paths where available;
- RDMA transport adapters within trusted environments.

Do not couple the first transport implementation to a specific accelerator runtime.

---

## 19. Distributed Inference Support Requirements

Quipnet does not schedule inference, but it must expose the information and primitives needed by an inference runtime.

### 19.1 Required network capabilities

- direct-path preference;
- accurate RTT and throughput measurements;
- stable peer identities;
- service and hardware advertisements;
- deadline-aware messages;
- bulk resumable transfers;
- path-change notifications;
- traffic isolation;
- flow backpressure;
- node failure events;
- region and network-coordinate queries.

### 19.2 Capability advertisement

```text
InferenceCapability {
  accelerators[]
  runtime_versions[]
  memory_total
  memory_available
  supported_dtypes[]
  supported_quantizations[]
  model_cache[]
  kv_formats[]
  max_concurrent_jobs
  observed_compute_score
}
```

These advertisements are signed but should be independently benchmarked or observed before trusted scheduling.

### 19.3 Supported distributed patterns

The network should efficiently support:

- request-level load distribution;
- model and adapter distribution;
- disaggregated prefill/decode;
- KV transfer;
- pipeline stages;
- coarse expert routing;
- speculative workers;
- result aggregation.

Fine-grained tensor parallelism over distant WAN paths is an application-level anti-pattern and should not define the base transport.

---

## 20. Distributed Storage Support Requirements

### 20.1 Common content service

Quipnet may provide generic support for:

- `ContentId`;
- provider lookup;
- immutable block transfer;
- integrity verification;
- range/chunk requests;
- parallel provider downloads;
- resumable sessions.

### 20.2 Storage application responsibilities

A storage layer above Quipnet owns:

- chunking algorithm;
- Merkle DAG format;
- file and directory metadata;
- replication policy;
- erasure coding;
- repair;
- garbage collection;
- access encryption;
- storage proofs;
- quotas and accounting.

### 20.3 Model weights

Weights should be distributed as immutable content-addressed shards, fetched to local NVMe or RAM before active inference. Quipnet must not assume remote WAN reads can substitute for VRAM or local model memory.

---

## 21. Optional Consensus and Blockchain Layer

A blockchain or consensus system should run as an application protocol:

```text
/quicnet/consensus/<protocol>/<version>
```

Quipnet contributes:

- authenticated peers;
- low-latency messaging;
- gossip;
- direct paths;
- topology awareness;
- peer scoring;
- traffic prioritization.

The consensus application owns:

- validator set;
- leader election;
- block proposal;
- voting;
- finality;
- state machine execution;
- fork choice;
- transaction semantics;
- economic incentives;
- slashing;
- storage or compute proofs.

Consensus messages receive a protected traffic class but do not gain implicit authority over the base network.

---

## 22. Security Threat Model

### 22.1 Adversaries

Assume:

- malicious public internet actors;
- compromised peers;
- stolen enrollment tokens;
- malicious relays;
- Sybil identities in public modes;
- packet injection, replay, delay, loss, and reordering;
- traffic analysis;
- DHT poisoning;
- gossip spam;
- resource exhaustion;
- downgrade attempts;
- compromised bootstrap servers;
- malicious application protocols;
- local unprivileged users attacking the daemon;
- supply-chain compromise.

### 22.2 Required properties

- mutual peer authentication;
- transport confidentiality and integrity;
- forward-secure sessions;
- replay resistance;
- authorization before protocol access;
- signed records;
- bounded resource use;
- relay blindness to plaintext;
- protocol downgrade protection;
- revocation;
- auditability;
- compartmentalized local workload access.

### 22.3 DoS controls

- stateless retry/address validation where appropriate;
- handshake rate limits;
- per-source token buckets;
- proof-of-work or admission puzzles as optional public-network defense;
- bounded queues;
- memory and stream caps;
- record size and rate limits;
- gossip peer scoring;
- DHT query budgets;
- relay quotas;
- circuit breakers;
- overload shedding by traffic class.

### 22.4 Metadata privacy

Encrypted transport does not hide peer relationships, timing, sizes, or endpoint addresses from all observers. Quipnet is not an anonymity network.

Provide optional privacy features:

- relay-forced connections;
- record-scope minimization;
- private discovery;
- padded control messages;
- endpoint redaction;
- rotating service identifiers;
- application-layer onion routing as a separate protocol if needed.

### 22.5 Supply chain

- reproducible builds;
- signed releases;
- dependency pinning;
- SBOMs;
- vulnerability scanning;
- minimal unsafe Rust;
- fuzzing of all parsers;
- independent security review;
- staged release channels.

---

## 23. Observability and Diagnostics

### 23.1 Metrics

Per node:

- active peers;
- direct versus relayed connections;
- connection setup latency;
- NAT type and UDP reachability;
- path RTT, loss, jitter, and throughput;
- bytes by protocol and traffic class;
- stream and datagram counts;
- retransmissions;
- congestion events;
- queue depth and drops;
- relay utilization;
- record-validation failures;
- policy denials;
- CPU and memory;
- event-loop lag;
- key and credential expiry health.

### 23.2 Tracing

Use structured distributed traces for:

- enrollment;
- discovery;
- hole punching;
- path selection;
- connection establishment;
- protocol negotiation;
- migration;
- relay fallback;
- record propagation.

Trace IDs may cross peers only when allowed by privacy policy.

### 23.3 Logs

Structured logs with:

- no private keys;
- no plaintext application payloads;
- redacted tokens;
- stable event IDs;
- peer IDs optionally pseudonymized in exported telemetry;
- local full-fidelity debug mode.

### 23.4 Operator commands

```bash
quicnet status
quicnet peers
quicnet peer inspect <peer>
quicnet netcheck
quicnet path probe <peer>
quicnet path watch <peer>
quicnet relay status
quicnet records inspect <namespace>
quicnet policy explain <peer> <protocol>
quicnet debug bundle
```

### 23.5 Connection explanation

The daemon must explain why a path is being used:

```text
Peer: qn1...
Selected path: direct IPv6
Reason: 13 ms RTT, 0.1% loss, 780 Mbps measured
Alternatives:
  direct IPv4 NAT: 16 ms, 0.4% loss
  fra-relay-2: 24 ms, 1.2 Gbps
Policy: prefer-low-latency, relay allowed
```

---

## 24. Persistence and State Recovery

Persist:

- encrypted node identity;
- memberships and grants;
- peer store;
- validated records;
- endpoint history;
- relay map;
- policy cache;
- schema version;
- monotonic sequence counters;
- backoff state.

Use transactional storage such as SQLite initially, with strict migrations and corruption recovery.

A node should recover from loss of non-key state by rediscovery. The durable identity key and current membership are the critical assets.

Support stateless ephemeral nodes for jobs and containers.

---

## 25. Platform Support

### 25.1 Linux

Primary production platform.

Support:

- systemd;
- containers;
- Kubernetes;
- TUN mode;
- userspace SDK mode;
- nftables integration;
- io_uring optimization;
- network namespaces;
- TPM;
- eBPF observability where useful.

### 25.2 macOS

Support daemon and userspace SDK first, then system-extension/TUN integration as required.

### 25.3 Windows

Support service mode, named-pipe API, Windows filtering/TUN integration, and hardware-backed keys.

### 25.4 Mobile

Mobile support follows core stability and must account for battery, background suspension, roaming, and OS VPN frameworks.

### 25.5 Embedded

Provide a reduced-footprint profile with bounded memory, no DHT server role, and configurable protocol set.

---

## 26. Performance Engineering

### 26.1 Targets

Initial production targets on modern Linux servers:

- direct connection establishment after peer hint: median under 150 ms on healthy paths;
- relay-first reachability under 500 ms where direct path is not ready;
- migration to a validated better path without application reconnect;
- line-rate or near-line-rate encrypted throughput on 1/10 GbE-class servers where CPU and NIC permit;
- low single-digit percentage overhead relative to the chosen QUIC library for large transfers;
- bounded per-peer idle memory;
- 10,000+ mostly idle peer relationships per capable server node;
- predictable degradation under overload.

Targets must be benchmarked by hardware class and traffic pattern rather than treated as universal promises.

### 26.2 Optimization areas

- syscall reduction;
- batching and GSO/GRO;
- io_uring;
- zero-copy receive/send where stable;
- lock minimization;
- shard peer/path maps;
- compact record encoding;
- pooled buffers;
- vectorized crypto;
- NUMA awareness;
- RSS and multi-queue NIC affinity;
- relay packet batching;
- connection and stream scheduling;
- backpressure before allocation.

### 26.3 Performance test matrix

Test:

- LAN 1/10/25/100 GbE;
- home broadband asymmetry;
- cloud cross-zone;
- cloud cross-region;
- residential CGNAT;
- cellular;
- IPv6-only;
- high loss;
- high jitter;
- reordered packets;
- MTU black holes;
- relay saturation;
- thousands of peers;
- millions of signed records;
- mixed traffic classes.

---

## 27. Testing Strategy

### 27.1 Unit tests

Every parser, signature validator, policy evaluator, state transition, and path scorer.

### 27.2 Property tests

- record canonicalization;
- sequence conflict handling;
- idempotent state merge;
- framing and varints;
- policy invariants;
- path-selection stability.

### 27.3 Fuzzing

Continuously fuzz:

- transport frames;
- record decoders;
- relay protocol;
- protocol negotiation;
- DHT messages;
- gossip messages;
- local daemon API;
- state migration.

### 27.4 Simulation

Build a deterministic network simulator supporting:

- NAT types;
- delay;
- jitter;
- bandwidth;
- loss;
- reordering;
- partitions;
- malicious peers;
- clock skew;
- relay failure;
- topology changes.

### 27.5 Integration lab

Maintain real routers, cloud networks, CGNAT-like environments, IPv6, multiple ISPs, cellular links, and relay POPs.

### 27.6 Chaos tests

- kill bootstrap nodes;
- revoke authorities;
- rotate keys mid-transfer;
- drop direct paths;
- overload relays;
- partition DHT regions;
- corrupt local state;
- downgrade peers;
- inject stale records;
- change IPs and interfaces repeatedly;
- suspend and resume machines.

### 27.7 Interoperability tests

Wire protocols are specified independently from implementation and tested against multiple versions and, eventually, multiple language implementations.

---

## 28. Production Deployment Topology

Initial production control infrastructure:

- offline root authority;
- two or more regional online enrollment authorities;
- multiple independent bootstrap nodes;
- signed relay-map publisher;
- revocation publisher;
- observer fleet;
- regional performance relays;
- telemetry ingestion with privacy controls;
- release and update infrastructure.

No single component should be both unavoidable for the data path and globally singular.

### 28.1 VPS and bare-metal deployment

Every public node should prefer:

- public IPv6;
- public IPv4 where affordable;
- explicit UDP ingress;
- provider-local firewall restrictions;
- stable clock synchronization;
- local NVMe for caches;
- measured egress pricing.

### 28.2 Edge placement

Higher-level schedulers should choose edge nodes by measured performance and capability, not region labels alone.

---

## 29. Upgrade and Compatibility Plan

### 29.1 Version domains

Version separately:

- transport wire protocol;
- record schemas;
- relay protocol;
- discovery protocol;
- daemon API;
- SDK;
- local database schema;
- policy language.

### 29.2 Rolling upgrades

Nodes advertise supported versions and negotiate the highest mutually compatible version.

### 29.3 Feature flags

Experimental features require signed network policy and local operator opt-in.

### 29.4 Rollback

Every release must define:

- state compatibility;
- rollback window;
- migration reversibility;
- protocol fallback;
- kill-switch controls.

### 29.5 Network epochs

Use network epochs only for major cryptographic or authority transitions, not routine software releases.

---

## 30. Implementation Program

This is a production program, but it should still be executed through vertically complete milestones. Each milestone must leave behind production-quality code, tests, documentation, and operational tooling; none is a disposable proof of concept.

### Milestone 1 — Architecture, specifications, and skeleton

Deliver:

- accepted architecture RFCs;
- threat model;
- canonical IDs and record schemas;
- repository and CI;
- release signing;
- transport abstraction;
- identity keystore abstraction;
- simulator skeleton;
- protocol compatibility policy.

Exit criteria:

- no unresolved ambiguity in trust boundaries;
- wire formats have canonical test vectors;
- security review of identity and enrollment design.

### Milestone 2 — Identity, membership, and direct QUIC

Deliver:

- durable node identity;
- session credentials;
- authority and enrollment flow;
- direct known-endpoint QUIC connections;
- protocol negotiation;
- local daemon API;
- policy enforcement;
- structured metrics and logs.

Exit criteria:

- mutual cryptographic identity binding verified;
- rolling session-key rotation;
- revoked peers denied;
- sustained direct transfer benchmarks.

### Milestone 3 — Discovery, netcheck, and NAT traversal

Deliver:

- bootstrap discovery;
- peer store;
- signed endpoint records;
- STUN-like observers;
- NAT characterization;
- coordinated UDP hole punching;
- LAN discovery;
- network-change handling.

Exit criteria:

- tested across documented NAT matrix;
- successful direct upgrades measured;
- failure reasons observable.

### Milestone 4 — Relay network and seamless path migration

Deliver:

- relay protocol;
- regional relay service;
- relay maps;
- relay-first connection bootstrap;
- direct-path upgrade;
- connection migration;
- peer relay role;
- relay quotas and abuse controls.

Exit criteria:

- applications survive relay/direct transitions;
- opaque relay property verified;
- regional failover tested.

### Milestone 5 — Path intelligence and traffic classes

Deliver:

- continuous path probes;
- traffic-class-specific path scoring;
- hysteresis;
- QoS queues;
- deadline-aware messages;
- bulk resumable transfer;
- operator path diagnostics.

Exit criteria:

- mixed inference/control/bulk workloads remain stable;
- no starvation under load;
- deterministic path-decision explanations.

### Milestone 6 — Decentralized records, DHT, and gossip

Deliver:

- signed record distribution;
- scoped DHT;
- provider records;
- scored gossip mesh;
- revocation propagation;
- conflict and expiry handling;
- privacy scopes.

Exit criteria:

- bootstrap directory may be unavailable without breaking established decentralized operation;
- stale and malicious records rejected;
- DHT and gossip abuse tests pass.

### Milestone 7 — Multipath abstraction and performance relays

Deliver:

- multi-interface candidate management;
- failover and latency racing;
- application-level bulk striping;
- redundant critical messages;
- high-throughput regional relays;
- native multipath QUIC adapter when production-ready.

Exit criteria:

- demonstrated failover without application interruption;
- measurable tail-latency or throughput benefits;
- no reordering leakage beyond declared delivery semantics.

### Milestone 8 — Platform hardening and SDKs

Deliver:

- Linux production packages;
- macOS and Windows clients;
- container and Kubernetes support;
- Rust, Go, Python, TypeScript, and C SDKs;
- hardware keystore support;
- stable daemon API;
- reproducible builds and SBOMs.

Exit criteria:

- SDK compatibility suite;
- signed multi-platform releases;
- operator deployment guides.

### Milestone 9 — Production scale and security hardening

Deliver:

- large-scale soak tests;
- independent security audit;
- fuzzing coverage goals;
- DDoS protections;
- fleet observability;
- upgrade/rollback exercises;
- incident-response playbooks;
- SLO dashboards.

Exit criteria:

- audit findings resolved or formally accepted;
- chaos and overload tests pass;
- defined production SLOs met.

### Milestone 10 — First-class application integration

Deliver integration profiles for:

- PersonalCloud service routing;
- distributed model and artifact distribution;
- inference scheduler and KV transport;
- content-addressed storage;
- optional consensus network.

Exit criteria:

- each application uses only stable Quipnet APIs;
- application failure cannot compromise network authority;
- network remains useful without any single application.

---

## 31. Production SLOs

Define separate SLOs for network services and direct peer performance.

Suggested service SLOs:

- membership issuance availability: 99.95%;
- bootstrap discovery availability across fleet: 99.99%;
- at least one relay reachable from supported public networks: 99.99%;
- revocation propagation to connected authorized nodes: target under 60 seconds for urgent revocations;
- no unplanned identity loss;
- successful rolling upgrade without network-wide disconnect.

Peer-path performance SLOs must be conditioned on underlying connectivity and should report distributions rather than absolute guarantees.

---

## 32. Operational Runbooks

Required runbooks:

- bootstrap outage;
- relay-region outage;
- enrollment authority compromise;
- leaked enrollment token;
- node identity compromise;
- root rotation;
- bad release rollback;
- DHT poisoning attempt;
- gossip spam attack;
- relay bandwidth abuse;
- widespread NAT regression;
- telemetry outage;
- clock-skew incident;
- database corruption;
- network partition;
- emergency protocol disablement.

---

## 33. Build-versus-Borrow Decisions

### Borrow or wrap

- a mature QUIC implementation;
- TLS 1.3 and standard cryptography;
- OS keystore and TPM interfaces;
- STUN message standards where useful;
- established serialization primitives;
- proven DHT and gossip concepts;
- OpenTelemetry-compatible instrumentation.

### Build as Quipnet core

- identity-to-session binding;
- membership and capability model;
- signed record schemas;
- endpoint and path engine;
- relay protocol and fleet;
- traffic-class scheduler;
- protocol registry;
- daemon API;
- operational tooling;
- topology observations;
- application-facing fabric abstraction.

### Study but do not tightly fork initially

- Tailscale `magicsock` and DERP architecture;
- libp2p identify, Kademlia, relay, and GossipSub designs;
- IPFS provider and block-exchange patterns.

A deep fork of another project's internal packages should be avoided unless measurement proves that clean composition or reimplementation cannot meet requirements.

---

## 34. Critical Risks

### Risk: attempting to make WAN behave like local accelerator interconnect

Mitigation: expose accurate topology and build applications around coarse-grained boundaries, batching, caching, and prefetching.

### Risk: overloading the base layer with blockchain semantics

Mitigation: signed eventual-consistency records in the base; consensus only in application protocols.

### Risk: implementing cryptography or QUIC from scratch

Mitigation: use audited libraries behind replaceable adapters.

### Risk: NAT traversal becomes a permanent engineering sink

Mitigation: combine direct IPv6, public UDP, STUN, hole punching, port mapping, peer relays, and managed relays; instrument every failure.

### Risk: relay costs dominate

Mitigation: direct-path upgrades, public endpoints for infrastructure nodes, peer relays, capacity-aware admission, and traffic-class relay policies.

### Risk: DHT and gossip create attack surfaces

Mitigation: network scopes, signed records, expiries, rate limits, peer scoring, diversity, and optional closed-network directory acceleration.

### Risk: internal APIs become inseparable from first transport implementation

Mitigation: stable transport-neutral interfaces and wire-level conformance tests.

### Risk: metadata leaks

Mitigation: scoped discovery, minimum advertisements, private provider records, relay-forced modes, and explicit privacy documentation.

---

## 35. Definition of Done

Quipnet is production-ready when:

1. A node can securely join from a home network, VPS, bare-metal server, or cloud environment using a short-lived credential.
2. Node identity remains stable across IP changes, restarts, and transport-key rotation.
3. Authorized peers discover each other without depending on a single global coordinator.
4. Direct connectivity is attempted and upgraded automatically; relay fallback is seamless.
5. Applications use streams, messages, datagrams, deadline delivery, and resumable transfers through a stable SDK.
6. Path choices are traffic-aware, measurable, explainable, and resilient to interface or network changes.
7. Signed peer, service, capability, provider, and revocation records propagate safely.
8. Policy is enforced locally before protocol or resource access.
9. Relay operators cannot decrypt application payloads.
10. The network survives bootstrap, relay, authority, and regional failures within documented limits.
11. Mixed-version rolling upgrades work.
12. Security audits, fuzzing, chaos testing, and scale testing meet release gates.
13. PersonalCloud, distributed storage, distributed inference, and an optional consensus application can all run above Quipnet without modifying its core semantics.

---

## 36. Immediate Engineering Actions

1. Create the Quipnet monorepo and RFC process.
2. Write `RFC-0001: Identity, Network, and Trust Domains`.
3. Write `RFC-0002: Signed Record Envelope and Canonical Encoding`.
4. Write `RFC-0003: Transport Abstraction and Delivery Semantics`.
5. Write `RFC-0004: Enrollment, Membership, Capabilities, and Revocation`.
6. Write `RFC-0005: Endpoint Discovery, NAT Traversal, and Path State Machine`.
7. Write `RFC-0006: Relay Protocol and Relay Trust Model`.
8. Select and benchmark the initial Rust QUIC implementation behind an adapter.
9. Build canonical key, `PeerId`, and record test vectors.
10. Implement the deterministic network simulator before relying on ad hoc real-world tests.
11. Stand up a three-region internal test network with at least two independent providers.
12. Build the CLI diagnostics concurrently with networking functionality.
13. Add fuzzing and protocol conformance to CI from the first wire parser.
14. Establish release signing, SBOM generation, and reproducible-build goals before public deployment.
15. Integrate the first real application only after the stable daemon API and protocol negotiation are functioning.

---

## 37. Reference Standards and Systems

The implementation should track, but not blindly copy, the following:

- IETF QUIC v1, RFC 9000;
- QUIC TLS, RFC 9001;
- QUIC loss detection and congestion control, RFC 9002;
- QUIC DATAGRAM, RFC 9221;
- current IETF multipath QUIC work;
- STUN and ICE concepts for endpoint discovery and traversal;
- Tailscale's published NAT traversal, `magicsock`, and relay architecture;
- libp2p peer identity, identify, protocol negotiation, Kademlia, relay, and GossipSub specifications;
- IPFS content addressing and provider-record concepts;
- mature capability-security and signed-credential systems.

Primary references:

- https://datatracker.ietf.org/doc/html/rfc9000
- https://datatracker.ietf.org/doc/html/rfc9001
- https://datatracker.ietf.org/doc/html/rfc9002
- https://datatracker.ietf.org/doc/html/rfc9221
- https://datatracker.ietf.org/group/quic/
- https://tailscale.com/blog/how-nat-traversal-works
- https://tailscale.com/blog/how-tailscale-works
- https://github.com/tailscale/tailscale
- https://libp2p.io/docs/protocols/
- https://github.com/libp2p/specs
- https://docs.ipfs.tech/concepts/content-addressing/

---

# Final Architecture Statement

Quipnet will be a global cryptographic peer fabric in which identity is derived from keys, membership is expressed through signed capabilities, discovery is distributed and scoped, endpoint selection is dynamic, secure sessions run primarily over direct QUIC paths, relays guarantee reachability, and applications receive explicit delivery and traffic semantics.

Its decentralized character comes from self-certifying peers, signed records, direct communication, distributed discovery, and the absence of a mandatory central data path—not from forcing every network event into a blockchain.

The result is one durable foundational network capable of supporting closed PersonalCloud deployments, deploy-anywhere edge infrastructure, distributed model and data placement, WAN-aware inference systems, decentralized storage, and optional consensus networks without binding those applications to one provider, one geography, or one centralized transport service.
