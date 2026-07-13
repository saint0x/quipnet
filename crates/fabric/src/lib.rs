use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use control::{AuthorityArtifactSnapshot, ControlClient};
use crypto::IdentityKeypair;
use membership::{CapabilityGrant, MembershipCertificate, RevocationRecord, RevocationTarget};
use rand::{rngs::OsRng, RngCore};
use relaywire::{RelayAnnouncement, RelayMap};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub use discovery::{BootstrapHint, BootstrapIngestReport, DiscoveryService};
pub use model::*;
pub use netcheck::{NatType, NetcheckReport, ProbeObservation, ProbeStatus};
pub use observability::*;
pub use peerstore::{
    PeerInspection, PeerReachability, PeerSnapshot, PeerSource, PeerStatus, PeerStore,
};
pub use policy::*;
pub use protocol::*;
pub use records::*;
pub use routing::{
    select_best_path, PathCandidate, PathDecision, PathExplanation, PathScoreBreakdown, PathSource,
};
pub use scheduler::*;
pub use transport::*;

pub const DAEMON_STATE_SCHEMA_VERSION: u64 = 1;
pub const BACKUP_BUNDLE_FORMAT_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DaemonRole {
    Bootstrap,
    Relay,
    Observer,
    Edge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonConfig {
    pub network: String,
    pub state_path: PathBuf,
    pub roles: Vec<DaemonRole>,
}

impl DaemonConfig {
    pub fn new(network: impl Into<String>, state_path: impl Into<PathBuf>) -> Self {
        Self {
            network: network.into(),
            state_path: state_path.into(),
            roles: vec![DaemonRole::Edge, DaemonRole::Observer],
        }
    }
}

#[derive(Debug, Error)]
pub enum DaemonStateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("peer {0} was not found in daemon state")]
    PeerNotFound(String),
    #[error("authority snapshot network does not match configured network")]
    NetworkMismatch,
    #[error("authority snapshot did not contain a membership certificate")]
    MissingMembership,
    #[error("control-plane merge failed: {0}")]
    Control(#[from] control::ControlError),
    #[error("no route is available for peer {0}")]
    NoRoute(PeerId),
    #[error("transport policy denied request: {0}")]
    PolicyDenied(String),
    #[error("transport execution failed: {0}")]
    Transport(#[from] transport::TransportError),
    #[error("session {0} was not found")]
    SessionNotFound(String),
    #[error("session state is invalid: {0}")]
    InvalidSession(String),
    #[error("durable state schema version is missing")]
    MissingSchemaVersion,
    #[error("durable state schema version {found} is unsupported; expected {expected}")]
    UnsupportedSchemaVersion { found: u64, expected: u64 },
    #[error("durable state contains unsupported field `{0}`")]
    UnsupportedDurableField(String),
    #[error("backup bundle is invalid or the passphrase is incorrect")]
    InvalidBackupBundle,
    #[error("backup bundle key derivation failed")]
    BackupKeyDerivation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableBackupAsset {
    pub concern: String,
    pub relative_path: String,
    pub sha256_hex: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableBackupManifest {
    pub format: String,
    pub format_version: u8,
    pub created_at_unix_secs: u64,
    pub hostname: String,
    pub environment: String,
    pub network: String,
    pub identity_path: String,
    pub state_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_snapshot: Option<String>,
    pub durable_state_present: bool,
    pub durable_state_valid: bool,
    pub assets: Vec<DurableBackupAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableBackupBundleData {
    pub manifest: DurableBackupManifest,
    pub identity_file_base64: String,
    pub state_file_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableBackupBundleEnvelope {
    pub version: u8,
    pub cipher: String,
    pub kdf: String,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableBackupExportRequest {
    pub output_path: PathBuf,
    pub passphrase: String,
    pub hostname: String,
    pub environment: String,
    pub identity_path: PathBuf,
    pub state_path: PathBuf,
    pub network: String,
    pub authority_origin: Option<String>,
    pub authority_subject: Option<String>,
    pub authority_snapshot: Option<String>,
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableBackupExportReport {
    pub bundle_path: PathBuf,
    pub created_at_unix_secs: u64,
    pub hostname: String,
    pub environment: String,
    pub network: String,
    pub identity_sha256_hex: String,
    pub state_sha256_hex: String,
    pub durable_state_present: bool,
    pub durable_state_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableBackupRestoreRequest {
    pub input_path: PathBuf,
    pub passphrase: String,
    pub identity_path: PathBuf,
    pub state_path: PathBuf,
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableBackupRestoreReport {
    pub input_path: PathBuf,
    pub restored_identity_path: PathBuf,
    pub restored_state_path: PathBuf,
    pub created_at_unix_secs: u64,
    pub hostname: String,
    pub environment: String,
    pub network: String,
    pub identity_sha256_hex: String,
    pub state_sha256_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapEndpoint {
    pub peer: Option<PeerId>,
    pub addresses: Vec<String>,
    pub protocols: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeniedPeer {
    pub peer: PeerId,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DaemonState {
    pub schema_version: u64,
    pub network: String,
    pub local_peer_id: PeerId,
    pub roles: Vec<DaemonRole>,
    pub membership: MembershipCertificate,
    pub capability_grants: Vec<CapabilityGrant>,
    pub revocations: Vec<RevocationRecord>,
    pub denied_peers: Vec<DeniedPeer>,
    pub bootstrap: Vec<BootstrapEndpoint>,
    #[serde(default)]
    pub relay_map: Option<RelayMap>,
    pub peers: Vec<PeerInspection>,
    pub netcheck: NetcheckReport,
    pub queue_policies: Vec<QueuePolicy>,
    #[serde(default, skip_serializing, skip_deserializing)]
    pub active_sessions: Vec<SessionSnapshot>,
    pub path_candidates: Vec<PathCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSyncReport {
    pub membership_changed: bool,
    pub grants_added: usize,
    pub grants_removed: usize,
    pub revocations_added: usize,
    pub bootstrap_hints_added: usize,
    pub bootstrap_hints_removed: usize,
    pub relay_announcements_added: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetcheckReprobeReport {
    pub reason: String,
    pub udp_reachable: bool,
    pub ipv6_reachable: bool,
    pub relay_required: bool,
    pub probe_observations: usize,
    pub path_candidates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionReconcileDisposition {
    Unchanged,
    Upgraded,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionReconcileEntry {
    pub session_id: [u8; 16],
    pub peer: PeerId,
    pub disposition: SessionReconcileDisposition,
    pub reason: String,
    pub path_kind: Option<PathKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionReconcileReport {
    pub examined: usize,
    pub unchanged: usize,
    pub upgraded: usize,
    pub closed: usize,
    pub entries: Vec<SessionReconcileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityReevaluationReport {
    pub reevaluated_sessions: usize,
    pub closed_sessions: usize,
    pub degraded_sessions: usize,
    pub migrated_sessions: usize,
    pub unchanged_sessions: usize,
    pub reevaluated_listeners: usize,
    pub suppressed_listeners: usize,
    pub restored_listeners: usize,
    pub reconnect_suppressions_added: usize,
    pub reconnect_suppressions_cleared: usize,
    pub local_policy_denied: bool,
    pub authority_subject_mismatch: bool,
    pub subject_mismatch_sessions: usize,
    pub local_membership_denied_sessions: usize,
    pub peer_membership_denied_sessions: usize,
    pub capability_denied_sessions: usize,
    pub local_policy_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePathState {
    Candidate,
    Active,
    Degraded,
    Migrating,
    Failed,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePathAlternative {
    pub path_kind: PathKind,
    pub source: PathSource,
    pub relay_peer: Option<PeerId>,
    pub score: u32,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePathSnapshot {
    pub session_id: Option<[u8; 16]>,
    pub peer: PeerId,
    pub protocol: Option<ProtocolId>,
    pub class: TrafficClass,
    pub state: RuntimePathState,
    pub path_kind: Option<PathKind>,
    pub source: Option<PathSource>,
    pub relay_peer: Option<PeerId>,
    pub endpoint_summary: String,
    pub state_reason: Option<String>,
    pub decision_reason: Option<String>,
    pub score: Option<u32>,
    pub summary: String,
    pub alternatives: Vec<RuntimePathAlternative>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHealthLevel {
    Ready,
    Degraded,
    Failed,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeHealthReport {
    pub daemon_readiness: RuntimeHealthLevel,
    pub authority_sync_health: RuntimeHealthLevel,
    pub runtime_registry_health: RuntimeHealthLevel,
    pub path_manager_health: RuntimeHealthLevel,
    pub reconnect_subsystem_health: RuntimeHealthLevel,
    pub authority_subject_status: String,
    pub authority_deny_reason: Option<String>,
    pub active_sessions: usize,
    pub active_paths: usize,
    pub active_listeners: usize,
    pub reconnect_state: RuntimeReconnectState,
    pub reconnect_attempt_count: usize,
    pub reconnect_next_attempt_unix_secs: Option<u64>,
    pub reconnect_suppression_count: usize,
    pub runtime_event_buffer_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableStateViolation {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableStateSummary {
    pub network: String,
    pub local_peer_id: PeerId,
    pub roles: Vec<DaemonRole>,
    pub bootstrap_hints: usize,
    pub relays: usize,
    pub peers: usize,
    pub capability_grants: usize,
    pub revocations: usize,
    pub denied_peers: usize,
    pub path_candidates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableStateInspectionReport {
    pub state_path: PathBuf,
    pub present: bool,
    pub schema_version: Option<u64>,
    pub valid: bool,
    pub violations: Vec<DurableStateViolation>,
    pub summary: Option<DurableStateSummary>,
}

impl DaemonState {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, DaemonStateError> {
        let value = serde_json::from_slice::<Value>(&fs::read(path)?)?;
        validate_durable_state_value(&value)?;
        let mut state = serde_json::from_value::<Self>(value)?;
        state.active_sessions = Vec::new();
        Ok(state)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), DaemonStateError> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let mut state = self.clone();
        state.schema_version = DAEMON_STATE_SCHEMA_VERSION;
        state.active_sessions.clear();
        fs::write(path, serde_json::to_vec_pretty(&state)?)?;
        Ok(())
    }

    pub fn peer(&self, peer: &PeerId) -> Option<&PeerInspection> {
        self.peers.iter().find(|entry| &entry.snapshot.peer == peer)
    }

    pub fn status_line(&self) -> String {
        format!(
            "network={} local_peer={} roles={} bootstrap={} relays={} peers={} revocations={} denied={} sessions={} relay_required={}",
            self.network,
            self.local_peer_id,
            self.roles.len(),
            self.bootstrap.len(),
            self.relay_count(),
            self.peers.len(),
            self.revocations.len(),
            self.denied_peers.len(),
            self.active_sessions.len(),
            self.netcheck.relay_required()
        )
    }

    pub fn best_path(&self, peer: &PeerId, class: TrafficClass) -> Option<PathDecision> {
        let candidates = self
            .path_candidates
            .iter()
            .filter(|candidate| &candidate.peer == peer)
            .cloned()
            .collect::<Vec<_>>();
        crate::select_best_path(&candidates, class)
    }

    pub fn path_candidates_for(&self, peer: &PeerId) -> Vec<PathCandidate> {
        self.path_candidates
            .iter()
            .filter(|candidate| &candidate.peer == peer)
            .cloned()
            .collect()
    }

    pub fn first_peer(&self) -> Option<&PeerInspection> {
        self.peers.first()
    }

    pub fn active_sessions(&self) -> &[SessionSnapshot] {
        &self.active_sessions
    }

    pub fn session(&self, session_id: &[u8; 16]) -> Option<&SessionSnapshot> {
        self.active_sessions
            .iter()
            .find(|session| &session.session_id == session_id)
    }

    pub fn grants_for_peer(&self, peer: &PeerId) -> Vec<CapabilityGrant> {
        self.capability_grants
            .iter()
            .filter(|grant| &grant.subject_peer_id == peer)
            .filter(|grant| !self.is_capability_revoked(&grant.subject_peer_id, grant.sequence))
            .cloned()
            .collect()
    }

    pub fn deny_reason(&self, peer: &PeerId) -> Option<&str> {
        self.denied_peers
            .iter()
            .find(|entry| &entry.peer == peer)
            .map(|entry| entry.reason.as_str())
    }

    pub fn explain_policy(&self, peer: &PeerId, protocol: &ProtocolId) -> Decision {
        if let Some(reason) = self.deny_reason(peer) {
            return Decision {
                allowed: false,
                reason: reason.to_string(),
            };
        }

        self.explain_local_protocol_policy(protocol)
    }

    pub fn explain_local_protocol_policy(&self, protocol: &ProtocolId) -> Decision {
        let grants = self.grants_for_peer(&self.local_peer_id);
        let engine = PolicyEngine::with_rules(vec![PolicyRule {
            effect: Effect::Allow,
            network_id: Some(NetworkId::derive(&self.network)),
            protocol: Some(protocol.clone()),
            source_peer: Some(self.local_peer_id.clone()),
            required_capability: Some(protocol_capability(protocol)),
        }]);
        let decision = engine.evaluate(
            &NetworkId::derive(&self.network),
            &self.local_peer_id,
            protocol,
            &grants,
        );

        if decision.allowed {
            Decision {
                allowed: true,
                reason: format!("{} using {} active grant(s)", decision.reason, grants.len()),
            }
        } else if grants.is_empty() {
            Decision {
                allowed: false,
                reason: format!("no active capability grants for {}", protocol.as_str()),
            }
        } else {
            decision
        }
    }

    pub fn authority_snapshot(&self) -> AuthorityArtifactSnapshot {
        AuthorityArtifactSnapshot {
            network_id: NetworkId::derive(&self.network),
            enrollment_token: None,
            membership: Some(self.membership.clone()),
            capability_grants: self.capability_grants.clone(),
            revocations: self.revocations.clone(),
            bootstrap_hints: self
                .bootstrap
                .iter()
                .map(|endpoint| membership::BootstrapHint {
                    peer_id: endpoint.peer.clone(),
                    addresses: endpoint.addresses.clone(),
                    metadata: endpoint.metadata.clone(),
                })
                .collect(),
        }
    }

    pub fn relay_count(&self) -> usize {
        self.relay_map
            .as_ref()
            .map(|relay_map| relay_map.relays.len())
            .unwrap_or(0)
    }

    pub fn relay_announcements(&self) -> &[RelayAnnouncement] {
        self.relay_map
            .as_ref()
            .map(|relay_map| relay_map.relays.as_slice())
            .unwrap_or(&[])
    }

    pub fn max_revocation_sequence(&self) -> Option<u64> {
        self.revocations
            .iter()
            .map(|revocation| revocation.sequence)
            .max()
    }

    pub fn apply_revocations(&self, incoming: Vec<RevocationRecord>) -> (Self, usize) {
        let mut state = self.clone();
        let mut added = 0;

        for revocation in incoming {
            if !state.revocations.iter().any(|existing| {
                existing.sequence == revocation.sequence
                    && existing.issuer_peer_id == revocation.issuer_peer_id
                    && existing.target == revocation.target
            }) {
                state.revocations.push(revocation);
                added += 1;
            }
        }

        state.denied_peers = denied_peers(&state.membership, &state.revocations);
        (state, added)
    }

    pub fn apply_relay_map(&self, incoming: RelayMap) -> (Self, usize) {
        let current = self.relay_map.as_ref();
        if current.is_some_and(|existing| existing.version > incoming.version) {
            return (self.clone(), 0);
        }

        let added = incoming
            .relays
            .iter()
            .filter(|relay| {
                !current.is_some_and(|existing| {
                    existing
                        .relays
                        .iter()
                        .any(|known| known.peer_id == relay.peer_id)
                })
            })
            .count();
        let relay_peers = relay_peers(&incoming);
        let mut state = self.clone();
        state.relay_map = Some(incoming);
        state.peers = merge_relay_peers(&state.peers, &relay_peers);
        state.path_candidates = merged_path_candidates(&state);
        (state, added)
    }

    pub fn route_plan(
        &self,
        peer: &PeerId,
        protocol: Option<ProtocolId>,
        class: TrafficClass,
    ) -> Result<RoutePlan, DaemonStateError> {
        let decision = self
            .best_path(peer, class)
            .ok_or_else(|| DaemonStateError::NoRoute(peer.clone()))?;
        let inspection = self
            .peer(peer)
            .ok_or_else(|| DaemonStateError::PeerNotFound(peer.to_text()))?;
        let remote_endpoints =
            route_endpoints(&inspection.snapshot.addresses, decision.selected.path_kind);
        let relay = if decision.selected.path_kind == PathKind::Relay {
            let relay_peer = decision
                .selected
                .relay_peer
                .as_ref()
                .ok_or_else(|| DaemonStateError::NoRoute(peer.clone()))?;
            let relay = self
                .relay_announcements()
                .iter()
                .find(|candidate| &candidate.peer_id == relay_peer)
                .ok_or_else(|| DaemonStateError::NoRoute(peer.clone()))?;
            Some(RelayPlan {
                relay_peer: relay_peer.clone(),
                relay_endpoints: route_endpoints(
                    &relay.advertised_endpoints,
                    relay_path_kind(relay),
                ),
                relay_control_endpoint: relay.control_endpoint.clone(),
                destination_endpoints: remote_endpoints.clone(),
                supports_datagrams: relay.supports_quic_datagrams,
                supports_path_migration: relay.supports_path_migration,
            })
        } else {
            None
        };

        Ok(RoutePlan {
            local_peer: self.local_peer_id.clone(),
            peer: peer.clone(),
            protocol,
            class,
            path_kind: decision.selected.path_kind,
            source: route_source(&decision.selected.source),
            remote_endpoints,
            relay,
        })
    }

    pub fn with_active_session(&self, session: SessionSnapshot) -> Self {
        let mut state = self.clone();
        if let Some(existing) = state
            .active_sessions
            .iter_mut()
            .find(|existing| existing.session_id == session.session_id)
        {
            *existing = session;
        } else {
            state.active_sessions.push(session);
        }
        state
    }

    pub fn without_session(&self, session_id: &[u8; 16]) -> Self {
        let mut state = self.clone();
        state
            .active_sessions
            .retain(|session| &session.session_id != session_id);
        state
    }

    pub fn sync_authority_snapshot(
        &self,
        client: &ControlClient,
        incoming: AuthorityArtifactSnapshot,
    ) -> Result<(Self, StateSyncReport), DaemonStateError> {
        let (merged, delta) = client.merge_snapshot(Some(self.authority_snapshot()), incoming)?;
        let membership = merged
            .membership
            .ok_or(DaemonStateError::MissingMembership)?;
        let bootstrap = merged
            .bootstrap_hints
            .into_iter()
            .map(bootstrap_endpoint_from_hint)
            .collect::<Vec<_>>();
        let mut state = self.clone();
        state.local_peer_id = membership.subject_peer_id.clone();
        state.membership = membership.clone();
        state.capability_grants = merged.capability_grants;
        state.revocations = merged.revocations;
        state.denied_peers = denied_peers(&membership, &state.revocations);
        state.bootstrap = bootstrap.clone();
        state.peers = merge_bootstrap_peers(&state.peers, &bootstrap);
        state.path_candidates = merged_path_candidates(&state);
        Ok((
            state,
            StateSyncReport {
                membership_changed: delta.membership_changed,
                grants_added: delta.grants_added,
                grants_removed: delta.grants_removed,
                revocations_added: delta.revocations_added,
                bootstrap_hints_added: delta.bootstrap_hints_added,
                bootstrap_hints_removed: delta.bootstrap_hints_removed,
                relay_announcements_added: 0,
            },
        ))
    }

    pub fn from_authority_snapshot(
        network: &str,
        roles: Vec<DaemonRole>,
        snapshot: AuthorityArtifactSnapshot,
    ) -> Result<Self, DaemonStateError> {
        if snapshot.network_id != NetworkId::derive(network) {
            return Err(DaemonStateError::NetworkMismatch);
        }

        let membership = snapshot
            .membership
            .ok_or(DaemonStateError::MissingMembership)?;
        let capability_grants = snapshot.capability_grants;
        let revocations = snapshot.revocations;
        let bootstrap = snapshot
            .bootstrap_hints
            .into_iter()
            .map(bootstrap_endpoint_from_hint)
            .collect::<Vec<_>>();

        let denied_peers = denied_peers(&membership, &revocations);

        let mut state = Self {
            schema_version: DAEMON_STATE_SCHEMA_VERSION,
            network: network.to_string(),
            local_peer_id: membership.subject_peer_id.clone(),
            roles,
            membership,
            capability_grants,
            revocations,
            denied_peers,
            peers: bootstrap_peers(&bootstrap),
            bootstrap,
            relay_map: None,
            netcheck: pending_netcheck(),
            queue_policies: default_queue_policies(),
            active_sessions: Vec::new(),
            path_candidates: Vec::new(),
        };
        state.path_candidates = merged_path_candidates(&state);
        Ok(state)
    }
}

fn durable_state_summary(state: &DaemonState) -> DurableStateSummary {
    DurableStateSummary {
        network: state.network.clone(),
        local_peer_id: state.local_peer_id.clone(),
        roles: state.roles.clone(),
        bootstrap_hints: state.bootstrap.len(),
        relays: state.relay_count(),
        peers: state.peers.len(),
        capability_grants: state.capability_grants.len(),
        revocations: state.revocations.len(),
        denied_peers: state.denied_peers.len(),
        path_candidates: state.path_candidates.len(),
    }
}

fn durable_state_schema_version(value: &Value) -> Option<u64> {
    value
        .as_object()
        .and_then(|object| object.get("schema_version"))
        .and_then(Value::as_u64)
}

fn durable_state_violation(
    path: impl Into<String>,
    message: impl Into<String>,
) -> DurableStateViolation {
    DurableStateViolation {
        path: path.into(),
        message: message.into(),
    }
}

fn durable_state_violations_from_error(error: &DaemonStateError) -> Vec<DurableStateViolation> {
    match error {
        DaemonStateError::MissingSchemaVersion => {
            vec![durable_state_violation(
                "$.schema_version",
                error.to_string(),
            )]
        }
        DaemonStateError::UnsupportedSchemaVersion { .. } => {
            vec![durable_state_violation(
                "$.schema_version",
                error.to_string(),
            )]
        }
        DaemonStateError::UnsupportedDurableField(field) => {
            vec![durable_state_violation(
                format!("$.{field}"),
                error.to_string(),
            )]
        }
        _ => vec![durable_state_violation("$", error.to_string())],
    }
}

pub fn inspect_durable_state_file(
    path: impl AsRef<Path>,
) -> Result<DurableStateInspectionReport, DaemonStateError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(DurableStateInspectionReport {
            state_path: path.to_path_buf(),
            present: false,
            schema_version: None,
            valid: false,
            violations: vec![durable_state_violation(
                "$",
                "durable state file is missing",
            )],
            summary: None,
        });
    }

    let bytes = fs::read(path)?;
    let value = match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => value,
        Err(error) => {
            return Ok(DurableStateInspectionReport {
                state_path: path.to_path_buf(),
                present: true,
                schema_version: None,
                valid: false,
                violations: vec![durable_state_violation(
                    "$",
                    format!("durable state is not valid JSON: {error}"),
                )],
                summary: None,
            });
        }
    };
    let schema_version = durable_state_schema_version(&value);
    match validate_durable_state_value(&value) {
        Ok(()) => {
            let mut state = match serde_json::from_value::<DaemonState>(value) {
                Ok(state) => state,
                Err(error) => {
                    return Ok(DurableStateInspectionReport {
                        state_path: path.to_path_buf(),
                        present: true,
                        schema_version,
                        valid: false,
                        violations: vec![durable_state_violation(
                            "$",
                            format!("durable state could not be deserialized: {error}"),
                        )],
                        summary: None,
                    });
                }
            };
            state.active_sessions.clear();
            Ok(DurableStateInspectionReport {
                state_path: path.to_path_buf(),
                present: true,
                schema_version,
                valid: true,
                violations: Vec::new(),
                summary: Some(durable_state_summary(&state)),
            })
        }
        Err(error) => Ok(DurableStateInspectionReport {
            state_path: path.to_path_buf(),
            present: true,
            schema_version,
            valid: false,
            violations: durable_state_violations_from_error(&error),
            summary: None,
        }),
    }
}

pub fn validate_durable_state_file(
    path: impl AsRef<Path>,
) -> Result<DurableStateInspectionReport, DaemonStateError> {
    let report = inspect_durable_state_file(path)?;
    Ok(DurableStateInspectionReport {
        state_path: report.state_path,
        present: report.present,
        schema_version: report.schema_version,
        valid: report.valid,
        violations: report.violations,
        summary: None,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn derive_backup_key(passphrase: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], DaemonStateError> {
    let params = ScryptParams::recommended();
    let mut key = [0_u8; 32];
    scrypt(passphrase, salt, &params, &mut key)
        .map_err(|_| DaemonStateError::BackupKeyDerivation)?;
    Ok(key)
}

fn encrypt_backup_bundle(
    bundle: &DurableBackupBundleData,
    passphrase: &str,
) -> Result<DurableBackupBundleEnvelope, DaemonStateError> {
    let plaintext = serde_json::to_vec_pretty(bundle)?;
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut key = derive_backup_key(passphrase.as_bytes(), &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| DaemonStateError::InvalidBackupBundle)?;
    key.zeroize();
    Ok(DurableBackupBundleEnvelope {
        version: BACKUP_BUNDLE_FORMAT_VERSION,
        cipher: "chacha20poly1305".to_string(),
        kdf: "scrypt".to_string(),
        salt,
        nonce,
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn decrypt_backup_bundle(
    envelope: &DurableBackupBundleEnvelope,
    passphrase: &str,
) -> Result<DurableBackupBundleData, DaemonStateError> {
    if envelope.version != BACKUP_BUNDLE_FORMAT_VERSION
        || envelope.cipher != "chacha20poly1305"
        || envelope.kdf != "scrypt"
    {
        return Err(DaemonStateError::InvalidBackupBundle);
    }
    let ciphertext = BASE64
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| DaemonStateError::InvalidBackupBundle)?;
    let mut key = derive_backup_key(passphrase.as_bytes(), &envelope.salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&envelope.nonce), ciphertext.as_ref())
        .map_err(|_| DaemonStateError::InvalidBackupBundle)?;
    key.zeroize();
    serde_json::from_slice(&plaintext).map_err(Into::into)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs()
}

pub fn export_backup_bundle(
    request: DurableBackupExportRequest,
) -> Result<DurableBackupExportReport, DaemonStateError> {
    if request.output_path.exists() && !request.overwrite {
        return Err(DaemonStateError::InvalidSession(format!(
            "backup bundle path {} already exists; rerun with overwrite enabled",
            request.output_path.display()
        )));
    }
    let identity_bytes = fs::read(&request.identity_path)?;
    let state_bytes = fs::read(&request.state_path)?;
    let durable_state = inspect_durable_state_file(&request.state_path)?;
    let identity_sha256_hex = sha256_hex(&identity_bytes);
    let state_sha256_hex = sha256_hex(&state_bytes);
    let created_at_unix_secs = now_unix_secs();
    let bundle = DurableBackupBundleData {
        manifest: DurableBackupManifest {
            format: "quip_backup_bundle".to_string(),
            format_version: BACKUP_BUNDLE_FORMAT_VERSION,
            created_at_unix_secs,
            hostname: request.hostname.clone(),
            environment: request.environment.clone(),
            network: request.network.clone(),
            identity_path: request.identity_path.display().to_string(),
            state_path: request.state_path.display().to_string(),
            authority_origin: request.authority_origin.clone(),
            authority_subject: request.authority_subject.clone(),
            authority_snapshot: request.authority_snapshot.clone(),
            durable_state_present: durable_state.present,
            durable_state_valid: durable_state.valid,
            assets: vec![
                DurableBackupAsset {
                    concern: "identity".to_string(),
                    relative_path: "identity/node.json".to_string(),
                    sha256_hex: identity_sha256_hex.clone(),
                    bytes: identity_bytes.len(),
                },
                DurableBackupAsset {
                    concern: "network_state".to_string(),
                    relative_path: "net/state.json".to_string(),
                    sha256_hex: state_sha256_hex.clone(),
                    bytes: state_bytes.len(),
                },
            ],
        },
        identity_file_base64: BASE64.encode(identity_bytes),
        state_file_base64: BASE64.encode(state_bytes),
    };
    let envelope = encrypt_backup_bundle(&bundle, &request.passphrase)?;
    if let Some(parent) = request.output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&request.output_path, serde_json::to_vec_pretty(&envelope)?)?;
    Ok(DurableBackupExportReport {
        bundle_path: request.output_path,
        created_at_unix_secs,
        hostname: request.hostname,
        environment: request.environment,
        network: request.network,
        identity_sha256_hex,
        state_sha256_hex,
        durable_state_present: durable_state.present,
        durable_state_valid: durable_state.valid,
    })
}

pub fn restore_backup_bundle(
    request: DurableBackupRestoreRequest,
) -> Result<DurableBackupRestoreReport, DaemonStateError> {
    if !request.overwrite && (request.identity_path.exists() || request.state_path.exists()) {
        return Err(DaemonStateError::InvalidSession(
            "restore target already exists; rerun with overwrite enabled".to_string(),
        ));
    }
    let envelope: DurableBackupBundleEnvelope =
        serde_json::from_slice(&fs::read(&request.input_path)?)?;
    let bundle = decrypt_backup_bundle(&envelope, &request.passphrase)?;
    let identity_bytes = BASE64
        .decode(bundle.identity_file_base64.as_bytes())
        .map_err(|_| DaemonStateError::InvalidBackupBundle)?;
    let state_bytes = BASE64
        .decode(bundle.state_file_base64.as_bytes())
        .map_err(|_| DaemonStateError::InvalidBackupBundle)?;
    let identity_asset = bundle
        .manifest
        .assets
        .iter()
        .find(|asset| asset.concern == "identity")
        .ok_or(DaemonStateError::InvalidBackupBundle)?;
    let state_asset = bundle
        .manifest
        .assets
        .iter()
        .find(|asset| asset.concern == "network_state")
        .ok_or(DaemonStateError::InvalidBackupBundle)?;
    if sha256_hex(&identity_bytes) != identity_asset.sha256_hex
        || sha256_hex(&state_bytes) != state_asset.sha256_hex
    {
        return Err(DaemonStateError::InvalidBackupBundle);
    }
    let state_value = serde_json::from_slice::<Value>(&state_bytes)
        .map_err(|_| DaemonStateError::InvalidBackupBundle)?;
    validate_durable_state_value(&state_value)?;
    if let Some(parent) = request.identity_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = request.state_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&request.identity_path, &identity_bytes)?;
    fs::write(&request.state_path, &state_bytes)?;
    Ok(DurableBackupRestoreReport {
        input_path: request.input_path,
        restored_identity_path: request.identity_path,
        restored_state_path: request.state_path,
        created_at_unix_secs: bundle.manifest.created_at_unix_secs,
        hostname: bundle.manifest.hostname,
        environment: bundle.manifest.environment,
        network: bundle.manifest.network,
        identity_sha256_hex: sha256_hex(&identity_bytes),
        state_sha256_hex: sha256_hex(&state_bytes),
    })
}

#[derive(Debug)]
pub struct LocalNode {
    pub network_id: NetworkId,
    pub peer_store: PeerStore,
    pub discovery: DiscoveryService,
    pub netcheck: NetcheckReport,
    pub candidate_paths: Vec<PathCandidate>,
}

impl LocalNode {
    pub fn fixture(network_name: &str) -> Self {
        let network_id = NetworkId::derive(network_name);
        let relay_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"fra-relay-1");
        let worker_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"worker-17");
        let bootstrap = vec![
            BootstrapHint {
                peer: relay_peer.clone(),
                addresses: vec!["udp://203.0.113.10:443".to_string()],
                protocols: vec!["/quicnet/relay/1".to_string()],
            },
            BootstrapHint {
                peer: worker_peer.clone(),
                addresses: vec!["udp://198.51.100.24:8443".to_string()],
                protocols: vec![
                    "/quicnet/control/1".to_string(),
                    "/quicnet/records/1".to_string(),
                ],
            },
        ];

        let discovery = DiscoveryService::with_bootstrap(bootstrap);
        let mut peer_store = PeerStore::default();
        discovery.ingest_bootstrap(&mut peer_store, 1_720_000_000);
        peer_store.upsert_peer_with_status(
            PeerSnapshot {
                peer: worker_peer.clone(),
                protocols: vec![
                    "/quicnet/control/1".to_string(),
                    "/quicnet/records/1".to_string(),
                ],
                addresses: vec!["udp://198.51.100.24:8443".to_string()],
            },
            PeerStatus {
                source: PeerSource::Discovery,
                reachability: PeerReachability::Direct,
                last_seen_unix_secs: Some(1_720_000_120),
            },
        );

        Self {
            network_id,
            peer_store,
            discovery,
            netcheck: NetcheckReport {
                nat_type: NatType::RestrictedCone,
                udp_reachable: true,
                ipv6_reachable: true,
                hairpin_supported: true,
                public_udp_addr: Some("198.51.100.24:8443".to_string()),
                port_mapped: false,
                probe_observations: vec![
                    ProbeObservation {
                        vantage: "nyc-observer-1".to_string(),
                        status: ProbeStatus::Passed,
                        latency_ms: Some(12),
                        detail: "reflexive candidate validated".to_string(),
                    },
                    ProbeObservation {
                        vantage: "fra-observer-1".to_string(),
                        status: ProbeStatus::Passed,
                        latency_ms: Some(24),
                        detail: "ipv6 direct candidate validated".to_string(),
                    },
                ],
            },
            candidate_paths: vec![
                PathCandidate {
                    peer: worker_peer.clone(),
                    path_kind: PathKind::DirectIpv6,
                    relay_peer: None,
                    source: PathSource::Observed,
                    traffic_classes: vec![TrafficClass::Interactive, TrafficClass::Control],
                    rtt_ms: 13,
                    jitter_ms: 1,
                    loss_pct: 0.1,
                    throughput_mbps: 780,
                    relay_penalty: 0,
                },
                PathCandidate {
                    peer: worker_peer,
                    path_kind: PathKind::Relay,
                    relay_peer: Some(relay_peer.clone()),
                    source: PathSource::Observed,
                    traffic_classes: vec![TrafficClass::Interactive, TrafficClass::Bulk],
                    rtt_ms: 24,
                    jitter_ms: 4,
                    loss_pct: 0.3,
                    throughput_mbps: 1_200,
                    relay_penalty: 25,
                },
            ],
        }
    }

    pub fn status_line(&self) -> String {
        format!(
            "network={} peers={} bootstrap_candidates={} {}",
            self.network_id,
            self.peer_store.peers().len(),
            self.discovery.bootstrap_candidates().len(),
            self.netcheck.summary()
        )
    }

    pub fn peers(&self) -> Vec<PeerInspection> {
        self.peer_store.peers()
    }

    pub fn best_path_for(&self, class: TrafficClass) -> Option<PathDecision> {
        crate::select_best_path(&self.candidate_paths, class)
    }
}

pub fn fixture_daemon_state(network: &str) -> DaemonState {
    let node = LocalNode::fixture(network);
    let authority = crypto::IdentityKeypair::from_secret_bytes([11_u8; 32]);
    let local_identity = crypto::IdentityKeypair::from_secret_bytes([12_u8; 32]);
    let local_peer_id = local_identity.peer_id();
    let membership = MembershipCertificate::issue(
        &authority,
        NetworkId::derive(network),
        local_peer_id.clone(),
        1_720_000_000,
        1_820_000_000,
        vec!["member".to_string()],
    );
    let bootstrap = node
        .discovery
        .bootstrap_candidates()
        .iter()
        .cloned()
        .map(|hint| BootstrapEndpoint {
            peer: Some(hint.peer),
            addresses: hint.addresses,
            protocols: hint.protocols,
            metadata: BTreeMap::from([("source".to_string(), "fixture".to_string())]),
        })
        .collect();
    let peers = node.peer_store.peers();
    let netcheck = node.netcheck.clone();
    let path_candidates = node.candidate_paths.clone();

    DaemonState {
        schema_version: DAEMON_STATE_SCHEMA_VERSION,
        network: network.to_string(),
        local_peer_id,
        roles: vec![DaemonRole::Edge, DaemonRole::Observer],
        membership,
        capability_grants: Vec::new(),
        revocations: Vec::new(),
        denied_peers: Vec::new(),
        bootstrap,
        relay_map: Some(RelayMap {
            version: 1,
            generated_at: 1_720_000_000,
            relays: vec![RelayAnnouncement {
                peer_id: PeerId::from_public_key(KeyAlgorithm::Ed25519, b"fra-relay-1"),
                region: "eu-central-1".to_string(),
                advertised_endpoints: vec!["udp://203.0.113.10:443".to_string()],
                control_endpoint: "http://203.0.113.10:9081".to_string(),
                max_bandwidth_bps: 1_500_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec![
                    "NetworkControl".to_string(),
                    "InteractiveRpc".to_string(),
                    "Background".to_string(),
                ],
            }],
        }),
        peers,
        netcheck,
        queue_policies: default_queue_policies(),
        active_sessions: Vec::new(),
        path_candidates,
    }
}

fn validate_durable_state_value(value: &Value) -> Result<(), DaemonStateError> {
    let object = value.as_object().ok_or_else(|| {
        DaemonStateError::InvalidSession("durable state must be a JSON object".to_string())
    })?;

    let schema_version = object
        .get("schema_version")
        .ok_or(DaemonStateError::MissingSchemaVersion)?
        .as_u64()
        .ok_or_else(|| {
            DaemonStateError::InvalidSession(
                "durable state schema version must be an unsigned integer".to_string(),
            )
        })?;
    if schema_version != DAEMON_STATE_SCHEMA_VERSION {
        return Err(DaemonStateError::UnsupportedSchemaVersion {
            found: schema_version,
            expected: DAEMON_STATE_SCHEMA_VERSION,
        });
    }

    let allowed_fields = [
        "schema_version",
        "network",
        "local_peer_id",
        "roles",
        "membership",
        "capability_grants",
        "revocations",
        "denied_peers",
        "bootstrap",
        "relay_map",
        "peers",
        "netcheck",
        "queue_policies",
        "path_candidates",
    ];
    for field in object.keys() {
        if !allowed_fields.contains(&field.as_str()) {
            return Err(DaemonStateError::UnsupportedDurableField(field.clone()));
        }
    }

    Ok(())
}

#[derive(Debug)]
pub struct LocalControlPlane {
    pub config: DaemonConfig,
}

impl LocalControlPlane {
    pub fn new(config: DaemonConfig) -> Self {
        Self { config }
    }

    pub fn ensure_state(&self) -> Result<DaemonState, DaemonStateError> {
        if self.config.state_path.exists() {
            let mut state = DaemonState::load(&self.config.state_path)?;
            state.roles = self.config.roles.clone();
            state.path_candidates = merged_path_candidates(&state);
            Ok(state)
        } else {
            let mut state = fixture_daemon_state(&self.config.network);
            state.roles = self.config.roles.clone();
            state.path_candidates = merged_path_candidates(&state);
            state.save(&self.config.state_path)?;
            Ok(state)
        }
    }

    pub fn ensure_state_for_local_identity(
        &self,
        local_identity: &IdentityKeypair,
    ) -> Result<DaemonState, DaemonStateError> {
        if self.config.state_path.exists() {
            self.ensure_state()
        } else {
            let mut state = self_identity_daemon_state(
                &self.config.network,
                self.config.roles.clone(),
                local_identity,
            );
            state.path_candidates = merged_path_candidates(&state);
            state.save(&self.config.state_path)?;
            Ok(state)
        }
    }

    pub fn ensure_identity_bound_state(
        &self,
        local_identity: &IdentityKeypair,
    ) -> Result<DaemonState, DaemonStateError> {
        let state = self.ensure_state_for_local_identity(local_identity)?;
        let expected = local_identity.peer_id();
        if state.local_peer_id != expected {
            return Err(DaemonStateError::InvalidSession(format!(
                "state local peer {} does not match runtime identity {}",
                state.local_peer_id, expected
            )));
        }
        if state.membership.subject_peer_id != expected {
            return Err(DaemonStateError::InvalidSession(format!(
                "membership subject peer {} does not match runtime identity {}",
                state.membership.subject_peer_id, expected
            )));
        }
        Ok(state)
    }

    pub fn refresh_and_persist(&self) -> Result<DaemonState, DaemonStateError> {
        let state = self.ensure_state()?;
        state.save(&self.config.state_path)?;
        Ok(state)
    }

    pub fn refresh_and_persist_for_local_identity(
        &self,
        local_identity: &IdentityKeypair,
    ) -> Result<DaemonState, DaemonStateError> {
        let state = self.ensure_state_for_local_identity(local_identity)?;
        state.save(&self.config.state_path)?;
        Ok(state)
    }

    pub fn reprobe_network_change(
        &self,
        reason: impl Into<String>,
    ) -> Result<NetcheckReprobeReport, DaemonStateError> {
        let mut state = self.ensure_state()?;
        let reason = reason.into();
        state.netcheck = reprobe_netcheck(&state, &reason);
        state.path_candidates = merged_path_candidates(&state);
        let report = NetcheckReprobeReport {
            reason,
            udp_reachable: state.netcheck.udp_reachable,
            ipv6_reachable: state.netcheck.ipv6_reachable,
            relay_required: state.netcheck.relay_required(),
            probe_observations: state.netcheck.probe_observations.len(),
            path_candidates: state.path_candidates.len(),
        };
        state.save(&self.config.state_path)?;
        Ok(report)
    }

    pub fn seed_from_authority_snapshot(
        &self,
        snapshot_path: impl AsRef<Path>,
    ) -> Result<DaemonState, DaemonStateError> {
        let snapshot = load_authority_snapshot(snapshot_path)?;
        let mut state = DaemonState::from_authority_snapshot(
            &self.config.network,
            self.config.roles.clone(),
            snapshot,
        )?;
        state.path_candidates = merged_path_candidates(&state);
        state.save(&self.config.state_path)?;
        Ok(state)
    }

    pub fn sync_authority_snapshot(
        &self,
        snapshot_path: impl AsRef<Path>,
    ) -> Result<(DaemonState, StateSyncReport), DaemonStateError> {
        let snapshot = load_authority_snapshot(snapshot_path)?;
        let state = if self.config.state_path.exists() {
            let mut state = DaemonState::load(&self.config.state_path)?;
            state.roles = self.config.roles.clone();
            state
        } else {
            let mut state = DaemonState::from_authority_snapshot(
                &self.config.network,
                self.config.roles.clone(),
                snapshot,
            )?;
            state.path_candidates = merged_path_candidates(&state);
            let report = StateSyncReport {
                membership_changed: true,
                grants_added: state.capability_grants.len(),
                grants_removed: 0,
                revocations_added: state.revocations.len(),
                bootstrap_hints_added: state.bootstrap.len(),
                bootstrap_hints_removed: 0,
                relay_announcements_added: 0,
            };
            state.save(&self.config.state_path)?;
            return Ok((state, report));
        };
        let client = ControlClient {
            network_id: NetworkId::derive(&self.config.network),
            endpoints: control::AuthorityEndpoints {
                enrollment: "local://enroll".to_string(),
                revocation: "local://revoke".to_string(),
                relay_map: "local://relays".to_string(),
                bootstrap: "local://bootstrap".to_string(),
                snapshot: "local://snapshot".to_string(),
            },
        };
        let (state, report) = state.sync_authority_snapshot(&client, snapshot)?;
        state.save(&self.config.state_path)?;
        Ok((state, report))
    }

    pub fn seed_from_authority_origin(
        &self,
        origin: &str,
        subject: Option<&str>,
    ) -> Result<DaemonState, DaemonStateError> {
        let client = authority_client(&self.config.network, origin);
        let snapshot = client.fetch_authority_snapshot_for(subject)?;
        let relay_map = client.fetch_relay_map()?;
        let mut state = DaemonState::from_authority_snapshot(
            &self.config.network,
            self.config.roles.clone(),
            snapshot,
        )?;
        state.path_candidates = merged_path_candidates(&state);
        let (state, _) = state.apply_relay_map(relay_map);
        state.save(&self.config.state_path)?;
        Ok(state)
    }

    pub fn sync_authority_origin(
        &self,
        origin: &str,
        subject: Option<&str>,
    ) -> Result<(DaemonState, StateSyncReport), DaemonStateError> {
        let client = authority_client(&self.config.network, origin);
        let snapshot = client.fetch_authority_snapshot_for(subject)?;
        let relay_map = client.fetch_relay_map()?;
        let state = if self.config.state_path.exists() {
            let mut state = DaemonState::load(&self.config.state_path)?;
            state.roles = self.config.roles.clone();
            state
        } else {
            let mut state = DaemonState::from_authority_snapshot(
                &self.config.network,
                self.config.roles.clone(),
                snapshot,
            )?;
            state.path_candidates = merged_path_candidates(&state);
            let (state, relay_announcements_added) = state.apply_relay_map(relay_map);
            let report = StateSyncReport {
                membership_changed: true,
                grants_added: state.capability_grants.len(),
                grants_removed: 0,
                revocations_added: state.revocations.len(),
                bootstrap_hints_added: state.bootstrap.len(),
                bootstrap_hints_removed: 0,
                relay_announcements_added,
            };
            state.save(&self.config.state_path)?;
            return Ok((state, report));
        };
        let (state, report) = state.sync_authority_snapshot(&client, snapshot)?;
        let (state, relay_announcements_added) = state.apply_relay_map(relay_map);
        state.save(&self.config.state_path)?;
        Ok((
            state,
            StateSyncReport {
                grants_removed: report.grants_removed,
                bootstrap_hints_removed: report.bootstrap_hints_removed,
                relay_announcements_added,
                ..report
            },
        ))
    }

    pub fn sync_authority_revocations_origin(
        &self,
        origin: &str,
    ) -> Result<(DaemonState, usize), DaemonStateError> {
        let mut state = self.ensure_state()?;
        state.roles = self.config.roles.clone();
        let client = authority_client(&self.config.network, origin);
        let revocations = client.fetch_revocations(state.max_revocation_sequence())?;
        let (state, added) = state.apply_revocations(revocations);
        state.save(&self.config.state_path)?;
        Ok((state, added))
    }

    pub fn inspect_peer(
        &self,
        peer: &PeerId,
    ) -> Result<(PeerInspection, Option<PathDecision>), DaemonStateError> {
        let state = self.ensure_state()?;
        let inspection = state
            .peer(peer)
            .cloned()
            .ok_or_else(|| DaemonStateError::PeerNotFound(peer.to_text()))?;
        let routing = state.best_path(peer, TrafficClass::Interactive);
        Ok((inspection, routing))
    }

    pub fn session_snapshots(&self) -> Result<Vec<SessionSnapshot>, DaemonStateError> {
        Ok(self.ensure_state()?.active_sessions.clone())
    }

    pub fn inspect_state_file(&self) -> Result<DurableStateInspectionReport, DaemonStateError> {
        inspect_durable_state_file(&self.config.state_path)
    }

    pub fn validate_state_file(&self) -> Result<DurableStateInspectionReport, DaemonStateError> {
        validate_durable_state_file(&self.config.state_path)
    }

    pub fn export_backup_bundle(
        &self,
        request: DurableBackupExportRequest,
    ) -> Result<DurableBackupExportReport, DaemonStateError> {
        export_backup_bundle(request)
    }

    pub fn reset_network_state(&self) -> Result<bool, DaemonStateError> {
        if self.config.state_path.exists() {
            fs::remove_file(&self.config.state_path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn sync_runtime_sessions<T>(&self, transport: &T) -> Result<DaemonState, DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        let mut state = self.ensure_state()?;
        state.active_sessions = transport.active_sessions()?;
        state.save(&self.config.state_path)?;
        Ok(state)
    }

    pub async fn close_session<T>(
        &self,
        session_id: &[u8; 16],
        transport: &T,
    ) -> Result<(), DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        let mut state = self.ensure_state()?;
        let session = transport
            .session_snapshot(session_id)?
            .ok_or_else(|| DaemonStateError::SessionNotFound(hex_session_id(session_id)))?;
        let _ = transport.update_session_state(
            session_id,
            RuntimeSessionState::Closing,
            Some(SessionClosureReason::OperatorRequested),
            Some("operator requested close".to_string()),
        )?;
        transport.close_session(&session).await?;
        state.active_sessions = transport.active_sessions()?;
        state.save(&self.config.state_path)?;
        Ok(())
    }

    pub async fn upgrade_session<T>(
        &self,
        session_id: &[u8; 16],
        transport: &T,
    ) -> Result<SessionSnapshot, DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        let state = self.ensure_state()?;
        let session = transport
            .session_snapshot(session_id)?
            .ok_or_else(|| DaemonStateError::SessionNotFound(hex_session_id(session_id)))?;
        let protocol = session.protocol.clone().ok_or_else(|| {
            DaemonStateError::InvalidSession("session has no negotiated protocol".to_string())
        })?;
        let policy = state.explain_policy(&session.peer, &protocol);
        if !policy.allowed {
            let _ = transport.update_session_state(
                session_id,
                RuntimeSessionState::Failed,
                Some(SessionClosureReason::PolicyRejected),
                Some(policy.reason.clone()),
            )?;
            return Err(DaemonStateError::PolicyDenied(policy.reason));
        }
        let _ = transport.update_session_state(
            session_id,
            RuntimeSessionState::Migrating,
            None,
            Some("daemon selected a better path".to_string()),
        )?;
        let route = state.route_plan(&session.peer, Some(protocol), session.class)?;
        let upgraded = transport.migrate(&session, route).await?;
        let mut state = state.with_active_session(upgraded.clone());
        state.active_sessions = transport.active_sessions()?;
        state.save(&self.config.state_path)?;
        Ok(upgraded)
    }

    pub async fn reconcile_sessions<T>(
        &self,
        transport: &T,
    ) -> Result<SessionReconcileReport, DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        let mut state = self.ensure_state()?;
        let sessions = transport.active_sessions()?;
        let mut entries = Vec::with_capacity(sessions.len());
        let mut unchanged = 0;
        let mut upgraded = 0;
        let mut closed = 0;

        for session in sessions {
            let _ = transport.update_session_state(
                &session.session_id,
                RuntimeSessionState::Reconciling,
                None,
                Some("daemon reconcile cycle".to_string()),
            )?;
            let Some(session) = transport.session_snapshot(&session.session_id)? else {
                state = state.without_session(&session.session_id);
                closed += 1;
                entries.push(SessionReconcileEntry {
                    session_id: session.session_id,
                    peer: session.peer,
                    disposition: SessionReconcileDisposition::Closed,
                    reason: "session is not active in runtime transport".to_string(),
                    path_kind: None,
                });
                continue;
            };
            let Some(protocol) = session.protocol.clone() else {
                let _ = transport.update_session_state(
                    &session.session_id,
                    RuntimeSessionState::Closing,
                    Some(SessionClosureReason::LocalRuntimeFailure),
                    Some("session is missing negotiated protocol".to_string()),
                )?;
                transport.close_session(&session).await?;
                state = state.without_session(&session.session_id);
                closed += 1;
                entries.push(SessionReconcileEntry {
                    session_id: session.session_id,
                    peer: session.peer,
                    disposition: SessionReconcileDisposition::Closed,
                    reason: "session is missing negotiated protocol".to_string(),
                    path_kind: None,
                });
                continue;
            };

            let policy = state.explain_policy(&session.peer, &protocol);
            if !policy.allowed {
                let _ = transport.update_session_state(
                    &session.session_id,
                    RuntimeSessionState::Closing,
                    Some(SessionClosureReason::PolicyRejected),
                    Some(policy.reason.clone()),
                )?;
                transport.close_session(&session).await?;
                state = state.without_session(&session.session_id);
                closed += 1;
                entries.push(SessionReconcileEntry {
                    session_id: session.session_id,
                    peer: session.peer,
                    disposition: SessionReconcileDisposition::Closed,
                    reason: format!("policy denied session: {}", policy.reason),
                    path_kind: None,
                });
                continue;
            }

            let route = match state.route_plan(&session.peer, Some(protocol.clone()), session.class)
            {
                Ok(route) => route,
                Err(DaemonStateError::NoRoute(_)) => {
                    let _ = transport.update_session_state(
                        &session.session_id,
                        RuntimeSessionState::Closing,
                        Some(SessionClosureReason::PathExhaustion),
                        Some("no route is available for session".to_string()),
                    )?;
                    transport.close_session(&session).await?;
                    state = state.without_session(&session.session_id);
                    closed += 1;
                    entries.push(SessionReconcileEntry {
                        session_id: session.session_id,
                        peer: session.peer,
                        disposition: SessionReconcileDisposition::Closed,
                        reason: "no route is available for session".to_string(),
                        path_kind: None,
                    });
                    continue;
                }
                Err(error) => return Err(error),
            };

            if session_matches_route(&session, &route) {
                let _ = transport.update_session_state(
                    &session.session_id,
                    RuntimeSessionState::Active,
                    None,
                    Some("selected path still matches active session".to_string()),
                )?;
                unchanged += 1;
                entries.push(SessionReconcileEntry {
                    session_id: session.session_id,
                    peer: session.peer,
                    disposition: SessionReconcileDisposition::Unchanged,
                    reason: "selected path still matches active session".to_string(),
                    path_kind: Some(session.path_kind),
                });
                continue;
            }

            let next_path_kind = route.path_kind;
            let _ = transport.update_session_state(
                &session.session_id,
                RuntimeSessionState::Migrating,
                None,
                Some("selected path changed; session migrating".to_string()),
            )?;
            let migrated = transport.migrate(&session, route).await?;
            state = state.with_active_session(migrated);
            upgraded += 1;
            entries.push(SessionReconcileEntry {
                session_id: session.session_id,
                peer: session.peer,
                disposition: SessionReconcileDisposition::Upgraded,
                reason: "selected path changed; session migrated".to_string(),
                path_kind: Some(next_path_kind),
            });
        }

        state.active_sessions = transport.active_sessions()?;
        state.save(&self.config.state_path)?;
        Ok(SessionReconcileReport {
            examined: entries.len(),
            unchanged,
            upgraded,
            closed,
            entries,
        })
    }

    pub async fn realize_best_path<T>(
        &self,
        peer: &PeerId,
        protocol: &ProtocolId,
        class: TrafficClass,
        transport: &T,
    ) -> Result<SessionSnapshot, DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        let state = self.ensure_state()?;
        let policy = state.explain_policy(peer, protocol);
        if !policy.allowed {
            return Err(DaemonStateError::PolicyDenied(policy.reason));
        }
        let route = state.route_plan(peer, Some(protocol.clone()), class)?;
        let connection = transport.connect(route).await?;
        let session = connection.snapshot();
        let mut state = state.with_active_session(session.clone());
        state.active_sessions = transport.active_sessions()?;
        state.save(&self.config.state_path)?;
        Ok(session)
    }

    pub fn runtime_events<T>(
        &self,
        transport: &T,
        limit: usize,
    ) -> Result<Vec<RuntimeEvent>, DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        transport.recent_events(limit).map_err(Into::into)
    }

    pub fn runtime_paths<T>(
        &self,
        transport: &T,
    ) -> Result<Vec<RuntimePathSnapshot>, DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        let state = self.ensure_state()?;
        let mut snapshots = Vec::new();
        let sessions = transport.active_sessions()?;
        let suppressions = transport.reconnect_suppressions()?;

        for session in sessions {
            let candidates = state.path_candidates_for(&session.peer);
            let selected = candidates
                .iter()
                .find(|candidate| runtime_candidate_matches_session(candidate, &session));
            let alternatives = runtime_path_alternatives(&candidates, session.class, selected);
            let explanation = selected.map(|candidate| candidate.explain(session.class));
            snapshots.push(RuntimePathSnapshot {
                session_id: Some(session.session_id),
                peer: session.peer.clone(),
                protocol: session.protocol.clone(),
                class: session.class,
                state: runtime_path_state_from_session(&session.state),
                path_kind: Some(session.path_kind),
                source: selected
                    .map(|candidate| candidate.source.clone())
                    .or_else(|| route_source_to_path_source(&session.source)),
                relay_peer: session.relay_peer.clone(),
                endpoint_summary: runtime_session_endpoint_summary(&session),
                state_reason: session.state_reason.clone(),
                decision_reason: explanation.as_ref().map(runtime_path_decision_reason),
                score: selected.map(|candidate| candidate.score(session.class)),
                summary: explanation
                    .map(|explanation| explanation.summary)
                    .unwrap_or_else(|| runtime_session_summary(&session)),
                alternatives,
            });
        }

        for suppression in suppressions {
            if snapshots.iter().any(|entry| {
                entry.session_id.is_some()
                    && entry.peer == suppression.peer
                    && entry.protocol == suppression.protocol
                    && entry.class == suppression.class
            }) {
                continue;
            }
            let candidates = state.path_candidates_for(&suppression.peer);
            let selected = select_best_path(&candidates, suppression.class);
            let suppressed_summary = selected
                .as_ref()
                .map(|decision| {
                    format!(
                        "reconnect suppressed for {}: {}",
                        suppression.peer, decision.explanation.summary
                    )
                })
                .unwrap_or_else(|| {
                    format!(
                        "reconnect suppressed for {} because {}",
                        suppression.peer, suppression.reason
                    )
                });
            let selected_candidate = selected.as_ref().map(|decision| &decision.selected);
            snapshots.push(RuntimePathSnapshot {
                session_id: None,
                peer: suppression.peer.clone(),
                protocol: suppression.protocol.clone(),
                class: suppression.class,
                state: RuntimePathState::Suppressed,
                path_kind: selected_candidate.map(|candidate| candidate.path_kind),
                source: selected_candidate.map(|candidate| candidate.source.clone()),
                relay_peer: selected_candidate.and_then(|candidate| candidate.relay_peer.clone()),
                endpoint_summary: selected_candidate
                    .map(runtime_candidate_endpoint_summary)
                    .unwrap_or_else(|| "no active runtime path".to_string()),
                state_reason: Some(suppression.reason.clone()),
                decision_reason: selected
                    .as_ref()
                    .map(|decision| runtime_path_decision_reason(&decision.explanation)),
                score: selected_candidate.map(|candidate| candidate.score(suppression.class)),
                summary: suppressed_summary,
                alternatives: runtime_path_alternatives(
                    &candidates,
                    suppression.class,
                    selected_candidate,
                ),
            });
        }

        let reconnect_attempts = transport.reconnect_attempts()?;
        for attempt in reconnect_attempts {
            if snapshots.iter().any(|entry| {
                entry.peer == attempt.peer
                    && entry.protocol == attempt.protocol
                    && entry.class == attempt.class
            }) {
                continue;
            }
            let candidates = state.path_candidates_for(&attempt.peer);
            let selected = select_best_path(&candidates, attempt.class);
            let selected_candidate = selected.as_ref().map(|decision| &decision.selected);
            let (state_kind, state_reason, summary) =
                runtime_reconnect_path_status(&attempt, selected.as_ref());
            snapshots.push(RuntimePathSnapshot {
                session_id: None,
                peer: attempt.peer.clone(),
                protocol: attempt.protocol.clone(),
                class: attempt.class,
                state: state_kind,
                path_kind: selected_candidate.map(|candidate| candidate.path_kind),
                source: selected_candidate.map(|candidate| candidate.source.clone()),
                relay_peer: selected_candidate.and_then(|candidate| candidate.relay_peer.clone()),
                endpoint_summary: selected_candidate
                    .map(runtime_candidate_endpoint_summary)
                    .unwrap_or_else(|| "no known runtime candidate path".to_string()),
                state_reason,
                decision_reason: selected
                    .as_ref()
                    .map(|decision| runtime_path_decision_reason(&decision.explanation)),
                score: selected_candidate.map(|candidate| candidate.score(attempt.class)),
                summary,
                alternatives: runtime_path_alternatives(
                    &candidates,
                    attempt.class,
                    selected_candidate,
                ),
            });
        }

        let path_classes = [
            TrafficClass::Control,
            TrafficClass::Interactive,
            TrafficClass::Bulk,
            TrafficClass::Background,
        ];
        for peer in state.peers.iter().map(|entry| entry.snapshot.peer.clone()) {
            let candidates = state.path_candidates_for(&peer);
            if candidates.is_empty() {
                continue;
            }
            for class in path_classes {
                if snapshots
                    .iter()
                    .any(|entry| entry.peer == peer && entry.class == class)
                {
                    continue;
                }
                let selected = select_best_path(&candidates, class);
                let Some(selected) = selected else {
                    continue;
                };
                let selected_candidate = &selected.selected;
                snapshots.push(RuntimePathSnapshot {
                    session_id: None,
                    peer: peer.clone(),
                    protocol: None,
                    class,
                    state: RuntimePathState::Candidate,
                    path_kind: Some(selected_candidate.path_kind),
                    source: Some(selected_candidate.source.clone()),
                    relay_peer: selected_candidate.relay_peer.clone(),
                    endpoint_summary: runtime_candidate_endpoint_summary(selected_candidate),
                    state_reason: Some("known candidate path is not currently active".to_string()),
                    decision_reason: Some(runtime_path_decision_reason(&selected.explanation)),
                    score: Some(selected_candidate.score(class)),
                    summary: format!(
                        "candidate path available for {}: {}",
                        peer, selected.explanation.summary
                    ),
                    alternatives: runtime_path_alternatives(
                        &candidates,
                        class,
                        Some(selected_candidate),
                    ),
                });
            }
        }

        snapshots.sort_by(|left, right| {
            left.peer
                .to_string()
                .cmp(&right.peer.to_string())
                .then(runtime_class_rank(left.class).cmp(&runtime_class_rank(right.class)))
                .then(
                    runtime_path_state_rank(&left.state)
                        .cmp(&runtime_path_state_rank(&right.state)),
                )
                .then(left.session_id.cmp(&right.session_id))
        });
        Ok(snapshots)
    }

    pub fn runtime_listeners<T>(
        &self,
        transport: &T,
    ) -> Result<Vec<RuntimeListenerSnapshot>, DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        let state = self.ensure_state()?;
        let local_policy_reason = if state.membership.subject_peer_id != state.local_peer_id {
            Some(format!(
                "authority subject {} does not match runtime identity {}",
                state.membership.subject_peer_id, state.local_peer_id
            ))
        } else {
            state.deny_reason(&state.local_peer_id).map(str::to_string)
        };
        let mut listeners = transport.active_listeners()?;
        for listener in &mut listeners {
            if listener.state == RuntimeListenerState::Failed {
                continue;
            }
            if let Some(reason) = local_policy_reason.clone() {
                listener.state = RuntimeListenerState::Suppressed;
                listener.state_reason = Some(reason);
                continue;
            }
            let decision = state.explain_local_protocol_policy(&listener.protocol);
            if !decision.allowed {
                listener.state = RuntimeListenerState::Suppressed;
                listener.state_reason = Some(decision.reason);
            } else if listener.state == RuntimeListenerState::Suppressed {
                listener.state = RuntimeListenerState::Active;
                listener.state_reason = None;
            }
        }
        Ok(listeners)
    }

    pub fn runtime_health<T>(&self, transport: &T) -> Result<RuntimeHealthReport, DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        let state = self.ensure_state()?;
        let transport_health = transport.transport_health()?;
        let active_listeners = self
            .runtime_listeners(transport)?
            .into_iter()
            .filter(|listener| listener.state == RuntimeListenerState::Active)
            .count();
        let active_paths = self
            .runtime_paths(transport)?
            .into_iter()
            .filter(|path| path.session_id.is_some())
            .count();
        let authority_subject_mismatch = state.membership.subject_peer_id != state.local_peer_id;
        let authority_deny_reason = state.deny_reason(&state.local_peer_id).map(str::to_string);
        let authority_sync_health = if authority_subject_mismatch {
            RuntimeHealthLevel::Failed
        } else if authority_deny_reason.is_some() {
            RuntimeHealthLevel::Suppressed
        } else {
            RuntimeHealthLevel::Ready
        };
        let runtime_registry_health = if transport_health.session_registry_healthy
            && transport_health.listener_registry_healthy
        {
            RuntimeHealthLevel::Ready
        } else {
            RuntimeHealthLevel::Failed
        };
        let path_manager_health = if transport_health.active_sessions > 0 && active_paths == 0 {
            RuntimeHealthLevel::Failed
        } else if active_paths < transport_health.active_sessions {
            RuntimeHealthLevel::Degraded
        } else {
            RuntimeHealthLevel::Ready
        };
        let reconnect_subsystem_health =
            runtime_reconnect_health_level(&transport_health.reconnect_state);
        let daemon_readiness = runtime_rollup_health(&[
            authority_sync_health.clone(),
            runtime_registry_health.clone(),
            path_manager_health.clone(),
            reconnect_subsystem_health.clone(),
        ]);
        Ok(RuntimeHealthReport {
            daemon_readiness,
            authority_sync_health,
            runtime_registry_health,
            path_manager_health,
            reconnect_subsystem_health,
            authority_subject_status: if authority_subject_mismatch {
                "mismatched".to_string()
            } else {
                "matched".to_string()
            },
            authority_deny_reason,
            active_sessions: transport_health.active_sessions,
            active_paths,
            active_listeners,
            reconnect_state: transport_health.reconnect_state,
            reconnect_attempt_count: transport_health.reconnect_attempt_count,
            reconnect_next_attempt_unix_secs: transport_health.reconnect_next_attempt_unix_secs,
            reconnect_suppression_count: transport_health.reconnect_suppression_count,
            runtime_event_buffer_depth: transport_health.event_buffer_depth,
        })
    }

    pub async fn reevaluate_runtime_authority<T>(
        &self,
        runtime_identity: &IdentityKeypair,
        transport: &T,
    ) -> Result<AuthorityReevaluationReport, DaemonStateError>
    where
        T: SessionLifecycleTransport,
    {
        let state = self.ensure_state()?;
        let runtime_peer_id = runtime_identity.peer_id();
        let authority_subject_mismatch = state.membership.subject_peer_id != runtime_peer_id;
        let local_policy_reason = if authority_subject_mismatch {
            Some(format!(
                "authority subject {} does not match runtime identity {}",
                state.membership.subject_peer_id, runtime_peer_id
            ))
        } else {
            state.deny_reason(&state.local_peer_id).map(str::to_string)
        };
        transport.record_runtime_event(
            "authority.reevaluation_started",
            RuntimeEventSubject {
                kind: "authority".to_string(),
                id: runtime_peer_id.to_string(),
            },
            json!({
                "active_sessions": transport.active_sessions()?.len(),
                "authority_subject_peer_id": state.membership.subject_peer_id.to_string(),
                "runtime_peer_id": runtime_peer_id.to_string(),
                "authority_subject_mismatch": authority_subject_mismatch,
                "local_policy_reason": local_policy_reason.clone()
            }),
        )?;
        let sessions = transport.active_sessions()?;
        let local_policy_denied = local_policy_reason.is_some();
        let mut reevaluated_sessions = 0;
        let mut closed_sessions = 0;
        let mut degraded_sessions = 0;
        let mut migrated_sessions = 0;
        let mut unchanged_sessions = 0;
        let mut reevaluated_listeners = 0;
        let mut suppressed_listeners = 0;
        let mut restored_listeners = 0;
        let mut reconnect_suppressions_added = 0;
        let mut reconnect_suppressions_cleared = 0;
        let mut subject_mismatch_sessions = 0;
        let mut local_membership_denied_sessions = 0;
        let mut peer_membership_denied_sessions = 0;
        let mut capability_denied_sessions = 0;

        for session in sessions {
            let Some(protocol) = session.protocol.clone() else {
                continue;
            };
            reevaluated_sessions += 1;
            let policy = state.explain_policy(&session.peer, &protocol);
            let enforced = if let Some(reason) = local_policy_reason.clone() {
                Some(classify_authority_policy_enforcement(
                    AuthorityPolicyCause::if_subject_mismatch(
                        authority_subject_mismatch,
                        &session.peer,
                        &policy.reason,
                    )
                    .unwrap_or(AuthorityPolicyCause::LocalMembershipDenied),
                    reason,
                ))
            } else if !policy.allowed {
                Some(classify_authority_policy_enforcement(
                    classify_remote_policy_cause(&state, &session.peer, &policy.reason),
                    policy.reason.clone(),
                ))
            } else {
                None
            };
            if let Some(enforced) = enforced {
                transport.suppress_reconnect(
                    &session.peer,
                    Some(&protocol),
                    session.class,
                    enforced.reason.clone(),
                )?;
                reconnect_suppressions_added += 1;
                match enforced.cause {
                    AuthorityPolicyCause::SubjectMismatch => {
                        subject_mismatch_sessions += 1;
                    }
                    AuthorityPolicyCause::LocalMembershipDenied => {
                        local_membership_denied_sessions += 1;
                    }
                    AuthorityPolicyCause::PeerMembershipDenied => {
                        peer_membership_denied_sessions += 1;
                    }
                    AuthorityPolicyCause::CapabilityDenied => {
                        capability_denied_sessions += 1;
                    }
                }
                let _ = transport.update_session_state(
                    &session.session_id,
                    RuntimeSessionState::Closing,
                    Some(SessionClosureReason::PolicyRejected),
                    Some(enforced.reason.clone()),
                )?;
                transport.record_runtime_event(
                    "authority.policy_enforced",
                    RuntimeEventSubject {
                        kind: "session".to_string(),
                        id: hex_session_id(&session.session_id),
                    },
                    json!({
                        "peer_id": session.peer.to_string(),
                        "protocol": protocol.as_str(),
                        "class": format!("{:?}", session.class),
                        "action": "close_and_suppress_reconnect",
                        "cause": enforced.cause.label(),
                        "reason": enforced.reason,
                        "local_policy_denied": local_policy_denied,
                        "authority_subject_mismatch": authority_subject_mismatch
                    }),
                )?;
                transport.close_session(&session).await?;
                closed_sessions += 1;
            } else {
                let suppression_present = transport.reconnect_suppressions()?.iter().any(|entry| {
                    entry.peer == session.peer
                        && entry.protocol.as_ref() == Some(&protocol)
                        && entry.class == session.class
                });
                transport.clear_reconnect_suppression(
                    &session.peer,
                    Some(&protocol),
                    session.class,
                )?;
                if suppression_present {
                    reconnect_suppressions_cleared += 1;
                }
                match state.route_plan(&session.peer, Some(protocol.clone()), session.class) {
                    Ok(route) if session_matches_route(&session, &route) => {
                        if session.state == RuntimeSessionState::Degraded {
                            let _ = transport.update_session_state(
                                &session.session_id,
                                RuntimeSessionState::Active,
                                None,
                                Some(
                                    "authority reevaluation restored the selected path posture"
                                        .to_string(),
                                ),
                            )?;
                        }
                        unchanged_sessions += 1;
                    }
                    Ok(route) => {
                        if session.migration_capable {
                            transport.record_runtime_event(
                                "path.migration_started",
                                RuntimeEventSubject {
                                    kind: "session".to_string(),
                                    id: hex_session_id(&session.session_id),
                                },
                                json!({
                                    "peer_id": session.peer.to_string(),
                                    "protocol": protocol.as_str(),
                                    "class": format!("{:?}", session.class),
                                    "reason": "authority reevaluation selected a different eligible path"
                                }),
                            )?;
                            let _ = transport.update_session_state(
                                &session.session_id,
                                RuntimeSessionState::Migrating,
                                None,
                                Some(
                                    "authority reevaluation selected a different eligible path"
                                        .to_string(),
                                ),
                            )?;
                            let _ = transport.migrate(&session, route).await?;
                            migrated_sessions += 1;
                        } else {
                            let reason = "authority reevaluation selected a different eligible path but the active session cannot migrate".to_string();
                            let _ = transport.update_session_state(
                                &session.session_id,
                                RuntimeSessionState::Degraded,
                                None,
                                Some(reason.clone()),
                            )?;
                            transport.record_runtime_event(
                                "path.degraded",
                                RuntimeEventSubject {
                                    kind: "session".to_string(),
                                    id: hex_session_id(&session.session_id),
                                },
                                json!({
                                    "peer_id": session.peer.to_string(),
                                    "protocol": protocol.as_str(),
                                    "class": format!("{:?}", session.class),
                                    "reason": reason
                                }),
                            )?;
                            degraded_sessions += 1;
                        }
                    }
                    Err(DaemonStateError::NoRoute(_)) => {
                        let reason = "authority reevaluation found no eligible replacement path; keeping the current session alive in degraded posture".to_string();
                        let _ = transport.update_session_state(
                            &session.session_id,
                            RuntimeSessionState::Degraded,
                            None,
                            Some(reason.clone()),
                        )?;
                        transport.record_runtime_event(
                            "path.degraded",
                            RuntimeEventSubject {
                                kind: "session".to_string(),
                                id: hex_session_id(&session.session_id),
                            },
                            json!({
                                "peer_id": session.peer.to_string(),
                                "protocol": protocol.as_str(),
                                "class": format!("{:?}", session.class),
                                "reason": reason
                            }),
                        )?;
                        degraded_sessions += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        for listener in transport.active_listeners()? {
            reevaluated_listeners += 1;
            if listener.state == RuntimeListenerState::Failed {
                continue;
            }
            let enforced_reason = local_policy_reason.clone().or_else(|| {
                let decision = state.explain_local_protocol_policy(&listener.protocol);
                if decision.allowed {
                    None
                } else {
                    Some(decision.reason)
                }
            });
            if let Some(reason) = enforced_reason {
                let was_suppressed = listener.state == RuntimeListenerState::Suppressed
                    && listener.state_reason.as_deref() == Some(reason.as_str());
                let _ = transport.update_listener_state(
                    &listener.listener_id,
                    RuntimeListenerState::Suppressed,
                    Some(reason.clone()),
                )?;
                if !was_suppressed {
                    suppressed_listeners += 1;
                    transport.record_runtime_event(
                        "authority.policy_enforced",
                        RuntimeEventSubject {
                            kind: "listener".to_string(),
                            id: listener.listener_id.clone(),
                        },
                        json!({
                            "listener_id": listener.listener_id,
                            "protocol": listener.protocol.as_str(),
                            "action": "suppress_listener",
                            "reason": reason,
                            "local_policy_denied": local_policy_denied,
                            "authority_subject_mismatch": authority_subject_mismatch
                        }),
                    )?;
                }
            } else if listener.state == RuntimeListenerState::Suppressed {
                let _ = transport.update_listener_state(
                    &listener.listener_id,
                    RuntimeListenerState::Active,
                    None,
                )?;
                restored_listeners += 1;
            }
        }

        let report = AuthorityReevaluationReport {
            reevaluated_sessions,
            closed_sessions,
            degraded_sessions,
            migrated_sessions,
            unchanged_sessions,
            reevaluated_listeners,
            suppressed_listeners,
            restored_listeners,
            reconnect_suppressions_added,
            reconnect_suppressions_cleared,
            local_policy_denied,
            authority_subject_mismatch,
            subject_mismatch_sessions,
            local_membership_denied_sessions,
            peer_membership_denied_sessions,
            capability_denied_sessions,
            local_policy_reason: local_policy_reason.clone(),
        };
        transport.record_runtime_event(
            "authority.reevaluation_completed",
            RuntimeEventSubject {
                kind: "authority".to_string(),
                id: runtime_peer_id.to_string(),
            },
            json!({
                "reevaluated_sessions": report.reevaluated_sessions,
                "closed_sessions": report.closed_sessions,
                "degraded_sessions": report.degraded_sessions,
                "migrated_sessions": report.migrated_sessions,
                "unchanged_sessions": report.unchanged_sessions,
                "reevaluated_listeners": report.reevaluated_listeners,
                "suppressed_listeners": report.suppressed_listeners,
                "restored_listeners": report.restored_listeners,
                "reconnect_suppressions_added": report.reconnect_suppressions_added,
                "reconnect_suppressions_cleared": report.reconnect_suppressions_cleared,
                "local_policy_denied": report.local_policy_denied,
                "authority_subject_mismatch": report.authority_subject_mismatch,
                "subject_mismatch_sessions": report.subject_mismatch_sessions,
                "local_membership_denied_sessions": report.local_membership_denied_sessions,
                "peer_membership_denied_sessions": report.peer_membership_denied_sessions,
                "capability_denied_sessions": report.capability_denied_sessions,
                "local_policy_reason": report.local_policy_reason
            }),
        )?;
        Ok(report)
    }

    pub fn explain_policy(
        &self,
        peer: &PeerId,
        protocol: &ProtocolId,
    ) -> Result<Decision, DaemonStateError> {
        let state = self.ensure_state()?;
        Ok(state.explain_policy(peer, protocol))
    }
}

fn load_authority_snapshot(
    snapshot_path: impl AsRef<Path>,
) -> Result<AuthorityArtifactSnapshot, DaemonStateError> {
    Ok(serde_json::from_slice::<AuthorityArtifactSnapshot>(
        &fs::read(snapshot_path.as_ref())?,
    )?)
}

fn authority_client(network: &str, origin: &str) -> ControlClient {
    ControlClient::from_origin(NetworkId::derive(network), origin)
}

fn self_identity_daemon_state(
    network: &str,
    roles: Vec<DaemonRole>,
    local_identity: &IdentityKeypair,
) -> DaemonState {
    let mut state = fixture_daemon_state(network);
    let local_peer_id = local_identity.peer_id();
    state.roles = roles;
    state.local_peer_id = local_peer_id.clone();
    state.membership = MembershipCertificate::issue(
        local_identity,
        NetworkId::derive(network),
        local_peer_id,
        1_720_000_000,
        1_820_000_000,
        vec!["member".to_string()],
    );
    state.denied_peers = denied_peers(&state.membership, &state.revocations);
    state.path_candidates = merged_path_candidates(&state);
    state
}

fn hex_session_id(session_id: &[u8; 16]) -> String {
    session_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthorityPolicyCause {
    SubjectMismatch,
    LocalMembershipDenied,
    PeerMembershipDenied,
    CapabilityDenied,
}

impl AuthorityPolicyCause {
    fn if_subject_mismatch(mismatch: bool, _peer: &PeerId, _policy_reason: &str) -> Option<Self> {
        if mismatch {
            Some(Self::SubjectMismatch)
        } else {
            None
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::SubjectMismatch => "subject_mismatch",
            Self::LocalMembershipDenied => "local_membership_denied",
            Self::PeerMembershipDenied => "peer_membership_denied",
            Self::CapabilityDenied => "capability_denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorityPolicyEnforcement {
    cause: AuthorityPolicyCause,
    reason: String,
}

fn classify_authority_policy_enforcement(
    cause: AuthorityPolicyCause,
    reason: String,
) -> AuthorityPolicyEnforcement {
    AuthorityPolicyEnforcement { cause, reason }
}

fn classify_remote_policy_cause(
    state: &DaemonState,
    peer: &PeerId,
    reason: &str,
) -> AuthorityPolicyCause {
    if state.deny_reason(peer).is_some() || reason.contains("revoked") || reason.contains("denied")
    {
        AuthorityPolicyCause::PeerMembershipDenied
    } else {
        AuthorityPolicyCause::CapabilityDenied
    }
}

fn session_matches_route(session: &SessionSnapshot, route: &RoutePlan) -> bool {
    if session.path_kind != route.path_kind || session.class != route.class {
        return false;
    }
    if session.protocol != route.protocol {
        return false;
    }

    let Some(remote_endpoint) = route.remote_endpoints.first() else {
        return false;
    };
    if session.remote_endpoint != *remote_endpoint {
        return false;
    }

    match (&session.relay_peer, &route.relay) {
        (None, None) => true,
        (Some(peer), Some(relay)) => {
            session.relay_control_endpoint.as_deref() == Some(relay.relay_control_endpoint.as_str())
                && peer == &relay.relay_peer
                && session.relay_endpoint.as_deref()
                    == relay.relay_endpoints.first().map(String::as_str)
        }
        _ => false,
    }
}

fn bootstrap_protocols(metadata: &BTreeMap<String, String>) -> Vec<String> {
    metadata
        .get("protocols")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| {
            vec![
                "/quicnet/control/1".to_string(),
                "/quicnet/records/1".to_string(),
            ]
        })
}

fn bootstrap_endpoint_from_hint(hint: membership::BootstrapHint) -> BootstrapEndpoint {
    BootstrapEndpoint {
        peer: hint.peer_id,
        addresses: hint.addresses,
        protocols: bootstrap_protocols(&hint.metadata),
        metadata: hint.metadata,
    }
}

fn bootstrap_peers(endpoints: &[BootstrapEndpoint]) -> Vec<PeerInspection> {
    let mut store = PeerStore::default();

    for endpoint in endpoints {
        let Some(peer) = endpoint.peer.clone() else {
            continue;
        };
        store.upsert_peer_with_status(
            PeerSnapshot {
                peer,
                protocols: endpoint.protocols.clone(),
                addresses: endpoint.addresses.clone(),
            },
            PeerStatus {
                source: PeerSource::Bootstrap,
                reachability: PeerReachability::Unknown,
                last_seen_unix_secs: None,
            },
        );
    }

    store.peers()
}

fn merge_bootstrap_peers(
    existing: &[PeerInspection],
    bootstrap: &[BootstrapEndpoint],
) -> Vec<PeerInspection> {
    let mut store = PeerStore::default();

    for peer in existing {
        store.upsert_peer_with_status(peer.snapshot.clone(), peer.status.clone());
    }

    for endpoint in bootstrap {
        let Some(peer) = endpoint.peer.clone() else {
            continue;
        };
        let snapshot = PeerSnapshot {
            peer: peer.clone(),
            protocols: endpoint.protocols.clone(),
            addresses: endpoint.addresses.clone(),
        };
        let status = store.peer_status(&peer).cloned().unwrap_or(PeerStatus {
            source: PeerSource::Bootstrap,
            reachability: PeerReachability::Unknown,
            last_seen_unix_secs: None,
        });
        store.upsert_peer_with_status(snapshot, status);
    }

    store.peers()
}

fn relay_peers(relay_map: &RelayMap) -> Vec<PeerInspection> {
    let mut store = PeerStore::default();

    for relay in &relay_map.relays {
        store.upsert_peer_with_status(
            PeerSnapshot {
                peer: relay.peer_id.clone(),
                protocols: vec!["/quicnet/relay/1".to_string()],
                addresses: relay.advertised_endpoints.clone(),
            },
            PeerStatus {
                source: PeerSource::RelayMap,
                reachability: PeerReachability::Unknown,
                last_seen_unix_secs: Some(relay_map.generated_at),
            },
        );
    }

    store.peers()
}

fn merge_relay_peers(
    existing: &[PeerInspection],
    relays: &[PeerInspection],
) -> Vec<PeerInspection> {
    let mut store = PeerStore::default();

    for peer in existing {
        store.upsert_peer_with_status(peer.snapshot.clone(), peer.status.clone());
    }

    for relay in relays {
        let peer_id = relay.snapshot.peer.clone();
        let status = store.peer_status(&peer_id).cloned().unwrap_or(PeerStatus {
            source: PeerSource::RelayMap,
            reachability: PeerReachability::Unknown,
            last_seen_unix_secs: relay.status.last_seen_unix_secs,
        });
        store.upsert_peer_with_status(relay.snapshot.clone(), status);
    }

    store.peers()
}

fn merged_path_candidates(state: &DaemonState) -> Vec<PathCandidate> {
    let mut candidates = state
        .path_candidates
        .iter()
        .filter(|candidate| candidate.source == PathSource::Observed)
        .cloned()
        .collect::<Vec<_>>();

    for candidate in synthesized_direct_bootstrap_candidates(state) {
        push_unique_candidate(&mut candidates, candidate);
    }
    for candidate in synthesized_relay_candidates(state) {
        push_unique_candidate(&mut candidates, candidate);
    }

    candidates
}

fn runtime_path_state_from_session(state: &RuntimeSessionState) -> RuntimePathState {
    match state {
        RuntimeSessionState::Degraded => RuntimePathState::Degraded,
        RuntimeSessionState::Migrating => RuntimePathState::Migrating,
        RuntimeSessionState::Failed
        | RuntimeSessionState::Closing
        | RuntimeSessionState::Closed => RuntimePathState::Failed,
        _ => RuntimePathState::Active,
    }
}

fn runtime_candidate_matches_session(candidate: &PathCandidate, session: &SessionSnapshot) -> bool {
    candidate.peer == session.peer
        && candidate.path_kind == session.path_kind
        && candidate.relay_peer == session.relay_peer
        && candidate.supports_class(session.class)
}

fn runtime_path_alternatives(
    candidates: &[PathCandidate],
    class: TrafficClass,
    selected: Option<&PathCandidate>,
) -> Vec<RuntimePathAlternative> {
    let mut alternatives = candidates
        .iter()
        .filter(|candidate| candidate.supports_class(class))
        .filter(|candidate| Some(*candidate) != selected)
        .cloned()
        .collect::<Vec<_>>();
    alternatives.sort_by_key(|candidate| candidate.score(class));
    alternatives
        .into_iter()
        .map(|candidate| RuntimePathAlternative {
            path_kind: candidate.path_kind,
            source: candidate.source.clone(),
            relay_peer: candidate.relay_peer.clone(),
            score: candidate.score(class),
            summary: candidate.explain(class).summary,
        })
        .collect()
}

fn route_source_to_path_source(source: &RouteSource) -> Option<PathSource> {
    Some(match source {
        RouteSource::Observed => PathSource::Observed,
        RouteSource::Bootstrap => PathSource::Bootstrap,
        RouteSource::AuthorityRelay => PathSource::AuthorityRelay,
    })
}

fn runtime_session_endpoint_summary(session: &SessionSnapshot) -> String {
    if session.path_kind == PathKind::Relay {
        format!(
            "relay={} destination={}",
            session
                .relay_endpoint
                .as_deref()
                .unwrap_or("unknown-relay-endpoint"),
            session.remote_endpoint
        )
    } else {
        session.remote_endpoint.clone()
    }
}

fn runtime_candidate_endpoint_summary(candidate: &PathCandidate) -> String {
    match candidate.path_kind {
        PathKind::Relay => format!(
            "relay={}",
            candidate
                .relay_peer
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown-relay".to_string())
        ),
        _ => "direct".to_string(),
    }
}

fn runtime_session_summary(session: &SessionSnapshot) -> String {
    format!(
        "{} runtime path for {} is {}",
        match session.path_kind {
            PathKind::Relay => "relay",
            _ => "direct",
        },
        session.peer,
        runtime_session_endpoint_summary(session)
    )
}

fn runtime_reconnect_path_status(
    attempt: &RuntimeReconnectAttempt,
    selected: Option<&PathDecision>,
) -> (RuntimePathState, Option<String>, String) {
    let selected_summary = selected
        .map(|decision| decision.explanation.summary.clone())
        .unwrap_or_else(|| "no known runtime candidate path remains".to_string());
    let fallback_summary = selected
        .map(|decision| match decision.selected.path_kind {
            PathKind::Relay => {
                format!(
                    "best known relay fallback remains {}",
                    decision.explanation.summary
                )
            }
            _ => format!(
                "best known direct path remains {}",
                decision.explanation.summary
            ),
        })
        .unwrap_or_else(|| "no known runtime candidate path remains".to_string());
    match attempt.state {
        RuntimeReconnectAttemptState::BackingOff => (
            RuntimePathState::Candidate,
            Some(format!(
                "attempt {}/{} backing off until {} because {}",
                attempt.attempt_count,
                attempt.max_attempts,
                attempt.next_attempt_unix_secs,
                attempt.reason
            )),
            format!(
                "reconnect backing off for {} after {}/{} attempts; {}",
                attempt.peer, attempt.attempt_count, attempt.max_attempts, selected_summary
            ),
        ),
        RuntimeReconnectAttemptState::Failed => (
            RuntimePathState::Failed,
            Some(format!(
                "reconnect exhausted {}/{} attempts because {}",
                attempt.attempt_count, attempt.max_attempts, attempt.reason
            )),
            format!(
                "reconnect failed for {} after {}/{} attempts; {}",
                attempt.peer, attempt.attempt_count, attempt.max_attempts, fallback_summary
            ),
        ),
    }
}

fn runtime_path_decision_reason(explanation: &PathExplanation) -> String {
    match (
        explanation.strengths.is_empty(),
        explanation.tradeoffs.is_empty(),
    ) {
        (false, false) => format!(
            "strengths={} tradeoffs={}",
            explanation.strengths.join("|"),
            explanation.tradeoffs.join("|")
        ),
        (false, true) => format!("strengths={}", explanation.strengths.join("|")),
        (true, false) => format!("tradeoffs={}", explanation.tradeoffs.join("|")),
        (true, true) => explanation.summary.clone(),
    }
}

fn runtime_class_rank(class: TrafficClass) -> u8 {
    match class {
        TrafficClass::Control => 0,
        TrafficClass::Interactive => 1,
        TrafficClass::Bulk => 2,
        TrafficClass::Background => 3,
    }
}

fn runtime_path_state_rank(state: &RuntimePathState) -> u8 {
    match state {
        RuntimePathState::Active => 0,
        RuntimePathState::Migrating => 1,
        RuntimePathState::Degraded => 2,
        RuntimePathState::Candidate => 3,
        RuntimePathState::Suppressed => 4,
        RuntimePathState::Failed => 5,
    }
}

fn runtime_reconnect_health_level(state: &RuntimeReconnectState) -> RuntimeHealthLevel {
    match state {
        RuntimeReconnectState::Idle => RuntimeHealthLevel::Ready,
        RuntimeReconnectState::Active => RuntimeHealthLevel::Degraded,
        RuntimeReconnectState::Suppressed => RuntimeHealthLevel::Suppressed,
        RuntimeReconnectState::Failed => RuntimeHealthLevel::Failed,
    }
}

fn runtime_rollup_health(levels: &[RuntimeHealthLevel]) -> RuntimeHealthLevel {
    if levels
        .iter()
        .any(|level| *level == RuntimeHealthLevel::Failed)
    {
        RuntimeHealthLevel::Failed
    } else if levels
        .iter()
        .any(|level| *level == RuntimeHealthLevel::Suppressed)
    {
        RuntimeHealthLevel::Suppressed
    } else if levels
        .iter()
        .any(|level| *level == RuntimeHealthLevel::Degraded)
    {
        RuntimeHealthLevel::Degraded
    } else {
        RuntimeHealthLevel::Ready
    }
}

fn push_unique_candidate(candidates: &mut Vec<PathCandidate>, candidate: PathCandidate) {
    let exists = candidates.iter().any(|existing| {
        existing.peer == candidate.peer
            && existing.path_kind == candidate.path_kind
            && existing.relay_peer == candidate.relay_peer
            && existing.source == candidate.source
    });
    if !exists {
        candidates.push(candidate);
    }
}

fn synthesized_direct_bootstrap_candidates(state: &DaemonState) -> Vec<PathCandidate> {
    if !state.netcheck.udp_reachable && !state.netcheck.ipv6_reachable {
        return Vec::new();
    }
    state
        .bootstrap
        .iter()
        .filter(|endpoint| endpoint.peer.is_some())
        .filter(|endpoint| {
            endpoint
                .addresses
                .iter()
                .any(|address| is_direct_quic_address(address))
        })
        .filter_map(|endpoint| {
            let peer = endpoint.peer.clone()?;
            Some(PathCandidate {
                peer,
                path_kind: endpoint_path_kind(endpoint),
                relay_peer: None,
                source: PathSource::Bootstrap,
                traffic_classes: vec![
                    TrafficClass::Control,
                    TrafficClass::Interactive,
                    TrafficClass::Bulk,
                    TrafficClass::Background,
                ],
                rtt_ms: direct_bootstrap_rtt_ms(&state.netcheck),
                jitter_ms: direct_bootstrap_jitter_ms(&state.netcheck),
                loss_pct: direct_bootstrap_loss_pct(&state.netcheck),
                throughput_mbps: direct_bootstrap_throughput_mbps(&state.netcheck),
                relay_penalty: 0,
            })
        })
        .collect()
}

fn synthesized_relay_candidates(state: &DaemonState) -> Vec<PathCandidate> {
    let Some(relay_map) = &state.relay_map else {
        return Vec::new();
    };
    let relay_peer_ids = relay_map
        .relays
        .iter()
        .map(|relay| relay.peer_id.clone())
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();

    for relay in &relay_map.relays {
        candidates.push(PathCandidate {
            peer: relay.peer_id.clone(),
            path_kind: relay_path_kind(relay),
            relay_peer: None,
            source: PathSource::AuthorityRelay,
            traffic_classes: relay_traffic_classes(&relay.traffic_classes),
            rtt_ms: direct_relay_rtt_ms(relay, &state.netcheck),
            jitter_ms: direct_relay_jitter_ms(&state.netcheck),
            loss_pct: direct_relay_loss_pct(&state.netcheck),
            throughput_mbps: relay_direct_throughput_mbps(relay),
            relay_penalty: 0,
        });
    }

    for peer in &state.peers {
        if relay_peer_ids.contains(&peer.snapshot.peer) {
            continue;
        }
        for relay in &relay_map.relays {
            candidates.push(PathCandidate {
                peer: peer.snapshot.peer.clone(),
                path_kind: PathKind::Relay,
                relay_peer: Some(relay.peer_id.clone()),
                source: PathSource::AuthorityRelay,
                traffic_classes: relay_traffic_classes(&relay.traffic_classes),
                rtt_ms: relay_fallback_rtt_ms(relay, &state.netcheck),
                jitter_ms: relay_fallback_jitter_ms(&state.netcheck),
                loss_pct: relay_fallback_loss_pct(&state.netcheck),
                throughput_mbps: relay_fallback_throughput_mbps(relay),
                relay_penalty: 25,
            });
        }
    }

    candidates
}

fn endpoint_path_kind(endpoint: &BootstrapEndpoint) -> PathKind {
    if endpoint
        .addresses
        .iter()
        .any(|address| is_ipv6_address(address))
    {
        PathKind::DirectIpv6
    } else {
        PathKind::DirectUdp
    }
}

fn relay_path_kind(relay: &RelayAnnouncement) -> PathKind {
    if relay
        .advertised_endpoints
        .iter()
        .any(|address| is_ipv6_address(address))
    {
        PathKind::DirectIpv6
    } else {
        PathKind::DirectUdp
    }
}

fn route_source(source: &PathSource) -> RouteSource {
    match source {
        PathSource::Observed => RouteSource::Observed,
        PathSource::Bootstrap => RouteSource::Bootstrap,
        PathSource::AuthorityRelay => RouteSource::AuthorityRelay,
    }
}

fn route_endpoints(addresses: &[String], path_kind: PathKind) -> Vec<String> {
    let filtered = addresses
        .iter()
        .filter(|address| endpoint_matches_path_kind(address, path_kind))
        .cloned()
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        addresses.to_vec()
    } else {
        filtered
    }
}

fn endpoint_matches_path_kind(address: &str, path_kind: PathKind) -> bool {
    match path_kind {
        PathKind::DirectIpv6 => is_direct_quic_address(address) && is_ipv6_address(address),
        PathKind::DirectUdp => is_direct_quic_address(address) && !is_ipv6_address(address),
        PathKind::Relay => is_direct_quic_address(address),
        PathKind::Loopback => address.contains("127.0.0.1") || address.contains("://[::1]"),
        PathKind::Lan => {
            address.contains("192.168.") || address.contains("10.") || address.contains("172.16.")
        }
    }
}

fn is_direct_quic_address(address: &str) -> bool {
    address.starts_with("quic://") || address.starts_with("udp://")
}

fn is_ipv6_address(address: &str) -> bool {
    address.contains("://[") || address.matches(':').count() > 2
}

fn best_probe_latency_ms(netcheck: &NetcheckReport) -> Option<u32> {
    netcheck
        .probe_observations
        .iter()
        .filter(|observation| observation.status == ProbeStatus::Passed)
        .filter_map(|observation| observation.latency_ms)
        .min()
}

fn direct_bootstrap_rtt_ms(netcheck: &NetcheckReport) -> u32 {
    best_probe_latency_ms(netcheck).unwrap_or(40)
}

fn direct_bootstrap_jitter_ms(netcheck: &NetcheckReport) -> u32 {
    if netcheck.udp_reachable {
        3
    } else {
        12
    }
}

fn direct_bootstrap_loss_pct(netcheck: &NetcheckReport) -> f32 {
    if netcheck.udp_reachable {
        0.2
    } else {
        1.5
    }
}

fn direct_bootstrap_throughput_mbps(netcheck: &NetcheckReport) -> u32 {
    if netcheck.udp_reachable {
        600
    } else {
        120
    }
}

fn direct_relay_rtt_ms(relay: &RelayAnnouncement, netcheck: &NetcheckReport) -> u32 {
    let base =
        best_probe_latency_ms(netcheck).unwrap_or(if netcheck.udp_reachable { 30 } else { 70 });
    if relay_path_kind(relay) == PathKind::DirectIpv6 && netcheck.ipv6_reachable {
        base.saturating_add(5)
    } else {
        base.saturating_add(15)
    }
}

fn direct_relay_jitter_ms(netcheck: &NetcheckReport) -> u32 {
    if netcheck.udp_reachable {
        4
    } else {
        14
    }
}

fn direct_relay_loss_pct(netcheck: &NetcheckReport) -> f32 {
    if netcheck.udp_reachable {
        0.3
    } else {
        1.8
    }
}

fn relay_direct_throughput_mbps(relay: &RelayAnnouncement) -> u32 {
    (relay.max_bandwidth_bps / 1_000_000).clamp(100, 5_000) as u32
}

fn relay_fallback_rtt_ms(relay: &RelayAnnouncement, netcheck: &NetcheckReport) -> u32 {
    direct_relay_rtt_ms(relay, netcheck)
        .saturating_mul(2)
        .saturating_add(20)
}

fn relay_fallback_jitter_ms(netcheck: &NetcheckReport) -> u32 {
    direct_relay_jitter_ms(netcheck).saturating_add(5)
}

fn relay_fallback_loss_pct(netcheck: &NetcheckReport) -> f32 {
    direct_relay_loss_pct(netcheck) + 0.4
}

fn relay_fallback_throughput_mbps(relay: &RelayAnnouncement) -> u32 {
    (relay_direct_throughput_mbps(relay) / 2).max(80)
}

fn reprobe_netcheck(state: &DaemonState, reason: &str) -> NetcheckReport {
    let mut netcheck = state.netcheck.clone();

    if netcheck.port_mapped || netcheck.public_udp_addr.is_some() {
        netcheck.udp_reachable = true;
        if matches!(netcheck.nat_type, NatType::Unknown | NatType::UdpBlocked) {
            netcheck.nat_type = NatType::RestrictedCone;
        }
    }

    if netcheck
        .public_udp_addr
        .as_deref()
        .is_some_and(is_ipv6_address)
    {
        netcheck.ipv6_reachable = true;
    }

    let status = if netcheck.udp_reachable || netcheck.ipv6_reachable {
        ProbeStatus::Passed
    } else {
        ProbeStatus::Failed
    };
    let latency_ms = if status == ProbeStatus::Passed {
        best_probe_latency_ms(&netcheck).or(Some(20))
    } else {
        None
    };
    netcheck.probe_observations.push(ProbeObservation {
        vantage: "local-runtime".to_string(),
        status,
        latency_ms,
        detail: format!("network change reprobe: {reason}"),
    });
    if netcheck.probe_observations.len() > 8 {
        let drop_count = netcheck.probe_observations.len() - 8;
        netcheck.probe_observations.drain(0..drop_count);
    }

    netcheck
}

fn relay_traffic_classes(values: &[String]) -> Vec<TrafficClass> {
    let mut classes = values
        .iter()
        .filter_map(|value| match value.as_str() {
            "NetworkControl" => Some(TrafficClass::Control),
            "InteractiveRpc" => Some(TrafficClass::Interactive),
            "Background" => Some(TrafficClass::Background),
            "Bulk" => Some(TrafficClass::Bulk),
            _ => None,
        })
        .collect::<Vec<_>>();
    if classes.is_empty() {
        classes = vec![TrafficClass::Control, TrafficClass::Interactive];
    }
    classes
}

fn pending_netcheck() -> NetcheckReport {
    NetcheckReport {
        nat_type: NatType::Unknown,
        udp_reachable: false,
        ipv6_reachable: false,
        hairpin_supported: false,
        public_udp_addr: None,
        port_mapped: false,
        probe_observations: vec![ProbeObservation {
            vantage: "local".to_string(),
            status: ProbeStatus::Pending,
            latency_ms: None,
            detail: "netcheck has not run yet".to_string(),
        }],
    }
}

fn denied_peers(
    membership: &MembershipCertificate,
    revocations: &[RevocationRecord],
) -> Vec<DeniedPeer> {
    revocations
        .iter()
        .filter_map(|revocation| match &revocation.target {
            RevocationTarget::Peer { peer_id } => Some(DeniedPeer {
                peer: peer_id.clone(),
                reason: format!(
                    "peer revoked: {:?} seq={} issuer={}",
                    revocation.reason, revocation.sequence, revocation.issuer_peer_id
                ),
            }),
            RevocationTarget::MembershipCertificate {
                subject_peer_id,
                issued_at,
            } if subject_peer_id == &membership.subject_peer_id
                && *issued_at == membership.issued_at =>
            {
                Some(DeniedPeer {
                    peer: subject_peer_id.clone(),
                    reason: format!(
                        "membership revoked: {:?} seq={} issuer={}",
                        revocation.reason, revocation.sequence, revocation.issuer_peer_id
                    ),
                })
            }
            _ => None,
        })
        .collect()
}

fn protocol_capability(protocol: &ProtocolId) -> String {
    match protocol.as_str() {
        "/quicnet/records/1" => "records.publish".to_string(),
        "/quicnet/control/1" => "control.access".to_string(),
        _ => format!("protocol:{}", protocol.as_str()),
    }
}

impl DaemonState {
    fn is_capability_revoked(&self, peer: &PeerId, sequence: u64) -> bool {
        self.revocations.iter().any(|revocation| {
            matches!(
                &revocation.target,
                RevocationTarget::CapabilityGrant {
                    subject_peer_id,
                    sequence: revoked_sequence,
                } if subject_peer_id == peer && *revoked_sequence == sequence
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use control::AuthorityArtifactSnapshot;
    use quic::QuicTransportAdapter;
    use relay::{
        clear_registry, register_relay, registered_session_count, InProcessRelayControl, RelayNode,
        RelayQuota, RelayService,
    };

    use super::*;

    fn unique_state_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}-{suffix}.json"))
    }

    fn relay_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("relay test lock")
    }

    async fn establish_persisted_relay_session(
        network: &str,
        state_path: &Path,
        authority_seed: u8,
        subject_seed: u8,
        relay_label: &'static [u8],
        bootstrap_label: &'static [u8],
    ) -> (
        LocalControlPlane,
        QuicTransportAdapter,
        SessionSnapshot,
        PeerId,
    ) {
        clear_registry();
        let relay_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, relay_label);
        let bootstrap_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, bootstrap_label);
        let authority = crypto::IdentityKeypair::from_secret_bytes([authority_seed; 32]);
        let subject = crypto::IdentityKeypair::from_secret_bytes([subject_seed; 32]);
        let protocol = ProtocolId::new("/quicnet/control/1").expect("protocol");
        let snapshot = AuthorityArtifactSnapshot {
            network_id: NetworkId::derive(network),
            enrollment_token: None,
            membership: Some(membership::MembershipCertificate::issue(
                &authority,
                NetworkId::derive(network),
                subject.peer_id(),
                100,
                200,
                vec!["member".to_string()],
            )),
            capability_grants: vec![membership::CapabilityGrant::issue(
                &authority,
                NetworkId::derive(network),
                subject.peer_id(),
                vec!["control.access".to_string()],
                vec![protocol.clone()],
                membership::ResourceLimits::default(),
                vec![],
                100,
                200,
                7,
            )],
            revocations: vec![],
            bootstrap_hints: vec![membership::BootstrapHint {
                peer_id: Some(bootstrap_peer.clone()),
                addresses: vec!["quic://198.51.100.77:8443".to_string()],
                metadata: BTreeMap::from([(
                    "protocols".to_string(),
                    "/quicnet/control/1".to_string(),
                )]),
            }],
        };
        let mut state =
            DaemonState::from_authority_snapshot(network, vec![DaemonRole::Edge], snapshot)
                .expect("state should build from snapshot");
        state.netcheck.udp_reachable = false;
        state.netcheck.ipv6_reachable = false;
        let relay_map = RelayMap {
            version: 1,
            generated_at: 1_720_555_000,
            relays: vec![RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.70:443".to_string()],
                control_endpoint: format!("inproc://{relay_peer}"),
                max_bandwidth_bps: 2_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            }],
        };
        let (state, _) = state.apply_relay_map(relay_map);
        state.save(state_path).expect("state should persist");
        register_relay(RelayService::new(RelayNode {
            announcement: RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.70:443".to_string()],
                control_endpoint: format!("inproc://{relay_peer}"),
                max_bandwidth_bps: 2_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            },
            quotas: vec![RelayQuota {
                peer: subject.peer_id(),
                max_bandwidth_bps: 100_000_000,
                max_concurrent_sessions: 2,
            }],
            destinations: vec![relay::RelayDestination {
                peer: bootstrap_peer.clone(),
                protocols: vec![protocol.clone()],
            }],
        }));
        let control = LocalControlPlane::new(DaemonConfig::new(network, state_path));
        let transport =
            QuicTransportAdapter::with_identity(NetworkId::derive(network), subject.clone())
                .with_relay_control(Arc::new(InProcessRelayControl));
        let session = control
            .realize_best_path(
                &bootstrap_peer,
                &protocol,
                TrafficClass::Control,
                &transport,
            )
            .await
            .expect("relay session should be accepted");

        (control, transport, session, relay_peer)
    }

    async fn establish_persisted_direct_session(
        network: &str,
        state_path: &Path,
        authority_seed: u8,
        subject_seed: u8,
        bootstrap_label: &'static [u8],
    ) -> (
        LocalControlPlane,
        QuicTransportAdapter,
        SessionSnapshot,
        PeerId,
    ) {
        let bootstrap_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, bootstrap_label);
        let authority = crypto::IdentityKeypair::from_secret_bytes([authority_seed; 32]);
        let subject = crypto::IdentityKeypair::from_secret_bytes([subject_seed; 32]);
        let protocol = ProtocolId::new("/quicnet/control/1").expect("protocol");
        let snapshot = AuthorityArtifactSnapshot {
            network_id: NetworkId::derive(network),
            enrollment_token: None,
            membership: Some(membership::MembershipCertificate::issue(
                &authority,
                NetworkId::derive(network),
                subject.peer_id(),
                100,
                200,
                vec!["member".to_string()],
            )),
            capability_grants: vec![membership::CapabilityGrant::issue(
                &authority,
                NetworkId::derive(network),
                subject.peer_id(),
                vec!["control.access".to_string()],
                vec![protocol.clone()],
                membership::ResourceLimits::default(),
                vec![],
                100,
                200,
                7,
            )],
            revocations: vec![],
            bootstrap_hints: vec![membership::BootstrapHint {
                peer_id: Some(bootstrap_peer.clone()),
                addresses: vec!["quic://198.51.100.77:8443".to_string()],
                metadata: BTreeMap::from([(
                    "protocols".to_string(),
                    "/quicnet/control/1".to_string(),
                )]),
            }],
        };
        let mut state =
            DaemonState::from_authority_snapshot(network, vec![DaemonRole::Edge], snapshot)
                .expect("state should build from snapshot");
        state.netcheck.udp_reachable = true;
        state.netcheck.ipv6_reachable = false;
        state.netcheck.public_udp_addr = Some("203.0.113.60:8443".to_string());
        state.save(state_path).expect("state should persist");
        let control = LocalControlPlane::new(DaemonConfig::new(network, state_path));
        let transport =
            QuicTransportAdapter::with_identity(NetworkId::derive(network), subject.clone());
        let session = control
            .realize_best_path(
                &bootstrap_peer,
                &protocol,
                TrafficClass::Control,
                &transport,
            )
            .await
            .expect("direct session should be accepted");

        (control, transport, session, bootstrap_peer)
    }

    #[test]
    fn fixture_state_exposes_best_path() {
        let state = fixture_daemon_state("dev");
        let peer = state
            .path_candidates
            .first()
            .expect("fixture routing candidate should exist")
            .peer
            .clone();
        let decision = state
            .best_path(&peer, TrafficClass::Interactive)
            .expect("routing should be selected");
        assert_eq!(decision.selected.path_kind, PathKind::DirectIpv6);
    }

    #[test]
    fn fixture_state_builds_direct_route_plan() {
        let state = fixture_daemon_state("dev");
        let peer = state
            .path_candidates
            .first()
            .expect("fixture routing candidate should exist")
            .peer
            .clone();
        let protocol = ProtocolId::new("/quicnet/control/1").expect("protocol");

        let route = state
            .route_plan(&peer, Some(protocol.clone()), TrafficClass::Interactive)
            .expect("route plan should build");

        assert_eq!(route.peer, peer);
        assert_eq!(route.protocol, Some(protocol));
        assert!(matches!(
            route.source,
            RouteSource::Observed | RouteSource::Bootstrap | RouteSource::AuthorityRelay
        ));
        assert!(route.relay.is_none());
        assert!(!route.remote_endpoints.is_empty());
    }

    #[test]
    fn control_plane_persists_state() {
        let temp = std::env::temp_dir().join("quicnet-fabric-state.json");
        let control = LocalControlPlane::new(DaemonConfig::new("dev", &temp));
        let state = control.ensure_state().expect("state should be created");
        assert_eq!(state.network, "dev");
        assert_eq!(state.schema_version, DAEMON_STATE_SCHEMA_VERSION);

        let loaded = DaemonState::load(&temp).expect("state should be readable");
        assert_eq!(loaded.network, "dev");
        assert_eq!(loaded.schema_version, DAEMON_STATE_SCHEMA_VERSION);
        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn ensure_state_for_local_identity_bootstraps_matching_peer() {
        let temp = std::env::temp_dir().join("quicnet-fabric-bound-state.json");
        let control = LocalControlPlane::new(DaemonConfig::new("dev", &temp));
        let local_identity = crypto::IdentityKeypair::from_secret_bytes([88_u8; 32]);

        let state = control
            .ensure_state_for_local_identity(&local_identity)
            .expect("state should bootstrap from runtime identity");

        assert_eq!(state.local_peer_id, local_identity.peer_id());
        assert_eq!(state.membership.subject_peer_id, local_identity.peer_id());
        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn ensure_identity_bound_state_rejects_mismatched_runtime_identity() {
        let temp = std::env::temp_dir().join("quicnet-fabric-bound-mismatch.json");
        let control = LocalControlPlane::new(DaemonConfig::new("dev", &temp));
        let state = fixture_daemon_state("dev");
        state.save(&temp).expect("fixture state should persist");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([89_u8; 32]);

        let error = control
            .ensure_identity_bound_state(&runtime_identity)
            .expect_err("mismatched runtime identity should fail");

        assert!(error
            .to_string()
            .contains("does not match runtime identity"));
        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn durable_state_requires_schema_version() {
        let temp = std::env::temp_dir().join("quicnet-fabric-missing-schema-version.json");
        std::fs::write(
            &temp,
            r#"{
  "network": "dev",
  "local_peer_id": "ed25519:missing-schema",
  "roles": [],
  "membership": {},
  "capability_grants": [],
  "revocations": [],
  "denied_peers": [],
  "bootstrap": [],
  "relay_map": null,
  "peers": [],
  "netcheck": {
    "nat_type": "Unknown",
    "udp_reachable": false,
    "ipv6_reachable": false,
    "hairpin_supported": false,
    "public_udp_addr": null,
    "port_mapped": false,
    "probe_observations": []
  },
  "queue_policies": [],
  "path_candidates": []
}"#,
        )
        .expect("fixture should persist");

        let error = DaemonState::load(&temp).expect_err("missing schema version should fail");
        assert!(matches!(error, DaemonStateError::MissingSchemaVersion));
        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn durable_state_rejects_unsupported_schema_version() {
        let temp = std::env::temp_dir().join("quicnet-fabric-unsupported-schema-version.json");
        let mut value = serde_json::to_value(fixture_daemon_state("unsupported-schema-version"))
            .expect("fixture state should serialize");
        value["schema_version"] = serde_json::json!(99);
        std::fs::write(&temp, serde_json::to_vec_pretty(&value).expect("serialize"))
            .expect("fixture should persist");

        let error = DaemonState::load(&temp).expect_err("unsupported schema version should fail");
        assert!(matches!(
            error,
            DaemonStateError::UnsupportedSchemaVersion {
                found: 99,
                expected: DAEMON_STATE_SCHEMA_VERSION
            }
        ));
        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn durable_state_rejects_persisted_runtime_sessions() {
        let temp = std::env::temp_dir().join("quicnet-fabric-persisted-runtime-sessions.json");
        let mut value = serde_json::to_value(fixture_daemon_state("persisted-runtime-sessions"))
            .expect("fixture state should serialize");
        value["active_sessions"] = serde_json::json!([
            {
                "session_id": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            }
        ]);
        std::fs::write(&temp, serde_json::to_vec_pretty(&value).expect("serialize"))
            .expect("fixture should persist");

        let error = DaemonState::load(&temp).expect_err("persisted runtime sessions should fail");
        assert!(matches!(
            error,
            DaemonStateError::UnsupportedDurableField(field) if field == "active_sessions"
        ));
        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn validate_state_file_reports_schema_version_and_path() {
        let temp = std::env::temp_dir().join("quicnet-fabric-validate-state.json");
        let state = fixture_daemon_state("validate-state-report");
        state.save(&temp).expect("fixture state should persist");
        let control = LocalControlPlane::new(DaemonConfig::new("validate-state-report", &temp));

        let report = control
            .validate_state_file()
            .expect("state validation should succeed");

        assert_eq!(report.schema_version, Some(DAEMON_STATE_SCHEMA_VERSION));
        assert_eq!(report.state_path, temp);
        assert!(report.present);
        assert!(report.valid);
        assert!(report.violations.is_empty());
        let _ = std::fs::remove_file(report.state_path);
    }

    #[test]
    fn reset_network_state_removes_only_durable_state_file() {
        let temp = std::env::temp_dir().join("quicnet-fabric-reset-state.json");
        let control = LocalControlPlane::new(DaemonConfig::new("reset-state-report", &temp));
        let state = fixture_daemon_state("reset-state-report");
        state.save(&temp).expect("fixture state should persist");

        let removed = control
            .reset_network_state()
            .expect("state reset should succeed");

        assert!(removed);
        assert!(!temp.exists());
    }

    #[test]
    fn inspect_state_file_reports_summary_for_valid_state() {
        let temp = std::env::temp_dir().join("quicnet-fabric-inspect-state.json");
        let state = fixture_daemon_state("inspect-state-report");
        state.save(&temp).expect("fixture state should persist");
        let control = LocalControlPlane::new(DaemonConfig::new("inspect-state-report", &temp));

        let report = control
            .inspect_state_file()
            .expect("state inspection should succeed");

        assert!(report.present);
        assert!(report.valid);
        let summary = report.summary.expect("summary should be present");
        assert_eq!(summary.network, "inspect-state-report");
        assert_eq!(summary.bootstrap_hints, 2);
        assert_eq!(summary.roles.len(), 2);
        let _ = std::fs::remove_file(report.state_path);
    }

    #[test]
    fn inspect_state_file_reports_missing_file_without_erroring() {
        let temp = std::env::temp_dir().join("quicnet-fabric-missing-state.json");
        let control = LocalControlPlane::new(DaemonConfig::new("missing-state-report", &temp));

        let report = control
            .inspect_state_file()
            .expect("missing state inspection should succeed");

        assert!(!report.present);
        assert!(!report.valid);
        assert_eq!(report.schema_version, None);
        assert_eq!(report.violations.len(), 1);
        assert!(report.summary.is_none());
    }

    #[test]
    fn validate_state_file_reports_runtime_only_field_violation() {
        let temp = std::env::temp_dir().join("quicnet-fabric-invalid-runtime-field.json");
        let mut value = serde_json::to_value(fixture_daemon_state("invalid-runtime-field"))
            .expect("fixture state should serialize");
        value["active_sessions"] = serde_json::json!([
            {
                "session_id": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            }
        ]);
        std::fs::write(&temp, serde_json::to_vec_pretty(&value).expect("serialize"))
            .expect("fixture should persist");
        let control = LocalControlPlane::new(DaemonConfig::new("invalid-runtime-field", &temp));

        let report = control
            .validate_state_file()
            .expect("state validation should return a report");

        assert!(report.present);
        assert!(!report.valid);
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].path, "$.active_sessions");
        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn backup_bundle_roundtrips_identity_and_state_files() {
        let temp_dir =
            std::env::temp_dir().join(format!("quip-backup-roundtrip-{}", now_unix_secs()));
        std::fs::create_dir_all(&temp_dir).expect("temp dir should exist");
        let identity_path = temp_dir.join("identity-node.json");
        let state_path = temp_dir.join("state.json");
        let output_path = temp_dir.join("backup.qbk");
        let restored_identity = temp_dir.join("restored-identity.json");
        let restored_state = temp_dir.join("restored-state.json");
        std::fs::write(&identity_path, b"{\"encrypted\":true}").expect("identity should write");
        fixture_daemon_state("backup-roundtrip")
            .save(&state_path)
            .expect("state should persist");

        let exported = export_backup_bundle(DurableBackupExportRequest {
            output_path: output_path.clone(),
            passphrase: "backup-passphrase".to_string(),
            hostname: "host-a".to_string(),
            environment: "test".to_string(),
            identity_path: identity_path.clone(),
            state_path: state_path.clone(),
            network: "backup-roundtrip".to_string(),
            authority_origin: Some("https://authority.example".to_string()),
            authority_subject: Some("peer-authority".to_string()),
            authority_snapshot: None,
            overwrite: false,
        })
        .expect("backup should export");

        assert_eq!(exported.network, "backup-roundtrip");
        assert!(output_path.exists());
        let restored = restore_backup_bundle(DurableBackupRestoreRequest {
            input_path: output_path.clone(),
            passphrase: "backup-passphrase".to_string(),
            identity_path: restored_identity.clone(),
            state_path: restored_state.clone(),
            overwrite: false,
        })
        .expect("backup should restore");

        assert_eq!(restored.network, "backup-roundtrip");
        assert_eq!(
            std::fs::read(&identity_path).expect("identity should read"),
            std::fs::read(&restored_identity).expect("restored identity should read"),
        );
        assert_eq!(
            std::fs::read(&state_path).expect("state should read"),
            std::fs::read(&restored_state).expect("restored state should read"),
        );
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn authority_snapshot_seeds_state() {
        let authority = crypto::IdentityKeypair::from_secret_bytes([7_u8; 32]);
        let subject = crypto::IdentityKeypair::from_secret_bytes([8_u8; 32]);
        let bootstrap_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"bootstrap-1");
        let network = "personalcloud-prod";
        let snapshot = AuthorityArtifactSnapshot {
            network_id: NetworkId::derive(network),
            enrollment_token: None,
            membership: Some(membership::MembershipCertificate::issue(
                &authority,
                NetworkId::derive(network),
                subject.peer_id(),
                100,
                200,
                vec!["member".to_string()],
            )),
            capability_grants: vec![membership::CapabilityGrant::issue(
                &authority,
                NetworkId::derive(network),
                bootstrap_peer.clone(),
                vec!["records.publish".to_string()],
                vec![ProtocolId::new("/quicnet/records/1").expect("protocol")],
                membership::ResourceLimits::default(),
                vec![],
                100,
                200,
                7,
            )],
            revocations: vec![membership::RevocationRecord::issue(
                &authority,
                NetworkId::derive(network),
                membership::RevocationTarget::Peer {
                    peer_id: bootstrap_peer.clone(),
                },
                membership::RevocationReason::Administrative,
                150,
                150,
                8,
                Some("seed rotated".to_string()),
            )],
            bootstrap_hints: vec![
                membership::BootstrapHint {
                    peer_id: Some(bootstrap_peer.clone()),
                    addresses: vec!["quic://203.0.113.10:8443".to_string()],
                    metadata: BTreeMap::from([(
                        "protocols".to_string(),
                        "/quicnet/control/1,/quicnet/records/1".to_string(),
                    )]),
                },
                membership::BootstrapHint {
                    peer_id: None,
                    addresses: vec!["https://bootstrap.example.invalid:8443".to_string()],
                    metadata: BTreeMap::new(),
                },
            ],
        };

        let state = DaemonState::from_authority_snapshot(network, vec![DaemonRole::Edge], snapshot)
            .expect("authority snapshot should seed state");
        assert_eq!(state.local_peer_id, subject.peer_id());
        assert_eq!(state.bootstrap.len(), 2);
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.denied_peers.len(), 1);
        assert!(state.deny_reason(&bootstrap_peer).is_some());
        assert!(state.path_candidates.is_empty());
        assert_eq!(
            state.netcheck.probe_observations[0].status,
            ProbeStatus::Pending
        );
        let decision = state.explain_policy(
            &bootstrap_peer,
            &ProtocolId::new("/quicnet/records/1").expect("protocol"),
        );
        assert!(!decision.allowed);
        assert!(decision.reason.contains("peer revoked"));
    }

    #[test]
    fn snapshot_sync_preserves_runtime_state() {
        let authority = crypto::IdentityKeypair::from_secret_bytes([13_u8; 32]);
        let local = crypto::IdentityKeypair::from_secret_bytes([14_u8; 32]);
        let bootstrap_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"sync-bootstrap");
        let network = "personalcloud-prod";
        let membership = membership::MembershipCertificate::issue(
            &authority,
            NetworkId::derive(network),
            local.peer_id(),
            100,
            300,
            vec!["member".to_string()],
        );
        let mut state = fixture_daemon_state(network);
        state.local_peer_id = local.peer_id();
        state.membership = membership.clone();
        state.netcheck.public_udp_addr = Some("203.0.113.77:8443".to_string());
        state.path_candidates.push(PathCandidate {
            peer: bootstrap_peer.clone(),
            path_kind: PathKind::Relay,
            relay_peer: Some(PeerId::from_public_key(
                KeyAlgorithm::Ed25519,
                b"sync-relay",
            )),
            source: PathSource::Observed,
            traffic_classes: vec![TrafficClass::Control, TrafficClass::Interactive],
            rtt_ms: 20,
            jitter_ms: 3,
            loss_pct: 0.5,
            throughput_mbps: 500,
            relay_penalty: 10,
        });

        let incoming = AuthorityArtifactSnapshot {
            network_id: NetworkId::derive(network),
            enrollment_token: None,
            membership: Some(membership),
            capability_grants: vec![membership::CapabilityGrant::issue(
                &authority,
                NetworkId::derive(network),
                bootstrap_peer.clone(),
                vec!["records.publish".to_string()],
                vec![ProtocolId::new("/quicnet/records/1").expect("protocol")],
                membership::ResourceLimits::default(),
                vec![],
                100,
                300,
                1,
            )],
            revocations: vec![],
            bootstrap_hints: vec![membership::BootstrapHint {
                peer_id: Some(bootstrap_peer.clone()),
                addresses: vec!["quic://198.51.100.40:8443".to_string()],
                metadata: BTreeMap::from([(
                    "protocols".to_string(),
                    "/quicnet/records/1".to_string(),
                )]),
            }],
        };
        let client = ControlClient {
            network_id: NetworkId::derive(network),
            endpoints: control::AuthorityEndpoints {
                enrollment: "local://enroll".to_string(),
                revocation: "local://revoke".to_string(),
                relay_map: "local://relays".to_string(),
                bootstrap: "local://bootstrap".to_string(),
                snapshot: "local://snapshot".to_string(),
            },
        };

        let (synced, report) = state
            .sync_authority_snapshot(&client, incoming)
            .expect("sync should succeed");
        assert_eq!(report.grants_added, 1);
        assert_eq!(
            synced.netcheck.public_udp_addr.as_deref(),
            Some("203.0.113.77:8443")
        );
        assert!(synced.path_candidates.len() >= state.path_candidates.len());
        assert!(synced.path_candidates.iter().any(|candidate| {
            candidate.source == PathSource::Observed && candidate.peer == bootstrap_peer
        }));
        assert!(synced.peer(&bootstrap_peer).is_some());
    }

    #[test]
    fn explain_policy_uses_local_subject_grants_for_outbound_connects() {
        let authority = crypto::IdentityKeypair::from_secret_bytes([31_u8; 32]);
        let local = crypto::IdentityKeypair::from_secret_bytes([32_u8; 32]);
        let remote = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"remote-policy-target");
        let network = "personalcloud-prod";
        let protocol = ProtocolId::new("/quicnet/control/1").expect("protocol");
        let membership = membership::MembershipCertificate::issue(
            &authority,
            NetworkId::derive(network),
            local.peer_id(),
            100,
            300,
            vec!["member".to_string()],
        );
        let grant = membership::CapabilityGrant::issue(
            &authority,
            NetworkId::derive(network),
            local.peer_id(),
            vec!["control.access".to_string()],
            vec![protocol.clone()],
            membership::ResourceLimits::default(),
            Vec::new(),
            100,
            300,
            1,
        );
        let mut state = fixture_daemon_state(network);
        state.local_peer_id = local.peer_id();
        state.membership = membership;
        state.capability_grants = vec![grant];

        let decision = state.explain_policy(&remote, &protocol);

        assert!(decision.allowed);
        assert!(decision.reason.contains("active grant"));
    }

    #[test]
    fn apply_revocations_updates_deny_state_without_snapshot_reload() {
        let authority = crypto::IdentityKeypair::from_secret_bytes([21_u8; 32]);
        let subject = crypto::IdentityKeypair::from_secret_bytes([22_u8; 32]);
        let network = "revocation-only";
        let membership = membership::MembershipCertificate::issue(
            &authority,
            NetworkId::derive(network),
            subject.peer_id(),
            100,
            200,
            vec!["member".to_string()],
        );
        let grant = membership::CapabilityGrant::issue(
            &authority,
            NetworkId::derive(network),
            subject.peer_id(),
            vec!["records.publish".to_string()],
            vec![ProtocolId::new("/quicnet/records/1").expect("protocol")],
            membership::ResourceLimits::default(),
            vec![],
            100,
            200,
            7,
        );
        let state = DaemonState {
            schema_version: DAEMON_STATE_SCHEMA_VERSION,
            network: network.to_string(),
            local_peer_id: subject.peer_id(),
            roles: vec![DaemonRole::Edge],
            membership: membership.clone(),
            capability_grants: vec![grant],
            revocations: Vec::new(),
            denied_peers: Vec::new(),
            bootstrap: Vec::new(),
            relay_map: None,
            peers: Vec::new(),
            netcheck: pending_netcheck(),
            queue_policies: default_queue_policies(),
            active_sessions: Vec::new(),
            path_candidates: Vec::new(),
        };
        let revocation = membership::RevocationRecord::issue(
            &authority,
            NetworkId::derive(network),
            membership::RevocationTarget::MembershipCertificate {
                subject_peer_id: membership.subject_peer_id.clone(),
                issued_at: membership.issued_at,
            },
            membership::RevocationReason::Administrative,
            150,
            150,
            3,
            Some("compromised".to_string()),
        );

        let (updated, added) = state.apply_revocations(vec![revocation.clone(), revocation]);

        assert_eq!(added, 1);
        assert_eq!(updated.revocations.len(), 1);
        assert_eq!(updated.denied_peers.len(), 1);
        assert!(updated.deny_reason(&membership.subject_peer_id).is_some());
    }

    #[test]
    fn apply_relay_map_persists_announcements_into_peer_state() {
        let mut state = fixture_daemon_state("relay-map");
        state.relay_map = None;
        state.peers.clear();
        let relay_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"iad-relay-1");
        let relay_map = RelayMap {
            version: 4,
            generated_at: 1_720_123_456,
            relays: vec![RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "us-east-1".to_string(),
                advertised_endpoints: vec!["quic://198.51.100.88:443".to_string()],
                control_endpoint: "http://198.51.100.88:9081".to_string(),
                max_bandwidth_bps: 3_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string()],
            }],
        };

        let (updated, added) = state.apply_relay_map(relay_map.clone());

        assert_eq!(added, 1);
        assert_eq!(updated.relay_count(), 1);
        assert_eq!(updated.relay_map, Some(relay_map));
        assert!(updated.peer(&relay_peer).is_some());
    }

    #[test]
    fn relay_map_synthesizes_fallback_for_bootstrap_peer_when_direct_udp_is_unavailable() {
        let authority = crypto::IdentityKeypair::from_secret_bytes([31_u8; 32]);
        let subject = crypto::IdentityKeypair::from_secret_bytes([32_u8; 32]);
        let bootstrap_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"bootstrap-relayed");
        let relay_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"fra-relay-bootstrap");
        let network = "relay-fallback";
        let snapshot = AuthorityArtifactSnapshot {
            network_id: NetworkId::derive(network),
            enrollment_token: None,
            membership: Some(membership::MembershipCertificate::issue(
                &authority,
                NetworkId::derive(network),
                subject.peer_id(),
                100,
                200,
                vec!["member".to_string()],
            )),
            capability_grants: vec![],
            revocations: vec![],
            bootstrap_hints: vec![membership::BootstrapHint {
                peer_id: Some(bootstrap_peer.clone()),
                addresses: vec!["quic://198.51.100.77:8443".to_string()],
                metadata: BTreeMap::from([(
                    "protocols".to_string(),
                    "/quicnet/control/1".to_string(),
                )]),
            }],
        };
        let state = DaemonState::from_authority_snapshot(network, vec![DaemonRole::Edge], snapshot)
            .expect("state should build from snapshot");
        let relay_map = RelayMap {
            version: 1,
            generated_at: 1_720_555_000,
            relays: vec![RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.70:443".to_string()],
                control_endpoint: format!("inproc://{relay_peer}"),
                max_bandwidth_bps: 2_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            }],
        };

        let (state, added) = state.apply_relay_map(relay_map);
        let decision = state
            .best_path(&bootstrap_peer, TrafficClass::Control)
            .expect("relay fallback path should exist");

        assert_eq!(added, 1);
        assert_eq!(decision.selected.path_kind, PathKind::Relay);
        assert_eq!(decision.selected.relay_peer, Some(relay_peer));
        assert_eq!(decision.selected.source, PathSource::AuthorityRelay);
    }

    #[test]
    fn relay_fallback_builds_relay_route_plan() {
        let relay_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-route");
        let bootstrap_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-target");
        let authority = crypto::IdentityKeypair::from_secret_bytes([31_u8; 32]);
        let subject = crypto::IdentityKeypair::from_secret_bytes([32_u8; 32]);
        let network = "relay-route-prod";
        let snapshot = AuthorityArtifactSnapshot {
            network_id: NetworkId::derive(network),
            enrollment_token: None,
            membership: Some(membership::MembershipCertificate::issue(
                &authority,
                NetworkId::derive(network),
                subject.peer_id(),
                100,
                200,
                vec!["member".to_string()],
            )),
            capability_grants: vec![membership::CapabilityGrant::issue(
                &authority,
                NetworkId::derive(network),
                bootstrap_peer.clone(),
                vec!["records.publish".to_string()],
                vec![ProtocolId::new("/quicnet/control/1").expect("protocol")],
                membership::ResourceLimits::default(),
                vec![],
                100,
                200,
                7,
            )],
            revocations: vec![],
            bootstrap_hints: vec![membership::BootstrapHint {
                peer_id: Some(bootstrap_peer.clone()),
                addresses: vec!["quic://198.51.100.77:8443".to_string()],
                metadata: BTreeMap::from([(
                    "protocols".to_string(),
                    "/quicnet/control/1".to_string(),
                )]),
            }],
        };
        let state = DaemonState::from_authority_snapshot(network, vec![DaemonRole::Edge], snapshot)
            .expect("state should build from snapshot");
        let relay_map = RelayMap {
            version: 1,
            generated_at: 1_720_555_000,
            relays: vec![RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.70:443".to_string()],
                control_endpoint: format!("inproc://{relay_peer}"),
                max_bandwidth_bps: 2_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            }],
        };
        let (state, _) = state.apply_relay_map(relay_map);

        let route = state
            .route_plan(
                &bootstrap_peer,
                Some(ProtocolId::new("/quicnet/control/1").expect("protocol")),
                TrafficClass::Control,
            )
            .expect("relay route plan should build");

        assert_eq!(route.path_kind, PathKind::Relay);
        let relay = route.relay.expect("relay plan should exist");
        assert_eq!(relay.relay_peer, relay_peer);
        assert_eq!(
            relay.destination_endpoints,
            vec!["quic://198.51.100.77:8443".to_string()]
        );
        assert_eq!(
            relay.relay_endpoints,
            vec!["quic://203.0.113.70:443".to_string()]
        );
    }

    #[tokio::test]
    async fn realize_best_path_keeps_runtime_sessions_out_of_persisted_state() {
        let _guard = relay_test_lock();
        clear_registry();
        let relay_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-runtime");
        let bootstrap_peer =
            PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-target-runtime");
        let authority = crypto::IdentityKeypair::from_secret_bytes([41_u8; 32]);
        let subject = crypto::IdentityKeypair::from_secret_bytes([42_u8; 32]);
        let network = "relay-runtime-prod";
        let state_path = unique_state_path("quicnet-relay-runtime-state");
        let snapshot = AuthorityArtifactSnapshot {
            network_id: NetworkId::derive(network),
            enrollment_token: None,
            membership: Some(membership::MembershipCertificate::issue(
                &authority,
                NetworkId::derive(network),
                subject.peer_id(),
                100,
                200,
                vec!["member".to_string()],
            )),
            capability_grants: vec![membership::CapabilityGrant::issue(
                &authority,
                NetworkId::derive(network),
                subject.peer_id(),
                vec!["control.access".to_string()],
                vec![ProtocolId::new("/quicnet/control/1").expect("protocol")],
                membership::ResourceLimits::default(),
                vec![],
                100,
                200,
                7,
            )],
            revocations: vec![],
            bootstrap_hints: vec![membership::BootstrapHint {
                peer_id: Some(bootstrap_peer.clone()),
                addresses: vec!["quic://198.51.100.77:8443".to_string()],
                metadata: BTreeMap::from([(
                    "protocols".to_string(),
                    "/quicnet/control/1".to_string(),
                )]),
            }],
        };
        let mut state =
            DaemonState::from_authority_snapshot(network, vec![DaemonRole::Edge], snapshot)
                .expect("state should build from snapshot");
        state.netcheck.udp_reachable = false;
        state.netcheck.ipv6_reachable = false;
        let relay_map = RelayMap {
            version: 1,
            generated_at: 1_720_555_000,
            relays: vec![RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.70:443".to_string()],
                control_endpoint: "http://203.0.113.70:9081".to_string(),
                max_bandwidth_bps: 2_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            }],
        };
        let (state, _) = state.apply_relay_map(relay_map);
        state.save(&state_path).expect("state should persist");
        register_relay(RelayService::new(RelayNode {
            announcement: RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.70:443".to_string()],
                control_endpoint: format!("inproc://{relay_peer}"),
                max_bandwidth_bps: 2_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            },
            quotas: vec![RelayQuota {
                peer: subject.peer_id(),
                max_bandwidth_bps: 100_000_000,
                max_concurrent_sessions: 2,
            }],
            destinations: vec![relay::RelayDestination {
                peer: bootstrap_peer.clone(),
                protocols: vec![ProtocolId::new("/quicnet/control/1").expect("protocol")],
            }],
        }));
        let control = LocalControlPlane::new(DaemonConfig::new(network, &state_path));
        let transport =
            QuicTransportAdapter::with_identity(NetworkId::derive(network), subject.clone())
                .with_relay_control(Arc::new(InProcessRelayControl));

        let session = control
            .realize_best_path(
                &bootstrap_peer,
                &ProtocolId::new("/quicnet/control/1").expect("protocol"),
                TrafficClass::Control,
                &transport,
            )
            .await
            .expect("relay session should be accepted");

        let persisted = DaemonState::load(&state_path).expect("persisted state should load");
        assert_eq!(session.path_kind, PathKind::Relay);
        assert!(session.relay_attempt_id.is_some());
        assert!(persisted.active_sessions.is_empty());
        let _ = std::fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn close_session_releases_runtime_registry_without_persisting_sessions() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-relay-close-state");
        let (control, transport, session, relay_peer) = establish_persisted_relay_session(
            "relay-close-prod",
            &state_path,
            51,
            52,
            b"relay-close-runtime",
            b"relay-close-target",
        )
        .await;

        assert_eq!(registered_session_count(&relay_peer), Some(1));

        control
            .close_session(&session.session_id, &transport)
            .await
            .expect("relay session should close cleanly");

        let persisted = DaemonState::load(&state_path).expect("persisted state should load");
        assert!(persisted.active_sessions.is_empty());
        assert_eq!(registered_session_count(&relay_peer), Some(0));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn reconcile_sessions_leaves_matching_direct_session_unchanged() {
        let state_path = unique_state_path("quicnet-direct-reconcile-state");
        let (control, transport, session, bootstrap_peer) = establish_persisted_direct_session(
            "direct-reconcile-prod",
            &state_path,
            71,
            72,
            b"direct-reconcile-target",
        )
        .await;

        let report = control
            .reconcile_sessions(&transport)
            .await
            .expect("direct session should reconcile cleanly");

        let persisted = DaemonState::load(&state_path).expect("persisted state should load");
        assert_eq!(report.examined, 1);
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.upgraded, 0);
        assert_eq!(report.closed, 0);
        assert_eq!(report.entries[0].session_id, session.session_id);
        assert_eq!(
            report.entries[0].disposition,
            SessionReconcileDisposition::Unchanged
        );
        assert_eq!(report.entries[0].path_kind, Some(PathKind::DirectUdp));
        assert!(persisted.active_sessions.is_empty());
        let runtime_sessions = transport
            .active_sessions()
            .expect("runtime sessions should load");
        assert_eq!(runtime_sessions.len(), 1);
        assert_eq!(runtime_sessions[0].session_id, session.session_id);
        assert_eq!(runtime_sessions[0].peer, bootstrap_peer);

        let _ = std::fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn upgrade_session_updates_runtime_path_and_releases_relay_registry() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-relay-upgrade-state");
        let (control, transport, session, relay_peer) = establish_persisted_relay_session(
            "relay-upgrade-prod",
            &state_path,
            61,
            62,
            b"relay-upgrade-runtime",
            b"relay-upgrade-target",
        )
        .await;

        assert_eq!(session.path_kind, PathKind::Relay);
        assert_eq!(registered_session_count(&relay_peer), Some(1));

        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        updated.netcheck.udp_reachable = true;
        updated.netcheck.ipv6_reachable = false;
        updated.netcheck.public_udp_addr = Some("203.0.113.52:8443".to_string());
        updated
            .save(&state_path)
            .expect("updated state should persist");

        let upgraded = control
            .upgrade_session(&session.session_id, &transport)
            .await
            .expect("relay session should migrate to the direct path");

        let persisted = DaemonState::load(&state_path).expect("persisted state should load");
        assert_eq!(upgraded.session_id, session.session_id);
        assert!(matches!(
            upgraded.path_kind,
            PathKind::DirectUdp | PathKind::DirectIpv6
        ));
        assert_eq!(upgraded.relay_peer, None);
        assert_eq!(upgraded.relay_control_endpoint, None);
        assert!(persisted.active_sessions.is_empty());
        let runtime = transport
            .session_snapshot(&session.session_id)
            .expect("runtime session lookup should succeed")
            .expect("runtime session should still exist");
        assert_eq!(runtime.path_kind, upgraded.path_kind);
        assert_eq!(runtime.relay_peer, None);
        assert_eq!(runtime.relay_control_endpoint, None);
        assert_eq!(registered_session_count(&relay_peer), Some(0));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn reconcile_sessions_upgrades_relay_session_to_direct() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-relay-reconcile-upgrade-state");
        let (control, transport, session, relay_peer) = establish_persisted_relay_session(
            "relay-reconcile-upgrade-prod",
            &state_path,
            81,
            82,
            b"relay-reconcile-upgrade-runtime",
            b"relay-reconcile-upgrade-target",
        )
        .await;

        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        updated.netcheck.udp_reachable = true;
        updated.netcheck.ipv6_reachable = false;
        updated.netcheck.public_udp_addr = Some("203.0.113.82:8443".to_string());
        updated
            .save(&state_path)
            .expect("updated state should persist");

        let report = control
            .reconcile_sessions(&transport)
            .await
            .expect("relay session should reconcile to a direct path");

        let persisted = DaemonState::load(&state_path).expect("persisted state should load");
        assert_eq!(report.examined, 1);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.upgraded, 1);
        assert_eq!(report.closed, 0);
        assert_eq!(report.entries[0].session_id, session.session_id);
        assert_eq!(
            report.entries[0].disposition,
            SessionReconcileDisposition::Upgraded
        );
        assert!(matches!(
            report.entries[0].path_kind,
            Some(PathKind::DirectUdp | PathKind::DirectIpv6)
        ));
        assert!(persisted.active_sessions.is_empty());
        let runtime = transport
            .session_snapshot(&session.session_id)
            .expect("runtime session lookup should succeed")
            .expect("runtime session should still exist");
        assert_eq!(runtime.session_id, session.session_id);
        assert!(matches!(
            runtime.path_kind,
            PathKind::DirectUdp | PathKind::DirectIpv6
        ));
        assert_eq!(runtime.relay_peer, None);
        assert_eq!(registered_session_count(&relay_peer), Some(0));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn reconcile_sessions_closes_policy_denied_session() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-relay-reconcile-close-state");
        let (control, transport, session, relay_peer) = establish_persisted_relay_session(
            "relay-reconcile-close-prod",
            &state_path,
            91,
            92,
            b"relay-reconcile-close-runtime",
            b"relay-reconcile-close-target",
        )
        .await;

        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        updated.capability_grants.clear();
        updated
            .save(&state_path)
            .expect("updated state should persist");

        let report = control
            .reconcile_sessions(&transport)
            .await
            .expect("policy denied session should reconcile by closing");

        let persisted = DaemonState::load(&state_path).expect("persisted state should load");
        assert_eq!(report.examined, 1);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.upgraded, 0);
        assert_eq!(report.closed, 1);
        assert_eq!(report.entries[0].session_id, session.session_id);
        assert_eq!(
            report.entries[0].disposition,
            SessionReconcileDisposition::Closed
        );
        assert!(report.entries[0].reason.contains("policy denied session"));
        assert!(persisted.active_sessions.is_empty());
        assert_eq!(registered_session_count(&relay_peer), Some(0));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn authority_reevaluation_closes_denied_session_and_suppresses_reconnect() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-authority-reevaluation-close-state");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([94_u8; 32]);
        let (control, transport, session, relay_peer) = establish_persisted_relay_session(
            "authority-reevaluation-close-prod",
            &state_path,
            93,
            94,
            b"authority-reevaluation-runtime",
            b"authority-reevaluation-target",
        )
        .await;

        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        updated.capability_grants.clear();
        updated
            .save(&state_path)
            .expect("updated state should persist");

        let report = control
            .reevaluate_runtime_authority(&runtime_identity, &transport)
            .await
            .expect("authority reevaluation should succeed");

        assert_eq!(report.reevaluated_sessions, 1);
        assert_eq!(report.closed_sessions, 1);
        assert_eq!(report.reconnect_suppressions_added, 1);
        assert_eq!(report.capability_denied_sessions, 1);
        assert!(transport
            .session_snapshot(&session.session_id)
            .expect("runtime lookup should succeed")
            .is_none());
        let suppressions = transport
            .reconnect_suppressions()
            .expect("suppression lookup should succeed");
        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].peer, session.peer);
        assert_eq!(registered_session_count(&relay_peer), Some(0));
        let events = transport.recent_events(16).expect("events should load");
        assert!(events
            .iter()
            .any(|event| event.event_type == "authority.policy_enforced"
                && event.details.get("cause").and_then(|value| value.as_str())
                    == Some("capability_denied")));

        let denied = control
            .realize_best_path(
                &session.peer,
                &session.protocol.clone().expect("protocol should exist"),
                session.class,
                &transport,
            )
            .await
            .expect_err("suppressed reconnect should deny reestablishment");
        assert!(denied.to_string().contains("policy denied"));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn authority_reevaluation_migrates_session_when_a_better_eligible_path_emerges() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quipnet-authority-reevaluation-migrate-state");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([116_u8; 32]);
        let (control, transport, session, relay_peer) = establish_persisted_relay_session(
            "authority-reevaluation-migrate-prod",
            &state_path,
            115,
            116,
            b"authority-reevaluation-migrate-runtime",
            b"authority-reevaluation-migrate-target",
        )
        .await;

        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        updated.netcheck.udp_reachable = true;
        updated.netcheck.ipv6_reachable = false;
        updated.netcheck.public_udp_addr = Some("203.0.113.116:8443".to_string());
        updated
            .save(&state_path)
            .expect("updated state should persist");

        let report = control
            .reevaluate_runtime_authority(&runtime_identity, &transport)
            .await
            .expect("authority reevaluation should migrate the session");

        assert_eq!(report.reevaluated_sessions, 1);
        assert_eq!(report.migrated_sessions, 1);
        assert_eq!(report.degraded_sessions, 0);
        assert_eq!(report.closed_sessions, 0);
        let runtime = transport
            .session_snapshot(&session.session_id)
            .expect("runtime lookup should succeed")
            .expect("runtime session should still exist");
        assert!(matches!(
            runtime.path_kind,
            PathKind::DirectUdp | PathKind::DirectIpv6
        ));
        assert_eq!(runtime.relay_peer, None);
        assert_eq!(registered_session_count(&relay_peer), Some(0));

        let events = transport.recent_events(16).expect("events should load");
        assert!(events
            .iter()
            .any(|event| event.event_type == "path.migration_started"));
        assert!(events
            .iter()
            .any(|event| event.event_type == "path.migration_completed"));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn authority_reevaluation_degrades_session_when_no_eligible_replacement_path_exists() {
        let state_path = unique_state_path("quipnet-authority-reevaluation-degrade-state");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([118_u8; 32]);
        let (control, transport, session, _bootstrap_peer) = establish_persisted_direct_session(
            "authority-reevaluation-degrade-prod",
            &state_path,
            117,
            118,
            b"authority-reevaluation-degrade-target",
        )
        .await;

        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        updated.netcheck.udp_reachable = false;
        updated.netcheck.ipv6_reachable = false;
        updated.netcheck.public_udp_addr = None;
        updated.bootstrap.clear();
        updated.relay_map = None;
        updated.path_candidates.clear();
        updated
            .save(&state_path)
            .expect("updated state should persist");

        let report = control
            .reevaluate_runtime_authority(&runtime_identity, &transport)
            .await
            .expect("authority reevaluation should degrade the session");

        assert_eq!(report.reevaluated_sessions, 1);
        assert_eq!(report.degraded_sessions, 1);
        assert_eq!(report.migrated_sessions, 0);
        assert_eq!(report.closed_sessions, 0);
        let runtime = transport
            .session_snapshot(&session.session_id)
            .expect("runtime lookup should succeed")
            .expect("runtime session should still exist");
        assert_eq!(runtime.state, RuntimeSessionState::Degraded);
        assert!(runtime
            .state_reason
            .as_deref()
            .unwrap_or_default()
            .contains("no eligible replacement path"));

        let events = transport.recent_events(16).expect("events should load");
        assert!(events
            .iter()
            .any(|event| event.event_type == "path.degraded"));

        let _ = std::fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn runtime_paths_reports_active_and_suppressed_runtime_truth() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-runtime-paths-state");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([96_u8; 32]);
        let (control, transport, session, _relay_peer) = establish_persisted_relay_session(
            "runtime-paths-prod",
            &state_path,
            95,
            96,
            b"runtime-paths-runtime",
            b"runtime-paths-target",
        )
        .await;

        let active_paths = control
            .runtime_paths(&transport)
            .expect("runtime paths should render");
        let active_entry = active_paths
            .iter()
            .find(|entry| entry.session_id == Some(session.session_id))
            .expect("active session path should exist");
        assert_eq!(active_entry.state, RuntimePathState::Active);
        assert_eq!(active_entry.path_kind, Some(PathKind::Relay));
        assert!(!active_entry.summary.is_empty());
        assert!(active_paths
            .iter()
            .any(|entry| entry.state == RuntimePathState::Candidate));

        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        updated.capability_grants.clear();
        updated
            .save(&state_path)
            .expect("updated state should persist");
        control
            .reevaluate_runtime_authority(&runtime_identity, &transport)
            .await
            .expect("authority reevaluation should succeed");

        let suppressed_paths = control
            .runtime_paths(&transport)
            .expect("suppressed runtime paths should render");
        let suppressed_entry = suppressed_paths
            .iter()
            .find(|entry| entry.state == RuntimePathState::Suppressed)
            .expect("suppressed path should exist");
        assert_eq!(suppressed_entry.session_id, None);
        assert_eq!(suppressed_entry.protocol, session.protocol);
        assert!(suppressed_entry
            .state_reason
            .as_deref()
            .unwrap_or_default()
            .contains("no active capability grants"));
        assert!(suppressed_paths
            .iter()
            .any(|entry| entry.state == RuntimePathState::Candidate));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn runtime_paths_report_failed_reconnect_with_operator_diagnostics() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quipnet-runtime-paths-failed-reconnect");
        let (_control, transport, session, relay_peer) = establish_persisted_relay_session(
            "runtime-paths-failed-reconnect-prod",
            &state_path,
            120,
            121,
            b"runtime-paths-failed-reconnect-runtime",
            b"runtime-paths-failed-reconnect-target",
        )
        .await;

        transport
            .close_session(&session)
            .await
            .expect("runtime session should close");
        let protocol = session.protocol.clone().expect("protocol should exist");
        transport
            .schedule_reconnect(
                &session.peer,
                Some(&protocol),
                session.class,
                "relay dial rejected by runtime".to_string(),
                3,
                2,
                8,
            )
            .expect("first reconnect attempt should schedule");
        transport
            .schedule_reconnect(
                &session.peer,
                Some(&protocol),
                session.class,
                "relay dial rejected by runtime".to_string(),
                3,
                2,
                8,
            )
            .expect("second reconnect attempt should schedule");
        transport
            .schedule_reconnect(
                &session.peer,
                Some(&protocol),
                session.class,
                "relay dial rejected by runtime".to_string(),
                3,
                2,
                8,
            )
            .expect("third reconnect attempt should fail");

        let control = LocalControlPlane::new(DaemonConfig::new(
            "runtime-paths-failed-reconnect-prod",
            &state_path,
        ));
        let paths = control
            .runtime_paths(&transport)
            .expect("runtime paths should render");
        let failed_entry = paths
            .iter()
            .find(|entry| {
                entry.peer == session.peer
                    && entry.protocol.as_ref() == Some(&protocol)
                    && entry.state == RuntimePathState::Failed
            })
            .expect("failed reconnect path should exist");

        assert_eq!(failed_entry.path_kind, Some(PathKind::Relay));
        assert_eq!(failed_entry.relay_peer, Some(relay_peer.clone()));
        assert!(failed_entry
            .state_reason
            .as_deref()
            .unwrap_or_default()
            .contains("reconnect exhausted 3/3 attempts"));
        assert!(failed_entry.summary.contains("reconnect failed"));
        assert!(failed_entry.summary.contains("3/3 attempts"));
        assert!(failed_entry
            .summary
            .contains("best known relay fallback remains"));
        assert!(failed_entry
            .decision_reason
            .as_deref()
            .unwrap_or_default()
            .contains("strengths="));

        let events = transport.recent_events(32).expect("events should load");
        assert!(events
            .iter()
            .any(|event| event.event_type == "reconnect.failed"));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn runtime_health_reports_listener_and_suppression_state() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-runtime-health-state");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([98_u8; 32]);
        let (control, transport, session, _relay_peer) = establish_persisted_relay_session(
            "runtime-health-prod",
            &state_path,
            97,
            98,
            b"runtime-health-runtime",
            b"runtime-health-target",
        )
        .await;
        transport
            .listen(BindSpec {
                protocol: session.protocol.clone().expect("protocol should exist"),
                advertise: true,
            })
            .await
            .expect("listener should register");

        let ready = control
            .runtime_health(&transport)
            .expect("runtime health should render");
        assert_eq!(ready.daemon_readiness, RuntimeHealthLevel::Ready);
        assert_eq!(ready.active_sessions, 1);
        assert_eq!(ready.active_paths, 1);
        assert_eq!(ready.active_listeners, 1);
        assert_eq!(ready.reconnect_state, RuntimeReconnectState::Idle);

        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        updated.capability_grants.clear();
        updated
            .save(&state_path)
            .expect("updated state should persist");
        let report = control
            .reevaluate_runtime_authority(&runtime_identity, &transport)
            .await
            .expect("authority reevaluation should succeed");
        assert_eq!(report.reevaluated_listeners, 1);
        assert_eq!(report.suppressed_listeners, 1);
        assert_eq!(report.restored_listeners, 0);

        let suppressed = control
            .runtime_health(&transport)
            .expect("suppressed health should render");
        assert_eq!(suppressed.daemon_readiness, RuntimeHealthLevel::Suppressed);
        assert_eq!(
            suppressed.reconnect_subsystem_health,
            RuntimeHealthLevel::Suppressed
        );
        assert_eq!(
            suppressed.reconnect_state,
            RuntimeReconnectState::Suppressed
        );
        assert_eq!(suppressed.reconnect_suppression_count, 1);
        assert_eq!(suppressed.authority_subject_status, "matched");
        assert!(suppressed.authority_deny_reason.is_none());
        assert_eq!(suppressed.active_listeners, 0);

        let listeners = control
            .runtime_listeners(&transport)
            .expect("runtime listeners should render");
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].state, RuntimeListenerState::Suppressed);
        assert!(listeners[0]
            .state_reason
            .as_deref()
            .unwrap_or_default()
            .contains("no active capability grants"));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn authority_reevaluation_clears_runtime_suppression_and_restores_listener() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-authority-reevaluation-restore-state");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([121_u8; 32]);
        let (control, transport, session, _relay_peer) = establish_persisted_relay_session(
            "authority-reevaluation-restore-prod",
            &state_path,
            120,
            121,
            b"authority-reevaluation-restore-runtime",
            b"authority-reevaluation-restore-target",
        )
        .await;
        let protocol = session.protocol.clone().expect("protocol should exist");
        let _listener = transport
            .listen(BindSpec {
                protocol: protocol.clone(),
                advertise: true,
            })
            .await
            .expect("listener should register");
        transport
            .suppress_reconnect(
                &session.peer,
                Some(&protocol),
                session.class,
                "temporary policy denial".to_string(),
            )
            .expect("suppression should register");
        let listener_id = transport
            .active_listeners()
            .expect("listener lookup should succeed")
            .into_iter()
            .find(|entry| entry.protocol == protocol)
            .expect("listener snapshot should exist")
            .listener_id;
        let _ = transport
            .update_listener_state(
                &listener_id,
                RuntimeListenerState::Suppressed,
                Some("temporary policy denial".to_string()),
            )
            .expect("listener update should succeed");

        let report = control
            .reevaluate_runtime_authority(&runtime_identity, &transport)
            .await
            .expect("authority reevaluation should succeed");

        assert_eq!(report.reevaluated_sessions, 1);
        assert_eq!(report.reconnect_suppressions_added, 0);
        assert_eq!(report.reconnect_suppressions_cleared, 1);
        assert_eq!(report.reevaluated_listeners, 1);
        assert_eq!(report.restored_listeners, 1);
        assert_eq!(report.suppressed_listeners, 0);
        assert!(transport
            .reconnect_suppressions()
            .expect("suppression lookup should succeed")
            .is_empty());
        let listeners = transport
            .active_listeners()
            .expect("listener lookup should succeed");
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].state, RuntimeListenerState::Active);
        assert!(listeners[0].state_reason.is_none());
        let events = transport.recent_events(32).expect("events should load");
        assert!(events
            .iter()
            .any(|event| event.event_type == "reconnect.unsuppressed"));
        assert!(events.iter().any(|event| {
            event.event_type == "authority.reevaluation_completed"
                && event
                    .details
                    .get("reconnect_suppressions_cleared")
                    .and_then(|value| value.as_u64())
                    == Some(1)
                && event
                    .details
                    .get("restored_listeners")
                    .and_then(|value| value.as_u64())
                    == Some(1)
        }));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn authority_reevaluation_closes_subject_mismatch_sessions() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-authority-reevaluation-subject-mismatch");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([111_u8; 32]);
        let (control, transport, session, relay_peer) = establish_persisted_relay_session(
            "authority-reevaluation-subject-mismatch-prod",
            &state_path,
            109,
            110,
            b"authority-reevaluation-subject-mismatch-runtime",
            b"authority-reevaluation-subject-mismatch-target",
        )
        .await;

        let report = control
            .reevaluate_runtime_authority(&runtime_identity, &transport)
            .await
            .expect("authority reevaluation should succeed");

        assert!(report.authority_subject_mismatch);
        assert_eq!(report.subject_mismatch_sessions, 1);
        assert_eq!(report.closed_sessions, 1);
        assert_eq!(registered_session_count(&relay_peer), Some(0));
        assert!(transport
            .session_snapshot(&session.session_id)
            .expect("runtime lookup should succeed")
            .is_none());

        let events = transport.recent_events(16).expect("events should load");
        assert!(events.iter().any(|event| {
            event.event_type == "authority.policy_enforced"
                && event.details.get("cause").and_then(|value| value.as_str())
                    == Some("subject_mismatch")
        }));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn authority_reevaluation_closes_peer_membership_denied_sessions() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-authority-reevaluation-peer-membership");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([121_u8; 32]);
        let (control, transport, session, relay_peer) = establish_persisted_relay_session(
            "authority-reevaluation-peer-membership-prod",
            &state_path,
            120,
            121,
            b"authority-reevaluation-peer-membership-runtime",
            b"authority-reevaluation-peer-membership-target",
        )
        .await;
        let authority = crypto::IdentityKeypair::from_secret_bytes([120_u8; 32]);
        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        updated
            .revocations
            .push(membership::RevocationRecord::issue(
                &authority,
                NetworkId::derive("authority-reevaluation-peer-membership-prod"),
                membership::RevocationTarget::Peer {
                    peer_id: session.peer.clone(),
                },
                membership::RevocationReason::Administrative,
                150,
                150,
                9,
                Some("peer membership revoked".to_string()),
            ));
        updated.denied_peers = denied_peers(&updated.membership, &updated.revocations);
        updated
            .save(&state_path)
            .expect("updated state should persist");

        let report = control
            .reevaluate_runtime_authority(&runtime_identity, &transport)
            .await
            .expect("authority reevaluation should succeed");

        assert_eq!(report.peer_membership_denied_sessions, 1);
        assert_eq!(report.closed_sessions, 1);
        assert_eq!(registered_session_count(&relay_peer), Some(0));
        let events = transport.recent_events(16).expect("events should load");
        assert!(events.iter().any(|event| {
            event.event_type == "authority.policy_enforced"
                && event.details.get("cause").and_then(|value| value.as_str())
                    == Some("peer_membership_denied")
        }));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn authority_reevaluation_closes_sessions_after_local_membership_revocation() {
        let _guard = relay_test_lock();
        let state_path = unique_state_path("quicnet-authority-reevaluation-local-membership");
        let runtime_identity = crypto::IdentityKeypair::from_secret_bytes([141_u8; 32]);
        let (control, transport, _session, relay_peer) = establish_persisted_relay_session(
            "authority-reevaluation-local-membership-prod",
            &state_path,
            140,
            141,
            b"authority-reevaluation-local-membership-runtime",
            b"authority-reevaluation-local-membership-target",
        )
        .await;
        let authority = crypto::IdentityKeypair::from_secret_bytes([140_u8; 32]);
        let mut updated = DaemonState::load(&state_path).expect("persisted state should load");
        let membership = updated.membership.clone();
        updated
            .revocations
            .push(membership::RevocationRecord::issue(
                &authority,
                NetworkId::derive("authority-reevaluation-local-membership-prod"),
                membership::RevocationTarget::MembershipCertificate {
                    subject_peer_id: membership.subject_peer_id.clone(),
                    issued_at: membership.issued_at,
                },
                membership::RevocationReason::Administrative,
                150,
                150,
                11,
                Some("local membership revoked".to_string()),
            ));
        updated.denied_peers = denied_peers(&updated.membership, &updated.revocations);
        updated
            .save(&state_path)
            .expect("updated state should persist");

        let report = control
            .reevaluate_runtime_authority(&runtime_identity, &transport)
            .await
            .expect("authority reevaluation should succeed");

        assert!(report.local_policy_denied);
        assert_eq!(report.local_membership_denied_sessions, 1);
        assert_eq!(report.closed_sessions, 1);
        assert!(report
            .local_policy_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("membership revoked")));
        assert_eq!(registered_session_count(&relay_peer), Some(0));

        let events = transport.recent_events(16).expect("events should load");
        assert!(events.iter().any(|event| {
            event.event_type == "authority.policy_enforced"
                && event.details.get("cause").and_then(|value| value.as_str())
                    == Some("local_membership_denied")
        }));

        let _ = std::fs::remove_file(state_path);
        clear_registry();
    }

    #[tokio::test]
    async fn runtime_health_reports_failed_authority_subject_status_when_state_is_incoherent() {
        let authority = crypto::IdentityKeypair::from_secret_bytes([130_u8; 32]);
        let local = crypto::IdentityKeypair::from_secret_bytes([131_u8; 32]);
        let other = crypto::IdentityKeypair::from_secret_bytes([132_u8; 32]);
        let network = "authority-health-subject-mismatch";
        let protocol = ProtocolId::new("/quicnet/control/1").expect("protocol");
        let grant = membership::CapabilityGrant::issue(
            &authority,
            NetworkId::derive(network),
            local.peer_id(),
            vec!["control.access".to_string()],
            vec![protocol],
            membership::ResourceLimits::default(),
            Vec::new(),
            100,
            300,
            1,
        );
        let state_path = unique_state_path("quicnet-authority-health-subject-mismatch");
        let control = LocalControlPlane::new(DaemonConfig::new(network, &state_path));
        let mut state = self_identity_daemon_state(network, vec![DaemonRole::Edge], &local);
        state.membership = MembershipCertificate::issue(
            &authority,
            NetworkId::derive(network),
            other.peer_id(),
            100,
            300,
            vec!["member".to_string()],
        );
        state.capability_grants = vec![grant];
        state.save(&state_path).expect("state should persist");

        let health = control
            .runtime_health(&QuicTransportAdapter::with_identity(
                NetworkId::derive(network),
                local.clone(),
            ))
            .expect("runtime health should render");

        assert_eq!(health.authority_sync_health, RuntimeHealthLevel::Failed);
        assert_eq!(health.authority_subject_status, "mismatched");
        let _ = std::fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn reconcile_sessions_ignores_stale_persisted_sessions_missing_from_runtime_transport() {
        let state_path = unique_state_path("quicnet-direct-reconcile-missing-runtime-state");
        let (control, _transport, session, _bootstrap_peer) = establish_persisted_direct_session(
            "direct-reconcile-missing-runtime-prod",
            &state_path,
            91,
            92,
            b"direct-reconcile-missing-runtime-target",
        )
        .await;
        let fresh_transport = QuicTransportAdapter::with_identity(
            NetworkId::derive("direct-reconcile-missing-runtime-prod"),
            crypto::IdentityKeypair::from_secret_bytes([91_u8; 32]),
        );

        let report = control
            .reconcile_sessions(&fresh_transport)
            .await
            .expect("missing runtime session should not be treated as durable truth");

        let persisted = DaemonState::load(&state_path).expect("persisted state should load");
        assert_eq!(report.examined, 0);
        assert_eq!(report.closed, 0);
        assert_eq!(report.upgraded, 0);
        assert_eq!(report.unchanged, 0);
        assert!(persisted.active_sessions.is_empty());
        let _ = session;

        let _ = std::fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn sync_runtime_sessions_exposes_runtime_state_without_persisting_sessions() {
        let state_path = unique_state_path("quicnet-sync-runtime-sessions-state");
        let (control, transport, session, _bootstrap_peer) = establish_persisted_direct_session(
            "direct-sync-runtime-prod",
            &state_path,
            93,
            94,
            b"direct-sync-runtime-target",
        )
        .await;
        let synced = control
            .sync_runtime_sessions(&transport)
            .expect("runtime sessions should become primary");

        assert_eq!(synced.active_sessions.len(), 1);
        assert_eq!(synced.active_sessions[0].session_id, session.session_id);
        let persisted = DaemonState::load(&state_path).expect("persisted state should load");
        assert!(persisted.active_sessions.is_empty());
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn reprobe_network_change_promotes_udp_when_local_public_addr_exists() {
        let state_path = unique_state_path("quicnet-reprobe-public-addr-state");
        let control = LocalControlPlane::new(DaemonConfig::new("reprobe-public-addr", &state_path));
        let mut state = fixture_daemon_state("reprobe-public-addr");
        state.netcheck.nat_type = NatType::UdpBlocked;
        state.netcheck.udp_reachable = false;
        state.netcheck.ipv6_reachable = false;
        state.netcheck.public_udp_addr = Some("203.0.113.100:8443".to_string());
        state.path_candidates.clear();
        state.save(&state_path).expect("state should persist");

        let report = control
            .reprobe_network_change("network interface changed")
            .expect("reprobe should persist");
        let persisted = DaemonState::load(&state_path).expect("persisted state should load");

        assert!(report.udp_reachable);
        assert!(!report.relay_required);
        assert_eq!(persisted.netcheck.udp_reachable, true);
        assert_eq!(persisted.netcheck.nat_type, NatType::RestrictedCone);
        assert!(persisted.path_candidates.iter().any(|candidate| {
            matches!(
                candidate.path_kind,
                PathKind::DirectUdp | PathKind::DirectIpv6
            )
        }));
        assert!(persisted
            .netcheck
            .probe_observations
            .last()
            .is_some_and(|observation| observation.detail.contains("network change reprobe")));

        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn reprobe_network_change_records_failed_observation_without_udp_evidence() {
        let state_path = unique_state_path("quicnet-reprobe-failed-state");
        let control = LocalControlPlane::new(DaemonConfig::new("reprobe-failed", &state_path));
        let mut state = fixture_daemon_state("reprobe-failed");
        state.netcheck.nat_type = NatType::Unknown;
        state.netcheck.udp_reachable = false;
        state.netcheck.ipv6_reachable = false;
        state.netcheck.public_udp_addr = None;
        state.netcheck.port_mapped = false;
        state.path_candidates.clear();
        state.save(&state_path).expect("state should persist");

        let report = control
            .reprobe_network_change("carrier hop")
            .expect("reprobe should persist");
        let persisted = DaemonState::load(&state_path).expect("persisted state should load");

        assert!(!report.udp_reachable);
        assert!(report.relay_required);
        assert_eq!(persisted.netcheck.udp_reachable, false);
        assert!(persisted
            .netcheck
            .probe_observations
            .last()
            .is_some_and(|observation| observation.status == ProbeStatus::Failed));
        assert!(persisted
            .path_candidates
            .iter()
            .all(|candidate| candidate.path_kind == PathKind::Relay
                || candidate.relay_peer.is_none()));

        let _ = std::fs::remove_file(state_path);
    }
}
