use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fmt::Write as _, time::Duration};

use crypto::PublicIdentityKey;
use identity::IdentityError;
use model::{PeerId, TrafficClass};
use rand::{rngs::OsRng, RngCore};
use relaywire::{
    RelayAnnouncement, RelayFrame, RelayMap, RelayOpenRequest, RelayRejectCode,
    RelaySessionAccepted, RelaySessionRejected,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayQuota {
    pub peer: PeerId,
    pub max_bandwidth_bps: u64,
    pub max_concurrent_sessions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayDestination {
    pub peer: PeerId,
    pub protocols: Vec<model::ProtocolId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayNode {
    pub announcement: RelayAnnouncement,
    pub quotas: Vec<RelayQuota>,
    pub destinations: Vec<RelayDestination>,
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("peer is not authorized to use this relay")]
    Unauthorized,
    #[error("source identity proof is invalid: {0}")]
    InvalidIdentityProof(String),
    #[error("relay destination {0} is not authorized")]
    DestinationUnauthorized(PeerId),
    #[error("relay destination {0} does not support requested protocol")]
    DestinationProtocolRejected(PeerId),
    #[error("relay {0} is unavailable")]
    Unavailable(PeerId),
    #[error("relay path does not support traffic class {0:?}")]
    UnsupportedTrafficClass(TrafficClass),
    #[error("relay is at session capacity for peer {0}")]
    CapacityExceeded(PeerId),
    #[error("relay session already exists")]
    SessionExists,
    #[error("relay session was not found")]
    SessionNotFound,
    #[error("relay control transport failed: {0}")]
    ControlTransport(String),
    #[error("relay control payload decode failed: {0}")]
    ControlDecode(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelaySessionStatus {
    Pending,
    Open,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelaySession {
    pub session_id: [u8; 16],
    pub source: PeerId,
    pub destination: PeerId,
    pub protocol: Option<model::ProtocolId>,
    pub traffic_class: TrafficClass,
    pub status: RelaySessionStatus,
}

#[derive(Debug, Default)]
pub struct RelayRuntime {
    sessions: BTreeMap<[u8; 16], RelaySession>,
}

impl RelayRuntime {
    pub fn session(&self, session_id: &[u8; 16]) -> Option<&RelaySession> {
        self.sessions.get(session_id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| session.status == RelaySessionStatus::Open)
            .count()
    }

    pub fn apply_frame(&mut self, frame: RelayFrame) -> Result<(), RelayError> {
        match frame {
            RelayFrame::OpenSession(request) => {
                self.sessions.insert(
                    pending_session_id(&request.attempt_id),
                    RelaySession {
                        session_id: pending_session_id(&request.attempt_id),
                        source: request.source,
                        destination: request.destination,
                        protocol: request.protocol,
                        traffic_class: request.traffic_class,
                        status: RelaySessionStatus::Pending,
                    },
                );
                Ok(())
            }
            RelayFrame::SessionAccepted(accepted) => {
                self.sessions.insert(
                    accepted.session_id,
                    RelaySession {
                        session_id: accepted.session_id,
                        source: accepted.source,
                        destination: accepted.destination,
                        protocol: accepted.protocol,
                        traffic_class: accepted.traffic_class,
                        status: RelaySessionStatus::Open,
                    },
                );
                Ok(())
            }
            RelayFrame::SessionRejected(rejected) => {
                self.sessions
                    .remove(&pending_session_id(&rejected.attempt_id));
                Err(RelayError::Unauthorized)
            }
            RelayFrame::Data { session_id, .. } | RelayFrame::Health { session_id, .. } => {
                if self
                    .sessions
                    .get(&session_id)
                    .is_some_and(|session| session.status == RelaySessionStatus::Open)
                {
                    Ok(())
                } else {
                    Err(RelayError::Unauthorized)
                }
            }
            RelayFrame::Close { session_id, .. } => {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    session.status = RelaySessionStatus::Closed;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub struct RelayService {
    pub node: RelayNode,
    runtime: RelayRuntime,
}

impl RelayService {
    pub fn new(node: RelayNode) -> Self {
        Self {
            node,
            runtime: RelayRuntime::default(),
        }
    }

    pub fn open_session(
        &mut self,
        request: RelayOpenRequest,
    ) -> Result<RelaySessionAccepted, RelaySessionRejected> {
        if let Err(error) = verify_open_request(&request) {
            return Err(RelaySessionRejected {
                attempt_id: request.attempt_id,
                code: RelayRejectCode::InvalidIdentityProof,
                source: request.source,
                destination: request.destination,
                protocol: request.protocol,
                traffic_class: request.traffic_class,
                reason: error.to_string(),
            });
        }
        if !supports_traffic_class(
            &self.node.announcement.traffic_classes,
            request.traffic_class,
        ) {
            return Err(RelaySessionRejected {
                attempt_id: request.attempt_id,
                code: RelayRejectCode::UnsupportedTrafficClass,
                source: request.source,
                destination: request.destination,
                protocol: request.protocol,
                traffic_class: request.traffic_class,
                reason: format!("relay does not support {:?} traffic", request.traffic_class),
            });
        }
        if let Err(error) = authorize_destination(
            &self.node.destinations,
            &request.destination,
            request.protocol.as_ref(),
        ) {
            return Err(RelaySessionRejected {
                attempt_id: request.attempt_id,
                code: match error {
                    RelayError::DestinationProtocolRejected(_) => {
                        RelayRejectCode::DestinationProtocolRejected
                    }
                    _ => RelayRejectCode::DestinationUnauthorized,
                },
                source: request.source,
                destination: request.destination,
                protocol: request.protocol,
                traffic_class: request.traffic_class,
                reason: error.to_string(),
            });
        }
        if let Some(quota) = self
            .node
            .quotas
            .iter()
            .find(|quota| quota.peer == request.source)
        {
            let active_for_source = self
                .runtime
                .sessions
                .values()
                .filter(|session| {
                    session.source == request.source && session.status == RelaySessionStatus::Open
                })
                .count() as u32;
            if active_for_source >= quota.max_concurrent_sessions {
                return Err(RelaySessionRejected {
                    attempt_id: request.attempt_id,
                    code: RelayRejectCode::CapacityExceeded,
                    source: request.source,
                    destination: request.destination,
                    protocol: request.protocol,
                    traffic_class: request.traffic_class,
                    reason: format!("source {} is over relay session quota", quota.peer),
                });
            }
        }

        let session_id = random_session_id();
        if self.runtime.sessions.contains_key(&session_id) {
            return Err(RelaySessionRejected {
                attempt_id: request.attempt_id,
                code: RelayRejectCode::SessionExists,
                source: request.source,
                destination: request.destination,
                protocol: request.protocol,
                traffic_class: request.traffic_class,
                reason: "relay session already exists".to_string(),
            });
        }

        self.runtime
            .apply_frame(RelayFrame::OpenSession(request.clone()))
            .expect("open session frame should be accepted");
        let accepted = RelaySessionAccepted {
            attempt_id: request.attempt_id,
            session_id,
            source: request.source,
            destination: request.destination,
            protocol: request.protocol,
            traffic_class: request.traffic_class,
        };
        self.runtime
            .apply_frame(RelayFrame::SessionAccepted(accepted.clone()))
            .expect("accepted frame should open the session");
        Ok(accepted)
    }

    pub fn close_session(
        &mut self,
        session_id: [u8; 16],
        reason: String,
    ) -> Result<(), RelayError> {
        if self.runtime.session(&session_id).is_none() {
            return Err(RelayError::SessionNotFound);
        }
        self.runtime
            .apply_frame(RelayFrame::Close { session_id, reason })
    }

    pub fn session_count(&self) -> usize {
        self.runtime.session_count()
    }

    pub fn session(&self, session_id: &[u8; 16]) -> Option<&RelaySession> {
        self.runtime.session(session_id)
    }
}

static RELAY_REGISTRY: OnceLock<Mutex<BTreeMap<PeerId, RelayService>>> = OnceLock::new();

pub trait RelayControl: Send + Sync {
    fn open_session(
        &self,
        endpoint: &str,
        request: RelayOpenRequest,
    ) -> Result<RelaySessionAccepted, RelayError>;

    fn close_session(
        &self,
        endpoint: &str,
        session_id: [u8; 16],
        reason: &str,
    ) -> Result<(), RelayError>;

    fn session(
        &self,
        endpoint: &str,
        session_id: [u8; 16],
    ) -> Result<Option<RelaySession>, RelayError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HttpRelayControl;

impl RelayControl for HttpRelayControl {
    fn open_session(
        &self,
        endpoint: &str,
        request: RelayOpenRequest,
    ) -> Result<RelaySessionAccepted, RelayError> {
        let payload = serde_json::to_string(&request).expect("relay request should serialize");
        let response = relay_control_agent()
            .post(&format!("{}/sessions", endpoint.trim_end_matches('/')))
            .set("Content-Type", "application/json")
            .send_string(&payload);
        match response {
            Ok(response) => response
                .into_json::<RelaySessionAccepted>()
                .map_err(|error| RelayError::ControlDecode(error.to_string())),
            Err(ureq::Error::Status(_, response)) => {
                let rejected = response
                    .into_json::<RelaySessionRejected>()
                    .map_err(|error| RelayError::ControlDecode(error.to_string()))?;
                Err(map_rejected_to_error(rejected))
            }
            Err(error) => Err(RelayError::ControlTransport(error.to_string())),
        }
    }

    fn close_session(
        &self,
        endpoint: &str,
        session_id: [u8; 16],
        reason: &str,
    ) -> Result<(), RelayError> {
        let payload = serde_json::to_string(&json!({ "reason": reason }))
            .expect("close request should serialize");
        let response = relay_control_agent()
            .delete(&format!(
                "{}/sessions/{}",
                endpoint.trim_end_matches('/'),
                hex_session_id(&session_id)
            ))
            .set("Content-Type", "application/json")
            .send_string(&payload);
        match response {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(404, _)) => Err(RelayError::SessionNotFound),
            Err(ureq::Error::Status(_, response)) => Err(RelayError::ControlTransport(
                response
                    .into_string()
                    .unwrap_or_else(|error| error.to_string()),
            )),
            Err(error) => Err(RelayError::ControlTransport(error.to_string())),
        }
    }

    fn session(
        &self,
        endpoint: &str,
        session_id: [u8; 16],
    ) -> Result<Option<RelaySession>, RelayError> {
        let response = relay_control_agent()
            .get(&format!(
                "{}/sessions/{}",
                endpoint.trim_end_matches('/'),
                hex_session_id(&session_id)
            ))
            .call();
        match response {
            Ok(response) => response
                .into_json::<RelaySession>()
                .map(Some)
                .map_err(|error| RelayError::ControlDecode(error.to_string())),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(_, response)) => Err(RelayError::ControlTransport(
                response
                    .into_string()
                    .unwrap_or_else(|error| error.to_string()),
            )),
            Err(error) => Err(RelayError::ControlTransport(error.to_string())),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct InProcessRelayControl;

impl RelayControl for InProcessRelayControl {
    fn open_session(
        &self,
        endpoint: &str,
        request: RelayOpenRequest,
    ) -> Result<RelaySessionAccepted, RelayError> {
        let relay_peer = endpoint
            .strip_prefix("inproc://")
            .map(|value| {
                value.parse().map_err(|error| {
                    RelayError::ControlTransport(format!("invalid inproc relay peer: {error}"))
                })
            })
            .transpose()?
            .or_else(single_registered_relay_peer)
            .ok_or_else(|| RelayError::ControlTransport("missing inproc relay peer".to_string()))?;
        open_registered_session(&relay_peer, request)
    }

    fn close_session(
        &self,
        endpoint: &str,
        session_id: [u8; 16],
        reason: &str,
    ) -> Result<(), RelayError> {
        let relay_peer = resolve_inproc_relay_peer(endpoint)?;
        close_registered_session(&relay_peer, session_id, reason.to_string())
    }

    fn session(
        &self,
        endpoint: &str,
        session_id: [u8; 16],
    ) -> Result<Option<RelaySession>, RelayError> {
        let relay_peer = resolve_inproc_relay_peer(endpoint)?;
        Ok(registered_session(&relay_peer, &session_id))
    }
}

pub fn register_relay(service: RelayService) {
    relay_registry()
        .lock()
        .expect("relay registry lock")
        .insert(service.node.announcement.peer_id.clone(), service);
}

pub fn clear_registry() {
    relay_registry()
        .lock()
        .expect("relay registry lock")
        .clear();
}

pub fn open_registered_session(
    relay_peer: &PeerId,
    request: RelayOpenRequest,
) -> Result<RelaySessionAccepted, RelayError> {
    let mut registry = relay_registry().lock().expect("relay registry lock");
    let service = registry
        .get_mut(relay_peer)
        .ok_or_else(|| RelayError::Unavailable(relay_peer.clone()))?;
    service.open_session(request).map_err(map_rejected_to_error)
}

pub fn registered_session_count(relay_peer: &PeerId) -> Option<usize> {
    relay_registry()
        .lock()
        .expect("relay registry lock")
        .get(relay_peer)
        .map(RelayService::session_count)
}

pub fn registered_session(relay_peer: &PeerId, session_id: &[u8; 16]) -> Option<RelaySession> {
    relay_registry()
        .lock()
        .expect("relay registry lock")
        .get(relay_peer)
        .and_then(|service| service.session(session_id).cloned())
}

pub fn close_registered_session(
    relay_peer: &PeerId,
    session_id: [u8; 16],
    reason: String,
) -> Result<(), RelayError> {
    let mut registry = relay_registry().lock().expect("relay registry lock");
    let service = registry
        .get_mut(relay_peer)
        .ok_or_else(|| RelayError::Unavailable(relay_peer.clone()))?;
    service.close_session(session_id, reason)
}

fn relay_registry() -> &'static Mutex<BTreeMap<PeerId, RelayService>> {
    RELAY_REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn supports_traffic_class(values: &[String], class: TrafficClass) -> bool {
    values.iter().any(|value| match (value.as_str(), class) {
        ("NetworkControl", TrafficClass::Control) => true,
        ("InteractiveRpc", TrafficClass::Interactive) => true,
        ("BulkTransfer", TrafficClass::Bulk) => true,
        ("Background", TrafficClass::Background) => true,
        _ => false,
    })
}

fn verify_open_request(request: &RelayOpenRequest) -> Result<(), RelayError> {
    verify_source_key_binding(&request.source_public_key, &request.source)?;
    verify_session_credential(request).map_err(|error| RelayError::InvalidIdentityProof(error))?;
    Ok(())
}

fn verify_source_key_binding(
    public_key: &PublicIdentityKey,
    source: &PeerId,
) -> Result<(), RelayError> {
    if public_key.peer_id() != *source {
        return Err(RelayError::InvalidIdentityProof(
            "source identity proof peer id does not match claimed source".to_string(),
        ));
    }
    Ok(())
}

fn verify_session_credential(request: &RelayOpenRequest) -> Result<(), String> {
    request
        .source_credential
        .verify(&request.source_public_key)
        .map_err(identity_error_message)?;
    if request.source_credential.peer_id != request.source {
        return Err("source identity proof peer id does not match credential".to_string());
    }
    if request.source_credential.network_id != request.network_id {
        return Err("source identity proof network does not match relay network".to_string());
    }
    if request.source_credential.expires_at < now_epoch_secs() {
        return Err("source identity proof is expired".to_string());
    }
    if let Some(protocol) = request.protocol.as_ref() {
        if !request
            .source_credential
            .protocol_versions
            .iter()
            .any(|value| value == protocol.as_str())
        {
            return Err("source identity proof does not authorize requested protocol".to_string());
        }
    }
    Ok(())
}

fn authorize_destination(
    destinations: &[RelayDestination],
    destination: &PeerId,
    protocol: Option<&model::ProtocolId>,
) -> Result<(), RelayError> {
    let entry = destinations
        .iter()
        .find(|candidate| &candidate.peer == destination)
        .ok_or_else(|| RelayError::DestinationUnauthorized(destination.clone()))?;
    if let Some(protocol) = protocol {
        if !entry
            .protocols
            .iter()
            .any(|candidate| candidate == protocol)
        {
            return Err(RelayError::DestinationProtocolRejected(destination.clone()));
        }
    }
    Ok(())
}

fn random_session_id() -> [u8; 16] {
    let mut session_id = [0_u8; 16];
    OsRng.fill_bytes(&mut session_id);
    session_id
}

fn pending_session_id(attempt_id: &[u8; 16]) -> [u8; 16] {
    *attempt_id
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs()
}

fn identity_error_message(error: IdentityError) -> String {
    format!("source identity proof verification failed: {error}")
}

fn single_registered_relay_peer() -> Option<PeerId> {
    let registry = relay_registry().lock().expect("relay registry lock");
    if registry.len() == 1 {
        registry.keys().next().cloned()
    } else {
        None
    }
}

fn resolve_inproc_relay_peer(endpoint: &str) -> Result<PeerId, RelayError> {
    endpoint
        .strip_prefix("inproc://")
        .map(|value| {
            value.parse().map_err(|error| {
                RelayError::ControlTransport(format!("invalid inproc relay peer: {error}"))
            })
        })
        .transpose()?
        .or_else(single_registered_relay_peer)
        .ok_or_else(|| RelayError::ControlTransport("missing inproc relay peer".to_string()))
}

fn relay_control_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(2))
        .timeout_read(Duration::from_secs(5))
        .timeout_write(Duration::from_secs(5))
        .build()
}

fn map_rejected_to_error(rejected: RelaySessionRejected) -> RelayError {
    match rejected.code {
        RelayRejectCode::SessionExists => RelayError::SessionExists,
        RelayRejectCode::CapacityExceeded => RelayError::CapacityExceeded(rejected.source),
        RelayRejectCode::UnsupportedTrafficClass => {
            RelayError::UnsupportedTrafficClass(rejected.traffic_class)
        }
        RelayRejectCode::InvalidIdentityProof => RelayError::InvalidIdentityProof(rejected.reason),
        RelayRejectCode::DestinationProtocolRejected => {
            RelayError::DestinationProtocolRejected(rejected.destination)
        }
        RelayRejectCode::DestinationUnauthorized => {
            RelayError::DestinationUnauthorized(rejected.destination)
        }
        RelayRejectCode::InvalidRequest | RelayRejectCode::Unauthorized => RelayError::Unauthorized,
    }
}

pub fn control_response(
    service: &mut RelayService,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, String) {
    match (method, path) {
        ("POST", "/sessions") => match serde_json::from_slice::<RelayOpenRequest>(body) {
            Ok(request) => match service.open_session(request) {
                Ok(accepted) => (
                    200,
                    serde_json::to_string(&accepted).expect("accepted response should serialize"),
                ),
                Err(rejected) => (
                    403,
                    serde_json::to_string(&rejected).expect("rejected response should serialize"),
                ),
            },
            Err(error) => (
                400,
                serde_json::to_string(&RelaySessionRejected {
                    attempt_id: [0_u8; 16],
                    code: RelayRejectCode::InvalidRequest,
                    source: PeerId::from_public_key(model::KeyAlgorithm::Ed25519, b"invalid"),
                    destination: PeerId::from_public_key(model::KeyAlgorithm::Ed25519, b"invalid"),
                    protocol: None,
                    traffic_class: TrafficClass::Control,
                    reason: format!("invalid relay request: {error}"),
                })
                .expect("invalid request response should serialize"),
            ),
        },
        ("GET", "/healthz") => (
            200,
            json!({ "ok": true, "sessions": service.session_count() }).to_string(),
        ),
        _ if method == "GET" && path.starts_with("/sessions/") => {
            match parse_session_path(path) {
                Some(session_id) => match service.session(&session_id) {
                    Some(session) => (
                        200,
                        serde_json::to_string(session).expect("session response should serialize"),
                    ),
                    None => (
                        404,
                        json!({ "error": format!("relay session {} was not found", hex_session_id(&session_id)) }).to_string(),
                    ),
                },
                None => (
                    400,
                    json!({ "error": format!("invalid relay session path {path}") }).to_string(),
                ),
            }
        }
        _ if method == "DELETE" && path.starts_with("/sessions/") => {
            match parse_session_path(path) {
                Some(session_id) => {
                    let reason = match serde_json::from_slice::<CloseSessionRequest>(body) {
                        Ok(request) => request.reason,
                        Err(error) => {
                            return (
                                400,
                                json!({ "error": format!("invalid close request: {error}") }).to_string(),
                            )
                        }
                    };
                    match service.close_session(session_id, reason) {
                        Ok(()) => (204, String::new()),
                        Err(RelayError::SessionNotFound) => (
                            404,
                            json!({ "error": format!("relay session {} was not found", hex_session_id(&session_id)) }).to_string(),
                        ),
                        Err(error) => (409, json!({ "error": error.to_string() }).to_string()),
                    }
                }
                None => (
                    400,
                    json!({ "error": format!("invalid relay session path {path}") }).to_string(),
                ),
            }
        }
        _ => (
            404,
            json!({ "error": format!("no relay control route for {method} {path}") }).to_string(),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct CloseSessionRequest {
    reason: String,
}

fn parse_session_path(path: &str) -> Option<[u8; 16]> {
    let session = path.strip_prefix("/sessions/")?;
    parse_session_id(session)
}

fn parse_session_id(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut session_id = [0_u8; 16];
    for (index, slot) in session_id.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16).ok()?;
    }
    Some(session_id)
}

fn hex_session_id(session_id: &[u8; 16]) -> String {
    let mut value = String::with_capacity(32);
    for byte in session_id {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

impl RelayNode {
    pub fn relay_map(version: u64, generated_at: u64, relays: Vec<Self>) -> RelayMap {
        RelayMap {
            version,
            generated_at,
            relays: relays.into_iter().map(|relay| relay.announcement).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto::IdentityKeypair;
    use model::{KeyAlgorithm, NetworkId, PeerId, ProtocolId, TrafficClass};
    use relaywire::RelayFrame;

    use super::*;

    #[test]
    fn relay_runtime_tracks_session_lifecycle() {
        let mut runtime = RelayRuntime::default();
        let source = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"source");
        let destination = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"destination");
        let session_id = [7_u8; 16];

        runtime
            .apply_frame(RelayFrame::SessionAccepted(RelaySessionAccepted {
                attempt_id: [8_u8; 16],
                session_id,
                source,
                destination,
                protocol: Some(ProtocolId::new("/quicnet/control/1").unwrap()),
                traffic_class: TrafficClass::Interactive,
            }))
            .unwrap();
        assert_eq!(runtime.session_count(), 1);

        runtime
            .apply_frame(RelayFrame::Close {
                session_id,
                reason: "done".to_string(),
            })
            .unwrap();
        assert_eq!(runtime.session_count(), 0);
    }

    #[test]
    fn relay_service_accepts_supported_session() {
        clear_registry();
        let relay_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay");
        let source_identity = IdentityKeypair::from_secret_bytes([51_u8; 32]);
        let source = source_identity.peer_id();
        let destination = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"destination");
        register_relay(RelayService::new(RelayNode {
            announcement: RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.10:443".to_string()],
                control_endpoint: format!("inproc://{relay_peer}"),
                max_bandwidth_bps: 1_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            },
            quotas: vec![RelayQuota {
                peer: source.clone(),
                max_bandwidth_bps: 100_000_000,
                max_concurrent_sessions: 2,
            }],
            destinations: vec![RelayDestination {
                peer: destination.clone(),
                protocols: vec![ProtocolId::new("/quicnet/control/1").unwrap()],
            }],
        }));
        let credential = identity::SessionCredential::issue(
            NetworkId::derive("test-network"),
            &source_identity,
            [9_u8; 32],
            vec!["/quicnet/control/1".to_string()],
            60,
            1,
        );

        let accepted = open_registered_session(
            &relay_peer,
            RelayOpenRequest {
                attempt_id: [1_u8; 16],
                network_id: NetworkId::derive("test-network"),
                source: source.clone(),
                source_public_key: source_identity.public_key(),
                source_credential: credential,
                destination: destination.clone(),
                protocol: Some(ProtocolId::new("/quicnet/control/1").unwrap()),
                traffic_class: TrafficClass::Control,
            },
        )
        .expect("relay should accept control session");

        assert_eq!(accepted.source, source);
        assert_eq!(accepted.destination, destination);
        assert_eq!(registered_session_count(&relay_peer), Some(1));
    }

    #[test]
    fn relay_service_rejects_unsupported_traffic_class() {
        clear_registry();
        let relay_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-unsupported");
        let source_identity = IdentityKeypair::from_secret_bytes([52_u8; 32]);
        let source = source_identity.peer_id();
        let destination =
            PeerId::from_public_key(KeyAlgorithm::Ed25519, b"destination-unsupported");
        register_relay(RelayService::new(RelayNode {
            announcement: RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "iad".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.11:443".to_string()],
                control_endpoint: format!("inproc://{relay_peer}"),
                max_bandwidth_bps: 1_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string()],
            },
            quotas: Vec::new(),
            destinations: vec![RelayDestination {
                peer: destination.clone(),
                protocols: vec![ProtocolId::new("/quicnet/records/1").unwrap()],
            }],
        }));
        let credential = identity::SessionCredential::issue(
            NetworkId::derive("test-network"),
            &source_identity,
            [7_u8; 32],
            vec!["/quicnet/records/1".to_string()],
            60,
            1,
        );

        let result = open_registered_session(
            &relay_peer,
            RelayOpenRequest {
                attempt_id: [2_u8; 16],
                network_id: NetworkId::derive("test-network"),
                source,
                source_public_key: source_identity.public_key(),
                source_credential: credential,
                destination,
                protocol: Some(ProtocolId::new("/quicnet/records/1").unwrap()),
                traffic_class: TrafficClass::Bulk,
            },
        );

        assert!(matches!(
            result,
            Err(RelayError::UnsupportedTrafficClass(TrafficClass::Bulk))
        ));
    }

    #[test]
    fn relay_service_rejects_unauthorized_destination() {
        clear_registry();
        let relay_peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-dst");
        let source_identity = IdentityKeypair::from_secret_bytes([53_u8; 32]);
        let source = source_identity.peer_id();
        let destination = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"destination-dst");
        register_relay(RelayService::new(RelayNode {
            announcement: RelayAnnouncement {
                peer_id: relay_peer.clone(),
                region: "iad".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.12:443".to_string()],
                control_endpoint: format!("inproc://{relay_peer}"),
                max_bandwidth_bps: 1_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string()],
            },
            quotas: Vec::new(),
            destinations: Vec::new(),
        }));
        let credential = identity::SessionCredential::issue(
            NetworkId::derive("test-network"),
            &source_identity,
            [5_u8; 32],
            vec!["/quicnet/control/1".to_string()],
            60,
            1,
        );

        let result = open_registered_session(
            &relay_peer,
            RelayOpenRequest {
                attempt_id: [3_u8; 16],
                network_id: NetworkId::derive("test-network"),
                source,
                source_public_key: source_identity.public_key(),
                source_credential: credential,
                destination: destination.clone(),
                protocol: Some(ProtocolId::new("/quicnet/control/1").unwrap()),
                traffic_class: TrafficClass::Control,
            },
        );

        assert!(matches!(
            result,
            Err(RelayError::DestinationUnauthorized(peer)) if peer == destination
        ));
    }

    #[test]
    fn control_response_tracks_http_session_lifecycle() {
        let source_identity = IdentityKeypair::from_secret_bytes([61_u8; 32]);
        let source = source_identity.peer_id();
        let destination = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"destination-http");
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();
        let credential = identity::SessionCredential::issue(
            NetworkId::derive("test-network"),
            &source_identity,
            [4_u8; 32],
            vec![protocol.as_str().to_string()],
            60,
            1,
        );
        let mut service = RelayService::new(RelayNode {
            announcement: RelayAnnouncement {
                peer_id: PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-http"),
                region: "iad".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.44:443".to_string()],
                control_endpoint: "http://127.0.0.1:9081".to_string(),
                max_bandwidth_bps: 1_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string()],
            },
            quotas: Vec::new(),
            destinations: vec![RelayDestination {
                peer: destination.clone(),
                protocols: vec![protocol.clone()],
            }],
        });

        let (status, payload) = control_response(
            &mut service,
            "POST",
            "/sessions",
            &serde_json::to_vec(&RelayOpenRequest {
                attempt_id: [5_u8; 16],
                network_id: NetworkId::derive("test-network"),
                source: source.clone(),
                source_public_key: source_identity.public_key(),
                source_credential: credential,
                destination: destination.clone(),
                protocol: Some(protocol.clone()),
                traffic_class: TrafficClass::Control,
            })
            .unwrap(),
        );
        assert_eq!(status, 200);
        let accepted: RelaySessionAccepted = serde_json::from_str(&payload).unwrap();

        let (status, payload) = control_response(
            &mut service,
            "GET",
            &format!("/sessions/{}", hex_session_id(&accepted.session_id)),
            &[],
        );
        assert_eq!(status, 200);
        let session: RelaySession = serde_json::from_str(&payload).unwrap();
        assert_eq!(session.status, RelaySessionStatus::Open);
        assert_eq!(session.destination, destination);

        let (status, payload) = control_response(
            &mut service,
            "DELETE",
            &format!("/sessions/{}", hex_session_id(&accepted.session_id)),
            br#"{"reason":"done"}"#,
        );
        assert_eq!(status, 204);
        assert!(payload.is_empty());

        let (status, payload) = control_response(
            &mut service,
            "GET",
            &format!("/sessions/{}", hex_session_id(&accepted.session_id)),
            &[],
        );
        assert_eq!(status, 200);
        let session: RelaySession = serde_json::from_str(&payload).unwrap();
        assert_eq!(session.status, RelaySessionStatus::Closed);
    }
}
