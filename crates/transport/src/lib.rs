use async_trait::async_trait;
use bytes::Bytes;
use model::{ContentId, PathKind, PathStats, PeerId, PeerView, ProtocolId, TrafficClass};
use records::SignedRecord;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("peer is unreachable")]
    Unreachable,
    #[error("no route is available for peer {0}")]
    NoRoute(PeerId),
    #[error("protocol is not authorized or supported")]
    ProtocolRejected,
    #[error("policy denied transport request: {0}")]
    PolicyDenied(String),
    #[error("route plan is invalid: {0}")]
    InvalidRoute(String),
    #[error("relay rejected session open: {0}")]
    RelayRejected(String),
    #[error("transport implementation is not wired yet")]
    NotImplemented,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RouteSource {
    Observed,
    Bootstrap,
    AuthorityRelay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayPlan {
    pub relay_peer: PeerId,
    pub relay_endpoints: Vec<String>,
    pub relay_control_endpoint: String,
    pub destination_endpoints: Vec<String>,
    pub supports_datagrams: bool,
    pub supports_path_migration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutePlan {
    pub local_peer: PeerId,
    pub peer: PeerId,
    pub protocol: Option<ProtocolId>,
    pub class: TrafficClass,
    pub path_kind: PathKind,
    pub source: RouteSource,
    pub remote_endpoints: Vec<String>,
    pub relay: Option<RelayPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindSpec {
    pub protocol: ProtocolId,
    pub advertise: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageReceipt {
    pub peer: PeerId,
    pub protocol: ProtocolId,
    pub accepted_bytes: usize,
    pub route: SessionSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub session_id: [u8; 16],
    pub transport_session_id: [u8; 16],
    pub relay_attempt_id: Option<[u8; 16]>,
    pub peer: PeerId,
    pub protocol: Option<ProtocolId>,
    pub class: TrafficClass,
    pub path_kind: PathKind,
    pub source: RouteSource,
    pub remote_endpoint: String,
    pub relay_peer: Option<PeerId>,
    pub relay_endpoint: Option<String>,
    pub relay_control_endpoint: Option<String>,
    pub datagrams_capable: bool,
    pub migration_capable: bool,
    pub state: RuntimeSessionState,
    pub closure_reason: Option<SessionClosureReason>,
    pub state_reason: Option<String>,
    pub created_at_unix_secs: u64,
    pub last_activity_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSessionState {
    Pending,
    Connecting,
    Active,
    Degraded,
    Migrating,
    Reconciling,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionClosureReason {
    OperatorRequested,
    LocalRuntimeFailure,
    RemoteFailure,
    PolicyRejected,
    PathExhaustion,
    DaemonShutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_type: String,
    pub emitted_at: String,
    pub truth_kind: String,
    pub subject: RuntimeEventSubject,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEventSubject {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconnectSuppression {
    pub peer: PeerId,
    pub protocol: Option<ProtocolId>,
    pub class: TrafficClass,
    pub reason: String,
    pub imposed_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeListenerState {
    Active,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeListenerSnapshot {
    pub listener_id: String,
    pub transport: String,
    pub bind_summary: String,
    pub protocol: ProtocolId,
    pub advertise: bool,
    pub state: RuntimeListenerState,
    pub started_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeReconnectState {
    Idle,
    Active,
    Suppressed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeTransportHealth {
    pub active_sessions: usize,
    pub active_listeners: usize,
    pub reconnect_state: RuntimeReconnectState,
    pub reconnect_suppression_count: usize,
    pub event_buffer_depth: usize,
    pub session_registry_healthy: bool,
    pub listener_registry_healthy: bool,
}

pub trait ConnectionHandle {
    fn snapshot(&self) -> SessionSnapshot;
}

#[async_trait]
pub trait SecureTransport: Send + Sync {
    type Connection: ConnectionHandle + Send + Sync;
    type Listener: Send + Sync;

    async fn connect(&self, route: RoutePlan) -> Result<Self::Connection, TransportError>;
    async fn listen(&self, bind: BindSpec) -> Result<Self::Listener, TransportError>;
}

#[async_trait]
pub trait SessionLifecycleTransport: SecureTransport {
    fn active_sessions(&self) -> Result<Vec<SessionSnapshot>, TransportError>;

    fn session_snapshot(
        &self,
        session_id: &[u8; 16],
    ) -> Result<Option<SessionSnapshot>, TransportError>;

    fn update_session_state(
        &self,
        session_id: &[u8; 16],
        state: RuntimeSessionState,
        closure_reason: Option<SessionClosureReason>,
        state_reason: Option<String>,
    ) -> Result<Option<SessionSnapshot>, TransportError>;

    fn recent_events(&self, limit: usize) -> Result<Vec<RuntimeEvent>, TransportError>;

    fn suppress_reconnect(
        &self,
        peer: &PeerId,
        protocol: Option<&ProtocolId>,
        class: TrafficClass,
        reason: String,
    ) -> Result<(), TransportError>;

    fn clear_reconnect_suppression(
        &self,
        peer: &PeerId,
        protocol: Option<&ProtocolId>,
        class: TrafficClass,
    ) -> Result<(), TransportError>;

    fn reconnect_suppressions(&self) -> Result<Vec<ReconnectSuppression>, TransportError>;

    fn active_listeners(&self) -> Result<Vec<RuntimeListenerSnapshot>, TransportError>;

    fn transport_health(&self) -> Result<RuntimeTransportHealth, TransportError>;

    async fn migrate(
        &self,
        session: &SessionSnapshot,
        route: RoutePlan,
    ) -> Result<SessionSnapshot, TransportError>;

    async fn close_session(&self, session: &SessionSnapshot) -> Result<(), TransportError>;
}

#[async_trait]
pub trait Fabric: Send + Sync {
    type Stream: Send + Sync;
    type Listener: Send + Sync;

    async fn connect(
        &self,
        peer: PeerId,
        protocol: Option<ProtocolId>,
        class: TrafficClass,
    ) -> Result<SessionSnapshot, TransportError>;
    async fn listen(&self, protocol: ProtocolId) -> Result<Self::Listener, TransportError>;
    async fn open_stream(
        &self,
        peer: PeerId,
        protocol: ProtocolId,
        class: TrafficClass,
    ) -> Result<Self::Stream, TransportError>;
    async fn send_message(
        &self,
        peer: PeerId,
        protocol: ProtocolId,
        class: TrafficClass,
        message: Bytes,
    ) -> Result<MessageReceipt, TransportError>;
    async fn send_datagram(
        &self,
        peer: PeerId,
        protocol: ProtocolId,
        class: TrafficClass,
        payload: Bytes,
    ) -> Result<(), TransportError>;
    async fn publish_record(&self, record: SignedRecord) -> Result<(), TransportError>;
    async fn resolve_peer(&self, peer: PeerId) -> Result<PeerView, TransportError>;
    async fn find_providers(&self, cid: ContentId) -> Result<Vec<PeerId>, TransportError>;
    fn path_stats(&self, peer: PeerId) -> Vec<PathStats>;
}
