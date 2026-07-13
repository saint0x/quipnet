use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    LocalSocketPeer,
    LocalProcess,
    TestHarness,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestAuth {
    pub kind: AuthKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestEnvelope {
    pub request_id: String,
    pub operation: String,
    pub auth: RequestAuth,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    NotFound,
    RuntimeUnavailable,
    StaleRuntimeReference,
    PolicyRejected,
    AuthorityMismatch,
    StateValidationFailed,
    UnsupportedOperation,
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorObject {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseEnvelope {
    pub ok: bool,
    pub request_id: String,
    pub result: Option<Value>,
    pub error: Option<ErrorObject>,
}

impl ResponseEnvelope {
    pub fn success(request_id: impl Into<String>, result: impl Serialize) -> Self {
        Self {
            ok: true,
            request_id: request_id.into(),
            result: Some(serde_json::to_value(result).expect("daemon API result should serialize")),
            error: None,
        }
    }

    pub fn error(
        request_id: impl Into<String>,
        code: ErrorCode,
        message: impl Into<String>,
        details: Option<Value>,
    ) -> Self {
        Self {
            ok: false,
            request_id: request_id.into(),
            result: None,
            error: Some(ErrorObject {
                code,
                message: message.into(),
                details,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonEndpointDiscovery {
    pub endpoint: String,
    pub network: String,
    pub state_path: String,
    pub identity_path: String,
    pub runtime_instance_id: String,
    pub pid: u32,
    pub started_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStatusResult {
    pub truth_kind: String,
    pub daemon_health: String,
    pub identity: IdentityStatus,
    pub durable_state: DurableStateStatus,
    pub authority: AuthoritySyncStatus,
    pub runtime_summary: RuntimeSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityStatus {
    pub status: String,
    pub path: String,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableStateStatus {
    pub status: String,
    pub path: String,
    pub schema_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritySyncStatus {
    pub sync_status: String,
    pub last_accepted_revision: String,
    pub health: String,
    pub local_policy_denied: bool,
    pub authority_subject_mismatch: bool,
    pub reevaluated_sessions: usize,
    pub closed_sessions: usize,
    pub unchanged_sessions: usize,
    pub reconnect_suppressions_added: usize,
    pub reconnect_suppressions_cleared: usize,
    pub local_policy_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSummary {
    pub session_count: usize,
    pub active_path_count: usize,
    pub reconnect_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSessionsListResult {
    pub truth_kind: String,
    pub sessions: Vec<RuntimeSessionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeListenersListResult {
    pub truth_kind: String,
    pub listeners: Vec<RuntimeListenerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeListenerEntry {
    pub listener_id: String,
    pub transport: String,
    pub bind_summary: String,
    pub protocol: String,
    pub advertise: bool,
    pub state: String,
    pub age_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePathsListResult {
    pub truth_kind: String,
    pub paths: Vec<RuntimePathEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePathEntry {
    pub session_id: Option<String>,
    pub peer_id: String,
    pub protocol: Option<String>,
    pub class: String,
    pub state: String,
    pub path_class: String,
    pub source: String,
    pub relay_peer_id: Option<String>,
    pub endpoint_summary: String,
    pub score: Option<u32>,
    pub state_reason: Option<String>,
    pub summary: String,
    pub alternatives: Vec<RuntimePathAlternativeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePathAlternativeEntry {
    pub path_class: String,
    pub source: String,
    pub relay_peer_id: Option<String>,
    pub score: u32,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSessionEntry {
    pub session_id: String,
    pub peer_id: String,
    pub state: String,
    pub closure_reason: Option<String>,
    pub state_reason: Option<String>,
    pub active_path_class: String,
    pub age_seconds: u64,
    pub last_activity_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEventsListResult {
    pub truth_kind: String,
    pub events: Vec<RuntimeEventEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEventEntry {
    pub event_id: String,
    pub event_type: String,
    pub emitted_at: String,
    pub truth_kind: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeHealthResult {
    pub truth_kind: String,
    pub daemon_readiness: String,
    pub authority_sync_health: String,
    pub authority_subject_status: String,
    pub authority_deny_reason: Option<String>,
    pub runtime_registry_health: String,
    pub path_manager_health: String,
    pub reconnect_subsystem_health: String,
    pub active_sessions: usize,
    pub active_paths: usize,
    pub active_listeners: usize,
    pub reconnect_state: String,
    pub reconnect_attempt_count: usize,
    pub reconnect_next_attempt_unix_secs: Option<u64>,
    pub reconnect_suppression_count: usize,
    pub runtime_event_buffer_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityShowResult {
    pub truth_kind: String,
    pub configured_origin: Option<String>,
    pub configured_subject: Option<String>,
    pub configured_snapshot: Option<String>,
    pub network: String,
    pub local_peer_id: String,
    pub membership_subject_peer_id: String,
    pub membership_issuer_peer_id: String,
    pub membership_roles: Vec<String>,
    pub grants: usize,
    pub revocations: usize,
    pub denied_peers: usize,
    pub bootstrap_hints: usize,
    pub relays: usize,
    pub schema_version: u64,
    pub authority: AuthoritySyncStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityMembershipResult {
    pub truth_kind: String,
    pub network: String,
    pub subject_peer_id: String,
    pub issuer_peer_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub roles: Vec<String>,
    pub schema_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityCapabilitiesResult {
    pub truth_kind: String,
    pub network: String,
    pub subject_peer_id: String,
    pub schema_version: u64,
    pub grants: Vec<AuthorityCapabilityGrantEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityCapabilityGrantEntry {
    pub subject_peer_id: String,
    pub issuer_peer_id: String,
    pub sequence: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub capabilities: Vec<String>,
    pub protocols: Vec<String>,
    pub bandwidth_bps: Option<u64>,
    pub concurrent_streams: Option<u32>,
    pub max_object_bytes: Option<u64>,
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityRevocationsResult {
    pub truth_kind: String,
    pub network: String,
    pub schema_version: u64,
    pub revocations: Vec<AuthorityRevocationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityRevocationEntry {
    pub sequence: u64,
    pub issuer_peer_id: String,
    pub effective_at: u64,
    pub reason: String,
    pub target: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritySyncSnapshotPayload {
    pub authority_snapshot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritySyncOriginPayload {
    pub authority_origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_subject: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritySyncRevocationsOriginPayload {
    pub authority_origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritySyncResult {
    pub truth_kind: String,
    pub authority_source: String,
    pub authority_origin: Option<String>,
    pub authority_subject: Option<String>,
    pub authority_snapshot: Option<String>,
    pub network: String,
    pub local_peer_id: String,
    pub grants_added: usize,
    pub grants_removed: usize,
    pub revocations_added: usize,
    pub bootstrap_hints_added: usize,
    pub bootstrap_hints_removed: usize,
    pub relay_announcements_added: usize,
    pub membership_changed: bool,
    pub authority: AuthoritySyncStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConnectPayload {
    pub peer_id: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_preference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConnectResult {
    pub truth_kind: String,
    pub session: SessionConnectSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConnectSummary {
    pub session_id: String,
    pub state: String,
    pub initial_path_class: String,
    pub state_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionClosePayload {
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCloseResult {
    pub truth_kind: String,
    pub closed_session_id: String,
    pub final_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionUpgradePayload {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionUpgradeResult {
    pub truth_kind: String,
    pub session_id: String,
    pub prior_path_class: String,
    pub resulting_path_class: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SessionReconcilePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionReconcileResult {
    pub truth_kind: String,
    pub examined: usize,
    pub unchanged: usize,
    pub upgraded: usize,
    pub closed: usize,
    pub entries: Vec<SessionReconcileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionReconcileEntry {
    pub session_id: String,
    pub peer_id: String,
    pub disposition: String,
    pub reason: String,
    pub path_class: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_envelope_serializes_success() {
        let response = ResponseEnvelope::success(
            "req-1",
            RuntimeSummary {
                session_count: 1,
                active_path_count: 1,
                reconnect_state: "idle".to_string(),
            },
        );

        let value = serde_json::to_value(response).expect("response should serialize");
        assert_eq!(value["ok"], serde_json::json!(true));
        assert_eq!(value["request_id"], serde_json::json!("req-1"));
    }
}
