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
pub struct IdentityShowResult {
    pub truth_kind: String,
    pub status: String,
    pub identity_path: String,
    pub node_id: String,
    pub public_key_hex: String,
    pub durable_state_peer_id: Option<String>,
    pub authority_subject_peer_id: Option<String>,
    pub state_binding_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityVerifyResult {
    pub truth_kind: String,
    pub identity_path: String,
    pub expected_node_id: Option<String>,
    pub loaded_node_id: String,
    pub authority_subject_peer_id: Option<String>,
    pub match_result: String,
    pub mismatch_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableStateViolationEntry {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableStateSummaryResult {
    pub network: String,
    pub local_peer_id: String,
    pub roles: Vec<String>,
    pub bootstrap_hints: usize,
    pub relays: usize,
    pub peers: usize,
    pub capability_grants: usize,
    pub revocations: usize,
    pub denied_peers: usize,
    pub path_candidates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateShowResult {
    pub truth_kind: String,
    pub state_path: String,
    pub present: bool,
    pub schema_version: Option<u64>,
    pub valid: bool,
    pub violations: Vec<DurableStateViolationEntry>,
    pub summary: Option<DurableStateSummaryResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateValidateResult {
    pub truth_kind: String,
    pub state_path: String,
    pub present: bool,
    pub schema_version: Option<u64>,
    pub valid: bool,
    pub violations: Vec<DurableStateViolationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateResetPayload {
    pub scope: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateExportPayload {
    pub output_path: String,
    pub passphrase: String,
    pub hostname: String,
    pub environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateResetResult {
    pub truth_kind: String,
    pub identity_preserved: bool,
    pub network_state_reset: bool,
    pub next_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateExportResult {
    pub truth_kind: String,
    pub bundle_path: String,
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
    pub degraded_sessions: usize,
    pub migrated_sessions: usize,
    pub unchanged_sessions: usize,
    pub reevaluated_listeners: usize,
    pub suppressed_listeners: usize,
    pub restored_listeners: usize,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuntimeDiagnosePayload {
    pub event_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDiagnoseResult {
    pub truth_kind: String,
    pub primary_classification: String,
    pub issues: Vec<RuntimeDiagnosisIssue>,
    pub status: RuntimeStatusResult,
    pub health: RuntimeHealthResult,
    pub state: StateShowResult,
    pub identity: IdentityVerifyResult,
    pub authority_show: AuthorityShowResult,
    pub sessions: Vec<RuntimeSessionEntry>,
    pub listeners: Vec<RuntimeListenerEntry>,
    pub paths: Vec<RuntimePathEntry>,
    pub events: Vec<RuntimeEventEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDiagnosisIssue {
    pub code: String,
    pub severity: String,
    pub layer: String,
    pub summary: String,
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
    pub state_reason: Option<String>,
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
    pub decision_reason: Option<String>,
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
    use serde_json::Value;

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

    #[test]
    fn daemon_fixtures_deserialize_and_schemas_expose_new_fields() {
        let status: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/runtime.status.response.json"
        ))
        .expect("status fixture should deserialize");
        assert!(status.ok);

        let sessions: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/runtime.sessions.list.response.json"
        ))
        .expect("sessions fixture should deserialize");
        assert!(sessions.ok);

        let listeners: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/runtime.listeners.list.response.json"
        ))
        .expect("listener fixture should deserialize");
        assert!(listeners.ok);

        let paths: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/runtime.paths.list.response.json"
        ))
        .expect("path fixture should deserialize");
        assert!(paths.ok);

        let events: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/runtime.events.list.response.json"
        ))
        .expect("events fixture should deserialize");
        assert!(events.ok);

        let health: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/runtime.health.response.json"
        ))
        .expect("health fixture should deserialize");
        assert!(health.ok);

        let diagnose: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/runtime.diagnose.response.json"
        ))
        .expect("diagnose fixture should deserialize");
        assert!(diagnose.ok);

        let sessions_result: RuntimeSessionsListResult = serde_json::from_value(
            sessions
                .result
                .clone()
                .expect("sessions result should exist"),
        )
        .expect("sessions result should deserialize");
        assert!(sessions_result.sessions.iter().any(|entry| {
            entry.state == "closed" && entry.closure_reason.as_deref() == Some("operator_requested")
        }));

        let status_result: RuntimeStatusResult =
            serde_json::from_value(status.result.clone().expect("status result should exist"))
                .expect("status result should deserialize");
        assert_eq!(status_result.truth_kind, "runtime");
        assert_eq!(status_result.authority.sync_status, "policy_enforced");
        assert!(status_result.authority.local_policy_denied);

        let health_result: RuntimeHealthResult =
            serde_json::from_value(health.result.clone().expect("health result should exist"))
                .expect("health result should deserialize");
        assert_eq!(health_result.authority_subject_status, "matched");
        assert_eq!(
            health_result.authority_deny_reason.as_deref(),
            Some("membership revoked")
        );
        let events_result: RuntimeEventsListResult =
            serde_json::from_value(events.result.clone().expect("events result should exist"))
                .expect("events result should deserialize");
        assert_eq!(events_result.events[0].truth_kind, "runtime");
        assert_eq!(events_result.events[0].subject_kind, "listener");

        let diagnose_result: RuntimeDiagnoseResult = serde_json::from_value(
            diagnose
                .result
                .clone()
                .expect("diagnose result should exist"),
        )
        .expect("diagnose result should deserialize");
        assert_eq!(diagnose_result.primary_classification, "mixed");
        assert!(diagnose_result
            .issues
            .iter()
            .any(|issue| issue.layer == "durable" && issue.code == "identity_mismatch"));
        assert!(diagnose_result
            .sessions
            .iter()
            .any(|entry| entry.state == "closed"));

        let authority_show: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/authority.show.response.json"
        ))
        .expect("authority show fixture should deserialize");
        assert!(authority_show.ok);
        let identity_show: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/identity.show.response.json"
        ))
        .expect("identity show fixture should deserialize");
        assert!(identity_show.ok);

        let identity_verify: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/identity.verify.response.json"
        ))
        .expect("identity verify fixture should deserialize");
        assert!(identity_verify.ok);
        let authority_show_result: AuthorityShowResult = serde_json::from_value(
            authority_show
                .result
                .clone()
                .expect("authority show result should exist"),
        )
        .expect("authority show result should deserialize");
        assert_eq!(authority_show_result.truth_kind, "runtime");
        assert_eq!(authority_show_result.authority.sync_status, "in_sync");

        let state_show: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/state.show.response.json"
        ))
        .expect("state show fixture should deserialize");
        assert!(state_show.ok);

        let state_export: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/state.export.response.json"
        ))
        .expect("state export fixture should deserialize");
        assert!(state_export.ok);

        let state_validate: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/state.validate.response.json"
        ))
        .expect("state validate fixture should deserialize");
        assert!(state_validate.ok);

        let state_reset: ResponseEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/state.reset.response.json"
        ))
        .expect("state reset fixture should deserialize");
        assert!(state_reset.ok);

        let listener_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/runtime.listeners.list.response.schema.json"
        ))
        .expect("listener schema should parse");
        let listener_state_enum = &listener_schema["allOf"][1]["properties"]["result"]
            ["properties"]["listeners"]["items"]["properties"]["state"]["enum"];
        assert!(listener_state_enum
            .as_array()
            .expect("listener state enum should be an array")
            .iter()
            .any(|value| value == "suppressed"));

        let path_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/runtime.paths.list.response.schema.json"
        ))
        .expect("path schema should parse");
        let path_state_enum = &path_schema["allOf"][1]["properties"]["result"]["properties"]
            ["paths"]["items"]["properties"]["state"]["enum"];
        assert!(path_state_enum
            .as_array()
            .expect("path state enum should be an array")
            .iter()
            .any(|value| value == "candidate"));
        assert!(
            path_schema["allOf"][1]["properties"]["result"]["properties"]["paths"]["items"]
                ["properties"]
                .get("decision_reason")
                .is_some()
        );

        let events_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/runtime.events.list.response.schema.json"
        ))
        .expect("events schema should parse");
        let event_type_enum = &events_schema["allOf"][1]["properties"]["result"]["properties"]
            ["events"]["items"]["properties"]["event_type"]["enum"];
        assert!(event_type_enum
            .as_array()
            .expect("event type enum should be an array")
            .iter()
            .any(|value| value == "reconnect.unsuppressed"));
        assert!(event_type_enum
            .as_array()
            .expect("event type enum should be an array")
            .iter()
            .any(|value| value == "reconnect.failed"));
        assert!(event_type_enum
            .as_array()
            .expect("event type enum should be an array")
            .iter()
            .any(|value| value == "path.migration_completed"));
        let event_subject_enum = &events_schema["allOf"][1]["properties"]["result"]["properties"]
            ["events"]["items"]["properties"]["subject_kind"]["enum"];
        assert!(event_subject_enum
            .as_array()
            .expect("event subject enum should be an array")
            .iter()
            .any(|value| value == "listener"));

        let health_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/runtime.health.response.schema.json"
        ))
        .expect("health schema should parse");
        assert!(
            health_schema["allOf"][1]["properties"]["result"]["properties"]
                .get("authority_subject_status")
                .is_some()
        );
        assert!(
            health_schema["allOf"][1]["properties"]["result"]["properties"]
                .get("authority_deny_reason")
                .is_some()
        );

        let status_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/runtime.status.response.schema.json"
        ))
        .expect("status schema should parse");
        let authority_sync_enum = &status_schema["allOf"][1]["properties"]["result"]["properties"]
            ["authority"]["properties"]["sync_status"]["enum"];
        assert!(authority_sync_enum
            .as_array()
            .expect("authority sync enum should be an array")
            .iter()
            .any(|value| value == "policy_enforced"));
        assert!(
            status_schema["allOf"][1]["properties"]["result"]["properties"]["authority"]
                ["properties"]
                .get("local_policy_denied")
                .is_some()
        );

        let diagnose_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/runtime.diagnose.response.schema.json"
        ))
        .expect("diagnose schema should parse");
        let classification_enum = &diagnose_schema["allOf"][1]["properties"]["result"]
            ["properties"]["primary_classification"]["enum"];
        assert!(classification_enum
            .as_array()
            .expect("classification enum should be an array")
            .iter()
            .any(|value| value == "mixed"));
        assert!(
            diagnose_schema["allOf"][1]["properties"]["result"]["properties"]
                .get("authority_show")
                .is_some()
        );

        let state_show_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/state.show.response.schema.json"
        ))
        .expect("state show schema should parse");
        assert_eq!(
            state_show_schema["allOf"][1]["properties"]["result"]["properties"]["truth_kind"]
                ["const"],
            serde_json::json!("durable")
        );

        let state_validate_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/state.validate.response.schema.json"
        ))
        .expect("state validate schema should parse");
        assert_eq!(
            state_validate_schema["allOf"][1]["properties"]["result"]["properties"]["state_path"]
                ["type"],
            serde_json::json!("string")
        );

        let state_reset_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/state.reset.response.schema.json"
        ))
        .expect("state reset schema should parse");
        assert_eq!(
            state_reset_schema["allOf"][1]["properties"]["result"]["properties"]
                ["network_state_reset"]["type"],
            serde_json::json!("boolean")
        );

        let state_export_schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/daemon/state.export.response.schema.json"
        ))
        .expect("state export schema should parse");
        assert_eq!(
            state_export_schema["allOf"][1]["properties"]["result"]["properties"]["truth_kind"]
                ["const"],
            serde_json::json!("durable")
        );
        assert_eq!(
            state_export_schema["allOf"][1]["properties"]["result"]["properties"]["bundle_path"]
                ["type"],
            serde_json::json!("string")
        );
    }
}
