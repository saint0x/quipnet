use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use async_trait::async_trait;
use crypto::{IdentityKeypair, SessionKeypair};
use model::NetworkId;
use rand::{rngs::OsRng, RngCore};
use relay::{HttpRelayControl, RelayControl};
use relaywire::RelayOpenRequest;
use serde_json::json;
use transport::{
    BindSpec, ConnectionHandle, ReconnectSuppression, RelayPlan, RoutePlan, RuntimeEvent,
    RuntimeEventSubject, RuntimeListenerSnapshot, RuntimeListenerState, RuntimeReconnectAttempt,
    RuntimeReconnectAttemptState, RuntimeReconnectState, RuntimeSessionState,
    RuntimeTransportHealth, SecureTransport, SessionClosureReason, SessionLifecycleTransport,
    SessionSnapshot, TransportError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicConnectionHandle {
    pub session: SessionSnapshot,
    pub alpn_protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicListenerHandle {
    pub protocol: String,
    pub advertise: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeSessionRecord {
    snapshot: SessionSnapshot,
    alpn_protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeListenerRecord {
    snapshot: RuntimeListenerSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeReconnectRecord {
    snapshot: RuntimeReconnectAttempt,
}

#[derive(Clone)]
pub struct QuicTransportAdapter {
    pub implementation: &'static str,
    pub supports_datagrams: bool,
    pub supports_path_migration: bool,
    pub runtime_instance_id: String,
    pub network_id: Option<NetworkId>,
    pub local_identity: Option<IdentityKeypair>,
    relay_control: Arc<dyn RelayControl>,
    runtime_sessions: Arc<RwLock<BTreeMap<[u8; 16], RuntimeSessionRecord>>>,
    runtime_listeners: Arc<RwLock<BTreeMap<String, RuntimeListenerRecord>>>,
    runtime_events: Arc<RwLock<VecDeque<RuntimeEvent>>>,
    reconnect_suppressions: Arc<RwLock<Vec<ReconnectSuppression>>>,
    reconnect_attempts: Arc<RwLock<Vec<RuntimeReconnectRecord>>>,
}

impl Default for QuicTransportAdapter {
    fn default() -> Self {
        Self {
            implementation: "adapter-placeholder",
            supports_datagrams: true,
            supports_path_migration: true,
            runtime_instance_id: random_runtime_instance_id(),
            network_id: None,
            local_identity: None,
            relay_control: Arc::new(HttpRelayControl),
            runtime_sessions: Arc::new(RwLock::new(BTreeMap::new())),
            runtime_listeners: Arc::new(RwLock::new(BTreeMap::new())),
            runtime_events: Arc::new(RwLock::new(VecDeque::new())),
            reconnect_suppressions: Arc::new(RwLock::new(Vec::new())),
            reconnect_attempts: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl QuicTransportAdapter {
    pub fn with_identity(network_id: NetworkId, local_identity: IdentityKeypair) -> Self {
        Self {
            network_id: Some(network_id),
            local_identity: Some(local_identity),
            ..Self::default()
        }
    }

    pub fn with_relay_control(mut self, relay_control: Arc<dyn RelayControl>) -> Self {
        self.relay_control = relay_control;
        self
    }

    pub fn owns_session(&self, session_id: &[u8; 16]) -> bool {
        self.runtime_sessions
            .read()
            .expect("runtime session registry should remain readable")
            .contains_key(session_id)
    }

    pub fn runtime_instance_id(&self) -> &str {
        &self.runtime_instance_id
    }
}

#[async_trait]
impl SecureTransport for QuicTransportAdapter {
    type Connection = QuicConnectionHandle;
    type Listener = QuicListenerHandle;

    async fn connect(&self, route: RoutePlan) -> Result<Self::Connection, TransportError> {
        if let Some(suppression) =
            find_reconnect_suppression(self, &route.peer, route.protocol.as_ref(), route.class)
        {
            emit_runtime_event(
                self,
                "reconnect.suppressed".to_string(),
                RuntimeEventSubject {
                    kind: "peer".to_string(),
                    id: route.peer.to_string(),
                },
                json!({
                    "protocol": route.protocol.as_ref().map(|protocol| protocol.as_str()),
                    "class": route.class_string(),
                    "reason": suppression.reason
                }),
            );
            return Err(TransportError::PolicyDenied(format!(
                "reconnect suppressed: {}",
                suppression.reason
            )));
        }
        let session = session_snapshot_for_route(self, &route)?;
        let alpn_protocol = route.protocol.map(|id| id.as_str().to_string());
        let record = RuntimeSessionRecord {
            snapshot: session.clone(),
            alpn_protocol: alpn_protocol.clone(),
        };
        upsert_runtime_session(self, record)?;
        Ok(QuicConnectionHandle {
            session,
            alpn_protocol,
        })
    }

    async fn listen(&self, bind: BindSpec) -> Result<Self::Listener, TransportError> {
        let handle = QuicListenerHandle {
            protocol: bind.protocol.as_str().to_string(),
            advertise: bind.advertise,
        };
        upsert_runtime_listener(
            self,
            RuntimeListenerRecord {
                snapshot: RuntimeListenerSnapshot {
                    listener_id: runtime_listener_id(&self.runtime_instance_id, &bind),
                    transport: "quic".to_string(),
                    bind_summary: format!(
                        "protocol={} advertise={} runtime_instance={}",
                        bind.protocol.as_str(),
                        bind.advertise,
                        self.runtime_instance_id
                    ),
                    protocol: bind.protocol,
                    advertise: bind.advertise,
                    state: RuntimeListenerState::Active,
                    state_reason: None,
                    started_at_unix_secs: current_unix_secs(),
                },
            },
        )?;
        Ok(handle)
    }
}

#[async_trait]
impl SessionLifecycleTransport for QuicTransportAdapter {
    fn active_sessions(&self) -> Result<Vec<SessionSnapshot>, TransportError> {
        Ok(self
            .runtime_sessions
            .read()
            .expect("runtime session registry should remain readable")
            .values()
            .map(|record| record.snapshot.clone())
            .collect())
    }

    fn session_snapshot(
        &self,
        session_id: &[u8; 16],
    ) -> Result<Option<SessionSnapshot>, TransportError> {
        Ok(self
            .runtime_sessions
            .read()
            .expect("runtime session registry should remain readable")
            .get(session_id)
            .map(|record| record.snapshot.clone()))
    }

    fn update_session_state(
        &self,
        session_id: &[u8; 16],
        state: RuntimeSessionState,
        closure_reason: Option<SessionClosureReason>,
        state_reason: Option<String>,
    ) -> Result<Option<SessionSnapshot>, TransportError> {
        let mut sessions = self
            .runtime_sessions
            .write()
            .expect("runtime session registry should remain writable");
        let Some(record) = sessions.get_mut(session_id) else {
            return Ok(None);
        };
        let prior_state = record.snapshot.state.clone();
        record.snapshot.state = state.clone();
        record.snapshot.closure_reason = closure_reason.clone();
        record.snapshot.state_reason = state_reason.clone();
        record.snapshot.last_activity_unix_secs = current_unix_secs();
        let snapshot = record.snapshot.clone();
        drop(sessions);
        emit_runtime_event(
            self,
            runtime_event_type_for_state(&state).to_string(),
            RuntimeEventSubject {
                kind: "session".to_string(),
                id: hex_session_id(&snapshot.session_id),
            },
            json!({
                "peer_id": snapshot.peer.to_string(),
                "prior_state": runtime_session_state_label(&prior_state),
                "next_state": runtime_session_state_label(&snapshot.state),
                "closure_reason": closure_reason.as_ref().map(session_closure_reason_label),
                "reason": state_reason
            }),
        );
        Ok(Some(snapshot))
    }

    fn recent_events(&self, limit: usize) -> Result<Vec<RuntimeEvent>, TransportError> {
        let events = self
            .runtime_events
            .read()
            .expect("runtime event buffer should remain readable");
        let count = limit.max(1).min(events.len());
        Ok(events
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect())
    }

    fn suppress_reconnect(
        &self,
        peer: &model::PeerId,
        protocol: Option<&model::ProtocolId>,
        class: model::TrafficClass,
        reason: String,
    ) -> Result<(), TransportError> {
        let mut suppressions = self
            .reconnect_suppressions
            .write()
            .expect("reconnect suppression registry should remain writable");
        if let Some(existing) = suppressions.iter_mut().find(|entry| {
            &entry.peer == peer && entry.protocol.as_ref() == protocol && entry.class == class
        }) {
            existing.reason = reason.clone();
            existing.imposed_at_unix_secs = current_unix_secs();
        } else {
            suppressions.push(ReconnectSuppression {
                peer: peer.clone(),
                protocol: protocol.cloned(),
                class,
                reason: reason.clone(),
                imposed_at_unix_secs: current_unix_secs(),
            });
        }
        drop(suppressions);
        emit_runtime_event(
            self,
            "reconnect.suppressed".to_string(),
            RuntimeEventSubject {
                kind: "peer".to_string(),
                id: peer.to_string(),
            },
            json!({
                "protocol": protocol.map(|protocol| protocol.as_str()),
                "class": class_label(class),
                "reason": reason
            }),
        );
        Ok(())
    }

    fn clear_reconnect_suppression(
        &self,
        peer: &model::PeerId,
        protocol: Option<&model::ProtocolId>,
        class: model::TrafficClass,
    ) -> Result<(), TransportError> {
        let mut suppressions = self
            .reconnect_suppressions
            .write()
            .expect("reconnect suppression registry should remain writable");
        let removed = suppressions
            .iter()
            .find(|entry| {
                &entry.peer == peer && entry.protocol.as_ref() == protocol && entry.class == class
            })
            .cloned();
        suppressions.retain(|entry| {
            !(&entry.peer == peer && entry.protocol.as_ref() == protocol && entry.class == class)
        });
        drop(suppressions);
        if let Some(removed) = removed {
            emit_runtime_event(
                self,
                "reconnect.unsuppressed".to_string(),
                RuntimeEventSubject {
                    kind: "peer".to_string(),
                    id: peer.to_string(),
                },
                json!({
                    "protocol": protocol.map(|protocol| protocol.as_str()),
                    "class": class_label(class),
                    "prior_reason": removed.reason,
                    "imposed_at_unix_secs": removed.imposed_at_unix_secs
                }),
            );
        }
        Ok(())
    }

    fn reconnect_suppressions(&self) -> Result<Vec<ReconnectSuppression>, TransportError> {
        Ok(self
            .reconnect_suppressions
            .read()
            .expect("reconnect suppression registry should remain readable")
            .clone())
    }

    fn active_listeners(&self) -> Result<Vec<RuntimeListenerSnapshot>, TransportError> {
        Ok(self
            .runtime_listeners
            .read()
            .expect("runtime listener registry should remain readable")
            .values()
            .map(|record| record.snapshot.clone())
            .collect())
    }

    fn update_listener_state(
        &self,
        listener_id: &str,
        state: RuntimeListenerState,
        state_reason: Option<String>,
    ) -> Result<Option<RuntimeListenerSnapshot>, TransportError> {
        let mut listeners = self
            .runtime_listeners
            .write()
            .expect("runtime listener registry should remain writable");
        let Some(record) = listeners.get_mut(listener_id) else {
            return Ok(None);
        };
        record.snapshot.state = state;
        record.snapshot.state_reason = state_reason;
        Ok(Some(record.snapshot.clone()))
    }

    fn transport_health(&self) -> Result<RuntimeTransportHealth, TransportError> {
        let active_sessions = self
            .runtime_sessions
            .read()
            .expect("runtime session registry should remain readable")
            .len();
        let active_listeners = self
            .runtime_listeners
            .read()
            .expect("runtime listener registry should remain readable")
            .values()
            .filter(|record| record.snapshot.state == RuntimeListenerState::Active)
            .count();
        let reconnect_suppression_count = self
            .reconnect_suppressions
            .read()
            .expect("reconnect suppression registry should remain readable")
            .len();
        let reconnect_attempts = self
            .reconnect_attempts
            .read()
            .expect("reconnect attempt registry should remain readable")
            .clone();
        let event_buffer_depth = self
            .runtime_events
            .read()
            .expect("runtime event buffer should remain readable")
            .len();
        let reconnect_attempt_count = reconnect_attempts
            .iter()
            .filter(|entry| entry.snapshot.state == RuntimeReconnectAttemptState::BackingOff)
            .count();
        let reconnect_next_attempt_unix_secs = reconnect_attempts
            .iter()
            .filter(|entry| entry.snapshot.state == RuntimeReconnectAttemptState::BackingOff)
            .map(|entry| entry.snapshot.next_attempt_unix_secs)
            .min();
        Ok(RuntimeTransportHealth {
            active_sessions,
            active_listeners,
            reconnect_state: if reconnect_suppression_count > 0 {
                RuntimeReconnectState::Suppressed
            } else if reconnect_attempt_count > 0 {
                RuntimeReconnectState::Active
            } else if reconnect_attempts
                .iter()
                .any(|entry| entry.snapshot.state == RuntimeReconnectAttemptState::Failed)
            {
                RuntimeReconnectState::Failed
            } else {
                RuntimeReconnectState::Idle
            },
            reconnect_attempt_count,
            reconnect_next_attempt_unix_secs,
            reconnect_suppression_count,
            event_buffer_depth,
            session_registry_healthy: true,
            listener_registry_healthy: true,
        })
    }

    fn reconnect_attempts(&self) -> Result<Vec<RuntimeReconnectAttempt>, TransportError> {
        Ok(self
            .reconnect_attempts
            .read()
            .expect("reconnect attempt registry should remain readable")
            .iter()
            .map(|entry| entry.snapshot.clone())
            .collect())
    }

    fn schedule_reconnect(
        &self,
        peer: &model::PeerId,
        protocol: Option<&model::ProtocolId>,
        class: model::TrafficClass,
        reason: String,
        max_attempts: u32,
        base_backoff_secs: u64,
        max_backoff_secs: u64,
    ) -> Result<RuntimeReconnectAttempt, TransportError> {
        let now = current_unix_secs();
        let mut attempts = self
            .reconnect_attempts
            .write()
            .expect("reconnect attempt registry should remain writable");
        let snapshot = if let Some(existing) = attempts.iter_mut().find(|entry| {
            &entry.snapshot.peer == peer
                && entry.snapshot.protocol.as_ref() == protocol
                && entry.snapshot.class == class
        }) {
            existing.snapshot.attempt_count += 1;
            existing.snapshot.reason = reason.clone();
            existing.snapshot.last_attempt_unix_secs = now;
            existing.snapshot.state = if existing.snapshot.attempt_count >= max_attempts {
                RuntimeReconnectAttemptState::Failed
            } else {
                RuntimeReconnectAttemptState::BackingOff
            };
            let exp = existing.snapshot.attempt_count.saturating_sub(1).min(16);
            let backoff = base_backoff_secs
                .saturating_mul(1_u64 << exp)
                .min(max_backoff_secs);
            existing.snapshot.next_attempt_unix_secs = now.saturating_add(backoff);
            existing.snapshot.max_attempts = max_attempts;
            existing.snapshot.clone()
        } else {
            let initial_backoff = base_backoff_secs.min(max_backoff_secs);
            let snapshot = RuntimeReconnectAttempt {
                peer: peer.clone(),
                protocol: protocol.cloned(),
                class,
                state: if max_attempts <= 1 {
                    RuntimeReconnectAttemptState::Failed
                } else {
                    RuntimeReconnectAttemptState::BackingOff
                },
                reason: reason.clone(),
                attempt_count: 1,
                last_attempt_unix_secs: now,
                next_attempt_unix_secs: now.saturating_add(initial_backoff),
                max_attempts,
            };
            attempts.push(RuntimeReconnectRecord {
                snapshot: snapshot.clone(),
            });
            snapshot
        };
        drop(attempts);
        let backoff_secs = snapshot
            .next_attempt_unix_secs
            .saturating_sub(snapshot.last_attempt_unix_secs);
        emit_runtime_event(
            self,
            if snapshot.state == RuntimeReconnectAttemptState::Failed {
                "reconnect.failed".to_string()
            } else {
                "reconnect.retry_scheduled".to_string()
            },
            RuntimeEventSubject {
                kind: "peer".to_string(),
                id: peer.to_string(),
            },
            json!({
                "protocol": protocol.map(|protocol| protocol.as_str()),
                "class": class_label(class),
                "state": reconnect_attempt_state_label(&snapshot.state),
                "attempt_count": snapshot.attempt_count,
                "next_attempt_unix_secs": snapshot.next_attempt_unix_secs,
                "backoff_secs": backoff_secs,
                "max_attempts": snapshot.max_attempts,
                "reason": snapshot.reason
            }),
        );
        Ok(snapshot)
    }

    fn clear_reconnect_attempt(
        &self,
        peer: &model::PeerId,
        protocol: Option<&model::ProtocolId>,
        class: model::TrafficClass,
        outcome_reason: Option<String>,
    ) -> Result<(), TransportError> {
        let mut attempts = self
            .reconnect_attempts
            .write()
            .expect("reconnect attempt registry should remain writable");
        let removed = attempts
            .iter()
            .find(|entry| {
                &entry.snapshot.peer == peer
                    && entry.snapshot.protocol.as_ref() == protocol
                    && entry.snapshot.class == class
            })
            .map(|entry| entry.snapshot.clone());
        attempts.retain(|entry| {
            !(&entry.snapshot.peer == peer
                && entry.snapshot.protocol.as_ref() == protocol
                && entry.snapshot.class == class)
        });
        drop(attempts);
        if let Some(snapshot) = removed {
            let event_type = outcome_reason
                .as_deref()
                .map(|reason| {
                    if reason.contains("succeeded") || reason.contains("active") {
                        "reconnect.succeeded"
                    } else {
                        "reconnect.cleared"
                    }
                })
                .unwrap_or("reconnect.cleared");
            emit_runtime_event(
                self,
                event_type.to_string(),
                RuntimeEventSubject {
                    kind: "peer".to_string(),
                    id: peer.to_string(),
                },
                json!({
                    "protocol": protocol.map(|protocol| protocol.as_str()),
                    "class": class_label(class),
                    "state": reconnect_attempt_state_label(&snapshot.state),
                    "attempt_count": snapshot.attempt_count,
                    "reason": outcome_reason
                }),
            );
        }
        Ok(())
    }

    fn record_runtime_event(
        &self,
        event_type: &str,
        subject: RuntimeEventSubject,
        details: serde_json::Value,
    ) -> Result<(), TransportError> {
        emit_runtime_event(self, event_type.to_string(), subject, details);
        Ok(())
    }

    async fn migrate(
        &self,
        session: &SessionSnapshot,
        route: RoutePlan,
    ) -> Result<SessionSnapshot, TransportError> {
        let _ = self.update_session_state(
            &session.session_id,
            RuntimeSessionState::Migrating,
            None,
            Some("daemon requested path migration".to_string()),
        )?;
        let existing = self.session_snapshot(&session.session_id)?.ok_or_else(|| {
            TransportError::InvalidRoute("session is not active in runtime registry".into())
        })?;
        let mut migrated = session_snapshot_for_route(self, &route)?;
        let previous_transport_session_id = existing.transport_session_id;
        let previous_control_endpoint = existing.relay_control_endpoint.clone();
        let previous_path_kind = existing.path_kind;

        migrated.session_id = existing.session_id;
        migrated.created_at_unix_secs = existing.created_at_unix_secs;
        migrated.last_activity_unix_secs = current_unix_secs();

        if previous_path_kind == model::PathKind::Relay
            && (migrated.path_kind != model::PathKind::Relay
                || migrated.transport_session_id != previous_transport_session_id
                || migrated.relay_control_endpoint != previous_control_endpoint)
        {
            close_relay_transport_session(
                &*self.relay_control,
                previous_control_endpoint.as_deref(),
                previous_transport_session_id,
            )?;
        }

        upsert_runtime_session(
            self,
            RuntimeSessionRecord {
                snapshot: migrated.clone(),
                alpn_protocol: route.protocol.map(|id| id.as_str().to_string()),
            },
        )?;
        emit_runtime_event(
            self,
            "path.migration_completed".to_string(),
            RuntimeEventSubject {
                kind: "session".to_string(),
                id: hex_session_id(&migrated.session_id),
            },
            json!({
                "peer_id": migrated.peer.to_string(),
                "prior_path_class": path_class_label(previous_path_kind),
                "next_path_class": path_class_label(migrated.path_kind)
            }),
        );
        Ok(migrated)
    }

    async fn close_session(&self, session: &SessionSnapshot) -> Result<(), TransportError> {
        let _ = self.update_session_state(
            &session.session_id,
            RuntimeSessionState::Closing,
            session.closure_reason.clone(),
            session.state_reason.clone(),
        )?;
        let Some(active) = remove_runtime_session(self, &session.session_id)? else {
            return Ok(());
        };
        let session = active.snapshot;
        if session.path_kind == model::PathKind::Relay {
            close_relay_transport_session(
                &*self.relay_control,
                session.relay_control_endpoint.as_deref(),
                session.transport_session_id,
            )?;
        }
        emit_runtime_event(
            self,
            "session.closed".to_string(),
            RuntimeEventSubject {
                kind: "session".to_string(),
                id: hex_session_id(&session.session_id),
            },
            json!({
                "peer_id": session.peer.to_string(),
                "prior_state": runtime_session_state_label(&RuntimeSessionState::Closing),
                "next_state": runtime_session_state_label(&RuntimeSessionState::Closed),
                "closure_reason": session.closure_reason.as_ref().map(session_closure_reason_label),
                "reason": session.state_reason
            }),
        );
        Ok(())
    }
}

impl ConnectionHandle for QuicConnectionHandle {
    fn snapshot(&self) -> SessionSnapshot {
        self.session.clone()
    }
}

fn session_snapshot_for_route(
    adapter: &QuicTransportAdapter,
    route: &RoutePlan,
) -> Result<SessionSnapshot, TransportError> {
    match &route.relay {
        Some(relay) => relay_session_snapshot(adapter, route, relay),
        None => direct_session_snapshot(adapter, route),
    }
}

fn direct_session_snapshot(
    adapter: &QuicTransportAdapter,
    route: &RoutePlan,
) -> Result<SessionSnapshot, TransportError> {
    let local_identity = adapter.local_identity.as_ref().ok_or_else(|| {
        TransportError::InvalidRoute("direct route requires local identity".into())
    })?;
    if local_identity.peer_id() != route.local_peer {
        return Err(TransportError::InvalidRoute(
            "local identity peer does not match route local peer".into(),
        ));
    }
    let remote_endpoint = route
        .remote_endpoints
        .first()
        .cloned()
        .ok_or_else(|| TransportError::NoRoute(route.peer.clone()))?;
    let now = current_unix_secs();
    let session_id = logical_session_id(&adapter.runtime_instance_id, route);
    Ok(SessionSnapshot {
        session_id,
        transport_session_id: session_id,
        relay_attempt_id: None,
        peer: route.peer.clone(),
        protocol: route.protocol.clone(),
        class: route.class,
        path_kind: route.path_kind,
        source: route.source.clone(),
        remote_endpoint,
        relay_peer: None,
        relay_endpoint: None,
        relay_control_endpoint: None,
        datagrams_capable: adapter.supports_datagrams,
        migration_capable: adapter.supports_path_migration,
        state: RuntimeSessionState::Active,
        closure_reason: None,
        state_reason: None,
        created_at_unix_secs: now,
        last_activity_unix_secs: now,
    })
}

fn relay_session_snapshot(
    adapter: &QuicTransportAdapter,
    route: &RoutePlan,
    relay: &RelayPlan,
) -> Result<SessionSnapshot, TransportError> {
    let network_id = adapter.network_id.clone().ok_or_else(|| {
        TransportError::InvalidRoute("relay route requires network identity".into())
    })?;
    let local_identity = adapter.local_identity.as_ref().ok_or_else(|| {
        TransportError::InvalidRoute("relay route requires local identity".into())
    })?;
    if local_identity.peer_id() != route.local_peer {
        return Err(TransportError::InvalidRoute(
            "local identity peer does not match route local peer".into(),
        ));
    }
    let mut rng = OsRng;
    let session_key = SessionKeypair::generate(&mut rng);
    let credential = identity::SessionCredential::issue(
        network_id.clone(),
        local_identity,
        session_key.public_key_bytes(),
        route
            .protocol
            .as_ref()
            .map(|protocol| vec![protocol.as_str().to_string()])
            .unwrap_or_else(|| vec!["/quicnet/relay/1".to_string()]),
        300,
        1,
    );
    let attempt_id = random_attempt_id();
    let relay_endpoint =
        relay.relay_endpoints.first().cloned().ok_or_else(|| {
            TransportError::InvalidRoute("relay route has no relay endpoints".into())
        })?;
    let accepted = adapter
        .relay_control
        .open_session(
            &relay.relay_control_endpoint,
            RelayOpenRequest {
                attempt_id,
                network_id,
                source: route.local_peer.clone(),
                source_public_key: local_identity.public_key(),
                source_credential: credential,
                destination: route.peer.clone(),
                protocol: route.protocol.clone(),
                traffic_class: route.class,
            },
        )
        .map_err(|error| TransportError::RelayRejected(error.to_string()))?;
    let remote_endpoint = relay
        .destination_endpoints
        .first()
        .cloned()
        .or_else(|| route.remote_endpoints.first().cloned())
        .unwrap_or_else(|| route.peer.to_string());
    let now = current_unix_secs();
    let session_id = logical_session_id(&adapter.runtime_instance_id, route);
    Ok(SessionSnapshot {
        session_id,
        transport_session_id: accepted.session_id,
        relay_attempt_id: Some(accepted.attempt_id),
        peer: route.peer.clone(),
        protocol: route.protocol.clone(),
        class: route.class,
        path_kind: route.path_kind,
        source: route.source.clone(),
        remote_endpoint,
        relay_peer: Some(relay.relay_peer.clone()),
        relay_endpoint: Some(relay_endpoint),
        relay_control_endpoint: Some(relay.relay_control_endpoint.clone()),
        datagrams_capable: adapter.supports_datagrams && relay.supports_datagrams,
        migration_capable: adapter.supports_path_migration && relay.supports_path_migration,
        state: RuntimeSessionState::Active,
        closure_reason: None,
        state_reason: None,
        created_at_unix_secs: now,
        last_activity_unix_secs: now,
    })
}

fn random_attempt_id() -> [u8; 16] {
    let mut attempt_id = [0_u8; 16];
    OsRng.fill_bytes(&mut attempt_id);
    attempt_id
}

fn logical_session_id(runtime_instance_id: &str, route: &RoutePlan) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(runtime_instance_id.as_bytes());
    hasher.update(route.local_peer.as_bytes());
    hasher.update(route.peer.as_bytes());
    hasher.update(route.class_string().as_bytes());
    if let Some(protocol) = &route.protocol {
        hasher.update(protocol.as_str().as_bytes());
    }
    let digest = hasher.finalize();
    let mut session_id = [0_u8; 16];
    session_id.copy_from_slice(&digest.as_bytes()[..16]);
    session_id
}

fn random_runtime_instance_id() -> String {
    let mut runtime_instance_id = [0_u8; 16];
    OsRng.fill_bytes(&mut runtime_instance_id);
    runtime_instance_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn upsert_runtime_session(
    adapter: &QuicTransportAdapter,
    record: RuntimeSessionRecord,
) -> Result<(), TransportError> {
    let session_id = record.snapshot.session_id;
    let event_details = json!({
        "peer_id": record.snapshot.peer.to_string(),
        "next_state": runtime_session_state_label(&record.snapshot.state),
        "path_class": path_class_label(record.snapshot.path_kind)
    });
    let mut sessions = adapter
        .runtime_sessions
        .write()
        .expect("runtime session registry should remain writable");
    let previous = sessions.insert(session_id, record.clone());
    drop(sessions);
    if let Some(previous) = previous {
        if previous.snapshot.path_kind == model::PathKind::Relay
            && (previous.snapshot.transport_session_id != record.snapshot.transport_session_id
                || previous.snapshot.relay_control_endpoint
                    != record.snapshot.relay_control_endpoint
                || record.snapshot.path_kind != model::PathKind::Relay)
        {
            close_relay_transport_session(
                &*adapter.relay_control,
                previous.snapshot.relay_control_endpoint.as_deref(),
                previous.snapshot.transport_session_id,
            )?;
        }
        emit_runtime_event(
            adapter,
            "session.state_changed".to_string(),
            RuntimeEventSubject {
                kind: "session".to_string(),
                id: hex_session_id(&session_id),
            },
            json!({
                "peer_id": record.snapshot.peer.to_string(),
                "prior_state": runtime_session_state_label(&previous.snapshot.state),
                "next_state": runtime_session_state_label(&record.snapshot.state),
                "path_class": path_class_label(record.snapshot.path_kind)
            }),
        );
    } else {
        emit_runtime_event(
            adapter,
            "session.created".to_string(),
            RuntimeEventSubject {
                kind: "session".to_string(),
                id: hex_session_id(&session_id),
            },
            event_details,
        );
        emit_runtime_event(
            adapter,
            "path.selected".to_string(),
            RuntimeEventSubject {
                kind: "session".to_string(),
                id: hex_session_id(&session_id),
            },
            json!({
                "peer_id": record.snapshot.peer.to_string(),
                "path_class": path_class_label(record.snapshot.path_kind),
                "source": format!("{:?}", record.snapshot.source)
            }),
        );
    }
    Ok(())
}

fn remove_runtime_session(
    adapter: &QuicTransportAdapter,
    session_id: &[u8; 16],
) -> Result<Option<RuntimeSessionRecord>, TransportError> {
    Ok(adapter
        .runtime_sessions
        .write()
        .expect("runtime session registry should remain writable")
        .remove(session_id))
}

fn upsert_runtime_listener(
    adapter: &QuicTransportAdapter,
    record: RuntimeListenerRecord,
) -> Result<(), TransportError> {
    adapter
        .runtime_listeners
        .write()
        .expect("runtime listener registry should remain writable")
        .insert(record.snapshot.listener_id.clone(), record);
    Ok(())
}

fn close_relay_transport_session(
    relay_control: &dyn RelayControl,
    control_endpoint: Option<&str>,
    transport_session_id: [u8; 16],
) -> Result<(), TransportError> {
    let endpoint = control_endpoint.ok_or_else(|| {
        TransportError::InvalidRoute("relay session is missing relay control endpoint".into())
    })?;
    relay_control
        .close_session(endpoint, transport_session_id, "path migrated".into())
        .map_err(|error| TransportError::RelayRejected(error.to_string()))
}

fn emit_runtime_event(
    adapter: &QuicTransportAdapter,
    event_type: String,
    subject: RuntimeEventSubject,
    details: serde_json::Value,
) {
    let mut events = adapter
        .runtime_events
        .write()
        .expect("runtime event buffer should remain writable");
    events.push_back(RuntimeEvent {
        event_id: format!("evt-{}", current_unix_nanos()),
        event_type,
        emitted_at: current_rfc3339(),
        truth_kind: "runtime".to_string(),
        subject,
        details,
    });
    while events.len() > 256 {
        events.pop_front();
    }
}

fn find_reconnect_suppression(
    adapter: &QuicTransportAdapter,
    peer: &model::PeerId,
    protocol: Option<&model::ProtocolId>,
    class: model::TrafficClass,
) -> Option<ReconnectSuppression> {
    adapter
        .reconnect_suppressions
        .read()
        .expect("reconnect suppression registry should remain readable")
        .iter()
        .find(|entry| {
            &entry.peer == peer && entry.protocol.as_ref() == protocol && entry.class == class
        })
        .cloned()
}

fn reconnect_attempt_state_label(state: &RuntimeReconnectAttemptState) -> &'static str {
    match state {
        RuntimeReconnectAttemptState::BackingOff => "backing_off",
        RuntimeReconnectAttemptState::Failed => "failed",
    }
}

fn runtime_event_type_for_state(state: &RuntimeSessionState) -> &'static str {
    match state {
        RuntimeSessionState::Closing => "session.closing",
        RuntimeSessionState::Failed => "session.failed",
        _ => "session.state_changed",
    }
}

fn runtime_session_state_label(state: &RuntimeSessionState) -> &'static str {
    match state {
        RuntimeSessionState::Pending => "pending",
        RuntimeSessionState::Connecting => "connecting",
        RuntimeSessionState::Active => "active",
        RuntimeSessionState::Degraded => "degraded",
        RuntimeSessionState::Migrating => "migrating",
        RuntimeSessionState::Reconciling => "reconciling",
        RuntimeSessionState::Closing => "closing",
        RuntimeSessionState::Closed => "closed",
        RuntimeSessionState::Failed => "failed",
    }
}

fn session_closure_reason_label(reason: &SessionClosureReason) -> &'static str {
    match reason {
        SessionClosureReason::OperatorRequested => "operator_requested",
        SessionClosureReason::LocalRuntimeFailure => "local_runtime_failure",
        SessionClosureReason::RemoteFailure => "remote_failure",
        SessionClosureReason::PolicyRejected => "policy_rejected",
        SessionClosureReason::PathExhaustion => "path_exhaustion",
        SessionClosureReason::DaemonShutdown => "daemon_shutdown",
    }
}

fn path_class_label(path_kind: model::PathKind) -> &'static str {
    match path_kind {
        model::PathKind::Relay => "relay",
        _ => "direct",
    }
}

fn class_label(class: model::TrafficClass) -> &'static str {
    match class {
        model::TrafficClass::Control => "control",
        model::TrafficClass::Interactive => "interactive",
        model::TrafficClass::Bulk => "bulk",
        model::TrafficClass::Background => "background",
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs()
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos()
}

fn current_rfc3339() -> String {
    format!("{}Z", iso8601_seconds(current_unix_secs()))
}

fn hex_session_id(session_id: &[u8; 16]) -> String {
    session_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn runtime_listener_id(runtime_instance_id: &str, bind: &BindSpec) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(runtime_instance_id.as_bytes());
    hasher.update(bind.protocol.as_str().as_bytes());
    hasher.update(if bind.advertise { b"1" } else { b"0" });
    hasher.update(current_unix_nanos().to_string().as_bytes());
    format!("lst-{}", &hasher.finalize().to_hex()[..16])
}

fn iso8601_seconds(epoch_secs: u64) -> String {
    let datetime = chrono_like::DateTime::from_unix(epoch_secs as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        datetime.year,
        datetime.month,
        datetime.day,
        datetime.hour,
        datetime.minute,
        datetime.second
    )
}

mod chrono_like {
    pub struct DateTime {
        pub year: i32,
        pub month: u32,
        pub day: u32,
        pub hour: u32,
        pub minute: u32,
        pub second: u32,
    }

    impl DateTime {
        pub fn from_unix(epoch_secs: i64) -> Self {
            let days = epoch_secs.div_euclid(86_400);
            let seconds = epoch_secs.rem_euclid(86_400);
            let (year, month, day) = civil_from_days(days);
            Self {
                year,
                month,
                day,
                hour: (seconds / 3_600) as u32,
                minute: ((seconds % 3_600) / 60) as u32,
                second: (seconds % 60) as u32,
            }
        }
    }

    fn civil_from_days(days: i64) -> (i32, u32, u32) {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = mp + if mp < 10 { 3 } else { -9 };
        let year = y + if m <= 2 { 1 } else { 0 };
        (year as i32, m as u32, d as u32)
    }
}

trait RoutePlanExt {
    fn class_string(&self) -> &'static str;
}

impl RoutePlanExt for RoutePlan {
    fn class_string(&self) -> &'static str {
        match self.class {
            model::TrafficClass::Control => "control",
            model::TrafficClass::Interactive => "interactive",
            model::TrafficClass::Bulk => "bulk",
            model::TrafficClass::Background => "background",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use model::{KeyAlgorithm, PathKind, PeerId, ProtocolId, TrafficClass};
    use relay::{
        clear_registry, register_relay, registered_session_count, InProcessRelayControl, RelayNode,
        RelayQuota, RelayService,
    };
    use transport::{BindSpec, RoutePlan, RouteSource, SecureTransport, SessionLifecycleTransport};

    use super::*;

    fn relay_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("relay test lock")
    }

    #[tokio::test]
    async fn adapter_returns_connection_metadata() {
        let local_identity = IdentityKeypair::from_secret_bytes([60_u8; 32]);
        let local = local_identity.peer_id();
        let adapter =
            QuicTransportAdapter::with_identity(NetworkId::derive("direct-test"), local_identity);
        let peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"peer");
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();
        let handle = adapter
            .connect(RoutePlan {
                local_peer: local,
                peer: peer.clone(),
                protocol: Some(protocol),
                class: TrafficClass::Control,
                path_kind: PathKind::DirectUdp,
                source: RouteSource::Observed,
                remote_endpoints: vec!["quic://198.51.100.10:8443".to_string()],
                relay: None,
            })
            .await
            .unwrap();

        assert_eq!(handle.session.peer, peer);
        assert!(handle.session.migration_capable);
        assert!(handle.session.relay_peer.is_none());
        assert_eq!(handle.session.state, RuntimeSessionState::Active);
        assert!(adapter.owns_session(&handle.session.session_id));
    }

    #[tokio::test]
    async fn adapter_rejects_direct_route_when_local_identity_mismatches() {
        let local_identity = IdentityKeypair::from_secret_bytes([59_u8; 32]);
        let adapter =
            QuicTransportAdapter::with_identity(NetworkId::derive("direct-test"), local_identity);
        let error = adapter
            .connect(RoutePlan {
                local_peer: PeerId::from_public_key(KeyAlgorithm::Ed25519, b"other-local"),
                peer: PeerId::from_public_key(KeyAlgorithm::Ed25519, b"peer"),
                protocol: Some(ProtocolId::new("/quicnet/control/1").unwrap()),
                class: TrafficClass::Control,
                path_kind: PathKind::DirectUdp,
                source: RouteSource::Observed,
                remote_endpoints: vec!["quic://198.51.100.10:8443".to_string()],
                relay: None,
            })
            .await
            .expect_err("mismatched direct identity should fail");

        assert!(error
            .to_string()
            .contains("local identity peer does not match route local peer"));
    }

    #[tokio::test]
    async fn adapter_returns_listener_metadata() {
        let adapter = QuicTransportAdapter::default();
        let protocol = ProtocolId::new("/quicnet/relay/1").unwrap();
        let handle = adapter
            .listen(BindSpec {
                protocol,
                advertise: true,
            })
            .await
            .unwrap();

        assert_eq!(handle.protocol, "/quicnet/relay/1");
        assert!(handle.advertise);
        let listeners = adapter
            .active_listeners()
            .expect("listener registry should load");
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].transport, "quic");
        assert_eq!(listeners[0].protocol.as_str(), "/quicnet/relay/1");
        assert_eq!(listeners[0].state, RuntimeListenerState::Active);
        assert!(listeners[0]
            .bind_summary
            .contains(adapter.runtime_instance_id()));
    }

    #[tokio::test]
    async fn adapter_scopes_session_ids_to_runtime_instance() {
        let local_identity = IdentityKeypair::from_secret_bytes([65_u8; 32]);
        let local = local_identity.peer_id();
        let adapter_a = QuicTransportAdapter::with_identity(
            NetworkId::derive("restart-test"),
            local_identity.clone(),
        );
        let adapter_b =
            QuicTransportAdapter::with_identity(NetworkId::derive("restart-test"), local_identity);
        let peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"restart-peer");
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();
        let route = RoutePlan {
            local_peer: local,
            peer,
            protocol: Some(protocol),
            class: TrafficClass::Interactive,
            path_kind: PathKind::DirectUdp,
            source: RouteSource::Observed,
            remote_endpoints: vec!["quic://198.51.100.40:8443".to_string()],
            relay: None,
        };

        let session_a = adapter_a.connect(route.clone()).await.unwrap().session;
        let session_b = adapter_b.connect(route).await.unwrap().session;

        assert_ne!(
            adapter_a.runtime_instance_id(),
            adapter_b.runtime_instance_id()
        );
        assert_ne!(session_a.session_id, session_b.session_id);
        assert_ne!(
            session_a.transport_session_id,
            session_b.transport_session_id
        );
    }

    #[tokio::test]
    async fn adapter_scopes_listener_ids_to_runtime_instance() {
        let adapter_a = QuicTransportAdapter::default();
        let adapter_b = QuicTransportAdapter::default();
        let protocol = ProtocolId::new("/quip/control/1").unwrap();

        adapter_a
            .listen(BindSpec {
                protocol: protocol.clone(),
                advertise: true,
            })
            .await
            .expect("listener should register");
        adapter_b
            .listen(BindSpec {
                protocol,
                advertise: true,
            })
            .await
            .expect("listener should register");

        let listener_a = adapter_a.active_listeners().unwrap().pop().unwrap();
        let listener_b = adapter_b.active_listeners().unwrap().pop().unwrap();

        assert_ne!(
            adapter_a.runtime_instance_id(),
            adapter_b.runtime_instance_id()
        );
        assert_ne!(listener_a.listener_id, listener_b.listener_id);
    }

    #[tokio::test]
    async fn adapter_returns_relay_session_metadata() {
        let _guard = relay_test_lock();
        let destination = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"destination");
        let relay = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay");
        let local_identity = IdentityKeypair::from_secret_bytes([61_u8; 32]);
        let local = local_identity.peer_id();
        clear_registry();
        register_relay(RelayService::new(RelayNode {
            announcement: relaywire::RelayAnnouncement {
                peer_id: relay.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.70:443".to_string()],
                control_endpoint: format!("inproc://{relay}"),
                max_bandwidth_bps: 1_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            },
            quotas: vec![RelayQuota {
                peer: local.clone(),
                max_bandwidth_bps: 100_000_000,
                max_concurrent_sessions: 4,
            }],
            destinations: vec![relay::RelayDestination {
                peer: destination.clone(),
                protocols: vec![ProtocolId::new("/quicnet/control/1").unwrap()],
            }],
        }));
        let adapter =
            QuicTransportAdapter::with_identity(NetworkId::derive("relay-test"), local_identity)
                .with_relay_control(Arc::new(InProcessRelayControl));
        let handle = adapter
            .connect(RoutePlan {
                local_peer: local,
                peer: destination.clone(),
                protocol: Some(ProtocolId::new("/quicnet/control/1").unwrap()),
                class: TrafficClass::Interactive,
                path_kind: PathKind::Relay,
                source: RouteSource::AuthorityRelay,
                remote_endpoints: vec!["quic://198.51.100.20:9443".to_string()],
                relay: Some(RelayPlan {
                    relay_peer: relay.clone(),
                    relay_endpoints: vec!["quic://203.0.113.70:443".to_string()],
                    relay_control_endpoint: format!("inproc://{relay}"),
                    destination_endpoints: vec!["quic://198.51.100.20:9443".to_string()],
                    supports_datagrams: true,
                    supports_path_migration: true,
                }),
            })
            .await
            .unwrap();

        assert_eq!(handle.session.peer, destination);
        assert_eq!(handle.session.relay_peer, Some(relay));
        assert_eq!(
            handle.session.relay_endpoint.as_deref(),
            Some("quic://203.0.113.70:443")
        );
        assert!(handle.session.relay_attempt_id.is_some());
    }

    #[tokio::test]
    async fn adapter_records_runtime_events_and_state_transitions() {
        let local_identity = IdentityKeypair::from_secret_bytes([90_u8; 32]);
        let local = local_identity.peer_id();
        let adapter =
            QuicTransportAdapter::with_identity(NetworkId::derive("events-test"), local_identity);
        let peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"peer-events");
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();
        let handle = adapter
            .connect(RoutePlan {
                local_peer: local,
                peer,
                protocol: Some(protocol),
                class: TrafficClass::Interactive,
                path_kind: PathKind::DirectUdp,
                source: RouteSource::Observed,
                remote_endpoints: vec!["quic://198.51.100.10:8443".to_string()],
                relay: None,
            })
            .await
            .unwrap();

        let updated = adapter
            .update_session_state(
                &handle.session.session_id,
                RuntimeSessionState::Reconciling,
                None,
                Some("daemon reconcile cycle".to_string()),
            )
            .unwrap()
            .unwrap();

        assert_eq!(updated.state, RuntimeSessionState::Reconciling);
        let events = adapter.recent_events(8).unwrap();
        assert!(events
            .iter()
            .any(|event| event.event_type == "session.created"));
        assert!(events
            .iter()
            .any(|event| event.event_type == "path.selected"));
        assert!(events
            .iter()
            .any(|event| event.event_type == "session.state_changed"));
    }

    #[tokio::test]
    async fn adapter_blocks_suppressed_reconnect_attempts() {
        let local_identity = IdentityKeypair::from_secret_bytes([91_u8; 32]);
        let local = local_identity.peer_id();
        let adapter = QuicTransportAdapter::with_identity(
            NetworkId::derive("suppression-test"),
            local_identity,
        );
        let peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"peer-suppressed");
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();
        adapter
            .suppress_reconnect(
                &peer,
                Some(&protocol),
                TrafficClass::Interactive,
                "policy denied reconnect".to_string(),
            )
            .unwrap();

        let error = adapter
            .connect(RoutePlan {
                local_peer: local,
                peer: peer.clone(),
                protocol: Some(protocol),
                class: TrafficClass::Interactive,
                path_kind: PathKind::DirectUdp,
                source: RouteSource::Observed,
                remote_endpoints: vec!["quic://198.51.100.10:8443".to_string()],
                relay: None,
            })
            .await
            .expect_err("suppressed reconnect should be blocked");

        assert!(error.to_string().contains("reconnect suppressed"));
        let events = adapter.recent_events(8).unwrap();
        assert!(events
            .iter()
            .any(|event| event.event_type == "reconnect.suppressed"));
    }

    #[tokio::test]
    async fn adapter_transport_health_tracks_listeners_and_suppressions() {
        let adapter = QuicTransportAdapter::default();
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();
        adapter
            .listen(BindSpec {
                protocol: protocol.clone(),
                advertise: false,
            })
            .await
            .expect("listener should register");
        adapter
            .suppress_reconnect(
                &PeerId::from_public_key(KeyAlgorithm::Ed25519, b"suppressed-peer"),
                Some(&protocol),
                TrafficClass::Control,
                "policy denied".to_string(),
            )
            .expect("suppression should register");

        let health = adapter
            .transport_health()
            .expect("transport health should render");

        assert_eq!(health.active_listeners, 1);
        assert_eq!(health.reconnect_state, RuntimeReconnectState::Suppressed);
        assert_eq!(health.reconnect_attempt_count, 0);
        assert_eq!(health.reconnect_suppression_count, 1);
        assert!(health.listener_registry_healthy);
        assert!(health.session_registry_healthy);
    }

    #[tokio::test]
    async fn adapter_tracks_reconnect_attempt_backoff_and_clear() {
        let adapter = QuicTransportAdapter::default();
        let peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"reconnect-peer");
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();

        let scheduled = adapter
            .schedule_reconnect(
                &peer,
                Some(&protocol),
                TrafficClass::Interactive,
                "dial failed".to_string(),
                4,
                2,
                32,
            )
            .expect("reconnect attempt should schedule");
        assert_eq!(scheduled.attempt_count, 1);
        assert_eq!(scheduled.state, RuntimeReconnectAttemptState::BackingOff);
        assert!(scheduled.next_attempt_unix_secs >= scheduled.last_attempt_unix_secs + 2);

        let health = adapter
            .transport_health()
            .expect("transport health should render");
        assert_eq!(health.reconnect_state, RuntimeReconnectState::Active);
        assert_eq!(health.reconnect_attempt_count, 1);
        assert!(health.reconnect_next_attempt_unix_secs.is_some());

        adapter
            .clear_reconnect_attempt(
                &peer,
                Some(&protocol),
                TrafficClass::Interactive,
                Some("reconnect succeeded".to_string()),
            )
            .expect("reconnect attempt should clear");
        let cleared = adapter
            .transport_health()
            .expect("cleared health should render");
        assert_eq!(cleared.reconnect_state, RuntimeReconnectState::Idle);
        assert_eq!(cleared.reconnect_attempt_count, 0);

        let events = adapter.recent_events(16).expect("events should load");
        let retry = events
            .iter()
            .find(|event| event.event_type == "reconnect.retry_scheduled")
            .expect("retry event should exist");
        assert_eq!(
            retry.details.get("state").and_then(|value| value.as_str()),
            Some("backing_off")
        );
        assert_eq!(
            retry
                .details
                .get("backoff_secs")
                .and_then(|value| value.as_u64()),
            Some(2)
        );
        let succeeded = events
            .iter()
            .find(|event| event.event_type == "reconnect.succeeded")
            .expect("success event should exist");
        assert_eq!(
            succeeded
                .details
                .get("state")
                .and_then(|value| value.as_str()),
            Some("backing_off")
        );
    }

    #[tokio::test]
    async fn adapter_emits_unsuppressed_event_when_reconnect_suppression_clears() {
        let adapter = QuicTransportAdapter::default();
        let peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"reconnect-unsuppressed-peer");
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();

        adapter
            .suppress_reconnect(
                &peer,
                Some(&protocol),
                TrafficClass::Interactive,
                "policy denied reconnect".to_string(),
            )
            .expect("suppression should register");
        adapter
            .clear_reconnect_suppression(&peer, Some(&protocol), TrafficClass::Interactive)
            .expect("suppression should clear");

        let events = adapter.recent_events(16).expect("events should load");
        let unsuppressed = events
            .iter()
            .find(|event| event.event_type == "reconnect.unsuppressed")
            .expect("unsuppressed event should exist");
        assert_eq!(
            unsuppressed
                .details
                .get("prior_reason")
                .and_then(|value| value.as_str()),
            Some("policy denied reconnect")
        );
        assert!(unsuppressed
            .details
            .get("imposed_at_unix_secs")
            .and_then(|value| value.as_u64())
            .is_some());
    }

    #[tokio::test]
    async fn adapter_rejects_unavailable_relay_route() {
        let _guard = relay_test_lock();
        clear_registry();
        let local_identity = IdentityKeypair::from_secret_bytes([62_u8; 32]);
        let adapter = QuicTransportAdapter::with_identity(
            NetworkId::derive("relay-test"),
            local_identity.clone(),
        )
        .with_relay_control(Arc::new(InProcessRelayControl));
        let destination = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"destination-missing");
        let relay = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-missing");
        let local = local_identity.peer_id();

        let error = adapter
            .connect(RoutePlan {
                local_peer: local,
                peer: destination,
                protocol: Some(ProtocolId::new("/quicnet/control/1").unwrap()),
                class: TrafficClass::Control,
                path_kind: PathKind::Relay,
                source: RouteSource::AuthorityRelay,
                remote_endpoints: vec!["quic://198.51.100.20:9443".to_string()],
                relay: Some(RelayPlan {
                    relay_peer: relay,
                    relay_endpoints: vec!["quic://203.0.113.80:443".to_string()],
                    relay_control_endpoint: "inproc://peer1missing".to_string(),
                    destination_endpoints: vec!["quic://198.51.100.20:9443".to_string()],
                    supports_datagrams: true,
                    supports_path_migration: true,
                }),
            })
            .await
            .expect_err("relay connect should fail when relay is unavailable");

        assert!(matches!(error, TransportError::RelayRejected(_)));
    }

    #[tokio::test]
    async fn adapter_closes_relay_session_in_registry() {
        let _guard = relay_test_lock();
        let destination = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"destination-close");
        let relay = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-close");
        let local_identity = IdentityKeypair::from_secret_bytes([63_u8; 32]);
        let local = local_identity.peer_id();
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();
        clear_registry();
        register_relay(RelayService::new(RelayNode {
            announcement: relaywire::RelayAnnouncement {
                peer_id: relay.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.90:443".to_string()],
                control_endpoint: format!("inproc://{relay}"),
                max_bandwidth_bps: 1_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            },
            quotas: vec![RelayQuota {
                peer: local.clone(),
                max_bandwidth_bps: 100_000_000,
                max_concurrent_sessions: 4,
            }],
            destinations: vec![relay::RelayDestination {
                peer: destination.clone(),
                protocols: vec![protocol.clone()],
            }],
        }));
        let adapter =
            QuicTransportAdapter::with_identity(NetworkId::derive("relay-test"), local_identity)
                .with_relay_control(Arc::new(InProcessRelayControl));
        let handle = adapter
            .connect(RoutePlan {
                local_peer: local,
                peer: destination,
                protocol: Some(protocol),
                class: TrafficClass::Interactive,
                path_kind: PathKind::Relay,
                source: RouteSource::AuthorityRelay,
                remote_endpoints: vec!["quic://198.51.100.30:9443".to_string()],
                relay: Some(RelayPlan {
                    relay_peer: relay.clone(),
                    relay_endpoints: vec!["quic://203.0.113.90:443".to_string()],
                    relay_control_endpoint: format!("inproc://{relay}"),
                    destination_endpoints: vec!["quic://198.51.100.30:9443".to_string()],
                    supports_datagrams: true,
                    supports_path_migration: true,
                }),
            })
            .await
            .unwrap();

        assert_eq!(registered_session_count(&relay), Some(1));

        adapter.close_session(&handle.session).await.unwrap();

        assert_eq!(registered_session_count(&relay), Some(0));
        assert!(!adapter.owns_session(&handle.session.session_id));
    }

    #[tokio::test]
    async fn adapter_migrates_relay_session_to_direct_and_releases_old_transport() {
        let _guard = relay_test_lock();
        let destination = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"destination-migrate");
        let relay = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relay-migrate");
        let local_identity = IdentityKeypair::from_secret_bytes([64_u8; 32]);
        let local = local_identity.peer_id();
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();
        clear_registry();
        register_relay(RelayService::new(RelayNode {
            announcement: relaywire::RelayAnnouncement {
                peer_id: relay.clone(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.91:443".to_string()],
                control_endpoint: format!("inproc://{relay}"),
                max_bandwidth_bps: 1_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string(), "InteractiveRpc".to_string()],
            },
            quotas: vec![RelayQuota {
                peer: local.clone(),
                max_bandwidth_bps: 100_000_000,
                max_concurrent_sessions: 4,
            }],
            destinations: vec![relay::RelayDestination {
                peer: destination.clone(),
                protocols: vec![protocol.clone()],
            }],
        }));
        let adapter =
            QuicTransportAdapter::with_identity(NetworkId::derive("relay-test"), local_identity)
                .with_relay_control(Arc::new(InProcessRelayControl));
        let relay_handle = adapter
            .connect(RoutePlan {
                local_peer: local.clone(),
                peer: destination.clone(),
                protocol: Some(protocol.clone()),
                class: TrafficClass::Interactive,
                path_kind: PathKind::Relay,
                source: RouteSource::AuthorityRelay,
                remote_endpoints: vec!["quic://198.51.100.31:9443".to_string()],
                relay: Some(RelayPlan {
                    relay_peer: relay.clone(),
                    relay_endpoints: vec!["quic://203.0.113.91:443".to_string()],
                    relay_control_endpoint: format!("inproc://{relay}"),
                    destination_endpoints: vec!["quic://198.51.100.31:9443".to_string()],
                    supports_datagrams: true,
                    supports_path_migration: true,
                }),
            })
            .await
            .unwrap();

        assert_eq!(registered_session_count(&relay), Some(1));

        let migrated = adapter
            .migrate(
                &relay_handle.session,
                RoutePlan {
                    local_peer: local,
                    peer: destination,
                    protocol: Some(protocol),
                    class: TrafficClass::Interactive,
                    path_kind: PathKind::DirectUdp,
                    source: RouteSource::Observed,
                    remote_endpoints: vec!["quic://198.51.100.31:9443".to_string()],
                    relay: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(migrated.session_id, relay_handle.session.session_id);
        assert_eq!(migrated.transport_session_id, migrated.session_id);
        assert_ne!(
            migrated.transport_session_id,
            relay_handle.session.transport_session_id
        );
        assert_eq!(migrated.path_kind, PathKind::DirectUdp);
        assert!(migrated.relay_peer.is_none());
        assert!(migrated.relay_endpoint.is_none());
        assert!(migrated.relay_control_endpoint.is_none());
        assert_eq!(registered_session_count(&relay), Some(0));
        assert!(adapter.owns_session(&migrated.session_id));
        assert_eq!(
            adapter
                .session_snapshot(&migrated.session_id)
                .expect("runtime snapshot should resolve")
                .expect("migrated session should remain active")
                .path_kind,
            PathKind::DirectUdp
        );
    }

    #[tokio::test]
    async fn adapter_rejects_migration_for_session_missing_from_runtime_registry() {
        let local_identity = IdentityKeypair::from_secret_bytes([58_u8; 32]);
        let local = local_identity.peer_id();
        let adapter =
            QuicTransportAdapter::with_identity(NetworkId::derive("direct-test"), local_identity);
        let session = SessionSnapshot {
            session_id: [7_u8; 16],
            transport_session_id: [8_u8; 16],
            relay_attempt_id: None,
            peer: PeerId::from_public_key(KeyAlgorithm::Ed25519, b"peer-missing"),
            protocol: Some(ProtocolId::new("/quicnet/control/1").unwrap()),
            class: TrafficClass::Control,
            path_kind: PathKind::DirectUdp,
            source: RouteSource::Observed,
            remote_endpoint: "quic://198.51.100.10:8443".to_string(),
            relay_peer: None,
            relay_endpoint: None,
            relay_control_endpoint: None,
            datagrams_capable: true,
            migration_capable: true,
            state: RuntimeSessionState::Active,
            closure_reason: None,
            state_reason: None,
            created_at_unix_secs: current_unix_secs(),
            last_activity_unix_secs: current_unix_secs(),
        };

        let error = adapter
            .migrate(
                &session,
                RoutePlan {
                    local_peer: local,
                    peer: session.peer.clone(),
                    protocol: session.protocol.clone(),
                    class: session.class,
                    path_kind: PathKind::DirectIpv6,
                    source: RouteSource::Observed,
                    remote_endpoints: vec!["quic://[2001:db8::2]:8443".to_string()],
                    relay: None,
                },
            )
            .await
            .expect_err("migration should require a runtime-owned session");

        assert!(error
            .to_string()
            .contains("session is not active in runtime registry"));
    }
}
