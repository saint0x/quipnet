use std::sync::Arc;

use async_trait::async_trait;
use crypto::{IdentityKeypair, SessionKeypair};
use model::NetworkId;
use rand::{rngs::OsRng, RngCore};
use relay::{HttpRelayControl, RelayControl};
use relaywire::RelayOpenRequest;
use transport::{
    BindSpec, ConnectionHandle, RelayPlan, RoutePlan, SecureTransport, SessionLifecycleTransport,
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

#[derive(Clone)]
pub struct QuicTransportAdapter {
    pub implementation: &'static str,
    pub supports_datagrams: bool,
    pub supports_path_migration: bool,
    pub network_id: Option<NetworkId>,
    pub local_identity: Option<IdentityKeypair>,
    relay_control: Arc<dyn RelayControl>,
}

impl Default for QuicTransportAdapter {
    fn default() -> Self {
        Self {
            implementation: "adapter-placeholder",
            supports_datagrams: true,
            supports_path_migration: true,
            network_id: None,
            local_identity: None,
            relay_control: Arc::new(HttpRelayControl),
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
}

#[async_trait]
impl SecureTransport for QuicTransportAdapter {
    type Connection = QuicConnectionHandle;
    type Listener = QuicListenerHandle;

    async fn connect(&self, route: RoutePlan) -> Result<Self::Connection, TransportError> {
        let session = session_snapshot_for_route(self, &route)?;
        Ok(QuicConnectionHandle {
            session,
            alpn_protocol: route.protocol.map(|id| id.as_str().to_string()),
        })
    }

    async fn listen(&self, bind: BindSpec) -> Result<Self::Listener, TransportError> {
        Ok(QuicListenerHandle {
            protocol: bind.protocol.as_str().to_string(),
            advertise: bind.advertise,
        })
    }
}

#[async_trait]
impl SessionLifecycleTransport for QuicTransportAdapter {
    async fn migrate(
        &self,
        session: &SessionSnapshot,
        route: RoutePlan,
    ) -> Result<SessionSnapshot, TransportError> {
        let mut migrated = session_snapshot_for_route(self, &route)?;
        let previous_transport_session_id = session.transport_session_id;
        let previous_control_endpoint = session.relay_control_endpoint.clone();
        let previous_path_kind = session.path_kind;

        migrated.session_id = session.session_id;

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

        Ok(migrated)
    }

    async fn close_session(&self, session: &SessionSnapshot) -> Result<(), TransportError> {
        if session.path_kind == model::PathKind::Relay {
            close_relay_transport_session(
                &*self.relay_control,
                session.relay_control_endpoint.as_deref(),
                session.transport_session_id,
            )?;
        }
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
    let remote_endpoint = route
        .remote_endpoints
        .first()
        .cloned()
        .ok_or_else(|| TransportError::NoRoute(route.peer.clone()))?;
    Ok(SessionSnapshot {
        session_id: logical_session_id(route),
        transport_session_id: logical_session_id(route),
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
    Ok(SessionSnapshot {
        session_id: logical_session_id(route),
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
    })
}

fn random_attempt_id() -> [u8; 16] {
    let mut attempt_id = [0_u8; 16];
    OsRng.fill_bytes(&mut attempt_id);
    attempt_id
}

fn logical_session_id(route: &RoutePlan) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
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
        let adapter = QuicTransportAdapter::default();
        let peer = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"peer");
        let protocol = ProtocolId::new("/quicnet/control/1").unwrap();
        let handle = adapter
            .connect(RoutePlan {
                local_peer: PeerId::from_public_key(KeyAlgorithm::Ed25519, b"local"),
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
    }
}
