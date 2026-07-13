use crypto::PublicIdentityKey;
use identity::SessionCredential;
use model::{NetworkId, PeerId, ProtocolId, TrafficClass};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayRejectCode {
    Unauthorized,
    UnsupportedTrafficClass,
    CapacityExceeded,
    SessionExists,
    InvalidIdentityProof,
    DestinationUnauthorized,
    DestinationProtocolRejected,
    InvalidRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayOpenRequest {
    pub attempt_id: [u8; 16],
    pub network_id: NetworkId,
    pub source: PeerId,
    pub source_public_key: PublicIdentityKey,
    pub source_credential: SessionCredential,
    pub destination: PeerId,
    pub protocol: Option<ProtocolId>,
    pub traffic_class: TrafficClass,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelaySessionAccepted {
    pub attempt_id: [u8; 16],
    pub session_id: [u8; 16],
    pub source: PeerId,
    pub destination: PeerId,
    pub protocol: Option<ProtocolId>,
    pub traffic_class: TrafficClass,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelaySessionRejected {
    pub attempt_id: [u8; 16],
    pub code: RelayRejectCode,
    pub source: PeerId,
    pub destination: PeerId,
    pub protocol: Option<ProtocolId>,
    pub traffic_class: TrafficClass,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayFrame {
    OpenSession(RelayOpenRequest),
    SessionAccepted(RelaySessionAccepted),
    SessionRejected(RelaySessionRejected),
    Data {
        session_id: [u8; 16],
        payload: Vec<u8>,
    },
    Health {
        session_id: [u8; 16],
        queue_depth: u32,
        load_percent: u8,
    },
    Close {
        session_id: [u8; 16],
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayAnnouncement {
    pub peer_id: PeerId,
    pub region: String,
    pub advertised_endpoints: Vec<String>,
    #[serde(default)]
    pub control_endpoint: String,
    pub max_bandwidth_bps: u64,
    pub supports_quic_datagrams: bool,
    pub supports_path_migration: bool,
    pub traffic_classes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayMap {
    pub version: u64,
    pub generated_at: u64,
    pub relays: Vec<RelayAnnouncement>,
}

#[cfg(test)]
mod tests {
    use model::KeyAlgorithm;

    use super::*;

    #[test]
    fn relay_announcement_deserializes_without_control_endpoint() {
        let payload = serde_json::json!({
            "peer_id": PeerId::from_public_key(KeyAlgorithm::Ed25519, b"relaywire-missing-control"),
            "region": "us-east-1",
            "advertised_endpoints": ["quic://198.51.100.44:443"],
            "max_bandwidth_bps": 1000000u64,
            "supports_quic_datagrams": true,
            "supports_path_migration": true,
            "traffic_classes": ["NetworkControl"]
        });

        let relay: RelayAnnouncement =
            serde_json::from_value(payload).expect("relay announcement should deserialize");

        assert_eq!(relay.control_endpoint, "");
        assert_eq!(relay.advertised_endpoints.len(), 1);
    }
}
