use std::collections::BTreeMap;

use model::PeerId;
use records::SignedRecord;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerSnapshot {
    pub peer: PeerId,
    pub protocols: Vec<String>,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PeerSource {
    Bootstrap,
    RelayMap,
    Discovery,
    Manual,
    Observed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PeerReachability {
    Unknown,
    Direct,
    Relayed,
    Unreachable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerStatus {
    pub source: PeerSource,
    pub reachability: PeerReachability,
    pub last_seen_unix_secs: Option<u64>,
}

impl Default for PeerStatus {
    fn default() -> Self {
        Self {
            source: PeerSource::Observed,
            reachability: PeerReachability::Unknown,
            last_seen_unix_secs: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInspection {
    pub snapshot: PeerSnapshot,
    pub status: PeerStatus,
    pub record_count: usize,
}

#[derive(Debug, Default)]
pub struct PeerStore {
    peers: BTreeMap<PeerId, PeerSnapshot>,
    statuses: BTreeMap<PeerId, PeerStatus>,
    records: BTreeMap<PeerId, Vec<SignedRecord>>,
}

impl PeerStore {
    pub fn upsert_peer(&mut self, snapshot: PeerSnapshot) {
        let peer = snapshot.peer.clone();
        self.peers.insert(peer.clone(), snapshot);
        self.statuses.entry(peer).or_default();
    }

    pub fn upsert_peer_with_status(&mut self, snapshot: PeerSnapshot, status: PeerStatus) {
        let peer = snapshot.peer.clone();
        self.peers.insert(peer.clone(), snapshot);
        self.statuses.insert(peer, status);
    }

    pub fn append_record(&mut self, peer: PeerId, record: SignedRecord) {
        self.records.entry(peer).or_default().push(record);
    }

    pub fn peer(&self, peer: &PeerId) -> Option<&PeerSnapshot> {
        self.peers.get(peer)
    }

    pub fn peer_status(&self, peer: &PeerId) -> Option<&PeerStatus> {
        self.statuses.get(peer)
    }

    pub fn record_count(&self, peer: &PeerId) -> usize {
        self.records.get(peer).map(Vec::len).unwrap_or_default()
    }

    pub fn inspection(&self, peer: &PeerId) -> Option<PeerInspection> {
        Some(PeerInspection {
            snapshot: self.peers.get(peer)?.clone(),
            status: self.statuses.get(peer).cloned().unwrap_or_default(),
            record_count: self.record_count(peer),
        })
    }

    pub fn peers(&self) -> Vec<PeerInspection> {
        self.peers
            .keys()
            .filter_map(|peer| self.inspection(peer))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_includes_status_and_record_counts() {
        let peer = PeerId::from_public_key(model::KeyAlgorithm::Ed25519, b"bootstrap-1");
        let mut store = PeerStore::default();
        store.upsert_peer_with_status(
            PeerSnapshot {
                peer: peer.clone(),
                protocols: vec!["/quip/control/1".into()],
                addresses: vec!["udp://203.0.113.10:4242".into()],
            },
            PeerStatus {
                source: PeerSource::Bootstrap,
                reachability: PeerReachability::Direct,
                last_seen_unix_secs: Some(1_720_000_000),
            },
        );

        let inspection = store.inspection(&peer).expect("peer should exist");
        assert_eq!(inspection.snapshot.peer, peer);
        assert_eq!(inspection.status.source, PeerSource::Bootstrap);
        assert_eq!(inspection.record_count, 0);
    }
}
