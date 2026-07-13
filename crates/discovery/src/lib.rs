use std::collections::BTreeSet;

use model::PeerId;
use peerstore::{PeerReachability, PeerSnapshot, PeerSource, PeerStatus, PeerStore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapHint {
    pub peer: PeerId,
    pub addresses: Vec<String>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BootstrapIngestReport {
    pub imported: usize,
    pub updated: usize,
    pub skipped: usize,
}

#[derive(Debug, Default)]
pub struct DiscoveryService {
    bootstrap: Vec<BootstrapHint>,
}

impl DiscoveryService {
    pub fn with_bootstrap(bootstrap: Vec<BootstrapHint>) -> Self {
        Self { bootstrap }
    }

    pub fn bootstrap_candidates(&self) -> &[BootstrapHint] {
        &self.bootstrap
    }

    pub fn ingest_bootstrap(&self, store: &mut PeerStore, seen_at: u64) -> BootstrapIngestReport {
        let mut report = BootstrapIngestReport::default();
        for hint in &self.bootstrap {
            let snapshot = PeerSnapshot {
                peer: hint.peer.clone(),
                protocols: hint.protocols.clone(),
                addresses: hint.addresses.clone(),
            };

            match store.peer(&hint.peer) {
                Some(existing) if existing == &snapshot => {
                    report.skipped += 1;
                }
                Some(_) => {
                    report.updated += 1;
                }
                None => {
                    report.imported += 1;
                }
            }

            store.upsert_peer_with_status(
                snapshot,
                PeerStatus {
                    source: PeerSource::Bootstrap,
                    reachability: PeerReachability::Unknown,
                    last_seen_unix_secs: Some(seen_at),
                },
            );
        }

        report
    }

    pub fn merge_peer_snapshot(&self, snapshot: PeerSnapshot) -> PeerSnapshot {
        if let Some(existing) = self
            .bootstrap
            .iter()
            .find(|hint| hint.peer == snapshot.peer)
        {
            let protocols = snapshot
                .protocols
                .iter()
                .cloned()
                .chain(existing.protocols.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let addresses = snapshot
                .addresses
                .iter()
                .cloned()
                .chain(existing.addresses.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            PeerSnapshot {
                peer: snapshot.peer,
                protocols,
                addresses,
            }
        } else {
            snapshot
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(label: &str) -> PeerId {
        PeerId::from_public_key(model::KeyAlgorithm::Ed25519, label.as_bytes())
    }

    #[test]
    fn bootstrap_ingest_populates_store() {
        let service = DiscoveryService::with_bootstrap(vec![BootstrapHint {
            peer: peer("seed-1"),
            addresses: vec!["udp://198.51.100.10:4242".into()],
            protocols: vec!["/quicnet/control/1".into()],
        }]);
        let mut store = PeerStore::default();

        let report = service.ingest_bootstrap(&mut store, 1_720_000_100);
        assert_eq!(report.imported, 1);
        assert_eq!(store.peers().len(), 1);
    }
}
