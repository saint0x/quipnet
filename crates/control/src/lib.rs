use membership::{
    BootstrapHint, CapabilityGrant, EnrollmentToken, MembershipCertificate, RevocationRecord,
};
use model::NetworkId;
use records::SignedRecord;
use relaywire::RelayMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityEndpoints {
    pub enrollment: String,
    pub revocation: String,
    pub relay_map: String,
    pub bootstrap: String,
    pub snapshot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityArtifactSnapshot {
    pub network_id: NetworkId,
    pub enrollment_token: Option<EnrollmentToken>,
    pub membership: Option<MembershipCertificate>,
    pub capability_grants: Vec<membership::CapabilityGrant>,
    pub revocations: Vec<RevocationRecord>,
    pub bootstrap_hints: Vec<BootstrapHint>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlError {
    #[error("snapshot network does not match client network")]
    NetworkMismatch,
    #[error("incoming membership subject does not match local membership subject")]
    SubjectMismatch,
    #[error("incoming membership is older than the local membership")]
    MembershipRollback,
    #[error("grant identity collision with non-identical payload")]
    GrantConflict,
    #[error("http transport failed: {0}")]
    Transport(String),
    #[error("snapshot decoding failed: {0}")]
    Decode(String),
    #[error("authority subject projection is unavailable: {0}")]
    MissingSubject(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDelta {
    pub membership_changed: bool,
    pub grants_added: usize,
    pub grants_removed: usize,
    pub revocations_added: usize,
    pub bootstrap_hints_added: usize,
    pub bootstrap_hints_removed: usize,
}

impl SnapshotDelta {
    fn empty() -> Self {
        Self {
            membership_changed: false,
            grants_added: 0,
            grants_removed: 0,
            revocations_added: 0,
            bootstrap_hints_added: 0,
            bootstrap_hints_removed: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ControlClient {
    pub network_id: NetworkId,
    pub endpoints: AuthorityEndpoints,
}

impl ControlClient {
    pub fn from_origin(network_id: NetworkId, origin: &str) -> Self {
        let base = origin.trim_end_matches('/').to_string();
        Self {
            network_id,
            endpoints: AuthorityEndpoints {
                enrollment: format!("{base}/enroll"),
                revocation: format!("{base}/revoke"),
                relay_map: format!("{base}/relays"),
                bootstrap: format!("{base}/bootstrap"),
                snapshot: format!("{base}/snapshot"),
            },
        }
    }

    pub fn sync_authority_snapshot(
        &self,
        snapshot: AuthorityArtifactSnapshot,
    ) -> Result<AuthorityArtifactSnapshot, ControlError> {
        if snapshot.network_id != self.network_id {
            return Err(ControlError::NetworkMismatch);
        }
        Ok(snapshot)
    }

    pub fn enroll_with_token(&self, token: EnrollmentToken) -> EnrollmentToken {
        token
    }

    pub fn sync_membership(&self, membership: MembershipCertificate) -> MembershipCertificate {
        membership
    }

    pub fn list_bootstrap_hints<'a>(
        &self,
        snapshot: &'a AuthorityArtifactSnapshot,
    ) -> &'a [BootstrapHint] {
        &snapshot.bootstrap_hints
    }

    pub fn publish_record(&self, record: SignedRecord) -> SignedRecord {
        record
    }

    pub fn fetch_authority_snapshot(&self) -> Result<AuthorityArtifactSnapshot, ControlError> {
        self.fetch_authority_snapshot_for(None)
    }

    pub fn fetch_authority_snapshot_for(
        &self,
        subject: Option<&str>,
    ) -> Result<AuthorityArtifactSnapshot, ControlError> {
        let snapshot_url = endpoint_with_subject(&self.endpoints.snapshot, subject);
        let response = ureq::get(&snapshot_url)
            .call()
            .map_err(|error| map_transport_error(error, subject))?;
        let snapshot = response
            .into_json::<AuthorityArtifactSnapshot>()
            .map_err(|error| ControlError::Decode(error.to_string()))?;
        self.sync_authority_snapshot(snapshot)
    }

    pub fn fetch_bootstrap_hints(&self) -> Result<Vec<BootstrapHint>, ControlError> {
        self.fetch_bootstrap_hints_for(None)
    }

    pub fn fetch_bootstrap_hints_for(
        &self,
        subject: Option<&str>,
    ) -> Result<Vec<BootstrapHint>, ControlError> {
        let bootstrap_url = endpoint_with_subject(&self.endpoints.bootstrap, subject);
        let response = ureq::get(&bootstrap_url)
            .call()
            .map_err(|error| map_transport_error(error, subject))?;
        response
            .into_json::<Vec<BootstrapHint>>()
            .map_err(|error| ControlError::Decode(error.to_string()))
    }

    pub fn fetch_revocations(
        &self,
        after_sequence: Option<u64>,
    ) -> Result<Vec<RevocationRecord>, ControlError> {
        let revocation_url =
            endpoint_with_after_sequence(&self.endpoints.revocation, after_sequence);
        let response = ureq::get(&revocation_url)
            .call()
            .map_err(|error| ControlError::Transport(error.to_string()))?;
        response
            .into_json::<Vec<RevocationRecord>>()
            .map_err(|error| ControlError::Decode(error.to_string()))
    }

    pub fn fetch_relay_map(&self) -> Result<RelayMap, ControlError> {
        let response = ureq::get(&self.endpoints.relay_map)
            .call()
            .map_err(|error| ControlError::Transport(error.to_string()))?;
        response
            .into_json::<RelayMap>()
            .map_err(|error| ControlError::Decode(error.to_string()))
    }

    pub fn merge_snapshot(
        &self,
        current: Option<AuthorityArtifactSnapshot>,
        incoming: AuthorityArtifactSnapshot,
    ) -> Result<(AuthorityArtifactSnapshot, SnapshotDelta), ControlError> {
        let incoming = self.sync_authority_snapshot(incoming)?;
        let Some(current) = current else {
            let delta = SnapshotDelta {
                membership_changed: incoming.membership.is_some(),
                grants_added: incoming.capability_grants.len(),
                grants_removed: 0,
                revocations_added: incoming.revocations.len(),
                bootstrap_hints_added: incoming.bootstrap_hints.len(),
                bootstrap_hints_removed: 0,
            };
            return Ok((incoming, delta));
        };

        let mut delta = SnapshotDelta::empty();
        let membership = merge_membership(current.membership.clone(), incoming.membership)?;
        let membership_changed = membership != current.membership;

        let current_grants = current.capability_grants;
        let incoming_grants = incoming.capability_grants;
        for grant in &incoming_grants {
            if let Some(existing) = current_grants
                .iter()
                .find(|existing| same_grant(existing, grant))
            {
                if existing != grant {
                    return Err(ControlError::GrantConflict);
                }
            }
        }
        delta.grants_added = incoming_grants
            .iter()
            .filter(|grant| {
                !current_grants
                    .iter()
                    .any(|existing| same_grant(existing, grant))
            })
            .count();
        delta.grants_removed = current_grants
            .iter()
            .filter(|grant| {
                !incoming_grants
                    .iter()
                    .any(|incoming| same_grant(grant, incoming))
            })
            .count();
        let grants = incoming_grants;

        let mut revocations = current.revocations;
        for revocation in incoming.revocations {
            if !revocations
                .iter()
                .any(|existing| same_revocation(existing, &revocation))
            {
                revocations.push(revocation);
                delta.revocations_added += 1;
            }
        }

        let current_bootstrap_hints = current.bootstrap_hints;
        let incoming_bootstrap_hints = incoming.bootstrap_hints;
        delta.bootstrap_hints_added = incoming_bootstrap_hints
            .iter()
            .filter(|hint| {
                !current_bootstrap_hints
                    .iter()
                    .any(|existing| same_hint(existing, hint))
            })
            .count();
        delta.bootstrap_hints_removed = current_bootstrap_hints
            .iter()
            .filter(|hint| {
                !incoming_bootstrap_hints
                    .iter()
                    .any(|incoming| same_hint(hint, incoming))
            })
            .count();
        let bootstrap_hints = incoming_bootstrap_hints;

        delta.membership_changed = membership_changed;
        Ok((
            AuthorityArtifactSnapshot {
                network_id: incoming.network_id,
                enrollment_token: incoming.enrollment_token.or(current.enrollment_token),
                membership,
                capability_grants: grants,
                revocations,
                bootstrap_hints,
            },
            delta,
        ))
    }
}

fn same_grant(left: &CapabilityGrant, right: &CapabilityGrant) -> bool {
    left.network_id == right.network_id
        && left.issuer_peer_id == right.issuer_peer_id
        && left.subject_peer_id == right.subject_peer_id
        && left.sequence == right.sequence
}

fn same_revocation(left: &RevocationRecord, right: &RevocationRecord) -> bool {
    left.sequence == right.sequence
        && left.issuer_peer_id == right.issuer_peer_id
        && left.target == right.target
}

fn same_hint(left: &BootstrapHint, right: &BootstrapHint) -> bool {
    match (&left.peer_id, &right.peer_id) {
        (Some(left_peer), Some(right_peer)) => left_peer == right_peer,
        _ => normalize_addresses(&left.addresses) == normalize_addresses(&right.addresses),
    }
}

fn merge_membership(
    current: Option<MembershipCertificate>,
    incoming: Option<MembershipCertificate>,
) -> Result<Option<MembershipCertificate>, ControlError> {
    match (current, incoming) {
        (None, incoming) => Ok(incoming),
        (Some(current), None) => Ok(Some(current)),
        (Some(current), Some(incoming)) => {
            if current.subject_peer_id != incoming.subject_peer_id {
                return Err(ControlError::SubjectMismatch);
            }
            if incoming.issued_at < current.issued_at {
                return Err(ControlError::MembershipRollback);
            }
            if incoming.issued_at == current.issued_at && incoming != current {
                return Err(ControlError::GrantConflict);
            }
            Ok(Some(
                if incoming.issued_at > current.issued_at
                    || incoming.expires_at >= current.expires_at
                {
                    incoming
                } else {
                    current
                },
            ))
        }
    }
}

fn normalize_addresses(addresses: &[String]) -> Vec<String> {
    let mut values = addresses
        .iter()
        .map(|value| value.trim().to_string())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn endpoint_with_subject(endpoint: &str, subject: Option<&str>) -> String {
    match subject {
        Some(subject) => format!("{endpoint}?subject={subject}"),
        None => endpoint.to_string(),
    }
}

fn endpoint_with_after_sequence(endpoint: &str, after_sequence: Option<u64>) -> String {
    match after_sequence {
        Some(sequence) => format!("{endpoint}?after_sequence={sequence}"),
        None => endpoint.to_string(),
    }
}

fn map_transport_error(error: ureq::Error, subject: Option<&str>) -> ControlError {
    match error {
        ureq::Error::Status(404, _) if subject.is_some() => {
            ControlError::MissingSubject(subject.unwrap_or_default().to_string())
        }
        other => ControlError::Transport(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use crypto::IdentityKeypair;
    use membership::{ResourceLimits, RevocationReason, RevocationTarget};
    use model::ProtocolId;
    use relaywire::{RelayAnnouncement, RelayMap};

    use super::*;

    #[test]
    fn authority_snapshot_retains_bootstrap_hints() {
        let issuer = IdentityKeypair::from_secret_bytes([3_u8; 32]);
        let subject = IdentityKeypair::from_secret_bytes([4_u8; 32]);
        let network_id = NetworkId::derive("control:test");
        let token = EnrollmentToken::issue(
            &issuer,
            network_id.clone(),
            100,
            200,
            "test",
            Some("device-a".to_string()),
            vec!["member".to_string()],
            vec![BootstrapHint {
                peer_id: None,
                addresses: vec!["https://bootstrap.example.invalid".to_string()],
                metadata: BTreeMap::new(),
            }],
            [1_u8; 16],
        );
        let membership = MembershipCertificate::issue(
            &issuer,
            network_id.clone(),
            subject.peer_id(),
            100,
            300,
            vec!["member".to_string()],
        );
        let grant = membership::CapabilityGrant::issue(
            &issuer,
            network_id.clone(),
            subject.peer_id(),
            vec!["records.publish".to_string()],
            vec![ProtocolId::new("/quip/records/1").expect("protocol")],
            ResourceLimits::default(),
            vec![],
            100,
            300,
            1,
        );
        let revocation = RevocationRecord::issue(
            &issuer,
            network_id.clone(),
            RevocationTarget::CapabilityGrant {
                subject_peer_id: subject.peer_id(),
                sequence: 99,
            },
            RevocationReason::Superseded,
            200,
            200,
            2,
            None,
        );
        let snapshot = AuthorityArtifactSnapshot {
            network_id: network_id.clone(),
            enrollment_token: Some(token),
            membership: Some(membership),
            capability_grants: vec![grant],
            revocations: vec![revocation],
            bootstrap_hints: vec![BootstrapHint {
                peer_id: Some(subject.peer_id()),
                addresses: vec!["quic://198.51.100.10:8443".to_string()],
                metadata: BTreeMap::from([("tier".to_string(), "seed".to_string())]),
            }],
        };
        let client = ControlClient {
            network_id,
            endpoints: AuthorityEndpoints {
                enrollment: "https://authority.example.invalid/enroll".to_string(),
                revocation: "https://authority.example.invalid/revoke".to_string(),
                relay_map: "https://authority.example.invalid/relays".to_string(),
                bootstrap: "https://authority.example.invalid/bootstrap".to_string(),
                snapshot: "https://authority.example.invalid/snapshot".to_string(),
            },
        };

        let synced = client
            .sync_authority_snapshot(snapshot)
            .expect("network should match");
        let hints = client.list_bootstrap_hints(&synced);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].metadata.get("tier"), Some(&"seed".to_string()));
    }

    #[test]
    fn merge_snapshot_dedupes_and_tracks_delta() {
        let issuer = IdentityKeypair::from_secret_bytes([5_u8; 32]);
        let subject = IdentityKeypair::from_secret_bytes([6_u8; 32]);
        let network_id = NetworkId::derive("control:merge");
        let membership = MembershipCertificate::issue(
            &issuer,
            network_id.clone(),
            subject.peer_id(),
            100,
            300,
            vec!["member".to_string()],
        );
        let grant_one = membership::CapabilityGrant::issue(
            &issuer,
            network_id.clone(),
            subject.peer_id(),
            vec!["records.publish".to_string()],
            vec![ProtocolId::new("/quip/records/1").expect("protocol")],
            ResourceLimits::default(),
            vec![],
            100,
            300,
            1,
        );
        let grant_two = membership::CapabilityGrant::issue(
            &issuer,
            network_id.clone(),
            subject.peer_id(),
            vec!["control.access".to_string()],
            vec![ProtocolId::new("/quip/control/1").expect("protocol")],
            ResourceLimits::default(),
            vec![],
            100,
            300,
            2,
        );
        let revocation = RevocationRecord::issue(
            &issuer,
            network_id.clone(),
            RevocationTarget::CapabilityGrant {
                subject_peer_id: subject.peer_id(),
                sequence: 2,
            },
            RevocationReason::Superseded,
            200,
            200,
            4,
            None,
        );
        let current = AuthorityArtifactSnapshot {
            network_id: network_id.clone(),
            enrollment_token: None,
            membership: Some(membership.clone()),
            capability_grants: vec![grant_one.clone()],
            revocations: vec![],
            bootstrap_hints: vec![BootstrapHint {
                peer_id: Some(subject.peer_id()),
                addresses: vec!["quic://198.51.100.10:8443".to_string()],
                metadata: BTreeMap::new(),
            }],
        };
        let incoming = AuthorityArtifactSnapshot {
            network_id: network_id.clone(),
            enrollment_token: None,
            membership: Some(membership),
            capability_grants: vec![grant_one, grant_two],
            revocations: vec![revocation],
            bootstrap_hints: vec![
                BootstrapHint {
                    peer_id: Some(subject.peer_id()),
                    addresses: vec!["quic://198.51.100.10:8443".to_string()],
                    metadata: BTreeMap::new(),
                },
                BootstrapHint {
                    peer_id: None,
                    addresses: vec!["https://bootstrap.example.invalid".to_string()],
                    metadata: BTreeMap::new(),
                },
            ],
        };
        let client = ControlClient {
            network_id,
            endpoints: AuthorityEndpoints {
                enrollment: "https://authority.example.invalid/enroll".to_string(),
                revocation: "https://authority.example.invalid/revoke".to_string(),
                relay_map: "https://authority.example.invalid/relays".to_string(),
                bootstrap: "https://authority.example.invalid/bootstrap".to_string(),
                snapshot: "https://authority.example.invalid/snapshot".to_string(),
            },
        };

        let (merged, delta) = client
            .merge_snapshot(Some(current), incoming)
            .expect("merge should succeed");
        assert_eq!(merged.capability_grants.len(), 2);
        assert_eq!(merged.revocations.len(), 1);
        assert_eq!(merged.bootstrap_hints.len(), 2);
        assert_eq!(delta.grants_added, 1);
        assert_eq!(delta.revocations_added, 1);
        assert_eq!(delta.bootstrap_hints_added, 1);
        assert!(!delta.membership_changed);
    }

    #[test]
    fn fetch_authority_snapshot_over_http() {
        let issuer = IdentityKeypair::from_secret_bytes([9_u8; 32]);
        let subject = IdentityKeypair::from_secret_bytes([10_u8; 32]);
        let network_id = NetworkId::derive("control:http");
        let snapshot = AuthorityArtifactSnapshot {
            network_id: network_id.clone(),
            enrollment_token: None,
            membership: Some(MembershipCertificate::issue(
                &issuer,
                network_id.clone(),
                subject.peer_id(),
                100,
                300,
                vec!["member".to_string()],
            )),
            capability_grants: Vec::new(),
            revocations: Vec::new(),
            bootstrap_hints: vec![BootstrapHint {
                peer_id: Some(subject.peer_id()),
                addresses: vec!["quic://198.51.100.20:8443".to_string()],
                metadata: BTreeMap::new(),
            }],
        };
        let relay_map = RelayMap {
            version: 3,
            generated_at: 1234,
            relays: vec![RelayAnnouncement {
                peer_id: issuer.peer_id(),
                region: "fra".to_string(),
                advertised_endpoints: vec!["quic://203.0.113.44:443".to_string()],
                control_endpoint: "http://203.0.113.44:9081".to_string(),
                max_bandwidth_bps: 2_000_000_000,
                supports_quic_datagrams: true,
                supports_path_migration: true,
                traffic_classes: vec!["NetworkControl".to_string()],
            }],
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let snapshot_body =
            serde_json::to_vec(&snapshot).expect("snapshot serialization should work");
        let bootstrap_body = serde_json::to_vec(&snapshot.bootstrap_hints)
            .expect("bootstrap serialization should work");
        let revocations_body = serde_json::to_vec(&snapshot.revocations)
            .expect("revocations serialization should work");
        let relay_map_body =
            serde_json::to_vec(&relay_map).expect("relay-map serialization should work");

        let server = thread::spawn(move || {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().expect("client should connect");
                let mut request = [0_u8; 2048];
                let bytes = stream.read(&mut request).expect("request should read");
                let request = String::from_utf8_lossy(&request[..bytes]);
                let body = if request.starts_with("GET /snapshot ") {
                    &snapshot_body
                } else if request.starts_with("GET /relays ") {
                    &relay_map_body
                } else if request.starts_with("GET /revoke?after_sequence=0 ")
                    || request.starts_with("GET /revoke ")
                {
                    &revocations_body
                } else {
                    &bootstrap_body
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("headers should write");
                stream.write_all(body).expect("body should write");
            }
        });

        let client = ControlClient::from_origin(network_id, &format!("http://{}", addr));
        let fetched = client
            .fetch_authority_snapshot()
            .expect("snapshot fetch should succeed");
        let hints = client
            .fetch_bootstrap_hints()
            .expect("bootstrap fetch should succeed");
        let revocations = client
            .fetch_revocations(Some(0))
            .expect("revocation fetch should succeed");
        let fetched_relay_map = client
            .fetch_relay_map()
            .expect("relay-map fetch should succeed");
        server.join().expect("server thread should finish");

        assert_eq!(fetched.membership, snapshot.membership);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].addresses[0], "quic://198.51.100.20:8443");
        assert_eq!(revocations, snapshot.revocations);
        assert_eq!(fetched_relay_map, relay_map);
    }

    #[test]
    fn merge_snapshot_reports_removed_grants_and_bootstrap_hints() {
        let issuer = IdentityKeypair::from_secret_bytes([41_u8; 32]);
        let subject = IdentityKeypair::from_secret_bytes([42_u8; 32]);
        let network_id = NetworkId::derive("control:removals");
        let membership = MembershipCertificate::issue(
            &issuer,
            network_id.clone(),
            subject.peer_id(),
            100,
            300,
            vec!["member".to_string()],
        );
        let protocol = model::ProtocolId::new("/quip/control/1").expect("protocol");
        let current = AuthorityArtifactSnapshot {
            network_id: network_id.clone(),
            enrollment_token: None,
            membership: Some(membership.clone()),
            capability_grants: vec![
                CapabilityGrant::issue(
                    &issuer,
                    network_id.clone(),
                    subject.peer_id(),
                    vec!["control.access".to_string()],
                    vec![protocol.clone()],
                    membership::ResourceLimits::default(),
                    vec![],
                    100,
                    300,
                    1,
                ),
                CapabilityGrant::issue(
                    &issuer,
                    network_id.clone(),
                    subject.peer_id(),
                    vec!["records.publish".to_string()],
                    vec![model::ProtocolId::new("/quip/records/1").expect("protocol")],
                    membership::ResourceLimits::default(),
                    vec![],
                    100,
                    300,
                    2,
                ),
            ],
            revocations: vec![],
            bootstrap_hints: vec![
                BootstrapHint {
                    peer_id: Some(subject.peer_id()),
                    addresses: vec!["quic://198.51.100.10:8443".to_string()],
                    metadata: BTreeMap::new(),
                },
                BootstrapHint {
                    peer_id: None,
                    addresses: vec!["https://bootstrap.example.invalid".to_string()],
                    metadata: BTreeMap::new(),
                },
            ],
        };
        let incoming = AuthorityArtifactSnapshot {
            network_id: network_id.clone(),
            enrollment_token: None,
            membership: Some(membership),
            capability_grants: vec![current.capability_grants[0].clone()],
            revocations: vec![],
            bootstrap_hints: vec![current.bootstrap_hints[0].clone()],
        };
        let client = ControlClient {
            network_id,
            endpoints: AuthorityEndpoints {
                enrollment: "https://authority.example.invalid/enroll".to_string(),
                revocation: "https://authority.example.invalid/revoke".to_string(),
                relay_map: "https://authority.example.invalid/relays".to_string(),
                bootstrap: "https://authority.example.invalid/bootstrap".to_string(),
                snapshot: "https://authority.example.invalid/snapshot".to_string(),
            },
        };

        let (merged, delta) = client
            .merge_snapshot(Some(current), incoming)
            .expect("merge should succeed");

        assert_eq!(merged.capability_grants.len(), 1);
        assert_eq!(merged.bootstrap_hints.len(), 1);
        assert_eq!(delta.grants_added, 0);
        assert_eq!(delta.grants_removed, 1);
        assert_eq!(delta.bootstrap_hints_added, 0);
        assert_eq!(delta.bootstrap_hints_removed, 1);
    }
}
