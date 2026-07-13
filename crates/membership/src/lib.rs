use std::collections::BTreeMap;

use crypto::{hash_bytes, IdentityKeypair, PublicIdentityKey, SignatureBytes};
use model::{NetworkId, PeerId, ProtocolId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MembershipError {
    #[error("artifact signature validation failed")]
    InvalidSignature,
    #[error("artifact is expired")]
    ExpiredArtifact,
    #[error("artifact is not valid yet")]
    NotYetValid,
    #[error("artifact subject or network does not match")]
    SubjectMismatch,
    #[error("artifact identifier does not match canonical payload")]
    ArtifactIdMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapHint {
    pub peer_id: Option<PeerId>,
    pub addresses: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentToken {
    pub token_id: [u8; 32],
    pub network_id: NetworkId,
    pub issuer_peer_id: PeerId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub realm: String,
    pub subject_alias: Option<String>,
    pub requested_roles: Vec<String>,
    pub bootstrap_hints: Vec<BootstrapHint>,
    pub nonce: [u8; 16],
    pub signature: SignatureBytes,
}

impl EnrollmentToken {
    pub fn issue(
        issuer: &IdentityKeypair,
        network_id: NetworkId,
        issued_at: u64,
        expires_at: u64,
        realm: impl Into<String>,
        subject_alias: Option<String>,
        requested_roles: Vec<String>,
        bootstrap_hints: Vec<BootstrapHint>,
        nonce: [u8; 16],
    ) -> Self {
        let unsigned = UnsignedEnrollmentToken {
            network_id: network_id.clone(),
            issuer_peer_id: issuer.peer_id(),
            issued_at,
            expires_at,
            realm: realm.into(),
            subject_alias,
            requested_roles,
            bootstrap_hints,
            nonce,
        };
        let canonical = canonical_json(&unsigned);
        let token_id = hash_bytes(&canonical);
        let signature = issuer.sign(&canonical);

        Self {
            token_id,
            network_id,
            issuer_peer_id: unsigned.issuer_peer_id,
            issued_at,
            expires_at,
            realm: unsigned.realm,
            subject_alias: unsigned.subject_alias,
            requested_roles: unsigned.requested_roles,
            bootstrap_hints: unsigned.bootstrap_hints,
            nonce,
            signature,
        }
    }

    pub fn verify(
        &self,
        issuer_key: &PublicIdentityKey,
        expected_network: &NetworkId,
        now_epoch_secs: u64,
    ) -> Result<(), MembershipError> {
        if &self.network_id != expected_network {
            return Err(MembershipError::SubjectMismatch);
        }
        if now_epoch_secs > self.expires_at {
            return Err(MembershipError::ExpiredArtifact);
        }

        let unsigned = UnsignedEnrollmentToken::from(self.clone());
        let canonical = canonical_json(&unsigned);
        if hash_bytes(&canonical) != self.token_id {
            return Err(MembershipError::ArtifactIdMismatch);
        }

        self.signature
            .verify(issuer_key, &canonical)
            .map_err(|_| MembershipError::InvalidSignature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipCertificate {
    pub network_id: NetworkId,
    pub subject_peer_id: PeerId,
    pub issuer_peer_id: PeerId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub roles: Vec<String>,
    pub signature: SignatureBytes,
}

impl MembershipCertificate {
    pub fn issue(
        issuer: &IdentityKeypair,
        network_id: NetworkId,
        subject_peer_id: PeerId,
        issued_at: u64,
        expires_at: u64,
        roles: Vec<String>,
    ) -> Self {
        let unsigned = UnsignedMembershipCertificate {
            network_id: network_id.clone(),
            subject_peer_id,
            issuer_peer_id: issuer.peer_id(),
            issued_at,
            expires_at,
            roles,
        };
        let canonical = canonical_json(&unsigned);
        let signature = issuer.sign(&canonical);

        Self {
            network_id,
            subject_peer_id: unsigned.subject_peer_id,
            issuer_peer_id: unsigned.issuer_peer_id,
            issued_at,
            expires_at,
            roles: unsigned.roles,
            signature,
        }
    }

    pub fn verify(
        &self,
        issuer_key: &PublicIdentityKey,
        expected_network: &NetworkId,
        expected_subject: &PeerId,
        now_epoch_secs: u64,
    ) -> Result<(), MembershipError> {
        if &self.network_id != expected_network || &self.subject_peer_id != expected_subject {
            return Err(MembershipError::SubjectMismatch);
        }
        if now_epoch_secs > self.expires_at {
            return Err(MembershipError::ExpiredArtifact);
        }

        let canonical = canonical_json(&UnsignedMembershipCertificate::from(self.clone()));
        self.signature
            .verify(issuer_key, &canonical)
            .map_err(|_| MembershipError::InvalidSignature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub bandwidth_bps: Option<u64>,
    pub concurrent_streams: Option<u32>,
    pub max_object_bytes: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            bandwidth_bps: None,
            concurrent_streams: None,
            max_object_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub network_id: NetworkId,
    pub subject_peer_id: PeerId,
    pub issuer_peer_id: PeerId,
    pub capabilities: Vec<String>,
    pub protocol_scopes: Vec<ProtocolId>,
    pub resource_limits: ResourceLimits,
    pub constraints: Vec<String>,
    pub not_before: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub signature: SignatureBytes,
}

impl CapabilityGrant {
    pub fn issue(
        issuer: &IdentityKeypair,
        network_id: NetworkId,
        subject_peer_id: PeerId,
        capabilities: Vec<String>,
        protocol_scopes: Vec<ProtocolId>,
        resource_limits: ResourceLimits,
        constraints: Vec<String>,
        not_before: u64,
        expires_at: u64,
        sequence: u64,
    ) -> Self {
        let unsigned = UnsignedCapabilityGrant {
            network_id: network_id.clone(),
            subject_peer_id,
            issuer_peer_id: issuer.peer_id(),
            capabilities,
            protocol_scopes,
            resource_limits,
            constraints,
            not_before,
            expires_at,
            sequence,
        };
        let canonical = canonical_json(&unsigned);
        let signature = issuer.sign(&canonical);

        Self {
            network_id,
            subject_peer_id: unsigned.subject_peer_id,
            issuer_peer_id: unsigned.issuer_peer_id,
            capabilities: unsigned.capabilities,
            protocol_scopes: unsigned.protocol_scopes,
            resource_limits: unsigned.resource_limits,
            constraints: unsigned.constraints,
            not_before,
            expires_at,
            sequence,
            signature,
        }
    }

    pub fn verify(
        &self,
        issuer_key: &PublicIdentityKey,
        expected_network: &NetworkId,
        expected_subject: &PeerId,
        now_epoch_secs: u64,
    ) -> Result<(), MembershipError> {
        if &self.network_id != expected_network || &self.subject_peer_id != expected_subject {
            return Err(MembershipError::SubjectMismatch);
        }
        if now_epoch_secs < self.not_before {
            return Err(MembershipError::NotYetValid);
        }
        if now_epoch_secs > self.expires_at {
            return Err(MembershipError::ExpiredArtifact);
        }

        let canonical = canonical_json(&UnsignedCapabilityGrant::from(self.clone()));
        self.signature
            .verify(issuer_key, &canonical)
            .map_err(|_| MembershipError::InvalidSignature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationReason {
    Administrative,
    KeyCompromise,
    Superseded,
    Unspecified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationTarget {
    EnrollmentToken {
        token_id: [u8; 32],
    },
    MembershipCertificate {
        subject_peer_id: PeerId,
        issued_at: u64,
    },
    CapabilityGrant {
        subject_peer_id: PeerId,
        sequence: u64,
    },
    Peer {
        peer_id: PeerId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationRecord {
    pub network_id: NetworkId,
    pub issuer_peer_id: PeerId,
    pub target: RevocationTarget,
    pub reason: RevocationReason,
    pub issued_at: u64,
    pub effective_at: u64,
    pub sequence: u64,
    pub note: Option<String>,
    pub signature: SignatureBytes,
}

impl RevocationRecord {
    pub fn issue(
        issuer: &IdentityKeypair,
        network_id: NetworkId,
        target: RevocationTarget,
        reason: RevocationReason,
        issued_at: u64,
        effective_at: u64,
        sequence: u64,
        note: Option<String>,
    ) -> Self {
        let unsigned = UnsignedRevocationRecord {
            network_id: network_id.clone(),
            issuer_peer_id: issuer.peer_id(),
            target,
            reason,
            issued_at,
            effective_at,
            sequence,
            note,
        };
        let canonical = canonical_json(&unsigned);
        let signature = issuer.sign(&canonical);

        Self {
            network_id,
            issuer_peer_id: unsigned.issuer_peer_id,
            target: unsigned.target,
            reason: unsigned.reason,
            issued_at,
            effective_at,
            sequence,
            note: unsigned.note,
            signature,
        }
    }

    pub fn verify(
        &self,
        issuer_key: &PublicIdentityKey,
        expected_network: &NetworkId,
        now_epoch_secs: u64,
    ) -> Result<(), MembershipError> {
        if &self.network_id != expected_network {
            return Err(MembershipError::SubjectMismatch);
        }
        if now_epoch_secs < self.effective_at {
            return Err(MembershipError::NotYetValid);
        }

        let canonical = canonical_json(&UnsignedRevocationRecord::from(self.clone()));
        self.signature
            .verify(issuer_key, &canonical)
            .map_err(|_| MembershipError::InvalidSignature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedEnrollmentToken {
    network_id: NetworkId,
    issuer_peer_id: PeerId,
    issued_at: u64,
    expires_at: u64,
    realm: String,
    subject_alias: Option<String>,
    requested_roles: Vec<String>,
    bootstrap_hints: Vec<BootstrapHint>,
    nonce: [u8; 16],
}

impl From<EnrollmentToken> for UnsignedEnrollmentToken {
    fn from(value: EnrollmentToken) -> Self {
        Self {
            network_id: value.network_id,
            issuer_peer_id: value.issuer_peer_id,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            realm: value.realm,
            subject_alias: value.subject_alias,
            requested_roles: value.requested_roles,
            bootstrap_hints: value.bootstrap_hints,
            nonce: value.nonce,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedMembershipCertificate {
    network_id: NetworkId,
    subject_peer_id: PeerId,
    issuer_peer_id: PeerId,
    issued_at: u64,
    expires_at: u64,
    roles: Vec<String>,
}

impl From<MembershipCertificate> for UnsignedMembershipCertificate {
    fn from(value: MembershipCertificate) -> Self {
        Self {
            network_id: value.network_id,
            subject_peer_id: value.subject_peer_id,
            issuer_peer_id: value.issuer_peer_id,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            roles: value.roles,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedCapabilityGrant {
    network_id: NetworkId,
    subject_peer_id: PeerId,
    issuer_peer_id: PeerId,
    capabilities: Vec<String>,
    protocol_scopes: Vec<ProtocolId>,
    resource_limits: ResourceLimits,
    constraints: Vec<String>,
    not_before: u64,
    expires_at: u64,
    sequence: u64,
}

impl From<CapabilityGrant> for UnsignedCapabilityGrant {
    fn from(value: CapabilityGrant) -> Self {
        Self {
            network_id: value.network_id,
            subject_peer_id: value.subject_peer_id,
            issuer_peer_id: value.issuer_peer_id,
            capabilities: value.capabilities,
            protocol_scopes: value.protocol_scopes,
            resource_limits: value.resource_limits,
            constraints: value.constraints,
            not_before: value.not_before,
            expires_at: value.expires_at,
            sequence: value.sequence,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedRevocationRecord {
    network_id: NetworkId,
    issuer_peer_id: PeerId,
    target: RevocationTarget,
    reason: RevocationReason,
    issued_at: u64,
    effective_at: u64,
    sequence: u64,
    note: Option<String>,
}

impl From<RevocationRecord> for UnsignedRevocationRecord {
    fn from(value: RevocationRecord) -> Self {
        Self {
            network_id: value.network_id,
            issuer_peer_id: value.issuer_peer_id,
            target: value.target,
            reason: value.reason,
            issued_at: value.issued_at,
            effective_at: value.effective_at,
            sequence: value.sequence,
            note: value.note,
        }
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("membership artifact serialization should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_hint() -> BootstrapHint {
        BootstrapHint {
            peer_id: None,
            addresses: vec!["https://bootstrap.example.invalid:8443".to_string()],
            metadata: BTreeMap::from([("region".to_string(), "test".to_string())]),
        }
    }

    #[test]
    fn enrollment_tokens_issue_and_verify() {
        let issuer = IdentityKeypair::from_secret_bytes([1_u8; 32]);
        let network_id = NetworkId::derive("realm:test");
        let token = EnrollmentToken::issue(
            &issuer,
            network_id.clone(),
            100,
            200,
            "test",
            Some("device-a".to_string()),
            vec!["member".to_string()],
            vec![fixture_hint()],
            [7_u8; 16],
        );

        token
            .verify(&issuer.public_key(), &network_id, 150)
            .expect("enrollment token should verify");
    }

    #[test]
    fn membership_certificates_issue_and_verify() {
        let issuer = IdentityKeypair::from_secret_bytes([2_u8; 32]);
        let subject = IdentityKeypair::from_secret_bytes([3_u8; 32]);
        let network_id = NetworkId::derive("realm:test");
        let certificate = MembershipCertificate::issue(
            &issuer,
            network_id.clone(),
            subject.peer_id(),
            100,
            200,
            vec!["member".to_string(), "relay".to_string()],
        );

        certificate
            .verify(&issuer.public_key(), &network_id, &subject.peer_id(), 150)
            .expect("membership certificate should verify");
    }

    #[test]
    fn capability_grants_reject_early_use() {
        let issuer = IdentityKeypair::from_secret_bytes([4_u8; 32]);
        let subject = IdentityKeypair::from_secret_bytes([5_u8; 32]);
        let network_id = NetworkId::derive("realm:test");
        let grant = CapabilityGrant::issue(
            &issuer,
            network_id.clone(),
            subject.peer_id(),
            vec!["records.publish".to_string()],
            vec![ProtocolId::new("/quicnet/records/1").expect("protocol")],
            ResourceLimits::default(),
            vec![],
            150,
            300,
            1,
        );

        let err = grant
            .verify(&issuer.public_key(), &network_id, &subject.peer_id(), 149)
            .expect_err("grant should not be valid before not_before");
        assert!(matches!(err, MembershipError::NotYetValid));
    }

    #[test]
    fn revocation_records_issue_and_verify() {
        let issuer = IdentityKeypair::from_secret_bytes([6_u8; 32]);
        let subject = IdentityKeypair::from_secret_bytes([7_u8; 32]);
        let network_id = NetworkId::derive("realm:test");
        let revocation = RevocationRecord::issue(
            &issuer,
            network_id.clone(),
            RevocationTarget::Peer {
                peer_id: subject.peer_id(),
            },
            RevocationReason::Administrative,
            300,
            300,
            9,
            Some("rotated credentials".to_string()),
        );

        revocation
            .verify(&issuer.public_key(), &network_id, 300)
            .expect("revocation should verify");
    }
}
