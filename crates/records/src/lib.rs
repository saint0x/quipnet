use crypto::{hash_bytes, IdentityKeypair, PublicIdentityKey, SignatureBytes};
use model::{NetworkId, PeerId, RecordNamespace};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecordError {
    #[error("record signature is invalid")]
    InvalidSignature,
    #[error("record payload hash does not match payload bytes")]
    PayloadHashMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRecord {
    pub network_id: NetworkId,
    pub namespace: RecordNamespace,
    pub record_type: String,
    pub schema_version: u16,
    pub author_peer_id: PeerId,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub previous_hash: Option<[u8; 32]>,
    pub payload_hash: [u8; 32],
    pub payload: Vec<u8>,
    pub signature: SignatureBytes,
}

impl SignedRecord {
    pub fn sign(
        network_id: NetworkId,
        namespace: RecordNamespace,
        record_type: impl Into<String>,
        schema_version: u16,
        author: &IdentityKeypair,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
        previous_hash: Option<[u8; 32]>,
        payload: Vec<u8>,
    ) -> Self {
        let payload_hash = hash_bytes(&payload);
        let unsigned = UnsignedRecord {
            network_id: network_id.clone(),
            namespace: namespace.clone(),
            record_type: record_type.into(),
            schema_version,
            author_peer_id: author.peer_id(),
            sequence,
            issued_at,
            expires_at,
            previous_hash,
            payload_hash,
            payload: payload.clone(),
        };
        let signature = author.sign(&serde_json::to_vec(&unsigned).expect("record serialization"));

        Self {
            network_id,
            namespace,
            record_type: unsigned.record_type,
            schema_version,
            author_peer_id: unsigned.author_peer_id,
            sequence,
            issued_at,
            expires_at,
            previous_hash,
            payload_hash,
            payload,
            signature,
        }
    }

    pub fn verify(&self, public_key: &PublicIdentityKey) -> Result<(), RecordError> {
        if hash_bytes(&self.payload) != self.payload_hash {
            return Err(RecordError::PayloadHashMismatch);
        }

        let unsigned = UnsignedRecord::from(self.clone());
        let canonical = serde_json::to_vec(&unsigned).expect("record serialization");
        self.signature
            .verify(public_key, &canonical)
            .map_err(|_| RecordError::InvalidSignature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedRecord {
    network_id: NetworkId,
    namespace: RecordNamespace,
    record_type: String,
    schema_version: u16,
    author_peer_id: PeerId,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    previous_hash: Option<[u8; 32]>,
    payload_hash: [u8; 32],
    payload: Vec<u8>,
}

impl From<SignedRecord> for UnsignedRecord {
    fn from(value: SignedRecord) -> Self {
        Self {
            network_id: value.network_id,
            namespace: value.namespace,
            record_type: value.record_type,
            schema_version: value.schema_version,
            author_peer_id: value.author_peer_id,
            sequence: value.sequence,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            previous_hash: value.previous_hash,
            payload_hash: value.payload_hash,
            payload: value.payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto::IdentityKeypair;
    use model::{NetworkId, RecordNamespace};
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn signed_record_verifies() {
        let author = IdentityKeypair::generate(&mut OsRng);
        let record = SignedRecord::sign(
            NetworkId::derive("personalcloud-prod"),
            RecordNamespace::new("peers"),
            "PeerRecord",
            1,
            &author,
            7,
            1_717_171_717,
            1_717_171_777,
            None,
            br#"{"versions":["1"]}"#.to_vec(),
        );
        record.verify(&author.public_key()).unwrap();
    }
}
