use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use blake3::Hasher;
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const NETWORK_ID_DOMAIN: &[u8] = b"quicnet:network-id:v1";
const CONTENT_ID_DOMAIN: &[u8] = b"quicnet:content-id:v1";
const BLAKE3_256_MULTIHASH_CODE: u64 = 0x1E;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum KeyAlgorithm {
    Ed25519 = 0xED,
    X25519 = 0xEC,
}

impl KeyAlgorithm {
    pub fn codec(self) -> u64 {
        self as u64
    }
}

#[derive(Debug, Error)]
pub enum TypeError {
    #[error("peer id text prefix is invalid")]
    InvalidPeerIdPrefix,
    #[error("peer id encoding is invalid: {0}")]
    InvalidPeerIdEncoding(String),
    #[error("protocol id must start with '/' and contain at least one namespace")]
    InvalidProtocolId,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PeerId(#[serde(with = "serde_bytes_vec")] Vec<u8>);

impl PeerId {
    pub fn from_public_key(algorithm: KeyAlgorithm, public_key: &[u8]) -> Self {
        let mut codec_buf = unsigned_varint::encode::u64_buffer();
        let codec = unsigned_varint::encode::u64(algorithm.codec(), &mut codec_buf);
        let multihash = encode_multihash(public_key);

        let mut bytes = Vec::with_capacity(codec.len() + multihash.len());
        bytes.extend_from_slice(codec);
        bytes.extend_from_slice(&multihash);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_text(&self) -> String {
        format!("peer1{}", BASE32_NOPAD.encode(&self.0).to_lowercase())
    }
}

impl Display for PeerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl FromStr for PeerId {
    type Err = TypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(encoded) = value.strip_prefix("peer1") else {
            return Err(TypeError::InvalidPeerIdPrefix);
        };

        let bytes = BASE32_NOPAD
            .decode(encoded.to_ascii_uppercase().as_bytes())
            .map_err(|err| TypeError::InvalidPeerIdEncoding(err.to_string()))?;

        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct NetworkId([u8; 32]);

impl NetworkId {
    pub fn derive(scope: impl AsRef<[u8]>) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(NETWORK_ID_DOMAIN);
        hasher.update(scope.as_ref());
        Self(*hasher.finalize().as_bytes())
    }

    pub fn to_text(&self) -> String {
        format!("net1{}", BASE32_NOPAD.encode(&self.0).to_lowercase())
    }
}

fn encode_multihash(payload: &[u8]) -> Vec<u8> {
    let digest = *Hasher::new().update(payload).finalize().as_bytes();

    let mut code_buf = unsigned_varint::encode::u64_buffer();
    let code = unsigned_varint::encode::u64(BLAKE3_256_MULTIHASH_CODE, &mut code_buf);
    let mut size_buf = unsigned_varint::encode::u64_buffer();
    let size = unsigned_varint::encode::u64(digest.len() as u64, &mut size_buf);

    let mut bytes = Vec::with_capacity(code.len() + size.len() + digest.len());
    bytes.extend_from_slice(code);
    bytes.extend_from_slice(size);
    bytes.extend_from_slice(&digest);
    bytes
}

impl Display for NetworkId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ContentId([u8; 32]);

impl ContentId {
    pub fn hash(content: impl AsRef<[u8]>) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONTENT_ID_DOMAIN);
        hasher.update(content.as_ref());
        Self(*hasher.finalize().as_bytes())
    }
}

impl Display for ContentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&BASE32_NOPAD.encode(&self.0).to_lowercase())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ProtocolId(String);

impl ProtocolId {
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        if !value.starts_with('/') || value.matches('/').count() < 2 {
            return Err(TypeError::InvalidProtocolId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ProtocolId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ProtocolId {
    type Err = TypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct RecordNamespace(String);

impl RecordNamespace {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrafficClass {
    Control,
    Interactive,
    Bulk,
    Background,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PathKind {
    DirectUdp,
    DirectIpv6,
    Relay,
    Loopback,
    Lan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathStats {
    pub peer: PeerId,
    pub path_kind: PathKind,
    pub rtt_ms: u32,
    pub jitter_ms: u32,
    pub loss_pct: f32,
    pub relay_peer: Option<PeerId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerView {
    pub peer: PeerId,
    pub protocols: BTreeSet<ProtocolId>,
    pub addresses: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        <Vec<u8>>::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_roundtrips_text() {
        let peer_id = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"canonical-public-key");
        let text = peer_id.to_text();
        let reparsed = PeerId::from_str(&text).expect("peer id should parse");
        assert_eq!(peer_id, reparsed);
    }

    #[test]
    fn peer_id_is_stable() {
        let first = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"canonical-public-key");
        let second = PeerId::from_public_key(KeyAlgorithm::Ed25519, b"canonical-public-key");
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn protocol_ids_must_be_namespaced() {
        assert!(ProtocolId::new("quicnet").is_err());
        assert!(ProtocolId::new("/quicnet").is_err());
        assert!(ProtocolId::new("/quicnet/records/1").is_ok());
    }
}
