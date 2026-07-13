use std::collections::{BTreeMap, BTreeSet};

use model::ProtocolId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("protocol is not registered: {0}")]
    Unregistered(String),
    #[error("no mutually compatible version for protocol: {0}")]
    NoCompatibleVersion(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolDescriptor {
    pub id: ProtocolId,
    pub compatible_versions: BTreeSet<u16>,
    pub required_features: BTreeSet<String>,
    pub optional_features: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedProtocol {
    pub id: ProtocolId,
    pub version: u16,
    pub enabled_features: BTreeSet<String>,
}

#[derive(Debug, Default)]
pub struct ProtocolRegistry {
    protocols: BTreeMap<String, ProtocolDescriptor>,
}

impl ProtocolRegistry {
    pub fn register(&mut self, descriptor: ProtocolDescriptor) {
        self.protocols
            .insert(descriptor.id.as_str().to_string(), descriptor);
    }

    pub fn negotiate(
        &self,
        peer_offers: &[ProtocolDescriptor],
    ) -> Result<Vec<NegotiatedProtocol>, ProtocolError> {
        let mut negotiated = Vec::new();
        for offer in peer_offers {
            let local = self
                .protocols
                .get(offer.id.as_str())
                .ok_or_else(|| ProtocolError::Unregistered(offer.id.as_str().to_string()))?;
            let Some(version) = local
                .compatible_versions
                .intersection(&offer.compatible_versions)
                .copied()
                .max()
            else {
                return Err(ProtocolError::NoCompatibleVersion(
                    offer.id.as_str().to_string(),
                ));
            };
            let enabled_features = local
                .optional_features
                .intersection(&offer.optional_features)
                .cloned()
                .collect();
            negotiated.push(NegotiatedProtocol {
                id: offer.id.clone(),
                version,
                enabled_features,
            });
        }
        Ok(negotiated)
    }
}
