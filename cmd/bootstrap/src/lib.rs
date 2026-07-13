use std::collections::BTreeMap;

use membership::BootstrapHint;
use model::NetworkId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapServiceConfig {
    pub network_id: NetworkId,
    pub bind_addr: String,
    pub advertised_origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapRealmState {
    pub realm: String,
    pub hints: Vec<BootstrapHint>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapSnapshot {
    pub config: BootstrapServiceConfig,
    pub realms: Vec<BootstrapRealmState>,
}

#[derive(Debug, Clone)]
pub struct BootstrapService {
    config: BootstrapServiceConfig,
    realms: BTreeMap<String, BootstrapRealmState>,
}

impl BootstrapService {
    pub fn new(config: BootstrapServiceConfig) -> Self {
        Self {
            config,
            realms: BTreeMap::new(),
        }
    }

    pub fn stage_hint(&mut self, realm: impl Into<String>, hint: BootstrapHint) {
        let realm = realm.into();
        self.realms
            .entry(realm.clone())
            .or_insert_with(|| BootstrapRealmState {
                realm: realm.clone(),
                hints: Vec::new(),
                metadata: BTreeMap::new(),
            })
            .hints
            .push(hint);
    }

    pub fn set_realm_metadata(
        &mut self,
        realm: impl Into<String>,
        metadata: BTreeMap<String, String>,
    ) {
        let realm = realm.into();
        self.realms
            .entry(realm.clone())
            .and_modify(|state| state.metadata = metadata.clone())
            .or_insert_with(|| BootstrapRealmState {
                realm,
                hints: Vec::new(),
                metadata,
            });
    }

    pub fn snapshot(&self) -> BootstrapSnapshot {
        BootstrapSnapshot {
            config: self.config.clone(),
            realms: self.realms.values().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_hints_appear_in_snapshot() {
        let network_id = NetworkId::derive("bootstrap:test");
        let mut service = BootstrapService::new(BootstrapServiceConfig {
            network_id,
            bind_addr: "0.0.0.0:8443".to_string(),
            advertised_origin: "https://bootstrap.example.invalid:8443".to_string(),
        });
        service.stage_hint(
            "test",
            BootstrapHint {
                peer_id: None,
                addresses: vec!["quic://203.0.113.20:8443".to_string()],
                metadata: BTreeMap::from([("priority".to_string(), "0".to_string())]),
            },
        );

        let snapshot = service.snapshot();
        assert_eq!(snapshot.realms.len(), 1);
        assert_eq!(snapshot.realms[0].hints.len(), 1);
    }
}
