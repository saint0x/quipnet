use membership::CapabilityGrant;
use model::{NetworkId, PeerId, ProtocolId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub effect: Effect,
    pub network_id: Option<NetworkId>,
    pub protocol: Option<ProtocolId>,
    pub source_peer: Option<PeerId>,
    pub required_capability: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    pub fn with_rules(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    pub fn evaluate(
        &self,
        network_id: &NetworkId,
        source_peer: &PeerId,
        protocol: &ProtocolId,
        grants: &[CapabilityGrant],
    ) -> Decision {
        for rule in &self.rules {
            if rule.network_id.as_ref().is_some_and(|id| id != network_id) {
                continue;
            }
            if rule
                .source_peer
                .as_ref()
                .is_some_and(|peer| peer != source_peer)
            {
                continue;
            }
            if rule.protocol.as_ref().is_some_and(|id| id != protocol) {
                continue;
            }
            if let Some(capability) = &rule.required_capability {
                let has_capability = grants.iter().any(|grant| {
                    grant
                        .capabilities
                        .iter()
                        .any(|existing| existing == capability)
                        && grant.protocol_scopes.iter().any(|scope| scope == protocol)
                });
                if !has_capability {
                    continue;
                }
            }

            return Decision {
                allowed: matches!(rule.effect, Effect::Allow),
                reason: format!("{:?} rule matched for {}", rule.effect, protocol.as_str()),
            };
        }

        Decision {
            allowed: false,
            reason: format!("no matching policy rule for {}", protocol.as_str()),
        }
    }
}
