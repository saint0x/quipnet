use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    OpenInternet,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    UdpBlocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeStatus {
    Pending,
    Passed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeObservation {
    pub vantage: String,
    pub status: ProbeStatus,
    pub latency_ms: Option<u32>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetcheckReport {
    pub nat_type: NatType,
    pub udp_reachable: bool,
    pub ipv6_reachable: bool,
    pub hairpin_supported: bool,
    pub public_udp_addr: Option<String>,
    pub port_mapped: bool,
    pub probe_observations: Vec<ProbeObservation>,
}

impl NetcheckReport {
    pub fn relay_required(&self) -> bool {
        !self.udp_reachable || matches!(self.nat_type, NatType::Symmetric | NatType::UdpBlocked)
    }

    pub fn summary(&self) -> String {
        let mut parts = vec![
            format!("nat={:?}", self.nat_type),
            format!(
                "udp={}",
                if self.udp_reachable {
                    "reachable"
                } else {
                    "blocked"
                }
            ),
            format!(
                "ipv6={}",
                if self.ipv6_reachable {
                    "reachable"
                } else {
                    "unavailable"
                }
            ),
            format!(
                "hairpin={}",
                if self.hairpin_supported {
                    "supported"
                } else {
                    "unsupported"
                }
            ),
        ];

        if let Some(addr) = &self.public_udp_addr {
            parts.push(format!("public_addr={addr}"));
        }
        if self.port_mapped {
            parts.push("portmap=active".into());
        }
        if self.relay_required() {
            parts.push("relay=fallback-required".into());
        }

        parts.join(", ")
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.udp_reachable {
            warnings.push("UDP connectivity is blocked; direct QUIC paths will fail.".into());
        }
        if matches!(self.nat_type, NatType::Symmetric) {
            warnings.push("Symmetric NAT detected; relay capacity should be kept warm.".into());
        }
        if !self.ipv6_reachable {
            warnings.push("IPv6 pathing is unavailable; dual-stack upgrades are disabled.".into());
        }
        if !self.hairpin_supported {
            warnings.push(
                "Hairpinning is unavailable; same-site reflexive testing may degrade.".into(),
            );
        }
        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_requirement_and_summary_track_reachability() {
        let report = NetcheckReport {
            nat_type: NatType::Symmetric,
            udp_reachable: false,
            ipv6_reachable: false,
            hairpin_supported: false,
            public_udp_addr: Some("198.51.100.20:4242".into()),
            port_mapped: false,
            probe_observations: vec![ProbeObservation {
                vantage: "iad-relay".into(),
                status: ProbeStatus::Failed,
                latency_ms: None,
                detail: "timeout waiting for reflexive response".into(),
            }],
        };

        assert!(report.relay_required());
        assert!(report.summary().contains("relay=fallback-required"));
        assert!(!report.warnings().is_empty());
    }
}
