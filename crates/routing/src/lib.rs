use model::{PathKind, PeerId, TrafficClass};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathScoreBreakdown {
    pub total: u32,
    pub latency_cost: u32,
    pub jitter_cost: u32,
    pub loss_cost: u32,
    pub throughput_cost: u32,
    pub relay_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathExplanation {
    pub class: TrafficClass,
    pub score: PathScoreBreakdown,
    pub summary: String,
    pub strengths: Vec<String>,
    pub tradeoffs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathDecision {
    pub selected: PathCandidate,
    pub class: TrafficClass,
    pub explanation: PathExplanation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_latency_path_scores_better_for_interactive() {
        let fast = PathCandidate {
            peer: peer("fast"),
            path_kind: PathKind::DirectIpv6,
            relay_peer: None,
            source: PathSource::Observed,
            traffic_classes: vec![TrafficClass::Interactive, TrafficClass::Control],
            rtt_ms: 12,
            jitter_ms: 2,
            loss_pct: 0.1,
            throughput_mbps: 500,
            relay_penalty: 0,
        };
        let slow = PathCandidate {
            peer: peer("slow"),
            path_kind: PathKind::Relay,
            relay_peer: Some(peer("relay-hop")),
            source: PathSource::AuthorityRelay,
            traffic_classes: vec![TrafficClass::Interactive, TrafficClass::Control],
            rtt_ms: 28,
            jitter_ms: 5,
            loss_pct: 0.2,
            throughput_mbps: 900,
            relay_penalty: 25,
        };

        assert!(fast.score(TrafficClass::Interactive) < slow.score(TrafficClass::Interactive));
    }

    #[test]
    fn selector_prefers_higher_throughput_for_bulk() {
        let direct = PathCandidate {
            peer: peer("direct"),
            path_kind: PathKind::DirectUdp,
            relay_peer: None,
            source: PathSource::Observed,
            traffic_classes: vec![TrafficClass::Bulk, TrafficClass::Interactive],
            rtt_ms: 35,
            jitter_ms: 4,
            loss_pct: 0.2,
            throughput_mbps: 300,
            relay_penalty: 0,
        };
        let relay = PathCandidate {
            peer: peer("relay"),
            path_kind: PathKind::Relay,
            relay_peer: Some(peer("relay-hop")),
            source: PathSource::AuthorityRelay,
            traffic_classes: vec![TrafficClass::Bulk, TrafficClass::Control],
            rtt_ms: 45,
            jitter_ms: 6,
            loss_pct: 0.1,
            throughput_mbps: 800,
            relay_penalty: 25,
        };

        let decision = select_best_path(&[direct, relay.clone()], TrafficClass::Bulk)
            .expect("a routing should be selected");
        assert_eq!(decision.selected.peer, relay.peer);
    }

    fn peer(label: &str) -> PeerId {
        PeerId::from_public_key(model::KeyAlgorithm::Ed25519, label.as_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathCandidate {
    pub peer: PeerId,
    pub path_kind: PathKind,
    pub relay_peer: Option<PeerId>,
    pub source: PathSource,
    pub traffic_classes: Vec<TrafficClass>,
    pub rtt_ms: u32,
    pub jitter_ms: u32,
    pub loss_pct: f32,
    pub throughput_mbps: u32,
    pub relay_penalty: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PathSource {
    Observed,
    Bootstrap,
    AuthorityRelay,
}

impl PathCandidate {
    pub fn supports_class(&self, class: TrafficClass) -> bool {
        self.traffic_classes.contains(&class)
    }

    pub fn score(&self, class: TrafficClass) -> u32 {
        self.score_breakdown(class).total
    }

    pub fn score_breakdown(&self, class: TrafficClass) -> PathScoreBreakdown {
        match class {
            TrafficClass::Control | TrafficClass::Interactive => PathScoreBreakdown {
                total: self.rtt_ms
                    + self.jitter_ms * 2
                    + self.relay_penalty
                    + (self.loss_pct * 10.0) as u32,
                latency_cost: self.rtt_ms,
                jitter_cost: self.jitter_ms * 2,
                loss_cost: (self.loss_pct * 10.0) as u32,
                throughput_cost: 0,
                relay_cost: self.relay_penalty,
            },
            TrafficClass::Bulk => PathScoreBreakdown {
                total: self.relay_penalty + 250_u32.saturating_sub(self.throughput_mbps / 4),
                latency_cost: 0,
                jitter_cost: 0,
                loss_cost: (self.loss_pct * 20.0) as u32,
                throughput_cost: 250_u32.saturating_sub(self.throughput_mbps / 4),
                relay_cost: self.relay_penalty,
            },
            TrafficClass::Background => PathScoreBreakdown {
                total: self.relay_penalty + self.rtt_ms / 2 + (self.loss_pct * 8.0) as u32,
                latency_cost: self.rtt_ms / 2,
                jitter_cost: 0,
                loss_cost: (self.loss_pct * 8.0) as u32,
                throughput_cost: 0,
                relay_cost: self.relay_penalty,
            },
        }
    }

    pub fn explain(&self, class: TrafficClass) -> PathExplanation {
        let score = self.score_breakdown(class);
        let mut strengths = Vec::new();
        let mut tradeoffs = Vec::new();

        if self.rtt_ms <= 25 {
            strengths.push(format!("low RTT at {} ms", self.rtt_ms));
        }
        if self.throughput_mbps >= 500 {
            strengths.push(format!("high throughput at {} Mbps", self.throughput_mbps));
        }
        if self.relay_penalty == 0 {
            strengths.push("direct routing avoids relay tax".into());
        }
        if self.path_kind == PathKind::Relay {
            tradeoffs.push("relay routing adds intermediate hop cost".into());
            if let Some(relay_peer) = &self.relay_peer {
                strengths.push(format!("reachable through relay {}", relay_peer));
            }
        }
        if self.loss_pct >= 1.0 {
            tradeoffs.push(format!("loss is elevated at {:.1}%", self.loss_pct));
        }
        if self.jitter_ms >= 10 {
            tradeoffs.push(format!("jitter is elevated at {} ms", self.jitter_ms));
        }

        PathExplanation {
            class,
            score: score.clone(),
            summary: format!(
                "{:?} routing for {} via {} from {:?} scores {} for {:?} traffic",
                self.path_kind,
                self.peer,
                self.relay_peer
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "direct".to_string()),
                self.source,
                score.total,
                class
            ),
            strengths,
            tradeoffs,
        }
    }
}

pub fn select_best_path(candidates: &[PathCandidate], class: TrafficClass) -> Option<PathDecision> {
    let selected = candidates
        .iter()
        .filter(|candidate| candidate.supports_class(class))
        .min_by_key(|candidate| candidate.score(class))?
        .clone();
    let explanation = selected.explain(class);
    Some(PathDecision {
        selected,
        class,
        explanation,
    })
}
