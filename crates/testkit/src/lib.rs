use std::collections::BTreeMap;

use model::PeerId;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LinkProfile {
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_pct: f32,
    pub bandwidth_mbps: u32,
}

#[derive(Debug)]
pub struct DeterministicNetworkSim {
    rng: StdRng,
    links: BTreeMap<(PeerId, PeerId), LinkProfile>,
}

impl DeterministicNetworkSim {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            links: BTreeMap::new(),
        }
    }

    pub fn add_link(&mut self, left: PeerId, right: PeerId, profile: LinkProfile) {
        self.links
            .insert((left.clone(), right.clone()), profile.clone());
        self.links.insert((right, left), profile);
    }

    pub fn sample_latency(&mut self, left: &PeerId, right: &PeerId) -> Option<u32> {
        let link = self.links.get(&(left.clone(), right.clone()))?;
        let jitter = self.rng.gen_range(0..=link.jitter_ms);
        Some(link.latency_ms + jitter)
    }
}
