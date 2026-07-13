use model::PathStats;
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeSnapshot {
    pub active_peers: usize,
    pub relayed_connections: usize,
    pub direct_connections: usize,
    pub path_stats: Vec<PathStats>,
}

pub fn init_tracing(default_filter: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_filter.to_string()));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(false)
        .try_init();
}
