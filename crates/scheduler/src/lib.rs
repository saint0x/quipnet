use model::TrafficClass;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueuePolicy {
    pub class: TrafficClass,
    pub max_inflight_messages: usize,
    pub drop_stale: bool,
}

pub fn default_queue_policies() -> Vec<QueuePolicy> {
    vec![
        QueuePolicy {
            class: TrafficClass::Control,
            max_inflight_messages: 1_024,
            drop_stale: false,
        },
        QueuePolicy {
            class: TrafficClass::Interactive,
            max_inflight_messages: 4_096,
            drop_stale: true,
        },
        QueuePolicy {
            class: TrafficClass::Bulk,
            max_inflight_messages: 16_384,
            drop_stale: false,
        },
        QueuePolicy {
            class: TrafficClass::Background,
            max_inflight_messages: 2_048,
            drop_stale: false,
        },
    ]
}

pub fn policy_for(class: TrafficClass) -> QueuePolicy {
    default_queue_policies()
        .into_iter()
        .find(|policy| policy.class == class)
        .expect("all traffic classes should have a queue policy")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_policy_for_each_class() {
        let policy = policy_for(TrafficClass::Interactive);
        assert!(policy.drop_stale);
        assert_eq!(policy.max_inflight_messages, 4_096);
    }
}
