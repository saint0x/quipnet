use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use clap::Parser;
use crypto::IdentityKeypair;
use fabric::{DaemonConfig, LocalControlPlane, ProtocolId, SessionSnapshot, TrafficClass};
use identity::{FileKeystore, IdentityKeystore};
use quic::QuicTransportAdapter;
use rand::rngs::OsRng;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,

    #[arg(long, default_value = "./var/quicnetd/state.json")]
    state_path: String,

    #[arg(long, default_value = "./var/quicnetd/identity.json")]
    identity_path: String,

    #[arg(long, default_value = "QUICNET_IDENTITY_PASSPHRASE")]
    identity_passphrase_env: String,

    #[arg(long)]
    authority_snapshot: Option<String>,

    #[arg(long)]
    authority_origin: Option<String>,

    #[arg(long)]
    authority_subject: Option<String>,

    #[arg(long, default_value_t = false)]
    sync: bool,

    #[arg(long, default_value_t = false)]
    revocation_sync: bool,

    #[arg(long, default_value_t = false)]
    disable_reconcile: bool,

    #[arg(long, default_value_t = false)]
    reconcile_verbose: bool,

    #[arg(long, default_value_t = 30)]
    reconcile_interval_seconds: u64,

    #[arg(long, default_value_t = 1000)]
    change_watch_interval_ms: u64,

    #[arg(long)]
    network_change_trigger_path: Option<String>,

    #[arg(long, default_value_t = false)]
    one_shot: bool,

    #[arg(long)]
    connect_protocol: Option<String>,

    #[arg(long)]
    connect_peer: Option<String>,

    #[arg(long, default_value = "interactive")]
    connect_class: String,
}

#[derive(Debug)]
struct DaemonCycleReport {
    trigger: CycleTrigger,
    state: fabric::DaemonState,
    reconcile_report: Option<fabric::SessionReconcileReport>,
    active_session: Option<SessionSnapshot>,
    connect_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CycleTrigger {
    Startup,
    IntervalElapsed,
    StateChanged,
    AuthoritySnapshotChanged,
    NetworkChangeRequested,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    exists: bool,
    len: Option<u64>,
    modified: Option<SystemTime>,
}

#[derive(Debug)]
struct DaemonTriggerMonitor {
    state_path: PathBuf,
    authority_snapshot_path: Option<PathBuf>,
    network_change_trigger_path: Option<PathBuf>,
    state_fingerprint: FileFingerprint,
    authority_snapshot_fingerprint: Option<FileFingerprint>,
    network_change_trigger_fingerprint: Option<FileFingerprint>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    observability::init_tracing("quicnetd");
    let args = Args::parse();
    let control = LocalControlPlane::new(DaemonConfig::new(
        args.network.clone(),
        args.state_path.clone(),
    ));

    initialize_state(&args, &control).expect("daemon state should persist");
    let mut trigger_monitor = DaemonTriggerMonitor::new(&args);
    let mut trigger = CycleTrigger::Startup;

    loop {
        let report = match run_cycle(&args, &control, trigger.clone()).await {
            Ok(report) => report,
            Err(error) => {
                eprintln!("quicnetd cycle failed: {error}");
                std::process::exit(1);
            }
        };
        emit_cycle_report(&args, &report);

        if args.one_shot {
            break;
        }

        trigger_monitor.refresh_baseline();
        match wait_for_next_cycle(&args, &mut trigger_monitor).await {
            Ok(next_trigger) => trigger = next_trigger,
            Err(WaitOutcome::Interrupted) => {
                println!("quicnetd stopping: received interrupt");
                break;
            }
            Err(WaitOutcome::SignalError(error)) => {
                eprintln!("quicnetd signal handling failed: {error}");
                std::process::exit(1);
            }
        }
    }
}

#[derive(Debug)]
enum WaitOutcome {
    Interrupted,
    SignalError(std::io::Error),
}

fn initialize_state(
    args: &Args,
    control: &LocalControlPlane,
) -> Result<fabric::DaemonState, fabric::DaemonStateError> {
    let state = match (
        args.authority_snapshot.as_deref(),
        args.authority_origin.as_deref(),
    ) {
        (Some(path), None) => {
            if args.sync {
                control
                    .sync_authority_snapshot(path)
                    .map(|(state, _)| state)
            } else {
                control.seed_from_authority_snapshot(path)
            }
        }
        (None, Some(origin)) => {
            if args.sync {
                control
                    .sync_authority_origin(origin, args.authority_subject.as_deref())
                    .map(|(state, _)| state)
            } else {
                control.seed_from_authority_origin(origin, args.authority_subject.as_deref())
            }
        }
        (None, None) => control.refresh_and_persist(),
        (Some(_), Some(_)) => {
            panic!("only one of --authority-snapshot or --authority-origin may be supplied")
        }
    }?;

    if args.revocation_sync {
        if let Some(origin) = args.authority_origin.as_deref() {
            control
                .sync_authority_revocations_origin(origin)
                .map(|(state, _)| state)
        } else {
            Ok(state)
        }
    } else {
        Ok(state)
    }
}

fn refresh_state(
    args: &Args,
    control: &LocalControlPlane,
) -> Result<fabric::DaemonState, fabric::DaemonStateError> {
    let state = match (
        args.sync,
        args.authority_snapshot.as_deref(),
        args.authority_origin.as_deref(),
    ) {
        (true, Some(path), None) => control
            .sync_authority_snapshot(path)
            .map(|(state, _)| state),
        (true, None, Some(origin)) => control
            .sync_authority_origin(origin, args.authority_subject.as_deref())
            .map(|(state, _)| state),
        _ => control.refresh_and_persist(),
    }?;

    if args.revocation_sync {
        if let Some(origin) = args.authority_origin.as_deref() {
            control
                .sync_authority_revocations_origin(origin)
                .map(|(state, _)| state)
        } else {
            Ok(state)
        }
    } else {
        Ok(state)
    }
}

async fn run_cycle(
    args: &Args,
    control: &LocalControlPlane,
    trigger: CycleTrigger,
) -> Result<DaemonCycleReport, fabric::DaemonStateError> {
    let mut state = refresh_state(args, control)?;
    let reconcile_report = if args.disable_reconcile {
        None
    } else {
        if state.active_sessions().is_empty() {
            Some(fabric::SessionReconcileReport {
                examined: 0,
                unchanged: 0,
                upgraded: 0,
                closed: 0,
                entries: Vec::new(),
            })
        } else {
            let transport = daemon_transport(args);
            let report = control.reconcile_sessions(&transport).await?;
            state = control
                .ensure_state()
                .expect("daemon state should remain readable after reconcile");
            Some(report)
        }
    };
    let (active_session, connect_status) = match args.connect_protocol.as_deref() {
        Some(protocol) => {
            let transport = daemon_transport(args);
            match ensure_target_session(args, control, &state, transport, protocol).await {
                Ok(Some(session)) => {
                    state = control
                        .ensure_state()
                        .expect("daemon state should remain readable after connect");
                    (Some(session), "active".to_string())
                }
                Ok(None) => {
                    let existing = existing_target_session(args, &state, protocol);
                    (existing, "reused".to_string())
                }
                Err(error) => (None, format!("connect-failed:{error}")),
            }
        }
        None => (None, "disabled".to_string()),
    };

    Ok(DaemonCycleReport {
        trigger,
        state,
        reconcile_report,
        active_session,
        connect_status,
    })
}

async fn ensure_target_session(
    args: &Args,
    control: &LocalControlPlane,
    state: &fabric::DaemonState,
    transport: QuicTransportAdapter,
    protocol: &str,
) -> Result<Option<SessionSnapshot>, fabric::DaemonStateError> {
    if let Some(session) = existing_target_session(args, state, protocol) {
        return Ok(Some(session));
    }

    let target = args
        .connect_peer
        .as_deref()
        .and_then(|value| value.parse().ok())
        .or_else(|| state.first_peer().map(|peer| peer.snapshot.peer.clone()))
        .expect("a peer is required or must exist in state");
    let protocol = ProtocolId::new(protocol).expect("connect protocol must be valid");
    let session = control
        .realize_best_path(
            &target,
            &protocol,
            parse_class(&args.connect_class),
            &transport,
        )
        .await?;
    Ok(Some(session))
}

fn existing_target_session(
    args: &Args,
    state: &fabric::DaemonState,
    protocol: &str,
) -> Option<SessionSnapshot> {
    let target = args
        .connect_peer
        .as_deref()
        .and_then(|value| value.parse().ok())
        .or_else(|| state.first_peer().map(|peer| peer.snapshot.peer.clone()))?;
    let class = parse_class(&args.connect_class);
    state
        .active_sessions()
        .iter()
        .find(|session| {
            session.peer == target
                && session.class == class
                && session
                    .protocol
                    .as_ref()
                    .is_some_and(|value| value.as_str() == protocol)
        })
        .cloned()
}

fn emit_cycle_report(args: &Args, report: &DaemonCycleReport) {
    if let Some(reconcile_report) = &report.reconcile_report {
        if args.reconcile_verbose {
            for entry in &reconcile_report.entries {
                println!(
                    "quicnetd reconcile session_id={} peer={} disposition={} path={} reason={}",
                    hex_session_id(&entry.session_id),
                    entry.peer,
                    reconcile_disposition_label(&entry.disposition),
                    entry
                        .path_kind
                        .map(|path| format!("{path:?}"))
                        .unwrap_or_else(|| "none".to_string()),
                    entry.reason
                );
            }
        }
    }

    let selected_path = report
        .state
        .first_peer()
        .and_then(|peer| {
            report
                .state
                .best_path(&peer.snapshot.peer, TrafficClass::Interactive)
        })
        .map(|decision| decision.explanation.summary)
        .unwrap_or_else(|| "no routing candidates".to_string());
    println!(
        "quicnetd active: {} selected_path={} active_session={} reconcile={} connect={} trigger={} state_path={}",
        report.state.status_line(),
        selected_path,
        report
            .active_session
            .as_ref()
            .map(|session| format!("{}@{}", hex_session_id(&session.session_id), session.peer))
            .unwrap_or_else(|| "none".to_string()),
        report
            .reconcile_report
            .as_ref()
            .map(reconcile_summary_line)
            .unwrap_or_else(|| "disabled".to_string()),
        report.connect_status,
        cycle_trigger_label(&report.trigger),
        args.state_path
    );
}

fn parse_class(value: &str) -> TrafficClass {
    match value {
        "control" => TrafficClass::Control,
        "bulk" => TrafficClass::Bulk,
        "background" => TrafficClass::Background,
        _ => TrafficClass::Interactive,
    }
}

fn daemon_transport(args: &Args) -> QuicTransportAdapter {
    let identity = load_or_init_identity(&args.identity_path, &args.identity_passphrase_env);
    QuicTransportAdapter::with_identity(fabric::NetworkId::derive(&args.network), identity)
}

async fn wait_for_next_cycle(
    args: &Args,
    trigger_monitor: &mut DaemonTriggerMonitor,
) -> Result<CycleTrigger, WaitOutcome> {
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(args.reconcile_interval_seconds.max(1));
    let poll_interval = Duration::from_millis(args.change_watch_interval_ms.max(1));

    loop {
        if let Some(trigger) = trigger_monitor.detect_trigger() {
            return Ok(trigger);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(CycleTrigger::IntervalElapsed);
        }
        let remaining = deadline.duration_since(now);
        let sleep_duration = remaining.min(poll_interval);
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                match result {
                    Ok(()) => return Err(WaitOutcome::Interrupted),
                    Err(error) => return Err(WaitOutcome::SignalError(error)),
                }
            }
            _ = tokio::time::sleep(sleep_duration) => {}
        }
    }
}

fn hex_session_id(session_id: &[u8; 16]) -> String {
    session_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn cycle_trigger_label(trigger: &CycleTrigger) -> &'static str {
    match trigger {
        CycleTrigger::Startup => "startup",
        CycleTrigger::IntervalElapsed => "interval",
        CycleTrigger::StateChanged => "state-changed",
        CycleTrigger::AuthoritySnapshotChanged => "authority-snapshot-changed",
        CycleTrigger::NetworkChangeRequested => "network-change",
    }
}

fn reconcile_summary_line(report: &fabric::SessionReconcileReport) -> String {
    format!(
        "examined={} upgraded={} closed={} unchanged={}",
        report.examined, report.upgraded, report.closed, report.unchanged
    )
}

fn load_or_init_identity(identity_path: &str, passphrase_env: &str) -> IdentityKeypair {
    let passphrase = std::env::var(passphrase_env)
        .unwrap_or_else(|_| panic!("identity passphrase env var {passphrase_env} must be set"));
    let keystore = FileKeystore::new(identity_path);
    match keystore.load(&passphrase) {
        Ok(identity) => identity,
        Err(_) => {
            if let Some(parent) = std::path::Path::new(identity_path).parent() {
                std::fs::create_dir_all(parent).expect("identity directory should be creatable");
            }
            let identity = IdentityKeypair::generate(&mut OsRng);
            keystore
                .store(&identity, &passphrase)
                .expect("identity keystore should store");
            identity
        }
    }
}

impl DaemonTriggerMonitor {
    fn new(args: &Args) -> Self {
        let state_path = PathBuf::from(&args.state_path);
        let authority_snapshot_path = args.authority_snapshot.as_ref().map(PathBuf::from);
        let network_change_trigger_path =
            args.network_change_trigger_path.as_ref().map(PathBuf::from);
        Self {
            state_fingerprint: file_fingerprint(&state_path),
            authority_snapshot_fingerprint: authority_snapshot_path
                .as_ref()
                .map(|path| file_fingerprint(path)),
            network_change_trigger_fingerprint: network_change_trigger_path
                .as_ref()
                .map(|path| file_fingerprint(path)),
            state_path,
            authority_snapshot_path,
            network_change_trigger_path,
        }
    }

    fn refresh_baseline(&mut self) {
        self.state_fingerprint = file_fingerprint(&self.state_path);
        self.authority_snapshot_fingerprint = self
            .authority_snapshot_path
            .as_ref()
            .map(|path| file_fingerprint(path));
        self.network_change_trigger_fingerprint = self
            .network_change_trigger_path
            .as_ref()
            .map(|path| file_fingerprint(path));
    }

    fn detect_trigger(&mut self) -> Option<CycleTrigger> {
        if let Some(path) = &self.network_change_trigger_path {
            let current = file_fingerprint(path);
            if self.network_change_trigger_fingerprint.as_ref() != Some(&current) {
                self.network_change_trigger_fingerprint = Some(current);
                return Some(CycleTrigger::NetworkChangeRequested);
            }
        }

        let current_state = file_fingerprint(&self.state_path);
        if self.state_fingerprint != current_state {
            self.state_fingerprint = current_state;
            return Some(CycleTrigger::StateChanged);
        }

        if let Some(path) = &self.authority_snapshot_path {
            let current = file_fingerprint(path);
            if self.authority_snapshot_fingerprint.as_ref() != Some(&current) {
                self.authority_snapshot_fingerprint = Some(current);
                return Some(CycleTrigger::AuthoritySnapshotChanged);
            }
        }

        None
    }
}

fn file_fingerprint(path: &Path) -> FileFingerprint {
    match std::fs::metadata(path) {
        Ok(metadata) => FileFingerprint {
            exists: true,
            len: Some(metadata.len()),
            modified: metadata.modified().ok(),
        },
        Err(_) => FileFingerprint {
            exists: false,
            len: None,
            modified: None,
        },
    }
}

fn reconcile_disposition_label(disposition: &fabric::SessionReconcileDisposition) -> &'static str {
    match disposition {
        fabric::SessionReconcileDisposition::Unchanged => "unchanged",
        fabric::SessionReconcileDisposition::Upgraded => "upgraded",
        fabric::SessionReconcileDisposition::Closed => "closed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_monitor_detects_state_change() {
        let temp = unique_temp_path("quicnetd-trigger-state");
        std::fs::write(&temp, "v1").expect("state file should write");
        let args = test_args(temp.to_string_lossy().as_ref());
        let mut monitor = DaemonTriggerMonitor::new(&args);
        monitor.refresh_baseline();

        std::thread::sleep(Duration::from_millis(5));
        std::fs::write(&temp, "v2").expect("state file should update");

        assert_eq!(monitor.detect_trigger(), Some(CycleTrigger::StateChanged));
        let _ = std::fs::remove_file(temp);
    }

    #[test]
    fn trigger_monitor_detects_network_change_file_touch() {
        let state_path = unique_temp_path("quicnetd-trigger-state");
        let trigger_path = unique_temp_path("quicnetd-network-change");
        std::fs::write(&state_path, "state").expect("state file should write");
        let mut args = test_args(state_path.to_string_lossy().as_ref());
        args.network_change_trigger_path = Some(trigger_path.to_string_lossy().into_owned());
        let mut monitor = DaemonTriggerMonitor::new(&args);
        monitor.refresh_baseline();

        std::thread::sleep(Duration::from_millis(5));
        std::fs::write(&trigger_path, "poke").expect("trigger file should write");

        assert_eq!(
            monitor.detect_trigger(),
            Some(CycleTrigger::NetworkChangeRequested)
        );
        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trigger_path);
    }

    fn test_args(state_path: &str) -> Args {
        Args {
            network: "test-network".to_string(),
            state_path: state_path.to_string(),
            identity_path: "./var/test-identity.json".to_string(),
            identity_passphrase_env: "QUICNET_TEST_IDENTITY".to_string(),
            authority_snapshot: None,
            authority_origin: None,
            authority_subject: None,
            sync: false,
            revocation_sync: false,
            disable_reconcile: false,
            reconcile_verbose: false,
            reconcile_interval_seconds: 30,
            change_watch_interval_ms: 1000,
            network_change_trigger_path: None,
            one_shot: true,
            connect_protocol: None,
            connect_peer: None,
            connect_class: "interactive".to_string(),
        }
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}-{suffix}.tmp"))
    }
}
