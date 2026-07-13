use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use clap::Parser;
use crypto::IdentityKeypair;
use fabric::{DaemonConfig, LocalControlPlane, ProtocolId, SessionSnapshot, TrafficClass};
use identity::{FileKeystore, IdentityKeystore};
use quic::QuicTransportAdapter;
use rand::rngs::OsRng;
use std::error::Error;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,

    #[arg(long, default_value = "~/.quip/quicnet/state.json")]
    state_path: String,

    #[arg(long, default_value = "~/.quip/quicnet/identity.json")]
    identity_path: String,

    #[arg(long, default_value = "QUICNET_IDENTITY_PASSPHRASE")]
    identity_passphrase_env: String,

    #[arg(long)]
    authority_snapshot: Option<String>,

    #[arg(long, conflicts_with = "authority_snapshot")]
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
    force_network_reprobe: bool,

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
    preparation: CyclePreparation,
    reprobe_report: Option<fabric::NetcheckReprobeReport>,
    state: fabric::DaemonState,
    reconcile_report: Option<fabric::SessionReconcileReport>,
    active_session: Option<SessionSnapshot>,
    connect_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CyclePreparation {
    ReloadState,
    RefreshState,
    SyncAuthoritySnapshot,
    ReprobeNetwork,
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
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    observability::init_tracing("quicnetd");
    let mut args = Args::parse();
    normalize_args_paths(&mut args);
    let local_identity = load_or_init_identity(&args.identity_path, &args.identity_passphrase_env)?;
    let transport = daemon_transport(&args, &local_identity)?;
    let control = LocalControlPlane::new(DaemonConfig::new(
        args.network.clone(),
        args.state_path.clone(),
    ));

    initialize_state(&args, &control, &local_identity)?;
    control.ensure_identity_bound_state(&local_identity)?;
    let mut trigger_monitor = DaemonTriggerMonitor::new(&args);
    let mut trigger = if args.force_network_reprobe {
        CycleTrigger::NetworkChangeRequested
    } else {
        CycleTrigger::Startup
    };

    loop {
        let report = run_cycle(&args, &control, &local_identity, &transport, trigger.clone()).await?;
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
            Err(WaitOutcome::SignalError(error)) => return Err(error.into()),
        }
    }
    Ok(())
}

#[derive(Debug)]
enum WaitOutcome {
    Interrupted,
    SignalError(std::io::Error),
}

fn initialize_state(
    args: &Args,
    control: &LocalControlPlane,
    local_identity: &IdentityKeypair,
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
        (None, None) => control.refresh_and_persist_for_local_identity(local_identity),
        (Some(_), Some(_)) => Err(fabric::DaemonStateError::InvalidSession(
            "only one of --authority-snapshot or --authority-origin may be supplied".to_string(),
        )),
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
    local_identity: &IdentityKeypair,
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
        _ => control.refresh_and_persist_for_local_identity(local_identity),
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
    local_identity: &IdentityKeypair,
    transport: &QuicTransportAdapter,
    trigger: CycleTrigger,
) -> Result<DaemonCycleReport, fabric::DaemonStateError> {
    let (preparation, reprobe_report, _prepared_state) =
        prepare_state_for_trigger(args, control, local_identity, &trigger)?;
    let mut state = control.sync_runtime_sessions(transport)?;
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
            let report = control.reconcile_sessions(transport).await?;
            state = control.ensure_state()?;
            Some(report)
        }
    };
    let (active_session, connect_status) = match args.connect_protocol.as_deref() {
        Some(protocol) => {
            match ensure_target_session(args, control, &state, transport, protocol).await {
                Ok(Some(session)) => {
                    state = control.ensure_state()?;
                    (Some(session), "active".to_string())
                }
                Ok(None) => {
                    let existing = existing_target_session(args, &state, transport, protocol);
                    (existing, "reused".to_string())
                }
                Err(error) => (None, format!("connect-failed:{error}")),
            }
        }
        None => (None, "disabled".to_string()),
    };

    Ok(DaemonCycleReport {
        trigger,
        preparation,
        reprobe_report,
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
    transport: &QuicTransportAdapter,
    protocol: &str,
) -> Result<Option<SessionSnapshot>, fabric::DaemonStateError> {
    if let Some(session) = existing_target_session(args, state, transport, protocol) {
        return Ok(Some(session));
    }

    let target = args
        .connect_peer
        .as_deref()
        .and_then(|value| value.parse().ok())
        .or_else(|| state.first_peer().map(|peer| peer.snapshot.peer.clone()))
        .ok_or_else(|| {
            fabric::DaemonStateError::InvalidSession(
                "a peer is required or daemon state must contain at least one peer".to_string(),
            )
        })?;
    let protocol = ProtocolId::new(protocol)
        .map_err(|error| fabric::DaemonStateError::InvalidSession(error.to_string()))?;
    let session = control
        .realize_best_path(
            &target,
            &protocol,
            parse_class(&args.connect_class),
            transport,
        )
        .await?;
    Ok(Some(session))
}

fn existing_target_session(
    args: &Args,
    state: &fabric::DaemonState,
    transport: &QuicTransportAdapter,
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
                && transport.owns_session(&session.session_id)
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
        "quicnetd active: {} selected_path={} active_session={} preparation={} reprobe={} reconcile={} connect={} trigger={} state_path={}",
        report.state.status_line(),
        selected_path,
        report
            .active_session
            .as_ref()
            .map(|session| format!("{}@{}", hex_session_id(&session.session_id), session.peer))
            .unwrap_or_else(|| "none".to_string()),
        cycle_preparation_label(&report.preparation),
        report
            .reprobe_report
            .as_ref()
            .map(reprobe_summary_line)
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

fn daemon_transport(
    args: &Args,
    local_identity: &IdentityKeypair,
) -> Result<QuicTransportAdapter, Box<dyn Error>> {
    Ok(QuicTransportAdapter::with_identity(
        fabric::NetworkId::derive(&args.network),
        local_identity.clone(),
    ))
}

fn prepare_state_for_trigger(
    args: &Args,
    control: &LocalControlPlane,
    local_identity: &IdentityKeypair,
    trigger: &CycleTrigger,
) -> Result<
    (
        CyclePreparation,
        Option<fabric::NetcheckReprobeReport>,
        fabric::DaemonState,
    ),
    fabric::DaemonStateError,
> {
    match trigger {
        CycleTrigger::StateChanged => {
            Ok((CyclePreparation::ReloadState, None, control.ensure_state()?))
        }
        CycleTrigger::AuthoritySnapshotChanged => {
            let state = if let Some(path) = args.authority_snapshot.as_deref() {
                control
                    .sync_authority_snapshot(path)
                    .map(|(state, _)| state)?
            } else {
                control.ensure_state()?
            };
            Ok((CyclePreparation::SyncAuthoritySnapshot, None, state))
        }
        CycleTrigger::NetworkChangeRequested => {
            let reprobe_report =
                control.reprobe_network_change("network change trigger observed")?;
            let state = control.ensure_state()?;
            Ok((
                CyclePreparation::ReprobeNetwork,
                Some(reprobe_report),
                state,
            ))
        }
        CycleTrigger::Startup | CycleTrigger::IntervalElapsed => Ok((
            CyclePreparation::RefreshState,
            None,
            refresh_state(args, control, local_identity)?,
        )),
    }
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

fn cycle_preparation_label(preparation: &CyclePreparation) -> &'static str {
    match preparation {
        CyclePreparation::ReloadState => "reload",
        CyclePreparation::RefreshState => "refresh",
        CyclePreparation::SyncAuthoritySnapshot => "sync-authority-snapshot",
        CyclePreparation::ReprobeNetwork => "reprobe-network",
    }
}

fn reconcile_summary_line(report: &fabric::SessionReconcileReport) -> String {
    format!(
        "examined={} upgraded={} closed={} unchanged={}",
        report.examined, report.upgraded, report.closed, report.unchanged
    )
}

fn reprobe_summary_line(report: &fabric::NetcheckReprobeReport) -> String {
    format!(
        "udp={} ipv6={} relay_required={} probes={} paths={}",
        report.udp_reachable,
        report.ipv6_reachable,
        report.relay_required,
        report.probe_observations,
        report.path_candidates
    )
}

fn load_or_init_identity(
    identity_path: &str,
    passphrase_env: &str,
) -> Result<IdentityKeypair, Box<dyn Error>> {
    let passphrase = std::env::var(passphrase_env).map_err(|_| {
        std::io::Error::other(format!(
            "identity passphrase env var {passphrase_env} must be set"
        ))
    })?;
    let keystore = FileKeystore::new(identity_path);
    match keystore.load(&passphrase) {
        Ok(identity) => Ok(identity),
        Err(_) => {
            if let Some(parent) = std::path::Path::new(identity_path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            let identity = IdentityKeypair::generate(&mut OsRng);
            keystore.store(&identity, &passphrase)?;
            Ok(identity)
        }
    }
}

fn normalize_args_paths(args: &mut Args) {
    args.state_path = expand_home_path(&args.state_path);
    args.identity_path = expand_home_path(&args.identity_path);
    args.authority_snapshot = args.authority_snapshot.as_ref().map(|path| expand_home_path(path));
    args.network_change_trigger_path = args
        .network_change_trigger_path
        .as_ref()
        .map(|path| expand_home_path(path));
}

fn expand_home_path(path: &str) -> String {
    if let Some(suffix) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{suffix}");
        }
    }
    path.to_string()
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
    fn prepare_state_for_trigger_reloads_existing_state_for_state_change() {
        let state_path = unique_temp_path("quicnetd-prepare-state-change");
        let control =
            LocalControlPlane::new(DaemonConfig::new("prepare-state-change", &state_path));
        let state = fabric::fixture_daemon_state("prepare-state-change");
        state.save(&state_path).expect("state should persist");
        let args = test_args(state_path.to_string_lossy().as_ref());
        let local_identity = IdentityKeypair::from_secret_bytes([91_u8; 32]);

        let (preparation, reprobe_report, prepared_state) =
            prepare_state_for_trigger(
                &args,
                &control,
                &local_identity,
                &CycleTrigger::StateChanged,
            )
            .expect("state change preparation should succeed");

        assert_eq!(preparation, CyclePreparation::ReloadState);
        assert!(reprobe_report.is_none());
        assert_eq!(prepared_state.network, "prepare-state-change");
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn prepare_state_for_trigger_reprobes_before_network_change_cycle() {
        let state_path = unique_temp_path("quicnetd-prepare-network-change");
        let control =
            LocalControlPlane::new(DaemonConfig::new("prepare-network-change", &state_path));
        let mut state = fabric::fixture_daemon_state("prepare-network-change");
        state.netcheck.udp_reachable = false;
        state.netcheck.public_udp_addr = Some("203.0.113.120:8443".to_string());
        state.save(&state_path).expect("state should persist");
        let mut args = test_args(state_path.to_string_lossy().as_ref());
        args.force_network_reprobe = true;
        let local_identity = IdentityKeypair::from_secret_bytes([92_u8; 32]);

        let (preparation, reprobe_report, prepared_state) =
            prepare_state_for_trigger(
                &args,
                &control,
                &local_identity,
                &CycleTrigger::NetworkChangeRequested,
            )
            .expect("network change preparation should succeed");

        assert_eq!(preparation, CyclePreparation::ReprobeNetwork);
        assert!(reprobe_report.is_some());
        assert!(prepared_state.netcheck.udp_reachable);
        let _ = std::fs::remove_file(state_path);
    }

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
            force_network_reprobe: false,
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

    #[test]
    fn expand_home_path_uses_home_environment() {
        let original = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", "/tmp/quip-home");
        }

        let expanded = super::expand_home_path("~/.quip/quicnet/identity.json");

        match original {
            Some(home) => unsafe { std::env::set_var("HOME", home) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        assert_eq!(expanded, "/tmp/quip-home/.quip/quicnet/identity.json");
    }
}
