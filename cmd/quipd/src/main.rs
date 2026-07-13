use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use clap::Parser;
use crypto::IdentityKeypair;
use daemonapi::{
    AuthorityCapabilitiesResult, AuthorityCapabilityGrantEntry, AuthorityMembershipResult,
    AuthorityRevocationEntry, AuthorityRevocationsResult, AuthorityShowResult,
    AuthoritySyncOriginPayload, AuthoritySyncResult, AuthoritySyncRevocationsOriginPayload,
    AuthoritySyncSnapshotPayload, AuthoritySyncStatus, DaemonEndpointDiscovery, DurableStateStatus,
    ErrorCode, IdentityShowResult, IdentityStatus, IdentityVerifyResult, RequestEnvelope,
    ResponseEnvelope, RuntimeEventEntry, RuntimeEventsListResult, RuntimeHealthResult,
    RuntimeListenerEntry, RuntimeListenersListResult, RuntimePathAlternativeEntry,
    RuntimePathEntry, RuntimePathsListResult, RuntimeSessionEntry, RuntimeSessionsListResult,
    RuntimeStatusResult, RuntimeSummary, SessionClosePayload, SessionCloseResult,
    SessionConnectPayload, SessionConnectResult, SessionConnectSummary,
    SessionReconcileEntry as ApiSessionReconcileEntry, SessionReconcilePayload,
    SessionReconcileResult, SessionUpgradePayload, SessionUpgradeResult,
};
use fabric::SessionLifecycleTransport;
use fabric::{
    DaemonConfig, LocalControlPlane, PathSource, ProtocolId, RuntimeHealthLevel,
    RuntimePathAlternative, RuntimePathSnapshot, RuntimePathState, SessionSnapshot, TrafficClass,
};
use identity::{FileKeystore, IdentityKeystore};
use quic::QuicTransportAdapter;
use rand::rngs::OsRng;
use serde_json::json;
use std::error::Error;
use tiny_http::{Header, Method, Response, Server, StatusCode};

#[derive(Parser, Debug, Clone)]
struct Args {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,

    #[arg(long, default_value = "~/.quip/net/state.json")]
    state_path: String,

    #[arg(long, default_value = "~/.quip/identity/node.json")]
    identity_path: String,

    #[arg(long, default_value = "~/.quip/run/control.json")]
    control_discovery_path: String,

    #[arg(long, default_value = "127.0.0.1:0")]
    control_bind: String,

    #[arg(long, default_value = "QUIP_IDENTITY_PASSPHRASE")]
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
    authority_reevaluation_report: Option<fabric::AuthorityReevaluationReport>,
    reconcile_report: Option<fabric::SessionReconcileReport>,
    active_session: Option<SessionSnapshot>,
    connect_status: String,
}

const RECONNECT_MAX_ATTEMPTS: u32 = 5;
const RECONNECT_BASE_BACKOFF_SECS: u64 = 5;
const RECONNECT_MAX_BACKOFF_SECS: u64 = 300;

#[derive(Debug)]
enum TargetSessionOutcome {
    Active(SessionSnapshot),
    Reused(SessionSnapshot),
    BackingOff(String),
    Suppressed(String),
    Failed(String),
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
    observability::init_tracing("quipd");
    let mut args = Args::parse();
    normalize_args_paths(&mut args);
    let local_identity = load_or_init_identity(&args.identity_path, &args.identity_passphrase_env)?;
    let transport = daemon_transport(&args, &local_identity)?;
    let control = LocalControlPlane::new(DaemonConfig::new(
        args.network.clone(),
        args.state_path.clone(),
    ));
    let _control_server = start_control_server(&args, &control, &transport, &local_identity)?;

    initialize_state(&args, &control, &local_identity)?;
    control.ensure_identity_bound_state(&local_identity)?;
    let mut trigger_monitor = DaemonTriggerMonitor::new(&args);
    let mut trigger = if args.force_network_reprobe {
        CycleTrigger::NetworkChangeRequested
    } else {
        CycleTrigger::Startup
    };

    loop {
        let report = run_cycle(
            &args,
            &control,
            &local_identity,
            &transport,
            trigger.clone(),
        )
        .await?;
        emit_cycle_report(&args, &report);

        if args.one_shot {
            break;
        }

        trigger_monitor.refresh_baseline();
        match wait_for_next_cycle(&args, &mut trigger_monitor).await {
            Ok(next_trigger) => trigger = next_trigger,
            Err(WaitOutcome::Interrupted) => {
                println!("quipd stopping: received interrupt");
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
    control.sync_runtime_sessions(transport)?;
    let authority_reevaluation_report = if matches!(
        trigger,
        CycleTrigger::Startup
            | CycleTrigger::IntervalElapsed
            | CycleTrigger::AuthoritySnapshotChanged
            | CycleTrigger::StateChanged
    ) {
        Some(
            control
                .reevaluate_runtime_authority(local_identity, transport)
                .await?,
        )
    } else {
        None
    };
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
                Ok(TargetSessionOutcome::Active(session)) => {
                    state = control.ensure_state()?;
                    (Some(session), "active".to_string())
                }
                Ok(TargetSessionOutcome::Reused(session)) => (Some(session), "reused".to_string()),
                Ok(TargetSessionOutcome::BackingOff(status)) => (None, status),
                Ok(TargetSessionOutcome::Suppressed(status)) => (None, status),
                Ok(TargetSessionOutcome::Failed(status)) => (None, status),
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
        authority_reevaluation_report,
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
) -> Result<TargetSessionOutcome, fabric::DaemonStateError> {
    if let Some(session) = existing_target_session(args, state, transport, protocol) {
        let target_protocol = session.protocol.clone();
        transport.clear_reconnect_attempt(
            &session.peer,
            target_protocol.as_ref(),
            session.class,
            Some("session already active".to_string()),
        )?;
        return Ok(TargetSessionOutcome::Reused(session));
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
    let class = parse_class(&args.connect_class);
    if let Some(suppression) = transport
        .reconnect_suppressions()?
        .into_iter()
        .find(|entry| {
            entry.peer == target
                && entry.protocol.as_ref() == Some(&protocol)
                && entry.class == class
        })
    {
        transport.clear_reconnect_attempt(
            &target,
            Some(&protocol),
            class,
            Some("reconnect suppressed by policy".to_string()),
        )?;
        return Ok(TargetSessionOutcome::Suppressed(format!(
            "suppressed:{}",
            suppression.reason
        )));
    }

    let now = current_unix_secs();
    if let Some(attempt) = transport.reconnect_attempts()?.into_iter().find(|entry| {
        entry.peer == target && entry.protocol.as_ref() == Some(&protocol) && entry.class == class
    }) {
        match attempt.state {
            fabric::RuntimeReconnectAttemptState::Failed => {
                return Ok(TargetSessionOutcome::Failed(format!(
                    "failed:attempts={} reason={}",
                    attempt.attempt_count, attempt.reason
                )));
            }
            fabric::RuntimeReconnectAttemptState::BackingOff => {
                if now < attempt.next_attempt_unix_secs {
                    return Ok(TargetSessionOutcome::BackingOff(format!(
                        "backoff:attempts={} next_retry_in={}s reason={}",
                        attempt.attempt_count,
                        attempt.next_attempt_unix_secs.saturating_sub(now),
                        attempt.reason
                    )));
                }
            }
        }
    }

    transport.record_runtime_event(
        "reconnect.started",
        fabric::RuntimeEventSubject {
            kind: "peer".to_string(),
            id: target.to_string(),
        },
        json!({
            "protocol": protocol.as_str(),
            "class": class_label(class)
        }),
    )?;
    match control
        .realize_best_path(&target, &protocol, class, transport)
        .await
    {
        Ok(session) => {
            transport.clear_reconnect_attempt(
                &target,
                Some(&protocol),
                class,
                Some("reconnect succeeded".to_string()),
            )?;
            Ok(TargetSessionOutcome::Active(session))
        }
        Err(error) => {
            let scheduled = transport.schedule_reconnect(
                &target,
                Some(&protocol),
                class,
                error.to_string(),
                RECONNECT_MAX_ATTEMPTS,
                RECONNECT_BASE_BACKOFF_SECS,
                RECONNECT_MAX_BACKOFF_SECS,
            )?;
            Ok(match scheduled.state {
                fabric::RuntimeReconnectAttemptState::BackingOff => {
                    TargetSessionOutcome::BackingOff(format!(
                        "backoff:attempts={} next_retry_in={}s reason={}",
                        scheduled.attempt_count,
                        scheduled.next_attempt_unix_secs.saturating_sub(now),
                        scheduled.reason
                    ))
                }
                fabric::RuntimeReconnectAttemptState::Failed => {
                    TargetSessionOutcome::Failed(format!(
                        "failed:attempts={} reason={}",
                        scheduled.attempt_count, scheduled.reason
                    ))
                }
            })
        }
    }
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
                    "quipd reconcile session_id={} peer={} disposition={} path={} reason={}",
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
        "quipd active: {} selected_path={} active_session={} preparation={} reprobe={} authority_reevaluation={} reconcile={} connect={} trigger={} state_path={}",
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
            .authority_reevaluation_report
            .as_ref()
            .map(authority_reevaluation_summary_line)
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

fn normalize_args_paths(args: &mut Args) {
    args.state_path = expand_home_path(&args.state_path);
    args.identity_path = expand_home_path(&args.identity_path);
    args.control_discovery_path = expand_home_path(&args.control_discovery_path);
    args.network_change_trigger_path = args
        .network_change_trigger_path
        .as_deref()
        .map(expand_home_path);
    args.authority_snapshot = args.authority_snapshot.as_deref().map(expand_home_path);
}

fn expand_home_path(path: &str) -> String {
    if let Some(suffix) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{suffix}");
        }
    }
    path.to_string()
}

#[derive(Debug)]
struct ControlServerGuard {
    discovery_path: PathBuf,
    _thread: std::thread::JoinHandle<()>,
}

impl Drop for ControlServerGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.discovery_path);
    }
}

fn start_control_server(
    args: &Args,
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    local_identity: &IdentityKeypair,
) -> Result<ControlServerGuard, Box<dyn Error>> {
    let listener = TcpListener::bind(&args.control_bind)?;
    let local_addr = listener.local_addr()?;
    let server = Server::from_listener(listener, None)
        .map_err(|error| std::io::Error::other(format!("control server init failed: {error}")))?;
    let endpoint = format!("http://{local_addr}/rpc");
    let discovery_path = PathBuf::from(&args.control_discovery_path);
    write_control_discovery(
        &discovery_path,
        DaemonEndpointDiscovery {
            endpoint: endpoint.clone(),
            network: args.network.clone(),
            state_path: args.state_path.clone(),
            identity_path: args.identity_path.clone(),
            runtime_instance_id: transport.runtime_instance_id().to_string(),
            pid: std::process::id(),
            started_at_unix_secs: current_unix_secs(),
        },
    )?;

    let server_args = Arc::new(args.clone());
    let server_control = LocalControlPlane::new(control.config.clone());
    let server_transport = transport.clone();
    let server_identity = local_identity.clone();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("daemon control runtime should build");
        for mut request in server.incoming_requests() {
            let response = route_control_request(
                &server_args,
                &server_control,
                &server_transport,
                &server_identity,
                &runtime,
                &mut request,
            );
            if let Err(error) = request.respond(response) {
                eprintln!("quipd control respond failed: {error}");
            }
        }
    });

    println!(
        "quipd control ready endpoint={} discovery_path={}",
        endpoint,
        discovery_path.display()
    );

    Ok(ControlServerGuard {
        discovery_path,
        _thread: thread,
    })
}

fn write_control_discovery(
    path: &Path,
    discovery: DaemonEndpointDiscovery,
) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&discovery)
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    )
}

fn route_control_request(
    args: &Args,
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    local_identity: &IdentityKeypair,
    runtime: &tokio::runtime::Runtime,
    request: &mut tiny_http::Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    if request.method() != &Method::Post || request.url() != "/rpc" {
        return json_response(
            StatusCode(404),
            ResponseEnvelope::error(
                "unknown",
                ErrorCode::NotFound,
                format!(
                    "no daemon control route for {} {}",
                    request.method(),
                    request.url()
                ),
                None,
            ),
        );
    }

    let body = match read_request_body(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let envelope = match serde_json::from_slice::<RequestEnvelope>(&body) {
        Ok(envelope) => envelope,
        Err(error) => {
            return json_response(
                StatusCode(400),
                ResponseEnvelope::error(
                    "unknown",
                    ErrorCode::InvalidRequest,
                    format!("invalid daemon control request: {error}"),
                    None,
                ),
            );
        }
    };

    let response = match envelope.operation.as_str() {
        "runtime.status" => {
            runtime_status_response(args, control, transport, local_identity, envelope)
        }
        "runtime.sessions.list" => runtime_sessions_response(control, transport, envelope),
        "runtime.listeners.list" => runtime_listeners_response(control, transport, envelope),
        "runtime.paths.list" => runtime_paths_response(control, transport, envelope),
        "runtime.health" => runtime_health_response(control, transport, envelope),
        "runtime.events.list" => runtime_events_response(control, transport, envelope),
        "authority.show" => authority_show_response(args, control, transport, envelope),
        "authority.membership" => authority_membership_response(control, envelope),
        "authority.capabilities" => authority_capabilities_response(control, envelope),
        "authority.revocations" => authority_revocations_response(control, envelope),
        "identity.show" => identity_show_response(args, control, local_identity, envelope),
        "identity.verify" => identity_verify_response(args, control, local_identity, envelope),
        "authority.sync_snapshot" => runtime.block_on(authority_sync_snapshot_response(
            args,
            control,
            transport,
            local_identity,
            envelope,
        )),
        "authority.sync_origin" => runtime.block_on(authority_sync_origin_response(
            args,
            control,
            transport,
            local_identity,
            envelope,
        )),
        "authority.sync_revocations_origin" => {
            runtime.block_on(authority_sync_revocations_origin_response(
                args,
                control,
                transport,
                local_identity,
                envelope,
            ))
        }
        "session.connect" => runtime.block_on(session_connect_response(
            control,
            transport,
            local_identity,
            envelope,
        )),
        "session.close" => runtime.block_on(session_close_response(control, transport, envelope)),
        "session.upgrade" => {
            runtime.block_on(session_upgrade_response(control, transport, envelope))
        }
        "session.reconcile" => {
            runtime.block_on(session_reconcile_response(control, transport, envelope))
        }
        _ => ResponseEnvelope::error(
            envelope.request_id,
            ErrorCode::UnsupportedOperation,
            format!("unsupported daemon operation {}", envelope.operation),
            None,
        ),
    };

    let status = if response.ok {
        StatusCode(200)
    } else {
        map_error_status(&response)
    };
    json_response(status, response)
}

fn read_request_body(
    request: &mut tiny_http::Request,
) -> Result<Vec<u8>, Response<std::io::Cursor<Vec<u8>>>> {
    let Some(limit) = request.body_length() else {
        return Err(json_response(
            StatusCode(411),
            ResponseEnvelope::error(
                "unknown",
                ErrorCode::InvalidRequest,
                "daemon control requests must include Content-Length",
                None,
            ),
        ));
    };
    if limit > 64 * 1024 {
        return Err(json_response(
            StatusCode(413),
            ResponseEnvelope::error(
                "unknown",
                ErrorCode::InvalidRequest,
                "daemon control request body exceeds 65536 bytes",
                None,
            ),
        ));
    }
    let mut body = vec![0_u8; limit as usize];
    if let Err(error) = request.as_reader().read_exact(&mut body) {
        return Err(json_response(
            StatusCode(400),
            ResponseEnvelope::error(
                "unknown",
                ErrorCode::InvalidRequest,
                format!("daemon control request body could not be read: {error}"),
                None,
            ),
        ));
    }
    Ok(body)
}

fn runtime_status_response(
    args: &Args,
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    local_identity: &IdentityKeypair,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match (|| {
        let state = control.sync_runtime_sessions(transport)?;
        let health = control.runtime_health(transport)?;
        let authority = latest_authority_status(transport, &state, &health)?;
        Ok((state, health, authority))
    })() {
        Ok((state, health, authority)) => ResponseEnvelope::success(
            envelope.request_id,
            RuntimeStatusResult {
                truth_kind: "runtime".to_string(),
                daemon_health: runtime_health_level_label(&health.daemon_readiness).to_string(),
                identity: IdentityStatus {
                    status: "loaded".to_string(),
                    path: args.identity_path.clone(),
                    node_id: local_identity.peer_id().to_string(),
                },
                durable_state: DurableStateStatus {
                    status: "loaded".to_string(),
                    path: args.state_path.clone(),
                    schema_version: state.schema_version,
                },
                authority,
                runtime_summary: RuntimeSummary {
                    session_count: state.active_sessions().len(),
                    active_path_count: health.active_paths,
                    reconnect_state: runtime_reconnect_state_label(&health.reconnect_state)
                        .to_string(),
                },
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn runtime_sessions_response(
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match control.sync_runtime_sessions(transport) {
        Ok(state) => ResponseEnvelope::success(
            envelope.request_id,
            RuntimeSessionsListResult {
                truth_kind: "runtime".to_string(),
                sessions: state
                    .active_sessions()
                    .iter()
                    .map(runtime_session_entry)
                    .collect(),
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn runtime_events_response(
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    let limit = envelope
        .payload
        .get("limit")
        .and_then(|value| value.as_u64())
        .unwrap_or(32) as usize;
    match control.runtime_events(transport, limit) {
        Ok(events) => ResponseEnvelope::success(
            envelope.request_id,
            RuntimeEventsListResult {
                truth_kind: "runtime".to_string(),
                events: events
                    .into_iter()
                    .map(|event| RuntimeEventEntry {
                        event_id: event.event_id,
                        event_type: event.event_type,
                        emitted_at: event.emitted_at,
                        truth_kind: event.truth_kind,
                        subject_kind: event.subject.kind,
                        subject_id: event.subject.id,
                        details: event.details,
                    })
                    .collect(),
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn authority_show_response(
    args: &Args,
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match (|| {
        let state = control.sync_runtime_sessions(transport)?;
        let health = control.runtime_health(transport)?;
        let authority = latest_authority_status(transport, &state, &health)?;
        Ok((state, authority))
    })() {
        Ok((state, authority)) => ResponseEnvelope::success(
            envelope.request_id,
            AuthorityShowResult {
                truth_kind: "runtime".to_string(),
                configured_origin: args.authority_origin.clone(),
                configured_subject: args.authority_subject.clone(),
                configured_snapshot: args.authority_snapshot.clone(),
                network: state.network.clone(),
                local_peer_id: state.local_peer_id.to_string(),
                membership_subject_peer_id: state.membership.subject_peer_id.to_string(),
                membership_issuer_peer_id: state.membership.issuer_peer_id.to_string(),
                membership_roles: state.membership.roles.clone(),
                grants: state.capability_grants.len(),
                revocations: state.revocations.len(),
                denied_peers: state.denied_peers.len(),
                bootstrap_hints: state.bootstrap.len(),
                relays: state.relay_count(),
                schema_version: state.schema_version,
                authority,
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn identity_show_response(
    args: &Args,
    control: &LocalControlPlane,
    local_identity: &IdentityKeypair,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match control.ensure_state() {
        Ok(state) => ResponseEnvelope::success(
            envelope.request_id,
            IdentityShowResult {
                truth_kind: "runtime_and_durable".to_string(),
                status: "loaded".to_string(),
                identity_path: args.identity_path.clone(),
                node_id: local_identity.peer_id().to_string(),
                public_key_hex: hex_public_key(local_identity),
                durable_state_peer_id: Some(state.local_peer_id.to_string()),
                authority_subject_peer_id: Some(state.membership.subject_peer_id.to_string()),
                state_binding_status: if state.local_peer_id == local_identity.peer_id()
                    && state.membership.subject_peer_id == local_identity.peer_id()
                {
                    "matched".to_string()
                } else {
                    "mismatched".to_string()
                },
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn identity_verify_response(
    args: &Args,
    control: &LocalControlPlane,
    local_identity: &IdentityKeypair,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match control.ensure_state() {
        Ok(state) => {
            let loaded_node_id = local_identity.peer_id().to_string();
            let expected_node_id = state.local_peer_id.to_string();
            let authority_subject_peer_id = state.membership.subject_peer_id.to_string();
            let mut mismatch_reasons = Vec::new();
            if loaded_node_id != expected_node_id {
                mismatch_reasons.push(format!(
                    "durable state expects {} but daemon loaded {}",
                    expected_node_id, loaded_node_id
                ));
            }
            if loaded_node_id != authority_subject_peer_id {
                mismatch_reasons.push(format!(
                    "authority membership expects {} but daemon loaded {}",
                    authority_subject_peer_id, loaded_node_id
                ));
            }
            ResponseEnvelope::success(
                envelope.request_id,
                IdentityVerifyResult {
                    truth_kind: "runtime_and_durable".to_string(),
                    identity_path: args.identity_path.clone(),
                    expected_node_id: Some(expected_node_id),
                    loaded_node_id,
                    authority_subject_peer_id: Some(authority_subject_peer_id),
                    match_result: if mismatch_reasons.is_empty() {
                        "match".to_string()
                    } else {
                        "mismatch".to_string()
                    },
                    mismatch_reasons,
                },
            )
        }
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn authority_membership_response(
    control: &LocalControlPlane,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match control.ensure_state() {
        Ok(state) => ResponseEnvelope::success(
            envelope.request_id,
            AuthorityMembershipResult {
                truth_kind: "runtime".to_string(),
                network: state.network.clone(),
                subject_peer_id: state.membership.subject_peer_id.to_string(),
                issuer_peer_id: state.membership.issuer_peer_id.to_string(),
                issued_at: state.membership.issued_at,
                expires_at: state.membership.expires_at,
                roles: state.membership.roles.clone(),
                schema_version: state.schema_version,
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn authority_capabilities_response(
    control: &LocalControlPlane,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match control.ensure_state() {
        Ok(state) => ResponseEnvelope::success(
            envelope.request_id,
            AuthorityCapabilitiesResult {
                truth_kind: "runtime".to_string(),
                network: state.network.clone(),
                subject_peer_id: state.local_peer_id.to_string(),
                schema_version: state.schema_version,
                grants: state
                    .grants_for_peer(&state.local_peer_id)
                    .into_iter()
                    .map(|grant| AuthorityCapabilityGrantEntry {
                        subject_peer_id: grant.subject_peer_id.to_string(),
                        issuer_peer_id: grant.issuer_peer_id.to_string(),
                        sequence: grant.sequence,
                        not_before: grant.not_before,
                        expires_at: grant.expires_at,
                        capabilities: grant.capabilities.clone(),
                        protocols: grant
                            .protocol_scopes
                            .iter()
                            .map(|protocol| protocol.as_str().to_string())
                            .collect(),
                        bandwidth_bps: grant.resource_limits.bandwidth_bps,
                        concurrent_streams: grant.resource_limits.concurrent_streams,
                        max_object_bytes: grant.resource_limits.max_object_bytes,
                        constraints: grant.constraints.clone(),
                    })
                    .collect(),
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn authority_revocations_response(
    control: &LocalControlPlane,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match control.ensure_state() {
        Ok(state) => ResponseEnvelope::success(
            envelope.request_id,
            AuthorityRevocationsResult {
                truth_kind: "runtime".to_string(),
                network: state.network.clone(),
                schema_version: state.schema_version,
                revocations: state
                    .revocations
                    .iter()
                    .map(|revocation| AuthorityRevocationEntry {
                        sequence: revocation.sequence,
                        issuer_peer_id: revocation.issuer_peer_id.to_string(),
                        effective_at: revocation.effective_at,
                        reason: render_revocation_reason(&revocation.reason).to_string(),
                        target: render_revocation_target(&revocation.target),
                        note: revocation.note.clone(),
                    })
                    .collect(),
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn runtime_listeners_response(
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match control.runtime_listeners(transport) {
        Ok(listeners) => ResponseEnvelope::success(
            envelope.request_id,
            RuntimeListenersListResult {
                truth_kind: "runtime".to_string(),
                listeners: listeners.into_iter().map(runtime_listener_entry).collect(),
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn runtime_paths_response(
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match control.runtime_paths(transport) {
        Ok(paths) => ResponseEnvelope::success(
            envelope.request_id,
            RuntimePathsListResult {
                truth_kind: "runtime".to_string(),
                paths: paths.into_iter().map(runtime_path_entry).collect(),
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn runtime_health_response(
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    match control.runtime_health(transport) {
        Ok(health) => ResponseEnvelope::success(
            envelope.request_id,
            RuntimeHealthResult {
                truth_kind: "runtime".to_string(),
                daemon_readiness: runtime_health_level_label(&health.daemon_readiness).to_string(),
                authority_sync_health: runtime_health_level_label(&health.authority_sync_health)
                    .to_string(),
                authority_subject_status: health.authority_subject_status,
                authority_deny_reason: health.authority_deny_reason,
                runtime_registry_health: runtime_health_level_label(
                    &health.runtime_registry_health,
                )
                .to_string(),
                path_manager_health: runtime_health_level_label(&health.path_manager_health)
                    .to_string(),
                reconnect_subsystem_health: runtime_health_level_label(
                    &health.reconnect_subsystem_health,
                )
                .to_string(),
                active_sessions: health.active_sessions,
                active_paths: health.active_paths,
                active_listeners: health.active_listeners,
                reconnect_state: runtime_reconnect_state_label(&health.reconnect_state).to_string(),
                reconnect_attempt_count: health.reconnect_attempt_count,
                reconnect_next_attempt_unix_secs: health.reconnect_next_attempt_unix_secs,
                reconnect_suppression_count: health.reconnect_suppression_count,
                runtime_event_buffer_depth: health.runtime_event_buffer_depth,
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

async fn authority_sync_snapshot_response(
    args: &Args,
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    local_identity: &IdentityKeypair,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    let payload =
        match serde_json::from_value::<AuthoritySyncSnapshotPayload>(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(error) => {
                return ResponseEnvelope::error(
                    envelope.request_id,
                    ErrorCode::InvalidRequest,
                    format!("invalid authority.sync_snapshot payload: {error}"),
                    None,
                )
            }
        };
    authority_sync_response(
        args,
        control,
        transport,
        local_identity,
        envelope.request_id,
        "snapshot",
        Some(payload.authority_snapshot.clone()),
        None,
        None,
        |control| control.sync_authority_snapshot(&payload.authority_snapshot),
    )
    .await
}

async fn authority_sync_origin_response(
    args: &Args,
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    local_identity: &IdentityKeypair,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    let payload =
        match serde_json::from_value::<AuthoritySyncOriginPayload>(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(error) => {
                return ResponseEnvelope::error(
                    envelope.request_id,
                    ErrorCode::InvalidRequest,
                    format!("invalid authority.sync_origin payload: {error}"),
                    None,
                )
            }
        };
    authority_sync_response(
        args,
        control,
        transport,
        local_identity,
        envelope.request_id,
        "origin",
        None,
        Some(payload.authority_origin.clone()),
        payload.authority_subject.clone(),
        |control| {
            control.sync_authority_origin(
                &payload.authority_origin,
                payload.authority_subject.as_deref(),
            )
        },
    )
    .await
}

async fn authority_sync_revocations_origin_response(
    args: &Args,
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    local_identity: &IdentityKeypair,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    let payload = match serde_json::from_value::<AuthoritySyncRevocationsOriginPayload>(
        envelope.payload.clone(),
    ) {
        Ok(payload) => payload,
        Err(error) => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::InvalidRequest,
                format!("invalid authority.sync_revocations_origin payload: {error}"),
                None,
            )
        }
    };
    authority_sync_response(
        args,
        control,
        transport,
        local_identity,
        envelope.request_id,
        "revocations_origin",
        None,
        Some(payload.authority_origin.clone()),
        None,
        |control| {
            control
                .sync_authority_revocations_origin(&payload.authority_origin)
                .map(|(state, revocations_added)| {
                    (
                        state,
                        fabric::StateSyncReport {
                            membership_changed: false,
                            grants_added: 0,
                            grants_removed: 0,
                            revocations_added,
                            bootstrap_hints_added: 0,
                            bootstrap_hints_removed: 0,
                            relay_announcements_added: 0,
                        },
                    )
                })
        },
    )
    .await
}

async fn session_connect_response(
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    local_identity: &IdentityKeypair,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    let payload = match serde_json::from_value::<SessionConnectPayload>(envelope.payload.clone()) {
        Ok(payload) => payload,
        Err(error) => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::InvalidRequest,
                format!("invalid session.connect payload: {error}"),
                None,
            )
        }
    };
    let state = match control.ensure_identity_bound_state(local_identity) {
        Ok(state) => state,
        Err(error) => return daemon_error_response(envelope.request_id, &error),
    };
    let peer = match payload.peer_id.parse() {
        Ok(peer) => peer,
        Err(_) => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::InvalidRequest,
                "session.connect peer_id must parse as a peer identifier",
                None,
            )
        }
    };
    let protocol = match ProtocolId::new(payload.protocol) {
        Ok(protocol) => protocol,
        Err(error) => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::InvalidRequest,
                error.to_string(),
                None,
            )
        }
    };
    let class = payload
        .class
        .as_deref()
        .map(parse_class)
        .unwrap_or(TrafficClass::Interactive);
    match control
        .realize_best_path(&peer, &protocol, class, transport)
        .await
    {
        Ok(session) => ResponseEnvelope::success(
            envelope.request_id,
            SessionConnectResult {
                truth_kind: "runtime".to_string(),
                session: SessionConnectSummary {
                    session_id: hex_session_id(&session.session_id),
                    state: runtime_state_label(&session.state).to_string(),
                    initial_path_class: path_class_label(session.path_kind).to_string(),
                    state_reason: session.state_reason.clone(),
                },
            },
        ),
        Err(error) => {
            let _ = state;
            daemon_error_response(envelope.request_id, &error)
        }
    }
}

async fn session_close_response(
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    let payload = match serde_json::from_value::<SessionClosePayload>(envelope.payload.clone()) {
        Ok(payload) => payload,
        Err(error) => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::InvalidRequest,
                format!("invalid session.close payload: {error}"),
                None,
            )
        }
    };
    let session_id = match parse_hex_session_id(&payload.session_id) {
        Ok(session_id) => session_id,
        Err(error) => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::InvalidRequest,
                error.to_string(),
                None,
            )
        }
    };
    match control.close_session(&session_id, transport).await {
        Ok(()) => ResponseEnvelope::success(
            envelope.request_id,
            SessionCloseResult {
                truth_kind: "runtime".to_string(),
                closed_session_id: payload.session_id,
                final_state: "closed".to_string(),
                closure_reason: payload.reason.or(Some("operator_requested".to_string())),
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

async fn session_upgrade_response(
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    let payload = match serde_json::from_value::<SessionUpgradePayload>(envelope.payload.clone()) {
        Ok(payload) => payload,
        Err(error) => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::InvalidRequest,
                format!("invalid session.upgrade payload: {error}"),
                None,
            )
        }
    };
    let session_id = match parse_hex_session_id(&payload.session_id) {
        Ok(session_id) => session_id,
        Err(error) => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::InvalidRequest,
                error.to_string(),
                None,
            )
        }
    };
    let prior_state = match control.sync_runtime_sessions(transport) {
        Ok(state) => state,
        Err(error) => return daemon_error_response(envelope.request_id, &error),
    };
    let prior = match prior_state
        .active_sessions()
        .iter()
        .find(|session| session.session_id == session_id)
        .cloned()
    {
        Some(session) => session,
        None => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::StaleRuntimeReference,
                "session id is no longer owned by this daemon run",
                Some(json!({ "session_id": payload.session_id })),
            )
        }
    };
    match control.upgrade_session(&session_id, transport).await {
        Ok(session) => ResponseEnvelope::success(
            envelope.request_id,
            SessionUpgradeResult {
                truth_kind: "runtime".to_string(),
                session_id: payload.session_id,
                prior_path_class: path_class_label(prior.path_kind).to_string(),
                resulting_path_class: path_class_label(session.path_kind).to_string(),
                state: runtime_state_label(&session.state).to_string(),
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

async fn session_reconcile_response(
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    envelope: RequestEnvelope,
) -> ResponseEnvelope {
    let _payload = match serde_json::from_value::<SessionReconcilePayload>(envelope.payload.clone())
    {
        Ok(payload) => payload,
        Err(error) => {
            return ResponseEnvelope::error(
                envelope.request_id,
                ErrorCode::InvalidRequest,
                format!("invalid session.reconcile payload: {error}"),
                None,
            )
        }
    };
    match control.reconcile_sessions(transport).await {
        Ok(report) => ResponseEnvelope::success(
            envelope.request_id,
            SessionReconcileResult {
                truth_kind: "runtime".to_string(),
                examined: report.examined,
                unchanged: report.unchanged,
                upgraded: report.upgraded,
                closed: report.closed,
                entries: report
                    .entries
                    .iter()
                    .map(|entry| ApiSessionReconcileEntry {
                        session_id: hex_session_id(&entry.session_id),
                        peer_id: entry.peer.to_string(),
                        disposition: reconcile_disposition_label(&entry.disposition).to_string(),
                        reason: entry.reason.clone(),
                        path_class: entry
                            .path_kind
                            .map(path_class_label)
                            .unwrap_or("unknown")
                            .to_string(),
                    })
                    .collect(),
            },
        ),
        Err(error) => daemon_error_response(envelope.request_id, &error),
    }
}

fn runtime_session_entry(session: &SessionSnapshot) -> RuntimeSessionEntry {
    let now = current_unix_secs();
    RuntimeSessionEntry {
        session_id: hex_session_id(&session.session_id),
        peer_id: session.peer.to_string(),
        state: runtime_state_label(&session.state).to_string(),
        closure_reason: session.closure_reason.as_ref().map(closure_reason_label),
        state_reason: session.state_reason.clone(),
        active_path_class: path_class_label(session.path_kind).to_string(),
        age_seconds: now.saturating_sub(session.created_at_unix_secs),
        last_activity_seconds: now.saturating_sub(session.last_activity_unix_secs),
    }
}

fn runtime_listener_entry(listener: fabric::RuntimeListenerSnapshot) -> RuntimeListenerEntry {
    RuntimeListenerEntry {
        listener_id: listener.listener_id,
        transport: listener.transport,
        bind_summary: listener.bind_summary,
        protocol: listener.protocol.as_str().to_string(),
        advertise: listener.advertise,
        state: runtime_listener_state_label(&listener.state).to_string(),
        age_seconds: current_unix_secs().saturating_sub(listener.started_at_unix_secs),
    }
}

fn runtime_path_entry(path: RuntimePathSnapshot) -> RuntimePathEntry {
    RuntimePathEntry {
        session_id: path
            .session_id
            .map(|session_id| hex_session_id(&session_id)),
        peer_id: path.peer.to_string(),
        protocol: path.protocol.map(|protocol| protocol.as_str().to_string()),
        class: class_label(path.class).to_string(),
        state: runtime_path_state_label(&path.state).to_string(),
        path_class: path
            .path_kind
            .map(path_class_label)
            .unwrap_or("unknown")
            .to_string(),
        source: path
            .source
            .as_ref()
            .map(path_source_label)
            .unwrap_or("runtime")
            .to_string(),
        relay_peer_id: path.relay_peer.map(|peer| peer.to_string()),
        endpoint_summary: path.endpoint_summary,
        score: path.score,
        state_reason: path.state_reason,
        summary: path.summary,
        alternatives: path
            .alternatives
            .into_iter()
            .map(runtime_path_alternative_entry)
            .collect(),
    }
}

fn runtime_path_alternative_entry(
    alternative: RuntimePathAlternative,
) -> RuntimePathAlternativeEntry {
    RuntimePathAlternativeEntry {
        path_class: path_class_label(alternative.path_kind).to_string(),
        source: path_source_label(&alternative.source).to_string(),
        relay_peer_id: alternative.relay_peer.map(|peer| peer.to_string()),
        score: alternative.score,
        summary: alternative.summary,
    }
}

fn authority_revision(state: &fabric::DaemonState) -> String {
    let sequence = state.max_revocation_sequence().unwrap_or(0);
    format!(
        "membership:{}:grants:{}:revocations:{}:max_seq:{}",
        state.membership.subject_peer_id,
        state.capability_grants.len(),
        state.revocations.len(),
        sequence
    )
}

fn daemon_error_response(
    request_id: impl Into<String>,
    error: &fabric::DaemonStateError,
) -> ResponseEnvelope {
    let (code, details) = match error {
        fabric::DaemonStateError::PeerNotFound(peer) => {
            (ErrorCode::NotFound, Some(json!({ "peer_id": peer })))
        }
        fabric::DaemonStateError::SessionNotFound(session_id) => (
            ErrorCode::StaleRuntimeReference,
            Some(json!({ "session_id": session_id })),
        ),
        fabric::DaemonStateError::PolicyDenied(_) => (ErrorCode::PolicyRejected, None),
        fabric::DaemonStateError::NetworkMismatch => (ErrorCode::AuthorityMismatch, None),
        fabric::DaemonStateError::MissingSchemaVersion
        | fabric::DaemonStateError::UnsupportedSchemaVersion { .. }
        | fabric::DaemonStateError::UnsupportedDurableField(_) => {
            (ErrorCode::StateValidationFailed, None)
        }
        _ => (ErrorCode::InternalError, None),
    };
    ResponseEnvelope::error(request_id, code, error.to_string(), details)
}

fn map_error_status(response: &ResponseEnvelope) -> StatusCode {
    match response.error.as_ref().map(|error| &error.code) {
        Some(ErrorCode::InvalidRequest) => StatusCode(400),
        Some(ErrorCode::Unauthorized) => StatusCode(401),
        Some(ErrorCode::NotFound) => StatusCode(404),
        Some(ErrorCode::RuntimeUnavailable) => StatusCode(503),
        Some(ErrorCode::StaleRuntimeReference) => StatusCode(409),
        Some(ErrorCode::PolicyRejected) => StatusCode(403),
        Some(ErrorCode::AuthorityMismatch) => StatusCode(409),
        Some(ErrorCode::StateValidationFailed) => StatusCode(422),
        Some(ErrorCode::UnsupportedOperation) => StatusCode(404),
        Some(ErrorCode::InternalError) | None => StatusCode(500),
    }
}

fn json_response(
    status: StatusCode,
    value: impl serde::Serialize,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec_pretty(&value).expect("daemon JSON serialization should work");
    let mut response = Response::from_data(body).with_status_code(status);
    response.add_header(
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .expect("daemon response header should be valid"),
    );
    response
}

fn path_class_label(path_kind: fabric::PathKind) -> &'static str {
    match path_kind {
        fabric::PathKind::Relay => "relay",
        _ => "direct",
    }
}

fn path_source_label(source: &PathSource) -> &'static str {
    match source {
        PathSource::Observed => "observed",
        PathSource::Bootstrap => "bootstrap",
        PathSource::AuthorityRelay => "authority_relay",
    }
}

fn class_label(class: TrafficClass) -> &'static str {
    match class {
        TrafficClass::Control => "control",
        TrafficClass::Interactive => "interactive",
        TrafficClass::Bulk => "bulk",
        TrafficClass::Background => "background",
    }
}

fn runtime_state_label(state: &fabric::RuntimeSessionState) -> &'static str {
    match state {
        fabric::RuntimeSessionState::Pending => "pending",
        fabric::RuntimeSessionState::Connecting => "connecting",
        fabric::RuntimeSessionState::Active => "active",
        fabric::RuntimeSessionState::Degraded => "degraded",
        fabric::RuntimeSessionState::Migrating => "migrating",
        fabric::RuntimeSessionState::Reconciling => "reconciling",
        fabric::RuntimeSessionState::Closing => "closing",
        fabric::RuntimeSessionState::Closed => "closed",
        fabric::RuntimeSessionState::Failed => "failed",
    }
}

fn runtime_path_state_label(state: &RuntimePathState) -> &'static str {
    match state {
        RuntimePathState::Active => "active",
        RuntimePathState::Degraded => "degraded",
        RuntimePathState::Migrating => "migrating",
        RuntimePathState::Failed => "failed",
        RuntimePathState::Suppressed => "suppressed",
    }
}

fn runtime_listener_state_label(state: &fabric::RuntimeListenerState) -> &'static str {
    match state {
        fabric::RuntimeListenerState::Active => "active",
        fabric::RuntimeListenerState::Failed => "failed",
    }
}

fn runtime_health_level_label(level: &RuntimeHealthLevel) -> &'static str {
    match level {
        RuntimeHealthLevel::Ready => "ready",
        RuntimeHealthLevel::Degraded => "degraded",
        RuntimeHealthLevel::Failed => "failed",
        RuntimeHealthLevel::Suppressed => "suppressed",
    }
}

fn runtime_reconnect_state_label(state: &fabric::RuntimeReconnectState) -> &'static str {
    match state {
        fabric::RuntimeReconnectState::Idle => "idle",
        fabric::RuntimeReconnectState::Active => "active",
        fabric::RuntimeReconnectState::Suppressed => "suppressed",
        fabric::RuntimeReconnectState::Failed => "failed",
    }
}

fn closure_reason_label(reason: &fabric::SessionClosureReason) -> String {
    match reason {
        fabric::SessionClosureReason::OperatorRequested => "operator_requested".to_string(),
        fabric::SessionClosureReason::LocalRuntimeFailure => "local_runtime_failure".to_string(),
        fabric::SessionClosureReason::RemoteFailure => "remote_failure".to_string(),
        fabric::SessionClosureReason::PolicyRejected => "policy_rejected".to_string(),
        fabric::SessionClosureReason::PathExhaustion => "path_exhaustion".to_string(),
        fabric::SessionClosureReason::DaemonShutdown => "daemon_shutdown".to_string(),
    }
}

fn hex_public_key(identity: &IdentityKeypair) -> String {
    identity
        .public_key()
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn parse_hex_session_id(value: &str) -> Result<[u8; 16], std::io::Error> {
    if value.len() != 32 {
        return Err(std::io::Error::other(
            "session ids supplied to daemon API must be 32 hex characters",
        ));
    }
    let mut session_id = [0_u8; 16];
    for (index, slot) in session_id.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| {
            std::io::Error::other("session ids supplied to daemon API must be valid hex")
        })?;
    }
    Ok(session_id)
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs()
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

fn authority_reevaluation_summary_line(report: &fabric::AuthorityReevaluationReport) -> String {
    format!(
        "reevaluated={} closed={} degraded={} migrated={} unchanged={} suppressed_added={} suppressed_cleared={} local_policy_denied={} subject_mismatch={} local_membership_denied={} peer_membership_denied={} capability_denied={} reason={}",
        report.reevaluated_sessions,
        report.closed_sessions,
        report.degraded_sessions,
        report.migrated_sessions,
        report.unchanged_sessions,
        report.reconnect_suppressions_added,
        report.reconnect_suppressions_cleared,
        report.local_policy_denied,
        report.authority_subject_mismatch,
        report.local_membership_denied_sessions,
        report.peer_membership_denied_sessions,
        report.capability_denied_sessions,
        report.local_policy_reason.as_deref().unwrap_or("none")
    )
}

fn latest_authority_status(
    transport: &QuicTransportAdapter,
    state: &fabric::DaemonState,
    health: &fabric::RuntimeHealthReport,
) -> Result<AuthoritySyncStatus, fabric::DaemonStateError> {
    let latest = transport
        .recent_events(64)?
        .into_iter()
        .rev()
        .find(|event| event.event_type == "authority.reevaluation_completed");

    let mut status = AuthoritySyncStatus {
        sync_status: if health.authority_subject_status == "mismatched" {
            "subject_mismatch".to_string()
        } else if health.authority_deny_reason.is_some() {
            "policy_enforced".to_string()
        } else {
            "in_sync".to_string()
        },
        last_accepted_revision: authority_revision(state),
        health: runtime_health_level_label(&health.authority_sync_health).to_string(),
        local_policy_denied: health.authority_deny_reason.is_some(),
        authority_subject_mismatch: health.authority_subject_status == "mismatched",
        reevaluated_sessions: 0,
        closed_sessions: 0,
        degraded_sessions: 0,
        migrated_sessions: 0,
        unchanged_sessions: 0,
        reconnect_suppressions_added: 0,
        reconnect_suppressions_cleared: 0,
        local_policy_reason: health.authority_deny_reason.clone(),
    };

    if let Some(event) = latest {
        status.local_policy_denied = event
            .details
            .get("local_policy_denied")
            .and_then(|value| value.as_bool())
            .unwrap_or(status.local_policy_denied);
        status.authority_subject_mismatch = event
            .details
            .get("authority_subject_mismatch")
            .and_then(|value| value.as_bool())
            .unwrap_or(status.authority_subject_mismatch);
        status.reevaluated_sessions = event
            .details
            .get("reevaluated_sessions")
            .and_then(|value| value.as_u64())
            .unwrap_or(0) as usize;
        status.closed_sessions = event
            .details
            .get("closed_sessions")
            .and_then(|value| value.as_u64())
            .unwrap_or(0) as usize;
        status.degraded_sessions = event
            .details
            .get("degraded_sessions")
            .and_then(|value| value.as_u64())
            .unwrap_or(0) as usize;
        status.migrated_sessions = event
            .details
            .get("migrated_sessions")
            .and_then(|value| value.as_u64())
            .unwrap_or(0) as usize;
        status.unchanged_sessions = event
            .details
            .get("unchanged_sessions")
            .and_then(|value| value.as_u64())
            .unwrap_or(0) as usize;
        status.reconnect_suppressions_added = event
            .details
            .get("reconnect_suppressions_added")
            .and_then(|value| value.as_u64())
            .unwrap_or(0) as usize;
        status.reconnect_suppressions_cleared = event
            .details
            .get("reconnect_suppressions_cleared")
            .and_then(|value| value.as_u64())
            .unwrap_or(0) as usize;
        status.local_policy_reason = event
            .details
            .get("local_policy_reason")
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .or(status.local_policy_reason);
    }

    Ok(status)
}

async fn authority_sync_response<F>(
    _args: &Args,
    control: &LocalControlPlane,
    transport: &QuicTransportAdapter,
    local_identity: &IdentityKeypair,
    request_id: String,
    authority_source: &str,
    authority_snapshot: Option<String>,
    authority_origin: Option<String>,
    authority_subject: Option<String>,
    sync_fn: F,
) -> ResponseEnvelope
where
    F: FnOnce(
        &LocalControlPlane,
    )
        -> Result<(fabric::DaemonState, fabric::StateSyncReport), fabric::DaemonStateError>,
{
    let runtime_peer = local_identity.peer_id().to_string();
    if let Err(error) = transport.record_runtime_event(
        "authority.sync_started",
        fabric::RuntimeEventSubject {
            kind: "authority".to_string(),
            id: runtime_peer.clone(),
        },
        json!({
            "authority_source": authority_source,
            "authority_origin": authority_origin,
            "authority_subject": authority_subject,
            "authority_snapshot": authority_snapshot
        }),
    ) {
        return daemon_error_response(request_id, &error.into());
    }

    let sync = sync_fn(control);
    let (state, report) = match sync {
        Ok(result) => result,
        Err(error) => {
            let _ = transport.record_runtime_event(
                "authority.sync_failed",
                fabric::RuntimeEventSubject {
                    kind: "authority".to_string(),
                    id: runtime_peer,
                },
                json!({
                    "authority_source": authority_source,
                    "authority_origin": authority_origin,
                    "authority_subject": authority_subject,
                    "authority_snapshot": authority_snapshot,
                    "error": error.to_string()
                }),
            );
            return daemon_error_response(request_id, &error);
        }
    };

    let reevaluated = if state_sync_requires_reevaluation(&report) {
        match control
            .reevaluate_runtime_authority(local_identity, transport)
            .await
        {
            Ok(report) => Some(report),
            Err(error) => {
                let _ = transport.record_runtime_event(
                    "authority.sync_failed",
                    fabric::RuntimeEventSubject {
                        kind: "authority".to_string(),
                        id: runtime_peer,
                    },
                    json!({
                        "authority_source": authority_source,
                        "authority_origin": authority_origin,
                        "authority_subject": authority_subject,
                        "authority_snapshot": authority_snapshot,
                        "error": error.to_string(),
                        "phase": "reevaluation"
                    }),
                );
                return daemon_error_response(request_id, &error);
            }
        }
    } else {
        None
    };

    let health = match control.runtime_health(transport) {
        Ok(health) => health,
        Err(error) => return daemon_error_response(request_id, &error),
    };
    let authority = match latest_authority_status(transport, &state, &health) {
        Ok(authority) => authority,
        Err(error) => return daemon_error_response(request_id, &error),
    };

    if let Err(error) = transport.record_runtime_event(
        "authority.sync_completed",
        fabric::RuntimeEventSubject {
            kind: "authority".to_string(),
            id: runtime_peer,
        },
        json!({
            "authority_source": authority_source,
            "authority_origin": authority_origin,
            "authority_subject": authority_subject,
            "authority_snapshot": authority_snapshot,
            "membership_changed": report.membership_changed,
            "grants_added": report.grants_added,
            "grants_removed": report.grants_removed,
            "revocations_added": report.revocations_added,
            "bootstrap_hints_added": report.bootstrap_hints_added,
            "bootstrap_hints_removed": report.bootstrap_hints_removed,
            "relay_announcements_added": report.relay_announcements_added,
            "reevaluation_triggered": reevaluated.is_some()
        }),
    ) {
        return daemon_error_response(request_id, &error.into());
    }

    ResponseEnvelope::success(
        request_id,
        AuthoritySyncResult {
            truth_kind: "runtime".to_string(),
            authority_source: authority_source.to_string(),
            authority_origin,
            authority_subject,
            authority_snapshot,
            network: state.network.clone(),
            local_peer_id: state.local_peer_id.to_string(),
            grants_added: report.grants_added,
            grants_removed: report.grants_removed,
            revocations_added: report.revocations_added,
            bootstrap_hints_added: report.bootstrap_hints_added,
            bootstrap_hints_removed: report.bootstrap_hints_removed,
            relay_announcements_added: report.relay_announcements_added,
            membership_changed: report.membership_changed,
            authority,
        },
    )
}

fn state_sync_requires_reevaluation(report: &fabric::StateSyncReport) -> bool {
    report.membership_changed
        || report.grants_added > 0
        || report.grants_removed > 0
        || report.revocations_added > 0
        || report.bootstrap_hints_added > 0
        || report.bootstrap_hints_removed > 0
        || report.relay_announcements_added > 0
}

fn render_revocation_reason(reason: &membership::RevocationReason) -> &'static str {
    match reason {
        membership::RevocationReason::Administrative => "administrative",
        membership::RevocationReason::KeyCompromise => "key_compromise",
        membership::RevocationReason::Superseded => "superseded",
        membership::RevocationReason::Unspecified => "unspecified",
    }
}

fn render_revocation_target(target: &membership::RevocationTarget) -> String {
    match target {
        membership::RevocationTarget::EnrollmentToken { token_id } => {
            format!("enrollment_token:{}", hex_bytes(token_id))
        }
        membership::RevocationTarget::MembershipCertificate {
            subject_peer_id,
            issued_at,
        } => format!("membership_certificate:{subject_peer_id}:{issued_at}"),
        membership::RevocationTarget::CapabilityGrant {
            subject_peer_id,
            sequence,
        } => format!("capability_grant:{subject_peer_id}:{sequence}"),
        membership::RevocationTarget::Peer { peer_id } => format!("peer:{peer_id}"),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
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
    use daemonapi::{AuthoritySyncResult, RuntimeStatusResult};
    use quic::QuicTransportAdapter;
    use serde_json::json;

    #[test]
    fn prepare_state_for_trigger_reloads_existing_state_for_state_change() {
        let state_path = unique_temp_path("quicnetd-prepare-state-change");
        let control =
            LocalControlPlane::new(DaemonConfig::new("prepare-state-change", &state_path));
        let state = fabric::fixture_daemon_state("prepare-state-change");
        state.save(&state_path).expect("state should persist");
        let args = test_args(state_path.to_string_lossy().as_ref());
        let local_identity = IdentityKeypair::from_secret_bytes([91_u8; 32]);

        let (preparation, reprobe_report, prepared_state) = prepare_state_for_trigger(
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

        let (preparation, reprobe_report, prepared_state) = prepare_state_for_trigger(
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

    #[test]
    fn write_control_discovery_persists_runtime_instance_id() {
        let discovery_path = unique_temp_path("quipd-control-discovery");
        write_control_discovery(
            &discovery_path,
            DaemonEndpointDiscovery {
                endpoint: "http://127.0.0.1:4000/rpc".to_string(),
                network: "test-network".to_string(),
                state_path: "/tmp/state.json".to_string(),
                identity_path: "/tmp/identity.json".to_string(),
                runtime_instance_id: "runtime-instance-123".to_string(),
                pid: 42,
                started_at_unix_secs: 1_726_000_000,
            },
        )
        .expect("discovery should persist");

        let persisted: DaemonEndpointDiscovery = serde_json::from_slice(
            &std::fs::read(&discovery_path).expect("discovery file should be readable"),
        )
        .expect("discovery JSON should deserialize");

        assert_eq!(persisted.runtime_instance_id, "runtime-instance-123");
        assert_eq!(persisted.endpoint, "http://127.0.0.1:4000/rpc");
        let _ = std::fs::remove_file(discovery_path);
    }

    #[test]
    fn state_sync_requires_reevaluation_when_report_changes_authority_facts() {
        assert!(state_sync_requires_reevaluation(&fabric::StateSyncReport {
            membership_changed: false,
            grants_added: 0,
            grants_removed: 1,
            revocations_added: 0,
            bootstrap_hints_added: 0,
            bootstrap_hints_removed: 0,
            relay_announcements_added: 0,
        }));
        assert!(!state_sync_requires_reevaluation(
            &fabric::StateSyncReport {
                membership_changed: false,
                grants_added: 0,
                grants_removed: 0,
                revocations_added: 0,
                bootstrap_hints_added: 0,
                bootstrap_hints_removed: 0,
                relay_announcements_added: 0,
            }
        ));
    }

    #[test]
    fn identity_show_response_reports_runtime_and_durable_binding() {
        let state_path = unique_temp_path("quipd-identity-show");
        let control = LocalControlPlane::new(DaemonConfig::new("identity-show", &state_path));
        let local_identity = IdentityKeypair::from_secret_bytes([99_u8; 32]);
        let mut state = fabric::fixture_daemon_state("identity-show");
        state.local_peer_id = local_identity.peer_id();
        state.membership.subject_peer_id = local_identity.peer_id();
        state.save(&state_path).expect("state should persist");
        let args = test_args(state_path.to_string_lossy().as_ref());

        let response = identity_show_response(
            &args,
            &control,
            &local_identity,
            RequestEnvelope {
                request_id: "req-identity-show".to_string(),
                operation: "identity.show".to_string(),
                auth: daemonapi::RequestAuth {
                    kind: daemonapi::AuthKind::LocalProcess,
                },
                payload: json!({}),
            },
        );

        assert!(response.ok);
        let result: IdentityShowResult =
            serde_json::from_value(response.result.expect("show result should exist"))
                .expect("show result should deserialize");
        assert_eq!(result.node_id, local_identity.peer_id().to_string());
        assert_eq!(result.state_binding_status, "matched");
        assert_eq!(result.truth_kind, "runtime_and_durable");
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn identity_verify_response_reports_mismatch_against_durable_and_authority_state() {
        let state_path = unique_temp_path("quipd-identity-verify");
        let control = LocalControlPlane::new(DaemonConfig::new("identity-verify", &state_path));
        let local_identity = IdentityKeypair::from_secret_bytes([100_u8; 32]);
        let authority = IdentityKeypair::from_secret_bytes([101_u8; 32]);
        let different_identity = IdentityKeypair::from_secret_bytes([102_u8; 32]);
        let mut state = fabric::fixture_daemon_state("identity-verify");
        state.local_peer_id = different_identity.peer_id();
        state.membership = membership::MembershipCertificate::issue(
            &authority,
            fabric::NetworkId::derive("identity-verify"),
            different_identity.peer_id(),
            100,
            300,
            vec!["member".to_string()],
        );
        state.save(&state_path).expect("state should persist");
        let args = test_args(state_path.to_string_lossy().as_ref());

        let response = identity_verify_response(
            &args,
            &control,
            &local_identity,
            RequestEnvelope {
                request_id: "req-identity-verify".to_string(),
                operation: "identity.verify".to_string(),
                auth: daemonapi::RequestAuth {
                    kind: daemonapi::AuthKind::LocalProcess,
                },
                payload: json!({}),
            },
        );

        assert!(response.ok);
        let result: IdentityVerifyResult =
            serde_json::from_value(response.result.expect("verify result should exist"))
                .expect("verify result should deserialize");
        assert_eq!(result.match_result, "mismatch");
        assert_eq!(result.loaded_node_id, local_identity.peer_id().to_string());
        assert_eq!(
            result.expected_node_id,
            Some(different_identity.peer_id().to_string())
        );
        assert_eq!(result.mismatch_reasons.len(), 2);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn runtime_status_reports_authority_subject_mismatch_instead_of_failing() {
        let state_path = unique_temp_path("quipd-runtime-status-subject-mismatch");
        let control =
            LocalControlPlane::new(DaemonConfig::new("status-subject-mismatch", &state_path));
        let local_identity = IdentityKeypair::from_secret_bytes([101_u8; 32]);
        let other_identity = IdentityKeypair::from_secret_bytes([102_u8; 32]);
        let authority = IdentityKeypair::from_secret_bytes([103_u8; 32]);
        let mut state = fabric::fixture_daemon_state("status-subject-mismatch");
        state.local_peer_id = local_identity.peer_id();
        state.membership = membership::MembershipCertificate::issue(
            &authority,
            fabric::NetworkId::derive("status-subject-mismatch"),
            other_identity.peer_id(),
            100,
            300,
            vec!["member".to_string()],
        );
        state.save(&state_path).expect("state should persist");
        let args = test_args(state_path.to_string_lossy().as_ref());
        let transport = QuicTransportAdapter::with_identity(
            fabric::NetworkId::derive("status-subject-mismatch"),
            local_identity.clone(),
        );

        let response = runtime_status_response(
            &args,
            &control,
            &transport,
            &local_identity,
            RequestEnvelope {
                request_id: "req-status".to_string(),
                operation: "runtime.status".to_string(),
                auth: daemonapi::RequestAuth {
                    kind: daemonapi::AuthKind::LocalProcess,
                },
                payload: json!({}),
            },
        );

        assert!(response.ok);
        let result: RuntimeStatusResult =
            serde_json::from_value(response.result.expect("status result should exist"))
                .expect("status result should deserialize");
        assert_eq!(result.authority.sync_status, "subject_mismatch");
        assert!(result.authority.authority_subject_mismatch);
        let _ = std::fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn authority_sync_response_triggers_live_reevaluation_when_grants_are_removed() {
        let state_path = unique_temp_path("quipd-authority-sync-reevaluation");
        let network = "authority-sync-reevaluation";
        let control = LocalControlPlane::new(DaemonConfig::new(network, &state_path));
        let authority = IdentityKeypair::from_secret_bytes([104_u8; 32]);
        let local_identity = IdentityKeypair::from_secret_bytes([105_u8; 32]);
        let protocol = ProtocolId::new("/quicnet/control/1").expect("protocol");
        let mut state = fabric::fixture_daemon_state(network);
        let target = state
            .peers
            .first()
            .expect("fixture peer should exist")
            .snapshot
            .peer
            .clone();
        state.local_peer_id = local_identity.peer_id();
        state.membership = membership::MembershipCertificate::issue(
            &authority,
            fabric::NetworkId::derive(network),
            local_identity.peer_id(),
            100,
            300,
            vec!["member".to_string()],
        );
        state.capability_grants = vec![membership::CapabilityGrant::issue(
            &authority,
            fabric::NetworkId::derive(network),
            local_identity.peer_id(),
            vec!["control.access".to_string()],
            vec![protocol.clone()],
            membership::ResourceLimits::default(),
            vec![],
            100,
            300,
            1,
        )];
        state.denied_peers.clear();
        state.save(&state_path).expect("state should persist");
        let transport = QuicTransportAdapter::with_identity(
            fabric::NetworkId::derive(network),
            local_identity.clone(),
        );
        let _session = control
            .realize_best_path(&target, &protocol, TrafficClass::Control, &transport)
            .await
            .expect("session should establish");
        let args = test_args(state_path.to_string_lossy().as_ref());
        let state_path_for_closure = state_path.clone();

        let response = authority_sync_response(
            &args,
            &control,
            &transport,
            &local_identity,
            "req-sync".to_string(),
            "snapshot",
            Some("/tmp/authority-snapshot.json".to_string()),
            None,
            None,
            move |_| {
                let mut updated =
                    fabric::DaemonState::load(&state_path_for_closure).expect("state should load");
                updated.capability_grants.clear();
                updated
                    .save(&state_path_for_closure)
                    .expect("state should persist");
                Ok((
                    updated,
                    fabric::StateSyncReport {
                        membership_changed: false,
                        grants_added: 0,
                        grants_removed: 1,
                        revocations_added: 0,
                        bootstrap_hints_added: 0,
                        bootstrap_hints_removed: 0,
                        relay_announcements_added: 0,
                    },
                ))
            },
        )
        .await;

        assert!(response.ok);
        let result: AuthoritySyncResult =
            serde_json::from_value(response.result.expect("sync result should exist"))
                .expect("sync result should deserialize");
        assert_eq!(result.grants_removed, 1);
        assert_eq!(result.authority.closed_sessions, 1);
        assert_eq!(result.authority.reconnect_suppressions_added, 1);

        let events = transport.recent_events(16).expect("events should load");
        assert!(events
            .iter()
            .any(|event| event.event_type == "authority.sync_started"));
        assert!(events
            .iter()
            .any(|event| event.event_type == "authority.sync_completed"));
        assert!(events
            .iter()
            .any(|event| event.event_type == "authority.policy_enforced"));
        let _ = std::fs::remove_file(state_path);
    }

    fn test_args(state_path: &str) -> Args {
        Args {
            network: "test-network".to_string(),
            state_path: state_path.to_string(),
            identity_path: "./var/test-identity.json".to_string(),
            control_discovery_path: "./var/control.json".to_string(),
            control_bind: "127.0.0.1:0".to_string(),
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
}
