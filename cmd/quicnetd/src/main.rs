use std::time::Duration;

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
    state: fabric::DaemonState,
    reconcile_report: Option<fabric::SessionReconcileReport>,
    active_session: Option<SessionSnapshot>,
    connect_status: String,
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

    loop {
        let report = match run_cycle(&args, &control).await {
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

        let sleep_duration = Duration::from_secs(args.reconcile_interval_seconds.max(1));
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    eprintln!("quicnetd signal handling failed: {error}");
                    std::process::exit(1);
                }
                println!("quicnetd stopping: received interrupt");
                break;
            }
            _ = tokio::time::sleep(sleep_duration) => {}
        }
    }
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
        "quicnetd active: {} selected_path={} active_session={} reconcile={} connect={} state_path={}",
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

fn hex_session_id(session_id: &[u8; 16]) -> String {
    session_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
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

fn reconcile_disposition_label(disposition: &fabric::SessionReconcileDisposition) -> &'static str {
    match disposition {
        fabric::SessionReconcileDisposition::Unchanged => "unchanged",
        fabric::SessionReconcileDisposition::Upgraded => "upgraded",
        fabric::SessionReconcileDisposition::Closed => "closed",
    }
}
