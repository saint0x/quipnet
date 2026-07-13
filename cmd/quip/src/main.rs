use clap::{Parser, Subcommand};
use crypto::IdentityKeypair;
use daemonapi::{
    AuthKind, DaemonEndpointDiscovery, RequestAuth, RequestEnvelope, ResponseEnvelope,
    RuntimeSessionsListResult, RuntimeStatusResult, SessionClosePayload, SessionCloseResult,
    SessionConnectPayload, SessionConnectResult, SessionReconcilePayload, SessionReconcileResult,
    SessionUpgradePayload, SessionUpgradeResult,
};
use fabric::PathCandidate;
use fabric::{DaemonConfig, LocalControlPlane, PeerId, ProtocolId, TrafficClass};
use identity::{FileKeystore, IdentityKeystore};
use rand::rngs::OsRng;
use serde_json::json;
use std::error::Error;
use std::path::Path;
use std::time::Duration;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,

    #[arg(long, default_value = "~/.quip/net/state.json")]
    state_path: String,

    #[arg(long, default_value = "~/.quip/identity/node.json")]
    identity_path: String,

    #[arg(long, default_value = "~/.quip/run/control.json")]
    control_discovery_path: String,

    #[arg(long, default_value = "QUIP_IDENTITY_PASSPHRASE")]
    identity_passphrase_env: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Join {
        #[arg(long)]
        authority_snapshot: String,
    },
    JoinOrigin {
        #[arg(long)]
        authority_origin: String,
        #[arg(long)]
        authority_subject: Option<String>,
    },
    Status,
    Peers,
    PeerInspect {
        peer: Option<String>,
    },
    PolicyExplain {
        protocol: String,
        #[arg(long)]
        peer: Option<String>,
    },
    Netcheck,
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Path {
        #[command(subcommand)]
        command: PathCommand,
    },
    Connect {
        protocol: String,
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, default_value = "interactive")]
        class: String,
    },
    SessionStatus,
    SessionClose {
        #[arg(long)]
        session: Option<String>,
    },
    SessionUpgrade {
        #[arg(long)]
        session: Option<String>,
    },
    SessionReconcile,
    State {
        #[command(subcommand)]
        command: StateCommand,
    },
    Authority {
        #[command(subcommand)]
        command: AuthorityCommand,
    },
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    RelayStatus,
}

#[derive(Subcommand, Debug)]
enum PathCommand {
    Show {
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, default_value = "interactive")]
        class: String,
    },
    Watch {
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, default_value = "interactive")]
        class: String,
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        #[arg(long, default_value_t = 1)]
        sample_limit: u32,
    },
}

#[derive(Subcommand, Debug)]
enum RuntimeCommand {
    Sessions,
}

#[derive(Subcommand, Debug)]
enum SessionCommand {
    List,
    Connect {
        protocol: String,
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, default_value = "interactive")]
        class: String,
        #[arg(long, default_value = "direct_preferred")]
        path_preference: String,
    },
    Close {
        #[arg(long)]
        session: Option<String>,
    },
    Upgrade {
        #[arg(long)]
        session: Option<String>,
    },
    Reconcile,
}

#[derive(Subcommand, Debug)]
enum StateCommand {
    Validate,
    Reset {
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AuthorityCommand {
    Show,
    Membership,
    Capabilities,
    Revocations,
    SyncSnapshot {
        #[arg(long)]
        authority_snapshot: String,
    },
    SyncOrigin {
        #[arg(long)]
        authority_origin: String,
        #[arg(long)]
        authority_subject: Option<String>,
    },
    SyncRevocationsOrigin {
        #[arg(long)]
        authority_origin: String,
    },
}

#[derive(Subcommand, Debug)]
enum IdentityCommand {
    Show,
    Init {
        #[arg(long, default_value_t = false)]
        overwrite: bool,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    observability::init_tracing("quip");
    let mut cli = Cli::parse();
    normalize_cli_paths(&mut cli);
    let control = LocalControlPlane::new(DaemonConfig::new(
        cli.network.clone(),
        cli.state_path.clone(),
    ));
    match cli.command.take().unwrap_or(Command::Status) {
        Command::Join { authority_snapshot } => {
            let state = control.seed_from_authority_snapshot(&authority_snapshot)?;
            println!(
                "joined network={} local_peer={} bootstrap={} state_path={}",
                state.network,
                state.local_peer_id,
                state.bootstrap.len(),
                cli.state_path
            );
        }
        Command::JoinOrigin {
            authority_origin,
            authority_subject,
        } => {
            let state = control
                .seed_from_authority_origin(&authority_origin, authority_subject.as_deref())?;
            println!(
                "joined network={} local_peer={} bootstrap={} state_path={} authority_origin={} authority_subject={}",
                state.network,
                state.local_peer_id,
                state.bootstrap.len(),
                cli.state_path,
                authority_origin,
                authority_subject.as_deref().unwrap_or("active")
            );
        }
        Command::Status => {
            match daemon_request::<RuntimeStatusResult>(&cli, "runtime.status", json!({})) {
                Ok(status) => {
                    println!(
                        "daemon_health={} identity_status={} identity_peer={} durable_state_status={} schema_version={} authority_sync={} authority_revision={} runtime_sessions={} active_paths={} reconnect_state={} truth_kind={}",
                        status.daemon_health,
                        status.identity.status,
                        status.identity.node_id,
                        status.durable_state.status,
                        status.durable_state.schema_version,
                        status.authority.sync_status,
                        status.authority.last_accepted_revision,
                        status.runtime_summary.session_count,
                        status.runtime_summary.active_path_count,
                        status.runtime_summary.reconnect_state,
                        status.truth_kind
                    );
                }
                Err(_) => {
                    let state = control.ensure_state()?;
                    println!(
                        "{} daemon_health=unavailable truth_kind=durable",
                        state.status_line()
                    );
                }
            }
        }
        Command::Peers => {
            let state = control.ensure_state()?;
            for peer in &state.peers {
                let denied = state
                    .deny_reason(&peer.snapshot.peer)
                    .map(|reason| format!(" denied={reason}"))
                    .unwrap_or_default();
                println!(
                    "{} {:?} {:?} {:?}{}",
                    peer.snapshot.peer,
                    peer.status.source,
                    peer.status.reachability,
                    peer.snapshot.addresses,
                    denied
                );
            }
        }
        Command::PeerInspect { peer } => {
            let state = control.ensure_state()?;
            let target = resolve_peer(peer.as_deref(), &state)?;
            let (inspection, best_path) = control.inspect_peer(&target)?;
            println!(
                "{} {:?} {:?} {:?} records={}",
                inspection.snapshot.peer,
                inspection.status.source,
                inspection.status.reachability,
                inspection.snapshot.addresses,
                inspection.record_count
            );
            if let Some(reason) = state.deny_reason(&inspection.snapshot.peer) {
                println!("denied: {}", reason);
            }
            if let Some(best_path) = best_path {
                println!("{}", best_path.explanation.summary);
            }
        }
        Command::PolicyExplain { peer, protocol } => {
            let state = control.ensure_state()?;
            let target = resolve_peer(peer.as_deref(), &state)?;
            let protocol =
                ProtocolId::new(protocol).map_err(|error| usage_error(error.to_string()))?;
            let decision = control.explain_policy(&target, &protocol)?;
            println!(
                "peer={} protocol={} allowed={} reason={}",
                target, protocol, decision.allowed, decision.reason
            );
        }
        Command::Netcheck => {
            let state = control.ensure_state()?;
            println!("{}", state.netcheck.summary());
            for warning in state.netcheck.warnings() {
                println!("warning: {}", warning);
            }
        }
        Command::Runtime { command } => match command {
            RuntimeCommand::Sessions => {
                let sessions = daemon_request::<RuntimeSessionsListResult>(
                    &cli,
                    "runtime.sessions.list",
                    json!({}),
                )?;
                if sessions.sessions.is_empty() {
                    println!("truth_kind={} sessions=0", sessions.truth_kind);
                } else {
                    for session in sessions.sessions {
                        println!(
                            "session_id={} peer={} state={} path={} age_seconds={} last_activity_seconds={} truth_kind={}",
                            session.session_id,
                            session.peer_id,
                            session.state,
                            session.active_path_class,
                            session.age_seconds,
                            session.last_activity_seconds,
                            sessions.truth_kind
                        );
                    }
                }
            }
        },
        Command::Session { command } => match command {
            SessionCommand::List => {
                let sessions = daemon_request::<RuntimeSessionsListResult>(
                    &cli,
                    "runtime.sessions.list",
                    json!({}),
                )?;
                if sessions.sessions.is_empty() {
                    println!("truth_kind={} sessions=0", sessions.truth_kind);
                } else {
                    for session in sessions.sessions {
                        println!(
                            "session_id={} peer={} state={} path={} age_seconds={} last_activity_seconds={} truth_kind={}",
                            session.session_id,
                            session.peer_id,
                            session.state,
                            session.active_path_class,
                            session.age_seconds,
                            session.last_activity_seconds,
                            sessions.truth_kind
                        );
                    }
                }
            }
            SessionCommand::Connect {
                protocol,
                peer,
                class,
                path_preference,
            } => {
                let state = control.ensure_state()?;
                let target = resolve_peer(peer.as_deref(), &state)?;
                let result = daemon_request::<SessionConnectResult>(
                    &cli,
                    "session.connect",
                    serde_json::to_value(SessionConnectPayload {
                        peer_id: target.to_string(),
                        protocol,
                        class: Some(class),
                        path_preference: Some(path_preference),
                    })?,
                )?;
                println!(
                    "session_id={} state={} path={} truth_kind={}",
                    result.session.session_id,
                    result.session.state,
                    result.session.initial_path_class,
                    result.truth_kind
                );
            }
            SessionCommand::Close { session } => {
                let sessions = daemon_request::<RuntimeSessionsListResult>(
                    &cli,
                    "runtime.sessions.list",
                    json!({}),
                )?;
                let session_id = resolve_daemon_session_id(session.as_deref(), &sessions.sessions)?;
                let result = daemon_request::<SessionCloseResult>(
                    &cli,
                    "session.close",
                    serde_json::to_value(SessionClosePayload {
                        session_id,
                        reason: Some("operator_requested".to_string()),
                    })?,
                )?;
                println!(
                    "session_id={} final_state={} closure_reason={} truth_kind={}",
                    result.closed_session_id,
                    result.final_state,
                    result.closure_reason.as_deref().unwrap_or("none"),
                    result.truth_kind
                );
            }
            SessionCommand::Upgrade { session } => {
                let sessions = daemon_request::<RuntimeSessionsListResult>(
                    &cli,
                    "runtime.sessions.list",
                    json!({}),
                )?;
                let session_id = resolve_daemon_session_id(session.as_deref(), &sessions.sessions)?;
                let result = daemon_request::<SessionUpgradeResult>(
                    &cli,
                    "session.upgrade",
                    serde_json::to_value(SessionUpgradePayload { session_id })?,
                )?;
                println!(
                    "session_id={} prior_path={} resulting_path={} state={} truth_kind={}",
                    result.session_id,
                    result.prior_path_class,
                    result.resulting_path_class,
                    result.state,
                    result.truth_kind
                );
            }
            SessionCommand::Reconcile => {
                let result = daemon_request::<SessionReconcileResult>(
                    &cli,
                    "session.reconcile",
                    serde_json::to_value(SessionReconcilePayload::default())?,
                )?;
                println!(
                    "examined={} unchanged={} upgraded={} closed={} truth_kind={}",
                    result.examined,
                    result.unchanged,
                    result.upgraded,
                    result.closed,
                    result.truth_kind
                );
                for entry in result.entries {
                    println!(
                        "session_id={} peer={} disposition={} path={} reason={}",
                        entry.session_id,
                        entry.peer_id,
                        entry.disposition,
                        entry.path_class,
                        entry.reason
                    );
                }
            }
        },
        Command::Path { command } => match command {
            PathCommand::Show { peer, class } => {
                let state = control.ensure_state()?;
                let class = parse_class(&class);
                let peer = resolve_peer(peer.as_deref(), &state)?;
                if let Some(snapshot) = render_path_snapshot(&state, &peer, class) {
                    println!("{}", snapshot);
                } else {
                    println!("no routing candidates available");
                }
            }
            PathCommand::Watch {
                peer,
                class,
                interval_ms,
                sample_limit,
            } => {
                let class = parse_class(&class);
                let interval = Duration::from_millis(interval_ms.max(1));
                let mut previous = None;
                for index in 0..sample_limit.max(1) {
                    let state = control.ensure_state()?;
                    let target = resolve_peer(peer.as_deref(), &state)?;
                    let snapshot =
                        render_path_snapshot(&state, &target, class).unwrap_or_else(|| {
                            format!(
                                "peer={} class={} no routing candidates available",
                                target,
                                class_label(class)
                            )
                        });
                    if previous.as_ref() != Some(&snapshot) {
                        println!("sample={} {}", index + 1, snapshot);
                        previous = Some(snapshot);
                    }
                    if index + 1 < sample_limit.max(1) {
                        tokio::time::sleep(interval).await;
                    }
                }
            }
        },
        Command::Connect {
            protocol,
            peer,
            class,
        } => {
            let state = control.ensure_state()?;
            let target = resolve_peer(peer.as_deref(), &state)?;
            let result = daemon_request::<SessionConnectResult>(
                &cli,
                "session.connect",
                serde_json::to_value(SessionConnectPayload {
                    peer_id: target.to_string(),
                    protocol,
                    class: Some(class),
                    path_preference: Some("direct_preferred".to_string()),
                })?,
            )?;
            println!(
                "session_id={} state={} path={} truth_kind={}",
                result.session.session_id,
                result.session.state,
                result.session.initial_path_class,
                result.truth_kind
            );
        }
        Command::SessionStatus => {
            let sessions = daemon_request::<RuntimeSessionsListResult>(
                &cli,
                "runtime.sessions.list",
                json!({}),
            )?;
            if sessions.sessions.is_empty() {
                println!("truth_kind={} sessions=0", sessions.truth_kind);
            } else {
                for session in sessions.sessions {
                    println!(
                        "session_id={} peer={} state={} path={} age_seconds={} last_activity_seconds={} truth_kind={}",
                        session.session_id,
                        session.peer_id,
                        session.state,
                        session.active_path_class,
                        session.age_seconds,
                        session.last_activity_seconds,
                        sessions.truth_kind
                    );
                }
            }
        }
        Command::SessionClose { session } => {
            let sessions = daemon_request::<RuntimeSessionsListResult>(
                &cli,
                "runtime.sessions.list",
                json!({}),
            )?;
            let session_id = resolve_daemon_session_id(session.as_deref(), &sessions.sessions)?;
            let result = daemon_request::<SessionCloseResult>(
                &cli,
                "session.close",
                serde_json::to_value(SessionClosePayload {
                    session_id,
                    reason: Some("operator_requested".to_string()),
                })?,
            )?;
            println!(
                "session_id={} final_state={} closure_reason={} truth_kind={}",
                result.closed_session_id,
                result.final_state,
                result.closure_reason.as_deref().unwrap_or("none"),
                result.truth_kind
            );
        }
        Command::SessionUpgrade { session } => {
            let sessions = daemon_request::<RuntimeSessionsListResult>(
                &cli,
                "runtime.sessions.list",
                json!({}),
            )?;
            let session_id = resolve_daemon_session_id(session.as_deref(), &sessions.sessions)?;
            let result = daemon_request::<SessionUpgradeResult>(
                &cli,
                "session.upgrade",
                serde_json::to_value(SessionUpgradePayload { session_id })?,
            )?;
            println!(
                "session_id={} prior_path={} resulting_path={} state={} truth_kind={}",
                result.session_id,
                result.prior_path_class,
                result.resulting_path_class,
                result.state,
                result.truth_kind
            );
        }
        Command::SessionReconcile => {
            let result = daemon_request::<SessionReconcileResult>(
                &cli,
                "session.reconcile",
                serde_json::to_value(SessionReconcilePayload::default())?,
            )?;
            println!(
                "examined={} unchanged={} upgraded={} closed={} truth_kind={}",
                result.examined,
                result.unchanged,
                result.upgraded,
                result.closed,
                result.truth_kind
            );
            for entry in result.entries {
                println!(
                    "session_id={} peer={} disposition={} path={} reason={}",
                    entry.session_id,
                    entry.peer_id,
                    entry.disposition,
                    entry.path_class,
                    entry.reason
                );
            }
        }
        Command::State { command } => match command {
            StateCommand::Validate => {
                let report = control.validate_state_file()?;
                println!(
                    "state_path={} schema_version={} valid=true",
                    report.state_path.display(),
                    report.schema_version
                );
            }
            StateCommand::Reset { confirm } => {
                if !confirm {
                    return Err(usage_error(
                        "state reset is destructive; rerun with --confirm to preserve identity and remove only durable network state",
                    )
                    .into());
                }
                let removed = control.reset_network_state()?;
                println!(
                    "state_path={} identity_preserved=true network_state_reset={} next_action=bootstrap_required",
                    cli.state_path,
                    removed
                );
            }
        },
        Command::Authority { command } => match command {
            AuthorityCommand::Show => {
                let state = control.ensure_state()?;
                println!(
                    "network={} local_peer={} membership_subject={} grants={} revocations={} denied={} bootstrap={} relays={} schema_version={} durable_only=true",
                    state.network,
                    state.local_peer_id,
                    state.membership.subject_peer_id,
                    state.capability_grants.len(),
                    state.revocations.len(),
                    state.denied_peers.len(),
                    state.bootstrap.len(),
                    state.relay_count(),
                    state.schema_version
                );
            }
            AuthorityCommand::Membership => {
                let state = control.ensure_state()?;
                println!(
                    "network={} subject_peer={} issuer_peer={} issued_at={} expires_at={} roles={} schema_version={} durable_only=true",
                    state.network,
                    state.membership.subject_peer_id,
                    state.membership.issuer_peer_id,
                    state.membership.issued_at,
                    state.membership.expires_at,
                    render_roles(&state.membership.roles),
                    state.schema_version
                );
            }
            AuthorityCommand::Capabilities => {
                let state = control.ensure_state()?;
                let grants = state.grants_for_peer(&state.local_peer_id);
                if grants.is_empty() {
                    println!(
                        "network={} subject_peer={} active_grants=0 schema_version={} durable_only=true",
                        state.network, state.local_peer_id, state.schema_version
                    );
                } else {
                    for grant in grants {
                        println!(
                            "network={} subject_peer={} issuer_peer={} sequence={} not_before={} expires_at={} capabilities={} protocols={} limits={} constraints={} schema_version={} durable_only=true",
                            state.network,
                            grant.subject_peer_id,
                            grant.issuer_peer_id,
                            grant.sequence,
                            grant.not_before,
                            grant.expires_at,
                            render_csv(&grant.capabilities),
                            render_protocols(&grant.protocol_scopes),
                            render_limits(&grant.resource_limits),
                            render_csv(&grant.constraints),
                            state.schema_version
                        );
                    }
                }
            }
            AuthorityCommand::Revocations => {
                let state = control.ensure_state()?;
                if state.revocations.is_empty() {
                    println!(
                        "network={} revocations=0 schema_version={} durable_only=true",
                        state.network, state.schema_version
                    );
                } else {
                    for revocation in &state.revocations {
                        println!(
                            "network={} sequence={} issuer_peer={} effective_at={} reason={} target={} note={} schema_version={} durable_only=true",
                            state.network,
                            revocation.sequence,
                            revocation.issuer_peer_id,
                            revocation.effective_at,
                            render_revocation_reason(&revocation.reason),
                            render_revocation_target(&revocation.target),
                            revocation.note.as_deref().unwrap_or("none"),
                            state.schema_version
                        );
                    }
                }
            }
            AuthorityCommand::SyncSnapshot { authority_snapshot } => {
                let (state, report) = control.sync_authority_snapshot(&authority_snapshot)?;
                println!(
                    "synced network={} local_peer={} grants_added={} revocations_added={} bootstrap_hints_added={} relay_announcements_added={} membership_changed={} state_path={} authority_source=snapshot",
                    state.network,
                    state.local_peer_id,
                    report.grants_added,
                    report.revocations_added,
                    report.bootstrap_hints_added,
                    report.relay_announcements_added,
                    report.membership_changed,
                    cli.state_path
                );
            }
            AuthorityCommand::SyncOrigin {
                authority_origin,
                authority_subject,
            } => {
                let (state, report) = control
                    .sync_authority_origin(&authority_origin, authority_subject.as_deref())?;
                println!(
                    "synced network={} local_peer={} grants_added={} revocations_added={} bootstrap_hints_added={} relay_announcements_added={} membership_changed={} state_path={} authority_origin={} authority_subject={}",
                    state.network,
                    state.local_peer_id,
                    report.grants_added,
                    report.revocations_added,
                    report.bootstrap_hints_added,
                    report.relay_announcements_added,
                    report.membership_changed,
                    cli.state_path,
                    authority_origin,
                    authority_subject.as_deref().unwrap_or("active")
                );
            }
            AuthorityCommand::SyncRevocationsOrigin { authority_origin } => {
                let (state, revocations_added) =
                    control.sync_authority_revocations_origin(&authority_origin)?;
                println!(
                    "synced-revocations network={} local_peer={} revocations_added={} denied={} state_path={} authority_origin={}",
                    state.network,
                    state.local_peer_id,
                    revocations_added,
                    state.denied_peers.len(),
                    cli.state_path,
                    authority_origin
                );
            }
        },
        Command::Identity { command } => match command {
            IdentityCommand::Show => {
                let identity = load_identity(&cli.identity_path, &cli.identity_passphrase_env)?;
                println!(
                    "identity_path={} peer={} public_key_hex={}",
                    cli.identity_path,
                    identity.peer_id(),
                    hex_public_key(&identity)
                );
            }
            IdentityCommand::Init { overwrite } => {
                let identity =
                    init_identity(&cli.identity_path, &cli.identity_passphrase_env, overwrite)?;
                println!(
                    "identity_path={} peer={} public_key_hex={}",
                    cli.identity_path,
                    identity.peer_id(),
                    hex_public_key(&identity)
                );
            }
        },
        Command::RelayStatus => {
            let state = control.ensure_state()?;
            if state.relay_announcements().is_empty() {
                println!("no relay announcements available");
            } else {
                for relay in state.relay_announcements() {
                    println!(
                        "peer={} region={} endpoints={:?} control_endpoint={} max_bandwidth_bps={} datagrams={} migration={} classes={}",
                        relay.peer_id,
                        relay.region,
                        relay.advertised_endpoints,
                        relay.control_endpoint,
                        relay.max_bandwidth_bps,
                        relay.supports_quic_datagrams,
                        relay.supports_path_migration,
                        relay.traffic_classes.join(",")
                    );
                }
            }
        }
    }
    Ok(())
}

fn class_label(class: TrafficClass) -> &'static str {
    match class {
        TrafficClass::Control => "control",
        TrafficClass::Interactive => "interactive",
        TrafficClass::Bulk => "bulk",
        TrafficClass::Background => "background",
    }
}

fn resolve_peer(peer: Option<&str>, state: &fabric::DaemonState) -> Result<PeerId, std::io::Error> {
    peer.and_then(|value| value.parse().ok())
        .or_else(|| state.first_peer().map(|entry| entry.snapshot.peer.clone()))
        .ok_or_else(|| {
            usage_error("a peer is required or daemon state must contain at least one peer")
        })
}

fn render_path_snapshot(
    state: &fabric::DaemonState,
    peer: &PeerId,
    class: TrafficClass,
) -> Option<String> {
    let decision = state.best_path(peer, class)?;
    let alternatives = render_path_alternatives(state, peer, class, &decision.selected);
    Some(format!(
        "peer={} class={} selected_path={:?} selected_source={:?} selected_score={} relay_peer={} summary=\"{}\" strengths=\"{}\" tradeoffs=\"{}\" alternatives=[{}]",
        peer,
        class_label(class),
        decision.selected.path_kind,
        decision.selected.source,
        decision.explanation.score.total,
        decision
            .selected
            .relay_peer
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "direct".to_string()),
        decision.explanation.summary,
        decision.explanation.strengths.join("; "),
        decision.explanation.tradeoffs.join("; "),
        alternatives.join(", ")
    ))
}

fn render_path_alternatives(
    state: &fabric::DaemonState,
    peer: &PeerId,
    class: TrafficClass,
    selected: &PathCandidate,
) -> Vec<String> {
    let mut candidates = state
        .path_candidates_for(peer)
        .into_iter()
        .filter(|candidate| candidate.traffic_classes.contains(&class))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| candidate.score(class));
    candidates
        .into_iter()
        .filter(|candidate| candidate != selected)
        .map(|candidate| {
            format!(
                "{:?}/score={}/source={:?}/relay={}",
                candidate.path_kind,
                candidate.score(class),
                candidate.source,
                candidate
                    .relay_peer
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "direct".to_string())
            )
        })
        .collect()
}

fn render_roles(roles: &[String]) -> String {
    render_csv(roles)
}

fn render_csv(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    }
}

fn render_protocols(protocols: &[ProtocolId]) -> String {
    if protocols.is_empty() {
        "none".to_string()
    } else {
        protocols
            .iter()
            .map(ProtocolId::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn render_limits(limits: &membership::ResourceLimits) -> String {
    format!(
        "bandwidth_bps:{}|concurrent_streams:{}|max_object_bytes:{}",
        limits
            .bandwidth_bps
            .map(|value: u64| value.to_string())
            .unwrap_or_else(|| "none".to_string()),
        limits
            .concurrent_streams
            .map(|value: u32| value.to_string())
            .unwrap_or_else(|| "none".to_string()),
        limits
            .max_object_bytes
            .map(|value: u64| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    )
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

fn resolve_daemon_session_id(
    session: Option<&str>,
    sessions: &[daemonapi::RuntimeSessionEntry],
) -> Result<String, std::io::Error> {
    if let Some(session) = session {
        if session.len() != 32 {
            return Err(usage_error(
                "session ids supplied to CLI must be 32 hex characters",
            ));
        }
        Ok(session.to_string())
    } else {
        sessions
            .first()
            .map(|entry| entry.session_id.clone())
            .ok_or_else(|| usage_error("a session id is required or an active session must exist"))
    }
}

#[cfg(test)]
fn parse_hex_session_id(value: &str) -> Result<[u8; 16], std::io::Error> {
    if value.len() != 32 {
        return Err(usage_error(
            "session ids supplied to CLI must be 32 hex characters",
        ));
    }
    let mut session_id = [0_u8; 16];
    for (index, slot) in session_id.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| usage_error("session ids supplied to CLI must be valid hex"))?;
    }
    Ok(session_id)
}

fn load_identity(
    identity_path: &str,
    passphrase_env: &str,
) -> Result<IdentityKeypair, Box<dyn Error>> {
    let passphrase = std::env::var(passphrase_env).map_err(|_| {
        usage_error(format!(
            "identity passphrase env var {passphrase_env} must be set"
        ))
    })?;
    FileKeystore::new(identity_path)
        .load(&passphrase)
        .map_err(Into::into)
}

fn init_identity(
    identity_path: &str,
    passphrase_env: &str,
    overwrite: bool,
) -> Result<IdentityKeypair, Box<dyn Error>> {
    if Path::new(identity_path).exists() && !overwrite {
        return Err(usage_error(
            "identity path already exists; rerun with --overwrite to replace it",
        )
        .into());
    }
    let passphrase = std::env::var(passphrase_env).map_err(|_| {
        usage_error(format!(
            "identity passphrase env var {passphrase_env} must be set"
        ))
    })?;
    if let Some(parent) = Path::new(identity_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let identity = IdentityKeypair::generate(&mut OsRng);
    FileKeystore::new(identity_path).store(&identity, &passphrase)?;
    Ok(identity)
}

fn usage_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

#[cfg(test)]
fn runtime_session_cli_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

fn normalize_cli_paths(cli: &mut Cli) {
    cli.state_path = expand_home_path(&cli.state_path);
    cli.identity_path = expand_home_path(&cli.identity_path);
    cli.control_discovery_path = expand_home_path(&cli.control_discovery_path);
}

fn expand_home_path(path: &str) -> String {
    if let Some(suffix) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{suffix}");
        }
    }
    path.to_string()
}

fn daemon_request<T>(
    cli: &Cli,
    operation: &str,
    payload: serde_json::Value,
) -> Result<T, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned,
{
    let discovery = load_daemon_discovery(&cli.control_discovery_path)?;
    let request = RequestEnvelope {
        request_id: format!("req-{}", std::process::id()),
        operation: operation.to_string(),
        auth: RequestAuth {
            kind: AuthKind::LocalProcess,
        },
        payload,
    };
    let response = match ureq::post(&discovery.endpoint)
        .set("Content-Type", "application/json")
        .send_json(serde_json::to_value(&request)?)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => {
            let envelope: ResponseEnvelope = response.into_json()?;
            let error = envelope
                .error
                .map(|error| format!("{:?}: {}", error.code, error.message))
                .unwrap_or_else(|| "daemon request failed".to_string());
            return Err(usage_error(error).into());
        }
        Err(error) => return Err(error.into()),
    };
    let envelope: ResponseEnvelope = response.into_json()?;
    if !envelope.ok {
        let error = envelope
            .error
            .map(|error| format!("{:?}: {}", error.code, error.message))
            .unwrap_or_else(|| "daemon request failed".to_string());
        return Err(usage_error(error).into());
    }
    Ok(serde_json::from_value(envelope.result.ok_or_else(
        || usage_error("daemon response did not include a result"),
    )?)?)
}

fn load_daemon_discovery(path: &str) -> Result<DaemonEndpointDiscovery, Box<dyn Error>> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn hex_public_key(identity: &IdentityKeypair) -> String {
    identity
        .public_key()
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn parse_class(value: &str) -> TrafficClass {
    match value {
        "control" => TrafficClass::Control,
        "bulk" => TrafficClass::Bulk,
        "background" => TrafficClass::Background,
        _ => TrafficClass::Interactive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_path_snapshot_includes_selected_and_alternatives() {
        let state = fabric::fixture_daemon_state("path-watch-cli");
        let peer = state
            .first_peer()
            .map(|entry| entry.snapshot.peer.clone())
            .expect("fixture peer should exist");

        let snapshot = render_path_snapshot(&state, &peer, TrafficClass::Interactive)
            .expect("snapshot should render");

        assert!(snapshot.contains("selected_path=DirectIpv6"));
        assert!(snapshot.contains("alternatives=[Relay/score="));
        assert!(snapshot.contains("strengths=\""));
    }

    #[test]
    fn render_path_alternatives_orders_candidates_by_score() {
        let state = fabric::fixture_daemon_state("path-watch-cli");
        let peer = state
            .first_peer()
            .map(|entry| entry.snapshot.peer.clone())
            .expect("fixture peer should exist");
        let selected = state
            .best_path(&peer, TrafficClass::Interactive)
            .expect("best path should exist")
            .selected;

        let alternatives =
            render_path_alternatives(&state, &peer, TrafficClass::Interactive, &selected);

        assert_eq!(alternatives.len(), 1);
        assert!(alternatives[0].starts_with("Relay/score="));
    }

    #[test]
    fn parse_hex_session_id_rejects_invalid_length() {
        let error = parse_hex_session_id("abcd").expect_err("invalid length should fail");

        assert!(error.to_string().contains("32 hex characters"));
    }

    #[test]
    fn resolve_peer_requires_existing_peer() {
        let mut state = fabric::fixture_daemon_state("empty-peers");
        state.peers.clear();

        let error = resolve_peer(None, &state).expect_err("missing peer should fail");

        assert!(error.to_string().contains("a peer is required"));
    }

    #[test]
    fn runtime_session_cli_error_mentions_daemon_runtime() {
        let error = runtime_session_cli_error(
            "session-close requires a daemon-owned runtime session registry",
        );

        assert!(error.to_string().contains("daemon-owned runtime"));
    }

    #[test]
    fn usage_error_mentions_confirmation_requirement() {
        let error = usage_error(
            "state reset is destructive; rerun with --confirm to preserve identity and remove only durable network state",
        );

        assert!(error.to_string().contains("--confirm"));
    }

    #[test]
    fn authority_show_output_is_durable_not_runtime() {
        let state = fabric::fixture_daemon_state("authority-show-cli");
        let output = format!(
            "network={} local_peer={} membership_subject={} grants={} revocations={} denied={} bootstrap={} relays={} schema_version={} durable_only=true",
            state.network,
            state.local_peer_id,
            state.membership.subject_peer_id,
            state.capability_grants.len(),
            state.revocations.len(),
            state.denied_peers.len(),
            state.bootstrap.len(),
            state.relay_count(),
            state.schema_version
        );

        assert!(output.contains("durable_only=true"));
        assert!(output.contains("schema_version="));
    }

    #[test]
    fn render_protocols_and_csv_use_none_for_empty_values() {
        assert_eq!(render_csv(&[]), "none");
        assert_eq!(render_protocols(&[]), "none");
    }

    #[test]
    fn render_limits_outputs_stable_operator_surface() {
        let limits = membership::ResourceLimits {
            bandwidth_bps: Some(1_000),
            concurrent_streams: None,
            max_object_bytes: Some(4_096),
        };

        assert_eq!(
            render_limits(&limits),
            "bandwidth_bps:1000|concurrent_streams:none|max_object_bytes:4096"
        );
    }

    #[test]
    fn render_revocation_target_formats_peer_and_grant_targets() {
        let peer = fabric::fixture_daemon_state("revocation-format-cli").local_peer_id;
        let peer_target = membership::RevocationTarget::Peer {
            peer_id: peer.clone(),
        };
        let grant_target = membership::RevocationTarget::CapabilityGrant {
            subject_peer_id: peer.clone(),
            sequence: 7,
        };

        assert_eq!(
            render_revocation_target(&peer_target),
            format!("peer:{peer}")
        );
        assert_eq!(
            render_revocation_target(&grant_target),
            format!("capability_grant:{peer}:7")
        );
    }

    #[test]
    fn expand_home_path_uses_home_environment() {
        let original = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", "/tmp/quip-home");
        }

        let expanded = expand_home_path("~/.quip/net/state.json");

        match original {
            Some(home) => unsafe { std::env::set_var("HOME", home) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        assert_eq!(expanded, "/tmp/quip-home/.quip/net/state.json");
    }
}
