use clap::{Parser, Subcommand};
use crypto::IdentityKeypair;
use fabric::PathCandidate;
use fabric::{DaemonConfig, LocalControlPlane, PeerId, ProtocolId, TrafficClass};
use identity::{FileKeystore, IdentityKeystore};
use quic::QuicTransportAdapter;
use rand::rngs::OsRng;
use std::error::Error;
use std::path::Path;
use std::time::Duration;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,

    #[arg(long, default_value = "~/.quip/quicnet/state.json")]
    state_path: String,

    #[arg(long, default_value = "~/.quip/quicnet/identity.json")]
    identity_path: String,

    #[arg(long, default_value = "QUICNET_IDENTITY_PASSPHRASE")]
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
    Sync {
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
    IdentityInit {
        #[arg(long, default_value_t = false)]
        overwrite: bool,
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    observability::init_tracing("quicnet");
    let mut cli = Cli::parse();
    normalize_cli_paths(&mut cli);
    let control = LocalControlPlane::new(DaemonConfig::new(
        cli.network.clone(),
        cli.state_path.clone(),
    ));
    match cli.command.unwrap_or(Command::Status) {
        Command::IdentityInit { overwrite } => {
            let identity = init_identity(&cli.identity_path, &cli.identity_passphrase_env, overwrite)?;
            println!(
                "identity_path={} peer={} public_key_hex={}",
                cli.identity_path,
                identity.peer_id(),
                hex_public_key(&identity)
            );
        }
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
            let state =
                control.seed_from_authority_origin(&authority_origin, authority_subject.as_deref())?;
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
        Command::Sync { authority_snapshot } => {
            let (state, report) = control.sync_authority_snapshot(&authority_snapshot)?;
            println!(
                "synced network={} local_peer={} grants_added={} revocations_added={} bootstrap_hints_added={} relay_announcements_added={} membership_changed={} state_path={}",
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
        Command::SyncOrigin {
            authority_origin,
            authority_subject,
        } => {
            let (state, report) =
                control.sync_authority_origin(&authority_origin, authority_subject.as_deref())?;
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
        Command::SyncRevocationsOrigin { authority_origin } => {
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
        Command::Status => {
            let state = control.ensure_state()?;
            println!("{}", state.status_line());
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
            let identity = load_identity(&cli.identity_path, &cli.identity_passphrase_env)?;
            let state = control.ensure_identity_bound_state(&identity)?;
            let target = resolve_peer(peer.as_deref(), &state)?;
            let protocol =
                ProtocolId::new(protocol).map_err(|error| usage_error(error.to_string()))?;
            let class = parse_class(&class);
            let transport = QuicTransportAdapter::with_identity(
                fabric::NetworkId::derive(&cli.network),
                identity,
            );
            let session = control
                .realize_best_path(&target, &protocol, class, &transport)
                .await?;
            println!(
                "session_id={} relay_attempt_id={} peer={} protocol={} class={} path={:?} relay_peer={} remote_endpoint={} relay_endpoint={}",
                hex_session_id(&session.session_id),
                session
                    .relay_attempt_id
                    .as_ref()
                    .map(hex_session_id)
                    .unwrap_or_else(|| "none".to_string()),
                session.peer,
                session
                    .protocol
                    .as_ref()
                    .map(ProtocolId::as_str)
                    .unwrap_or("none"),
                class_label(session.class),
                session.path_kind,
                session
                    .relay_peer
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "direct".to_string()),
                session.remote_endpoint,
                session.relay_endpoint.unwrap_or_else(|| "none".to_string())
            );
        }
        Command::SessionStatus => {
            let sessions = control.session_snapshots()?;
            if sessions.is_empty() {
                println!("no cached sessions");
            } else {
                for session in sessions {
                    println!(
                        "session_id={} transport_session_id={} relay_attempt_id={} peer={} protocol={} class={} path={:?} relay_peer={} remote_endpoint={} relay_endpoint={} datagrams={} migration={} cached=true",
                        hex_session_id(&session.session_id),
                        hex_session_id(&session.transport_session_id),
                        session
                            .relay_attempt_id
                            .as_ref()
                            .map(hex_session_id)
                            .unwrap_or_else(|| "none".to_string()),
                        session.peer,
                        session
                            .protocol
                            .as_ref()
                            .map(ProtocolId::as_str)
                            .unwrap_or("none"),
                        class_label(session.class),
                        session.path_kind,
                        session
                            .relay_peer
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "direct".to_string()),
                        session.remote_endpoint,
                        session.relay_endpoint.unwrap_or_else(|| "none".to_string()),
                        session.datagrams_capable,
                        session.migration_capable,
                    );
                }
            }
        }
        Command::SessionClose { session } => {
            let sessions = control.session_snapshots()?;
            let session_id = resolve_session_id(session.as_deref(), &sessions)?;
            return Err(runtime_session_cli_error(format!(
                "session-close requires a daemon-owned runtime session registry; cached session {} cannot be closed from a standalone quicnet process",
                hex_session_id(&session_id)
            ))
            .into());
        }
        Command::SessionUpgrade { session } => {
            let sessions = control.session_snapshots()?;
            let session_id = resolve_session_id(session.as_deref(), &sessions)?;
            return Err(runtime_session_cli_error(format!(
                "session-upgrade requires a daemon-owned runtime session registry; cached session {} cannot be upgraded from a standalone quicnet process",
                hex_session_id(&session_id)
            ))
            .into());
        }
        Command::SessionReconcile => {
            return Err(runtime_session_cli_error(
                "session-reconcile requires a daemon-owned runtime session registry and cannot run from a standalone quicnet process",
            )
            .into());
        }
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
        .ok_or_else(|| usage_error("a peer is required or daemon state must contain at least one peer"))
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

fn hex_session_id(session_id: &[u8; 16]) -> String {
    session_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn resolve_session_id(
    session: Option<&str>,
    sessions: &[fabric::SessionSnapshot],
) -> Result<[u8; 16], std::io::Error> {
    if let Some(session) = session {
        parse_hex_session_id(session)
    } else {
        sessions
            .first()
            .map(|entry| entry.session_id)
            .ok_or_else(|| usage_error("a session id is required or an active session must exist"))
    }
}

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

fn load_identity(identity_path: &str, passphrase_env: &str) -> Result<IdentityKeypair, Box<dyn Error>> {
    let passphrase = std::env::var(passphrase_env)
        .map_err(|_| usage_error(format!("identity passphrase env var {passphrase_env} must be set")))?;
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
    let passphrase = std::env::var(passphrase_env)
        .map_err(|_| usage_error(format!("identity passphrase env var {passphrase_env} must be set")))?;
    if let Some(parent) = Path::new(identity_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let identity = IdentityKeypair::generate(&mut OsRng);
    FileKeystore::new(identity_path)
        .store(&identity, &passphrase)
        ?;
    Ok(identity)
}

fn usage_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

fn runtime_session_cli_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

fn normalize_cli_paths(cli: &mut Cli) {
    cli.state_path = expand_home_path(&cli.state_path);
    cli.identity_path = expand_home_path(&cli.identity_path);
}

fn expand_home_path(path: &str) -> String {
    if let Some(suffix) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{suffix}");
        }
    }
    path.to_string()
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

        assert!(error
            .to_string()
            .contains("32 hex characters"));
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
    fn expand_home_path_uses_home_environment() {
        let original = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", "/tmp/quip-home");
        }

        let expanded = expand_home_path("~/.quip/quicnet/state.json");

        match original {
            Some(home) => unsafe { std::env::set_var("HOME", home) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        assert_eq!(expanded, "/tmp/quip-home/.quip/quicnet/state.json");
    }
}
