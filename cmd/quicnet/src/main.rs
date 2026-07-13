use clap::{Parser, Subcommand};
use crypto::IdentityKeypair;
use fabric::{DaemonConfig, LocalControlPlane, ProtocolId, TrafficClass};
use identity::{FileKeystore, IdentityKeystore};
use quic::QuicTransportAdapter;
use rand::rngs::OsRng;
use std::path::Path;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,

    #[arg(long, default_value = "./var/quicnetd/state.json")]
    state_path: String,

    #[arg(long, default_value = "./var/quicnetd/identity.json")]
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
        #[arg(long, default_value = "interactive")]
        class: String,
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    observability::init_tracing("quicnet");
    let cli = Cli::parse();
    let control = LocalControlPlane::new(DaemonConfig::new(
        cli.network.clone(),
        cli.state_path.clone(),
    ));
    match cli.command.unwrap_or(Command::Status) {
        Command::IdentityInit { overwrite } => {
            let identity =
                init_identity(&cli.identity_path, &cli.identity_passphrase_env, overwrite);
            println!(
                "identity_path={} peer={} public_key_hex={}",
                cli.identity_path,
                identity.peer_id(),
                hex_public_key(&identity)
            );
        }
        Command::Join { authority_snapshot } => {
            let state = control
                .seed_from_authority_snapshot(&authority_snapshot)
                .expect("authority snapshot should seed daemon state");
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
                .seed_from_authority_origin(&authority_origin, authority_subject.as_deref())
                .expect("authority origin should seed daemon state");
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
            let (state, report) = control
                .sync_authority_snapshot(&authority_snapshot)
                .expect("authority snapshot should sync daemon state");
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
            let (state, report) = control
                .sync_authority_origin(&authority_origin, authority_subject.as_deref())
                .expect("authority origin should sync daemon state");
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
            let (state, revocations_added) = control
                .sync_authority_revocations_origin(&authority_origin)
                .expect("authority revocation origin should sync daemon state");
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
            let state = control
                .ensure_state()
                .expect("daemon state should be readable or creatable");
            println!("{}", state.status_line());
        }
        Command::Peers => {
            let state = control
                .ensure_state()
                .expect("daemon state should be readable or creatable");
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
            let state = control
                .ensure_state()
                .expect("daemon state should be readable or creatable");
            let target = peer
                .and_then(|value| value.parse().ok())
                .or_else(|| state.first_peer().map(|entry| entry.snapshot.peer.clone()))
                .expect("a peer is required or must exist in state");
            let (inspection, best_path) = control.inspect_peer(&target).expect("peer inspection");
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
            let state = control
                .ensure_state()
                .expect("daemon state should be readable or creatable");
            let target = peer
                .and_then(|value| value.parse().ok())
                .or_else(|| state.first_peer().map(|entry| entry.snapshot.peer.clone()))
                .expect("a peer is required or must exist in state");
            let protocol =
                ProtocolId::new(protocol).expect("protocol ids supplied to CLI must be valid");
            let decision = control
                .explain_policy(&target, &protocol)
                .expect("policy explanation should succeed");
            println!(
                "peer={} protocol={} allowed={} reason={}",
                target, protocol, decision.allowed, decision.reason
            );
        }
        Command::Netcheck => {
            let state = control
                .ensure_state()
                .expect("daemon state should be readable or creatable");
            println!("{}", state.netcheck.summary());
            for warning in state.netcheck.warnings() {
                println!("warning: {}", warning);
            }
        }
        Command::Path { class } => {
            let state = control
                .ensure_state()
                .expect("daemon state should be readable or creatable");
            let class = parse_class(&class);
            let peer = state
                .first_peer()
                .map(|entry| entry.snapshot.peer.clone())
                .expect("a peer should exist in daemon state");
            if let Some(decision) = state.best_path(&peer, class) {
                println!("{}", decision.explanation.summary);
            } else {
                println!("no routing candidates available");
            }
        }
        Command::Connect {
            protocol,
            peer,
            class,
        } => {
            let state = control
                .ensure_state()
                .expect("daemon state should be readable or creatable");
            let target = peer
                .and_then(|value| value.parse().ok())
                .or_else(|| state.first_peer().map(|entry| entry.snapshot.peer.clone()))
                .expect("a peer is required or must exist in state");
            let protocol =
                ProtocolId::new(protocol).expect("protocol ids supplied to CLI must be valid");
            let class = parse_class(&class);
            let transport = QuicTransportAdapter::with_identity(
                fabric::NetworkId::derive(&cli.network),
                load_identity(&cli.identity_path, &cli.identity_passphrase_env),
            );
            let session = match control
                .realize_best_path(&target, &protocol, class, &transport)
                .await
            {
                Ok(session) => session,
                Err(error) => {
                    eprintln!("connect failed: {error}");
                    std::process::exit(1);
                }
            };
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
            let sessions = control
                .session_snapshots()
                .expect("daemon state should be readable or creatable");
            if sessions.is_empty() {
                println!("no active sessions");
            } else {
                for session in sessions {
                    println!(
                        "session_id={} transport_session_id={} relay_attempt_id={} peer={} protocol={} class={} path={:?} relay_peer={} remote_endpoint={} relay_endpoint={} datagrams={} migration={}",
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
                        session.migration_capable
                    );
                }
            }
        }
        Command::SessionClose { session } => {
            let sessions = control
                .session_snapshots()
                .expect("daemon state should be readable or creatable");
            let session_id = resolve_session_id(session.as_deref(), &sessions);
            let transport = QuicTransportAdapter::default();
            control
                .close_session(&session_id, &transport)
                .await
                .unwrap_or_else(|error| {
                    eprintln!("session-close failed: {error}");
                    std::process::exit(1);
                });
            println!("closed session_id={}", hex_session_id(&session_id));
        }
        Command::SessionUpgrade { session } => {
            let sessions = control
                .session_snapshots()
                .expect("daemon state should be readable or creatable");
            let session_id = resolve_session_id(session.as_deref(), &sessions);
            let transport = QuicTransportAdapter::with_identity(
                fabric::NetworkId::derive(&cli.network),
                load_identity(&cli.identity_path, &cli.identity_passphrase_env),
            );
            let session = control
                .upgrade_session(&session_id, &transport)
                .await
                .unwrap_or_else(|error| {
                    eprintln!("session-upgrade failed: {error}");
                    std::process::exit(1);
                });
            println!(
                "session_id={} transport_session_id={} relay_attempt_id={} peer={} protocol={} class={} path={:?} relay_peer={} remote_endpoint={} relay_endpoint={} datagrams={} migration={}",
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
                session.migration_capable
            );
        }
        Command::SessionReconcile => {
            let transport = QuicTransportAdapter::with_identity(
                fabric::NetworkId::derive(&cli.network),
                load_identity(&cli.identity_path, &cli.identity_passphrase_env),
            );
            let report = control
                .reconcile_sessions(&transport)
                .await
                .unwrap_or_else(|error| {
                    eprintln!("session-reconcile failed: {error}");
                    std::process::exit(1);
                });
            println!(
                "examined={} unchanged={} upgraded={} closed={}",
                report.examined, report.unchanged, report.upgraded, report.closed
            );
            for entry in report.entries {
                println!(
                    "session_id={} peer={} disposition={} path={} reason={}",
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
        Command::RelayStatus => {
            let state = control
                .ensure_state()
                .expect("daemon state should be readable or creatable");
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
}

fn class_label(class: TrafficClass) -> &'static str {
    match class {
        TrafficClass::Control => "control",
        TrafficClass::Interactive => "interactive",
        TrafficClass::Bulk => "bulk",
        TrafficClass::Background => "background",
    }
}

fn reconcile_disposition_label(disposition: &fabric::SessionReconcileDisposition) -> &'static str {
    match disposition {
        fabric::SessionReconcileDisposition::Unchanged => "unchanged",
        fabric::SessionReconcileDisposition::Upgraded => "upgraded",
        fabric::SessionReconcileDisposition::Closed => "closed",
    }
}

fn hex_session_id(session_id: &[u8; 16]) -> String {
    session_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn resolve_session_id(session: Option<&str>, sessions: &[fabric::SessionSnapshot]) -> [u8; 16] {
    session
        .map(parse_hex_session_id)
        .or_else(|| sessions.first().map(|entry| entry.session_id))
        .expect("a session id is required or an active session must exist")
}

fn parse_hex_session_id(value: &str) -> [u8; 16] {
    assert_eq!(
        value.len(),
        32,
        "session ids supplied to CLI must be 32 hex characters"
    );
    let mut session_id = [0_u8; 16];
    for (index, slot) in session_id.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .expect("session ids supplied to CLI must be valid hex");
    }
    session_id
}

fn load_identity(identity_path: &str, passphrase_env: &str) -> IdentityKeypair {
    let passphrase = std::env::var(passphrase_env)
        .unwrap_or_else(|_| panic!("identity passphrase env var {passphrase_env} must be set"));
    FileKeystore::new(identity_path)
        .load(&passphrase)
        .expect("identity keystore should load")
}

fn init_identity(identity_path: &str, passphrase_env: &str, overwrite: bool) -> IdentityKeypair {
    if Path::new(identity_path).exists() && !overwrite {
        panic!("identity path already exists; rerun with --overwrite to replace it");
    }
    let passphrase = std::env::var(passphrase_env)
        .unwrap_or_else(|_| panic!("identity passphrase env var {passphrase_env} must be set"));
    if let Some(parent) = Path::new(identity_path).parent() {
        std::fs::create_dir_all(parent).expect("identity directory should be creatable");
    }
    let identity = IdentityKeypair::generate(&mut OsRng);
    FileKeystore::new(identity_path)
        .store(&identity, &passphrase)
        .expect("identity keystore should store");
    identity
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
