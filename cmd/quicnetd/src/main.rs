use clap::Parser;
use crypto::IdentityKeypair;
use fabric::{DaemonConfig, LocalControlPlane, ProtocolId, TrafficClass};
use identity::{FileKeystore, IdentityKeystore};
use quic::QuicTransportAdapter;

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
    reconcile: bool,

    #[arg(long, default_value_t = false)]
    reconcile_verbose: bool,

    #[arg(long)]
    connect_protocol: Option<String>,

    #[arg(long)]
    connect_peer: Option<String>,

    #[arg(long, default_value = "interactive")]
    connect_class: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    observability::init_tracing("quicnetd");
    let args = Args::parse();
    let control = LocalControlPlane::new(DaemonConfig::new(
        args.network.clone(),
        args.state_path.clone(),
    ));
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
    }
    .expect("daemon state should persist");
    let state = if args.revocation_sync {
        if let Some(origin) = args.authority_origin.as_deref() {
            control
                .sync_authority_revocations_origin(origin)
                .map(|(state, _)| state)
                .expect("revocation sync should persist")
        } else {
            state
        }
    } else {
        state
    };
    let reconcile_report = if args.reconcile {
        let report = match control.reconcile_report().await {
            Ok(report) => report,
            Err(error) => {
                eprintln!("reconcile failed: {error}");
                std::process::exit(1);
            }
        };
        if args.reconcile_verbose {
            println!("{}", report.detail_line());
        }
        Some(report)
    } else {
        None
    };
    let active_session = if let Some(protocol) = args.connect_protocol.as_deref() {
        let target = args
            .connect_peer
            .as_deref()
            .and_then(|value| value.parse().ok())
            .or_else(|| state.first_peer().map(|peer| peer.snapshot.peer.clone()))
            .expect("a peer is required or must exist in state");
        let protocol = ProtocolId::new(protocol).expect("connect protocol must be valid");
        let transport = QuicTransportAdapter::with_identity(
            fabric::NetworkId::derive(&args.network),
            load_identity(&args.identity_path, &args.identity_passphrase_env),
        );
        Some(
            match control
                .realize_best_path(&target, &protocol, parse_class(&args.connect_class), &transport)
                .await
            {
                Ok(session) => session,
                Err(error) => {
                    eprintln!("connect failed: {error}");
                    std::process::exit(1);
                }
            },
        )
    } else {
        None
    };
    let selected_path = state
        .first_peer()
        .and_then(|peer| state.best_path(&peer.snapshot.peer, TrafficClass::Interactive))
        .map(|decision| decision.explanation.summary)
        .unwrap_or_else(|| "no routing candidates".to_string());
    println!(
        "quicnetd active: {} selected_path={} active_session={} reconcile={} state_path={}",
        state.status_line(),
        selected_path,
        active_session
            .as_ref()
            .map(|session| format!("{}@{}", hex_session_id(&session.session_id), session.peer))
            .unwrap_or_else(|| "none".to_string()),
        reconcile_report
            .as_ref()
            .map(|report| report.summary_line())
            .unwrap_or_else(|| "disabled".to_string()),
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

fn hex_session_id(session_id: &[u8; 16]) -> String {
    session_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn load_identity(identity_path: &str, passphrase_env: &str) -> IdentityKeypair {
    let passphrase = std::env::var(passphrase_env)
        .unwrap_or_else(|_| panic!("identity passphrase env var {passphrase_env} must be set"));
    FileKeystore::new(identity_path)
        .load(&passphrase)
        .expect("identity keystore should load")
}

struct SessionReconcileReport {
    examined_sessions: usize,
    closed_sessions: usize,
    upgraded_sessions: usize,
    unchanged_sessions: usize,
}

impl SessionReconcileReport {
    fn summary_line(&self) -> String {
        format!(
            "examined={} upgraded={} closed={} unchanged={}",
            self.examined_sessions,
            self.upgraded_sessions,
            self.closed_sessions,
            self.unchanged_sessions
        )
    }

    fn detail_line(&self) -> String {
        format!("quicnetd reconcile: {}", self.summary_line())
    }
}

trait LocalControlPlaneReconcileExt {
    async fn reconcile_report(&self) -> Result<SessionReconcileReport, String>;
}

impl LocalControlPlaneReconcileExt for LocalControlPlane {
    async fn reconcile_report(&self) -> Result<SessionReconcileReport, String> {
        let state = self
            .refresh_and_persist()
            .map_err(|error| error.to_string())?;
        let examined_sessions = state.active_sessions().len();
        Ok(SessionReconcileReport {
            examined_sessions,
            closed_sessions: 0,
            upgraded_sessions: 0,
            unchanged_sessions: examined_sessions,
        })
    }
}
