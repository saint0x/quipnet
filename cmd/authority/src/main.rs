use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use control::AuthorityArtifactSnapshot;
use crypto::{hash_bytes, IdentityKeypair};
use membership::{
    BootstrapHint, CapabilityGrant, EnrollmentToken, MembershipCertificate, ResourceLimits,
    RevocationReason, RevocationRecord, RevocationTarget,
};
use model::{NetworkId, PeerId, ProtocolId};
use relaywire::{RelayAnnouncement, RelayMap};
use serde::Serialize;
use tiny_http::{Header, Method, Response, Server, StatusCode};

#[derive(Parser, Debug)]
#[command(name = "authority")]
#[command(about = "Issue and inspect Quipnet membership artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init(InitArgs),
    AddMember(AddMemberArgs),
    AddBootstrap(AddBootstrapArgs),
    AddRelay(AddRelayArgs),
    Serve(ServeArgs),
    Issue(IssueArgs),
    Fixtures(FixturesArgs),
}

#[derive(Args, Debug)]
struct InitArgs {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,
    #[arg(long, default_value = "default")]
    realm: String,
    #[arg(long, default_value = "./var/authority/state.json")]
    state_path: String,
    #[arg(long = "bootstrap-address", num_args = 0.., value_delimiter = ',')]
    bootstrap_addresses: Vec<String>,
}

#[derive(Args, Debug)]
struct AddBootstrapArgs {
    #[arg(long, default_value = "./var/authority/state.json")]
    state_path: String,
    #[arg(long)]
    address: String,
    #[arg(long)]
    peer_id: Option<String>,
    #[arg(long = "protocol", num_args = 0.., value_delimiter = ',')]
    protocols: Vec<String>,
    #[arg(long, default_value = "authority-cli")]
    source: String,
    #[arg(long)]
    priority: Option<u32>,
}

#[derive(Args, Debug)]
struct AddRelayArgs {
    #[arg(long, default_value = "./var/authority/state.json")]
    state_path: String,
    #[arg(long)]
    peer_id: Option<String>,
    #[arg(long)]
    peer_seed: Option<String>,
    #[arg(long)]
    region: String,
    #[arg(long = "address", num_args = 1.., value_delimiter = ',')]
    addresses: Vec<String>,
    #[arg(long)]
    control_endpoint: String,
    #[arg(long, default_value_t = 5_000_000_000)]
    max_bandwidth_bps: u64,
    #[arg(long, default_value_t = true)]
    supports_quic_datagrams: bool,
    #[arg(long, default_value_t = true)]
    supports_path_migration: bool,
    #[arg(long = "traffic-class", num_args = 0.., value_delimiter = ',')]
    traffic_classes: Vec<String>,
}

#[derive(Args, Debug)]
struct AddMemberArgs {
    #[arg(long, default_value = "./var/authority/state.json")]
    state_path: String,
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,
    #[arg(long, default_value = "default")]
    realm: String,
    #[arg(long)]
    subject_seed: Option<String>,
    #[arg(long)]
    subject_peer_id: Option<String>,
    #[arg(long = "role", num_args = 0.., value_delimiter = ',')]
    roles: Vec<String>,
    #[arg(long, default_value_t = 86_400)]
    ttl_secs: u64,
    #[arg(long, default_value_t = false)]
    active: bool,
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,
    #[arg(long, default_value = "default")]
    realm: String,
    #[arg(long, default_value = "127.0.0.1:9080")]
    bind: String,
    #[arg(long, default_value = "./var/authority/state.json")]
    state_path: String,
}

#[derive(Args, Debug)]
struct IssueArgs {
    #[arg(long)]
    state_path: Option<String>,
    #[command(subcommand)]
    artifact: ArtifactCommand,
}

#[derive(Subcommand, Debug)]
enum ArtifactCommand {
    EnrollmentToken(EnrollmentTokenArgs),
    Membership(MembershipArgs),
    Capability(CapabilityArgs),
    Revocation(RevocationArgs),
}

#[derive(Args, Debug)]
struct EnrollmentTokenArgs {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,
    #[arg(long, default_value = "default")]
    realm: String,
    #[arg(long)]
    subject: Option<String>,
    #[arg(long = "role", num_args = 0.., value_delimiter = ',')]
    roles: Vec<String>,
    #[arg(long = "bootstrap-address", num_args = 0.., value_delimiter = ',')]
    bootstrap_addresses: Vec<String>,
    #[arg(long, default_value_t = 3_600)]
    ttl_secs: u64,
}

#[derive(Args, Debug)]
struct MembershipArgs {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,
    #[arg(long, default_value = "default")]
    realm: String,
    #[arg(long)]
    subject_seed: Option<String>,
    #[arg(long)]
    subject_peer_id: Option<String>,
    #[arg(long = "role", num_args = 0.., value_delimiter = ',')]
    roles: Vec<String>,
    #[arg(long, default_value_t = 86_400)]
    ttl_secs: u64,
    #[arg(long, default_value_t = false)]
    active: bool,
}

#[derive(Args, Debug)]
struct CapabilityArgs {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,
    #[arg(long, default_value = "default")]
    realm: String,
    #[arg(long)]
    subject_seed: Option<String>,
    #[arg(long)]
    subject_peer_id: Option<String>,
    #[arg(long = "capability", num_args = 1.., value_delimiter = ',')]
    capabilities: Vec<String>,
    #[arg(long = "protocol", num_args = 1.., value_delimiter = ',')]
    protocols: Vec<String>,
    #[arg(long = "constraint", num_args = 0.., value_delimiter = ',')]
    constraints: Vec<String>,
    #[arg(long, default_value_t = 43_200)]
    ttl_secs: u64,
}

#[derive(Args, Debug)]
struct RevocationArgs {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,
    #[arg(long, default_value = "default")]
    realm: String,
    #[arg(long)]
    peer_id: String,
    #[arg(long, default_value = "administrative")]
    reason: String,
    #[arg(long)]
    note: Option<String>,
}

#[derive(Args, Debug)]
struct FixturesArgs {
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,
    #[arg(long, default_value = "default")]
    realm: String,
}

#[derive(Debug, Clone, Serialize)]
struct FixtureArtifacts {
    network_id: NetworkId,
    authority_peer_id: String,
    subject_peer_id: String,
    enrollment_token: EnrollmentToken,
    membership: MembershipCertificate,
    capability_grants: Vec<CapabilityGrant>,
    revocations: Vec<RevocationRecord>,
    bootstrap_hints: Vec<BootstrapHint>,
}

fn main() {
    observability::init_tracing("authority");
    let cli = Cli::parse();

    match cli.command {
        Command::Init(args) => init(args),
        Command::AddMember(args) => add_member(args),
        Command::AddBootstrap(args) => add_bootstrap(args),
        Command::AddRelay(args) => add_relay(args),
        Command::Serve(args) => serve(args),
        Command::Issue(args) => issue(args),
        Command::Fixtures(args) => print_json(&fixture_artifacts(&args.network, &args.realm)),
    }
}

fn init(args: InitArgs) {
    let state = initial_state(&args.network, &args.realm, args.bootstrap_addresses);
    save_state(&args.state_path, &state);
    print_json(&state);
}

fn add_member(args: AddMemberArgs) {
    let authority = seeded_keypair(&format!("authority:{}", args.realm));
    let (subject_label, subject_peer_id) =
        resolve_subject(args.subject_seed.as_deref(), args.subject_peer_id.as_deref());
    let issued_at = current_unix_secs();
    let membership = MembershipCertificate::issue(
        &authority,
        network_id(&args.network),
        subject_peer_id.clone(),
        issued_at,
        issued_at + args.ttl_secs,
        normalize_roles(args.roles),
    );
    let mut state = load_state(&args.state_path);
    upsert_member(
        &mut state.members,
        AuthorityMember {
            subject_seed: subject_label.clone(),
            peer_id: subject_peer_id.to_text(),
            membership: membership.clone(),
        },
    );
    if args.active || state.active_subject_seed.is_none() {
        state.active_subject_seed = Some(subject_label);
    }
    materialize_state(&mut state);
    save_state(&args.state_path, &state);
    print_json(&membership);
}

fn add_bootstrap(args: AddBootstrapArgs) {
    let mut state = load_state(&args.state_path);
    let mut metadata = BTreeMap::from([("source".to_string(), args.source)]);
    if let Some(priority) = args.priority {
        metadata.insert("priority".to_string(), priority.to_string());
    }
    if !args.protocols.is_empty() {
        metadata.insert("protocols".to_string(), args.protocols.join(","));
    }
    let hint = BootstrapHint {
        peer_id: args
            .peer_id
            .map(|peer| peer.parse().expect("peer id should be valid")),
        addresses: vec![args.address],
        metadata,
    };
    upsert_bootstrap_hint(&mut state.bootstrap_hints, hint);
    state.bootstrap_generation += 1;
    materialize_state(&mut state);
    save_state(&args.state_path, &state);
    print_json(&state.bootstrap_hints);
}

fn add_relay(args: AddRelayArgs) {
    let mut state = load_state(&args.state_path);
    let peer_id = args
        .peer_id
        .map(|peer_id| {
            peer_id
                .parse()
                .expect("relay peer ids supplied to CLI must be valid")
        })
        .or_else(|| {
            args.peer_seed.as_deref().map(|seed| {
                IdentityKeypair::from_secret_bytes(hash_bytes(seed.as_bytes())).peer_id()
            })
        })
        .expect("either --peer-id or --peer-seed must be supplied");
    let relay = RelayAnnouncement {
        peer_id,
        region: args.region,
        advertised_endpoints: args.addresses,
        control_endpoint: args.control_endpoint,
        max_bandwidth_bps: args.max_bandwidth_bps,
        supports_quic_datagrams: args.supports_quic_datagrams,
        supports_path_migration: args.supports_path_migration,
        traffic_classes: if args.traffic_classes.is_empty() {
            vec![
                "NetworkControl".to_string(),
                "InteractiveRpc".to_string(),
                "Background".to_string(),
            ]
        } else {
            args.traffic_classes
        },
    };
    upsert_relay(&mut state.relays, relay);
    state.relay_map_version += 1;
    materialize_state(&mut state);
    save_state(&args.state_path, &state);
    print_json(&state.relays);
}

fn serve(args: ServeArgs) {
    let state = load_or_init_state(&args.state_path, &args.network, &args.realm);
    let server = Server::http(&args.bind).expect("authority server should bind");
    println!(
        "authority serving realm {} on network {} at http://{} state_path={}",
        args.realm, state.snapshot.network_id, args.bind, args.state_path
    );

    for request in server.incoming_requests() {
        let state = load_or_init_state(&args.state_path, &args.network, &args.realm);
        let response = route_request(&state, request.method(), request.url());
        request
            .respond(response)
            .expect("authority server should write response");
    }
}

fn issue(args: IssueArgs) {
    let persisted_state_path = args.state_path.clone();
    let artifact = match args.artifact {
        ArtifactCommand::EnrollmentToken(args) => {
            let authority = seeded_keypair(&format!("authority:{}", args.realm));
            let network_id = network_id(&args.network);
            let issued_at = current_unix_secs();
            IssuedArtifact::EnrollmentToken(EnrollmentToken::issue(
                &authority,
                network_id,
                issued_at,
                issued_at + args.ttl_secs,
                args.realm,
                args.subject,
                normalize_roles(args.roles),
                bootstrap_hints(args.bootstrap_addresses),
                fixture_nonce("enrollment-token"),
            ))
        }
        ArtifactCommand::Membership(args) => {
            let authority = seeded_keypair(&format!("authority:{}", args.realm));
            let (subject_label, subject_peer_id) =
                resolve_subject(args.subject_seed.as_deref(), args.subject_peer_id.as_deref());
            let issued_at = current_unix_secs();
            IssuedArtifact::Membership {
                subject_seed: subject_label,
                active: args.active,
                value: MembershipCertificate::issue(
                    &authority,
                    network_id(&args.network),
                    subject_peer_id,
                    issued_at,
                    issued_at + args.ttl_secs,
                    normalize_roles(args.roles),
                ),
            }
        }
        ArtifactCommand::Capability(args) => {
            let authority = seeded_keypair(&format!("authority:{}", args.realm));
            let (_, subject_peer_id) =
                resolve_subject(args.subject_seed.as_deref(), args.subject_peer_id.as_deref());
            let issued_at = current_unix_secs();
            let sequence = next_capability_sequence(persisted_state_path.as_deref());
            IssuedArtifact::Capability(CapabilityGrant::issue(
                &authority,
                network_id(&args.network),
                subject_peer_id,
                normalize_capabilities(args.capabilities),
                parse_protocols(args.protocols),
                ResourceLimits {
                    bandwidth_bps: Some(10_000_000),
                    concurrent_streams: Some(32),
                    max_object_bytes: Some(4 * 1024 * 1024),
                },
                args.constraints,
                issued_at,
                issued_at + args.ttl_secs,
                sequence,
            ))
        }
        ArtifactCommand::Revocation(args) => {
            let authority = seeded_keypair(&format!("authority:{}", args.realm));
            let sequence = next_revocation_sequence(persisted_state_path.as_deref());
            let issued_at = current_unix_secs();
            IssuedArtifact::Revocation(RevocationRecord::issue(
                &authority,
                network_id(&args.network),
                RevocationTarget::Peer {
                    peer_id: args
                        .peer_id
                        .parse()
                        .expect("peer ids supplied to CLI must be valid"),
                },
                parse_revocation_reason(&args.reason),
                issued_at,
                issued_at,
                sequence,
                args.note,
            ))
        }
    };

    if let Some(state_path) = persisted_state_path.as_deref() {
        persist_issued_artifact(state_path, &artifact);
    }

    artifact.print_json();
}

fn fixture_artifacts(network: &str, realm: &str) -> FixtureArtifacts {
    let authority = seeded_keypair(&format!("authority:{realm}"));
    let subject = seeded_keypair("subject:fixture-member");
    let network_id = network_id(network);
    let issued_at = 1_700_000_000;
    let enrollment_token = EnrollmentToken::issue(
        &authority,
        network_id.clone(),
        issued_at,
        issued_at + 3_600,
        realm.to_string(),
        Some("fixture-member".to_string()),
        vec!["member".to_string()],
        vec![
            BootstrapHint {
                peer_id: None,
                addresses: vec!["https://bootstrap1.example.invalid:8443".to_string()],
                metadata: BTreeMap::from([
                    ("source".to_string(), "authority-cli".to_string()),
                    ("priority".to_string(), "0".to_string()),
                ]),
            },
            BootstrapHint {
                peer_id: Some(authority.peer_id()),
                addresses: vec!["quic://198.51.100.10:8443".to_string()],
                metadata: BTreeMap::from([
                    ("source".to_string(), "authority-cli".to_string()),
                    ("priority".to_string(), "1".to_string()),
                    (
                        "protocols".to_string(),
                        "/quicnet/control/1,/quicnet/records/1".to_string(),
                    ),
                ]),
            },
        ],
        fixture_nonce("fixture-enrollment"),
    );
    let membership = MembershipCertificate::issue(
        &authority,
        network_id.clone(),
        subject.peer_id(),
        issued_at,
        issued_at + 86_400,
        vec!["member".to_string(), "publisher".to_string()],
    );
    let capability_grant = CapabilityGrant::issue(
        &authority,
        network_id.clone(),
        subject.peer_id(),
        vec!["records.publish".to_string(), "records.read".to_string()],
        parse_protocols(vec!["/quicnet/records/1".to_string()]),
        ResourceLimits {
            bandwidth_bps: Some(25_000_000),
            concurrent_streams: Some(64),
            max_object_bytes: Some(8 * 1024 * 1024),
        },
        vec!["path_kind=relay".to_string()],
        issued_at,
        issued_at + 43_200,
        1,
    );
    let revocation_record = RevocationRecord::issue(
        &authority,
        network_id.clone(),
        RevocationTarget::Peer {
            peer_id: authority.peer_id(),
        },
        RevocationReason::Superseded,
        issued_at + 1_800,
        issued_at + 1_800,
        2,
        Some("bootstrap peer rotated out of service".to_string()),
    );

    FixtureArtifacts {
        network_id,
        authority_peer_id: authority.peer_id().to_text(),
        subject_peer_id: subject.peer_id().to_text(),
        bootstrap_hints: enrollment_token.bootstrap_hints.clone(),
        enrollment_token,
        membership,
        capability_grants: vec![capability_grant],
        revocations: vec![revocation_record],
    }
}

fn resolve_subject(subject_seed: Option<&str>, subject_peer_id: Option<&str>) -> (String, PeerId) {
    if let Some(peer_id) = subject_peer_id {
        let peer_id = peer_id
            .parse()
            .expect("subject peer ids supplied to CLI must be valid");
        let label = subject_seed
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("peer:{peer_id}"));
        (label, peer_id)
    } else {
        let seed = subject_seed.expect("either --subject-seed or --subject-peer-id must be supplied");
        let subject = seeded_keypair(&format!("subject:{seed}"));
        (seed.to_string(), subject.peer_id())
    }
}

fn route_request(
    state: &AuthorityState,
    method: &Method,
    url: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    if method != &Method::Get {
        return json_response(
            StatusCode(405),
            serde_json::json!({ "error": "method not allowed" }),
        );
    }

    let (path, query) = split_request_target(url);
    let subject = query_param(query, "subject");
    let after_sequence = query_param(query, "after_sequence")
        .map(parse_u64_param)
        .transpose();

    match path {
        "/healthz" => json_response(StatusCode(200), serde_json::json!({ "status": "ok" })),
        "/snapshot" => match projected_snapshot(state, subject) {
            Some(snapshot) => json_response(StatusCode(200), snapshot),
            None => missing_subject_response(subject),
        },
        "/bootstrap" => match projected_snapshot(state, subject) {
            Some(snapshot) => json_response(StatusCode(200), snapshot.bootstrap_hints),
            None => missing_subject_response(subject),
        },
        "/relays" => json_response(
            StatusCode(200),
            RelayMap {
                version: state.relay_map_version,
                generated_at: current_unix_secs(),
                relays: state.relays.clone(),
            },
        ),
        "/revoke" => match after_sequence {
            Ok(after_sequence) => {
                json_response(StatusCode(200), filtered_revocations(state, after_sequence))
            }
            Err(value) => json_response(
                StatusCode(400),
                serde_json::json!({
                    "error": "invalid after_sequence",
                    "value": value,
                }),
            ),
        },
        _ => json_response(
            StatusCode(404),
            serde_json::json!({ "error": "not found", "path": url }),
        ),
    }
}

fn split_request_target(url: &str) -> (&str, &str) {
    url.split_once('?').unwrap_or((url, ""))
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        (name == key && !value.is_empty()).then_some(value)
    })
}

fn missing_subject_response(subject: Option<&str>) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        StatusCode(404),
        serde_json::json!({
            "error": "subject not found",
            "subject": subject,
        }),
    )
}

fn parse_u64_param(value: &str) -> Result<u64, &str> {
    value.parse::<u64>().map_err(|_| value)
}

fn filtered_revocations(
    state: &AuthorityState,
    after_sequence: Option<u64>,
) -> Vec<RevocationRecord> {
    state
        .revocations
        .iter()
        .filter(|revocation| {
            after_sequence
                .map(|sequence| revocation.sequence > sequence)
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

fn json_response(status: StatusCode, value: impl Serialize) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec_pretty(&value).expect("authority JSON serialization should work");
    let header = Header::from_bytes("Content-Type", "application/json")
        .expect("content-type header should be valid");
    Response::from_data(body)
        .with_status_code(status)
        .with_header(header)
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct AuthorityState {
    realm: String,
    authority_peer_id: String,
    active_subject_seed: Option<String>,
    members: Vec<AuthorityMember>,
    capability_grants: Vec<CapabilityGrant>,
    revocations: Vec<RevocationRecord>,
    #[serde(default)]
    relay_map_version: u64,
    #[serde(default)]
    relays: Vec<RelayAnnouncement>,
    next_capability_sequence: u64,
    next_revocation_sequence: u64,
    bootstrap_generation: u64,
    bootstrap_hints: Vec<BootstrapHint>,
    snapshot: AuthorityArtifactSnapshot,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct AuthorityMember {
    subject_seed: String,
    peer_id: String,
    membership: MembershipCertificate,
}

enum IssuedArtifact {
    EnrollmentToken(EnrollmentToken),
    Membership {
        subject_seed: String,
        active: bool,
        value: MembershipCertificate,
    },
    Capability(CapabilityGrant),
    Revocation(RevocationRecord),
}

impl IssuedArtifact {
    fn print_json(&self) {
        match self {
            Self::EnrollmentToken(value) => print_json(value),
            Self::Membership { value, .. } => print_json(value),
            Self::Capability(value) => print_json(value),
            Self::Revocation(value) => print_json(value),
        }
    }
}

fn load_or_init_state(state_path: &str, network: &str, realm: &str) -> AuthorityState {
    if Path::new(state_path).exists() {
        load_state(state_path)
    } else {
        let state = initial_state(network, realm, Vec::new());
        save_state(state_path, &state);
        state
    }
}

fn load_state(state_path: &str) -> AuthorityState {
    let mut state: AuthorityState =
        serde_json::from_slice(&fs::read(state_path).expect("authority state should read"))
            .expect("authority state should decode");
    if state.bootstrap_hints.is_empty() {
        state.bootstrap_hints = state.snapshot.bootstrap_hints.clone();
    }
    if state.capability_grants.is_empty() {
        state.capability_grants = state.snapshot.capability_grants.clone();
    }
    if state.revocations.is_empty() {
        state.revocations = state.snapshot.revocations.clone();
    }
    materialize_state(&mut state);
    state
}

fn save_state(state_path: &str, state: &AuthorityState) {
    if let Some(parent) = Path::new(state_path).parent() {
        fs::create_dir_all(parent).expect("authority state parent should exist");
    }
    fs::write(
        state_path,
        serde_json::to_vec_pretty(state).expect("authority state should serialize"),
    )
    .expect("authority state should write");
}

fn persist_issued_artifact(state_path: &str, artifact: &IssuedArtifact) {
    let mut state: AuthorityState = serde_json::from_slice(
        &fs::read(state_path).expect("authority state should exist before persisting artifacts"),
    )
    .expect("authority state should decode");

    match artifact {
        IssuedArtifact::EnrollmentToken(value) => {
            state.snapshot.enrollment_token = Some(value.clone());
        }
        IssuedArtifact::Membership {
            subject_seed,
            active,
            value,
        } => {
            upsert_member(
                &mut state.members,
                AuthorityMember {
                    subject_seed: subject_seed.clone(),
                    peer_id: value.subject_peer_id.to_text(),
                    membership: value.clone(),
                },
            );
            if *active || state.active_subject_seed.is_none() {
                state.active_subject_seed = Some(subject_seed.clone());
            }
        }
        IssuedArtifact::Capability(value) => {
            if let Some(index) = state.capability_grants.iter().position(|existing| {
                existing.network_id == value.network_id
                    && existing.issuer_peer_id == value.issuer_peer_id
                    && existing.subject_peer_id == value.subject_peer_id
                    && existing.sequence == value.sequence
            }) {
                state.capability_grants[index] = value.clone();
            } else {
                state.capability_grants.push(value.clone());
            }
            state.next_capability_sequence = state.next_capability_sequence.max(value.sequence + 1);
        }
        IssuedArtifact::Revocation(value) => {
            if !state.revocations.iter().any(|existing| {
                existing.sequence == value.sequence
                    && existing.issuer_peer_id == value.issuer_peer_id
                    && existing.target == value.target
            }) {
                state.revocations.push(value.clone());
            }
            state.next_revocation_sequence = state.next_revocation_sequence.max(value.sequence + 1);
        }
    }

    materialize_state(&mut state);
    save_state(state_path, &state);
}

fn initial_state(network: &str, realm: &str, bootstrap_addresses: Vec<String>) -> AuthorityState {
    let authority = seeded_keypair(&format!("authority:{realm}"));
    let network_id = network_id(network);
    let issued_at = 1_700_000_000;
    let token_bootstrap = if bootstrap_addresses.is_empty() {
        fixture_artifacts(network, realm).bootstrap_hints
    } else {
        bootstrap_hints(bootstrap_addresses)
    };
    let enrollment_token = EnrollmentToken::issue(
        &authority,
        network_id.clone(),
        issued_at,
        issued_at + 3_600,
        realm.to_string(),
        None,
        vec!["member".to_string()],
        token_bootstrap.clone(),
        fixture_nonce("init-enrollment"),
    );
    let mut state = AuthorityState {
        realm: realm.to_string(),
        authority_peer_id: authority.peer_id().to_text(),
        active_subject_seed: None,
        members: Vec::new(),
        capability_grants: Vec::new(),
        revocations: Vec::new(),
        relay_map_version: 0,
        relays: Vec::new(),
        next_capability_sequence: 1,
        next_revocation_sequence: 1,
        bootstrap_generation: 1,
        bootstrap_hints: token_bootstrap,
        snapshot: AuthorityArtifactSnapshot {
            network_id,
            enrollment_token: Some(enrollment_token),
            membership: None,
            capability_grants: Vec::new(),
            revocations: Vec::new(),
            bootstrap_hints: Vec::new(),
        },
    };
    materialize_state(&mut state);
    state
}

fn next_capability_sequence(state_path: Option<&str>) -> u64 {
    state_path
        .map(load_state)
        .map(|state| state.next_capability_sequence)
        .unwrap_or(1)
}

fn next_revocation_sequence(state_path: Option<&str>) -> u64 {
    state_path
        .map(load_state)
        .map(|state| state.next_revocation_sequence)
        .unwrap_or(1)
}

fn upsert_bootstrap_hint(hints: &mut Vec<BootstrapHint>, hint: BootstrapHint) {
    if let Some(index) =
        hints
            .iter()
            .position(|existing| match (&existing.peer_id, &hint.peer_id) {
                (Some(left), Some(right)) => left == right,
                _ => existing.addresses == hint.addresses,
            })
    {
        hints[index] = hint;
    } else {
        hints.push(hint);
    }
}

fn upsert_relay(relays: &mut Vec<RelayAnnouncement>, relay: RelayAnnouncement) {
    if let Some(index) = relays
        .iter()
        .position(|existing| existing.peer_id == relay.peer_id)
    {
        relays[index] = relay;
    } else {
        relays.push(relay);
    }
}

fn upsert_member(members: &mut Vec<AuthorityMember>, member: AuthorityMember) {
    if let Some(index) = members
        .iter()
        .position(|existing| existing.subject_seed == member.subject_seed)
    {
        members[index] = member;
    } else {
        members.push(member);
    }
}

fn projected_snapshot(
    state: &AuthorityState,
    subject: Option<&str>,
) -> Option<AuthorityArtifactSnapshot> {
    let selected_member = match subject {
        Some(subject_seed) => Some(
            state
                .members
                .iter()
                .find(|member| member.subject_seed == subject_seed)?,
        ),
        None => state.active_subject_seed.as_ref().and_then(|subject_seed| {
            state
                .members
                .iter()
                .find(|member| member.subject_seed == *subject_seed)
        }),
    };

    let membership = selected_member.map(|member| member.membership.clone());
    let capability_grants = match &membership {
        Some(membership) => state
            .capability_grants
            .iter()
            .filter(|grant| grant.subject_peer_id == membership.subject_peer_id)
            .cloned()
            .collect(),
        None => Vec::new(),
    };
    let mut enrollment_token = state.snapshot.enrollment_token.clone();
    if let Some(token) = &mut enrollment_token {
        token.bootstrap_hints = state.bootstrap_hints.clone();
    }

    Some(AuthorityArtifactSnapshot {
        network_id: state.snapshot.network_id.clone(),
        enrollment_token,
        membership,
        capability_grants,
        revocations: state.revocations.clone(),
        bootstrap_hints: state.bootstrap_hints.clone(),
    })
}

fn materialize_state(state: &mut AuthorityState) {
    let enrollment_token = state.snapshot.enrollment_token.clone();
    state.snapshot = projected_snapshot(state, None).unwrap_or_else(|| AuthorityArtifactSnapshot {
        network_id: state.snapshot.network_id.clone(),
        enrollment_token,
        membership: None,
        capability_grants: Vec::new(),
        revocations: state.revocations.clone(),
        bootstrap_hints: state.bootstrap_hints.clone(),
    });
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs()
}

fn parse_revocation_reason(value: &str) -> RevocationReason {
    match value {
        "key-compromise" => RevocationReason::KeyCompromise,
        "superseded" => RevocationReason::Superseded,
        "unspecified" => RevocationReason::Unspecified,
        _ => RevocationReason::Administrative,
    }
}

fn network_id(network: &str) -> NetworkId {
    NetworkId::derive(network)
}

fn seeded_keypair(label: &str) -> IdentityKeypair {
    IdentityKeypair::from_secret_bytes(hash_bytes(label.as_bytes()))
}

fn normalize_roles(roles: Vec<String>) -> Vec<String> {
    if roles.is_empty() {
        vec!["member".to_string()]
    } else {
        roles
    }
}

fn normalize_capabilities(capabilities: Vec<String>) -> Vec<String> {
    if capabilities.is_empty() {
        vec!["records.publish".to_string()]
    } else {
        capabilities
    }
}

fn parse_protocols(protocols: Vec<String>) -> Vec<ProtocolId> {
    let values = if protocols.is_empty() {
        vec!["/quicnet/records/1".to_string()]
    } else {
        protocols
    };

    values
        .into_iter()
        .map(|protocol| {
            ProtocolId::new(protocol).expect("protocol ids supplied to CLI must be valid")
        })
        .collect()
}

fn bootstrap_hints(addresses: Vec<String>) -> Vec<BootstrapHint> {
    let values = if addresses.is_empty() {
        vec!["https://bootstrap.example.invalid:8443".to_string()]
    } else {
        addresses
    };

    values
        .into_iter()
        .enumerate()
        .map(|(index, address)| BootstrapHint {
            peer_id: None,
            addresses: vec![address],
            metadata: BTreeMap::from([
                ("source".to_string(), "authority-cli".to_string()),
                ("priority".to_string(), index.to_string()),
            ]),
        })
        .collect()
}

fn fixture_nonce(label: &str) -> [u8; 16] {
    let digest = hash_bytes(label.as_bytes());
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&digest[..16]);
    nonce
}

fn print_json<T: Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("authority artifact serialization should work")
    );
}
