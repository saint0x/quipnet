use clap::Parser;
use crypto::IdentityKeypair;
use model::ProtocolId;
use relay::{control_response, RelayDestination, RelayNode, RelayService};
use relaywire::RelayAnnouncement;
use tiny_http::{Header, Response, Server, StatusCode};

const MAX_CONTROL_BODY_BYTES: usize = 64 * 1024;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "local")]
    region: String,

    #[arg(long, default_value_t = 9000)]
    max_bandwidth_mbps: u64,

    #[arg(long)]
    peer_seed: Option<String>,

    #[arg(long, default_value = "127.0.0.1:9081")]
    bind: String,

    #[arg(long, default_value = "http://127.0.0.1:9081")]
    control_endpoint: String,

    #[arg(long = "advertise-address", num_args = 0.., value_delimiter = ',')]
    advertise_addresses: Vec<String>,

    #[arg(long = "allow-destination", num_args = 0.., value_delimiter = ',')]
    allow_destinations: Vec<String>,
}

fn main() {
    observability::init_tracing("relay");
    let args = Args::parse();
    let peer_seed = args
        .peer_seed
        .unwrap_or_else(|| format!("relay:{}", args.region));
    let peer_id =
        IdentityKeypair::from_secret_bytes(crypto::hash_bytes(peer_seed.as_bytes())).peer_id();
    let relay = RelayNode {
        announcement: RelayAnnouncement {
            peer_id,
            region: args.region,
            advertised_endpoints: if args.advertise_addresses.is_empty() {
                vec!["quic://127.0.0.1:443".to_string()]
            } else {
                args.advertise_addresses
            },
            control_endpoint: args.control_endpoint.clone(),
            max_bandwidth_bps: args.max_bandwidth_mbps * 1_000_000,
            supports_quic_datagrams: true,
            supports_path_migration: true,
            traffic_classes: vec![
                "NetworkControl".to_string(),
                "InteractiveRpc".to_string(),
                "Background".to_string(),
            ],
        },
        quotas: Vec::new(),
        destinations: parse_destinations(&args.allow_destinations),
    };
    let mut service = RelayService::new(relay);
    let server = Server::http(&args.bind).expect("relay control server should bind");
    println!(
        "relay ready in region {} with {} bps capacity destinations={} control_endpoint={} bind={}",
        service.node.announcement.region,
        service.node.announcement.max_bandwidth_bps,
        service.node.destinations.len(),
        service.node.announcement.control_endpoint,
        args.bind
    );

    for mut request in server.incoming_requests() {
        let body = match read_request_body(&mut request) {
            Ok(body) => body,
            Err((status, payload)) => {
                let response = Response::from_string(payload)
                    .with_status_code(StatusCode(status))
                    .with_header(
                        Header::from_bytes("Content-Type", "application/json")
                            .expect("relay response header should be valid"),
                    );
                request
                    .respond(response)
                    .expect("relay control error response should write");
                continue;
            }
        };
        let (status, payload) = control_response(
            &mut service,
            request.method().as_str(),
            request.url(),
            &body,
        );
        let response = Response::from_string(payload)
            .with_status_code(StatusCode(status))
            .with_header(
                Header::from_bytes("Content-Type", "application/json")
                    .expect("relay response header should be valid"),
            );
        request
            .respond(response)
            .expect("relay control response should write");
    }
}

fn read_request_body(request: &mut tiny_http::Request) -> Result<Vec<u8>, (u16, String)> {
    let method = request.method().as_str();
    if method == "GET" || method == "HEAD" {
        return Ok(Vec::new());
    }
    let Some(limit) = request.body_length() else {
        return Err((
            411,
            serde_json::json!({
                "error": "relay control requests must include Content-Length"
            })
            .to_string(),
        ));
    };
    if limit > MAX_CONTROL_BODY_BYTES {
        return Err((
            413,
            serde_json::json!({
                "error": format!("relay control request body exceeds {} bytes", MAX_CONTROL_BODY_BYTES)
            })
            .to_string(),
        ));
    }
    let mut body = Vec::with_capacity(limit);
    body.resize(limit, 0);
    request.as_reader().read_exact(&mut body).map_err(|error| {
        (
            400,
            serde_json::json!({
                "error": format!("relay control request body could not be read: {error}")
            })
            .to_string(),
        )
    })?;
    Ok(body)
}

fn parse_destinations(values: &[String]) -> Vec<RelayDestination> {
    values
        .iter()
        .map(|value| {
            let (peer, protocols) = value
                .split_once('=')
                .expect("destination rules must be peer_id=/proto1,/proto2");
            RelayDestination {
                peer: peer.parse().expect("destination peer ids must be valid"),
                protocols: protocols
                    .split(',')
                    .map(str::trim)
                    .filter(|protocol| !protocol.is_empty())
                    .map(|protocol| ProtocolId::new(protocol).expect("protocol ids must be valid"))
                    .collect(),
            }
        })
        .collect()
}
