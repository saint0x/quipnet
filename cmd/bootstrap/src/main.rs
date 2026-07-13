use std::collections::BTreeMap;

use bootstrap::{BootstrapService, BootstrapServiceConfig};
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = 8443)]
    port: u16,
    #[arg(long, default_value = "default")]
    realm: String,
}

fn main() {
    observability::init_tracing("bootstrap");
    let args = Args::parse();
    let mut service = BootstrapService::new(BootstrapServiceConfig {
        network_id: model::NetworkId::derive(format!("bootstrap:{}", args.realm)),
        bind_addr: format!("0.0.0.0:{}", args.port),
        advertised_origin: format!("https://bootstrap.example.invalid:{}", args.port),
    });
    service.stage_hint(
        args.realm.clone(),
        membership::BootstrapHint {
            peer_id: None,
            addresses: vec![format!("quic://127.0.0.1:{}", args.port)],
            metadata: BTreeMap::from([("source".to_string(), "bootstrap-service".to_string())]),
        },
    );
    service.set_realm_metadata(
        args.realm.clone(),
        BTreeMap::from([("status".to_string(), "active".to_string())]),
    );

    let snapshot = service.snapshot();
    println!(
        "bootstrap listening on {} with {} configured realm(s)",
        args.port,
        snapshot.realms.len()
    );
}
