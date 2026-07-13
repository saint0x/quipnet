use clap::{Parser, Subcommand};
use fabric::{LocalNode, TrafficClass};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "paths")]
    experiment: String,
    #[arg(long, default_value = "personalcloud-prod")]
    network: String,
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Status,
    Netcheck,
    PathExplain {
        #[arg(long, default_value = "interactive")]
        class: String,
    },
}

fn main() {
    observability::init_tracing("lab");
    let args = Args::parse();
    let node = LocalNode::fixture(&args.network);

    match args.command.unwrap_or(Command::Status) {
        Command::Status => print_output(
            args.json,
            &node.netcheck,
            format!("experiment={} {}", args.experiment, node.status_line()),
        ),
        Command::Netcheck => print_output(args.json, &node.netcheck, node.netcheck.summary()),
        Command::PathExplain { class } => {
            let class = parse_class(&class);
            let decision = node
                .best_path_for(class)
                .expect("fixture state should provide routing decisions");
            print_output(args.json, &decision, decision.explanation.summary.clone());
        }
    }
}

fn parse_class(value: &str) -> TrafficClass {
    match value {
        "control" => TrafficClass::Control,
        "bulk" => TrafficClass::Bulk,
        "background" => TrafficClass::Background,
        _ => TrafficClass::Interactive,
    }
}

fn print_output<T: serde::Serialize>(json: bool, value: &T, text: String) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).expect("json serialization")
        );
    } else {
        println!("{text}");
    }
}
