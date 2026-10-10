use clap::{Parser, Subcommand};

/// Symbol のピアプロトコルを話すためのツールキット。
#[derive(Parser)]
#[command(name = "heika", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {}

fn main() {
    Cli::parse();
}
