use clap::{Parser, Subcommand, ValueEnum};
use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;

/// Symbol のピアプロトコルを話すためのツールキット。
#[derive(Parser)]
#[command(name = "heika", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 鍵とアドレス
    #[command(subcommand)]
    Key(KeyCommand),
}

#[derive(Subcommand)]
enum KeyCommand {
    /// 公開鍵からアドレスを出す
    Address {
        /// 公開鍵（16進）
        public_key: PublicKey,
        #[arg(long, value_enum, default_value_t = Network::Mainnet)]
        network: Network,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
}

impl From<Network> for NetworkIdentifier {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::MAINNET,
            Network::Testnet => Self::TESTNET,
        }
    }
}

fn main() {
    match Cli::parse().command {
        Command::Key(KeyCommand::Address {
            public_key,
            network,
        }) => println!("{}", Address::from_public_key(&public_key, network.into())),
    }
}
