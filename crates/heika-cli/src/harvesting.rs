//! ハーベストのためのリンクの解除と紐づけ、委任の要求を、署名していない1つのアグリゲートに組む。

use std::io::{self, Write};

use clap::Args;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_transaction::{Body, KeyLink, LinkAction, Transfer};
use heika_wallet::harvest_request::{self, HarvesterKeys};

use crate::tx::Unsigned;
use crate::{Failure, Network};

/// `heika harvesting` の引数。
#[derive(Args)]
#[command(group = clap::ArgGroup::new("action").required(true).multiple(true))]
pub struct HarvestingArgs {
    #[arg(long, value_enum)]
    network: Network,
    /// メインアカウントの公開鍵
    #[arg(long)]
    signer: PublicKey,
    /// いま紐づいているリモートアカウントの公開鍵を外す
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    unlink_remote: Option<PublicKey>,
    /// いま紐づいている VRF の公開鍵を外す
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    unlink_vrf: Option<PublicKey>,
    /// いま紐づいているノードの公開鍵を外す
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    unlink_node: Option<PublicKey>,
    /// リモートアカウントの公開鍵を紐づける
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    link_remote: Option<PublicKey>,
    /// VRF の公開鍵を紐づける
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    link_vrf: Option<PublicKey>,
    /// ノードの公開鍵を紐づける
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    link_node: Option<PublicKey>,
    /// 委任先のノードの公開鍵（ノードの node.key.pem の公開鍵）。リモートアカウント、VRF、ノードを紐づけて、委任の要求を送る
    #[arg(
        long,
        value_name = "PUBLIC_KEY",
        group = "action",
        conflicts_with_all = ["link_remote", "link_vrf", "link_node"]
    )]
    delegate: Option<PublicKey>,
    #[command(flatten)]
    unsigned: Unsigned,
}

pub fn run(args: HarvestingArgs) -> Result<(), Failure> {
    let HarvestingArgs {
        network,
        signer,
        unlink_remote,
        unlink_vrf,
        unlink_node,
        mut link_remote,
        mut link_vrf,
        mut link_node,
        delegate,
        unsigned,
    } = args;
    let identifier = NetworkIdentifier::from(network);

    let mut request = None;
    if let Some(node) = delegate {
        let keys = HarvesterKeys {
            signing: generate()?,
            vrf: generate()?,
        };
        link_remote = Some(PublicKey::from_private_key(&keys.signing));
        link_vrf = Some(PublicKey::from_private_key(&keys.vrf));
        link_node = Some(node);
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let message = harvest_request::encode(&mut rng, &node, &keys)
            .map_err(|error| format!("--delegate の公開鍵は使えません: {error}"))?;
        request = Some((
            harvest_request::recipient_address(&node, identifier),
            message,
        ));
    }

    let link = |action, linked_public_key| KeyLink {
        linked_public_key,
        link_action: action,
    };
    // 解除してから紐づける。同じ種類のリンクがあるところには紐づけられない
    let mut bodies = Vec::new();
    bodies.extend(unlink_remote.map(|key| Body::AccountKeyLink(link(LinkAction::Unlink, key))));
    bodies.extend(unlink_vrf.map(|key| Body::VrfKeyLink(link(LinkAction::Unlink, key))));
    bodies.extend(unlink_node.map(|key| Body::NodeKeyLink(link(LinkAction::Unlink, key))));
    bodies.extend(link_remote.map(|key| Body::AccountKeyLink(link(LinkAction::Link, key))));
    bodies.extend(link_vrf.map(|key| Body::VrfKeyLink(link(LinkAction::Link, key))));
    bodies.extend(link_node.map(|key| Body::NodeKeyLink(link(LinkAction::Link, key))));
    if let Some((recipient, message)) = &request {
        bodies.push(Body::Transfer(
            Transfer::new((*recipient).into(), Default::default(), message.clone())
                .expect("one message and no mosaics fit"),
        ));
    }
    unsigned.write(network, signer, bodies)?;

    if let Some(key) = link_remote {
        outln!("紐づけるリモートアカウントの公開鍵: {key}");
    }
    if let Some(key) = link_vrf {
        outln!("紐づける VRF の公開鍵: {key}");
    }
    if let Some(key) = link_node {
        outln!("紐づけるノードの公開鍵: {key}");
    }
    if let Some((recipient, _)) = &request {
        outln!("委任の要求を送るアドレス: {recipient}");
    }
    let unlinks: Vec<String> = [
        ("--unlink-remote", link_remote),
        ("--unlink-vrf", link_vrf),
        ("--unlink-node", link_node),
    ]
    .into_iter()
    .filter_map(|(flag, key)| key.map(|key| format!("{flag} {key}")))
    .collect();
    if !unlinks.is_empty() {
        outln!(
            "次に紐づけ直すときは、{} を付けてください",
            unlinks.join(" ")
        );
    }
    Ok(())
}

fn generate() -> Result<PrivateKey, String> {
    PrivateKey::generate().map_err(|error| format!("OS の乱数を取れませんでした: {error}"))
}
