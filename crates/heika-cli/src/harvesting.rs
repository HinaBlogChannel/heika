//! ハーベストのためのリンクの解除と紐づけ、委任の要求を、署名していない1つのアグリゲートに組む。

use std::io::{self, Write};

use clap::Args;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_transaction::{Body, KeyLink, LinkAction, Transfer, VotingKeyLink};
use heika_wallet::harvest_request::{self, HarvesterKeys};

use crate::tx::Unsigned;
use crate::voting::VotingLink;
use crate::wallet::HarvestKeystoreArgs;
use crate::{Failure, Network};

/// `heika harvesting` の引数。
#[derive(Args)]
#[command(group = clap::ArgGroup::new("action").required(true).multiple(true))]
pub struct HarvestingArgs {
    #[arg(long, value_enum)]
    network: Network,
    /// メインアカウントの公開鍵。--link-derived なら、省くとキーストアのアカウントのものにする
    #[arg(long, required_unless_present = "link_derived")]
    signer: Option<PublicKey>,
    /// いま紐づいているリモートアカウントの公開鍵を外す
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    unlink_remote: Option<PublicKey>,
    /// いま紐づいている VRF の公開鍵を外す
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    unlink_vrf: Option<PublicKey>,
    /// いま紐づいているノードの公開鍵を外す
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    unlink_node: Option<PublicKey>,
    /// いま紐づいている投票鍵を外す。紐づけたときの期間も合わせて、<公開鍵>:<最初のエポック>-<最後のエポック> と書く。
    /// 何本も紐づけられるので、何度でも付けられる
    #[arg(long, value_name = "PUBLIC_KEY:START-END", group = "action")]
    unlink_voting: Vec<VotingLink>,
    /// リモートアカウントの公開鍵を紐づける
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    link_remote: Option<PublicKey>,
    /// VRF の公開鍵を紐づける
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    link_vrf: Option<PublicKey>,
    /// ノードの公開鍵を紐づける
    #[arg(long, value_name = "PUBLIC_KEY", group = "action")]
    link_node: Option<PublicKey>,
    /// 投票鍵を紐づける。heika key voting generate が出す <公開鍵>:<最初のエポック>-<最後のエポック> を渡す
    #[arg(long, value_name = "PUBLIC_KEY:START-END", group = "action")]
    link_voting: Option<VotingLink>,
    /// 委任先のノードの公開鍵（ノードの node.key.pem の公開鍵）。リモートアカウント、VRF、ノードを紐づけて、委任の要求を送る
    #[arg(
        long,
        value_name = "PUBLIC_KEY",
        group = "action",
        conflicts_with_all = ["link_remote", "link_vrf", "link_node"]
    )]
    delegate: Option<PublicKey>,
    /// キーストアのこのアカウントから導出したリモートと VRF の鍵を紐づける。heika experimental peer start --harvest
    /// で同じ鍵を導出してハーベストするので、鍵のファイルは要らない
    #[arg(
        long,
        value_name = "LABEL",
        group = "action",
        conflicts_with_all = ["link_remote", "link_vrf", "delegate"]
    )]
    link_derived: Option<String>,
    #[command(flatten)]
    keystore: HarvestKeystoreArgs,
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
        unlink_voting,
        mut link_remote,
        mut link_vrf,
        mut link_node,
        link_voting,
        delegate,
        link_derived,
        keystore,
        unsigned,
    } = args;
    let identifier = NetworkIdentifier::from(network);

    let mut signer = signer;
    if let Some(label) = &link_derived {
        let derived = keystore.derive(label)?;
        if derived.network != identifier {
            return Err(format!("{label} は --network と違うネットワークのアカウントです").into());
        }
        if signer.is_some_and(|signer| signer != derived.public_key) {
            return Err(format!("--signer が {label} の公開鍵と違います").into());
        }
        signer = Some(derived.public_key);
        link_remote = Some(PublicKey::from_private_key(&derived.keys.signing));
        link_vrf = Some(PublicKey::from_private_key(&derived.keys.vrf));
    }
    let signer = signer.expect("required unless --link-derived");

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
    bodies.extend(
        unlink_voting
            .iter()
            .map(|link| Body::VotingKeyLink(voting_link(LinkAction::Unlink, link))),
    );
    bodies.extend(link_remote.map(|key| Body::AccountKeyLink(link(LinkAction::Link, key))));
    bodies.extend(link_vrf.map(|key| Body::VrfKeyLink(link(LinkAction::Link, key))));
    bodies.extend(link_node.map(|key| Body::NodeKeyLink(link(LinkAction::Link, key))));
    bodies.extend(
        link_voting
            .iter()
            .map(|link| Body::VotingKeyLink(voting_link(LinkAction::Link, link))),
    );
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
    if let Some(link) = link_voting {
        outln!("紐づける投票鍵: {link}");
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
    .chain(link_voting.map(|link| format!("--unlink-voting {link}")))
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

fn voting_link(action: LinkAction, link: &VotingLink) -> VotingKeyLink {
    VotingKeyLink {
        linked_public_key: link.public_key,
        start_epoch: link.start_epoch,
        end_epoch: link.end_epoch,
        link_action: action,
    }
}
