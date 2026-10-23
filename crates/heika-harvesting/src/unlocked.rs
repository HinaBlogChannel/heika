//! ノードが引き受ける委任を、今のチェーンの状態で確かめる。catapult の harvesting 拡張の `UnlockedAccountsUpdater` に合わせている。
//!
//! 委任は、要求に入っていたリモートの鍵と VRF の鍵で表す。メインアカウントは要求の署名者ではなく、リモートアカウントの
//! 状態のリンクから辿る。harvesters.dat には要求の中身しか残らないので、catapult もそうしている。
//!
//! 取り込めるのは、次がそろっているときだけ。
//! - リモートの鍵のアカウントがリモートの種類で、メインアカウントにリンクしている
//! - メインアカウントの AccountKeyLink がリモートの鍵、VrfKeyLink が VRF の鍵
//! - メインアカウントの NodeKeyLink が、このノードの委任の鍵
//!
//! NodeKeyLink は合意のルールではなく、ノードの決まり。委任した人が選んだノードだけがハーベストし、
//! 別のノードに乗り換えた人の古い要求でハーベストし続けないようにする。

use heika_core::key::PublicKey;

use crate::delegation::LinkKind;

/// 確かめるのに要る、アカウントの状態の一部
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountLinks {
    /// リモートアカウントの種類か
    pub remote: bool,
    /// AccountKeyLink。リモートアカウントなら、メインアカウントの公開鍵
    pub linked: Option<PublicKey>,
    pub vrf: Option<PublicKey>,
    pub node: Option<PublicKey>,
    /// 今の重要度
    pub importance: u64,
}

/// 委任を取り込めない理由
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// リモートの鍵のアカウントがないか、リモートの種類でないか、メインアカウントが見つからない
    NoMainAccount,
    /// メインアカウントのリンクが要求と合わない
    Mismatched(Vec<LinkKind>),
}

/// 取り込める委任の、メインアカウントと重要度
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eligible {
    pub main_account: PublicKey,
    pub importance: u64,
}

/// `remote` と `vrf` の鍵の委任を、今の状態で取り込めるか。`lookup` は公開鍵のアカウントの状態を返す（なければ `None`）
pub fn check(
    remote: &PublicKey,
    vrf: &PublicKey,
    node_key: &PublicKey,
    lookup: impl Fn(&PublicKey) -> Option<AccountLinks>,
) -> Result<Eligible, Rejection> {
    let remote_account = lookup(remote).ok_or(Rejection::NoMainAccount)?;
    let main_account = match remote_account {
        AccountLinks {
            remote: true,
            linked: Some(main),
            ..
        } => main,
        _ => return Err(Rejection::NoMainAccount),
    };
    let main = lookup(&main_account).ok_or(Rejection::NoMainAccount)?;
    let mismatched: Vec<LinkKind> = [
        (LinkKind::Remote, main.linked, remote),
        (LinkKind::Vrf, main.vrf, vrf),
        (LinkKind::Node, main.node, node_key),
    ]
    .into_iter()
    .filter(|(_, linked, expected)| *linked != Some(**expected))
    .map(|(kind, _, _)| kind)
    .collect();
    if !mismatched.is_empty() {
        return Err(Rejection::Mismatched(mismatched));
    }
    Ok(Eligible {
        main_account,
        importance: main.importance,
    })
}

/// 取り込める委任から、重要度の大きい順に `max` 件を選ぶ。重要度が同じなら、先に並んでいた（先に届いた）ほうを残す。
/// catapult の既定の `delegatePrioritizationPolicy = Importance` に合わせる
pub fn choose<T>(mut eligible: Vec<(T, Eligible)>, max: usize) -> Vec<(T, Eligible)> {
    eligible.sort_by_key(|(_, eligible)| std::cmp::Reverse(eligible.importance));
    eligible.truncate(max);
    eligible
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    /// メイン 1、リモート 2、VRF 3、ノード 4 の、そろった委任
    fn accounts(main: AccountLinks) -> impl Fn(&PublicKey) -> Option<AccountLinks> {
        move |public_key| match public_key.0[0] {
            1 => Some(main),
            2 => Some(AccountLinks {
                remote: true,
                linked: Some(key(1)),
                ..Default::default()
            }),
            _ => None,
        }
    }

    fn linked_main() -> AccountLinks {
        AccountLinks {
            remote: false,
            linked: Some(key(2)),
            vrf: Some(key(3)),
            node: Some(key(4)),
            importance: 10,
        }
    }

    #[test]
    fn accepts_when_all_three_links_match() {
        let eligible = check(&key(2), &key(3), &key(4), accounts(linked_main())).unwrap();
        assert_eq!(
            eligible,
            Eligible {
                main_account: key(1),
                importance: 10
            }
        );
    }

    #[test]
    fn rejects_when_the_node_link_points_elsewhere() {
        let main = AccountLinks {
            node: Some(key(9)),
            ..linked_main()
        };
        assert_eq!(
            check(&key(2), &key(3), &key(4), accounts(main)),
            Err(Rejection::Mismatched(vec![LinkKind::Node]))
        );
        let unlinked = AccountLinks {
            node: None,
            vrf: None,
            ..linked_main()
        };
        assert_eq!(
            check(&key(2), &key(3), &key(4), accounts(unlinked)),
            Err(Rejection::Mismatched(vec![LinkKind::Vrf, LinkKind::Node]))
        );
    }

    #[test]
    fn rejects_without_a_linked_remote_account() {
        // リモートの鍵のアカウントがない
        assert_eq!(
            check(&key(5), &key(3), &key(4), accounts(linked_main())),
            Err(Rejection::NoMainAccount)
        );
        // メインアカウントの鍵を、リモートとして渡された
        assert_eq!(
            check(&key(1), &key(3), &key(4), accounts(linked_main())),
            Err(Rejection::NoMainAccount)
        );
    }

    #[test]
    fn chooses_by_importance_keeping_arrival_order_on_ties() {
        let eligible = |importance| Eligible {
            main_account: key(1),
            importance,
        };
        let chosen = choose(
            vec![
                ("a", eligible(5)),
                ("b", eligible(9)),
                ("c", eligible(5)),
                ("d", eligible(1)),
            ],
            3,
        );
        assert_eq!(
            chosen.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            ["b", "a", "c"]
        );
    }
}
