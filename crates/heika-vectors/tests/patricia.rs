//! 公式の Python SDK のテスト（`sdk/python/tests/symbol/test_Merkle.py`、MIT）にある、状態の Patricia Merkle の証明。
//!
//! ベクターのファイルにはなっていないので、テストのソースを取ってきて、16進の文字列の定数と、
//! 証明の引数（キー、値、ノード、StateHash、9本の根）を読み出す。

use heika_core::hash::Hash256;
use heika_core::patricia::{self, TreeNode};

const SOURCE: &str = "sdk/python/tests/symbol/test_Merkle.py";

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// `NAME = \` に続く、`'…' \` で区切って並べた文字列をつなげる
fn constant(source: &str, name: &str) -> String {
    let start = source
        .find(&format!("\n{name} = \\\n"))
        .unwrap_or_else(|| panic!("{name} がありません"));
    source[start..]
        .lines()
        .skip(2)
        .take_while(|line| line.trim_start().starts_with('\''))
        .map(|line| line.trim().trim_end_matches('\\').trim().trim_matches('\''))
        .collect()
}

/// `NAME = [` から `]` までの中の、`Hash256('…')` を順に読む。`None` は全部0にする
fn hashes(source: &str, name: &str) -> Vec<Option<Hash256>> {
    let start = source
        .find(&format!("\t{name} = ["))
        .unwrap_or_else(|| panic!("{name} がありません"));
    let block = &source[start..];
    let end = block.find("\n\t]").unwrap();
    block[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("None") {
                return Some(None);
            }
            let hex = line.strip_prefix("Hash256('")?.split('\'').next()?;
            Some(Some(hex.parse().unwrap()))
        })
        .collect()
}

struct Proof {
    key: Hash256,
    value: Option<Hash256>,
    nodes: Vec<TreeNode>,
    state_hash: Hash256,
    roots: [Hash256; 9],
}

fn proof(source: &str, params: &str, path: &str, base: Option<&str>) -> Proof {
    let own = hashes(source, params);
    // 否定の証明は、StateHash と根を肯定の証明から借りている
    let shared = base.map_or_else(
        || own[2..].to_vec(),
        |base| hashes(source, base)[2..].to_vec(),
    );
    let roots: Vec<_> = shared[1..].iter().map(|root| root.unwrap()).collect();
    Proof {
        key: own[0].unwrap(),
        value: own[1],
        nodes: TreeNode::decode_all(&from_hex(&constant(source, path))).unwrap(),
        state_hash: shared[0].unwrap(),
        roots: roots.try_into().unwrap(),
    }
}

#[test]
#[ignore = "fetches the official SDK tests from GitHub"]
fn proves_state_like_the_sdk() {
    let source = heika_vectors::fetch_text(SOURCE);
    let proofs = [
        (
            "肯定（偶数の経路）",
            proof(
                &source,
                "POSITIVE_PARAMS",
                "POSITIVE_PROOF_SERIALIZED_PATH",
                None,
            ),
        ),
        (
            "肯定（奇数の経路）",
            proof(
                &source,
                "POSITIVE_PARAMS_ODD",
                "POSITIVE_PROOF_SERIALIZED_PATH_ODD",
                None,
            ),
        ),
        (
            "否定",
            proof(
                &source,
                "NEGATIVE_PARAMS",
                "NEGATIVE_PROOF_SERIALIZED_PATH",
                Some("POSITIVE_PARAMS"),
            ),
        ),
    ];
    for (name, proof) in proofs {
        assert_eq!(
            patricia::state_hash(&proof.roots),
            proof.state_hash,
            "{name}"
        );
        // 根から始まる木は、9本の根のどれか
        let root = proof.nodes[0].hash();
        assert!(proof.roots.contains(&root), "{name}");
        assert_eq!(
            patricia::prove(&proof.key, &proof.nodes, &root),
            Ok(proof.value),
            "{name}"
        );
        // 値を1つ変えると、ノードのつながりが切れる
        let mut nodes = proof.nodes.clone();
        if let Some(TreeNode::Leaf { value, .. }) = nodes.last_mut() {
            value.0[0] ^= 1;
            assert!(
                patricia::prove(&proof.key, &nodes, &root).is_err(),
                "{name}"
            );
        }
    }
}
