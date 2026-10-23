//! REST の JSON を読む。通信はしない（`main.rs` が取ってきたものを渡す）。

use serde_json::Value;
use sha3::{Digest, Sha3_256};

/// 送金のトランザクションの種類
const TRANSFER: u64 = 0x4154;
/// `symbol.xym` のネームスペースの ID。名前だけから決まるので、どのネットワークでも同じ
pub const XYM_ALIAS: u64 = 0xE74B_99BA_41F4_AFEE;
/// 1 XYM の最小単位の数
pub const MICROS: u64 = 1_000_000;

/// `100` や `0.5` のような XYM の額を、最小単位にする。小数は6桁まで
pub fn parse_xym(text: &str) -> Option<u64> {
    let text = text.trim();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && fraction.is_empty()
        || fraction.len() > 6
        || !fraction.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let fraction: u64 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<6}").parse().ok()?
    };
    whole.checked_mul(MICROS)?.checked_add(fraction)
}

/// 最小単位の額を、`100` や `0.5` のような XYM の書き方にする
pub fn format_xym(micros: u64) -> String {
    let fraction = format!("{:06}", micros % MICROS);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{}", micros / MICROS)
    } else {
        format!("{}.{fraction}", micros / MICROS)
    }
}

/// 数える送金の1件
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Send {
    pub height: u64,
    /// 生えるものを決める種。トランザクションのハッシュ（アグリゲートの中なら、外のハッシュと何件目か）
    pub seed: [u8; 32],
}

fn number(value: &Value) -> Option<u64> {
    match value {
        Value::String(text) => text.parse().ok(),
        Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    let mut out = [0; 32];
    if text.len() != 64 {
        return None;
    }
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// `/chain/info` から、確定した高さ
pub fn finalized_height(info: &Value) -> Option<u64> {
    number(&info["latestFinalizedBlock"]["height"])
}

/// `/chain/info` から、チェーンの高さ
pub fn chain_height(info: &Value) -> Option<u64> {
    number(&info["height"])
}

/// `/network/properties` から、通貨のモザイクの ID（`0x6BED'913F'A202'23F8` の形）
pub fn currency_mosaic_id(properties: &Value) -> Option<u64> {
    let text = properties["chain"]["currencyMosaicId"].as_str()?;
    let digits: String = text
        .trim_start_matches("0x")
        .chars()
        .filter(|c| *c != '\'')
        .collect();
    u64::from_str_radix(&digits, 16).ok()
}

/// `/network/properties` から、ネットワークを見分ける値（キャッシュのキーに使う）
pub fn generation_hash_seed(properties: &Value) -> Option<String> {
    properties["network"]["generationHashSeed"]
        .as_str()
        .map(str::to_owned)
}

/// `/accounts/{address}` から、公開鍵。まだ署名したことがなければ `None`
pub fn public_key(account: &Value) -> Option<String> {
    let key = account["account"]["publicKey"].as_str()?;
    (key.chars().any(|c| c != '0')).then(|| key.to_ascii_uppercase())
}

/// `/transactions/confirmed` の1ページから、数える送金を取り出す。
/// REST の絞り込みを信じきらずに、送り先、署名者、通貨、額をもう一度確かめる。
/// `min` より少ない送金は数えない。2つ目の値は、ページに入っていた件数（0 なら、もう続きがない）
/// 署名者は `signer`（公開鍵の16進を受け取り、自分なら真）で確かめる。
pub fn sends(
    page: &Value,
    target_hex: &str,
    signer: impl Fn(&str) -> bool,
    currency: u64,
    min: u64,
) -> (Vec<Send>, usize) {
    let Some(entries) = page["data"].as_array() else {
        return (Vec::new(), 0);
    };
    let mut out = Vec::new();
    for entry in entries {
        let transaction = &entry["transaction"];
        let meta = &entry["meta"];
        if number(&transaction["type"]) != Some(TRANSFER)
            || !transaction["recipientAddress"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(target_hex))
            || !transaction["signerPublicKey"].as_str().is_some_and(&signer)
        {
            continue;
        }
        let amount: u64 = transaction["mosaics"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|mosaic| {
                mosaic["id"]
                    .as_str()
                    .and_then(|id| u64::from_str_radix(id, 16).ok())
                    .is_some_and(|id| id == currency || id == XYM_ALIAS)
            })
            .filter_map(|mosaic| number(&mosaic["amount"]))
            .fold(0, u64::saturating_add);
        if amount < min {
            continue;
        }
        let Some(height) = number(&meta["height"]) else {
            continue;
        };
        let seed = if let Some(hash) = meta["hash"].as_str().and_then(hex32) {
            hash
        } else if let (Some(outer), Some(index)) = (
            meta["aggregateHash"].as_str().and_then(hex32),
            number(&meta["index"]),
        ) {
            let mut hasher = Sha3_256::new();
            hasher.update(outer);
            hasher.update((index as u32).to_le_bytes());
            hasher.finalize().into()
        } else {
            continue;
        };
        out.push(Send { height, seed });
    }
    (out, entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TARGET: &str = "68AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const SIGNER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const CURRENCY: u64 = 0x6BED_913F_A202_23F8;

    fn transfer(meta: Value, recipient: &str, signer: &str, mosaics: Value) -> Value {
        json!({
            "meta": meta,
            "transaction": { "type": 16724, "recipientAddress": recipient, "signerPublicKey": signer, "mosaics": mosaics }
        })
    }

    #[test]
    fn reads_and_writes_xym_amounts() {
        assert_eq!(parse_xym("100"), Some(100_000_000));
        assert_eq!(parse_xym(" 0.5 "), Some(500_000));
        assert_eq!(parse_xym(".000001"), Some(1));
        assert_eq!(parse_xym("1.0000001"), None);
        assert_eq!(parse_xym("abc"), None);
        assert_eq!(parse_xym(""), None);
        assert_eq!(format_xym(100_000_000), "100");
        assert_eq!(format_xym(500_000), "0.5");
        assert_eq!(format_xym(1_250_000), "1.25");
    }

    #[test]
    fn reads_rest_shapes() {
        assert_eq!(
            finalized_height(&json!({"latestFinalizedBlock": {"height": "5887020"}})),
            Some(5887020)
        );
        assert_eq!(
            currency_mosaic_id(&json!({"chain": {"currencyMosaicId": "0x6BED'913F'A202'23F8"}})),
            Some(CURRENCY)
        );
        assert_eq!(
            public_key(&json!({"account": {"publicKey": "0".repeat(64)}})),
            None
        );
        assert_eq!(
            public_key(&json!({"account": {"publicKey": "ab".repeat(32)}})),
            Some("AB".repeat(32))
        );
    }

    #[test]
    fn counts_only_own_xym_sends_to_the_target() {
        let hash = "22".repeat(32);
        let outer = "33".repeat(32);
        let page = json!({ "data": [
            // 数える: ふつうの送金、モザイクの ID
            transfer(json!({"height": "10", "hash": hash}), TARGET, SIGNER, json!([{"id": "6BED913FA20223F8", "amount": "1000000"}])),
            // 数える: アグリゲートの中、ネームスペースの別名
            transfer(json!({"height": "11", "aggregateHash": outer, "index": 2}), TARGET, SIGNER, json!([{"id": "E74B99BA41F4AFEE", "amount": "5000000"}])),
            // 数えない: 1 XYM に足りない
            transfer(json!({"height": "12", "hash": hash}), TARGET, SIGNER, json!([{"id": "6BED913FA20223F8", "amount": "999999"}])),
            // 数えない: ほかの人が送った（代わりに育てるのはなし）
            transfer(json!({"height": "13", "hash": hash}), TARGET, &"44".repeat(32), json!([{"id": "6BED913FA20223F8", "amount": "1000000"}])),
            // 数えない: ほかの送り先
            transfer(json!({"height": "14", "hash": hash}), &"68".repeat(24), SIGNER, json!([{"id": "6BED913FA20223F8", "amount": "1000000"}])),
            // 数えない: XYM ではないモザイク
            transfer(json!({"height": "15", "hash": hash}), TARGET, SIGNER, json!([{"id": "6787EB27D79D2B23", "amount": "1000000"}])),
        ]});
        let (found, entries) = sends(
            &page,
            TARGET,
            |key: &str| key.eq_ignore_ascii_case(SIGNER),
            CURRENCY,
            MICROS,
        );
        assert_eq!(entries, 6);
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0],
            Send {
                height: 10,
                seed: [0x22; 32]
            }
        );
        let mut hasher = Sha3_256::new();
        hasher.update([0x33; 32]);
        hasher.update(2u32.to_le_bytes());
        assert_eq!(
            found[1],
            Send {
                height: 11,
                seed: hasher.finalize().into()
            }
        );
    }
}
