//! EVM の側。見張り役の署名をコントラクト（contracts/src/WrappedXym.sol）に渡す形にし、JSON-RPC で発行して Burn を拾う。

use frost_secp256k1 as frost;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

/// secp256k1 の位数（ビッグエンディアン）
const ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// コントラクトに登録する公開鍵。x 座標と、y の偶奇
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmKey {
    pub x: [u8; 32],
    pub parity: u8,
}

impl EvmKey {
    /// x 座標が位数以上の鍵は、コントラクトで確かめられない（ecrecover が受け付けない）ので `None`。
    /// 2¹²⁸ 回に 1 回ほどしか起きないが、起きたら鍵を作り直す
    pub fn new(key: &frost::VerifyingKey) -> Option<Self> {
        let bytes = key.serialize().ok()?;
        let (&prefix, x) = bytes.split_first()?;
        let x: [u8; 32] = x.try_into().ok()?;
        (x < ORDER).then_some(Self {
            x,
            parity: prefix - 2,
        })
    }
}

/// コントラクトに渡す署名。R は y 座標まで展開する
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmSignature {
    pub rx: [u8; 32],
    pub ry: [u8; 32],
    pub z: [u8; 32],
}

impl EvmSignature {
    pub fn new(signature: &frost::Signature) -> Option<Self> {
        // R（圧縮した 33 バイト）と z（32 バイト）
        let bytes = signature.serialize().ok()?;
        let (r, z) = bytes.split_at(33);
        let point = EncodedPoint::from_bytes(r).ok()?;
        let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&point))?;
        let point = point.to_encoded_point(false);
        Some(Self {
            rx: (*point.x()?).into(),
            ry: (*point.y()?).into(),
            z: z.try_into().ok()?,
        })
    }
}

/// 見張り役が発行に署名するもの。`keccak256(abi.encode("mint", chainid, コントラクト, to, amount, deposit))`
pub fn mint_digest(
    chain_id: u64,
    contract: &[u8; 20],
    to: &[u8; 20],
    amount: u64,
    deposit: &[u8; 32],
) -> [u8; 32] {
    keccak(&encode_with_tag(
        "mint",
        &[
            uint(chain_id),
            address(contract),
            address(to),
            uint(amount),
            *deposit,
        ],
    ))
}

/// 見張り役が鍵の差し替えに署名するもの。`keccak256(abi.encode("key", chainid, コントラクト, epoch, x, parity))`
pub fn key_digest(chain_id: u64, contract: &[u8; 20], epoch: u64, key: &EvmKey) -> [u8; 32] {
    keccak(&encode_with_tag(
        "key",
        &[
            uint(chain_id),
            address(contract),
            uint(epoch),
            key.x,
            uint(key.parity.into()),
        ],
    ))
}

/// `abi.encode(string tag, 32 バイトの値…)`。文字列は後ろに置き、頭にはその位置を書く
fn encode_with_tag(tag: &str, words: &[[u8; 32]]) -> Vec<u8> {
    assert!(tag.len() <= 32);
    let mut text = [0; 32];
    text[..tag.len()].copy_from_slice(tag.as_bytes());
    let mut out = uint(32 * (words.len() as u64 + 1)).to_vec();
    for word in words {
        out.extend_from_slice(word);
    }
    out.extend_from_slice(&uint(tag.len() as u64));
    out.extend_from_slice(&text);
    out
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn selector(signature: &str) -> [u8; 4] {
    keccak(signature.as_bytes())[..4]
        .try_into()
        .expect("4 bytes")
}

fn uint(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn address(value: &[u8; 20]) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(value);
    word
}

fn hex(bytes: &[u8]) -> String {
    let digits: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("0x{digits}")
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.strip_prefix("0x")?;
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}

/// `0x` で始まる 20 バイトのアドレスを読む
pub fn parse_address(text: &str) -> Option<[u8; 20]> {
    unhex(text)?.try_into().ok()
}

pub fn format_address(value: &[u8; 20]) -> String {
    hex(value)
}

fn quantity(text: &Value) -> Result<u64, String> {
    let text = text.as_str().ok_or("数が文字列ではありません")?;
    u64::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|error| error.to_string())
}

/// コントラクトの Burn
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Burn {
    pub id: u64,
    pub block: u64,
    /// Symbol の 24 バイトのアドレス
    pub recipient: [u8; 24],
    /// wXYM の最小単位（XYM と同じ）
    pub amount: u64,
}

/// EVM のノードの JSON-RPC。トランザクションは、ノードが持っているアカウント（anvil の開発用のアカウント）に
/// 署名してもらう（`eth_sendTransaction`）。本物のネットでは、自分で署名して `eth_sendRawTransaction` で送る
pub struct Evm {
    rpc: String,
    /// ガス代を払うアカウント
    from: [u8; 20],
    pub chain_id: u64,
}

impl Evm {
    pub fn connect(rpc: &str) -> Result<Self, String> {
        let mut evm = Self {
            rpc: rpc.to_owned(),
            from: [0; 20],
            chain_id: 0,
        };
        evm.chain_id = quantity(&evm.call("eth_chainId", json!([]))?)?;
        let accounts = evm.call("eth_accounts", json!([]))?;
        evm.from = accounts
            .get(0)
            .and_then(Value::as_str)
            .and_then(parse_address)
            .ok_or("ノードにアカウントがありません（anvil なら開発用のアカウントがあるはず）")?;
        Ok(evm)
    }

    pub fn block_number(&self) -> Result<u64, String> {
        quantity(&self.call("eth_blockNumber", json!([]))?)
    }

    /// `bytecode`（forge が作った JSON の `bytecode.object`）に、見張り役の鍵を渡して置く。コントラクトのアドレスを返す
    pub fn deploy(&self, bytecode: &str, key: &EvmKey) -> Result<[u8; 20], String> {
        let mut data = unhex(bytecode.trim()).ok_or("bytecode が読めません")?;
        data.extend_from_slice(&key.x);
        data.extend_from_slice(&uint(key.parity.into()));
        let receipt = self.send(None, &data)?;
        receipt
            .get("contractAddress")
            .and_then(Value::as_str)
            .and_then(parse_address)
            .ok_or_else(|| "コントラクトのアドレスがありません".to_owned())
    }

    pub fn mint(
        &self,
        contract: &[u8; 20],
        to: &[u8; 20],
        amount: u64,
        deposit: &[u8; 32],
        signature: &EvmSignature,
    ) -> Result<(), String> {
        let mut data = selector("mint(address,uint256,bytes32,uint256,uint256,uint256)").to_vec();
        for word in [
            address(to),
            uint(amount),
            *deposit,
            signature.rx,
            signature.ry,
            signature.z,
        ] {
            data.extend_from_slice(&word);
        }
        self.send(Some(contract), &data).map(drop)
    }

    pub fn change_key(
        &self,
        contract: &[u8; 20],
        key: &EvmKey,
        signature: &EvmSignature,
    ) -> Result<(), String> {
        let mut data = selector("changeKey(uint256,uint8,uint256,uint256,uint256)").to_vec();
        for word in [
            key.x,
            uint(key.parity.into()),
            signature.rx,
            signature.ry,
            signature.z,
        ] {
            data.extend_from_slice(&word);
        }
        self.send(Some(contract), &data).map(drop)
    }

    /// ノードのアカウントの wXYM を燃やして、Symbol の `recipient` に送ってもらう（試すときに使う）
    pub fn burn(
        &self,
        contract: &[u8; 20],
        amount: u64,
        recipient: &[u8; 24],
    ) -> Result<(), String> {
        let mut word = [0; 32];
        word[..24].copy_from_slice(recipient);
        let data = [&selector("burn(uint256,bytes24)")[..], &uint(amount), &word].concat();
        self.send(Some(contract), &data).map(drop)
    }

    /// `owner` の wXYM
    pub fn balance_of(&self, contract: &[u8; 20], owner: &[u8; 20]) -> Result<u64, String> {
        let data = [&selector("balanceOf(address)")[..], &address(owner)].concat();
        let word = self.read(contract, &data)?;
        Ok(u64::from_be_bytes(
            word.get(24..32)
                .ok_or("返事が短すぎます")?
                .try_into()
                .expect("8 bytes"),
        ))
    }

    /// ガス代を払うアカウント
    pub fn account(&self) -> [u8; 20] {
        self.from
    }

    /// その入金で、もう発行したか
    pub fn minted(&self, contract: &[u8; 20], deposit: &[u8; 32]) -> Result<bool, String> {
        let data = [&selector("minted(bytes32)")[..], deposit].concat();
        Ok(self.read(contract, &data)?.iter().any(|&byte| byte != 0))
    }

    /// 鍵を差し替えた回数
    pub fn key_epoch(&self, contract: &[u8; 20]) -> Result<u64, String> {
        let word = self.read(contract, &selector("keyEpoch()"))?;
        Ok(u64::from_be_bytes(
            word.get(24..32)
                .ok_or("返事が短すぎます")?
                .try_into()
                .expect("8 bytes"),
        ))
    }

    /// ブロック `from` から `to` までの Burn
    pub fn burns(&self, contract: &[u8; 20], from: u64, to: u64) -> Result<Vec<Burn>, String> {
        let topic = hex(&keccak(b"Burn(uint256,address,bytes24,uint256)"));
        let logs = self.call(
            "eth_getLogs",
            json!([{
                "address": hex(contract),
                "fromBlock": format!("0x{from:x}"),
                "toBlock": format!("0x{to:x}"),
                "topics": [topic],
            }]),
        )?;
        let mut burns = Vec::new();
        for log in logs.as_array().ok_or("ログが配列ではありません")? {
            let id = log["topics"][1]
                .as_str()
                .and_then(unhex)
                .ok_or("Burn の番号が読めません")?;
            let data = log["data"]
                .as_str()
                .and_then(unhex)
                .ok_or("Burn の中身が読めません")?;
            if data.len() != 64 || id.len() != 32 {
                return Err("Burn の形が違います".into());
            }
            burns.push(Burn {
                id: u64::from_be_bytes(id[24..].try_into().expect("8 bytes")),
                block: quantity(&log["blockNumber"])?,
                recipient: data[..24].try_into().expect("24 bytes"),
                amount: u64::from_be_bytes(data[56..].try_into().expect("8 bytes")),
            });
        }
        Ok(burns)
    }

    /// トランザクションを送り、ブロックに入るまで待って、レシートを返す。失敗したら Err
    fn send(&self, to: Option<&[u8; 20]>, data: &[u8]) -> Result<Value, String> {
        let mut transaction = json!({ "from": hex(&self.from), "data": hex(data) });
        if let Some(to) = to {
            transaction["to"] = json!(hex(to));
        }
        let hash = self.call("eth_sendTransaction", json!([transaction]))?;
        for _ in 0..60 {
            let receipt = self.call("eth_getTransactionReceipt", json!([hash]))?;
            if !receipt.is_null() {
                if quantity(&receipt["status"])? != 1 {
                    return Err("EVM のトランザクションが失敗しました".into());
                }
                return Ok(receipt);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Err("EVM のトランザクションが 30 秒たってもブロックに入りません".into())
    }

    fn read(&self, contract: &[u8; 20], data: &[u8]) -> Result<Vec<u8>, String> {
        let result = self.call(
            "eth_call",
            json!([{ "to": hex(contract), "data": hex(data) }, "latest"]),
        )?;
        result
            .as_str()
            .and_then(unhex)
            .ok_or_else(|| "eth_call の返事が読めません".to_owned())
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut response = ureq::post(&self.rpc)
            .header("Content-Type", "application/json")
            .send(request.to_string())
            .map_err(|error| format!("{method}: {error}"))?;
        let bytes = response
            .body_mut()
            .read_to_vec()
            .map_err(|error| format!("{method}: {error}"))?;
        let mut body: Value =
            serde_json::from_slice(&bytes).map_err(|error| format!("{method}: {error}"))?;
        if let Some(error) = body.get("error") {
            return Err(format!(
                "{method}: {}",
                error["message"].as_str().unwrap_or("?")
            ));
        }
        Ok(body["result"].take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;
    use std::collections::BTreeMap;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// 決まった乱数で 2-of-3 の署名を作る。contracts/test/FrostSecp256k1.t.sol の定数と同じになること
    #[test]
    fn fixed_signature_matches_solidity_test() {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let keys: BTreeMap<_, _> = shares
            .into_iter()
            .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
            .take(2)
            .collect();
        let message = [0x42; 32];
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for (id, key) in &keys {
            let (nonce, commitment) = frost::round1::commit(key.signing_share(), &mut rng);
            nonces.insert(*id, nonce);
            commitments.insert(*id, commitment);
        }
        let package = frost::SigningPackage::new(commitments, &message);
        let shares: BTreeMap<_, _> = keys
            .iter()
            .map(|(id, key)| {
                (
                    *id,
                    frost::round2::sign(&package, &nonces[id], key).unwrap(),
                )
            })
            .collect();
        let signature = frost::aggregate(&package, &shares, &public).unwrap();
        public.verifying_key().verify(&message, &signature).unwrap();

        let key = EvmKey::new(public.verifying_key()).unwrap();
        let signature = EvmSignature::new(&signature).unwrap();
        let solidity = include_str!("../contracts/test/FrostSecp256k1.t.sol");
        for (name, value) in [
            ("PX", hex(&key.x)),
            ("PARITY", key.parity.to_string()),
            ("RX", hex(&signature.rx)),
            ("RY", hex(&signature.ry)),
            ("Z", hex(&signature.z)),
        ] {
            let value = if name == "PARITY" {
                value
            } else {
                format!("0x{value}")
            };
            assert!(
                solidity.contains(&format!(" {name} = {value};")),
                "{name} = {value}"
            );
        }
    }
}
