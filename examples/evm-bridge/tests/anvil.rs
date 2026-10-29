//! anvil にコントラクトを置いて、見張り役の署名で発行し、燃やして Burn を拾う。
//! anvil と、`forge build`（contracts で）の済んだコントラクトが要るので、`cargo test -- --ignored` で走らせる。

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use evm_bridge::evm::{Evm, EvmKey, EvmSignature, key_digest, mint_digest};
use evm_bridge::roast::{Holder, deal, receive, sign_together};
use frost_secp256k1::Secp256K1Sha256;
use rand_core::OsRng;

struct Anvil(Child);

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_anvil() -> (Anvil, String) {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let anvil = std::env::var("ANVIL").unwrap_or_else(|_| "anvil".into());
    let anvil = Anvil(
        Command::new(anvil)
            .args(["--port", &port.to_string(), "--silent"])
            .stdout(Stdio::null())
            .spawn()
            .expect("anvil を起動できません（ANVIL で場所を渡せます）"),
    );
    let rpc = format!("http://127.0.0.1:{port}");
    for _ in 0..50 {
        if Evm::connect(&rpc).is_ok() {
            return (anvil, rpc);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("anvil が起動しません");
}

fn bytecode() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/contracts/out/WrappedXym.sol/WrappedXym.json"
    );
    let json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path).expect("contracts で forge build してください"),
    )
    .unwrap();
    json["bytecode"]["object"].as_str().unwrap().to_owned()
}

struct Group {
    holders: Vec<Holder<Secp256K1Sha256>>,
    public: Arc<frost_core::keys::PublicKeyPackage<Secp256K1Sha256>>,
    key: EvmKey,
}

impl Group {
    fn new() -> Self {
        loop {
            let (shares, public) = deal::<Secp256K1Sha256, _>(&[1; 3], 2, &mut OsRng).unwrap();
            let Some(key) = EvmKey::new(public.verifying_key()) else {
                continue;
            };
            let holders = shares
                .into_iter()
                .map(|shares| Holder::new(receive(shares).unwrap()))
                .collect();
            return Self {
                holders,
                public: Arc::new(public),
                key,
            };
        }
    }

    fn sign(&mut self, digest: &[u8; 32]) -> EvmSignature {
        let signature = sign_together(
            &mut self.holders,
            &self.public,
            &[1; 3],
            2,
            digest,
            &mut OsRng,
            |_, holder, package| holder.sign(package).ok(),
        )
        .unwrap();
        EvmSignature::new(&signature).unwrap()
    }
}

#[test]
#[ignore = "anvil と forge build が要る"]
fn mints_with_group_signature_and_emits_burn() {
    let (_anvil, rpc) = start_anvil();
    let evm = Evm::connect(&rpc).unwrap();
    let mut group = Group::new();
    let contract = evm.deploy(&bytecode(), &group.key).unwrap();
    let user = evm.account();
    let deposit = [0x11; 32];

    // 見張り役の署名で発行する。同じ入金ではもう発行できない
    let digest = mint_digest(evm.chain_id, &contract, &user, 1_500_000, &deposit);
    let signature = group.sign(&digest);
    evm.mint(&contract, &user, 1_500_000, &deposit, &signature)
        .unwrap();
    assert!(evm.minted(&contract, &deposit).unwrap());
    assert_eq!(evm.balance_of(&contract, &user).unwrap(), 1_500_000);
    assert!(
        evm.mint(&contract, &user, 1_500_000, &deposit, &signature)
            .is_err()
    );
    // 量を書き換えた発行は通らない
    assert!(
        evm.mint(&contract, &user, 2_000_000, &[0x22; 32], &signature)
            .is_err()
    );

    // 燃やすと Burn が出る
    let from = evm.block_number().unwrap();
    evm.burn(&contract, 500_000, &[0x98; 24]).unwrap();
    let burns = evm
        .burns(&contract, from, evm.block_number().unwrap())
        .unwrap();
    assert_eq!(burns.len(), 1);
    assert_eq!(
        (burns[0].id, burns[0].recipient, burns[0].amount),
        (0, [0x98; 24], 500_000)
    );
    assert_eq!(evm.balance_of(&contract, &user).unwrap(), 1_000_000);

    // 鍵を差し替えると、前の鍵の署名では発行できなくなる
    let mut new = Group::new();
    let digest = key_digest(
        evm.chain_id,
        &contract,
        evm.key_epoch(&contract).unwrap(),
        &new.key,
    );
    let signature = group.sign(&digest);
    evm.change_key(&contract, &new.key, &signature).unwrap();
    assert_eq!(evm.key_epoch(&contract).unwrap(), 1);
    let deposit = [0x33; 32];
    let digest = mint_digest(evm.chain_id, &contract, &user, 1, &deposit);
    assert!(
        evm.mint(&contract, &user, 1, &deposit, &group.sign(&digest))
            .is_err()
    );
    evm.mint(&contract, &user, 1, &deposit, &new.sign(&digest))
        .unwrap();
}
