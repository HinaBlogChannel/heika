//! SLIP-10 の ed25519 での鍵の導出。Symbol のウォレットが使うパスは [`symbol_path`] で作る。
//!
//! ed25519 には hardened の導出しかないので、番号は常に hardened として扱う。
//! Symbol の SDK（`sdk/python/symbolchain/Bip32.py`）と同じく、渡された番号に hardened のビットを立てて使うので、
//! `44` と `0x8000002C` は同じ `44'` になる。

use heika_core::key::PrivateKey;
use heika_core::network::NetworkIdentifier;
use hmac::digest::FixedOutput;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

const HARDENED: u32 = 0x8000_0000;
/// ルートを導出する HMAC の鍵。
const CURVE: &[u8] = b"ed25519 seed";

/// Symbol のウォレットがアカウントの鍵を導出するパス `m/44'/<coin type>'/<アカウント>'/0'/0'`。
///
/// coin type はメインネットなら 4343、それ以外なら 1。SDK の `SymbolFacade.bip32_path` と同じ。
pub fn symbol_path(network: NetworkIdentifier, account: u32) -> [u32; 5] {
    let coin_type = if network == NetworkIdentifier::MAINNET {
        4343
    } else {
        1
    };
    [44, coin_type, account, 0, 0]
}

/// ハーベストの鍵の役割。[`harvest_path`] の4番目の番号になる。
///
/// [`symbol_path`] の4番目は 0 なので、1 から始めて、間違えて同じシードを渡してもアカウントの鍵にはならないようにする。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarvestRole {
    /// ブロックに署名するリモートアカウント
    Remote = 1,
    /// VRF
    Vrf = 2,
}

/// ハーベストの鍵を導出するパス `m/44'/<coin type>'/<アカウント>'/<役割>'/<作り直しの番号>'`。
///
/// heika だけの約束。アカウントの鍵とは別のシード（キーストアの `Harvest-Secret`）から導出するので、
/// [`symbol_path`] と同じ形でもぶつからない。作り直しの番号は、鍵を作り直すたびに1つ上げる。
pub fn harvest_path(
    network: NetworkIdentifier,
    account: u32,
    role: HarvestRole,
    rotation: u32,
) -> [u32; 5] {
    let [purpose, coin_type, account, ..] = symbol_path(network, account);
    [purpose, coin_type, account, role as u32, rotation]
}

/// 秘密鍵とチェーンコードの組。使い終わるとメモリを0で上書きする。
#[derive(Clone)]
pub struct ExtendedKey {
    private_key: Zeroizing<[u8; 32]>,
    chain_code: Zeroizing<[u8; 32]>,
}

impl ExtendedKey {
    /// BIP 39 などのシードからルート `m` を作る。
    pub fn from_seed(seed: &[u8]) -> Self {
        Self::from_hmac(CURVE, seed)
    }

    /// 子を導出する。
    pub fn derive(&self, index: u32) -> Self {
        let mut data = Zeroizing::new([0; 1 + 32 + 4]);
        data[1..33].copy_from_slice(&*self.private_key);
        data[33..].copy_from_slice(&(index | HARDENED).to_be_bytes());
        Self::from_hmac(&*self.chain_code, &*data)
    }

    /// 番号を順にたどって子孫を導出する。
    pub fn derive_path(&self, path: &[u32]) -> Self {
        path.iter()
            .fold(self.clone(), |node, &index| node.derive(index))
    }

    pub fn private_key(&self) -> PrivateKey {
        PrivateKey::from_bytes(&self.private_key)
    }

    /// HMAC-SHA512 の前半を秘密鍵に、後半をチェーンコードにする。
    fn from_hmac(key: &[u8], data: &[u8]) -> Self {
        let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC takes a key of any length");
        mac.update(data);
        let mut output = Zeroizing::new([0; 64]);
        mac.finalize_into(
            (&mut output[..])
                .try_into()
                .expect("SHA-512 outputs 64 bytes"),
        );
        let mut private_key = Zeroizing::new([0; 32]);
        let mut chain_code = Zeroizing::new([0; 32]);
        private_key.copy_from_slice(&output[..32]);
        chain_code.copy_from_slice(&output[32..]);
        Self {
            private_key,
            chain_code,
        }
    }
}

impl std::fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtendedKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heika_core::key::PublicKey;

    // SLIP-10 の文書にある ed25519 のテストベクター 1
    const SEED: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    fn assert_keys(key: &ExtendedKey, private_key: &str, public_key: &str) {
        let private = key.private_key();
        assert_eq!(*private.to_hex(), private_key);
        assert_eq!(
            PublicKey::from_private_key(&private).to_string(),
            public_key
        );
    }

    #[test]
    fn derives_the_root_from_the_seed() {
        assert_keys(
            &ExtendedKey::from_seed(&SEED),
            "2B4BE7F19EE27BBF30C667B642D5F4AA69FD169872F8FC3059C08EBAE2EB19E7",
            "A4B2856BFEC510ABAB89753FAC1AC0E1112364E7D250545963F135F2A33188ED",
        );
    }

    #[test]
    fn derives_hardened_children() {
        let root = ExtendedKey::from_seed(&SEED);
        assert_keys(
            &root.derive(0),
            "68E0FE46DFB67E368C75379ACEC591DAD19DF3CDE26E63B93A8E704F1DADE7A3",
            "8C8A13DF77A28F3445213A0F432FDE644ACAA215FC72DCDF300D5EFAA85D350C",
        );
        assert_keys(
            &root.derive_path(&[0, 1]),
            "B1D0BAD404BF35DA785A64CA1AC54B2617211D2777696FBFFAF208F746AE84F2",
            "1932A5270F335BED617D5B935C80AEDB1A35BD9FC1E31ACAFD5372C30F5C1187",
        );
    }

    #[test]
    fn treats_indices_with_the_hardened_bit_the_same() {
        let root = ExtendedKey::from_seed(&SEED);
        assert_eq!(
            *root.derive(0x8000_0001).private_key().to_hex(),
            *root.derive(1).private_key().to_hex()
        );
    }

    #[test]
    fn empty_path_is_the_node_itself() {
        let root = ExtendedKey::from_seed(&SEED);
        assert_eq!(
            *root.derive_path(&[]).private_key().to_hex(),
            *root.private_key().to_hex()
        );
    }

    #[test]
    fn symbol_path_uses_the_coin_type_of_the_network() {
        assert_eq!(
            symbol_path(NetworkIdentifier::MAINNET, 2),
            [44, 4343, 2, 0, 0]
        );
        assert_eq!(symbol_path(NetworkIdentifier::TESTNET, 2), [44, 1, 2, 0, 0]);
    }

    #[test]
    fn debug_hides_the_key() {
        assert_eq!(
            format!("{:?}", ExtendedKey::from_seed(&SEED)),
            "ExtendedKey(..)"
        );
    }
}
