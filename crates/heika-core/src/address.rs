//! アドレス。catapult の `model/Address.cpp`。

use alloc::format;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use ripemd::Ripemd160;
use sha3::{Digest, Sha3_256};

use crate::base32;
use crate::hex::{self, ParseHexError};
use crate::key::PublicKey;
use crate::network::NetworkIdentifier;

/// 先頭1バイトのネットワーク、公開鍵の RIPEMD-160(SHA3-256) の20バイト、
/// その21バイトの SHA3-256 の先頭3バイト（チェックサム）を並べた24バイト。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 24]);

impl Address {
    pub const SIZE: usize = 24;
    /// Base32 にしたときの文字数
    pub const ENCODED_SIZE: usize = 39;
    const CHECKSUM_SIZE: usize = 3;

    pub fn from_public_key(public_key: &PublicKey, network: NetworkIdentifier) -> Self {
        let public_key_hash = Sha3_256::digest(public_key.0);
        let mut address = [0; Self::SIZE];
        address[0] = network.0;
        address[1..21].copy_from_slice(&Ripemd160::digest(public_key_hash));
        let checksum_begin = Self::SIZE - Self::CHECKSUM_SIZE;
        let checksum = Sha3_256::digest(&address[..checksum_begin]);
        address[checksum_begin..].copy_from_slice(&checksum[..Self::CHECKSUM_SIZE]);
        Self(address)
    }

    pub fn network(&self) -> NetworkIdentifier {
        NetworkIdentifier(self.0[0])
    }

    /// 末尾3バイトが、それより前の21バイトのチェックサムになっているか。
    /// catapult の `IsValidAddress` と同じく、ネットワーク自体は先頭のバイトを信じる。
    pub fn has_valid_checksum(&self) -> bool {
        let checksum_begin = Self::SIZE - Self::CHECKSUM_SIZE;
        Sha3_256::digest(&self.0[..checksum_begin])[..Self::CHECKSUM_SIZE]
            == self.0[checksum_begin..]
    }

    /// 24バイトを16進で書いたもの（48文字）から読む。REST はアドレスをこの形で返す。
    /// 公式の SDK の `from_decoded_address_hex_string` と違い、Base32 から読むときと同じくチェックサムも確かめる。
    pub fn from_hex(text: &str) -> Result<Self, ParseAddressError> {
        let address = Self(hex::decode(text).map_err(ParseAddressError::InvalidHex)?);
        if !address.has_valid_checksum() {
            return Err(ParseAddressError::InvalidChecksum);
        }
        Ok(address)
    }

    /// 24バイトを大文字の16進で書く。
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// Base32 は5バイト単位なので、catapult と同じく末尾に0を1バイト足して25バイトにし、
/// 40文字にしたうちの最後の1文字を落とす。
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut padded = [0; Self::SIZE + 1];
        padded[..Self::SIZE].copy_from_slice(&self.0);
        let mut encoded = base32::encode(&padded);
        encoded.pop();
        f.write_str(&encoded)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

/// catapult の `TryParseValue` と同じく、文字数、Base32、足した1バイトが0のままか、
/// チェックサムの順に確かめる。
impl FromStr for Address {
    type Err = ParseAddressError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let length = text.chars().count();
        if length != Self::ENCODED_SIZE {
            return Err(ParseAddressError::InvalidLength(length));
        }
        let padded = base32::decode(&format!("{text}A")).map_err(|(index, character)| {
            ParseAddressError::InvalidCharacter { index, character }
        })?;
        // 39文字目の下位3ビットが、足した1バイトに入る。0でなければ別の書き方になっている
        if padded[Self::SIZE] != 0 {
            return Err(ParseAddressError::NonCanonical);
        }
        let address = Self(padded[..Self::SIZE].try_into().expect("24 bytes"));
        if !address.has_valid_checksum() {
            return Err(ParseAddressError::InvalidChecksum);
        }
        Ok(address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAddressError {
    /// 39文字ではない
    InvalidLength(usize),
    /// Base32 の大文字の英字と2から7の数字ではない文字が含まれている
    InvalidCharacter {
        index: usize,
        character: char,
    },
    /// 最後の文字の下位ビットが0ではない
    NonCanonical,
    InvalidChecksum,
    /// 16進から読むときに、48文字の16進ではない
    InvalidHex(ParseHexError),
}

impl fmt::Display for ParseAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(length) => {
                write!(
                    f,
                    "アドレスは {} 文字のはずが {length} 文字でした",
                    Address::ENCODED_SIZE
                )
            }
            Self::InvalidCharacter { index, character } => {
                write!(
                    f,
                    "{index} 文字目の {character:?} は Base32 の文字ではありません"
                )
            }
            Self::NonCanonical => write!(f, "最後の文字が正規の書き方になっていません"),
            Self::InvalidChecksum => write!(f, "チェックサムが合いません"),
            Self::InvalidHex(error) => write!(f, "アドレスの16進として読めません: {error}"),
        }
    }
}

impl core::error::Error for ParseAddressError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// メインネットのブロック 2 の署名者。このブロックは報酬の受取人を自分自身にしているので、
    /// ヘッダーの BeneficiaryAddress がこの公開鍵のアドレスになっている。
    const BLOCK_2_SIGNER: &str = "79AF37ED4A98EF6C79F8C26992EA55ECEF74865827A1BBB602374C8F4F13DA07";
    const BLOCK_2_BENEFICIARY: &str = "68C32AB1A8FC9D5024A43787788879FE6D42A5490A614170";
    /// 上のアドレスを Base32 にしたもの
    const BLOCK_2_BENEFICIARY_ENCODED: &str = "NDBSVMNI7SOVAJFEG6DXRCDZ7ZWUFJKJBJQUC4A";

    fn block_2_beneficiary() -> Address {
        Address::from_public_key(&BLOCK_2_SIGNER.parse().unwrap(), NetworkIdentifier::MAINNET)
    }

    #[test]
    fn derives_the_beneficiary_of_mainnet_block_2_from_its_signer() {
        let address = block_2_beneficiary();
        assert_eq!(address.0, hex::decode(BLOCK_2_BENEFICIARY).unwrap());
        assert_eq!(address.network(), NetworkIdentifier::MAINNET);
        assert!(address.has_valid_checksum());
    }

    #[test]
    fn round_trips_through_hex() {
        let address = block_2_beneficiary();
        assert_eq!(address.to_hex(), BLOCK_2_BENEFICIARY);
        assert_eq!(Address::from_hex(BLOCK_2_BENEFICIARY), Ok(address));
        assert_eq!(
            Address::from_hex(&BLOCK_2_BENEFICIARY.to_lowercase()),
            Ok(address)
        );
        // 最後のバイトを変えると、チェックサムが合わない
        let mut changed = BLOCK_2_BENEFICIARY.to_owned();
        changed.replace_range(46.., "71");
        assert_eq!(
            Address::from_hex(&changed),
            Err(ParseAddressError::InvalidChecksum)
        );
        assert!(matches!(
            Address::from_hex(BLOCK_2_BENEFICIARY_ENCODED),
            Err(ParseAddressError::InvalidHex(_))
        ));
    }

    #[test]
    fn round_trips_through_base32() {
        let address = block_2_beneficiary();
        assert_eq!(address.to_string(), BLOCK_2_BENEFICIARY_ENCODED);
        assert_eq!(BLOCK_2_BENEFICIARY_ENCODED.parse(), Ok(address));
    }

    #[test]
    fn network_changes_the_whole_address() {
        let public_key = BLOCK_2_SIGNER.parse().unwrap();
        let mainnet = Address::from_public_key(&public_key, NetworkIdentifier::MAINNET);
        let testnet = Address::from_public_key(&public_key, NetworkIdentifier::TESTNET);
        assert!(testnet.to_string().starts_with('T'));
        // 先頭のバイトだけでなく、チェックサムも変わる
        assert_eq!(mainnet.0[1..21], testnet.0[1..21]);
        assert_ne!(mainnet.0[21..], testnet.0[21..]);
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            BLOCK_2_BENEFICIARY_ENCODED[..38].parse::<Address>(),
            Err(ParseAddressError::InvalidLength(38))
        );
    }

    #[test]
    fn rejects_lower_case() {
        assert_eq!(
            BLOCK_2_BENEFICIARY_ENCODED
                .to_lowercase()
                .parse::<Address>(),
            Err(ParseAddressError::InvalidCharacter {
                index: 0,
                character: 'n'
            })
        );
    }

    #[test]
    fn rejects_a_mistyped_character() {
        let mistyped = BLOCK_2_BENEFICIARY_ENCODED.replacen("NDBS", "NDBT", 1);
        assert_eq!(
            mistyped.parse::<Address>(),
            Err(ParseAddressError::InvalidChecksum)
        );
    }

    #[test]
    fn rejects_bits_beyond_the_24_bytes() {
        // 最後の文字の 'A' を 'B' にすると、24バイトのあとの余りのビットが立つ
        let mut text = BLOCK_2_BENEFICIARY_ENCODED.to_string();
        text.pop();
        text.push('B');
        assert_eq!(
            text.parse::<Address>(),
            Err(ParseAddressError::NonCanonical)
        );
    }
}
