//! ネットワークの識別子と、ネットワークごとに決まっている値。
//! catapult の `model/NetworkIdentifier.h` と、ノードの `config-network.properties`。

use core::fmt;
use core::str::FromStr;
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hash::Hash256;
use crate::hex::{self, ParseHexError};
/// アドレスやエンティティの先頭に入る1バイト。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NetworkIdentifier(pub u8);

impl NetworkIdentifier {
    /// メインネット。アドレスは N から始まる。
    pub const MAINNET: Self = Self(0x68);
    /// テストネット。アドレスは T から始まる。
    pub const TESTNET: Self = Self(0x98);
}

/// ネットワークごとに決まる32バイト。catapult の `GenerationHashSeed`。
/// トランザクションの署名とハッシュに混ぜて、別のネットワークで使い回せないようにする。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenerationHashSeed(pub [u8; 32]);

impl GenerationHashSeed {
    /// メインネット。
    pub const MAINNET: Self = Self(hex::decode_const(
        b"57F7DA205008026C776CB6AED843393F04CD458E0AA2D9F1D5F31A402072B2D6",
    ));
    /// テストネット。
    pub const TESTNET: Self = Self(hex::decode_const(
        b"49D6E1CE276A85B70EAFE52349AACCA389302E7A9754BCF1221E79494FC665A4",
    ));
}

impl fmt::Display for GenerationHashSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for GenerationHashSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GenerationHashSeed({self})")
    }
}

impl FromStr for GenerationHashSeed {
    type Err = ParseHexError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        hex::decode(text).map(Self)
    }
}

/// ネットワーク時刻。Nemesis の時刻（ネットワークのエポック）からのミリ秒。catapult の `Timestamp`。
/// トランザクションの期限やブロックの時刻は、これで書く。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NetworkTimestamp(pub u64);

impl NetworkTimestamp {
    /// `duration` だけ後の時刻。ミリ秒より細かいところは切り捨てる。u64 に収まらなければ `None`。
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let milliseconds = u64::try_from(duration.as_millis()).ok()?;
        self.0.checked_add(milliseconds).map(Self)
    }

    /// `duration` だけ前の時刻。ミリ秒より細かいところは切り上げる（前に戻しすぎない）。エポックより前なら `None`。
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        let milliseconds = u64::try_from(duration.as_nanos().div_ceil(1_000_000)).ok()?;
        self.0.checked_sub(milliseconds).map(Self)
    }

    /// `earlier` からの経過。`earlier` のほうが後なら `None`。
    pub fn duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_millis)
    }
}

/// ネットワークごとに決まっている値のうち、heika が使うもの。catapult ではノードの `config-network.properties` に書かれ、
/// フィールドの名前の後ろに、そこでの名前を添える。メインネットとテストネットの値は、それぞれのノードの設定から写した。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NetworkParameters {
    /// `identifier`
    pub identifier: NetworkIdentifier,
    /// `generationHashSeed`
    pub generation_hash_seed: GenerationHashSeed,
    /// `epochAdjustment`。Nemesis の時刻の Unix 時刻で、トランザクションの期限はここからのミリ秒で数える
    pub epoch_adjustment: Duration,
    /// `currencyMosaicId`
    pub currency_mosaic_id: u64,
    /// `blockGenerationTargetTime`
    pub block_generation_target_time: Duration,
    /// `blockTimeSmoothingFactor`。ブロックの間隔が目標から外れたときに、ハーベストの的をどれだけ動かすか（1000 で 1 倍）
    pub block_time_smoothing_factor: u64,
    /// `maxDifficultyBlocks`。難易度を決めるのに見る、直前のブロックの数
    pub max_difficulty_blocks: usize,
    /// `totalChainImportance`。Importance の合計
    pub total_chain_importance: u64,
    /// `importanceGrouping`。この高さの倍数のブロックが、Importance を計算し直すブロックになる
    pub importance_grouping: u64,
    /// `maxTransactionLifetime`
    pub max_transaction_lifetime: Duration,
    /// `maxCosignaturesPerAggregate`。外側の署名も数える
    pub max_cosignatures_per_aggregate: usize,
    /// `maxTransactionsPerAggregate`
    pub max_transactions_per_aggregate: usize,
    /// `maxMessageSize`。転送のメッセージのバイト数の上限
    pub max_message_size: usize,
    /// `maxHashLockDuration`
    pub max_hash_lock_duration: Duration,
    /// `maxSecretLockDuration`
    pub max_secret_lock_duration: Duration,
    /// `minProofSize`。シークレットプルーフのプルーフのバイト数の下限
    pub min_proof_size: usize,
    /// `maxProofSize`
    pub max_proof_size: usize,
    /// `maxValueSize`。メタデータの値のバイト数の上限
    pub max_metadata_value_size: usize,
    /// `maxNameSize`。ネームスペースの名前のバイト数の上限
    pub max_namespace_name_size: usize,
    /// `minNamespaceDuration`。ルートのネームスペースを取る期間の下限
    pub min_namespace_duration: Duration,
    /// `maxNamespaceDuration`
    pub max_namespace_duration: Duration,
    /// `votingSetGrouping`。ファイナライズのエポック1つぶんのブロック数
    pub voting_set_grouping: u64,
    /// `minVotingKeyLifetime`。投票鍵の期間（エポック数）の下限
    pub min_voting_key_lifetime: u32,
    /// `maxVotingKeyLifetime`。投票鍵の期間（エポック数）の上限
    pub max_voting_key_lifetime: u32,
    /// `maxVotingKeysPerAccount`
    pub max_voting_keys_per_account: usize,
    /// `[fork_heights]`
    pub fork_heights: ForkHeights,
    /// `[corrupt_aggregate_transaction_hashes]`。（アグリゲートのハッシュ、その TransactionsHash）の組。
    /// バージョン 1 のアグリゲートのうち、許されていたどの誤った求め方でも説明できない TransactionsHash を、1件ずつ認めたもの
    pub corrupt_aggregate_transaction_hashes: &'static [(Hash256, Hash256)],
}

/// フォークした高さ。`[fork_heights]` のうち、heika が使うもの。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ForkHeights {
    /// `strictAggregateTransactionHash`。この高さから、アグリゲートはバージョン 2 だけになる
    pub strict_aggregate_transaction_hash: u64,
    /// `uniqueAggregateTransactionHash`。この高さから、アグリゲートはバージョン 3 だけになる
    pub unique_aggregate_transaction_hash: u64,
}

/// 1日の秒数。設定の `2d` のような期間を書くのに使う。
const DAY: u64 = 24 * 60 * 60;

impl NetworkParameters {
    pub const MAINNET: Self = Self {
        identifier: NetworkIdentifier::MAINNET,
        generation_hash_seed: GenerationHashSeed::MAINNET,
        // 2021-03-16T00:06:25Z
        epoch_adjustment: Duration::from_secs(1_615_853_185),
        currency_mosaic_id: 0x6BED_913F_A202_23F8,
        block_generation_target_time: Duration::from_secs(30),
        block_time_smoothing_factor: 3000,
        max_difficulty_blocks: 60,
        total_chain_importance: 7_842_928_625_000_000,
        importance_grouping: 720,
        max_transaction_lifetime: Duration::from_secs(6 * 60 * 60),
        max_cosignatures_per_aggregate: 25,
        max_transactions_per_aggregate: 100,
        max_message_size: 1024,
        max_hash_lock_duration: Duration::from_secs(2 * DAY),
        max_secret_lock_duration: Duration::from_secs(365 * DAY),
        min_proof_size: 0,
        max_proof_size: 1024,
        max_metadata_value_size: 1024,
        max_namespace_name_size: 64,
        min_namespace_duration: Duration::from_secs(30 * DAY),
        max_namespace_duration: Duration::from_secs(1825 * DAY),
        voting_set_grouping: 1440,
        min_voting_key_lifetime: 112,
        max_voting_key_lifetime: 360,
        max_voting_keys_per_account: 3,
        fork_heights: ForkHeights {
            strict_aggregate_transaction_hash: 1_690_500,
            unique_aggregate_transaction_hash: 4_759_100,
        },
        corrupt_aggregate_transaction_hashes: &MAINNET_CORRUPT_AGGREGATE_TRANSACTION_HASHES,
    };

    pub const TESTNET: Self = Self {
        identifier: NetworkIdentifier::TESTNET,
        generation_hash_seed: GenerationHashSeed::TESTNET,
        // 2022-10-31T21:07:47Z
        epoch_adjustment: Duration::from_secs(1_667_250_467),
        currency_mosaic_id: 0x72C0_212E_67A0_8BCE,
        block_generation_target_time: Duration::from_secs(30),
        block_time_smoothing_factor: 3000,
        max_difficulty_blocks: 60,
        total_chain_importance: 7_842_928_625_000_000,
        importance_grouping: 180,
        max_transaction_lifetime: Duration::from_secs(6 * 60 * 60),
        max_cosignatures_per_aggregate: 25,
        max_transactions_per_aggregate: 100,
        max_message_size: 1024,
        max_hash_lock_duration: Duration::from_secs(2 * DAY),
        max_secret_lock_duration: Duration::from_secs(365 * DAY),
        min_proof_size: 0,
        max_proof_size: 1024,
        max_metadata_value_size: 1024,
        max_namespace_name_size: 64,
        min_namespace_duration: Duration::from_secs(30 * DAY),
        max_namespace_duration: Duration::from_secs(1825 * DAY),
        voting_set_grouping: 720,
        min_voting_key_lifetime: 28,
        max_voting_key_lifetime: 720,
        max_voting_keys_per_account: 3,
        fork_heights: ForkHeights {
            strict_aggregate_transaction_hash: 0,
            unique_aggregate_transaction_hash: 2_742_000,
        },
        corrupt_aggregate_transaction_hashes: &[],
    };

    /// 識別子が同じものを、知っているネットワークから探す。
    pub fn from_identifier(identifier: NetworkIdentifier) -> Option<&'static Self> {
        [&Self::MAINNET, &Self::TESTNET]
            .into_iter()
            .find(|parameters| parameters.identifier == identifier)
    }

    /// Nemesis の時刻。
    #[cfg(feature = "std")]
    pub fn epoch(&self) -> SystemTime {
        UNIX_EPOCH + self.epoch_adjustment
    }

    /// 期間をブロック数にする。catapult の `BlockSpan::blocks` と同じく、blockGenerationTargetTime で割って切り捨てる。
    pub fn blocks(&self, duration: Duration) -> u64 {
        let blocks = duration.as_millis() / self.block_generation_target_time.as_millis();
        u64::try_from(blocks).unwrap_or(u64::MAX)
    }

    /// ふつうの時刻をネットワーク時刻にする。ミリ秒より細かいところは切り捨てる。
    /// エポックより前か、u64 のミリ秒に収まらなければ `None`。
    #[cfg(feature = "std")]
    pub fn timestamp_at(&self, time: SystemTime) -> Option<NetworkTimestamp> {
        let elapsed = time.duration_since(self.epoch()).ok()?;
        u64::try_from(elapsed.as_millis())
            .ok()
            .map(NetworkTimestamp)
    }

    /// ネットワーク時刻をふつうの時刻にする。OS の時刻で表せなければ `None`。
    #[cfg(feature = "std")]
    pub fn time_of(&self, timestamp: NetworkTimestamp) -> Option<SystemTime> {
        self.epoch().checked_add(Duration::from_millis(timestamp.0))
    }

    /// その高さのブロックが入る、ファイナライズのエポック。catapult の `CalculateFinalizationEpochForHeight`。
    /// エポック 1 は高さ 1 だけで、そのあとは votingSetGrouping ごとに区切り、区切りの高さはその前のエポックに入る。
    pub fn finalization_epoch(&self, height: u64) -> u64 {
        if height <= 1 {
            return 1;
        }
        let adjustment = u64::from(!height.is_multiple_of(self.voting_set_grouping));
        1 + adjustment + height / self.voting_set_grouping
    }

    /// その高さのブロックに入れられるアグリゲートのバージョン。
    /// catapult の `AggregateTransactionVersionValidator` と同じく、1つのバージョンだけが認められる。
    pub fn aggregate_version(&self, height: u64) -> u8 {
        if height >= self.fork_heights.unique_aggregate_transaction_hash {
            3
        } else if height >= self.fork_heights.strict_aggregate_transaction_hash {
            2
        } else {
            1
        }
    }

    /// バージョン 1 のアグリゲートの TransactionsHash が、`[corrupt_aggregate_transaction_hashes]` で認められているか。
    pub fn is_known_corrupt_aggregate(
        &self,
        aggregate_hash: &Hash256,
        transactions_hash: &Hash256,
    ) -> bool {
        self.corrupt_aggregate_transaction_hashes
            .contains(&(*aggregate_hash, *transactions_hash))
    }
}

/// メインネットの `[corrupt_aggregate_transaction_hashes]`。バージョン 1 のアグリゲートは
/// 高さ 1,690,500 からは認められないので、この表はもう増えない。
const MAINNET_CORRUPT_AGGREGATE_TRANSACTION_HASHES: [(Hash256, Hash256); 20] = [
    (
        Hash256(hex::decode_const(
            b"26FF5E7174DEEF3147DB25C37C7AE9905157ACBA2D233D40D1F77A65B60D59BC",
        )),
        Hash256(hex::decode_const(
            b"3A2F78C2E7B10FF84EB33BF1DD0FD61951F8E3EA3303614D1B20060CD88F6E14",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"2DF1D19B5E68102665D11B3CF3069AB5DFED2E60A7690C8788172E0E5E30B72D",
        )),
        Hash256(hex::decode_const(
            b"3B64321593D06FF37B191F52FE31E107A8FDB0116AB5374157F8F415B8C73BE4",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"30FA71E6D1E34DF1E430A07E1B0817BED9A4ED6B0245B7471B0557380A700E1B",
        )),
        Hash256(hex::decode_const(
            b"AE377EAB7F1970DEC21FF305C39EBDD3ECE413B911EF3E4E11F7DDDC9C9C9748",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"33937869216924161235BA8E10DC075592022C22F6593042A1064ADD24B64FE8",
        )),
        Hash256(hex::decode_const(
            b"9C00D552960DEDC38A009B541681B2C7A68902D94A9D6C089604D2E7EFCCD88E",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"55EB9659C81600F1760C4C0A4F8A7A5C90A39FCEE36E3165143B8E72BBC709E8",
        )),
        Hash256(hex::decode_const(
            b"8980CF4407A48410C4E910FE766C135F8C3C84EA9917BFDB7A71434C2CDC625A",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"8090FFF457D88D98ACFDA7872DAAD1A901B4CB081387B1A45AFDA8EEF686EB54",
        )),
        Hash256(hex::decode_const(
            b"05718908AFBA83B420AE19BE0A11EE36119AC960353BA6C3F180078C8C4B428D",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"852A41F9452A34054DE1C21E46F925EA7B50D26AF97FBA8D745F01CC6DD5097F",
        )),
        Hash256(hex::decode_const(
            b"8626BB52F6457D95B01A5C178E6A6977F8BD418CD9A7D5B0A814210E0A4FBBA3",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"8BAA5EC2DDF55EE583ABB7EA4A4FE6EB8A4C16C41ED30CB1E68F6D1F40C3FC5A",
        )),
        Hash256(hex::decode_const(
            b"59850BF728A08555D10DAD5745EE2A349FECC0B16810F5D32CF3DFC376DEFFE1",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"8CE147B1B64E200FA48B17FE5B6F4FA2FFEC83FF03A1EC0D4725AB8122AF5B05",
        )),
        Hash256(hex::decode_const(
            b"1F3D4045C3482A9EED536F61CAA58284323037B72A9A774A0C75932F85999B0F",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"91C27BE7E5AC8EBCE6A5D576DE250054A3CDC2B674BAD5FA29B554C0A50E2973",
        )),
        Hash256(hex::decode_const(
            b"05718908AFBA83B420AE19BE0A11EE36119AC960353BA6C3F180078C8C4B428D",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"97CA49FCE55644FF28248C6EA4DCB6E87E53909811DEE2513F0218DAA394679F",
        )),
        Hash256(hex::decode_const(
            b"657BE411624B617F51CD8D151735F50FE50A91A5B7D0658192EF3EC4DD0C91C3",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"B2813813F709C3011468E23E61AE102BCB55A28A87D0CF74968B8BD2413615AA",
        )),
        Hash256(hex::decode_const(
            b"3FEF96C5496E60BC1D33815139BDCD4FA707CE1C2A9A25FF4F7D3B1BE698116C",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"B35D60C826470EB38B6963DCEF5A9FE406EDE405676EDB027956999D7618998D",
        )),
        Hash256(hex::decode_const(
            b"D8915C7EFFDB62B3CB5872597522C0920AF5D55EC44A4548DF8679C08A0C0541",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"BC312549DB027287836AD52B6EA30171AA1958B20BEB3D659F843D699DE45FD3",
        )),
        Hash256(hex::decode_const(
            b"4AC4B12DE7C5B0D02BFFEA3ED98F4247FAFF701C4CE0A2CFD75E7F633DB0ED60",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"BDF7755E44E1405C3353AB97651DD82785C6A3A8EAA5EA1CEA0E30DADB0D12F8",
        )),
        Hash256(hex::decode_const(
            b"B6D02DA3F69C20F69A9209B13192174091544512CD7D2CE53C366909B354B7B1",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"C0FAAD2439E9D8017F9A2E5F67A46850195209402C1EE55CF99880426D0F454F",
        )),
        Hash256(hex::decode_const(
            b"3B74892D50665E4A989C89EDCE88905937B81BF260A679653E86886407812F83",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"C1E7404CDAE41ACE07E8649FA2D5E3E2FF5DA502E43E5D1C6073192823F90BE6",
        )),
        Hash256(hex::decode_const(
            b"A7321E82547506079C0692DC0DFF8C9CB0D56DD2C9E3208F479DB8970B985E6C",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"D24D000FABBD1AC4BC21006A5CAE76AE9C32792A4920F66D6A6C6F76B438BDF1",
        )),
        Hash256(hex::decode_const(
            b"5FDEF85E8B3669FF155B5F3DA98288C6ED8A293CC699338ADB743C0F5E8614ED",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"D91689D6A3C9FE7AABB45C3FC44373DA23EF363D71360CB4B7ECD74F0BDE893B",
        )),
        Hash256(hex::decode_const(
            b"D8915C7EFFDB62B3CB5872597522C0920AF5D55EC44A4548DF8679C08A0C0541",
        )),
    ),
    (
        Hash256(hex::decode_const(
            b"E14FB95DA63CDA9899474D7EFD0DCB6A6C9E8931DF12ECA01F22DF2B59B6624C",
        )),
        Hash256(hex::decode_const(
            b"342E7C1E6318F7DCE5CE5A09B8FA1820453C4437AEF1B872BD06531E3ADB41C0",
        )),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn converts_between_system_time_and_network_time() {
        let network = NetworkParameters::MAINNET;
        let epoch = network.epoch();
        assert_eq!(network.timestamp_at(epoch), Some(NetworkTimestamp(0)));
        // ミリ秒より細かいところは切り捨てる
        let later = epoch + Duration::from_micros(1_500_999);
        assert_eq!(network.timestamp_at(later), Some(NetworkTimestamp(1_500)));
        assert_eq!(
            network.time_of(NetworkTimestamp(1_500)),
            Some(epoch + Duration::from_millis(1_500))
        );
        // エポックより前は表せない
        assert_eq!(network.timestamp_at(epoch - Duration::from_millis(1)), None);
        // 同じ時刻でも、ネットワークごとにエポックが違う
        assert_ne!(
            NetworkParameters::TESTNET.timestamp_at(later),
            network.timestamp_at(later)
        );
    }

    #[test]
    fn converts_durations_to_blocks() {
        // メインネットの設定の 2d、365d、30d を、30秒のブロックで数えたもの
        let network = NetworkParameters::MAINNET;
        assert_eq!(network.blocks(network.max_hash_lock_duration), 5_760);
        assert_eq!(network.blocks(network.max_secret_lock_duration), 1_051_200);
        assert_eq!(network.blocks(network.min_namespace_duration), 86_400);
        // 端数は切り捨てる
        assert_eq!(network.blocks(Duration::from_secs(59)), 1);
    }

    #[test]
    fn adds_and_subtracts_durations() {
        let deadline = NetworkTimestamp(1_000);
        assert_eq!(
            deadline.checked_add(Duration::from_secs(2 * 60 * 60)),
            Some(NetworkTimestamp(1_000 + 7_200_000))
        );
        assert_eq!(
            deadline.checked_add(Duration::from_micros(1_999)),
            Some(NetworkTimestamp(1_001))
        );
        assert_eq!(
            deadline.checked_sub(Duration::from_micros(1_001)),
            Some(NetworkTimestamp(998))
        );
        assert_eq!(deadline.checked_sub(Duration::from_millis(1_001)), None);
        assert_eq!(
            NetworkTimestamp(u64::MAX).checked_add(Duration::from_millis(1)),
            None
        );
        assert_eq!(
            NetworkTimestamp(1_500).duration_since(deadline),
            Some(Duration::from_millis(500))
        );
        assert_eq!(deadline.duration_since(NetworkTimestamp(1_500)), None);
    }

    #[test]
    fn finds_parameters_by_identifier() {
        assert_eq!(
            NetworkParameters::from_identifier(NetworkIdentifier::MAINNET),
            Some(&NetworkParameters::MAINNET)
        );
        assert_eq!(
            NetworkParameters::from_identifier(NetworkIdentifier::TESTNET),
            Some(&NetworkParameters::TESTNET)
        );
        assert_eq!(
            NetworkParameters::from_identifier(NetworkIdentifier(0)),
            None
        );
    }

    #[test]
    fn groups_heights_into_finalization_epochs() {
        let mainnet = NetworkParameters::MAINNET;
        assert_eq!(mainnet.finalization_epoch(1), 1);
        assert_eq!(mainnet.finalization_epoch(2), 2);
        assert_eq!(mainnet.finalization_epoch(1440), 2);
        assert_eq!(mainnet.finalization_epoch(1441), 3);
        assert_eq!(mainnet.finalization_epoch(2880), 3);
        assert_eq!(NetworkParameters::TESTNET.finalization_epoch(721), 3);
    }

    #[test]
    fn allows_one_aggregate_version_per_height() {
        let mainnet = NetworkParameters::MAINNET;
        assert_eq!(mainnet.aggregate_version(1), 1);
        assert_eq!(mainnet.aggregate_version(1_690_499), 1);
        assert_eq!(mainnet.aggregate_version(1_690_500), 2);
        assert_eq!(mainnet.aggregate_version(4_759_099), 2);
        assert_eq!(mainnet.aggregate_version(4_759_100), 3);
        // テストネットは最初からバージョン 2
        assert_eq!(NetworkParameters::TESTNET.aggregate_version(1), 2);
    }

    #[test]
    fn looks_up_corrupt_aggregates_by_both_hashes() {
        let mainnet = NetworkParameters::MAINNET;
        let (aggregate, transactions) = mainnet.corrupt_aggregate_transaction_hashes[0];
        assert!(mainnet.is_known_corrupt_aggregate(&aggregate, &transactions));
        assert!(!mainnet.is_known_corrupt_aggregate(&aggregate, &aggregate));
        assert!(!NetworkParameters::TESTNET.is_known_corrupt_aggregate(&aggregate, &transactions));
    }
}
