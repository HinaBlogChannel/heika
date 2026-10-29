// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

/// FROST(secp256k1, SHA-256)（RFC 9591）の署名を確かめる。
///
/// 署名は (R, z) で、z·G = R + e·P なら正しい。e はチャレンジで、R と公開鍵 P（どちらも圧縮した
/// 33 バイト）とメッセージをつないだものを、hash_to_field（RFC 9380 の expand_message_xmd、SHA-256、
/// 48 バイト）で位数 n で割った余りにしたもの。
///
/// 楕円曲線の計算は EVM にないので、ecrecover に肩代わりさせる。ecrecover(h, v, r, s) は、x 座標が r
/// の点 X について r⁻¹·(s·X − h·G) のアドレスを返す。X = P、h = −z·Px、s = −e·Px とすると、
/// z·G − e·P になる。これが R のアドレスと同じなら、署名は正しい。
library FrostSecp256k1 {
    /// secp256k1 の位数
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// チャレンジのハッシュのドメイン（"FROST-secp256k1-SHA256-v1" + "chal"）と、その長さ 29 バイト
    bytes internal constant DST_PRIME = "FROST-secp256k1-SHA256-v1chal\x1d";

    /// 公開鍵 P（x 座標と y の偶奇）で、`message` への署名 (R, z) を確かめる。R は y 座標まで渡す
    function verify(uint256 px, uint8 pyParity, bytes memory message, uint256 rx, uint256 ry, uint256 z)
        internal
        pure
        returns (bool)
    {
        // ecrecover の r は n 未満でないといけない。鍵を登録するときにも弾く
        if (px == 0 || px >= N || z == 0 || z >= N || pyParity > 1) {
            return false;
        }
        uint256 e = challenge(compress(rx, ry & 1), compress(px, pyParity), message);
        uint256 h = N - mulmod(z, px, N);
        uint256 s = N - mulmod(e, px, N);
        if (s == N) {
            return false;
        }
        address recovered = ecrecover(bytes32(h % N), 27 + pyParity, bytes32(px), bytes32(s));
        return recovered != address(0) && recovered == address(uint160(uint256(keccak256(abi.encodePacked(rx, ry)))));
    }

    function compress(uint256 x, uint256 parity) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(2 + parity), x);
    }

    /// H2（R ‖ P ‖ message）
    function challenge(bytes memory r, bytes memory p, bytes memory message) private pure returns (uint256) {
        bytes memory dst = DST_PRIME;
        // expand_message_xmd で 48 バイト（b1 の 32 バイトと、b2 の頭の 16 バイト）を作る
        bytes32 b0 = sha256(abi.encodePacked(bytes32(0), bytes32(0), r, p, message, uint16(48), uint8(0), dst));
        bytes32 b1 = sha256(abi.encodePacked(b0, uint8(1), dst));
        bytes32 b2 = sha256(abi.encodePacked(b0 ^ b1, uint8(2), dst));
        // 48 バイトを大きな整数として読み、n で割った余り
        return addmod(mulmod(uint256(b1), 1 << 128, N), uint256(b2) >> 128, N);
    }
}
