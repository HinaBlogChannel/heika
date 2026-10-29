// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {FrostSecp256k1} from "./FrostSecp256k1.sol";

/// Symbol の預かり口座に入った XYM と同じ量だけ発行するトークン（ERC-20、小数 6 桁は XYM と同じ）。
///
/// 発行と鍵の差し替えは、見張り役で分けて持つ鍵（FROST）の署名 1 つで認める。誰が出してもいい。
/// 燃やすと Burn が出て、見張り役が預かり口座から Symbol のアドレスに送る。
contract WrappedXym {
    string public constant name = "Wrapped XYM";
    string public constant symbol = "wXYM";
    uint8 public constant decimals = 6;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// 見張り役の鍵（x 座標と y の偶奇）
    uint256 public keyX;
    uint8 public keyParity;
    /// 鍵を差し替えた回数。差し替えの署名を使い回せないように、署名するものに入れる
    uint256 public keyEpoch;
    /// 発行に使った、Symbol の入金のトランザクションのハッシュ
    mapping(bytes32 => bool) public minted;
    /// 次の Burn の番号
    uint256 public burns;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    /// Symbol の `recipient`（24 バイトのアドレス）に `amount` を送ってほしい
    event Burn(uint256 indexed id, address indexed from, bytes24 recipient, uint256 amount);
    event KeyChanged(uint256 epoch, uint256 x, uint8 parity);

    error InvalidKey();
    error InvalidSignature();
    error AlreadyMinted();
    error InsufficientBalance();
    error InsufficientAllowance();

    constructor(uint256 x, uint8 parity) {
        setKey(x, parity);
    }

    /// Symbol の入金 `deposit` の分を、`to` に発行する
    function mint(address to, uint256 amount, bytes32 deposit, uint256 rx, uint256 ry, uint256 z) external {
        if (minted[deposit]) revert AlreadyMinted();
        bytes32 digest = keccak256(abi.encode("mint", block.chainid, address(this), to, amount, deposit));
        if (!FrostSecp256k1.verify(keyX, keyParity, abi.encodePacked(digest), rx, ry, z)) revert InvalidSignature();
        minted[deposit] = true;
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    /// 燃やして、Symbol の `recipient` に送ってもらう
    function burn(uint256 amount, bytes24 recipient) external {
        if (balanceOf[msg.sender] < amount) revert InsufficientBalance();
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
        emit Burn(burns++, msg.sender, recipient, amount);
    }

    /// 見張り役の鍵を差し替える。今の鍵で署名する
    function changeKey(uint256 x, uint8 parity, uint256 rx, uint256 ry, uint256 z) external {
        bytes32 digest = keccak256(abi.encode("key", block.chainid, address(this), keyEpoch, x, parity));
        if (!FrostSecp256k1.verify(keyX, keyParity, abi.encodePacked(digest), rx, ry, z)) revert InvalidSignature();
        keyEpoch++;
        setKey(x, parity);
    }

    function setKey(uint256 x, uint8 parity) private {
        if (x == 0 || x >= FrostSecp256k1.N || parity > 1) revert InvalidKey();
        keyX = x;
        keyParity = parity;
        emit KeyChanged(keyEpoch, x, parity);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        move(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < value) revert InsufficientAllowance();
            allowance[from][msg.sender] = allowed - value;
        }
        move(from, to, value);
        return true;
    }

    function move(address from, address to, uint256 value) private {
        if (balanceOf[from] < value) revert InsufficientBalance();
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
