// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {FrostSecp256k1} from "../src/FrostSecp256k1.sol";

/// Rust の frost-secp256k1 で、決まった乱数から作った 2-of-3 の署名（src/lib.rs のテストが、同じ値になることを確かめる）
contract FrostSecp256k1Test {
    uint256 constant PX = 0x35311ed2f953d38179fab3fd84b1bab6c021c9c54f4d9c5f0772f7fedc6c6acc;
    uint8 constant PARITY = 0;
    uint256 constant RX = 0x5449845599eed4e7f7de18e4c99b009514faae136ce44b1d9f513e7fe2d86ccc;
    uint256 constant RY = 0xa4dcdb7c8974713aef5f7175d92adb820505210d5eaa454beade7d35d84bb959;
    uint256 constant Z = 0x6d1fca58dcf09a59aa1e2aba6b0db0c648077250ddcb35ca1a1951c6f89b0e7a;

    function message() private pure returns (bytes memory) {
        return abi.encodePacked(bytes32(0x4242424242424242424242424242424242424242424242424242424242424242));
    }

    function testAcceptsRustSignature() public pure {
        require(FrostSecp256k1.verify(PX, PARITY, message(), RX, RY, Z), "rejected a valid signature");
    }

    function testRejectsOtherMessage() public pure {
        require(!FrostSecp256k1.verify(PX, PARITY, abi.encodePacked(bytes32(0)), RX, RY, Z), "accepted another message");
    }

    function testRejectsWrongParity() public pure {
        require(!FrostSecp256k1.verify(PX, 1 - PARITY, message(), RX, RY, Z), "accepted the negated key");
    }

    function testRejectsOtherZ() public pure {
        require(!FrostSecp256k1.verify(PX, PARITY, message(), RX, RY, Z + 1), "accepted another z");
    }

    function testRejectsOtherR() public pure {
        // R の y を反転した（−R）
        uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        require(!FrostSecp256k1.verify(PX, PARITY, message(), RX, p - RY, Z), "accepted -R");
    }
}
