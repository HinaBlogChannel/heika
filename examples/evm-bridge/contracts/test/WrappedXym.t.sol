// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {WrappedXym} from "../src/WrappedXym.sol";

/// 発行は見張り役の署名が要るので、正しい署名での発行は anvil に置いて Rust から確かめる。ここでは弾くほうを見る
contract WrappedXymTest {
    // FrostSecp256k1Test と同じ鍵と署名（別のメッセージへの署名なので、発行には使えない）
    uint256 constant PX = 0x35311ed2f953d38179fab3fd84b1bab6c021c9c54f4d9c5f0772f7fedc6c6acc;
    uint256 constant RX = 0x5449845599eed4e7f7de18e4c99b009514faae136ce44b1d9f513e7fe2d86ccc;
    uint256 constant RY = 0xa4dcdb7c8974713aef5f7175d92adb820505210d5eaa454beade7d35d84bb959;
    uint256 constant Z = 0x6d1fca58dcf09a59aa1e2aba6b0db0c648077250ddcb35ca1a1951c6f89b0e7a;

    function testRejectsKeyOutOfRange() public {
        try new WrappedXym(type(uint256).max, 0) {
            revert("accepted x >= n");
        } catch (bytes memory reason) {
            require(bytes4(reason) == WrappedXym.InvalidKey.selector, "wrong error");
        }
    }

    function testRejectsMintWithSignatureForOtherMessage() public {
        WrappedXym token = new WrappedXym(PX, 0);
        try token.mint(address(this), 1, bytes32(0), RX, RY, Z) {
            revert("minted with a wrong signature");
        } catch (bytes memory reason) {
            require(bytes4(reason) == WrappedXym.InvalidSignature.selector, "wrong error");
        }
        require(token.totalSupply() == 0, "supply changed");
    }

    function testRejectsKeyChangeWithSignatureForOtherMessage() public {
        WrappedXym token = new WrappedXym(PX, 0);
        try token.changeKey(RX, 0, RX, RY, Z) {
            revert("changed the key with a wrong signature");
        } catch (bytes memory reason) {
            require(bytes4(reason) == WrappedXym.InvalidSignature.selector, "wrong error");
        }
        require(token.keyX() == PX && token.keyEpoch() == 0, "key changed");
    }

    function testBurnNeedsBalance() public {
        WrappedXym token = new WrappedXym(PX, 0);
        try token.burn(1, bytes24(0)) {
            revert("burned without balance");
        } catch (bytes memory reason) {
            require(bytes4(reason) == WrappedXym.InsufficientBalance.selector, "wrong error");
        }
        require(token.burns() == 0, "burn counted");
    }
}
