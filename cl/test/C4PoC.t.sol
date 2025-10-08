// SPDX-License-Identifier: MIT
pragma solidity 0.8.13;

import "forge-std/Test.sol";

import {C4PoCTestbed} from "./C4PoCTestbed.t.sol";
import "./helpers/MockERC20.sol";

contract C4PoC is C4PoCTestbed {
    function setUp() public override {
        super.setUp();
    }

    function test_submissionValidity() external {
        // Create two mock ERC20 tokens
        MockERC20 token1 = new MockERC20("Token1", "TKN1", 18);
        MockERC20 token2 = new MockERC20("Token2", "TKN2", 18);
        MockERC20 token3 = new MockERC20("Token3", "TKN3", 18);

        // Mint some tokens for the user
        token1.mint(address(this), 1_000_000e18);
        token2.mint(address(this), 1_000_000e18);
        token3.mint(address(this), 1_000_000e18);

        // Whitelist tokens
        vm.startPrank(permissionsRegistry.hybraTeamMultisig());
        tokenHandler.addToken(address(token1), true);
        tokenHandler.addToken(address(token2), true);
        tokenHandler.addToken(address(token3), true);
        vm.stopPrank();

        // Create two pools
        address pool1 = thenaFiFactory.createPair(
            address(token1),
            address(token2)
        );
        address pool2 = thenaFiFactory.createPair(
            address(token1),
            address(token3)
        );

        // Create gauges for the pools
        vm.startPrank(permissionsRegistry.hybraTeamMultisig());
        address gauge1 = gaugeManager.createGauge(pool1, 0);
        address gauge2 = gaugeManager.createGauge(pool2, 0);
        vm.stopPrank();

        // Kill the first gauge
        vm.startPrank(permissionsRegistry.hybraMultisig());
        gaugeManager.killGauge(gauge1);
        vm.stopPrank();

        // Create a lock
        hybr.approve(address(votingEscrow), 1_000e18);
        uint256 tokenId = votingEscrow.create_lock(1_000e18, 86400 * 365 * 4);

        // Vote
        address[] memory pools = new address[](2);
        pools[0] = pool1;
        pools[1] = pool2;

        uint256[] memory weights = new uint256[](2);
        weights[0] = 5000;
        weights[1] = 5000;

        vm.warp(block.timestamp + 86400 * 8); // Move to the next epoch
        voter.vote(tokenId, pools, weights);

        // Check the vote weight
        uint256 totalWeightForPool2 = voter.weights(pool2);
        uint256 expectedWeight = votingEscrow.balanceOfNFT(tokenId) / 2;

        // The weight for the alive gauge should be half of the total voting power
        assertEq(
            totalWeightForPool2,
            expectedWeight,
            "Vote weight should be distributed correctly"
        );
    }
}
