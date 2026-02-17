// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/Exploit.sol";

contract Solve is Script {
    function run() external {
        // Use private key and setup address from environment variables
        uint256 privKey = vm.envUint("PRIVKEY");
        address setupAddr = vm.envAddress("SETUP_CONTRACT_ADDR");

        // Start broadcast transaction to network
        vm.startBroadcast(privKey);

        // 1. Deploy Exploit contract
        Exploit exploit = new Exploit(setupAddr);
        
        // 2. Execute pwn() func untuk to run flaw logic
        exploit.pwn();

        vm.stopBroadcast();
    }
}
