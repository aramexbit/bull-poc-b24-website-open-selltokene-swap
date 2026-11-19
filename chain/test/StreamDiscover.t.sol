// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Mocks.sol";

// ROUND 12 — Team A (forge / on-chain).
// Discovery probe of the LIVE stream contract 0xF02aD48D7Ae63F17941E78AAF228C1450Db13891
// (bytecode work/live-api-round11-a/stream-code.hex, etched verbatim).
// Goal: identify every selector's arity/shape + access control, then test
// whether any caller can steal or lock funds. Throwaway Anvil keys only.
contract StreamDiscoverTest is Test {
    address constant STREAM = 0xF02aD48D7Ae63F17941E78AAF228C1450Db13891;
    address constant BURNER = 0x1B3b7abb6553a1bbc9B285E6ab3F2012e88e4d5f;
    address constant FEE_SIGNER = 0x585770c10434fA6D434b6B27316354f9D1688bd0;

    uint256 constant PAYER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant PAYEE_PK = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant ARB_PK = 0x47e179ec1974f892c2cd3b0cf1a4ec6a36e72a0a0d26ccaa2aa5c8ad6b9b47a8;
    address payer; address payee; address arbiter;
    MockERC20 token;

    function setUp() public {
        vm.chainId(4663);
        payer = vm.addr(PAYER_PK);
        payee = vm.addr(PAYEE_PK);
        arbiter = vm.addr(ARB_PK);
        vm.etch(STREAM, vm.parseBytes(vm.readFile("bytecode/stream.hex")));
        token = new MockERC20();
        token.mint(payer, 1000000 ether);
        vm.deal(payer, 100 ether);
        vm.deal(payee, 10 ether);
        vm.deal(arbiter, 10 ether);
        vm.warp(1000);
    }

    function _call(bytes memory data) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = STREAM.call(data);
    }
    function _log(string memory name, bytes4 sel, bool ok, bytes memory ret) internal {
        emit log_named_string("fn", name);
        emit log_named_bytes32("sel", bytes32(sel));
        emit log_named_uint("ok", ok ? 1 : 0);
        emit log_named_uint("retlen", ret.length);
        if (ret.length >= 32) emit log_named_bytes32("ret0", abi.decode(ret, (bytes32)));
        if (ret.length >= 64) emit log_named_bytes32("ret1", abi.decode(_slice(ret, 32), (bytes32)));
    }
    function _slice(bytes memory b, uint256 off) internal pure returns (bytes memory) {
        bytes memory out = new bytes(b.length - off);
        for (uint256 i; i < out.length; i++) out[i] = b[off + i];
        return out;
    }

    // --- no-arg getters ---
    function testDiscoverNoArgGetters() public {
        bytes4[5] memory sels = [bytes4(0x07569339), bytes4(0x61d027b3), bytes4(0x61b8ce8c), bytes4(0xb1724b46), bytes4(0xbc063e1a)];
        string[5] memory names = ["feeSigner", "treasury", "nextId", "UNK_b1724b46", "UNK_bc063e1a"];
        for (uint256 i; i < sels.length; i++) {
            (bool ok, bytes memory ret) = _call(abi.encodeWithSelector(sels[i]));
            _log(names[i], sels[i], ok, ret);
        }
    }

    // --- single-uint256 views on stream id 0/1 (no streams exist yet) ---
    function testDiscoverUintViews() public {
        bytes4[5] memory sels = [bytes4(0x2d94d8b5), bytes4(0x968fb8ba), bytes4(0xf11988e0), bytes4(0x28079e4a), bytes4(0x409fa6b8)];
        string[5] memory names = ["stream", "vested", "withdrawable", "UNK_28079e4a", "UNK_409fa6b8"];
        for (uint256 i; i < sels.length; i++) {
            (bool ok, bytes memory ret) = _call(abi.encodeWithSelector(sels[i], uint256(1)));
            _log(string(abi.encodePacked(names[i], "(1)")), sels[i], ok, ret);
            (ok, ret) = _call(abi.encodeWithSelector(sels[i]));
            _log(string(abi.encodePacked(names[i], "(noarg)")), sels[i], ok, ret);
        }
    }

    // --- struct-arg unknowns: try a 6-word tuple and a 2-word tuple ---
    function testDiscoverStructUnknowns() public {
        bytes4[3] memory sels = [bytes4(0x1e83409a), bytes4(0xadfecd8a), bytes4(0x7257808e)];
        string[3] memory names = ["UNK_1e83409a", "UNK_adfecd8a", "createStream?"];
        for (uint256 i; i < sels.length; i++) {
            // 6-word tuple: (payee, token, amount, start, end, arbiter)
            bytes memory six = abi.encode(payee, address(token), uint256(1000 ether), uint256(1000), uint256(1000 + 86400), arbiter);
            (bool ok, bytes memory ret) = _call(abi.encodePacked(sels[i], six));
            _log(string(abi.encodePacked(names[i], " 6word")), sels[i], ok, ret);
            // single struct offset + tuple (ABI tuple encoding)
            bytes memory tup = abi.encodeWithSelector(sels[i], abi.encode(payee, address(token), uint256(1000 ether), uint256(1000), uint256(1000 + 86400), arbiter));
            (ok, ret) = _call(tup);
            _log(string(abi.encodePacked(names[i], " tuple")), sels[i], ok, ret);
        }
    }
}
