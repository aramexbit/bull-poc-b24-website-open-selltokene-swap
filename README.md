# PoC for Bull.family bug bounty report B-24

## Bull website `/d/` open forwards all server params without verification against the offer — malicious seller swaps sellToken and the buyer pays full price for a worthless token

**Report B-24** (K-654). Website under test: `https://www.bull.family/d/`
— chunk `page-16d1cf063b916c2c.js`, sha256 `4140f516…`, 12,878 bytes
(live 19 Nov 2026; included verbatim in this repo as
`website-deal-chunk.js` so the replica below can be checked against it).

### The bug

The website's deal-room page (`/d/`) opens an escrow deal without ever
checking what it is about to create against the offer the buyer is
looking at. In the chunk, the open function `M(e)` ("1. Open escrow
deal") does `POST /api/quote`, then passes the returned `a.params`
**verbatim** to `createDeal` (seller, sellerPayout, buyerReceive,
sellToken, sellAmount, payToken, payAmount, deadline). There is **not a
single comparison** — `buyerReceive` is not compared with the buyer's
wallet, `seller` is not compared with the offer's seller wallet,
`sellToken`/`payAmount` are not compared with the offer. The only
post-transaction check is that a `DealCreated` event exists.
`buyerReceive` appears 4× in the chunk (2× createDeal arguments, 2× ABI)
— and is never displayed in the UI. The fund function `V(e)` ("2. Pay")
takes the amount from the offer and calls `fundPayment(dealId)` — the
view function `deals()` is **never called** (0 occurrences in the chunk);
status, buyerReceive, sellerPayout and sellToken are never read before
paying. On the seller side, the website never signs an EIP-712 consent
at all (only EIP-191 messages for listing/proof); the consent is signed
outside the website via the SDK's `consent()`.

The attack needs NO compromised server. A malicious seller swaps
`sellToken` (a worthless token of their own) in their own consent; the
website creates the deal as-is; the buyer pays the full price and
receives the worthless token. The `buyerReceive` here is HONEST — the
fix for B-22 (checking buyerReceive) does not catch this, proven by
control P3 below.

**Measured (fresh Anvil):** P1 — deal 1 settles; buyer receives 0 T +
100 WORTHLESS; attacker +495 USDG (after 1% fee). P2 — seller + sellToken
both swapped; attacker2 +495 USDG. Uncapped in general (any payAmount).

### Why this is not a duplicate

**B-02** (report `e2388550b4`) was a MALICIOUS SERVER tampering with
`createDeal` inside the victim's own `open()` call in the SDK, and that
mechanism is now DEAD twice over (on-chain consent binding + `open()`
pre/post checks — proven by re-running the B-02/B-19 attack against the
new SDK: `open()` throws before sending anything). K-654's attacker is
the seller, its entry point is the website `/d/` open flow — a different
client that never received the patch's fix — its field is `sellToken`
(not `buyerReceive`), and its effect is different: the buyer receives a
worthless token (not zero tokens, and not tokens diverted to an attacker
address). The B-22 fix (buyerReceive check) is proven not to catch this
(control P3). Dedupe risk, stated honestly: HIGH. The team may view this
as a B-02 residue — "the same verification gap, params not checked
against intent, in another client". The counter-argument is that B-02
never claimed the website client or the sellToken field, its PoC never
exercised them, the website is a separate in-scope surface ("Website
(bull.family + OTC desk)"), and the patch itself drew the line: it fixed
the SDK's `open()` and left the website's open flow unverified.

### Threat model (stated honestly)

Preconditions: (1) the seller is malicious; (2) the server echoes the
seller's consent as-is in `POST /api/quote`. Caveat, stated explicitly:
whether the live server validates the consent against the offer inside
`POST /api/quote` CANNOT be tested read-only (live POSTs are forbidden
by the program's rules for this audit, and the endpoint is
authenticated). The PoC uses a mock server. If the live server does
validate, this client-side hole is moot and only the server-compromise
path (B-02 pure) remains. The client-side evidence (the chunk contains
no comparison) and the mock PoC stand on their own. No victim private key
is needed, and no server compromise is needed.

### How to reproduce

Local Anvil chain 4663, mock `/api/quote`, verbatim replica of the
website's `M(e)` open + `V(e)` fund logic from the chunk above, live
escrow v3 bytecode etched — no real funds, no mainnet, no Bull
infrastructure, no live API calls. All keys are Anvil's public throwaway
test keys.

1. Start Anvil: `anvil --port 8547 --chain-id 4663`
2. In this directory: `npm install`, then `node run-poc.mjs`

What the PoC does (offer: buy 100 token T for 500 USDG):

- **P1 (primary):** server params swap `sellToken=WORTHLESS`
  (`buyerReceive`=buyer, honest). Deal 1 is created, funded, settles
  (status 2); buyer receives 0 T + 100 WORTHLESS; attacker +495 USDG.
- **P2:** seller AND sellToken both swapped (second attacker +
  WORTHLESS2). Deal 2 settles; buyer receives 100 WORTHLESS2;
  attacker2 +495 USDG.
- **P0 (honest control):** honest params (sellToken=T, real seller) →
  deal 3 settles; buyer receives 100 T.
- **P0b (check control):** replica `M` WITH a `params.sellToken ==
  offer.token` check → REFUSES the evil params (`REFUSED-BY-CHECK`), 0
  deals created. This proves the check is the missing piece.
- **P3 (B-22 fix control):** replica `M` with ONLY a buyerReceive check
  (the B-22 fix) → evil params STILL pass (buyerReceive is honest here);
  deal 4 settles; attacker +495 USDG. This proves the B-22 fix does not
  close this hole.

Forge tests (live escrow/Agreement bytecode): `cd chain && forge test`
— 21/21 green.

`poc-result.json` holds the measured results (`exploited: true` for
K-654).

### Suggested fix

- In the website's open flow `M(e)`, compare the params against the
  offer before sending `createDeal` — at minimum `params.sellToken`
  (and `seller`/`sellAmount`/`payAmount`/`payToken`) must equal the
  offer's token/seller/amounts — and refuse (with a visible warning) on
  mismatch. Do the same in the fund flow `V(e)`: read `deals(dealId)`
  on-chain and verify `sellToken`/`seller`/amounts against the offer
  before paying.
