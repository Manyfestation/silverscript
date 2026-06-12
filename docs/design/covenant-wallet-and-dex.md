# Covenant Wallet Abstraction & KCC20 Marketplace — Design Notes

Status: exploratory draft. Companion to the KCC20 book (`docs/kcc20-book`) and the
state-decoding work on `state-tracking-markers`.

## 1. Goal

Build a KCC20 covenant explorer and marketplace ("a really fun and flexible DEX") where:

- users keep their existing Kaspa wallets (Kasware / Kastle browser extensions);
- a **wallet abstraction covenant** acts as the user's on-chain account;
- users can place **custom open orders** — "if you pay my address X KAS you may take
  these tokens" and the reverse "if you deliver N tokens you may take this locked KAS";
- contracts may be custom-generated per order (LLM-assisted), and the explorer can still
  decode and display them.

## 2. Building blocks already in the system

| Block | Where | What it gives us |
|---|---|---|
| KCC20 ownership modes | `kcc20.sil` | A token branch can be owned by a pubkey (`0x00`), a **P2SH script hash** (`0x01`), or a **covenant ID** (`0x02`). |
| ICC proof model | KCC20 book, overview | "Owned by contract X" is proven by *spending an input* with X's script hash / covenant ID in the same tx. No `eval`; proof is transaction-level. |
| Mux / template routing | `chess_mux.sil` | One covenant identity routes its state through multiple worker templates via `validateOutputStateWithTemplate`, then returns. The covenant ID persists across templates. |
| Template metadata | `KCC20Minter` | `templatePrefixLen / templateSuffixLen / expectedTemplateHash` lets a contract *verify* foreign covenant state instead of trusting that an output "looks right". |
| Covenant declarations | `docs/DECL.md` | `#[covenant(...)]` macro generates safe N:M fan-in/fan-out entrypoints (leader/delegate) — the backbone for batch matching and UTXO compounding. |
| State decoding markers | `state-tracking-markers` branch | Compiler emits `StateValidationMarker` offsets (state, output index, template hash/prefix/suffix) so an indexer can decode covenant state from raw scripts — i.e. the explorer can decode *any* contract compiled by us, including generated ones. |
| `checkDataSig` | compiler builtin | Verify a signature over **arbitrary data** from the stack — the entrypoint for extension wallets that can sign messages but not arbitrary covenant inputs. |
| Node cov-id index | rusty-kaspa | The node tags each covenant UTXO with its covenant ID → free discoverability for anything that is a covenant. |

## 3. The layer model

```text
Layer 0  KCC20 asset covenants            (exists)
Layer 1  Wallet covenant ("account")      (new — the abstraction)
Layer 2  Order objects                    (new — P2SH offers and/or order covenants)
Layer 3  Matching / market structure      (new — batch fills, auctions, mux markets)
```

The unifying mechanism across all layers is KCC20's owner-identifier indirection:
*placing tokens "into" something is just a KCC20 transfer that rewrites
`ownerIdentifier` to that thing's script hash or covenant ID.* Tokens never leave the
KCC20 covenant; only the ownership pointer moves.

## 4. Layer 1 — the wallet covenant

### 4.1 What it is

A singleton covenant (`#[covenant.singleton]` style, 1:1 continuation) whose covenant ID
**is the user's account identity**:

- KAS balance = the value carried on the wallet covenant UTXO (plus deposit UTXOs, §4.5);
- KCC20 balances = token branches with `identifierType = IDENTIFIER_COVENANT_ID` and
  `ownerIdentifier = wallet cov id`;
- orders = order objects owned by (or cancellable by) the wallet cov id;
- the explorer renders the account's full history as one covenant chain — the cov id is
  a stable, indexable username.

### 4.2 Two authorization tiers

The wallet supports both, selected per entrypoint:

1. **`checkSig` tier** — if the extension can sign the covenant input itself (PSKT-style
   signing), this is the simple path: the signature commits to the transaction, so
   outpoints are covered and replay is impossible. "Send KAS" really is just
   `require(checkSig(s, ownerPk))` plus output checks.
2. **`checkDataSig` tier** — for extensions that only expose *message signing*. The user
   signs an **intent message** in Kasware/Kastle; anyone (your backend) can then build,
   fund, and broadcast the transaction. This is genuine account abstraction with
   sponsored transactions: the user never needs KAS for fees in their extension wallet.

**Replay protection is the crux of the data-sig tier.** A data signature does not commit
to the spent outpoint, so a static message could be replayed against the wallet's next
state. The wallet therefore carries a monotonically increasing `nonce` in its state, and
every signed intent commits to it:

```text
msg = blake2b(DOMAIN_TAG || wallet_cov_id || nonce || action_digest)
```

- `DOMAIN_TAG` separates intent types (and separates "sign-in to app" messages from
  spend authorizations — never let a login signature double as a spend).
- `wallet_cov_id` prevents cross-account replay of identical intents.
- `nonce` prevents same-account replay; the continuation state must carry `nonce + 1`.
- `action_digest` is a hash of the structured action (recipient, amount, asset, expiry).

### 4.3 Sketch (pseudocode, not compiled)

```js
contract CovWallet(byte[32] init_owner_pk, int init_nonce) {
    byte[32] owner_pk = init_owner_pk;
    int nonce = init_nonce;

    // Tier 1: extension signs the tx input directly.
    entrypoint function send_signed(sig s, int out_idx, int amount, byte[] dest_spk) {
        require(checkSig(s, pubkey(owner_pk)));
        require(tx.outputs[out_idx].scriptPubKey == dest_spk);
        require(tx.outputs[out_idx].value == amount);
        // continuation: same state, nonce unchanged (tx sig covers outpoint)
        State next = { owner_pk: owner_pk, nonce: nonce };
        require(OpAuthOutputCount(this.activeInputIndex) == 1);
        int cont = OpAuthOutputIdx(this.activeInputIndex, 0);
        require(tx.outputs[cont].value ==
                tx.inputs[this.activeInputIndex].value - amount);
        validateOutputState(cont, next);
    }

    // Tier 2: extension only signed a message; relayer builds & funds the tx.
    entrypoint function send_intent(datasig ds, int out_idx, int amount, byte[] dest_spk) {
        byte[32] action = blake2b(dest_spk + byte[](amount, 8));
        byte[32] msg = blake2b(0x01 /*SEND*/ + OpInputCovenantId(this.activeInputIndex)
                               + byte[](nonce, 8) + action);
        require(checkDataSig(ds, msg, pubkey(owner_pk)));
        require(tx.outputs[out_idx].scriptPubKey == dest_spk);
        require(tx.outputs[out_idx].value == amount);
        State next = { owner_pk: owner_pk, nonce: nonce + 1 };  // <- replay protection
        require(OpAuthOutputCount(this.activeInputIndex) == 1);
        int cont = OpAuthOutputIdx(this.activeInputIndex, 0);
        validateOutputState(cont, next);
    }

    // Spending tokens: the wallet input IS the witness. KCC20's transfer is
    // co-spent in the same tx; KCC20 checks OpInputCovenantId(witness) == owner.
    entrypoint function act_as_token_owner(datasig ds /*, intent args */) {
        // verify intent over (nonce, kcc20 transition digest), bump nonce.
        // KCC20 does the rest on its own input.
    }
}
```

Note how token spending works: the wallet does **not** re-implement token logic. KCC20's
`checkSigs` requires a witness input whose covenant ID equals the token's owner; the
wallet covenant input *is* that witness. The wallet only authenticates the user's intent
and bumps its nonce. Each contract verifies its own side — the same separation of
responsibility as KCC20 / KCC20Minter.

### 4.4 Wallet as a mux (the chess pattern, applied)

Rather than growing one giant wallet script, adopt the `ChessMux` shape: the wallet
holds a table of **action-template hashes** (send, place-order, cancel-order, swap,
compound, recover) and routes its state into the selected worker template via
`validateOutputStateWithTemplate`; the worker performs its single action and routes
back. Benefits:

- the wallet script stays small (script-size limits matter);
- new actions ship as new worker templates without migrating the account — upgrade by
  rotating the template table (an owner-signed action);
- one stable cov id across all of it.

### 4.5 Deposits and compounding

Problem: outsiders can't easily pay *into* a covenant, because the wallet's P2SH
commitment changes whenever state (nonce) changes — there is no stable address.

Pattern: give each account a tiny stable **deposit P2SH**:

```js
// deposit script: spendable only in a tx that includes an input
// whose covenant ID == my wallet's cov id
require(OpInputCovenantId(witness_idx) == WALLET_COV_ID);
```

Anyone pays KAS (or assigns KCC20 via `IDENTIFIER_SCRIPT_HASH`) to this address forever.
The wallet periodically **sweeps**: one tx spends the wallet covenant (as witness) plus
N deposit UTXOs, folding value into the continuation output. That's the "compounding
UTXOs" feature, and it's ICC in the other direction — a plain P2SH deferring to a
covenant. Note the deposit script is one of the strongest arguments for the wallet being
a covenant at all: a stable script can only delegate to a stable *identity*, and the cov
id is the only stable identity a stateful UTXO chain has.

## 5. Layer 2 — orders: P2SH offers vs. order covenants

### 5.1 The "open invitation" as pure P2SH (no covenant needed)

Your intuition is right: the basic offer needs **no covenant**.

**Sell order (tokens for KAS).** Mint/transfer the KCC20 branch to
`identifierType = IDENTIFIER_SCRIPT_HASH`, owner = hash of an *offer script*:

```js
// offer script: anyone may use me as the token-spend witness IF
// this tx pays X KAS to the maker — or the maker signs (cancel path)
entrypoint function take(int pay_idx) {
    require(tx.outputs[pay_idx].scriptPubKey == MAKER_SPK);
    require(tx.outputs[pay_idx].value >= ASK_AMOUNT);
}
entrypoint function cancel(sig s) { require(checkSig(s, MAKER_PK)); }
```

The taker spends this P2SH input; KCC20 sees a witness input matching the owner script
hash and authorizes the token transfer to the taker. The tokens never sat "in" the offer
— ownership was just pointed at it.

**Buy order (KAS for tokens).** Lock KAS in a P2SH that verifies the *opposite* leg:
the tx must contain a KCC20 output of asset `A` assigning ≥ N tokens to the maker. The
script reconstructs the expected KCC20 state bytes (using the template
prefix/suffix/hash baked in at order creation — the KCC20Minter metadata pattern) and
checks the output's P2SH commitment plus covenant-output membership. This is ICC
initiated from a plain P2SH — a pattern worth naming: **predicate scripts** (stateless
scripts whose only job is to verify someone else's covenant transition in the same tx).

### 5.2 When you *do* want an order covenant

A covenant order is justified by anything stateful or long-lived:

| Capability | P2SH offer | Order covenant |
|---|---|---|
| All-or-nothing fill | yes | yes |
| **Partial fills** (remaining amount decrements) | no | yes |
| **Price schedules** (Dutch auction via `this.age`) | no | yes |
| Order identity across fills (explorer shows fill history as one chain) | no | yes — cov id persists |
| Discoverability | only via your own indexer keyed by script hash | **free** — node indexes cov id |
| State decoding in the explorer | you know the template, so possible, but ad hoc | uniform via `state-tracking-markers` metadata |
| Ownable / cancellable by the wallet covenant | needs a sig branch | natively — order state stores maker's wallet cov id |
| Batch matching participant | awkward | natively — N:M covenant transitions |
| Script size / cost | smallest | bigger |

So the honest answer to "do I even need a covenant here?": **not for v0.** The
P2SH offer is the minimum lovable product: it is cheap, it composes with KCC20 today,
and your app generates the scripts so your indexer can track them by script hash. The
covenant order is the v1 upgrade that buys partial fills, auctions, free node-side
discovery, uniform state decoding, and matching — and those are exactly the features
that make a DEX feel like a DEX rather than a bulletin board of atomic swaps.

The two are not rivals: an order covenant's *fill condition* can itself be expressed as
"a P2SH predicate input is present", so generated custom conditions stay tiny scripts
while the covenant supplies state and identity.

### 5.3 Layer 3 — matching and market structure

- **Batch matching.** Declare the order covenant with `#[covenant(binding = cov,
  from = max_ins, to = max_outs)]`. One transaction can then consume several buy and
  sell orders of the same market covenant ID and emit fills + remainders, with the
  leader entrypoint enforcing conservation and price compatibility across the whole
  batch (the `VaultNM` shape in `DECL.md`). A matcher (your backend, or anyone) earns
  the spread for assembling batches — permissionless market making.
- **Market mux.** A per-market mux covenant (chess pattern) routes between
  `order_book / auction / settle` worker templates: one market identity, many regimes.
- **Custom, LLM-generated order conditions.** Because the compiler emits state-layout +
  validation-marker metadata, a generated one-off contract is still explorable and
  indexable. The contract registry for the marketplace is: template hash → source →
  state layout. Template hashes are the ABI of this world; the `state-tracking-markers`
  branch is what makes "custom contracts everywhere" operationally sane.

## 6. Security checklist for this design

1. **Replay**: every `checkDataSig` entrypoint must commit to wallet cov id + nonce, and
   the continuation must bump the nonce. No exceptions.
2. **Domain separation**: tag every signed message with an action type; keep app login
   signatures in a disjoint domain from spend intents.
3. **Intent expiry**: include a max DAA score / locktime bound in the action digest so
   stale relayer-held intents die.
4. **Dust-fill griefing**: partial-fill orders need a minimum fill size, or attackers
   shave orders into uneconomical crumbs.
5. **Front-running**: open offers are take-able by anyone by design; for fairness-
   sensitive flows prefer batch/auction regimes over continuous first-come fills.
6. **Fee accounting**: covenant continuations check value equality — decide explicitly
   where fees come from (relayer-funded inputs is the cleanest with the intent tier).
7. **Predicate correlation**: a P2SH predicate verifying a foreign covenant output must
   pin template hash *and* covenant id, not just "an output that decodes plausibly".

## 7. Suggested build order

1. **Wallet covenant v0**: singleton, two tiers (checkSig + checkDataSig/nonce), send
   KAS, act-as-token-owner witness entrypoint. Wire Kasware/Kastle message signing.
2. **Deposit P2SH + sweep/compound** entrypoint.
3. **P2SH sell/buy offers** (marketplace v0: all-or-nothing, cancel branch), indexer
   keyed by script hash, explorer rendering via known templates.
4. **Order covenant** with partial fills + cancel-by-wallet-cov-id; switch discovery to
   the node's cov-id index; decode state via `state-tracking-markers` metadata.
5. **Batch matching** via N:M covenant declarations; then auction/mux market regimes.
6. **Generated-contract registry** (template hash → layout → renderer) to open the
   marketplace to custom contracts.
