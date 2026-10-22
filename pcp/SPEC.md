# PCP/0: Proof-Contingent Payment

**Status:** draft, version 0. Reference implementation in this folder (Rust crate `pcp`). Not audited. This crate's own tests use a proof backend that is insecure by design (section 7.3). A RISC Zero backend in `../pcp-risc0/` (section 7.2) is built and run in CI, with a reproducible guest image id. Two rails exist (section 8): a simulated ledger, and an LND rail that has been run against real LND v0.19.3 and v0.21.4 nodes on regtest in CI. On 21 October 2026 a sale with a real RISC Zero proof settled over two real LND nodes on regtest in CI. Nothing has run on signet or mainnet.

Key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

**Framing.** PCP/0 is *verified exchange under a human mandate*, not a machine economy. Every agent that buys or sells acts for a **principal** (a human, or an organisation a human controls) who signs a mandate for it (section 2.1). Money flows to the principal (section 8.3). Receipts and refusals go to the principal (section 5.4). Only reviewed and tested job classes are traded by default (section 6.4). None of this adds an operator or an issuer: a mandate is two signatures the parties made, the registry is a local list, and the payout rule is a field check.

## 1. Definition

A **proof-contingent payment** is a transfer of value that settles **if and only if** a verifier-accepted proof is delivered that specified work was performed correctly. It is **atomic**: neither side can obtain the other side's part without giving up its own. It works **between strangers or machines** who need not know, trust, or be able to sue each other. There is **no escrow agent, no platform and no court** in the loop.

Mechanism (zero-knowledge contingent payment, "ZKCP", as demonstrated on Bitcoin in February 2016 with a sudoku sale):

1. The seller computes the result `R`, picks a fresh random key `k`, encrypts `C = Enc_k(R)`, and computes `H = SHA256(k)`.
2. The seller produces a proof `π` of the statement: *there exist `R`, `k` such that `job_check(input, R) = true`, `C = Enc_k(R)` and `H = SHA256(k)`*.
3. The buyer verifies `π` against (job spec, input commitment, `C`, `H`) **before paying**.
4. The buyer pays a Lightning invoice whose `payment_hash` is `H`.
5. To claim the payment the seller must reveal the preimage `k`. The buyer obtains `k` from the settled payment and decrypts `C` to get `R`.

No payment without `k`; no `k` (through the payment) without payment.

PCP/0 has three layers:

| Layer | What it does | What exists in v0 |
|---|---|---|
| Condition | Proves the statement for a job class | `InsecureDevTransparentBackend` (no zero knowledge), for this crate's tests. A RISC Zero guest in `../pcp-risc0/` (transparent STARK, no trusted setup), built reproducibly and run in CI |
| Settlement | Pays to `H`, settles on `k` | In-memory HTLC ledger. Lightning BOLT11 hold invoices with `payment_hash = H` through LND (feature `lnd`), run on regtest only |
| Binding | Ties proof, offer, buyer and invoice together; buyer checks everything offline before paying | Implemented |
| Authorisation | Ties each agent to a principal's signed mandate (scope, cap, per-deal maximum, expiry); payouts to the principal's node; signed receipts and refusals to the principal | Implemented (Ed25519). Other mandate encodings MAY be accepted by local policy; none may be required |

## 2. Roles

There are exactly two roles: **buyer** and **seller**. Each is played by an **agent** (a program, or a person acting directly through a client) that acts for a **principal** under a mandate (section 2.1). This document defines no third role: no relay, coordinator, arbiter, escrow, facilitator, registry service, credential issuer or hub. A Lightning routing node on the payment path is part of the rail, not of the protocol, and learns nothing a PCP/0 participant must keep secret except `k` after settlement (section 11, T6).

The principal is not a protocol role. It sends no PCP/0 message. It signs a mandate offline, holds the Lightning node that pays or is paid, and reads its agent's log. Two parties who trade under PCP/0 still need nobody else.

### 2.1 Principal and mandate

A **mandate** is a statement signed by a principal key that authorises one agent key:

| Field | Type | Meaning |
|---|---|---|
| `version` | string | `PCP/0` |
| `principal_key` | 32 bytes | Ed25519 public key of the principal |
| `agent_key` | 32 bytes | Ed25519 public key of the agent. MUST differ from `principal_key` |
| `role` | string | `buyer` or `seller` |
| `scope` | list of hash | `spec_hash`es of the job classes the agent may trade |
| `cap_msat` | u64 | Cumulative limit over the mandate's life: bought (buyer) or sold (seller) |
| `per_deal_max_msat` | u64 | Largest single deal |
| `payout_node` | string | The principal's Lightning node. Seller: every invoice MUST pay this node (section 8.3). Buyer: the node payments leave from and refunds return to |
| `expires_at` | u64 | Absolute time (seconds) at and after which the mandate is void |
| `nonce` | hash | 32 random bytes |
| `principal_sig` | 64 bytes | `Ed25519(principal_sk, mandate_id)` (RFC 8032; verified strictly) |

`mandate_id` is defined in section 3.2.

**What a mandate proves, and what it does not.** A valid mandate proves that the holder of `principal_key` authorised the holder of `agent_key` within these limits. **It does not prove that the principal is a human, and it does not prove who the principal is in law.** The protocol creates the fact "this key signed this"; it cannot create the fact "this key belongs to a person", and it does not claim to.

**No issuer.** A mandate MUST be verifiable with no network access and no third party. Any Ed25519 key is an acceptable `principal_key`. No credential issuer is privileged. A counterparty MAY, by its own local policy, also accept other mandate encodings or weigh extra credentials a principal chooses to show; an implementation MUST NOT require any particular issuer's credential.

**Rules, enforced by default in both directions:**

- Every Request carries the buyer agent's mandate and `agent_sig` over `request_auth`; every Offer carries the seller agent's mandate and `agent_sig` over `offer_auth` (section 3.2). The signature proves the sender holds `agent_key`; a mandate copied by someone else is useless without it.
- A **buyer refuses an offer** whose mandate is missing, does not verify, is not a `seller` mandate, has expired, does not cover the offer's `spec_hash`, is not signed for by its agent, has `per_deal_max_msat < price_msat`, or whose `payout_node` differs from the offer's `seller_node` (section 9, O2).
- A **seller refuses a request** whose mandate is missing, does not verify, is not a `buyer` mandate, has expired, does not cover the `spec_hash`, is not signed for by its agent, has `per_deal_max_msat < price`, or has no cap left: `mandate_spent_msat + price > cap_msat` (section 9, S1m).
- Each agent also enforces **its own** mandate: it trades only inside its scope, before its expiry, within its per-deal maximum and cap.
- `principal_key = agent_key` is refused (`SelfOwned`). An agent MUST NOT be its own principal. A conformant agent never holds its principal's secret key; the protocol can check only the equality, not who holds which key.

**Cap accounting.** The buyer agent tracks, per mandate, the amount committed: it reserves the price at payment (P1), keeps it on settlement, and releases it when the HTLC is refunded. Parallel purchases under one mandate draw on one cap. `mandate_spent_msat` in a Request is the buyer agent's own declaration; a seller can check it against the cap but cannot verify it. The binding enforcement is the buyer's client and, below it, the principal's custody: a Lightning channel funded with N sats caps the agent at N whatever any client does. The seller agent counts settled sales against its own cap and withholds `k` rather than exceed it.

**The stop button.** The principal stops an agent by letting the mandate expire, by setting a cap, and, on the real rail, by closing the channel that funds the agent's spending. None of these asks anyone's permission. Whether LND macaroon constraints or LNC budgets suffice as the agent's "budgeted credential" on the real rail is not yet checked.

## 3. Canonical encoding

All identifiers and commitments are **tagged hashes** over **length-prefixed fields**. JSON (section 3.3) is transport only; no hash is ever computed over JSON text.

### 3.1 Primitives

```
lp(x)               = u32_be(len(x)) || x
tagged_hash(t, f..) = SHA256( lp("PCP/0/" || t) || lp(f1) || lp(f2) || ... )
u64 field           = 8 bytes, big-endian
string field        = UTF-8 bytes, no terminator, no normalisation
hash field          = 32 raw bytes
```

The single exception is the payment hash `H = SHA256(k)`, which is plain SHA-256 so that any Lightning node can use it unchanged.

### 3.2 Derived values

| Name | Definition |
|---|---|
| `spec_hash` | `tagged_hash("spec", [job_id, params])` |
| `input_commitment` | `tagged_hash("input", [input])` |
| `offer_id` | `tagged_hash("offer", [version, job_id, spec_hash, input_commitment, buyer_nonce, u64(price_msat), u64(offer_expires_at), seller_node, backend_id, enc_scheme, rail])` |
| `ciphertext_hash` | `tagged_hash("ciphertext", [C])` |
| `statement_hash` | `tagged_hash("statement", [version, job_id, spec_hash, input_commitment, offer_id, buyer_nonce, ciphertext_hash, payment_hash])` |
| `bundle_id` | `tagged_hash("bundle", [statement_hash, backend_id, C, proof])` |
| `H` (`payment_hash`) | `SHA256(k)` |
| `mandate_id` | `tagged_hash("mandate", [version, principal_key, agent_key, role, scope, u64(cap_msat), u64(per_deal_max_msat), payout_node, u64(expires_at), nonce])`, where `scope` is one field: the concatenated 32-byte hashes in order |
| `request_id` | `tagged_hash("request", [version, job_id, spec_hash, input_commitment, buyer_nonce, u64(max_price_msat), u64(mandate_spent_msat)])` |
| `request_auth` | `tagged_hash("request-auth", [request_id, mandate_id])`, signed by the buyer agent |
| `offer_auth` | `tagged_hash("offer-auth", [offer_id, mandate_id])`, signed by the seller agent |
| `accept_auth` | `tagged_hash("accept-auth", [offer_id, mandate_id])`, signed by the buyer agent |
| `receipt_id` | `tagged_hash("receipt", [version, role, mandate_id, principal_key, counterparty_mandate_id, counterparty_principal_key, agent_key, offer_id, statement_hash, bundle_id, payment_hash, preimage, u64(amount_msat), u64(settled_at)])` |
| `refusal_id` | `tagged_hash("refusal", [version, role, mandate_id, agent_key, subject_id, counterparty_agent_key or empty, reason, detail, u64(at)])` |

`offer_id` commits to the terms only; the mandate and the agent signature are bound to it through `offer_auth`. All signatures are Ed25519 over the 32-byte value named.

### 3.3 JSON transport

- 32-byte values, 64-byte signatures and byte strings are **lowercase** hex strings. Uppercase hex MUST be rejected.
- Integers are JSON numbers. All amounts are millisatoshi (`u64`); implementations MUST reject values that do not fit in `u64`.
- Field names are as in section 5. Unknown fields SHOULD be rejected.

## 4. Encryption scheme `chacha20poly1305-k/0`

```
k        32 bytes from a CSPRNG, fresh for every proof bundle, never reused
enc_key  tagged_hash("enc-key", [k])
nonce    12 zero bytes
aad      tagged_hash("enc-aad", [offer_id])
C        ChaCha20-Poly1305(enc_key, nonce, R, aad)      (ciphertext || 16-byte tag)
```

- The all-zero nonce is safe only because `enc_key` is used exactly once. A seller MUST NOT reuse `k`.
- Encryption is deterministic given `(k, R, offer_id)`. A prover holding the witness can therefore recompute `C` exactly, which is how the relation `C = Enc_k(R)` is checked.
- `enc_key` is derived from `k` by a tagged hash and is not computable from `H`.
- Binding `C` to `offer_id` through the AEAD's associated data means a ciphertext made for one offer does not decrypt under another.

## 5. Messages

All messages carry `"version": "PCP/0"`.

### 5.0 Request (buyer to seller)

| Field | Type | Meaning |
|---|---|---|
| `job_id` | string | Job class, e.g. `pcp/sudoku/v0` |
| `spec_hash` | hash | Exact predicate the buyer wants |
| `input` | bytes | Job input in the class's canonical encoding |
| `input_commitment` | hash | `tagged_hash("input", [input])` |
| `buyer_nonce` | hash | 32 fresh random bytes; binds the whole exchange to this purchase |
| `max_price_msat` | u64 | Most the buyer will pay |
| `mandate_spent_msat` | u64 | What the buyer agent has committed under its mandate so far (its declaration) |
| `mandate` | object | The buyer agent's mandate (section 2.1). Required by default |
| `agent_sig` | 64 bytes | `Ed25519(agent_sk, request_auth)`. Required by default |

### 5.1 Offer (seller to buyer)

| Field | Type | Meaning |
|---|---|---|
| `job_id`, `spec_hash`, `input_commitment`, `buyer_nonce` | | Echoed from the request |
| `price_msat` | u64 | Price |
| `offer_expires_at` | u64 | Absolute time (seconds) after which the offer is void |
| `seller_node` | string | Lightning node id that will issue the invoice and be paid |
| `backend_id` | string | Proof backend, e.g. `risc0/…` or `INSECURE-dev-transparent/0` |
| `enc_scheme` | string | `chacha20poly1305-k/0` |
| `rail` | string | `lightning-bolt11/0` (real) or `lightning-htlc-sim/0` (v0 simulation) |
| `mandate` | object | The seller agent's mandate. Required by default. `seller_node` MUST equal its `payout_node` |
| `agent_sig` | 64 bytes | `Ed25519(agent_sk, offer_auth)`. Required by default |

`offer_id` (section 3.2) commits to every terms field; `mandate` and `agent_sig` are bound to it by `offer_auth`.

### 5.1a Accept (buyer to seller)

| Field | Type | Meaning |
|---|---|---|
| `offer_id` | hash | The offer the buyer accepts |
| `mandate` | object | The buyer agent's mandate: the same one it sent with the request. Required |
| `agent_sig` | 64 bytes | `Ed25519(agent_sk, accept_auth)`. Required |

The seller proves only after a valid Accept (S1o). The buyer does not echo the offer: the seller keeps the offers it issued and looks the `offer_id` up. A changed term changes `offer_id`, so a tampered offer is simply an offer the seller never issued (`offer_not_issued`). The signature ties the proving cost to the agent that sent the request: anyone who saw the offer, but does not hold that agent's key, cannot make the seller prove. A repeated Accept is not an error: the seller answers it with the bundle and invoice it already made, or nothing while it is still working, and never proves twice.

### 5.2 Proof bundle (seller to buyer)

| Field | Type | Meaning |
|---|---|---|
| `backend_id` | string | As in the offer |
| `statement` | object | `{version, job_id, spec_hash, input_commitment, offer_id, buyer_nonce, ciphertext_hash, payment_hash}` |
| `ciphertext` | bytes | `C` |
| `proof` | bytes | Backend-specific, opaque to the protocol |

The bundle SHOULD be sent to the buyer only, over a confidential channel (see T6).

### 5.3 Invoice binding (seller to buyer)

| Field | Type | Meaning |
|---|---|---|
| `offer_id` | hash | Offer this invoice is for |
| `statement_hash` | hash | Statement this invoice is for |
| `invoice` | object | BOLT11 invoice (real rail) or its simulated equivalent: `{payee, payment_hash, amount_msat, created_at, expiry_secs, min_htlc_secs, description_hash}` |

On the real rail, the BOLT11 `h` tag (description hash) MUST equal `statement_hash`, the `p` tag MUST equal `H`, the amount MUST equal `price_msat`, the payee node (recovered from the invoice signature) MUST equal `seller_node`, which MUST equal the seller mandate's `payout_node`. `min_htlc_secs` stands in for `min_final_cltv_expiry_delta`.

### 5.4 Receipts and refusals, to the principal

After settlement **each side** produces a receipt, signs it with its agent key, and appends it to its principal's log:

| Field | Type | Meaning |
|---|---|---|
| `role` | string | Which side wrote it |
| `mandate_id`, `principal_key`, `agent_key` | | Whose agent, under which mandate |
| `counterparty_mandate_id`, `counterparty_principal_key` | | Who was on the other side |
| `offer_id`, `statement_hash`, `bundle_id`, `payment_hash` | hash | What was traded |
| `preimage` | hash | `k` |
| `amount_msat` | u64 | What was paid |
| `settled_at` | u64 | When |
| `agent_sig` | 64 bytes | `Ed25519(agent_sk, receipt_id)` |

The log entry for a deal holds the receipt **together with the bundle and the input**, so the principal can re-verify the sale offline: the receipt is bound to the principal's mandate and signed by its agent, `SHA256(preimage) = payment_hash`, `C` decrypts under `preimage`, the result passes `job_check`, the amount is within `per_deal_max_msat`, and the running total stays within `cap_msat`. A deal entry therefore discloses `R`; the log is for the principal only.

Every deal that does not complete is also logged, as a **refusal**: refused by this agent (with the error's reason code, e.g. `counterparty_mandate.cap_exceeded`, `own_mandate.expired`, `job_class_not_registered`), refused by the counterparty (`refused_by_counterparty.<code>`), refunded (`refunded`), or failed after payment. A refusal names the request or offer it is about, the counterparty agent key if known, the reason code, a human-readable detail and the time, and is signed by the agent over `refusal_id`.

The log is exported as JSON lines, one entry per line. It goes to the principal, never to a third party.

**Limit.** An agent running a modified client can leave entries out of the log. The principal's own node history is the ground truth for amounts, and the counterparty's receipt names this agent's mandate, so an omitted deal leaves evidence elsewhere; the log itself cannot prove its own completeness.

## 6. Job classes

A job class is a deterministic predicate `check(input, result) -> bool` with fixed parameters. Its `spec_hash` names it exactly. For a zkVM backend, the buyer MUST also pin the exact guest binary. The guest image id cannot be part of `params`, because the guest itself computes `spec_hash` and a binary cannot contain its own image id; the reference RISC Zero backend therefore puts the image id in `backend_id` (`risc0-zkvm-3-succinct/<image id hex>`), which `offer_id` commits to, and the buyer verifies every receipt against the image id it built or reviewed itself.

A job class is in scope for PCP/0 only if:

- `check` is a pure function of `(params, input, result)`: no clock, network, randomness, floating point or environment;
- `check` is total and terminates within a bound the class documents;
- inputs and results have a canonical byte encoding the class defines.

The predicate **is** the contract. A result that passes `check` is a correct delivery by definition, even if it is not the result the buyer had in mind; buyers must write predicates that say what they want.

### 6.1 In scope for v0

| Class | Example | Implemented in v0 |
|---|---|---|
| Pure computation with a checkable output | Sudoku, SAT under a bound, numerical result with a verifiable certificate | `pcp/sudoku/v0` (4x4 and 9x9) |
| Schema-valid data | Parse, clean, deduplicate or convert data so that the buyer's validator accepts it; buyer commits the input hash | Not yet (same shape as the two below) |
| Code that passes a hermetic test suite | A patch or function body that passes the buyer's fixed tests (pinned toolchain, no network, time or randomness) | `pcp/testsuite-toyexpr/v0`: a toy expression language over one `i64` variable checked against `(x, expected)` vectors, standing in for a prebuilt WASM/RISC-V module run against tests inside a zkVM guest |

`pcp/sudoku/v0`: input and result are `n*n` bytes row-major, `n ∈ {4, 9}`, `0` = blank in the input; `params = [n]`. Valid iff lengths match, every result cell is in `1..=n`, every given is preserved, and every row, column and box is a permutation of `1..=n`.

`pcp/testsuite-toyexpr/v0`: input is `u32_be(count) || count × (i64_be(x) || i64_be(expected))` with `1 <= count <= 4096`; result is UTF-8 source in the grammar documented in `src/job/testsuite.rs` (integers, `x`, `+ - * / %`, comparisons, `if(c, a, b)`; wrapping `i64`; division by zero fails the test); at most 4096 bytes and nesting depth 64; `params = u32_be(4096) || u32_be(4096) || u32_be(64)`.

### 6.2 Out of scope

| Class | Why |
|---|---|
| Judgement work (quality of prose, design, strategy) | No predicate is code. Any judge (a person, a jury, an LLM in a TEE) is a trusted third party. Outside the primitive. |
| Physical delivery | Not a computation. Needs an oracle. |
| Large-model inference | Proving is not viable today; the alternatives (TEE attestation, optimistic replay) re-introduce a chip vendor or a replayer as a trusted party. |
| Proof of storage / retrievability | Deterministic, but it is a *service* with no good to reveal; needs the contingent-service-payment variant (ZKCSP, 2017). Later. |

### 6.3 Excluded job classes

Some classes are checkable, and are excluded anyway, by policy. The reference implementation does not ship them, the default registry (section 6.4) MUST NOT contain them, and this project does not document how to define them:

- any class whose result is a **third party's secret or credential**, or that recovers a key, password, preimage or similar against a system the buyer does not own (generic "hash search" is excluded for this reason: it is the same family as credential cracking);
- any class whose result is an **exploit or attack** against a system the buyer does not own;
- any class whose result is **personal data** about people;
- any class whose outcome is an **action in the physical world**.

This list is a default, not a guarantee. A fork can define any class. See section 11.1.

### 6.4 Registry of reviewed job classes

Each client keeps a local **registry**: `spec_hash → (name, version, review note)`. By default a buyer does not buy, and a seller does not sell, a class whose `spec_hash` is not in its registry (`JobClassNotRegistered`). An explicit development flag (`allow_unregistered_job_classes`) lifts this for testing.

An entry means the class was **reviewed and tested**: checked against the rules of section 6 and against section 6.3, with conformance vectors. It does not mean the class is safe or harmless. The registry is a local value; anyone can fork it and nobody is asked for permission. The v0 reference registry holds `pcp/sudoku/v0` (n = 4 and n = 9) and `pcp/testsuite-toyexpr/v0`.

## 7. Proof backends

### 7.1 Interface

```rust
trait ProofBackend {
    fn backend_id(&self) -> &'static str;
    fn is_secure(&self) -> bool;  // zero knowledge and sound
    fn prove(&self, job, statement, ciphertext, witness{input, R, k}) -> Result<ProofBundle, ProveError>;
    fn verify(&self, job, expected_statement, bundle) -> Result<(), VerifyError>;
}
```

`verify` MUST accept only if all of the following hold for the **verifier's own expected statement** (section 9, V4):

1. `bundle.version`, `statement.version` are `PCP/0`; `bundle.backend_id` names this backend;
2. `statement.job_id = job.job_id()` and `statement.spec_hash = job.spec_hash()`;
3. `bundle.statement` equals the expected statement;
4. `tagged_hash("ciphertext", [C]) = statement.ciphertext_hash`;
5. the proof establishes, for some witness `(input, R, k)`:
   `tagged_hash("input", [input]) = input_commitment`, `job.check(input, R)`, `Enc_k(R) under offer_id = C`, `SHA256(k) = payment_hash`.

A sound prover MUST refuse to produce a proof for a witness that fails any relation.

### 7.2 zkVM backend (RISC Zero, in `../pcp-risc0/`, run in CI)

The relation of 7.1 item 5 is one pure function, `statement::evaluate` (`no_std + alloc`; dependencies SHA-256 and ChaCha20-Poly1305 only; no randomness, clock or I/O). The dev backend calls it in the clear; a zkVM guest calls it inside the VM.

- **Guest input** (private except the offer binding): `canonical_bytes("guest-input", [spec_hash, input, R, k, C, offer_id, buyer_nonce])`, where `canonical_bytes(t, f..) = lp("PCP/0/" || t) || lp(f1) || ...` is the tagged-hash pre-image of section 3.1.
- **Checks**: `spec_hash` names a job class the guest knows; `check(input, R)`; `C = Enc_k(R)` under `offer_id` (section 4).
- **Journal** (public): `canonical_bytes("statement", [version, job_id, spec_hash, input_commitment, offer_id, buyer_nonce, ciphertext_hash, payment_hash])`, with `input_commitment`, `ciphertext_hash` and `payment_hash = SHA256(k)` computed inside. `SHA256(journal) = statement_hash`.

The verifier rejects fake (dev-mode) receipts, verifies the receipt against the pinned image id (section 6), parses the journal and compares it field by field with the statement it built from its own state (section 9, V4). Proving MUST be local: the guest input contains `R` and `k`, so a remote proving service would learn the goods. The buyer verifies the STARK receipt directly; PCP/0 has no on-chain verifier and therefore no reason to wrap the proof in Groth16.

The reference guest is built reproducibly in Docker; two separate CI builds gave the same image id, `cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328` (builder `risczero/risc0-guest-builder:r0.1.97.0`). Measured costs, and the sale that settled over two LND nodes on regtest with this guest, are in `../pcp-risc0/COSTS.md`.

### 7.3 `InsecureDevTransparentBackend` (v0): INSECURE

The "proof" is the witness `(input, R, k)` sealed with ChaCha20-Poly1305 under a key that is **a constant in the source code**, with the statement hash as associated data. `verify` opens the seal and checks every relation of section 7.1, so the protocol's order, errors and binding are exercised for real. The public API never returns the opened witness (enforced by `compile_fail` doctests).

It provides **no zero knowledge**: anyone who reads the source can open the seal and learn `R` and `k` without paying. Buyers MUST refuse it unless explicitly configured for testing (`BuyerPolicy::allow_insecure_dev_backend`). It MUST NOT be used with real funds.

## 8. Settlement rail

### 8.1 Lightning (target)

A BOLT11 invoice issued by `seller_node` with `payment_hash = H`, amount `price_msat`, description hash `statement_hash`. The seller's node knows `k` and settles automatically when the HTLC arrives. The buyer obtains `k` as the payment preimage (proof of payment). Direct channels between repeat counterparties are RECOMMENDED; an on-chain ZKCP fallback (2016 construction) is RECOMMENDED above a size threshold.

### 8.1a Rail interface

The state machines settle through one interface, `rail::Rail`: `create_invoice(payee, H, amount, description_hash, expiry, min_htlc)`, `pay_invoice`, `settle_invoice(H, k)`, `lookup_invoice(H)` (payee's view of the HTLC) and `lookup_payment(H)` (payer's view, with `k` once settled). Offers name the rail (`lightning-htlc-sim/0` or `lightning-bolt11/0`) and both sides refuse a rail they are not on. The simulated ledger implements it; so does an LND REST client (feature `lnd`, hold invoices, run against LND v0.19.3 and v0.21.4 nodes on regtest in CI): the seller's node holds the HTLC until the seller settles with `k`, and the buyer's rail decodes the BOLT11 string with the buyer's own node and refuses to pay one that decodes to other terms than those checked in V5 to V8.

### 8.2 Simulated ledger (v0)

`lightning::Ledger` models only what an HTLC enforces:

- funds locked by the payer move to the payee **only** if the payee presents `k` with `SHA256(k) = H` before the timeout;
- on success the funds move and `k` becomes visible to the payer in one step; on any failure nothing changes and `k` is not recorded;
- after the timeout, locked funds return to the payer and `k` is no longer accepted;
- an invoice cannot be paid after its expiry, with a lock shorter than its `min_htlc_secs`, twice, or if altered;
- a second invoice for an existing payment hash is refused.

### 8.3 Payout to the principal

The seller's invoice payee MUST be the `payout_node` declared in the seller's mandate: money lands on the node the principal holds, never on a node the agent holds. The buyer checks `seller_node = payout_node` when it accepts the offer (O2) and `invoice.payee = payout_node` before paying (V7). The buyer pays from its own mandate's `payout_node`. In the simulation, nodes are opened for principals (`Ledger::open_principal_node`) and balances are read per principal (`Ledger::principal_balance`).

This is the most important line of the mandate design. An agent paid into its own node funds itself, and a self-funding agent is no longer stopped by its principal's cap.

## 9. Verification order

The buyer performs these steps in this order. A failure at any step aborts the purchase; nothing later is attempted.

| Step | Buyer checks | On failure |
|---|---|---|
| R0 | Before sending the request: the job class is registered (6.4); own mandate is valid, a `buyer` mandate, unexpired, covers the class, has cap left | `JobClassNotRegistered`, `OwnMandate(…)` |
| O1 | Offer: version, `job_id`/`spec_hash` as requested, `input_commitment` of own input, `buyer_nonce` is own, `price_msat <= max`, `price_msat <=` the policy's per-deal value ceiling (default 10 000 sat: PCP/0 is for small, capped, repeatable jobs), not expired, backend is one the buyer runs and (unless testing) secure, `enc_scheme`, `rail` | `JobMismatch`, `InputCommitmentMismatch`, `ReplayedOrMisdirected`, `PriceTooHigh`, `DealAboveCeiling`, `OfferExpired`, `BackendNotAccepted`, `InsecureBackendRefused`, … |
| O2 | **Mandates**: the seller's mandate and `agent_sig` (section 2.1), `seller_node = payout_node`, price within the seller's per-deal maximum; then own mandate: unexpired, price within own per-deal maximum and remaining cap | `CounterpartyMandate(…)`, `OwnMandate(…)` |
| A1 | Send the signed Accept (5.1a). Resend it, unchanged, until the bundle arrives or the offer expires | `OfferExpired` (gives up at `offer_expires_at`) |
| V1 | Bundle: version, `backend_id`, `statement.buyer_nonce` is own | `ReplayedOrMisdirected` |
| V2 | `statement.offer_id = offer_id` of the accepted offer; `job_id`, `spec_hash`, `input_commitment` as expected | `OfferMismatch`, `JobMismatch`, `InputCommitmentMismatch` |
| V3 | `tagged_hash("ciphertext", [C]) = statement.ciphertext_hash` | `CiphertextHashMismatch` |
| V4 | **Verify the proof** against the statement the buyer builds from its own state, taking only `ciphertext_hash` and `payment_hash` from the bundle | `ProofInvalid(…)` |
| V5 | Invoice binding names this `offer_id` and `statement_hash` | `InvoiceBindingMismatch` |
| V6 | **`invoice.payment_hash = H`** (the proven `statement.payment_hash`) | `InvoiceHashMismatch` |
| V7 | `invoice.amount_msat = price_msat`; `invoice.payee = seller_node = payout_node` of the seller mandate; `invoice.description_hash = statement_hash` | `InvoiceAmountMismatch`, `InvoicePayeeMismatch`, `InvoiceDescriptionMismatch` |
| V8 | **Expiry**: at least `min_invoice_remaining_secs` left; `min_htlc_secs <= htlc_secs` (buyer's maximum lock) | `InvoiceExpiresTooSoon`, `HtlcLockTooLong` |
| P1 | **Pay**: reserve the price against the mandate's cap (refused if expired or over cap) and record the state `Paying`, then HTLC to `H` from the principal's node, locked for `htlc_secs`. If the payment call fails, look the payment up at the node: in flight or settled means paid; known never to have left (or failed) releases the reservation; a lookup that fails keeps `Paying` and the reservation, and is retried. A buyer MUST NOT release a reservation while the payment may be out. (The reference LND rail looks the payment up in the node's last 1,000 payments, which covers a restart, not a node that has made 1,000 payments since.) A buyer MUST NOT pay on an offer past `offer_expires_at`, even if the invoice is still payable | `OwnMandate(…)`; rail error (state `Paying` or back to `InvoiceAccepted`) |
| P2 | **Receive preimage** `k` when the HTLC settles; if it times out, funds return and the reservation is released | `Refunded` |
| P3 | **`SHA256(k) = H`** | `PreimageMismatch` |
| P4 | **Decrypt** `C` with `k` under `offer_id` | `DecryptionFailed` |
| P5 | **Re-check** `job_check(input, R)` locally if cheap (default on) | `PostPaymentCheckFailed` |
| P6 | Sign the receipt and append it, with the bundle and input, to the principal's log (5.4) | |

Every failure is also appended to the principal's log as a signed refusal with its reason code (5.4).

P4 or P5 failing after a valid proof means the proof backend is unsound. The buyer has paid; the receipt, the bundle and the input form public evidence of the failure.

The seller, for its part:

| Step | Seller does |
|---|---|
| S1 | Check the request (`input_commitment` opens to `input`, job is one it serves and is registered, price within the buyer's maximum) |
| S1m | **Mandates**: own mandate valid for `seller`, unexpired, covers the class, price within own per-deal maximum and cap; the buyer's mandate and `agent_sig` (section 2.1), price within its per-deal maximum and within `cap_msat - mandate_spent_msat`. Then quote an offer naming `payout_node` as `seller_node`, signed over `offer_auth` |
| S1o | **Accept**: prove only for an offer this seller issued (`offer_not_issued` otherwise), still valid (`OfferExpired`), accepted by an Accept signed over `accept_auth` by the agent of the mandate that came with the request (`CounterpartyMandate(…)`). A repeated Accept is answered, never refused and never proven again. A request sent again gets the same offer while it is valid. A seller that is handed an offer instead (one process, `fulfil`) checks it is its own, unchanged: its own `agent_sig` verifies over `offer_auth`, and `seller_node`, `backend_id`, `job_id` and `spec_hash` match its configuration (`OfferMismatch`). Refuse an expired offer before proving and again before invoicing |
| S2 | Do the work; run `check` locally; refuse to package a failing result (`SellerResultInvalid`) |
| S3 | Draw a fresh `k`; compute `H`, `C`, the statement; prove; **record `k` before the invoice exists**; create the invoice to `H`, payable to `payout_node`. After a restart, find the invoice the node already issued for `H` and reuse it (a second invoice to the same hash is refused) |
| S4 | When an HTLC to `H` is locked for at least the price **and** its timeout is at least `settle_margin_secs` away **and** the sale stays within the seller's cap, settle with `k`. Otherwise withhold `k` (`SettleMarginTooShort`, `OwnMandate(CapExceeded)`). `k` MUST NOT be disclosed by any other means. When it withholds for a reason that cannot clear (amount short, too close to the timeout, own cap now exceeded: the cap only grows), it SHOULD cancel the HTLC so the buyer's funds return at once, and the sale ends (`Cancelled`, logged). A sale also ends when its invoice has expired with no HTLC held (the seller then also cancels the invoice at its node, so a late HTLC is refused at once), or its HTLC was cancelled. If a settle call fails, it MUST look the HTLC up before reporting failure: a settled HTLC means `k` reached the node, and the sale is recorded. On Lightning, express margins in blocks and keep the margin above the payee node's own hold-expiry cancel (LND `invoices.holdexpirydelta`, 12 blocks by default) |
| S5 | Sign the receipt and append it, with the bundle and input, to the principal's log. Refusals at S1, S1m and S2 are logged too |

### 9.1 What each party can lose, by step

| Point reached | Buyer has spent | Seller has spent | Buyer has `R`? | Seller has payment? |
|---|---|---|---|---|
| Before V4 | Nothing | Work and proving cost | No | No |
| After V8, before P1 | Verification time | Work and proving cost | No | No |
| After P1 (HTLC locked) | Price, locked until settle or timeout | Same | No | No |
| Seller settles (P2) | Price | Same | Yes (after P4) | Yes |
| HTLC times out | Nothing (refunded); liquidity tied up for `htlc_secs` | Same | No | No |

There is no row in which one side has the other's part without giving up its own.

## 10. Protocol state machines (reference)

Buyer: `Requested → OfferAccepted → BundleVerified → InvoiceAccepted → Paying → Paid → Delivered`, with `Refunded` (HTLC timeout) and `Aborted(error)` as terminal states. `Paying` is the state between the cap reservation and a known payment outcome (P1); `Paying → InvoiceAccepted` when the payment is known never to have left. `result()` returns `NotPaid` in every state except `Delivered`. `Delivered` appends a receipt to the principal's log; `Refunded` and `Aborted` append a refusal. A buyer gives up where waiting can no longer succeed: no offer within its wait, offer expired before the invoice was accepted, invoice expired before paying. It never gives up in `Paying` or `Paid`: only the rail decides those.

Seller: per offer, `Issued → Accepted → Proven (k recorded) → Invoiced (bundle + invoice issued) → Settled` or `Cancelled`, and `Issued`/`Accepted → Closed` when the offer expires first. `k` leaves the seller only by settling the HTLC. `Settled` appends a receipt to the principal's log; `Cancelled`, `Closed` after an accept, and a refused request, accept or result append a refusal.

### 10.1 Restarts

A party that runs as a process SHOULD save its state after every step and before every side effect that depends on it, so that a process killed at any point restarts into a state from which the sale still ends delivered, refunded or refused with a logged reason, provided its node is reachable again. (The reference implementation shows this at its named crash points, below; a node that forgets a payment, or stays unreachable, leaves the sale open.) In particular: the seller records `k` before creating the invoice (S3); the buyer records `Paying`, with the reservation, before the payment call (P1); the protocol state and the principal log are saved together, so a sale is never logged twice or lost from the log; each side's cap is recomputed from its records (settled sales; each purchase's held amount, which stays held after a settled payment whose result then failed its checks), never kept as a separate counter. Receiving a message twice is harmless: every step is idempotent or does nothing in the wrong state.

The saved state contains `k` (seller) or `R` (buyer) and the agent key. It is as sensitive as a Lightning node's credentials.

The reference implementation (`src/node/`, binaries `pcp-sell`, `pcp-buy`, `pcp-audit`) does this over a directory transport, and `tools/crash-matrix.sh` kills each side at every named point and checks the result.

The mandate's budget and the log belong to the agent, not to one purchase: parallel purchases under one mandate share one cap and one log.

## 11. Threats

| # | Threat | Defence | Test |
|---|---|---|---|
| T1 | **Seller sends a wrong `C`**: ciphertext of a result that fails the check, or of something other than the proven result, or swapped after proving | V3 and V4 (relations `job_check` and `C = Enc_k(R)`; dev seal bound to statement hash). An honest backend refuses to prove a false statement | `wrong_result_fails_verification_and_nothing_is_paid`, `ciphertext_of_other_result_than_proven_fails`, `swapped_ciphertext_after_proving_fails`, `honest_seller_and_backend_refuse_wrong_result` |
| T2 | **Buyer refuses to pay** after receiving the bundle; or makes the seller prove for nothing | The buyer learns nothing about `R` (zero knowledge; with the dev backend only by API discipline, see 7.3). The seller loses work and proving cost, never `R`. The seller proves only on a signed Accept from the agent that sent the request (S1o, 5.1a), so a third party who saw the offer cannot trigger proving, and a repeated Accept never proves twice. Mitigations outside PCP/0: price proving cost in, rate-limit unknown buyers, ZKCSP-style service payments | `buyer_who_never_pays_never_gets_k`, `buyer_cannot_learn_result_before_paying`, `accept_for_an_offer_not_issued_or_not_signed_is_refused_without_proving`, `accept_runs_the_work_once_and_repeats_resend` |
| T3 | **Invoice hash mismatch**: invoice to a hash whose preimage does not decrypt `C` (money with no delivery) | V6 | `invoice_payment_hash_mismatch_is_refused` |
| T4 | Invoice amount, payee, description, binding altered | V5, V7 | `invoice_amount_payee_description_and_timing_are_checked` |
| T5 | **Replay of a proof for another buyer** (forwarding a bundle or invoice made for Alice to Bob, or rewriting its public fields) | `buyer_nonce` and `offer_id` in the statement (V1, V2); `C` bound to `offer_id` via AEAD; proof bound to the statement hash; invoice bound to `statement_hash` (V5); fresh `k` per sale. Buyers SHOULD also refuse any `H` they have seen before | `proof_replayed_to_another_buyer_fails` |
| T6 | **Lightning routing and hub trust** | Hubs and LSPs can delay or fail a payment; they cannot forge settlement without `k`. **Every hop on the route learns `k` when the payment settles**, so confidentiality of `R` after the sale rests on `C` not being public: send the bundle to the buyer only. Hops also see `H` (correlation); PTLCs remove that later. Prefer direct channels between repeat counterparties | Out of scope for the simulation |
| T7 | **Griefing via expiry and lock time**: invoice that expires before the buyer can pay; invoice that asks for a very long HTLC lock; seller who holds the HTLC without settling; payment arriving so late that settling races the refund | V8 (minimum remaining time; maximum lock `htlc_secs`); HTLC timeout returns funds; seller withholds `k` within `settle_margin_secs` of the timeout (S4) | `invoice_amount_payee_description_and_timing_are_checked`, `expiry_refunds_and_seller_does_not_reveal_late`, `unpaid_invoice_expires`, `wrong_preimage_cannot_settle_and_buyer_is_refunded` |
| T8 | **Seller reveals a wrong preimage** | Ledger rejects it (`SHA256(k) ≠ H`); funds stay locked, then refund; P3 re-checks | `wrong_preimage_cannot_settle_and_buyer_is_refunded` |
| T9 | **The 2017 CCS attack on ZKCP** (Campanelli, Gennaro, Goldfeder, Nizzardo): in the 2016 pay-to-sudoku the buyer generated the zk-SNARK common reference string. A buyer who generates the CRS maliciously breaks zero knowledge and can learn part of the solution (a sudoku cell) without paying | PCP/0 requires backends whose proof the buyer verifies to have **no trusted setup**: STARK-based zkVMs (RISC Zero, SP1) use transparent, hash-based parameters, so there is no CRS for either party to choose and the attack's premise is absent. The Groth16 wrapper these zkVMs offer for on-chain verification re-introduces a setup; PCP/0 verifies off-chain and MUST NOT require it | Design rule. The RISC Zero backend (7.2) uses succinct STARK receipts with no Groth16 wrapper |
| T10 | **Dev backend used for real** | Insecure backend refused by default (`InsecureBackendRefused`); loud naming; `is_secure() = false` | `buyer_refuses_insecure_backend_by_default` |
| T11 | Offer misdirected, expired, overpriced or for another job | O1 | `offer_checks` |
| T12 | Seller reuses `k` across sales | Breaks the zero-nonce rule and lets every hop of the first payment settle the second. Harms the seller, not the buyer (the buyer still gets `k`). Sellers MUST draw a fresh `k`; the simulated ledger refuses duplicate hashes | `invoice_rules` (ledger) |
| T13 | Predicate does not say what the buyer meant | Not a protocol failure. The predicate is the contract (section 6) | n/a |
| T14 | **Agent spends beyond its authorisation** (over cap, over per-deal maximum, after expiry, outside scope) | Own-mandate checks at R0, O2 and P1 with the cap reserved atomically across parallel purchases; the seller's S1m check against the declared spend; the principal's log audit re-checks the running total; custody caps (2.1) | `cap_is_enforced_across_deals`, `per_deal_max_is_enforced`, `expired_mandates_are_refused`, `scope_mismatch_is_refused`, `refund_returns_the_reservation` |
| T15 | **Missing, forged or stolen mandate** (no mandate; altered limits; mandate signed by another key; a valid mandate presented by someone without its agent key) | Required by default (O2, S1m); `principal_sig` over `mandate_id`; `agent_sig` over `request_auth` / `offer_auth` | `missing_mandate_is_refused_by_both_sides`, `wrong_signatures_are_refused` |
| T16 | **Payout diversion**: the seller agent is paid into its own node, and funds itself | `seller_node = payout_node` (O2); `invoice.payee = payout_node` (V7) | `payee_must_be_the_seller_principals_payout_node` |
| T17 | **Self-owned agent** (agent key = principal key) | Refused (`SelfOwned`) by the agent's own client and by counterparties. An agent that holds a *different* key and calls it its principal is not detectable (section 2.1) | `agent_may_not_be_its_own_principal` |
| T18 | **Issuer capture of the mandate layer**: counterparties come to accept only mandates from one credential issuer, which then owns the layer | Design rule: offline verification, any key is a principal, no issuer privileged, no issuer may be required (2.1) | Design rule |
| T19 | **Unreviewed predicate** traded by default | Registry check at R0 and S1 (6.4) | `unregistered_job_class_is_refused_by_default` |
| T20 | **Agent hides deals from its principal** | Signed receipts and refusals (5.4); principal-side verification detects altered or forged entries. Omission by a modified client is not detectable from the log alone (5.4, Limit) | `principals_can_verify_every_deal_and_refusal` |
| T21 | **Large wrong-but-valid settlement** | Default per-deal value ceiling in the buyer policy (O1); mandate per-deal maximum; small staged jobs | `default_buyer_policy_has_a_per_deal_value_ceiling` |

### 11.1 Societal threats

Categories only. "Mitigated by default" means the reference implementation ships a default that narrows the threat; it never means the threat is removed, since every default can be removed by modifying the client (section 12).

| Threat | Default mitigation | Status |
|---|---|---|
| Agents with no human principal | Mandate required in both directions (2.1); `SelfOwned` refused; payout to the principal's node (8.3); cap and expiry | Mitigated by default. A mandate proves a key, not a human: an agent can be given a principal key that no human holds. Not removable by protocol |
| Trust-free markets for illicit but code-checkable goods | Registry of reviewed classes (6.4); excluded classes (6.3); small per-deal ceiling | Mitigated by default. Anyone can define a new class in a fork: inherent, not mitigable by protocol |
| Predicate gaming (sellers optimise to the check, not the intent) | Reviewed classes; per-deal ceiling limits the loss per deal | Inherent, not mitigable by protocol. The predicate is the contract; buyer-side tooling (held-out tests) helps outside the protocol |
| No recourse after a large wrong settlement | Per-deal value ceiling in the default buyer policy; mandate per-deal maximum and cap; staged small jobs | Mitigated by default in size. Finality itself is inherent, not mitigable by protocol |
| Self-dealing volume inflating adoption metrics | Self-payments flagged in receipts and excluded from metrics (section 14) | Mitigated in measurement only. One person holding two principal keys is not detectable: inherent, not mitigable by protocol |
| Gradual displacement of human work | Receipts to the principal keep a human as the accountable party | Inherent, not mitigable by protocol. PCP/0 takes no fee, so it concentrates nothing, and it redistributes nothing either |
| Blame landing on identifiable authors | Defaults visible in code and in this document; the legal note in `README.md` (section 13); this table | Mitigated by default in part. That the authors are the identifiable edge is inherent, not mitigable by protocol |

## 12. Non-goals and honest limits

- **Mandate-free operation is possible only by modifying the client. This project does not ship it and does not document it.**
- **None of the rules in this document is enforceable against a modified client. They are defaults, enforced by counterparties' refusal: they shape the default economy, not the possible one.**
- Judgement work, physical delivery, large-model inference, any oracle.
- Dispute resolution, refunds after settlement, chargebacks. A settled PCP is final.
- Reputation, identity, discovery, matching. Buyers and sellers find each other by other means. A mandate proves authorisation by a key, not identity (2.1).
- Custody of anyone's funds or keys; routing others' payments.
- Fiat or stablecoin settlement. (A stablecoin version can be built; it adds an issuer who can freeze and a facilitator who can be regulated, which are exactly the roles PCP/0 has none of.)
- On-chain verification of proofs; BitVM-style optimistic verification. Later, for large long-running jobs.
- Privacy of the payment beyond what Lightning gives (hash correlation across hops remains until PTLCs).
- **Which trade risk PCP removes, and which it does not.** Any trade between strangers carries three risks:
  1. the counterparty does not deliver or does not pay;
  2. the good is not what was promised;
  3. the seller's right to the good is not clean, so a third party can take it back later (stolen goods, assets later seized as proceeds of crime).

  PCP removes risk 1, and removes risk 2 when the promise is a predicate a program can check. It does nothing about risk 3. Nor can any proof system: the facts that decide risk 3 live outside the trade (an investigation, a registry, a court), and the power to act on them belongs to others.
- **Not quantum-resistant as a whole.** A large fault-tolerant quantum computer running Shor's algorithm breaks elliptic-curve discrete logarithms. That breaks (a) Lightning and Bitcoin signatures, so channel funds can be stolen: a bigger and older target than PCP; (b) mandate signatures (Ed25519), so a mandate could be forged; (c) the soundness of discrete-log proof systems, including the halo2 IPA/Pasta backend, so a seller with such a machine could forge a proof at sale time and be paid for nothing. Things that hold against a quantum adversary as far as is known: the hash-based parts (SHA-256 for `H`; the Poseidon keystream of the `zk-poseidon-ctr/0` suite, which the halo2 backend in `../pcp-zk/` uses and which is defined in `../pcp-zk/README.md`, section "Cipher suite `zk-poseidon-ctr/0`", not in this specification; with roughly halved security under Grover: about 128 bits for a 256-bit key), the soundness of hash-based STARKs such as the zkVM backend's (without a Groth16 wrapper, which is pairing-based and not post-quantum), and the hiding of blinded Pedersen commitments, which is information-theoretic. If halo2's zero-knowledge is statistical in every component (expected from its design, not checked by this project), the privacy of past sales is not exposed by "harvest now, break later" through the proof itself; the remaining exposure is the 256-bit key under Grover. Mitigation is algorithm agility: `backend_id` is bound into the offer, so a buyer policy can refuse discrete-log backends, and mandate keys can move to a post-quantum signature scheme in a future mandate version. Settlement cannot be more quantum-resistant than the rail it settles on.

## 13. Legal boundary

Not part of the protocol. The project's legal position, including Indonesian currency law, is in the "Legal note" section of [`README.md`](README.md#legal-note).

## 14. Metrics

Adoption metrics for PCP/0 (for example "settlements per month between strangers") MUST exclude **self-payments**: settlements where the buyer's principal and the seller's principal are the same key, that is, one principal paying itself through two agents. Each sale is counted once, from its buyer-side receipt. The reference implementation provides `Receipt::is_self_payment` and `mandate::adoption_count`, which counts buyer-side receipts and reports self-payments separately.

Limit: a person who holds two principal keys looks like two strangers. Metrics SHOULD say so when they are reported.

## Appendix A. Conformance vectors

Computed by the Rust crate (tests `conformance_vectors` in `src/tests.rs` for vectors 1 to 13, and `statement_core_conformance_vectors` in `src/statement.rs` for 14 to 17). `tools/vectors.py` is a separate Python implementation (`hashlib`, and `cryptography`'s ChaCha20Poly1305 and Ed25519) that recomputes all 17 vectors and compares each with this table: `python3 tools/vectors.py`. A second implementation MUST reproduce them.

Fixed inputs: `k = 0x11 × 32`, `offer_id = 0x22 × 32`, `input_commitment = 0x33 × 32`, `buyer_nonce = 0x44 × 32`. For the mandate vectors: principal seed `0x55 × 32`, agent seed `0x66 × 32` (RFC 8032 secret keys), and the mandate `{version "PCP/0", role "buyer", scope [spec_hash #4], cap_msat 5 000 000, per_deal_max_msat 2 000 000, payout_node "principal-node", expires_at 86 400, nonce 0x77 × 32}`.

| # | Value | Result (hex) |
|---|---|---|
| 1 | `tagged_hash("test", ["", "abc", u64(1)])` | `69b1f5ad126e00c4f741eab035dc593a23728edb32ee92d98dfd442272842463` |
| 2 | `H = SHA256(k)` | `02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc` |
| 3 | `Enc_k("PCP")` under `offer_id` | `1b7e1354b4a7b7f40ad290a740585505a2001a` |
| 4 | `spec_hash` of `pcp/sudoku/v0`, `n = 4` | `977fe68aefda363451d6526e3598975c18f39fa3399a792e16650319448f36be` |
| 5 | `spec_hash` of `pcp/sudoku/v0`, `n = 9` | `0a3c3833260ed33c76cd735d4b005686f15f14b38f1aaa0422ac95e17797f5a0` |
| 6 | `spec_hash` of `pcp/testsuite-toyexpr/v0` | `9aa91b2878399b36576180833e32dcd2b7f793b9c89dc24300cd4f1e35dcf3ea` |
| 7 | `input_commitment` of suite `[(-1, 1)]` | `9e2497098d49db24713ed622b7220e02fa38b646b7e11925614d73ecfc746242` |
| 8 | `statement_hash` for sudoku n=4, the fixed inputs, `C = "C"`, `H` from #2 | `48b2ecc5eccf1ec9f13e74019ff6a45aa7aae444a3cae5f4338f28aff28e39b8` |
| 9 | `offer_id` for sudoku n=4, the fixed inputs, price 1 000 000 msat, expiry 600, seller `"seller"`, backend `INSECURE-dev-transparent/0`, `chacha20poly1305-k/0`, `lightning-htlc-sim/0` | `0e5dd77c4975f961abf06701b79ec912900f3ce5fc0cacb08856b92a5e8fc105` |
| 10 | `principal_key` from seed `0x55 × 32` | `c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242` |
| 11 | `agent_key` from seed `0x66 × 32` | `34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746` |
| 12 | `mandate_id` of the fixed mandate | `768febe650b08741e15fb538587b359df87bd48a6e78f7b93cfa7f7a5424c772` |
| 13 | `principal_sig` over #12 | `60e9f0b666227078f8c10dadadd1862b9ba54be3d14ac6014a743cc5540d76f20d2a3ae5cf030a8d20975bf99248aef53e787ee8b9473853b04d6edc5bf09a0e` |
| 14 | Statement core: `C = Enc_k(R)` under `offer_id`, for sudoku n=4 input `1 0 0 4 / 0 0 1 0 / 0 1 0 0 / 4 0 0 1` and `R = 1 2 3 4 / 3 4 1 2 / 2 1 4 3 / 4 3 2 1` (bytes, row-major) | `4a3f402e4c2e98b8371e2fe27c1869c35d2b11e3107848cff28e8b624e5bf554` |
| 15 | `SHA256` of the guest input `canonical_bytes("guest-input", [spec_hash #4, input, R, k, C #14, offer_id, buyer_nonce])` | `ee93318d136f05eeecc095c3512a667c4bae50fa81b8fb1718e29c30ce66bed9` |
| 16 | `SHA256` of the journal the guest commits for #15, which equals its `statement_hash` | `9119de0c3d909b092a118b655588b7e85e004e9de2d17ab297f247cd42bd3c02` |
| 17 | Length in bytes of that journal | `261` |

Vectors 14 to 17 are checked by `statement_core_conformance_vectors` in `src/statement.rs`.

## Appendix B. Lineage

- Bitcoin wiki, zero-knowledge contingent payment (2011).
- Maxwell and Bowe, first ZKCP on Bitcoin mainnet: a sudoku solution for 0.10 BTC, 26 February 2016.
- Campanelli, Gennaro, Goldfeder, Nizzardo, "Zero-Knowledge Contingent Payments Revisited: Attacks and Payments for Services", ACM CCS 2017 (IACR ePrint 2017/566).
- Lightning BOLT11 invoices; hash time-locked contracts.
- Google AP2 (2025): user-signed intent mandates for agent payments, with an identity root and rails owned by its operators. PCP/0's mandate has the same shape and no root.
