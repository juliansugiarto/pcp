# Independent buyer checks for PCP/0

A second implementation of the buyer's offline checks, written in Python from
`pcp/SPEC.md` **alone**: no Rust source, no `tools/vectors.py`, no fuzz
harness was read. Its purpose is differential testing: every verdict on which
this code and the Rust buyer differ is a SPEC bug or an implementation bug.

## Files

| File | What it does |
|---|---|
| `pcp0.py` | Canonical encoding and every derived value of SPEC section 3; the `chacha20poly1305-k/0` scheme (4); mandate verification (2.1); `pcp/sudoku/v0` spec hashes and `check` (6.1); the buyer's checks R0, O1, O2, V1-V3, V5-V8 of section 9, in the SPEC's order, each refusal carrying the SPEC's reason code |
| `vectors_check.py` | Recomputes Appendix A vectors 1-17 and prints PASS/FAIL per vector |
| `compare.py` | Runs the checks over a corpus of cases with the Rust buyer's verdicts and reports agreement by category |

## What it checks

Given the buyer's own request (input, nonce, mandate), its policy, and the
seller's offer, proof bundle and invoice binding as JSON on the wire:

- strict JSON transport (3.3): lowercase hex, exact lengths, `u64` range,
  unknown fields rejected;
- O1 and O2 on the offer: version, job, input commitment, nonce, price against
  `max_price_msat` and the per-deal ceiling, expiry (void at and after
  `offer_expires_at`), backend accepted and secure (or testing allowed),
  `enc_scheme`, `rail`; then the seller mandate in the order of 2.1 (present
  with `agent_sig`, version, `principal_sig` over `mandate_id`, not
  self-owned, role, expiry, scope, `agent_sig` over `offer_auth`), the deal
  checks (`seller_node = payout_node`, per-deal maximum) and the buyer's own
  mandate (expiry, per-deal maximum, remaining cap);
- V1-V3 on the bundle: versions, `backend_id`, nonce, `offer_id`, job, input
  commitment, `tagged_hash("ciphertext", [C])`;
- V5-V8 on the binding: `offer_id` and `statement_hash` (recomputed from the
  buyer's own state), `payment_hash`, amount, payee (= `seller_node` =
  `payout_node`), description hash, remaining invoice time, maximum HTLC lock,
  and the P1 rule "never pay on an offer past `offer_expires_at`".

## What it does not check

- **V4, the proof.** The proof is backend specific and opaque to the protocol
  (SPEC 5.2, 7.x). This code never looks inside it and never returns
  `proof_invalid`. `compare.py` therefore ignores the cases where the Rust
  buyer refused with `proof_invalid` and says how many.
- R0's registry is the v0 reference registry hard-coded from 6.4.
- Anything after payment (P2-P6) beyond the helper `post_payment`.

## Reason codes

Every code this implementation returns is a wire code from SPEC 5.4a (the
table mapping the CamelCase names of section 9 to `snake_case`), and every
mandate failure is `own_mandate.<sub>` or `counterparty_mandate.<sub>` with the
sub-codes and the check order of SPEC 2.1. `compare.py` compares codes
verbatim; it has no alias table. A message that breaks 3.3 (uppercase hex,
wrong length, out-of-range number, unknown or missing field) is, by SPEC 5.5,
an HTTP `400` with no reason code that never reaches the protocol; this code
reports it as `http_400`, which is deliberately not a protocol code. No corpus
case has hit it.

## Run

```
python3 vectors_check.py                      # 17/17 expected
python3 compare.py CORPUS.jsonl [--show N] [--dump divergences.jsonl]
```

Needs Python 3 and the `cryptography` package only.

## Findings

First run (3,173-case corpus, 22 October 2026), against the SPEC before its
amendment: vectors 17/17; no accept/refuse or stage divergence; one code
divergence (bundle `backend_id`: SPEC V1 named one code for three checks);
seven codes the Rust buyer used that the SPEC never named (`version`,
`enc_scheme_not_supported`, `rail_not_supported`,
`counterparty_mandate.{missing,version,signature_invalid,agent_signature_invalid}`),
bridged by an alias table.

Second run, same corpus, against the amended SPEC (2.1 check order and
sub-codes, 5.1 `offer_expires_at` "at and after", 5.4a code table, V1/V5
codes): vectors 17/17; 3,145 agree verbatim, 28 ignored (`proof_invalid`),
0 divergences of any kind, no alias table. The corpus exercises 24 distinct
refusal codes and no boundary.

Third run, on a second corpus (`corpus2.jsonl`, 3,621 cases: the first plus
448 boundary cases varying `now`, the buyer policy and the own mandate's
limits). Before the amendment of V8 the one divergence class was V8 at the
boundary; the SPEC now says `now + min_invoice_remaining_secs < created_at +
expiry_secs`, and with that:

| corpus | cases | agree | ignored (`proof_invalid`) | divergences |
|---|---|---|---|---|
| `corpus.jsonl` | 3,173 | 3,145 | 28 | 0 |
| `corpus2.jsonl` | 3,621 | 3,593 | 28 | 0 |

The boundary cases reach `offer_expired`, `price_too_high`,
`deal_above_ceiling`, `insecure_backend_refused`,
`own_mandate.{per_deal_max_exceeded,cap_exceeded}`, `invoice_expires_too_soon`
and `htlc_lock_too_long` (32 codes in all). Still unexercised by either
corpus: `counterparty_mandate.{self_owned,wrong_role,expired,scope_mismatch,
payout_node_mismatch,per_deal_max_exceeded}`, `own_mandate.{missing,expired}`,
all of R0, and `http_400`.
