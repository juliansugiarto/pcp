# Witnessed Record, spec v0.3 (draft)

Status: draft for discussion. Not audited. Do not use in a real election. Reference implementation: `verifier/wr3.py` (v0.2 stays in `verifier/wr2.py` for history). Rationale: in the project's private research notes (not published), sections R5.1, R5.3 and R5.5 of the v0.2 threat model.

This document is a diff from [v0.2](witnessed-record-v0.2.md). Everything not mentioned here is unchanged.

**One-line principle (unchanged):** whoever counts must not be the only one who can recount.

## 1. Encoding and signatures

| Change | Reason |
|---|---|
| `spec` is `"witnessed-record/0.3"`; signature input is `"wr/0.3/" + type + "\n" + canonical_bytes(body)` | A v0.2 signature can never be replayed as a v0.3 one. |
| Witness keys may be **ES256** (ECDSA P-256 + SHA-256) or Ed25519; org keys stay Ed25519 | Budget Android phones guarantee hardware-backed P-256, not Ed25519; org keys live on laptops and benefit from determinism. |
| ES256 public key = uncompressed SEC1 point, 130 hex chars (`04‖x‖y`); signature = raw `r‖s`, 64 bytes, 128 hex | One fixed-size encoding for both algorithms; no DER parsing in the format. |
| **Envelope identity = SHA-256 of the canonical body**, not of the envelope | ECDSA signatures are malleable (`s` and `n − s` both verify) and Android Keystore does not promise low-S, so a third party could mint a second valid envelope for the same body. |
| Log leaves (`input_root`) are canonical bodies, deduplicated by body hash, sorted by `(type, contest, station, signer, body_hash)` | A malleated or replayed copy adds no leaf; honest mirrors still agree. |
| In aggregation a body counts once; it is accepted if **any** of its received signatures verifies | A junk or malleated copy can neither double count nor block the good one. |
| `policy_sha256` and `stations_sha256` are over canonical bytes | One hashing rule everywhere. |

## 2. Envelope types

| Type | Change | Reason |
|---|---|---|
| `witness-cert` | Adds `role` ∈ `saksi, ptps, pemantau, kpps, posted` and `alg` ∈ `ed25519, es256`; `pubkey` length must match `alg` | Role encodes the legal position (inside the room, outside it, or the public posting later); the verifier needs the algorithm before it can check anything. |
| `capture.image` | Becomes `{"orig_sha256": hex64, "deriv_sha256": hex64 or "", "deriv_params": string}` | When the same key signs original and derivative in one act, no edit proof is needed; ZK is only for edits by non-signers. |
| `capture.anchors` | New: list of body hashes the witness saw in the room (e.g. decoded from the KPPS phone's QR); may be empty | Lets a witness say "I saw that official capture" without replacing their own photo. |
| `capture.witness.pubkey` | Structurally 64 or 130 hex; the algorithm is looked up in the cert table during aggregation | The capture itself does not need to restate what its cert already binds. |
| `official` | Adds `stage` ∈ `capture, tps, ppk, kabko, prov, nasional` | The state is the only camp that produces downstream numbers; each stage is a row to diff. |
| `revocation` | Takes effect only for keys certified by the **same org** | In v0.2 any org could revoke another org's witnesses. |

The state's signed capture is **not** a new type: KPU is an org like any other, its KPPS devices hold `witness-cert`s with role `kpps`, and they emit ordinary `capture` envelopes.

## 3. Station list

Entries are strings or objects `{"station": "...", "dpt": int}` (other fields ignored). `dpt` feeds the `implausible` flag only.

## 4. Policy

| Change | Reason |
|---|---|
| A camp named `official` may be listed but **must never appear in `require_camps`**; the verifier refuses such a policy (`ValueError`, CLI exit 2) | Cooperation from the state is welcome, assumed absent, and never a precondition for a result. |
| Warning in report header `policy_warnings` when a camp mixes `kpps`-role witnesses with other roles | Putting the KPPS in a party's camp is legal but almost always a modelling mistake. |
| Optional `freeze_at` (RFC 3339) | Registry freeze: certs whose first `not_before` is after it are flagged `late_enrollment`. |
| The `official` camp is droppable | Deleting it from a policy must still give a complete report; it does, because the data layer is policy-free. |

## 5. Aggregation additions (per policy)

1. **Supporter entries** carry `org_name`, `role`, `alg`, the `image` object and `anchored_to_official`. Reason: the rendering and a court need to see who signed, in what legal position.
2. **`anchored_to_official`** per capture: true if any anchor equals the body hash of a signature-valid capture by a `kpps`-role key at the same station. Never an admission rule. Reason: a one-way "I saw it" edge must not become a substitute for the witness's own photo.
3. **Recap drift** per station and form: `recap_drift` lists each stage present, in stage order, with `status` = `equal`, `differs` (with `delta_official_minus_witnessed`), `official_conflict` (two or more distinct tallies at that stage, all listed) or `official_only` (no settled witnessed tally). Reason: Teluk Bintuni and Medan Timur are both rows in this table.
4. **`first_divergent_stage`**: the first stage whose status is `differs` or `official_conflict`; `null` if none or not settled. Reason: names the exact step where the number changed.
5. **Station-level `official`** diff is taken against the **most downstream stage present** and carries that `stage`. Reason: that is the number that enters the official total. Report adds `first_divergent_stage_counts`.
6. **Flags, evidence only, never rejection**, per station, with `flag_detail` naming the keys at that station:
   - `implausible`: a capture's tally sum (all options, `invalid` included) exceeds the station's `dpt`. Reason: 2019 forms showed hundreds more votes than voters.
   - `same_image`: two different witness keys share an `orig_sha256`, or a non-empty `deriv_sha256` (checked across all stations). Reason: two "independent" witnesses with one phone.
   - `nonce_reuse`: the same nonce in captures at different stations. Reason: a nonce is per room.
   - `late_enrollment`: the witness's first cert `not_before` is after the policy's `freeze_at`. Reason: kills minting keys after results are known.
   Flags are computed over every signature-valid capture from any certified org, not only orgs the policy counts. Reason: a sybil does not leave the evidence by being left out of a policy.
7. **Coverage** adds `flags_by_org`: per org, the number of stations where its keys raised each flag.
8. `coverage.missing` lists stations with no witnessed capture under the policy, even if an official record exists. Reason: v0.2 hid official-only stations from that list.

## 6. Outputs

**`bundle`** (one station, the "berkas TPS"): a deterministic JSON file with every envelope for the station (captures, incidents, officials at every stage); captures at other stations that share a nonce or image hash with it (so its flags reproduce); the full chain for each signer (witness-certs, org manifests, revocations that name the signer); the policies; the station entry; the per-policy station result; and a human-readable `rendering` (candidates with signers as org/role/camp, official per stage, deltas, `first_divergent_stage`, statuses, flags, incidents). `bundle_sha256` = SHA-256 of the canonical bundle without that field. Reason: the unit of evidence is the station, and a lawyer with one file and a laptop must be able to check it.

**`verify-bundle`** recomputes from the bundle alone and exits 0 only if the hash matches, every envelope is well formed, the recomputed station results equal the stored ones, and the rendering equals the recomputed rendering. Reason: a re-hashed bundle with a doctored table or printout must still fail.

**`disputes --official-stage S`**: stations where the settled witnessed tally differs from the official tally at stage S, with per-option delta, sorted by total absolute delta (descending), with a running cumulative delta and the settled margin; stations with an `official_conflict` at S are listed separately. Reason: materiality becomes a computed number ("these N stations move the result by M").

**Vocabulary rule:** no output string contains "fraud", "curang" or "kecurangan". Statuses only. Enforced by a test over every CLI output of the demo and over the verifier's string table. Reason: the verifier reports differences; naming them is for courts.

## 7. What the protocol can honestly promise

- Any dispute about the count can be reduced, by anyone, offline, to a list of named stations with named signers on each side.
- Manipulation after the room cannot be done by fewer people than were in the room.
- No party can later claim a number its own witnesses did not sign without saying so in public.

It cannot promise acceptance, peace, or that the loser's supporters will read the list.

## 8. Enrolment residual

The protocol cannot enrol anyone; orgs do. It makes enrolment abuse visible (registry freeze, `late_enrollment`, `same_image`, `nonce_reuse`, per-org flag counts), and cross-camp co-presence remains the floor. What it does not solve: an org that honestly enrols many real people whose keys are then pooled by coordinators and used from one phone per area. The flags would show it; only the cross-camp rule prevents it from deciding a station.

## 9. Left for v0.4

- Signed tree heads, inclusion and consistency proofs (RFC 6962), carried inside the bundle.
- OpenTimestamps anchoring, so a witnessed C.Hasil provably existed before the recap.
- Compact encoding for SMS.
- A conformance directory, one folder per attack (today: `tests/test_wr3.py`).
- A second, independent implementation in another language that passes it.
- Privacy-preserving witness identity ("a registered witness of org X" without saying which).

Also from R5 and not yet implemented: recorded key attestation and attested share per org, a cert budget per area, and the `burst` flag.
