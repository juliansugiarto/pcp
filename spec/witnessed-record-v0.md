# Witnessed Record, spec v0 (draft)

Status: draft for discussion. Not audited. Do not use in a real election.

## Purpose

Let anyone recompute a public total (for example a vote count) from records signed at the source by several independent witnesses, without trusting the single party that collects and publishes the official number.

One-line principle: **whoever counts must not be the only one who can recount.**

## 1. Record

A record states what was observed at one leaf (for example one polling station) for one contest.

```json
{
  "spec": "witnessed-record/0.1",
  "tier": "witnessed",
  "contest": "example-contest-2029",
  "station": "32.03.01.2001.001",
  "tally": {"A": 120, "B": 98, "invalid": 3},
  "image_sha256": "<hex sha-256 of the photo of the paper form>",
  "captured_at": "2029-02-14T13:05:00+07:00"
}
```

- `tier` is `witnessed` (signed at capture) or `historical` (re-entered later from a published source, no witnesses). The two tiers are never mixed in one total.
- `tally` values are non-negative integers.
- `image_sha256` binds the numbers to one specific photo of the physical form. The photo itself can be published anywhere; only its hash is signed.

## 2. Canonical bytes

The bytes that are signed are the record body serialized as JSON with keys sorted, no insignificant whitespace, UTF-8, integers without leading zeros. Any implementation must produce identical bytes for the same record.

## 3. Witness signatures

```json
{
  "record": { ...as above... },
  "witnesses": [
    {"pubkey": "<hex ed25519 public key>", "sig": "<hex signature over canonical bytes>"}
  ]
}
```

- Algorithm: Ed25519.
- A witness signs only what they personally observed at the leaf.

## 4. Witness registry

A registry maps each public key to a role and an organization:

```json
{"<pubkey hex>": {"role": "saksi", "org": "party-x"}}
```

Each organization publishes its own list of keys. Trust comes from the **independence of witnesses** (different organizations with opposing interests), not from the strength of any single device or any single list.

## 5. Aggregation rules

For each `(contest, station)`:

1. Drop signatures that do not verify or whose key is not in the registry.
2. A record is **accepted** if it has at least `K` valid signatures from at least `R` distinct organizations (defaults: `K = 2`, `R = 2`).
3. If two accepted records for the same station disagree on `tally` or `image_sha256`, the station is a **conflict**. It is excluded from the total and listed publicly.
4. Stations with no accepted record are **missing**, and listed.

The output is: totals per option over accepted stations, coverage (accepted / seen), the conflict list, the missing list, and a Merkle root over the accepted records.

## 6. Public log

Accepted records are hashed in a fixed order (sorted by contest, then station) into a Merkle tree using the RFC 6962 leaf and node prefixes (`0x00` for leaves, `0x01` for nodes). Anyone holding the same set of records gets the same root. Mirrors held by many parties make silent deletion detectable.

## 7. Out of scope for v0 (open problems)

- **Edit proofs:** proving that a cropped or compressed photo derives from the signed original (zero-knowledge proofs of image edits). Research exists; nothing runs on a cheap phone yet.
- **Device attestation:** cheap phones may lack a secure element. v0 relies on witness independence instead.
- **Key distribution and revocation** for witness organizations.
- **Collusion at the leaf and vote buying** are not addressed by this design at all.
- **Legal review:** any real use must be checked against election law first.
