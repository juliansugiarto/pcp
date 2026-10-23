"""PCP/0 buyer-side offline checks, written from SPEC.md alone.

This module was written by reading only ``pcp/SPEC.md`` (no Rust source, no
``tools/vectors.py``).  It implements:

* section 3: canonical encoding (``lp``, ``tagged_hash``) and every derived
  value the buyer needs (``spec_hash``, ``input_commitment``, ``offer_id``,
  ``ciphertext_hash``, ``statement_hash``, ``bundle_id``, ``mandate_id``,
  ``request_id``, ``request_auth``, ``offer_auth``, ``accept_auth``,
  ``receipt_id``, ``refusal_id``);
* section 4: the ``chacha20poly1305-k/0`` scheme (encrypt and decrypt);
* section 2.1: mandate verification;
* section 6.1: ``pcp/sudoku/v0`` and ``pcp/testsuite-toyexpr/v0`` spec hashes,
  and the sudoku ``check`` predicate;
* section 9: the buyer's checks R0 (own mandate), O1, O2, V1-V3, V5-V8, in the
  order the SPEC gives them.

**Out of scope, on purpose:** V4 (the proof).  The proof is backend specific
(section 7) and opaque to the protocol; this module never looks inside it and
can therefore never return ``proof_invalid``.  Everything a buyer can check
with nothing but the SPEC, its own request and the three messages is checked.

Reason codes
------------
Every code is a wire code from SPEC section 5.4a (the table mapping the
CamelCase names of section 9 to ``snake_case``), and every mandate failure is
``own_mandate.<sub>`` or ``counterparty_mandate.<sub>`` with the sub-codes and
the check order of section 2.1.  A message that breaks section 3.3 (uppercase
hex, wrong length, number outside ``u64``, unknown or missing field) is, by
5.5, an HTTP ``400`` that never reaches the protocol and has no reason code;
this module reports it as ``http_400`` (not a protocol code) so a comparison
can see it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

VERSION = "PCP/0"
ENC_SCHEME = "chacha20poly1305-k/0"
RAILS = ("lightning-bolt11/0", "lightning-htlc-sim/0")
INSECURE_DEV_BACKEND = "INSECURE-dev-transparent/0"
U64_MAX = 2**64 - 1

# ---------------------------------------------------------------------------
# 3.1 Primitives
# ---------------------------------------------------------------------------


def lp(x: bytes) -> bytes:
    """``lp(x) = u32_be(len(x)) || x``"""
    if len(x) > 0xFFFFFFFF:
        raise ValueError("field too long for u32 length prefix")
    return len(x).to_bytes(4, "big") + x


def u64(n: int) -> bytes:
    """``u64 field = 8 bytes, big-endian``"""
    if not isinstance(n, int) or n < 0 or n > U64_MAX:
        raise ValueError("not a u64: %r" % (n,))
    return n.to_bytes(8, "big")


def s(x: str) -> bytes:
    """``string field = UTF-8 bytes, no terminator, no normalisation``"""
    return x.encode("utf-8")


def canonical_bytes(tag: str, fields) -> bytes:
    """``lp("PCP/0/" || t) || lp(f1) || lp(f2) || ...`` (section 7.2 name for
    the tagged-hash pre-image of section 3.1)."""
    out = lp(s("PCP/0/" + tag))
    for f in fields:
        if not isinstance(f, (bytes, bytearray)):
            raise TypeError("field must be bytes, got %r" % type(f))
        out += lp(bytes(f))
    return out


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def tagged_hash(tag: str, fields) -> bytes:
    """``SHA256( lp("PCP/0/" || t) || lp(f1) || lp(f2) || ... )``"""
    return sha256(canonical_bytes(tag, fields))


# ---------------------------------------------------------------------------
# 3.2 Derived values
# ---------------------------------------------------------------------------


def spec_hash(job_id: str, params: bytes) -> bytes:
    return tagged_hash("spec", [s(job_id), params])


def input_commitment(inp: bytes) -> bytes:
    return tagged_hash("input", [inp])


def offer_id(
    version: str,
    job_id: str,
    spec_h: bytes,
    input_c: bytes,
    buyer_nonce: bytes,
    price_msat: int,
    offer_expires_at: int,
    seller_node: str,
    backend_id: str,
    enc_scheme: str,
    rail: str,
) -> bytes:
    return tagged_hash(
        "offer",
        [
            s(version),
            s(job_id),
            spec_h,
            input_c,
            buyer_nonce,
            u64(price_msat),
            u64(offer_expires_at),
            s(seller_node),
            s(backend_id),
            s(enc_scheme),
            s(rail),
        ],
    )


def ciphertext_hash(c: bytes) -> bytes:
    return tagged_hash("ciphertext", [c])


def statement_fields(
    version: str,
    job_id: str,
    spec_h: bytes,
    input_c: bytes,
    offer_i: bytes,
    buyer_nonce: bytes,
    ciphertext_h: bytes,
    payment_hash: bytes,
):
    return [s(version), s(job_id), spec_h, input_c, offer_i, buyer_nonce, ciphertext_h, payment_hash]


def statement_hash(*args) -> bytes:
    return tagged_hash("statement", statement_fields(*args))


def journal(*args) -> bytes:
    """The zkVM journal (7.2): ``canonical_bytes("statement", [...])``.
    ``SHA256(journal) = statement_hash``."""
    return canonical_bytes("statement", statement_fields(*args))


def bundle_id(statement_h: bytes, backend_id: str, c: bytes, proof: bytes) -> bytes:
    return tagged_hash("bundle", [statement_h, s(backend_id), c, proof])


def payment_hash(k: bytes) -> bytes:
    """``H = SHA256(k)``, plain SHA-256 (the single exception to tagging)."""
    return sha256(k)


def mandate_id(
    version: str,
    principal_key: bytes,
    agent_key: bytes,
    role: str,
    scope: list,
    cap_msat: int,
    per_deal_max_msat: int,
    payout_node: str,
    expires_at: int,
    nonce: bytes,
) -> bytes:
    """``scope`` is one field: the concatenated 32-byte hashes in order."""
    return tagged_hash(
        "mandate",
        [
            s(version),
            principal_key,
            agent_key,
            s(role),
            b"".join(scope),
            u64(cap_msat),
            u64(per_deal_max_msat),
            s(payout_node),
            u64(expires_at),
            nonce,
        ],
    )


def request_id(
    version: str,
    job_id: str,
    spec_h: bytes,
    input_c: bytes,
    buyer_nonce: bytes,
    max_price_msat: int,
    mandate_spent_msat: int,
) -> bytes:
    return tagged_hash(
        "request",
        [s(version), s(job_id), spec_h, input_c, buyer_nonce, u64(max_price_msat), u64(mandate_spent_msat)],
    )


def request_auth(request_i: bytes, mandate_i: bytes) -> bytes:
    return tagged_hash("request-auth", [request_i, mandate_i])


def offer_auth(offer_i: bytes, mandate_i: bytes) -> bytes:
    return tagged_hash("offer-auth", [offer_i, mandate_i])


def accept_auth(offer_i: bytes, mandate_i: bytes) -> bytes:
    return tagged_hash("accept-auth", [offer_i, mandate_i])


def receipt_id(
    version, role, mandate_i, principal_key, counterparty_mandate_id, counterparty_principal_key,
    agent_key, offer_i, statement_h, bundle_i, payment_h, preimage, amount_msat, settled_at,
) -> bytes:
    return tagged_hash(
        "receipt",
        [
            s(version), s(role), mandate_i, principal_key, counterparty_mandate_id,
            counterparty_principal_key, agent_key, offer_i, statement_h, bundle_i,
            payment_h, preimage, u64(amount_msat), u64(settled_at),
        ],
    )


def refusal_id(version, role, mandate_i, agent_key, subject_id, counterparty_agent_key, reason, detail, at) -> bytes:
    return tagged_hash(
        "refusal",
        [
            s(version), s(role), mandate_i, agent_key, subject_id,
            counterparty_agent_key if counterparty_agent_key is not None else b"",
            s(reason), s(detail), u64(at),
        ],
    )


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032), all signatures over the 32-byte value named
# ---------------------------------------------------------------------------


def ed25519_public_key_from_seed(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)


def ed25519_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    if len(pk) != 32 or len(sig) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# 4. Encryption scheme chacha20poly1305-k/0
# ---------------------------------------------------------------------------


def enc_key(k: bytes) -> bytes:
    return tagged_hash("enc-key", [k])


def enc_aad(offer_i: bytes) -> bytes:
    return tagged_hash("enc-aad", [offer_i])


def encrypt(k: bytes, r: bytes, offer_i: bytes) -> bytes:
    """``C = ChaCha20-Poly1305(enc_key, 12 zero bytes, R, aad)``, ``ciphertext || tag``."""
    return ChaCha20Poly1305(enc_key(k)).encrypt(b"\x00" * 12, r, enc_aad(offer_i))


def decrypt(k: bytes, c: bytes, offer_i: bytes) -> Optional[bytes]:
    try:
        return ChaCha20Poly1305(enc_key(k)).decrypt(b"\x00" * 12, c, enc_aad(offer_i))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 6.1 Job classes
# ---------------------------------------------------------------------------

SUDOKU_JOB_ID = "pcp/sudoku/v0"
TOYEXPR_JOB_ID = "pcp/testsuite-toyexpr/v0"


def sudoku_params(n: int) -> bytes:
    """``params = [n]`` (one byte)."""
    return bytes([n])


def sudoku_spec_hash(n: int) -> bytes:
    return spec_hash(SUDOKU_JOB_ID, sudoku_params(n))


def toyexpr_params() -> bytes:
    return (4096).to_bytes(4, "big") + (4096).to_bytes(4, "big") + (64).to_bytes(4, "big")


def toyexpr_spec_hash() -> bytes:
    return spec_hash(TOYEXPR_JOB_ID, toyexpr_params())


def toyexpr_input(vectors) -> bytes:
    """``u32_be(count) || count x (i64_be(x) || i64_be(expected))``"""
    out = len(vectors).to_bytes(4, "big")
    for x, expected in vectors:
        out += int(x).to_bytes(8, "big", signed=True) + int(expected).to_bytes(8, "big", signed=True)
    return out


def sudoku_check(n: int, inp: bytes, result: bytes) -> bool:
    """Valid iff lengths match, every result cell is in 1..=n, every given is
    preserved, and every row, column and box is a permutation of 1..=n."""
    if n not in (4, 9):
        return False
    if len(inp) != n * n or len(result) != n * n:
        return False
    full = set(range(1, n + 1))
    for i in range(n * n):
        if not (1 <= result[i] <= n):
            return False
        if inp[i] != 0 and inp[i] != result[i]:
            return False
    b = int(n**0.5)
    for i in range(n):
        if set(result[i * n:(i + 1) * n]) != full:
            return False
        if set(result[i::n]) != full:
            return False
    for br in range(0, n, b):
        for bc in range(0, n, b):
            cells = {result[(br + r) * n + bc + c] for r in range(b) for c in range(b)}
            if cells != full:
                return False
    return True


# The v0 reference registry (6.4).
REGISTRY = {
    sudoku_spec_hash(4): ("pcp/sudoku/v0", 4),
    sudoku_spec_hash(9): ("pcp/sudoku/v0", 9),
    toyexpr_spec_hash(): ("pcp/testsuite-toyexpr/v0", None),
}


# ---------------------------------------------------------------------------
# 3.3 JSON transport: strict field parsing
# ---------------------------------------------------------------------------


class Malformed(Exception):
    """A message that does not parse under section 3.3 (uppercase hex, wrong
    length, number outside u64, unknown field, missing field, wrong type)."""


_LOWER_HEX = re.compile(r"^[0-9a-f]*$")


def _hex(v: Any, nbytes: Optional[int], where: str) -> bytes:
    if not isinstance(v, str):
        raise Malformed("%s: expected hex string" % where)
    if not _LOWER_HEX.match(v):
        raise Malformed("%s: not lowercase hex" % where)
    if len(v) % 2:
        raise Malformed("%s: odd-length hex" % where)
    b = bytes.fromhex(v)
    if nbytes is not None and len(b) != nbytes:
        raise Malformed("%s: expected %d bytes, got %d" % (where, nbytes, len(b)))
    return b


def _u64(v: Any, where: str) -> int:
    # JSON booleans are ints in Python; the SPEC says integers are JSON numbers.
    if isinstance(v, bool) or not isinstance(v, int):
        raise Malformed("%s: expected integer" % where)
    if v < 0 or v > U64_MAX:
        raise Malformed("%s: does not fit in u64" % where)
    return v


def _str(v: Any, where: str) -> str:
    if not isinstance(v, str):
        raise Malformed("%s: expected string" % where)
    return v


def _obj(v: Any, where: str) -> dict:
    if not isinstance(v, dict):
        raise Malformed("%s: expected object" % where)
    return v


def _parse(obj: Any, schema: dict, where: str, optional=()) -> dict:
    """Parse ``obj`` against ``schema`` (field -> kind).  Unknown fields are
    rejected (3.3: SHOULD be rejected).  Fields in ``optional`` may be absent
    or ``null`` and come back as ``None``."""
    obj = _obj(obj, where)
    out = {}
    for key in obj:
        if key not in schema:
            raise Malformed("%s: unknown field %r" % (where, key))
    for key, kind in schema.items():
        w = "%s.%s" % (where, key)
        if key not in obj or obj[key] is None:
            if key in optional:
                out[key] = None
                continue
            raise Malformed("%s: missing" % w)
        v = obj[key]
        if kind == "str":
            out[key] = _str(v, w)
        elif kind == "role":
            # 3.3: an enumerated string outside its domain does not parse.
            r = _str(v, w)
            if r not in ("buyer", "seller"):
                raise Malformed("%s: not buyer or seller" % w)
            out[key] = r
        elif kind == "u64":
            out[key] = _u64(v, w)
        elif kind == "hash":
            out[key] = _hex(v, 32, w)
        elif kind == "sig":
            out[key] = _hex(v, 64, w)
        elif kind == "bytes":
            out[key] = _hex(v, None, w)
        elif kind == "hash_list":
            if not isinstance(v, list):
                raise Malformed("%s: expected list" % w)
            out[key] = [_hex(h, 32, "%s[%d]" % (w, i)) for i, h in enumerate(v)]
        elif kind == "mandate":
            out[key] = parse_mandate(v, w)
        elif kind == "statement":
            out[key] = _parse(v, STATEMENT_SCHEMA, w)
        elif kind == "invoice":
            # 5.3: `bolt11` on the real rail, absent on the simulated rail.
            out[key] = _parse(v, INVOICE_SCHEMA, w, optional=("bolt11",))
        else:
            raise AssertionError(kind)
    return out


MANDATE_SCHEMA = {
    "version": "str",
    "principal_key": "hash",
    "agent_key": "hash",
    "role": "role",
    "scope": "hash_list",
    "cap_msat": "u64",
    "per_deal_max_msat": "u64",
    "payout_node": "str",
    "expires_at": "u64",
    "nonce": "hash",
    "principal_sig": "sig",
}

REQUEST_SCHEMA = {
    "version": "str",
    "job_id": "str",
    "spec_hash": "hash",
    "input": "bytes",
    "input_commitment": "hash",
    "buyer_nonce": "hash",
    "max_price_msat": "u64",
    "mandate_spent_msat": "u64",
    "mandate": "mandate",
    "agent_sig": "sig",
}

OFFER_SCHEMA = {
    "version": "str",
    "job_id": "str",
    "spec_hash": "hash",
    "input_commitment": "hash",
    "buyer_nonce": "hash",
    "price_msat": "u64",
    "offer_expires_at": "u64",
    "seller_node": "str",
    "backend_id": "str",
    "enc_scheme": "str",
    "rail": "str",
    "mandate": "mandate",
    "agent_sig": "sig",
}

STATEMENT_SCHEMA = {
    "version": "str",
    "job_id": "str",
    "spec_hash": "hash",
    "input_commitment": "hash",
    "offer_id": "hash",
    "buyer_nonce": "hash",
    "ciphertext_hash": "hash",
    "payment_hash": "hash",
}

BUNDLE_SCHEMA = {
    "version": "str",
    "backend_id": "str",
    "statement": "statement",
    "ciphertext": "bytes",
    "proof": "bytes",
}

INVOICE_SCHEMA = {
    "payee": "str",
    "payment_hash": "hash",
    "amount_msat": "u64",
    "created_at": "u64",
    "expiry_secs": "u64",
    "min_htlc_secs": "u64",
    "description_hash": "hash",
    "bolt11": "str",
}

BINDING_SCHEMA = {
    "version": "str",
    "offer_id": "hash",
    "statement_hash": "hash",
    "invoice": "invoice",
}


def parse_mandate(obj, where="mandate") -> dict:
    return _parse(obj, MANDATE_SCHEMA, where)


def parse_request(obj) -> dict:
    return _parse(obj, REQUEST_SCHEMA, "request", optional=("mandate", "agent_sig"))


def parse_offer(obj) -> dict:
    # mandate and agent_sig are "required by default": their absence is a
    # mandate refusal (O2), not a parse error, so they are parsed as optional.
    return _parse(obj, OFFER_SCHEMA, "offer", optional=("mandate", "agent_sig"))


def parse_bundle(obj) -> dict:
    return _parse(obj, BUNDLE_SCHEMA, "bundle")


def parse_binding(obj) -> dict:
    return _parse(obj, BINDING_SCHEMA, "binding")


def mandate_id_of(m: dict) -> bytes:
    return mandate_id(
        m["version"], m["principal_key"], m["agent_key"], m["role"], m["scope"],
        m["cap_msat"], m["per_deal_max_msat"], m["payout_node"], m["expires_at"], m["nonce"],
    )


def offer_id_of(o: dict) -> bytes:
    return offer_id(
        o["version"], o["job_id"], o["spec_hash"], o["input_commitment"], o["buyer_nonce"],
        o["price_msat"], o["offer_expires_at"], o["seller_node"], o["backend_id"],
        o["enc_scheme"], o["rail"],
    )


def request_id_of(r: dict) -> bytes:
    return request_id(
        r["version"], r["job_id"], r["spec_hash"], r["input_commitment"], r["buyer_nonce"],
        r["max_price_msat"], r["mandate_spent_msat"],
    )


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


@dataclass
class Refusal(Exception):
    stage: str  # request | offer | bundle | invoice
    code: str
    detail: str = ""

    def __str__(self):
        return "%s: %s (%s)" % (self.stage, self.code, self.detail)


# Wire codes, from the table of section 5.4a.
VERSION_CODE = "version"
JOB_CLASS_NOT_REGISTERED = "job_class_not_registered"
JOB_MISMATCH = "job_mismatch"
INPUT_COMMITMENT_MISMATCH = "input_commitment_mismatch"
REPLAYED_OR_MISDIRECTED = "replayed_or_misdirected"
PRICE_TOO_HIGH = "price_too_high"
DEAL_ABOVE_CEILING = "deal_above_ceiling"
OFFER_EXPIRED = "offer_expired"
BACKEND_NOT_ACCEPTED = "backend_not_accepted"
INSECURE_BACKEND_REFUSED = "insecure_backend_refused"
ENC_SCHEME_NOT_SUPPORTED = "enc_scheme_not_supported"
RAIL_NOT_SUPPORTED = "rail_not_supported"
OFFER_MISMATCH = "offer_mismatch"
CIPHERTEXT_HASH_MISMATCH = "ciphertext_hash_mismatch"
PROOF_INVALID = "proof_invalid"  # never produced here: V4 is out of scope
INVOICE_BINDING_MISMATCH = "invoice_binding_mismatch"
INVOICE_HASH_MISMATCH = "invoice_hash_mismatch"
INVOICE_AMOUNT_MISMATCH = "invoice_amount_mismatch"
INVOICE_PAYEE_MISMATCH = "invoice_payee_mismatch"
INVOICE_DESCRIPTION_MISMATCH = "invoice_description_mismatch"
INVOICE_EXPIRES_TOO_SOON = "invoice_expires_too_soon"
HTLC_LOCK_TOO_LONG = "htlc_lock_too_long"

# A body that breaks 3.3 is an HTTP 400 with no reason code (5.5); it never
# reaches the protocol.  Reported with a marker that is not a protocol code.
HTTP_400 = "http_400"

# Mandate families (5.4a: OwnMandate(x) -> own_mandate.x, CounterpartyMandate(x)
# -> counterparty_mandate.x) and sub-codes, in the check order of 2.1.
CP = "counterparty_mandate."
OWN = "own_mandate."
SUB_MISSING = "missing"  # present with its agent_sig
SUB_VERSION = "version"  # version is PCP/0
SUB_SIGNATURE_INVALID = "signature_invalid"  # principal_sig verifies
SUB_SELF_OWNED = "self_owned"  # principal_key != agent_key
SUB_AGENT_KEY_MISMATCH = "agent_key_mismatch"  # own mandate: agent_key is the agent's own key (start)
SUB_WRONG_ROLE = "wrong_role"  # role
SUB_EXPIRED = "expired"  # now < expires_at
SUB_SCOPE_MISMATCH = "scope_mismatch"  # scope covers the spec_hash
SUB_AGENT_SIGNATURE_INVALID = "agent_signature_invalid"  # agent_sig verifies under agent_key
# Then the deal checks:
SUB_PAYOUT_NODE_MISMATCH = "payout_node_mismatch"  # payout_node = seller_node (seller mandate)
SUB_PER_DEAL_MAX_EXCEEDED = "per_deal_max_exceeded"
SUB_CAP_EXCEEDED = "cap_exceeded"


# ---------------------------------------------------------------------------
# 2.1 Mandate verification
# ---------------------------------------------------------------------------


def mandate_expired(m: dict, now: int) -> bool:
    """``expires_at``: time at and after which the mandate is void
    (2.1: the check is ``now < expires_at``)."""
    return not (now < m["expires_at"])


def verify_mandate(m, agent_sig, auth_of_mandate_id, role: str, now: int, spec_h: bytes,
                   stage: str, family: str) -> bytes:
    """The mandate checks of 2.1, in the order the SPEC gives, the first
    failure being the reason: missing, version, signature_invalid,
    self_owned, wrong_role, expired, scope_mismatch, agent_signature_invalid.
    Returns ``mandate_id``.

    ``auth_of_mandate_id(mid)`` gives the 32-byte value the agent signed
    (``offer_auth`` for an offer); pass ``None`` to skip the agent-signature
    check (the buyer's own mandate at R0, whose request it signed itself).
    ``family`` is ``CP`` or ``OWN``."""
    def refuse(sub, detail):
        raise Refusal(stage, family + sub, detail)

    if m is None or (auth_of_mandate_id is not None and agent_sig is None):
        refuse(SUB_MISSING, "mandate or agent_sig missing")
    if m["version"] != VERSION:
        refuse(SUB_VERSION, "mandate.version=%r" % m["version"])
    mid = mandate_id_of(m)
    if not ed25519_verify(m["principal_key"], m["principal_sig"], mid):
        refuse(SUB_SIGNATURE_INVALID, "principal_sig does not verify over mandate_id")
    if m["principal_key"] == m["agent_key"]:
        refuse(SUB_SELF_OWNED, "principal_key = agent_key")
    if m["role"] != role:
        refuse(SUB_WRONG_ROLE, "role=%r, expected %r" % (m["role"], role))
    if mandate_expired(m, now):
        refuse(SUB_EXPIRED, "expires_at=%d now=%d" % (m["expires_at"], now))
    if spec_h not in m["scope"]:
        refuse(SUB_SCOPE_MISMATCH, "spec_hash not in scope")
    if auth_of_mandate_id is not None:
        if not ed25519_verify(m["agent_key"], agent_sig, auth_of_mandate_id(mid)):
            refuse(SUB_AGENT_SIGNATURE_INVALID, "agent_sig does not verify under agent_key")
    return mid


# ---------------------------------------------------------------------------
# The buyer
# ---------------------------------------------------------------------------


@dataclass
class BuyerPolicy:
    max_price_msat: int
    accepted_backend_id: str
    allow_insecure_dev_backend: bool
    htlc_secs: int
    min_invoice_remaining_secs: int
    max_deal_msat: int  # the per-deal value ceiling of O1
    rail: str
    payout_node: str
    allow_unregistered_job_classes: bool = False
    # The buyer agent's own public key (2.1: an agent starts only with a
    # mandate made for it).  None: not known to this check.
    agent_key: Optional[bytes] = None


def is_secure_backend(backend_id: str) -> bool:
    """7.3: the dev backend is insecure.  7.2: ``risc0-zkvm-3-succinct/<image id>``
    is the secure one.  Anything else we do not know and treat as not secure."""
    return backend_id.startswith("risc0-zkvm-3-succinct/")


class Buyer:
    """One purchase: the buyer's own state is its request (input, nonce,
    mandate) and its policy.  Each ``check_*`` either returns derived state or
    raises :class:`Refusal` with the stage and SPEC code."""

    def __init__(self, request_json: dict, policy: BuyerPolicy):
        self.policy = policy
        self.req = parse_request(request_json)
        self.input = self.req["input"]
        self.input_commitment = input_commitment(self.input)
        self.buyer_nonce = self.req["buyer_nonce"]
        self.job_id = self.req["job_id"]
        self.spec_hash = self.req["spec_hash"]
        self.own_mandate = self.req["mandate"]
        self.own_mandate_id = mandate_id_of(self.own_mandate) if self.own_mandate else None
        self.spent = self.req["mandate_spent_msat"]

    # --- Agent start (2.1) ---------------------------------------------
    def check_start(self) -> None:
        """An agent starts only with a mandate made for it: version,
        principal_sig, not self-owned, agent_key is its own key, in that
        order.  Failing, it does not start (reported as stage ``request``)."""
        m = self.own_mandate
        if m is None:
            raise Refusal("request", OWN + SUB_MISSING, "no own mandate")
        if m["version"] != VERSION:
            raise Refusal("request", OWN + SUB_VERSION, "mandate.version=%r" % m["version"])
        if not ed25519_verify(m["principal_key"], m["principal_sig"], mandate_id_of(m)):
            raise Refusal("request", OWN + SUB_SIGNATURE_INVALID, "principal_sig does not verify")
        if m["principal_key"] == m["agent_key"]:
            raise Refusal("request", OWN + SUB_SELF_OWNED, "principal_key = agent_key")
        if self.policy.agent_key is not None and m["agent_key"] != self.policy.agent_key:
            raise Refusal("request", OWN + SUB_AGENT_KEY_MISMATCH, "mandate is for another agent key")

    # --- R0 -------------------------------------------------------------
    def check_r0(self, now: int) -> None:
        """Before sending the request: job class registered; own mandate valid,
        a buyer mandate, unexpired, covers the class, has cap left."""
        if self.spec_hash not in REGISTRY and not self.policy.allow_unregistered_job_classes:
            raise Refusal("request", JOB_CLASS_NOT_REGISTERED, "spec_hash not in registry")
        if self.spec_hash in REGISTRY and REGISTRY[self.spec_hash][0] != self.job_id:
            raise Refusal("request", JOB_MISMATCH, "job_id does not name the registered class")
        # Own mandate (2.1 order; no agent_sig check: the buyer signed the
        # request itself, so that is not a check on the mandate).  Cap left:
        # committed < cap_msat (the price is not known yet).
        verify_mandate(self.own_mandate, None, None, "buyer", now, self.spec_hash, "request", OWN)
        if not (self.spent < self.own_mandate["cap_msat"]):
            raise Refusal("request", OWN + SUB_CAP_EXCEEDED, "committed %d >= cap %d" % (self.spent, self.own_mandate["cap_msat"]))
        # The request's own commitment and signature (not a SPEC buyer check,
        # but the buyer made them, so they had better hold).
        if self.req["input_commitment"] != self.input_commitment:
            raise Refusal("request", INPUT_COMMITMENT_MISMATCH, "request.input_commitment is not of request.input")

    # --- O1 / O2 ----------------------------------------------------------
    def check_offer(self, offer_json: dict, now: int) -> dict:
        p = self.policy
        try:
            o = parse_offer(offer_json)
        except Malformed as e:
            raise Refusal("offer", HTTP_400, str(e))

        # O1: version, job_id/spec_hash as requested, input_commitment of own
        # input, buyer_nonce is own, price <= max, price <= ceiling, not
        # expired, backend accepted and (unless testing) secure, enc_scheme, rail.
        if o["version"] != VERSION:
            raise Refusal("offer", VERSION_CODE, "offer.version=%r" % o["version"])
        if o["job_id"] != self.job_id or o["spec_hash"] != self.spec_hash:
            raise Refusal("offer", JOB_MISMATCH, "job_id/spec_hash differ from the request")
        if o["input_commitment"] != self.input_commitment:
            raise Refusal("offer", INPUT_COMMITMENT_MISMATCH, "offer.input_commitment is not of own input")
        if o["buyer_nonce"] != self.buyer_nonce:
            raise Refusal("offer", REPLAYED_OR_MISDIRECTED, "buyer_nonce is not ours")
        if o["price_msat"] > p.max_price_msat:
            raise Refusal("offer", PRICE_TOO_HIGH, "%d > %d" % (o["price_msat"], p.max_price_msat))
        if o["price_msat"] > p.max_deal_msat:
            raise Refusal("offer", DEAL_ABOVE_CEILING, "%d > %d" % (o["price_msat"], p.max_deal_msat))
        # offer_expires_at (5.1): "time at and after which the offer is void"
        if now >= o["offer_expires_at"]:
            raise Refusal("offer", OFFER_EXPIRED, "offer_expires_at=%d now=%d" % (o["offer_expires_at"], now))
        if o["backend_id"] != p.accepted_backend_id:
            raise Refusal("offer", BACKEND_NOT_ACCEPTED, "backend_id=%r" % o["backend_id"])
        if not is_secure_backend(o["backend_id"]) and not p.allow_insecure_dev_backend:
            raise Refusal("offer", INSECURE_BACKEND_REFUSED, "backend_id=%r" % o["backend_id"])
        if o["enc_scheme"] != ENC_SCHEME:
            raise Refusal("offer", ENC_SCHEME_NOT_SUPPORTED, "enc_scheme=%r" % o["enc_scheme"])
        if o["rail"] not in RAILS or o["rail"] != p.rail:
            raise Refusal("offer", RAIL_NOT_SUPPORTED, "rail=%r" % o["rail"])

        oid = offer_id_of(o)

        # O2: the seller's mandate and agent_sig (2.1, in its order), then the
        # deal checks of 2.1: seller_node = payout_node, price within the
        # seller's per-deal maximum; then own mandate: unexpired, price within
        # own per-deal maximum and remaining cap.
        m = o["mandate"]
        mid = verify_mandate(m, o["agent_sig"], lambda mid_: offer_auth(oid, mid_),
                             "seller", now, o["spec_hash"], "offer", CP)
        if o["seller_node"] != m["payout_node"]:
            raise Refusal("offer", CP + SUB_PAYOUT_NODE_MISMATCH, "seller_node %r != payout_node %r" % (o["seller_node"], m["payout_node"]))
        if m["per_deal_max_msat"] < o["price_msat"]:
            raise Refusal("offer", CP + SUB_PER_DEAL_MAX_EXCEEDED, "seller per_deal_max %d < price %d" % (m["per_deal_max_msat"], o["price_msat"]))

        own = self.own_mandate
        if own is None:
            raise Refusal("offer", OWN + SUB_MISSING, "own mandate missing")
        if mandate_expired(own, now):
            raise Refusal("offer", OWN + SUB_EXPIRED, "own mandate expired")
        if o["price_msat"] > own["per_deal_max_msat"]:
            raise Refusal("offer", OWN + SUB_PER_DEAL_MAX_EXCEEDED, "price above own per_deal_max")
        if self.spent + o["price_msat"] > own["cap_msat"]:
            raise Refusal("offer", OWN + SUB_CAP_EXCEEDED, "spent %d + price %d > cap %d" % (self.spent, o["price_msat"], own["cap_msat"]))

        return {"offer": o, "offer_id": oid, "seller_mandate": m, "seller_mandate_id": mid}

    # --- V1 .. V3 (V4 opaque) ----------------------------------------------
    def check_bundle(self, bundle_json: dict, accepted: dict) -> dict:
        o = accepted["offer"]
        oid = accepted["offer_id"]
        try:
            b = parse_bundle(bundle_json)
        except Malformed as e:
            raise Refusal("bundle", HTTP_400, str(e))
        st = b["statement"]

        # V1, in this order: version of the bundle and of its statement
        # (Version), backend_id is the offer's (BackendNotAccepted),
        # statement.buyer_nonce is own (ReplayedOrMisdirected).
        if b["version"] != VERSION:
            raise Refusal("bundle", VERSION_CODE, "bundle.version=%r" % b["version"])
        if st["version"] != VERSION:
            raise Refusal("bundle", VERSION_CODE, "statement.version=%r" % st["version"])
        if b["backend_id"] != o["backend_id"]:
            raise Refusal("bundle", BACKEND_NOT_ACCEPTED, "backend_id %r != offer's %r" % (b["backend_id"], o["backend_id"]))
        if st["buyer_nonce"] != self.buyer_nonce:
            raise Refusal("bundle", REPLAYED_OR_MISDIRECTED, "statement.buyer_nonce is not ours")

        # V2
        if st["offer_id"] != oid:
            raise Refusal("bundle", OFFER_MISMATCH, "statement.offer_id != accepted offer_id")
        if st["job_id"] != self.job_id or st["spec_hash"] != self.spec_hash:
            raise Refusal("bundle", JOB_MISMATCH, "statement job_id/spec_hash differ")
        if st["input_commitment"] != self.input_commitment:
            raise Refusal("bundle", INPUT_COMMITMENT_MISMATCH, "statement.input_commitment is not of own input")

        # V3
        c_hash = ciphertext_hash(b["ciphertext"])
        if c_hash != st["ciphertext_hash"]:
            raise Refusal("bundle", CIPHERTEXT_HASH_MISMATCH, "tagged_hash(ciphertext) != statement.ciphertext_hash")

        # V4: the proof is opaque to this implementation.  We build the
        # expected statement from our own state, taking only ciphertext_hash
        # and payment_hash from the bundle, as the SPEC says, and hand it on.
        expected = (VERSION, self.job_id, self.spec_hash, self.input_commitment, oid,
                    self.buyer_nonce, c_hash, st["payment_hash"])
        sh = statement_hash(*expected)
        return {
            "bundle": b,
            "expected_statement": expected,
            "statement_hash": sh,
            "payment_hash": st["payment_hash"],
            "bundle_id": bundle_id(sh, b["backend_id"], b["ciphertext"], b["proof"]),
            "proof_checked": False,
        }

    # --- V5 .. V8 ---------------------------------------------------------
    def check_binding(self, binding_json: dict, accepted: dict, verified: dict, now: int) -> dict:
        p = self.policy
        o = accepted["offer"]
        oid = accepted["offer_id"]
        m = accepted["seller_mandate"]
        try:
            bd = parse_binding(binding_json)
        except Malformed as e:
            raise Refusal("invoice", HTTP_400, str(e))
        inv = bd["invoice"]
        sh = verified["statement_hash"]
        h = verified["payment_hash"]

        # V5: version; names this offer_id and statement_hash
        if bd["version"] != VERSION:
            raise Refusal("invoice", VERSION_CODE, "binding.version=%r" % bd["version"])
        if bd["offer_id"] != oid or bd["statement_hash"] != sh:
            raise Refusal("invoice", INVOICE_BINDING_MISMATCH, "binding names another offer_id/statement_hash")
        # V6
        if inv["payment_hash"] != h:
            raise Refusal("invoice", INVOICE_HASH_MISMATCH, "invoice.payment_hash != H")
        # V7
        if inv["amount_msat"] != o["price_msat"]:
            raise Refusal("invoice", INVOICE_AMOUNT_MISMATCH, "%d != %d" % (inv["amount_msat"], o["price_msat"]))
        if not (inv["payee"] == o["seller_node"] == m["payout_node"]):
            raise Refusal("invoice", INVOICE_PAYEE_MISMATCH, "payee %r seller_node %r payout_node %r" % (inv["payee"], o["seller_node"], m["payout_node"]))
        if inv["description_hash"] != sh:
            raise Refusal("invoice", INVOICE_DESCRIPTION_MISMATCH, "description_hash != statement_hash")
        # V8: more than min_invoice_remaining_secs left:
        #   now + min_invoice_remaining_secs < created_at + expiry_secs
        if not (now + p.min_invoice_remaining_secs < inv["created_at"] + inv["expiry_secs"]):
            raise Refusal("invoice", INVOICE_EXPIRES_TOO_SOON, "now %d + min %d >= created_at %d + expiry %d" % (
                now, p.min_invoice_remaining_secs, inv["created_at"], inv["expiry_secs"]))
        if inv["min_htlc_secs"] > p.htlc_secs:
            raise Refusal("invoice", HTLC_LOCK_TOO_LONG, "min_htlc_secs %d > htlc_secs %d" % (inv["min_htlc_secs"], p.htlc_secs))
        # P1 rule, checkable offline: never pay on an offer past
        # offer_expires_at (5.1: void at and after it).
        if now >= o["offer_expires_at"]:
            raise Refusal("invoice", OFFER_EXPIRED, "offer expired before paying")
        return {"binding": bd, "invoice": inv}

    # --- the whole offline path --------------------------------------------
    def evaluate(self, offer_json, bundle_json, binding_json, now: int, r0_now=None):
        """Run R0, O1, O2, V1-V3, (V4 skipped), V5-V8.  Returns
        ``("accepted", None)`` or ``(stage, code)``.  R0 runs when the
        request is made, at ``r0_now`` (default ``now``); the rest at ``now``."""
        try:
            self.check_start()
            self.check_r0(now if r0_now is None else r0_now)
            acc = self.check_offer(offer_json, now)
            ver = self.check_bundle(bundle_json, acc)
            self.check_binding(binding_json, acc, ver, now)
        except Refusal as r:
            return r.stage, r.code, r.detail
        return "accepted", None, ""


# ---------------------------------------------------------------------------
# Post-payment checks (P3-P5), for completeness; no corpus case reaches them.
# ---------------------------------------------------------------------------


def post_payment(k: bytes, h: bytes, c: bytes, offer_i: bytes, n: int, inp: bytes):
    if payment_hash(k) != h:
        return "preimage_mismatch", None
    r = decrypt(k, c, offer_i)
    if r is None:
        return "decryption_failed", None
    if not sudoku_check(n, inp, r):
        return "post_payment_check_failed", r
    return None, r
