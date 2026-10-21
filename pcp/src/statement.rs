//! The statement core: the exact relation every PCP/0 proof backend proves
//! (SPEC.md 7.1 item 5 and 7.2), as one pure function.
//!
//! ```text
//! input  (private)  job class id (spec_hash), input bytes, result R, key k, ciphertext C
//!        (public)   offer binding: offer_id, buyer_nonce
//! checks            job class is known (or given) and its spec_hash matches
//!                   job_check(input, R)
//!                   C == ChaCha20-Poly1305(tagged_hash("enc-key",[k]), 0^12, R,
//!                                          aad = tagged_hash("enc-aad",[offer_id]))
//! output (public)   Journal {version, job_id, spec_hash,
//!                            input_commitment = tagged_hash("input",[input]),
//!                            offer_id, buyer_nonce,
//!                            ciphertext_hash  = tagged_hash("ciphertext",[C]),
//!                            payment_hash     = SHA256(k)}
//! ```
//!
//! [`evaluate`] is the one source of truth for this relation. Two callers:
//!
//! - the INSECURE dev backend (`proof::InsecureDevTransparentBackend`), which
//!   unseals the witness and calls [`evaluate_with`] in the clear;
//! - the RISC Zero guest in `../pcp-risc0/methods/guest/`, which calls
//!   [`evaluate`] inside the zkVM and commits [`Journal::to_bytes`].
//!
//! A verifier then compares the journal with the statement it expects
//! ([`Journal::check_expected`]). The journal bytes are exactly the
//! `statement_hash` pre-image, so `SHA256(journal) = statement_hash`.
//!
//! Constraints, so that the same code runs in a zkVM guest: `core` and
//! `alloc` only (this module compiles with the crate's `std` feature off),
//! dependencies `sha2` and `chacha20poly1305` only, no randomness, no clock,
//! no I/O, no floating point, and no panics on any input: every failure is a
//! [`RelationError`]. (The guest turns an error into a panic, which yields no
//! receipt.)

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::crypto;
use crate::encoding::{canonical_bytes, sha256, Hash32, VERSION};
use crate::job::{input_commitment, JobClass, SudokuJob, TestSuiteJob};

/// Tag of the guest input encoding: `canonical_bytes("guest-input", ...)`.
pub const GUEST_INPUT_TAG: &str = "guest-input";

/// Tag of the journal encoding. It is the statement tag, so the journal is
/// the `statement_hash` pre-image.
pub const JOURNAL_TAG: &str = "statement";

/// Everything the relation takes. Private to the seller (it contains `R`
/// and `k`) except `offer_id` and `buyer_nonce`.
#[derive(Clone, PartialEq, Eq)]
pub struct StatementInput {
    /// The job class id: `spec_hash = tagged_hash("spec", [job_id, params])`.
    pub spec_hash: Hash32,
    /// The job input in the class's canonical encoding.
    pub input: Vec<u8>,
    /// The result `R` being sold.
    pub result: Vec<u8>,
    /// The key `k`; `SHA256(k)` is the Lightning payment hash.
    pub key: [u8; 32],
    /// `C`, claimed to be `Enc_k(R)` bound to `offer_id`.
    pub ciphertext: Vec<u8>,
    /// Offer binding: the offer this proof answers.
    pub offer_id: Hash32,
    /// Offer binding: the buyer's nonce.
    pub buyer_nonce: Hash32,
}

impl core::fmt::Debug for StatementInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StatementInput { <redacted: contains R and k> }")
    }
}

impl StatementInput {
    /// Canonical byte encoding, used to pass the input to a zkVM guest:
    /// `canonical_bytes("guest-input", [spec_hash, input, result, k, C,
    /// offer_id, buyer_nonce])`.
    pub fn encode(&self) -> Vec<u8> {
        canonical_bytes(
            GUEST_INPUT_TAG,
            &[
                &self.spec_hash,
                &self.input,
                &self.result,
                &self.key,
                &self.ciphertext,
                &self.offer_id,
                &self.buyer_nonce,
            ],
        )
    }

    /// Strict inverse of [`StatementInput::encode`]: wrong tag, wrong field
    /// count, wrong 32-byte field length or trailing bytes give `None`.
    pub fn decode(bytes: &[u8]) -> Option<StatementInput> {
        let f = decode_fields(bytes, GUEST_INPUT_TAG, 7)?;
        Some(StatementInput {
            spec_hash: f[0].try_into().ok()?,
            input: f[1].to_vec(),
            result: f[2].to_vec(),
            key: f[3].try_into().ok()?,
            ciphertext: f[4].to_vec(),
            offer_id: f[5].try_into().ok()?,
            buyer_nonce: f[6].try_into().ok()?,
        })
    }
}

/// The public output of the relation: the statement fields (SPEC 5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    /// Always `"PCP/0"`.
    pub version: String,
    /// Job class identifier, e.g. `"pcp/sudoku/v0"`.
    pub job_id: String,
    /// The job class's `spec_hash`.
    pub spec_hash: Hash32,
    /// `tagged_hash("input", [input])`.
    pub input_commitment: Hash32,
    /// Offer binding.
    pub offer_id: Hash32,
    /// Offer binding.
    pub buyer_nonce: Hash32,
    /// `tagged_hash("ciphertext", [C])`.
    pub ciphertext_hash: Hash32,
    /// `H = SHA256(k)`.
    pub payment_hash: Hash32,
}

impl Journal {
    /// `canonical_bytes("statement", [version, job_id, spec_hash,
    /// input_commitment, offer_id, buyer_nonce, ciphertext_hash,
    /// payment_hash])`. A zkVM guest commits exactly these bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        canonical_bytes(
            JOURNAL_TAG,
            &[
                self.version.as_bytes(),
                self.job_id.as_bytes(),
                &self.spec_hash,
                &self.input_commitment,
                &self.offer_id,
                &self.buyer_nonce,
                &self.ciphertext_hash,
                &self.payment_hash,
            ],
        )
    }

    /// Strict inverse of [`Journal::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Option<Journal> {
        let f = decode_fields(bytes, JOURNAL_TAG, 8)?;
        Some(Journal {
            version: core::str::from_utf8(f[0]).ok()?.to_string(),
            job_id: core::str::from_utf8(f[1]).ok()?.to_string(),
            spec_hash: f[2].try_into().ok()?,
            input_commitment: f[3].try_into().ok()?,
            offer_id: f[4].try_into().ok()?,
            buyer_nonce: f[5].try_into().ok()?,
            ciphertext_hash: f[6].try_into().ok()?,
            payment_hash: f[7].try_into().ok()?,
        })
    }

    /// `statement_hash = tagged_hash("statement", [...]) = SHA256(to_bytes())`.
    pub fn statement_hash(&self) -> Hash32 {
        sha256(&self.to_bytes())
    }

    /// Compare with the journal the verifier expects, field by field in
    /// statement order, and name the first field that differs.
    pub fn check_expected(&self, expected: &Journal) -> Result<(), JournalMismatch> {
        if self.version != expected.version {
            Err(JournalMismatch::Version)
        } else if self.job_id != expected.job_id || self.spec_hash != expected.spec_hash {
            Err(JournalMismatch::Job)
        } else if self.input_commitment != expected.input_commitment {
            Err(JournalMismatch::InputCommitment)
        } else if self.offer_id != expected.offer_id || self.buyer_nonce != expected.buyer_nonce {
            Err(JournalMismatch::OfferBinding)
        } else if self.ciphertext_hash != expected.ciphertext_hash {
            Err(JournalMismatch::CiphertextHash)
        } else if self.payment_hash != expected.payment_hash {
            Err(JournalMismatch::PaymentHash)
        } else {
            Ok(())
        }
    }
}

/// Why the relation does not hold for a given input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationError {
    /// [`evaluate`] does not know a job class with this `spec_hash`.
    UnknownJobClass,
    /// [`evaluate_with`] was given a job class whose `spec_hash` differs
    /// from the input's.
    SpecMismatch,
    /// `job_check(input, R)` is false.
    JobCheckFailed,
    /// `C != Enc_k(R)` under `offer_id`.
    CiphertextMismatch,
}

/// The first journal field that differs from the expected statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalMismatch {
    Version,
    /// `job_id` or `spec_hash`.
    Job,
    InputCommitment,
    /// `offer_id` or `buyer_nonce`.
    OfferBinding,
    CiphertextHash,
    PaymentHash,
}

/// The job classes the statement core knows by `spec_hash`: the reviewed
/// reference classes (`pcp/sudoku/v0` with n = 4 and n = 9, and
/// `pcp/testsuite-toyexpr/v0`). A zkVM guest built from this crate can
/// prove exactly these.
pub static KNOWN_JOB_CLASSES: [&(dyn JobClass + Sync); 3] =
    [&SudokuJob::four(), &SudokuJob::nine(), &TestSuiteJob];

/// Look up a known job class by `spec_hash`.
pub fn known_job(spec_hash: &Hash32) -> Option<&'static (dyn JobClass + Sync)> {
    KNOWN_JOB_CLASSES
        .iter()
        .copied()
        .find(|j| j.spec_hash() == *spec_hash)
}

/// The relation, for a job class known by `spec_hash`. This is what the
/// zkVM guest runs.
pub fn evaluate(w: &StatementInput) -> Result<Journal, RelationError> {
    let job = known_job(&w.spec_hash).ok_or(RelationError::UnknownJobClass)?;
    evaluate_with(job, w)
}

/// The relation, for a job class supplied by the caller (the dev backend
/// passes any `JobClass`, including test-only ones). Checks run in this
/// order: spec hash, `job_check`, `C == Enc_k(R)`.
pub fn evaluate_with(job: &dyn JobClass, w: &StatementInput) -> Result<Journal, RelationError> {
    if job.spec_hash() != w.spec_hash {
        return Err(RelationError::SpecMismatch);
    }
    if !job.check(&w.input, &w.result) {
        return Err(RelationError::JobCheckFailed);
    }
    if crypto::encrypt(&w.key, &w.offer_id, &w.result) != w.ciphertext {
        return Err(RelationError::CiphertextMismatch);
    }
    Ok(Journal {
        version: VERSION.to_string(),
        job_id: job.job_id().to_string(),
        spec_hash: w.spec_hash,
        input_commitment: input_commitment(&w.input),
        offer_id: w.offer_id,
        buyer_nonce: w.buyer_nonce,
        ciphertext_hash: crypto::ciphertext_hash(&w.ciphertext),
        payment_hash: crypto::payment_hash(&w.key),
    })
}

/// Split `canonical_bytes(tag, fields)` back into exactly `n` fields.
fn decode_fields<'a>(bytes: &'a [u8], tag: &str, n: usize) -> Option<Vec<&'a [u8]>> {
    let mut rest = bytes;
    let t = take_lp(&mut rest)?;
    let full = [VERSION.as_bytes(), b"/", tag.as_bytes()].concat();
    if t != full.as_slice() {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(take_lp(&mut rest)?);
    }
    rest.is_empty().then_some(out)
}

/// Take one length-prefixed field off the front of `rest`.
fn take_lp<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
    let end = 4usize.checked_add(len)?;
    let field = rest.get(4..end)?;
    *rest = &rest[end..];
    Some(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::tagged_hash;

    /// `pcp/sudoku/v0`, n = 4, the puzzle used by the conformance vectors.
    const PUZZLE4: [u8; 16] = [1, 0, 0, 4, 0, 0, 1, 0, 0, 1, 0, 0, 4, 0, 0, 1];
    const SOLUTION4: [u8; 16] = [1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1];

    fn fixed() -> StatementInput {
        let key = [0x11u8; 32];
        let offer_id = [0x22u8; 32];
        StatementInput {
            spec_hash: SudokuJob::four().spec_hash(),
            input: PUZZLE4.to_vec(),
            result: SOLUTION4.to_vec(),
            key,
            ciphertext: crypto::encrypt(&key, &offer_id, &SOLUTION4),
            offer_id,
            buyer_nonce: [0x44u8; 32],
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| alloc::format!("{x:02x}")).collect()
    }

    #[test]
    fn honest_input_gives_the_expected_journal() {
        let w = fixed();
        assert!(SudokuJob::four().check(&PUZZLE4, &SOLUTION4));
        let j = evaluate(&w).unwrap();
        assert_eq!(j.version, "PCP/0");
        assert_eq!(j.job_id, "pcp/sudoku/v0");
        assert_eq!(j.spec_hash, SudokuJob::four().spec_hash());
        assert_eq!(j.input_commitment, input_commitment(&PUZZLE4));
        assert_eq!(j.payment_hash, crypto::payment_hash(&w.key));
        assert_eq!(j.ciphertext_hash, crypto::ciphertext_hash(&w.ciphertext));
        assert_eq!(evaluate_with(&SudokuJob::four(), &w), Ok(j));
    }

    #[test]
    fn every_relation_is_checked() {
        let mut w = fixed();
        w.spec_hash = [0u8; 32];
        assert_eq!(evaluate(&w), Err(RelationError::UnknownJobClass));
        assert_eq!(
            evaluate_with(&SudokuJob::four(), &w),
            Err(RelationError::SpecMismatch)
        );

        let mut w = fixed();
        w.result.swap(0, 1);
        assert_eq!(evaluate(&w), Err(RelationError::JobCheckFailed));

        // A valid result encrypted under another key, another offer, or a
        // ciphertext with one bit flipped: C != Enc_k(R).
        let mut w = fixed();
        w.ciphertext = crypto::encrypt(&[0x12; 32], &w.offer_id, &w.result);
        assert_eq!(evaluate(&w), Err(RelationError::CiphertextMismatch));
        let mut w = fixed();
        w.ciphertext = crypto::encrypt(&w.key, &[0x23; 32], &w.result);
        assert_eq!(evaluate(&w), Err(RelationError::CiphertextMismatch));
        let mut w = fixed();
        w.ciphertext[0] ^= 1;
        assert_eq!(evaluate(&w), Err(RelationError::CiphertextMismatch));

        // A different key gives a different C and H: the relation holds for
        // that key, and the verifier catches it when it compares journals
        // (C is compared first).
        let mut w = fixed();
        w.key = [0x12; 32];
        w.ciphertext = crypto::encrypt(&w.key, &w.offer_id, &w.result);
        let j = evaluate(&w).unwrap();
        let expected = evaluate(&fixed()).unwrap();
        assert_ne!(j.payment_hash, expected.payment_hash);
        assert_eq!(
            j.check_expected(&expected),
            Err(JournalMismatch::CiphertextHash)
        );
    }

    #[test]
    fn journal_mismatches_name_the_first_field() {
        let good = evaluate(&fixed()).unwrap();
        assert_eq!(good.check_expected(&good), Ok(()));
        type Case = (fn(&mut Journal), JournalMismatch);
        let cases: [Case; 6] = [
            (|j| j.version.push('x'), JournalMismatch::Version),
            (|j| j.job_id.push('x'), JournalMismatch::Job),
            (
                |j| j.input_commitment[0] ^= 1,
                JournalMismatch::InputCommitment,
            ),
            (|j| j.buyer_nonce[0] ^= 1, JournalMismatch::OfferBinding),
            (
                |j| j.ciphertext_hash[0] ^= 1,
                JournalMismatch::CiphertextHash,
            ),
            (|j| j.payment_hash[0] ^= 1, JournalMismatch::PaymentHash),
        ];
        for (mutate, want) in cases {
            let mut j = good.clone();
            mutate(&mut j);
            assert_eq!(j.check_expected(&good), Err(want));
        }
    }

    #[test]
    fn encodings_roundtrip_strictly() {
        let w = fixed();
        let enc = w.encode();
        assert_eq!(StatementInput::decode(&enc), Some(w.clone()));
        let mut long = enc.clone();
        long.push(0);
        assert_eq!(StatementInput::decode(&long), None, "trailing byte");
        assert_eq!(StatementInput::decode(&enc[..enc.len() - 1]), None);
        let j = evaluate(&w).unwrap();
        let jb = j.to_bytes();
        assert_eq!(Journal::from_bytes(&jb), Some(j.clone()));
        assert_eq!(Journal::from_bytes(&enc), None, "wrong tag");
        assert_eq!(StatementInput::decode(&jb), None, "wrong tag");
        assert_eq!(StatementInput::decode(&[0xff; 3]), None);
        assert_eq!(StatementInput::decode(&[0xff; 64]), None);
        // The journal is the statement_hash pre-image.
        assert_eq!(
            j.statement_hash(),
            tagged_hash(
                "statement",
                &[
                    b"PCP/0",
                    b"pcp/sudoku/v0",
                    &j.spec_hash,
                    &j.input_commitment,
                    &j.offer_id,
                    &j.buyer_nonce,
                    &j.ciphertext_hash,
                    &j.payment_hash,
                ]
            )
        );
        assert!(format_is_redacted(&w));
    }

    fn format_is_redacted(w: &StatementInput) -> bool {
        let s = alloc::format!("{w:?}");
        !s.contains("17") && s.contains("redacted")
    }

    #[test]
    fn known_classes_are_the_reference_registry() {
        for j in KNOWN_JOB_CLASSES {
            assert_eq!(known_job(&j.spec_hash()).unwrap().job_id(), j.job_id());
        }
        assert!(known_job(&[0u8; 32]).is_none());
    }

    /// SPEC.md Appendix A, vectors 14 to 17. Computed by this crate and
    /// independently by a Python implementation (hashlib and
    /// `cryptography`'s ChaCha20Poly1305); both agree.
    #[test]
    fn statement_core_conformance_vectors() {
        let w = fixed();
        assert_eq!(hex(&w.ciphertext), STATEMENT_VECTORS[0]);
        assert_eq!(hex(&sha256(&w.encode())), STATEMENT_VECTORS[1]);
        let j = evaluate(&w).unwrap();
        assert_eq!(hex(&sha256(&j.to_bytes())), STATEMENT_VECTORS[2]);
        assert_eq!(hex(&j.statement_hash()), STATEMENT_VECTORS[2]);
        assert_eq!(
            j.to_bytes().len(),
            STATEMENT_VECTORS[3].parse::<usize>().unwrap()
        );
    }

    const STATEMENT_VECTORS: [&str; 4] = [
        "4a3f402e4c2e98b8371e2fe27c1869c35d2b11e3107848cff28e8b624e5bf554",
        "ee93318d136f05eeecc095c3512a667c4bae50fa81b8fb1718e29c30ce66bed9",
        "9119de0c3d909b092a118b655588b7e85e004e9de2d17ab297f247cd42bd3c02",
        "261",
    ];
}
