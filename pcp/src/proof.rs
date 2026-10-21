//! The statement, the proof bundle and the proof-backend interface
//! (SPEC.md sections 5 and 7).
//!
//! The statement every backend proves, for a given job class `J`:
//!
//! > there exist `input, R, k` such that
//! > `input_commitment = tagged_hash("input", [input])`,
//! > `J.check(input, R) = true`,
//! > `C = Enc_k(R)` bound to `offer_id`,
//! > `ciphertext_hash = tagged_hash("ciphertext", [C])`, and
//! > `payment_hash = SHA256(k)`.
//!
//! The relation itself lives in [`crate::statement`], shared with the RISC
//! Zero guest in `../pcp-risc0/`. A real backend proves it in zero knowledge.
//! The only backend in v0, [`InsecureDevTransparentBackend`], does **not**:
//! read its documentation before using it for anything.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::encoding::{self, hex32, hexbytes, sha256, tagged_hash, Hash32, VERSION};
use crate::job::JobClass;
use crate::statement::{evaluate_with, Journal, JournalMismatch, RelationError, StatementInput};

/// The public statement. Everything a verifier needs except the job class
/// implementation and the ciphertext bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    /// Always `"PCP/0"`.
    pub version: String,
    /// Job class identifier, e.g. `"pcp/sudoku/v0"`.
    pub job_id: String,
    /// `JobClass::spec_hash()` of the predicate being proven.
    #[serde(with = "hex32")]
    pub spec_hash: Hash32,
    /// `tagged_hash("input", [input])`, supplied by the buyer.
    #[serde(with = "hex32")]
    pub input_commitment: Hash32,
    /// Identifier of the offer this proof answers (binds buyer, price, nonce).
    #[serde(with = "hex32")]
    pub offer_id: Hash32,
    /// The buyer's fresh nonce, repeated here so the statement is
    /// self-describing (it is also inside `offer_id`).
    #[serde(with = "hex32")]
    pub buyer_nonce: Hash32,
    /// `tagged_hash("ciphertext", [C])`.
    #[serde(with = "hex32")]
    pub ciphertext_hash: Hash32,
    /// `H = SHA256(k)`, the Lightning payment hash.
    #[serde(with = "hex32")]
    pub payment_hash: Hash32,
}

impl Statement {
    /// The statement as the public journal a zkVM guest commits
    /// ([`crate::statement::Journal`]).
    pub fn journal(&self) -> Journal {
        Journal {
            version: self.version.clone(),
            job_id: self.job_id.clone(),
            spec_hash: self.spec_hash,
            input_commitment: self.input_commitment,
            offer_id: self.offer_id,
            buyer_nonce: self.buyer_nonce,
            ciphertext_hash: self.ciphertext_hash,
            payment_hash: self.payment_hash,
        }
    }

    /// Canonical `statement_hash = tagged_hash("statement", [...])`, which
    /// is `SHA256` of the journal bytes.
    pub fn hash(&self) -> Hash32 {
        self.journal().statement_hash()
    }
}

impl From<Journal> for Statement {
    fn from(j: Journal) -> Statement {
        Statement {
            version: j.version,
            job_id: j.job_id,
            spec_hash: j.spec_hash,
            input_commitment: j.input_commitment,
            offer_id: j.offer_id,
            buyer_nonce: j.buyer_nonce,
            ciphertext_hash: j.ciphertext_hash,
            payment_hash: j.payment_hash,
        }
    }
}

/// The secret witness. Never leaves the seller except inside a proof that
/// (for a real backend) reveals nothing about it.
pub struct Witness {
    /// Job input (the buyer knows it too).
    pub input: Vec<u8>,
    /// The result `R` being sold.
    pub result: Vec<u8>,
    /// The key `k`; `SHA256(k)` is the payment hash.
    pub key: [u8; 32],
}

impl std::fmt::Debug for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Witness { <redacted> }")
    }
}

impl Witness {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encoding::lp(&mut out, &self.input);
        encoding::lp(&mut out, &self.result);
        out.extend_from_slice(&self.key);
        out
    }

    /// The statement core's input for this witness, `statement` and
    /// ciphertext: what a zkVM guest reads.
    pub fn statement_input(&self, statement: &Statement, ciphertext: &[u8]) -> StatementInput {
        StatementInput {
            spec_hash: statement.spec_hash,
            input: self.input.clone(),
            result: self.result.clone(),
            key: self.key,
            ciphertext: ciphertext.to_vec(),
            offer_id: statement.offer_id,
            buyer_nonce: statement.buyer_nonce,
        }
    }

    fn decode(bytes: &[u8]) -> Option<Witness> {
        let mut rest = bytes;
        let take = |rest: &mut &[u8]| -> Option<Vec<u8>> {
            let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let v = rest.get(4..4 + len)?.to_vec();
            *rest = &rest[4 + len..];
            Some(v)
        };
        let input = take(&mut rest)?;
        let result = take(&mut rest)?;
        let key: [u8; 32] = rest.try_into().ok()?;
        Some(Witness { input, result, key })
    }
}

/// What the seller sends the buyer before any payment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofBundle {
    /// Always `"PCP/0"`.
    pub version: String,
    /// Which backend produced `proof`.
    pub backend_id: String,
    /// The public statement.
    pub statement: Statement,
    /// `C = Enc_k(R)`.
    #[serde(with = "hexbytes")]
    pub ciphertext: Vec<u8>,
    /// Backend-specific proof bytes. Opaque to the protocol.
    #[serde(with = "hexbytes")]
    pub proof: Vec<u8>,
}

impl ProofBundle {
    /// `tagged_hash("bundle", [statement_hash, backend_id, ciphertext, proof])`.
    pub fn bundle_id(&self) -> Hash32 {
        tagged_hash(
            "bundle",
            &[
                &self.statement.hash(),
                self.backend_id.as_bytes(),
                &self.ciphertext,
                &self.proof,
            ],
        )
    }
}

/// Why a proof could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    /// The witness does not satisfy the statement (a sound prover cannot
    /// prove a false statement).
    Unsatisfied(VerifyError),
    /// The backend failed for a reason unrelated to the witness (prover
    /// error, misconfiguration, a refused remote or fake prover).
    Backend(String),
}

/// Why a proof bundle was rejected. Each variant is one relation of the
/// statement, checked in this order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Wrong version string.
    Version,
    /// `backend_id` does not name this backend.
    BackendMismatch,
    /// `job_id` or `spec_hash` does not match the job class.
    SpecMismatch,
    /// `ciphertext_hash != tagged_hash("ciphertext", [C])`.
    CiphertextHashMismatch,
    /// The proof bytes are malformed, or bound to a different statement.
    ProofMalformed,
    /// `input_commitment` does not open to the witness input.
    InputCommitmentMismatch,
    /// `check(input, R)` is false.
    JobCheckFailed,
    /// `C != Enc_k(R)`.
    CiphertextMismatch,
    /// `payment_hash != SHA256(k)`.
    PaymentHashMismatch,
    /// A zkVM receipt that does not verify against the pinned image id, or
    /// a fake (dev-mode) receipt.
    ReceiptInvalid,
}

impl From<RelationError> for VerifyError {
    fn from(e: RelationError) -> Self {
        match e {
            RelationError::UnknownJobClass | RelationError::SpecMismatch => {
                VerifyError::SpecMismatch
            }
            RelationError::JobCheckFailed => VerifyError::JobCheckFailed,
            RelationError::CiphertextMismatch => VerifyError::CiphertextMismatch,
        }
    }
}

impl From<JournalMismatch> for VerifyError {
    fn from(e: JournalMismatch) -> Self {
        match e {
            JournalMismatch::Version => VerifyError::Version,
            JournalMismatch::Job => VerifyError::SpecMismatch,
            JournalMismatch::InputCommitment => VerifyError::InputCommitmentMismatch,
            // The proof answers another offer or buyer.
            JournalMismatch::OfferBinding => VerifyError::ProofMalformed,
            JournalMismatch::CiphertextHash => VerifyError::CiphertextHashMismatch,
            JournalMismatch::PaymentHash => VerifyError::PaymentHashMismatch,
        }
    }
}

/// A proof system that can prove and verify the PCP/0 statement for a job
/// class. A zkVM backend runs `job.check` and the encryption inside a guest
/// whose image id corresponds to `job.spec_hash()`, and emits the statement
/// fields as its public journal.
pub trait ProofBackend {
    /// Stable identifier carried in `ProofBundle::backend_id`.
    fn backend_id(&self) -> &'static str;

    /// `true` if this backend provides zero knowledge and soundness.
    /// Buyers refuse backends that return `false` unless explicitly told not to.
    fn is_secure(&self) -> bool;

    /// Prove the statement. `statement.ciphertext_hash` must already describe
    /// `ciphertext`.
    fn prove(
        &self,
        job: &dyn JobClass,
        statement: &Statement,
        ciphertext: &[u8],
        witness: &Witness,
    ) -> Result<ProofBundle, ProveError>;

    /// Verify a bundle against a statement the *verifier* expects. Returns
    /// `Ok(())` only if every relation holds.
    fn verify(
        &self,
        job: &dyn JobClass,
        statement: &Statement,
        bundle: &ProofBundle,
    ) -> Result<(), VerifyError>;
}

/// Check every relation of the statement given the witness, by running the
/// statement core ([`crate::statement::evaluate_with`]) and comparing its
/// journal with `statement`. This is the same function a zkVM guest runs;
/// the dev backend runs it in the clear.
pub(crate) fn check_relations(
    job: &dyn JobClass,
    statement: &Statement,
    ciphertext: &[u8],
    witness: &Witness,
) -> Result<(), VerifyError> {
    let journal = evaluate_with(job, &witness.statement_input(statement, ciphertext))?;
    journal.check_expected(&statement.journal())?;
    Ok(())
}

/// The checks of SPEC 7.1 items 1 to 4, which need no proof system:
/// versions, backend id, job class, that the bundle carries exactly the
/// verifier's expected statement, and the ciphertext hash. Every backend
/// runs this before looking at the proof bytes.
pub fn check_bundle_public(
    backend_id: &str,
    job: &dyn JobClass,
    statement: &Statement,
    bundle: &ProofBundle,
) -> Result<(), VerifyError> {
    if bundle.version != VERSION || statement.version != VERSION {
        return Err(VerifyError::Version);
    }
    if bundle.backend_id != backend_id {
        return Err(VerifyError::BackendMismatch);
    }
    if statement.job_id != job.job_id() || statement.spec_hash != job.spec_hash() {
        return Err(VerifyError::SpecMismatch);
    }
    if bundle.statement != *statement {
        // The verifier's expected statement is what counts; a bundle that
        // carries a different one is bound to something else.
        return Err(VerifyError::ProofMalformed);
    }
    if crypto::ciphertext_hash(&bundle.ciphertext) != statement.ciphertext_hash {
        return Err(VerifyError::CiphertextHashMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------

/// # INSECURE. DEVELOPMENT ONLY. NOT ZERO KNOWLEDGE. NOT A PROOF.
///
/// This backend exists only to exercise the PCP/0 message flow until a zkVM
/// backend (RISC Zero or SP1) lands. Its "proof" is the **witness itself**
/// (input, result `R` and key `k`), sealed with ChaCha20-Poly1305 under a
/// key that is a **constant in this crate's source code**.
///
/// What it does give you:
/// - `verify()` opens the seal and checks every relation of the statement
///   (`input_commitment`, `job.check(input, R)`, `C = Enc_k(R)`,
///   `H = SHA256(k)`), so the protocol's verification order, error paths and
///   binding are exercised for real.
/// - The seal is bound to the statement hash, so a proof cannot be moved to
///   another statement (another buyer, another offer, another `H`).
/// - The crate's public API never returns the opened witness: `verify()`
///   returns only `Ok(())` or an error.
///
/// What it does **not** give you:
/// - **Zero knowledge.** Anyone who reads this file can recompute the seal
///   key and open the proof, learning `R` and `k` without paying. A buyer
///   who does that gets the goods for free.
/// - **Soundness against a malicious prover.** A seller who reads this file
///   can seal any witness. (Verification still recomputes every relation,
///   so a *false* witness is still caught; what is lost is only privacy.)
///
/// Buyers refuse this backend unless `BuyerPolicy::allow_insecure_dev_backend`
/// is set. Never set it outside tests and demos.
///
/// The opened witness is not reachable through the public API. This does not
/// compile:
///
/// ```compile_fail
/// let _ = pcp::proof::InsecureDevTransparentBackend::unseal;
/// ```
///
/// and neither does this:
///
/// ```compile_fail
/// let _ = pcp::proof::DEV_SEAL_KEY_INSECURE;
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct InsecureDevTransparentBackend;

/// The `backend_id` of [`InsecureDevTransparentBackend`].
pub const INSECURE_DEV_BACKEND_ID: &str = "INSECURE-dev-transparent/0";

/// Public in the source, therefore not a secret. That is the point.
const DEV_SEAL_KEY_INSECURE: &[u8] =
    b"PCP/0 INSECURE dev seal key: this constant is public in the source code";

impl InsecureDevTransparentBackend {
    fn seal_cipher() -> ChaCha20Poly1305 {
        let key = sha256(DEV_SEAL_KEY_INSECURE);
        ChaCha20Poly1305::new(Key::from_slice(&key))
    }

    fn seal_aad(statement: &Statement) -> Hash32 {
        tagged_hash("dev-seal-aad", &[&statement.hash()])
    }

    /// Seal a witness for a statement. Random nonce, so two seals of the same
    /// witness differ.
    fn seal<R: RngCore + CryptoRng>(
        statement: &Statement,
        witness: &Witness,
        rng: &mut R,
    ) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        let aad = Self::seal_aad(statement);
        let body = Self::seal_cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &witness.encode(),
                    aad: &aad,
                },
            )
            .expect("in-memory encryption does not fail");
        let mut out = b"INSECURE-DEV-SEAL/0:".to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        out
    }

    /// Open a seal. Crate-private: only `verify()` and the crate's own tests
    /// call this.
    pub(crate) fn unseal(statement: &Statement, proof: &[u8]) -> Option<Witness> {
        let rest = proof.strip_prefix(b"INSECURE-DEV-SEAL/0:".as_slice())?;
        if rest.len() < 12 {
            return None;
        }
        let (nonce, body) = rest.split_at(12);
        let aad = Self::seal_aad(statement);
        let plain = Self::seal_cipher()
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: &aad,
                },
            )
            .ok()?;
        Witness::decode(&plain)
    }

    /// Seal an arbitrary witness WITHOUT checking it. Crate-private, for
    /// adversarial tests that model a malicious seller who read the source.
    #[cfg(test)]
    pub(crate) fn prove_unchecked(
        statement: &Statement,
        ciphertext: &[u8],
        witness: &Witness,
    ) -> ProofBundle {
        ProofBundle {
            version: VERSION.to_string(),
            backend_id: INSECURE_DEV_BACKEND_ID.to_string(),
            statement: statement.clone(),
            ciphertext: ciphertext.to_vec(),
            proof: Self::seal(statement, witness, &mut rand::rngs::OsRng),
        }
    }
}

impl ProofBackend for InsecureDevTransparentBackend {
    fn backend_id(&self) -> &'static str {
        INSECURE_DEV_BACKEND_ID
    }

    fn is_secure(&self) -> bool {
        false
    }

    fn prove(
        &self,
        job: &dyn JobClass,
        statement: &Statement,
        ciphertext: &[u8],
        witness: &Witness,
    ) -> Result<ProofBundle, ProveError> {
        if statement.version != VERSION
            || statement.job_id != job.job_id()
            || statement.spec_hash != job.spec_hash()
        {
            return Err(ProveError::Unsatisfied(VerifyError::SpecMismatch));
        }
        if crypto::ciphertext_hash(ciphertext) != statement.ciphertext_hash {
            return Err(ProveError::Unsatisfied(VerifyError::CiphertextHashMismatch));
        }
        check_relations(job, statement, ciphertext, witness).map_err(ProveError::Unsatisfied)?;
        Ok(ProofBundle {
            version: VERSION.to_string(),
            backend_id: INSECURE_DEV_BACKEND_ID.to_string(),
            statement: statement.clone(),
            ciphertext: ciphertext.to_vec(),
            proof: Self::seal(statement, witness, &mut rand::rngs::OsRng),
        })
    }

    fn verify(
        &self,
        job: &dyn JobClass,
        statement: &Statement,
        bundle: &ProofBundle,
    ) -> Result<(), VerifyError> {
        check_bundle_public(INSECURE_DEV_BACKEND_ID, job, statement, bundle)?;
        let witness = Self::unseal(statement, &bundle.proof).ok_or(VerifyError::ProofMalformed)?;
        check_relations(job, statement, &bundle.ciphertext, &witness)
        // `witness` is dropped here; nothing about it leaves this function.
    }
}

/// Build the statement a seller will prove (helper for sellers and tests).
pub fn build_statement(
    job: &dyn JobClass,
    input_commitment: Hash32,
    offer_id: Hash32,
    buyer_nonce: Hash32,
    ciphertext: &[u8],
    payment_hash: Hash32,
) -> Statement {
    Statement {
        version: VERSION.to_string(),
        job_id: job.job_id().to_string(),
        spec_hash: job.spec_hash(),
        input_commitment,
        offer_id,
        buyer_nonce,
        ciphertext_hash: crypto::ciphertext_hash(ciphertext),
        payment_hash,
    }
}
