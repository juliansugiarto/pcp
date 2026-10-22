//! Principals, mandates, agents and the principal-readable log (SPEC.md
//! sections 2.1, 5.4 and 14).
//!
//! Every buyer and every seller is an **agent acting for a principal**: a
//! human, or an organisation a human controls. The principal signs a
//! [`Mandate`] that authorises one agent key, for one role, for a list of
//! job classes, up to a cumulative cap and a per-deal maximum, until an
//! expiry. Money flows to the principal's node; receipts and refusals go to
//! the principal's log.
//!
//! **What a mandate proves.** That the holder of `principal_key` authorised
//! `agent_key` within these limits. It does **not** prove that the principal
//! is a human, or who the principal is in law. No credential issuer is
//! privileged: any Ed25519 key is an acceptable principal key, and a mandate
//! verifies with no network and no third party.
//!
//! None of this adds a role to the protocol. The principal never sends a
//! PCP message; it signs a mandate offline, holds the node that is paid, and
//! reads the log.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{CryptoRng, RngCore};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::encoding::{hex32, hex32opt, hex32vec, hexbytes, tagged_hash, u64_be, Hash32, VERSION};
use crate::job::JobClass;
use crate::lightning::NodeId;
use crate::proof::ProofBundle;
use crate::protocol::{PcpError, Receipt};

/// A 32-byte Ed25519 public key.
pub type PublicKey = Hash32;

// ---------------------------------------------------------------------------
// Keys and signatures

/// An Ed25519 signature (64 bytes, lowercase hex on the wire).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sig(pub [u8; 64]);

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({}..)", &hex::encode(self.0)[..16])
    }
}

impl Serialize for Sig {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Sig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 128 || s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(D::Error::custom("expected 128 lowercase hex characters"));
        }
        let v = hex::decode(&s).map_err(D::Error::custom)?;
        Ok(Sig(v
            .try_into()
            .map_err(|_| D::Error::custom("expected 64 bytes"))?))
    }
}

/// Verify an Ed25519 signature (strict verification: no malleable or
/// small-order encodings).
pub fn verify_sig(public: &PublicKey, msg: &[u8], sig: &Sig) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(&sig.0))
        .is_ok()
}

/// An Ed25519 secret key: a principal's or an agent's.
pub struct SecretKey(SigningKey);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(pub {})", hex::encode(self.public_key()))
    }
}

impl SecretKey {
    /// A fresh random key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> SecretKey {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        SecretKey::from_seed(seed)
    }

    /// The key with this 32-byte seed (RFC 8032 secret key).
    pub fn from_seed(seed: [u8; 32]) -> SecretKey {
        SecretKey(SigningKey::from_bytes(&seed))
    }

    pub fn public_key(&self) -> PublicKey {
        self.0.verifying_key().to_bytes()
    }

    /// The 32-byte seed, to store the key. Keep it as secret as the key.
    pub fn to_seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> Sig {
        Sig(self.0.sign(msg).to_bytes())
    }
}

// ---------------------------------------------------------------------------
// Mandate

/// Which side of a deal a mandate authorises.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Buyer,
    Seller,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Buyer => "buyer",
            Role::Seller => "seller",
        }
    }
}

/// The limits a principal sets when signing a mandate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateTerms {
    pub role: Role,
    /// `spec_hash`es of the job classes the agent may trade.
    pub scope: Vec<Hash32>,
    /// Cumulative limit over the mandate's life (bought for a buyer, sold
    /// for a seller).
    pub cap_msat: u64,
    /// Largest single deal.
    pub per_deal_max_msat: u64,
    /// The principal's Lightning node. Seller: every invoice MUST pay this
    /// node. Buyer: the node payments are made from and refunds return to.
    pub payout_node: NodeId,
    /// Absolute time (seconds) at and after which the mandate is void.
    pub expires_at: u64,
}

/// A principal's signed authorisation of one agent key (SPEC 2.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mandate {
    pub version: String,
    #[serde(with = "hex32")]
    pub principal_key: PublicKey,
    #[serde(with = "hex32")]
    pub agent_key: PublicKey,
    pub role: Role,
    #[serde(with = "hex32vec")]
    pub scope: Vec<Hash32>,
    pub cap_msat: u64,
    pub per_deal_max_msat: u64,
    pub payout_node: NodeId,
    pub expires_at: u64,
    /// 32 random bytes, so two mandates with the same terms differ.
    #[serde(with = "hex32")]
    pub nonce: Hash32,
    /// `Ed25519(principal_sk, mandate_id)`.
    pub principal_sig: Sig,
}

/// Why a mandate check failed. Carried in [`PcpError::OwnMandate`] (the
/// agent's own limits) or [`PcpError::CounterpartyMandate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MandateError {
    /// The message carries no mandate or no agent signature.
    Missing,
    Version,
    /// `principal_sig` does not verify under `principal_key`.
    SignatureInvalid,
    /// `principal_key == agent_key`: an agent may not be its own principal.
    SelfOwned,
    /// The agent key in use is not the mandate's `agent_key`.
    AgentKeyMismatch,
    /// The message is not signed by the mandate's `agent_key`.
    AgentSignatureInvalid,
    WrongRole,
    Expired,
    /// The job class is not in the mandate's scope.
    ScopeMismatch,
    PerDealMaxExceeded {
        max: u64,
        price: u64,
    },
    CapExceeded {
        cap: u64,
        committed: u64,
        price: u64,
    },
    /// The offer's `seller_node` is not the mandate's `payout_node`.
    PayoutNodeMismatch,
}

impl MandateError {
    /// Stable reason code, used in refusal records.
    pub fn code(&self) -> &'static str {
        match self {
            MandateError::Missing => "missing",
            MandateError::Version => "version",
            MandateError::SignatureInvalid => "signature_invalid",
            MandateError::SelfOwned => "self_owned",
            MandateError::AgentKeyMismatch => "agent_key_mismatch",
            MandateError::AgentSignatureInvalid => "agent_signature_invalid",
            MandateError::WrongRole => "wrong_role",
            MandateError::Expired => "expired",
            MandateError::ScopeMismatch => "scope_mismatch",
            MandateError::PerDealMaxExceeded { .. } => "per_deal_max_exceeded",
            MandateError::CapExceeded { .. } => "cap_exceeded",
            MandateError::PayoutNodeMismatch => "payout_node_mismatch",
        }
    }
}

impl Mandate {
    /// The principal signs a mandate for `agent_key`.
    pub fn sign<R: RngCore + CryptoRng>(
        principal: &SecretKey,
        agent_key: PublicKey,
        terms: MandateTerms,
        rng: &mut R,
    ) -> Mandate {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let mut m = Mandate {
            version: VERSION.to_string(),
            principal_key: principal.public_key(),
            agent_key,
            role: terms.role,
            scope: terms.scope,
            cap_msat: terms.cap_msat,
            per_deal_max_msat: terms.per_deal_max_msat,
            payout_node: terms.payout_node,
            expires_at: terms.expires_at,
            nonce,
            principal_sig: Sig([0u8; 64]),
        };
        m.principal_sig = principal.sign(&m.mandate_id());
        m
    }

    /// `tagged_hash("mandate", [...every field except the signature])`.
    /// `scope` is one field: the concatenated 32-byte hashes, in order.
    pub fn mandate_id(&self) -> Hash32 {
        let scope: Vec<u8> = self.scope.concat();
        tagged_hash(
            "mandate",
            &[
                self.version.as_bytes(),
                &self.principal_key,
                &self.agent_key,
                self.role.as_str().as_bytes(),
                &scope,
                &u64_be(self.cap_msat),
                &u64_be(self.per_deal_max_msat),
                self.payout_node.as_bytes(),
                &u64_be(self.expires_at),
                &self.nonce,
            ],
        )
    }

    /// Version, principal signature, and the rule that an agent is not its
    /// own principal. Offline; no issuer is consulted.
    pub fn verify_signature(&self) -> Result<(), MandateError> {
        if self.version != VERSION {
            return Err(MandateError::Version);
        }
        if !verify_sig(&self.principal_key, &self.mandate_id(), &self.principal_sig) {
            return Err(MandateError::SignatureInvalid);
        }
        if self.principal_key == self.agent_key {
            return Err(MandateError::SelfOwned);
        }
        Ok(())
    }

    /// Whether `spec_hash` is in scope.
    pub fn covers(&self, spec_hash: &Hash32) -> bool {
        self.scope.contains(spec_hash)
    }

    /// The static checks: signature, role, expiry, scope.
    pub fn check(&self, role: Role, spec_hash: &Hash32, now: u64) -> Result<(), MandateError> {
        self.verify_signature()?;
        if self.role != role {
            return Err(MandateError::WrongRole);
        }
        if now >= self.expires_at {
            return Err(MandateError::Expired);
        }
        if !self.covers(spec_hash) {
            return Err(MandateError::ScopeMismatch);
        }
        Ok(())
    }

    /// Per-deal and cumulative limits for a deal of `price` on top of
    /// `committed`.
    pub fn check_amount(&self, committed: u64, price: u64) -> Result<(), MandateError> {
        if price > self.per_deal_max_msat {
            return Err(MandateError::PerDealMaxExceeded {
                max: self.per_deal_max_msat,
                price,
            });
        }
        if committed
            .checked_add(price)
            .is_none_or(|t| t > self.cap_msat)
        {
            return Err(MandateError::CapExceeded {
                cap: self.cap_msat,
                committed,
                price,
            });
        }
        Ok(())
    }
}

/// Check a counterparty's mandate and its agent's signature over
/// `auth_msg(mandate_id)`.
pub(crate) fn check_counterparty<'a>(
    mandate: Option<&'a Mandate>,
    sig: Option<&Sig>,
    role: Role,
    spec_hash: &Hash32,
    now: u64,
    auth_msg: impl Fn(&Hash32) -> Hash32,
) -> Result<&'a Mandate, MandateError> {
    let (Some(m), Some(sig)) = (mandate, sig) else {
        return Err(MandateError::Missing);
    };
    m.check(role, spec_hash, now)?;
    if !verify_sig(&m.agent_key, &auth_msg(&m.mandate_id()), sig) {
        return Err(MandateError::AgentSignatureInvalid);
    }
    Ok(m)
}

// ---------------------------------------------------------------------------
// Agent

struct AgentInner {
    key: SecretKey,
    mandate: Mandate,
    book: Mutex<Book>,
}

#[derive(Default)]
struct Book {
    /// Buyer: spent or locked in flight. Seller: sold and settled.
    committed_msat: u64,
    log: PrincipalLog,
}

/// An agent: its own key, the mandate its principal signed for that key,
/// the running total against the cap, and the log the principal reads.
///
/// Cloning an `Agent` shares the same budget and log, so several purchases
/// in parallel draw on one cap. The agent never holds the principal's key.
#[derive(Clone)]
pub struct Agent {
    inner: Arc<AgentInner>,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Agent({}, {} for principal {})",
            &hex::encode(self.public_key())[..16],
            self.mandate().role.as_str(),
            &hex::encode(self.mandate().principal_key)[..16]
        )
    }
}

impl Agent {
    /// Bind an agent key to its mandate. Refuses a mandate that does not
    /// verify, names another agent key, or makes the agent its own principal.
    pub fn new(key: SecretKey, mandate: Mandate) -> Result<Agent, PcpError> {
        mandate.verify_signature().map_err(PcpError::OwnMandate)?;
        if mandate.agent_key != key.public_key() {
            return Err(PcpError::OwnMandate(MandateError::AgentKeyMismatch));
        }
        Ok(Agent {
            inner: Arc::new(AgentInner {
                key,
                mandate,
                book: Mutex::new(Book::default()),
            }),
        })
    }

    /// Rebuild an agent after a restart: its key, its mandate, what it had
    /// committed against the cap, and the principal log saved with its
    /// state. The caller computes `committed_msat` from saved records
    /// (settled sales, or purchases' held amounts), never from the log.
    pub fn restore(
        key: SecretKey,
        mandate: Mandate,
        committed_msat: u64,
        log: PrincipalLog,
    ) -> Result<Agent, PcpError> {
        let a = Agent::new(key, mandate)?;
        {
            let mut book = a.book();
            book.committed_msat = committed_msat;
            book.log = log;
        }
        Ok(a)
    }

    pub fn public_key(&self) -> PublicKey {
        self.inner.key.public_key()
    }

    pub fn mandate(&self) -> &Mandate {
        &self.inner.mandate
    }

    pub fn mandate_id(&self) -> Hash32 {
        self.inner.mandate.mandate_id()
    }

    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.inner.book.lock().expect("agent book lock poisoned")
    }

    /// Committed against the cap so far.
    pub fn committed_msat(&self) -> u64 {
        self.book().committed_msat
    }

    /// What is left under the cap.
    pub fn remaining_msat(&self) -> u64 {
        self.inner
            .mandate
            .cap_msat
            .saturating_sub(self.committed_msat())
    }

    /// A copy of the principal-readable log.
    pub fn log(&self) -> PrincipalLog {
        self.book().log.clone()
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> Sig {
        self.inner.key.sign(msg)
    }

    /// Expiry, per-deal maximum and cap for a deal of `price`.
    pub(crate) fn check_budget(&self, price: u64, now: u64) -> Result<(), MandateError> {
        if now >= self.inner.mandate.expires_at {
            return Err(MandateError::Expired);
        }
        self.inner
            .mandate
            .check_amount(self.committed_msat(), price)
    }

    /// Atomically check and commit `price` against the cap.
    pub(crate) fn reserve(&self, price: u64, now: u64) -> Result<(), MandateError> {
        if now >= self.inner.mandate.expires_at {
            return Err(MandateError::Expired);
        }
        let mut book = self.book();
        self.inner
            .mandate
            .check_amount(book.committed_msat, price)?;
        book.committed_msat += price;
        Ok(())
    }

    /// Return a reservation (HTLC refunded, or the payment never left).
    pub(crate) fn release(&self, amount: u64) {
        let mut book = self.book();
        book.committed_msat = book.committed_msat.saturating_sub(amount);
    }

    /// Sign and append a refusal.
    pub(crate) fn record_refusal(
        &self,
        subject_id: Hash32,
        counterparty_agent_key: Option<PublicKey>,
        err: &PcpError,
        at: u64,
    ) {
        let mut r = Refusal {
            version: VERSION.to_string(),
            role: self.inner.mandate.role,
            mandate_id: self.mandate_id(),
            agent_key: self.public_key(),
            subject_id,
            counterparty_agent_key,
            reason: err.code(),
            detail: format!("{err:?}"),
            at,
            agent_sig: Sig([0u8; 64]),
        };
        r.agent_sig = self.sign(&r.refusal_id());
        self.book().log.entries.push(LogEntry::Refusal(Box::new(r)));
    }

    /// Sign a receipt and append it, with the bundle and the input, so the
    /// principal can re-verify the deal offline. Returns the signed receipt.
    pub(crate) fn record_deal(
        &self,
        mut receipt: Receipt,
        bundle: &ProofBundle,
        input: &[u8],
    ) -> Receipt {
        receipt.agent_key = self.public_key();
        receipt.mandate_id = self.mandate_id();
        receipt.principal_key = self.inner.mandate.principal_key;
        receipt.role = self.inner.mandate.role;
        receipt.agent_sig = self.sign(&receipt.receipt_id());
        self.book().log.entries.push(LogEntry::Deal {
            receipt: Box::new(receipt.clone()),
            bundle: Box::new(bundle.clone()),
            input: input.to_vec(),
        });
        receipt
    }

    /// Seller side: count a settled sale against the cap.
    pub(crate) fn commit(&self, amount: u64) {
        self.book().committed_msat += amount;
    }
}

// ---------------------------------------------------------------------------
// Principal log

/// A deal that did not complete: refused by this agent, refused by the
/// counterparty, refunded, or failed after payment. Signed by the agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub version: String,
    pub role: Role,
    #[serde(with = "hex32")]
    pub mandate_id: Hash32,
    #[serde(with = "hex32")]
    pub agent_key: PublicKey,
    /// `request_id` or `offer_id` the refusal is about (zero if none).
    #[serde(with = "hex32")]
    pub subject_id: Hash32,
    #[serde(with = "hex32opt")]
    pub counterparty_agent_key: Option<PublicKey>,
    /// Stable reason code, e.g. `counterparty_mandate.cap_exceeded`.
    pub reason: String,
    /// Human-readable detail.
    pub detail: String,
    pub at: u64,
    /// `Ed25519(agent_sk, refusal_id)`.
    pub agent_sig: Sig,
}

impl Refusal {
    /// `tagged_hash("refusal", [...every field except the signature])`.
    pub fn refusal_id(&self) -> Hash32 {
        let cp: &[u8] = match &self.counterparty_agent_key {
            Some(k) => k,
            None => &[],
        };
        tagged_hash(
            "refusal",
            &[
                self.version.as_bytes(),
                self.role.as_str().as_bytes(),
                &self.mandate_id,
                &self.agent_key,
                &self.subject_id,
                cp,
                self.reason.as_bytes(),
                self.detail.as_bytes(),
                &u64_be(self.at),
            ],
        )
    }
}

/// One line of the principal's log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LogEntry {
    /// A settled deal, with what the principal needs to re-verify it.
    Deal {
        receipt: Box<Receipt>,
        bundle: Box<ProofBundle>,
        #[serde(with = "hexbytes")]
        input: Vec<u8>,
    },
    Refusal(Box<Refusal>),
}

/// Everything an agent did under one mandate, readable by the principal.
/// In memory; [`PrincipalLog::to_jsonl`] exports one JSON object per line.
///
/// A deal entry contains the preimage, the ciphertext and the input, so it
/// discloses the result `R`. The log is for the principal only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrincipalLog {
    entries: Vec<LogEntry>,
}

/// Result of [`PrincipalLog::verify`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogSummary {
    pub deals: usize,
    pub refusals: usize,
    /// Sum of settled deal amounts.
    pub total_msat: u64,
    /// Refusal count per reason code.
    pub reasons: BTreeMap<String, usize>,
}

/// Which log entry failed verification, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogError {
    pub index: usize,
    pub error: PcpError,
}

impl PrincipalLog {
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    #[cfg(test)]
    pub(crate) fn entries_mut(&mut self) -> &mut Vec<LogEntry> {
        &mut self.entries
    }

    pub fn receipts(&self) -> impl Iterator<Item = &Receipt> {
        self.entries.iter().filter_map(|e| match e {
            LogEntry::Deal { receipt, .. } => Some(receipt.as_ref()),
            LogEntry::Refusal(_) => None,
        })
    }

    pub fn refusals(&self) -> impl Iterator<Item = &Refusal> {
        self.entries.iter().filter_map(|e| match e {
            LogEntry::Refusal(r) => Some(r.as_ref()),
            LogEntry::Deal { .. } => None,
        })
    }

    /// One JSON object per line.
    pub fn to_jsonl(&self) -> String {
        self.entries
            .iter()
            .map(|e| serde_json::to_string(e).expect("log entries serialise") + "\n")
            .collect()
    }

    /// A log from its entries (as saved with an agent's state).
    pub fn from_entries(entries: Vec<LogEntry>) -> PrincipalLog {
        PrincipalLog { entries }
    }

    /// Parse an exported log.
    pub fn from_jsonl(text: &str) -> Result<PrincipalLog, serde_json::Error> {
        let entries = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        Ok(PrincipalLog { entries })
    }

    /// The principal's audit, offline. For every entry: it is bound to
    /// `mandate` (mandate id, agent key, role) and carries a valid agent
    /// signature. For every deal: the receipt re-verifies against the bundle
    /// and the input under the job class named by its `spec_hash` (which
    /// must be in `jobs`), the amount is within the per-deal maximum, and
    /// the running total stays within the cap.
    pub fn verify(
        &self,
        mandate: &Mandate,
        jobs: &[&dyn JobClass],
    ) -> Result<LogSummary, LogError> {
        let fail = |index, error| Err(LogError { index, error });
        if let Err(e) = mandate.verify_signature() {
            return fail(0, PcpError::OwnMandate(e));
        }
        let mid = mandate.mandate_id();
        let mut s = LogSummary::default();
        for (i, entry) in self.entries.iter().enumerate() {
            match entry {
                LogEntry::Deal {
                    receipt,
                    bundle,
                    input,
                } => {
                    if let Err(e) = receipt.verify_signature(mandate) {
                        return fail(i, e);
                    }
                    let spec = bundle.statement.spec_hash;
                    let Some(job) = jobs.iter().find(|j| j.spec_hash() == spec) else {
                        return fail(i, PcpError::JobClassNotRegistered);
                    };
                    if let Err(e) = receipt.verify(*job, input, bundle) {
                        return fail(i, e);
                    }
                    if let Err(e) = mandate.check_amount(s.total_msat, receipt.amount_msat) {
                        return fail(i, PcpError::OwnMandate(e));
                    }
                    s.deals += 1;
                    s.total_msat += receipt.amount_msat;
                }
                LogEntry::Refusal(r) => {
                    if r.version != VERSION {
                        return fail(i, PcpError::Version);
                    }
                    if r.mandate_id != mid
                        || r.agent_key != mandate.agent_key
                        || r.role != mandate.role
                    {
                        return fail(i, PcpError::RecordNotBound);
                    }
                    if !verify_sig(&r.agent_key, &r.refusal_id(), &r.agent_sig) {
                        return fail(i, PcpError::RecordSignatureInvalid);
                    }
                    s.refusals += 1;
                    *s.reasons.entry(r.reason.clone()).or_insert(0) += 1;
                }
            }
        }
        Ok(s)
    }
}

// ---------------------------------------------------------------------------
// Metrics (SPEC 14)

/// Settlement counts for adoption metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdoptionCount {
    /// Buyer-side receipts between different principals.
    pub counted: usize,
    /// Buyer-side receipts where one principal paid itself through two
    /// agents. Excluded from every adoption metric.
    pub self_payments: usize,
}

/// Count settlements for adoption metrics from buyer-side receipts, each
/// sale counted once, self-payments excluded. Seller-side receipts are
/// ignored (they describe the same sales).
pub fn adoption_count<'a>(receipts: impl IntoIterator<Item = &'a Receipt>) -> AdoptionCount {
    let mut c = AdoptionCount::default();
    for r in receipts.into_iter().filter(|r| r.role == Role::Buyer) {
        if r.is_self_payment() {
            c.self_payments += 1;
        } else {
            c.counted += 1;
        }
    }
    c
}
