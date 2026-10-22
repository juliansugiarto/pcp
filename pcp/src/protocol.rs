//! PCP/0 messages and the buyer and seller state machines (SPEC.md
//! sections 2, 9 and 10).
//!
//! There are two roles, buyer and seller. No third role exists. Each side
//! is an [`Agent`] acting under a [`Mandate`] its principal signed (SPEC
//! 2.1): requests and offers carry the mandate and the agent's signature,
//! and each side refuses a counterparty without a valid one by default.
//!
//! ```text
//! buyer                                   seller
//!   | Request{job, input, nonce, max}  ->   |
//!   |   <-  Offer{price, expiry, node...}   |
//!   |                                       |  computes R, picks k,
//!   |                                       |  C = Enc_k(R), H = SHA256(k),
//!   |   <-  ProofBundle{statement, C, π}    |  proves the statement
//!   |   <-  InvoiceBinding{invoice(H)}      |
//!   | verify π, check invoice               |
//!   | pay (HTLC to H)                  ->   |
//!   |   <-  preimage k (settles HTLC)       |
//!   | SHA256(k)==H, decrypt C, recheck      |
//!   | Receipt -> buyer principal's log      |  Receipt -> seller principal's log
//! ```

use std::collections::BTreeMap;
use std::fmt;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, ENC_SCHEME};
use crate::encoding::{hex32, hexbytes, tagged_hash, u64_be, Hash32, VERSION};
use crate::job::{input_commitment, JobClass};
use crate::lightning::{HtlcId, Invoice, Ledger, LedgerError, NodeId};
use crate::mandate::{
    check_counterparty, verify_sig, Agent, Mandate, MandateError, PublicKey, Role, Sig,
};
use crate::proof::{
    build_statement, ProofBackend, ProofBundle, ProveError, Statement, VerifyError, Witness,
};
use crate::rail::{IncomingState, InvoiceRequest, PaymentStatus, Rail, RailError};
use crate::registry::JobRegistry;

pub use crate::rail::{RAIL_BOLT11, RAIL_SIM};

/// Default per-deal value ceiling in the reference buyer policy: 10 000 sat.
/// PCP/0 is for small, capped, repeatable jobs; split large work into
/// stages rather than raise this (SPEC 9, O1).
pub const DEFAULT_MAX_DEAL_MSAT: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// Messages

/// Buyer -> seller: what is wanted, for how much at most.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: String,
    pub job_id: String,
    #[serde(with = "hex32")]
    pub spec_hash: Hash32,
    /// The job input in its class's canonical encoding.
    #[serde(with = "hexbytes")]
    pub input: Vec<u8>,
    #[serde(with = "hex32")]
    pub input_commitment: Hash32,
    /// 32 fresh random bytes. Binds every later message to this purchase.
    #[serde(with = "hex32")]
    pub buyer_nonce: Hash32,
    pub max_price_msat: u64,
    /// What the buyer agent has already committed under its mandate, as it
    /// declares it. Lets the seller refuse an agent whose cap is used up.
    pub mandate_spent_msat: u64,
    /// The buyer agent's mandate. Required by default (SPEC 2.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate: Option<Mandate>,
    /// `Ed25519(agent_sk, tagged_hash("request-auth", [request_id, mandate_id]))`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_sig: Option<Sig>,
}

impl Request {
    /// `tagged_hash("request", [version, job_id, spec_hash, input_commitment,
    /// buyer_nonce, u64(max_price_msat), u64(mandate_spent_msat)])`.
    pub fn request_id(&self) -> Hash32 {
        tagged_hash(
            "request",
            &[
                self.version.as_bytes(),
                self.job_id.as_bytes(),
                &self.spec_hash,
                &self.input_commitment,
                &self.buyer_nonce,
                &u64_be(self.max_price_msat),
                &u64_be(self.mandate_spent_msat),
            ],
        )
    }

    /// The message the buyer agent signs.
    pub fn auth_message(&self, mandate_id: &Hash32) -> Hash32 {
        tagged_hash("request-auth", &[&self.request_id(), mandate_id])
    }
}

/// Seller -> buyer: the terms. `offer_id` binds all of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub version: String,
    pub job_id: String,
    #[serde(with = "hex32")]
    pub spec_hash: Hash32,
    #[serde(with = "hex32")]
    pub input_commitment: Hash32,
    #[serde(with = "hex32")]
    pub buyer_nonce: Hash32,
    pub price_msat: u64,
    /// Absolute time after which the offer is void.
    pub offer_expires_at: u64,
    pub seller_node: NodeId,
    pub backend_id: String,
    pub enc_scheme: String,
    pub rail: String,
    /// The seller agent's mandate. Required by default (SPEC 2.1).
    /// Not part of `offer_id`; bound by `agent_sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate: Option<Mandate>,
    /// `Ed25519(agent_sk, tagged_hash("offer-auth", [offer_id, mandate_id]))`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_sig: Option<Sig>,
}

impl Offer {
    /// The message the seller agent signs.
    pub fn auth_message(&self, mandate_id: &Hash32) -> Hash32 {
        tagged_hash("offer-auth", &[&self.offer_id(), mandate_id])
    }

    /// `tagged_hash("offer", [every terms field in declaration order])`.
    /// The mandate and the agent signature are not terms and are excluded.
    pub fn offer_id(&self) -> Hash32 {
        tagged_hash(
            "offer",
            &[
                self.version.as_bytes(),
                self.job_id.as_bytes(),
                &self.spec_hash,
                &self.input_commitment,
                &self.buyer_nonce,
                &u64_be(self.price_msat),
                &u64_be(self.offer_expires_at),
                self.seller_node.as_bytes(),
                self.backend_id.as_bytes(),
                self.enc_scheme.as_bytes(),
                self.rail.as_bytes(),
            ],
        )
    }
}

/// Buyer -> seller: the buyer accepts an offer and asks the seller to prove
/// (SPEC 5.1a). Signed by the buyer agent under the mandate it sent with
/// the request, so only that agent can make the seller spend proving time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accept {
    pub version: String,
    #[serde(with = "hex32")]
    pub offer_id: Hash32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate: Option<Mandate>,
    /// `Ed25519(agent_sk, tagged_hash("accept-auth", [offer_id, mandate_id]))`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_sig: Option<Sig>,
}

impl Accept {
    /// The message the buyer agent signs.
    pub fn auth_message(&self, mandate_id: &Hash32) -> Hash32 {
        tagged_hash("accept-auth", &[&self.offer_id, mandate_id])
    }
}

/// Seller -> buyer: the invoice, and what it is for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceBinding {
    pub version: String,
    #[serde(with = "hex32")]
    pub offer_id: Hash32,
    #[serde(with = "hex32")]
    pub statement_hash: Hash32,
    pub invoice: Invoice,
}

/// Produced by each side after settlement, signed by its agent key, bound
/// to its mandate, and appended to its principal's log (SPEC 5.4). Anyone
/// holding the receipt, the bundle and the input can re-verify the sale
/// offline (and learn `R`, since the receipt contains `k`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: String,
    /// Which side produced this receipt.
    pub role: Role,
    #[serde(with = "hex32")]
    pub mandate_id: Hash32,
    #[serde(with = "hex32")]
    pub principal_key: PublicKey,
    #[serde(with = "hex32")]
    pub counterparty_mandate_id: Hash32,
    #[serde(with = "hex32")]
    pub counterparty_principal_key: PublicKey,
    #[serde(with = "hex32")]
    pub agent_key: PublicKey,
    #[serde(with = "hex32")]
    pub offer_id: Hash32,
    #[serde(with = "hex32")]
    pub statement_hash: Hash32,
    #[serde(with = "hex32")]
    pub bundle_id: Hash32,
    #[serde(with = "hex32")]
    pub payment_hash: Hash32,
    #[serde(with = "hex32")]
    pub preimage: Hash32,
    pub amount_msat: u64,
    pub settled_at: u64,
    /// `Ed25519(agent_sk, receipt_id)`.
    pub agent_sig: Sig,
}

impl Receipt {
    /// `tagged_hash("receipt", [...every field except the signature])`.
    pub fn receipt_id(&self) -> Hash32 {
        tagged_hash(
            "receipt",
            &[
                self.version.as_bytes(),
                self.role.as_str().as_bytes(),
                &self.mandate_id,
                &self.principal_key,
                &self.counterparty_mandate_id,
                &self.counterparty_principal_key,
                &self.agent_key,
                &self.offer_id,
                &self.statement_hash,
                &self.bundle_id,
                &self.payment_hash,
                &self.preimage,
                &u64_be(self.amount_msat),
                &u64_be(self.settled_at),
            ],
        )
    }

    /// The receipt is bound to `mandate` (id, principal, agent key, role)
    /// and signed by its agent key.
    pub fn verify_signature(&self, mandate: &Mandate) -> Result<(), PcpError> {
        if self.version != VERSION {
            return Err(PcpError::Version);
        }
        if self.mandate_id != mandate.mandate_id()
            || self.principal_key != mandate.principal_key
            || self.agent_key != mandate.agent_key
            || self.role != mandate.role
        {
            return Err(PcpError::RecordNotBound);
        }
        if !verify_sig(&self.agent_key, &self.receipt_id(), &self.agent_sig) {
            return Err(PcpError::RecordSignatureInvalid);
        }
        Ok(())
    }

    /// One principal on both sides: a self-payment through two agents.
    /// Excluded from adoption metrics (SPEC 14).
    pub fn is_self_payment(&self) -> bool {
        self.principal_key == self.counterparty_principal_key
    }

    /// Third-party re-verification: the preimage opens the payment hash, the
    /// ciphertext decrypts, and the result passes the job check. Returns `R`.
    pub fn verify(
        &self,
        job: &dyn JobClass,
        input: &[u8],
        bundle: &ProofBundle,
    ) -> Result<Vec<u8>, PcpError> {
        let st = &bundle.statement;
        if self.version != VERSION || st.version != VERSION {
            return Err(PcpError::Version);
        }
        if st.hash() != self.statement_hash
            || bundle.bundle_id() != self.bundle_id
            || st.offer_id != self.offer_id
        {
            return Err(PcpError::OfferMismatch);
        }
        if st.job_id != job.job_id() || st.spec_hash != job.spec_hash() {
            return Err(PcpError::JobMismatch);
        }
        if input_commitment(input) != st.input_commitment {
            return Err(PcpError::InputCommitmentMismatch);
        }
        if st.payment_hash != self.payment_hash
            || crypto::payment_hash(&self.preimage) != self.payment_hash
        {
            return Err(PcpError::PreimageMismatch);
        }
        if crypto::ciphertext_hash(&bundle.ciphertext) != st.ciphertext_hash {
            return Err(PcpError::CiphertextHashMismatch);
        }
        let r = crypto::decrypt(&self.preimage, &self.offer_id, &bundle.ciphertext)
            .ok_or(PcpError::DecryptionFailed)?;
        if !job.check(input, &r) {
            return Err(PcpError::PostPaymentCheckFailed);
        }
        Ok(r)
    }
}

// ---------------------------------------------------------------------------
// Errors

/// Every way a PCP/0 exchange can stop. Most variants name one threat from
/// SPEC.md section 11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcpError {
    /// The call is not valid in the current state.
    WrongState(&'static str),
    Version,
    /// Job id or spec hash differs from what the buyer asked for.
    JobMismatch,
    InputCommitmentMismatch,
    /// The message is for a different offer.
    OfferMismatch,
    /// Seller-side: no offer with this id was issued here (or it was
    /// purged after expiry). Nothing is proven for it.
    OfferNotIssued,
    /// The buyer nonce is not this buyer's: a proof replayed from another
    /// purchase, or a message sent to the wrong buyer.
    ReplayedOrMisdirected,
    PriceTooHigh {
        offered: u64,
        max: u64,
    },
    OfferExpired,
    /// Bundle or offer names a backend this buyer does not run.
    BackendNotAccepted,
    /// The backend is the insecure dev backend and the policy forbids it.
    InsecureBackendRefused,
    EncSchemeNotSupported,
    RailNotSupported,
    CiphertextHashMismatch,
    /// The proof does not verify.
    ProofInvalid(VerifyError),
    /// The seller's backend refused to prove (the witness is false).
    ProveFailed(ProveError),
    /// Seller-side: the result does not pass the job check, so it is not
    /// offered for sale.
    SellerResultInvalid,
    /// Invoice binding names another offer or statement.
    InvoiceBindingMismatch,
    /// Invoice payment hash differs from the proven `H`.
    InvoiceHashMismatch,
    InvoiceAmountMismatch {
        invoice: u64,
        offer: u64,
    },
    InvoicePayeeMismatch,
    InvoiceDescriptionMismatch,
    /// Too little time left on the invoice for the buyer's policy.
    InvoiceExpiresTooSoon,
    /// The invoice expired: seller-side with no HTLC held, buyer-side
    /// before paying. The sale is over.
    InvoiceExpired,
    /// The invoice asks for a longer HTLC lock than the buyer allows
    /// (liquidity griefing bound).
    HtlcLockTooLong {
        asked: u64,
        allowed: u64,
    },
    /// Seller-side: too little time left on the HTLC to settle safely, so
    /// `k` is not revealed.
    SettleMarginTooShort,
    /// `SHA256(k) != H`.
    PreimageMismatch,
    /// `k` does not decrypt `C`. Evidence that the proof backend is unsound.
    DecryptionFailed,
    /// The decrypted result fails the local job check. Same evidence.
    PostPaymentCheckFailed,
    /// The result is not available before payment settles.
    NotPaid,
    /// The HTLC timed out and the buyer's funds came back; nothing delivered.
    Refunded,
    Ledger(LedgerError),
    /// A settlement rail error other than the simulated ledger's.
    Rail(RailError),
    /// This agent's own mandate does not allow the step.
    OwnMandate(MandateError),
    /// The counterparty's mandate is missing, invalid or exceeded.
    CounterpartyMandate(MandateError),
    /// The job class's `spec_hash` is not in the local registry of reviewed
    /// classes (SPEC 6.4).
    JobClassNotRegistered,
    /// The price is above the buyer policy's per-deal value ceiling.
    DealAboveCeiling {
        price: u64,
        ceiling: u64,
    },
    /// The counterparty refused, with this reason code.
    RefusedByCounterparty(String),
    /// A receipt or refusal is not bound to the principal's mandate.
    RecordNotBound,
    /// A receipt or refusal does not carry a valid agent signature.
    RecordSignatureInvalid,
    /// An error recorded before a restart, by its reason code. The detail
    /// is in the principal's log.
    Recorded(String),
    /// Buyer-side: no answer from the seller within the policy's wait.
    NoAnswer,
    /// Seller-side: too many open offers (in total, or for this principal)
    /// to quote another now. Nothing was proven or reserved; ask later.
    SellerBusy,
    /// Seller-side: this seller serves only listed principals (an invited
    /// window), and the request's principal is not on the list.
    PrincipalNotAllowed,
    /// The buyer's node already paid this payment hash, in flight or
    /// settled (SPEC 9, P0).
    PaymentHashSeen,
}

impl PcpError {
    /// Stable reason code, used in refusal records and logs.
    pub fn code(&self) -> String {
        let s = match self {
            PcpError::WrongState(_) => "wrong_state",
            PcpError::Version => "version",
            PcpError::JobMismatch => "job_mismatch",
            PcpError::InputCommitmentMismatch => "input_commitment_mismatch",
            PcpError::OfferMismatch => "offer_mismatch",
            PcpError::OfferNotIssued => "offer_not_issued",
            PcpError::ReplayedOrMisdirected => "replayed_or_misdirected",
            PcpError::PriceTooHigh { .. } => "price_too_high",
            PcpError::OfferExpired => "offer_expired",
            PcpError::BackendNotAccepted => "backend_not_accepted",
            PcpError::InsecureBackendRefused => "insecure_backend_refused",
            PcpError::EncSchemeNotSupported => "enc_scheme_not_supported",
            PcpError::RailNotSupported => "rail_not_supported",
            PcpError::CiphertextHashMismatch => "ciphertext_hash_mismatch",
            PcpError::ProofInvalid(_) => "proof_invalid",
            PcpError::ProveFailed(_) => "prove_failed",
            PcpError::SellerResultInvalid => "seller_result_invalid",
            PcpError::InvoiceBindingMismatch => "invoice_binding_mismatch",
            PcpError::InvoiceHashMismatch => "invoice_hash_mismatch",
            PcpError::InvoiceAmountMismatch { .. } => "invoice_amount_mismatch",
            PcpError::InvoicePayeeMismatch => "invoice_payee_mismatch",
            PcpError::InvoiceDescriptionMismatch => "invoice_description_mismatch",
            PcpError::InvoiceExpiresTooSoon => "invoice_expires_too_soon",
            PcpError::InvoiceExpired => "invoice_expired",
            PcpError::HtlcLockTooLong { .. } => "htlc_lock_too_long",
            PcpError::SettleMarginTooShort => "settle_margin_too_short",
            PcpError::PreimageMismatch => "preimage_mismatch",
            PcpError::DecryptionFailed => "decryption_failed",
            PcpError::PostPaymentCheckFailed => "post_payment_check_failed",
            PcpError::NotPaid => "not_paid",
            PcpError::Refunded => "refunded",
            PcpError::Ledger(_) => "ledger",
            PcpError::Rail(_) => "rail",
            PcpError::OwnMandate(e) => return format!("own_mandate.{}", e.code()),
            PcpError::CounterpartyMandate(e) => {
                return format!("counterparty_mandate.{}", e.code())
            }
            PcpError::JobClassNotRegistered => "job_class_not_registered",
            PcpError::DealAboveCeiling { .. } => "deal_above_ceiling",
            PcpError::RefusedByCounterparty(code) => {
                return format!("refused_by_counterparty.{code}")
            }
            PcpError::RecordNotBound => "record_not_bound",
            PcpError::RecordSignatureInvalid => "record_signature_invalid",
            PcpError::Recorded(code) => return code.clone(),
            PcpError::NoAnswer => "no_answer",
            PcpError::SellerBusy => "seller_busy",
            PcpError::PrincipalNotAllowed => "principal_not_allowed",
            PcpError::PaymentHashSeen => "payment_hash_seen",
        };
        s.to_string()
    }
}

impl fmt::Display for PcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PcpError {}

impl From<LedgerError> for PcpError {
    fn from(e: LedgerError) -> Self {
        PcpError::Ledger(e)
    }
}

impl From<RailError> for PcpError {
    fn from(e: RailError) -> Self {
        match e {
            RailError::Ledger(e) => PcpError::Ledger(e),
            e => PcpError::Rail(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Buyer

/// What the buyer is willing to accept.
#[derive(Clone, Debug)]
pub struct BuyerPolicy {
    /// Accept proofs from `InsecureDevTransparentBackend`. Tests and demos only.
    pub allow_insecure_dev_backend: bool,
    /// HTLC lock time the buyer offers, in seconds. Invoices asking for more
    /// are refused (bounds how long a seller can tie up the buyer's funds).
    pub htlc_secs: u64,
    /// Minimum seconds that must remain on an invoice when the buyer checks it.
    pub min_invoice_remaining_secs: u64,
    /// Re-run `job.check(input, R)` after decryption.
    pub recheck_locally: bool,
    /// Per-deal value ceiling, independent of any mandate. Default
    /// [`DEFAULT_MAX_DEAL_MSAT`].
    pub max_deal_msat: u64,
    /// Reviewed job classes this buyer will buy.
    pub registry: JobRegistry,
    /// Development only: buy job classes that are not in `registry`.
    pub allow_unregistered_job_classes: bool,
    /// The settlement rail this buyer pays on (`offer.rail` must match).
    /// Default [`RAIL_SIM`]; [`RAIL_BOLT11`] with a real node.
    pub rail: String,
}

/// Seconds per block assumed when converting timelocks on the BOLT11 rail.
pub const SECS_PER_BLOCK: u64 = 600;
/// Final CLTV delta a seller asks for on Lightning: LND v0.21 refuses less
/// than 24 blocks for a hold invoice.
pub const LN_FINAL_CLTV_BLOCKS: u64 = 24;
/// LND's default per-hop CLTV delta (`bitcoin.timelockdelta`, 80 blocks).
pub const LN_HOP_DELTA_BLOCKS: u64 = 80;
/// Intermediate hops a buyer's timelock limit leaves room for by default.
pub const LN_ROUTE_HOPS: u64 = 2;
/// LND cancels a held HTLC this many blocks before it expires
/// (`invoices.holdexpirydelta`, default 12). A seller's settle margin below
/// this never binds on LND.
pub const LN_HOLD_EXPIRY_DELTA_BLOCKS: u64 = 12;

impl BuyerPolicy {
    /// Defaults for a buyer paying BOLT11 hold invoices over Lightning.
    /// The HTLC limit leaves room for the seller's final CLTV, two routing
    /// hops at LND's default delta and a buffer: 24 + 2 x 80 + 20 = 204
    /// blocks. `BuyerPolicy::default()` targets the simulated ledger and its
    /// one-hour limit would refuse every LND invoice.
    pub fn lightning() -> Self {
        BuyerPolicy {
            htlc_secs: (LN_FINAL_CLTV_BLOCKS + LN_ROUTE_HOPS * LN_HOP_DELTA_BLOCKS + 20)
                * SECS_PER_BLOCK,
            rail: RAIL_BOLT11.to_string(),
            ..BuyerPolicy::default()
        }
    }
}

impl Default for BuyerPolicy {
    fn default() -> Self {
        BuyerPolicy {
            allow_insecure_dev_backend: false,
            htlc_secs: 3_600,
            min_invoice_remaining_secs: 60,
            recheck_locally: true,
            max_deal_msat: DEFAULT_MAX_DEAL_MSAT,
            registry: JobRegistry::reference(),
            allow_unregistered_job_classes: false,
            rail: RAIL_SIM.to_string(),
        }
    }
}

/// Where the buyer is in the exchange.
#[derive(Debug)]
pub enum BuyerState {
    Requested,
    OfferAccepted {
        offer: Offer,
    },
    BundleVerified {
        offer: Offer,
        statement: Statement,
        bundle: ProofBundle,
    },
    InvoiceAccepted {
        offer: Offer,
        statement: Statement,
        bundle: ProofBundle,
        invoice: Invoice,
    },
    /// The price is reserved against the cap and the payment call was made
    /// (or is about to be), but it is not known whether the HTLC left. Only
    /// [`Buyer::recover_payment`] leaves this state: a lookup that fails
    /// keeps the reservation, because the money may be out.
    Paying {
        offer: Offer,
        statement: Statement,
        bundle: ProofBundle,
        invoice: Invoice,
    },
    /// HTLC to `statement.payment_hash` locked; waiting for `k`.
    Paid {
        offer: Offer,
        statement: Statement,
        bundle: ProofBundle,
        invoice: Invoice,
    },
    Delivered {
        receipt: Receipt,
        bundle: ProofBundle,
        result: Vec<u8>,
    },
    Refunded,
    Aborted(PcpError),
}

impl BuyerState {
    /// Short name for logs.
    pub fn name(&self) -> &'static str {
        match self {
            BuyerState::Requested => "Requested",
            BuyerState::OfferAccepted { .. } => "OfferAccepted",
            BuyerState::BundleVerified { .. } => "BundleVerified",
            BuyerState::InvoiceAccepted { .. } => "InvoiceAccepted",
            BuyerState::Paying { .. } => "Paying",
            BuyerState::Paid { .. } => "Paid",
            BuyerState::Delivered { .. } => "Delivered",
            BuyerState::Refunded => "Refunded",
            BuyerState::Aborted(_) => "Aborted",
        }
    }
}

/// A buyer's state as saved. Mirrors [`BuyerState`]; an abort keeps only
/// its reason code (the detail is in the principal's log).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum BuyerStateRecord {
    Requested,
    OfferAccepted {
        offer: Offer,
    },
    BundleVerified {
        offer: Offer,
        statement: Statement,
        bundle: ProofBundle,
    },
    InvoiceAccepted {
        offer: Offer,
        statement: Statement,
        bundle: ProofBundle,
        invoice: Invoice,
    },
    Paying {
        offer: Offer,
        statement: Statement,
        bundle: ProofBundle,
        invoice: Invoice,
    },
    Paid {
        offer: Offer,
        statement: Statement,
        bundle: ProofBundle,
        invoice: Invoice,
    },
    Delivered {
        receipt: Receipt,
        bundle: ProofBundle,
        #[serde(with = "hexbytes")]
        result: Vec<u8>,
    },
    Refunded,
    Aborted {
        reason: String,
    },
}

/// Everything a purchase must keep across a restart, except the agent key,
/// mandate and principal log (kept by the caller with the agent).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuyerSnapshot {
    pub schema: u32,
    pub request: Request,
    pub started_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seller_mandate: Option<Mandate>,
    /// Held against the cap by this purchase ([`Buyer::spent_msat`]).
    pub spent_msat: u64,
    pub clock: u64,
    /// P0 passed for this purchase's invoice (SPEC 9).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hash_checked: bool,
    pub state: BuyerStateRecord,
}

/// Result of [`Buyer::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuyerProgress {
    /// HTLC still locked; seller has not revealed `k`.
    Waiting,
    /// `k` received, result decrypted and checked.
    Delivered,
}

/// The buyer's state machine. One instance per purchase; the [`Agent`]
/// (and with it the cap and the principal's log) is shared across purchases.
pub struct Buyer {
    agent: Agent,
    /// The principal's node, from the mandate: payments leave from here and
    /// refunds return here.
    node: NodeId,
    job: Box<dyn JobClass>,
    backend: Box<dyn ProofBackend>,
    policy: BuyerPolicy,
    input: Vec<u8>,
    nonce: Hash32,
    max_price_msat: u64,
    request_id: Hash32,
    /// The signed request, kept so it can be sent again after a restart.
    request: Request,
    /// When the request was made (for the wait-for-offer limit).
    started_at: u64,
    /// The accepted offer's seller mandate.
    seller_mandate: Option<Mandate>,
    /// Amount reserved against the cap for this purchase.
    reserved_msat: u64,
    /// P0 passed: the node had not paid `H` before this purchase. Set
    /// once, before any payment of ours, and never cleared.
    hash_checked: bool,
    /// Latest time seen (for refusal records).
    clock: u64,
    state: BuyerState,
}

impl Buyer {
    /// Start a purchase. Returns the buyer and the signed request to send.
    ///
    /// Refuses (and records the refusal in the principal's log) if the job
    /// class is not registered, or if the agent's own mandate does not
    /// cover it, has expired, or has no cap left.
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: RngCore + CryptoRng>(
        agent: &Agent,
        job: Box<dyn JobClass>,
        backend: Box<dyn ProofBackend>,
        policy: BuyerPolicy,
        input: Vec<u8>,
        max_price_msat: u64,
        now: u64,
        rng: &mut R,
    ) -> Result<(Buyer, Request), PcpError> {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let mandate = agent.mandate().clone();
        let mid = mandate.mandate_id();
        let mut req = Request {
            version: VERSION.to_string(),
            job_id: job.job_id().to_string(),
            spec_hash: job.spec_hash(),
            input: input.clone(),
            input_commitment: input_commitment(&input),
            buyer_nonce: nonce,
            max_price_msat,
            mandate_spent_msat: agent.committed_msat(),
            mandate: None,
            agent_sig: None,
        };
        req.agent_sig = Some(agent.sign(&req.auth_message(&mid)));
        req.mandate = Some(mandate.clone());
        let request_id = req.request_id();

        let spec = job.spec_hash();
        let e = if !policy.allow_unregistered_job_classes && !policy.registry.contains(&spec) {
            Some(PcpError::JobClassNotRegistered)
        } else if let Err(e) = mandate.check(Role::Buyer, &spec, now) {
            Some(PcpError::OwnMandate(e))
        } else if agent.remaining_msat() == 0 {
            Some(PcpError::OwnMandate(MandateError::CapExceeded {
                cap: mandate.cap_msat,
                committed: agent.committed_msat(),
                price: max_price_msat,
            }))
        } else {
            None
        };
        if let Some(e) = e {
            agent.record_refusal(request_id, None, &e, now);
            return Err(e);
        }
        let b = Buyer {
            agent: agent.clone(),
            node: mandate.payout_node.clone(),
            job,
            backend,
            policy,
            input,
            nonce,
            max_price_msat,
            request_id,
            request: req.clone(),
            started_at: now,
            seller_mandate: None,
            reserved_msat: 0,
            hash_checked: false,
            clock: now,
            state: BuyerState::Requested,
        };
        Ok((b, req))
    }

    /// Current state.
    pub fn state(&self) -> &BuyerState {
        &self.state
    }

    /// The signed request this purchase started with.
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// What this purchase holds against the cap: the price from the
    /// reservation until a refund or a payment known never to have left.
    /// It stays counted after a payment that settled, including one whose
    /// result then failed its checks.
    pub fn spent_msat(&self) -> u64 {
        self.reserved_msat
    }

    /// True when the purchase is over (delivered, refunded or aborted).
    pub fn is_done(&self) -> bool {
        matches!(
            self.state,
            BuyerState::Delivered { .. } | BuyerState::Refunded | BuyerState::Aborted(_)
        )
    }

    /// The signed acceptance to send after [`Buyer::accept_offer`]. May be
    /// sent again while waiting for the bundle: the seller treats a repeat
    /// as a no-op.
    pub fn accept_message(&self) -> Result<Accept, PcpError> {
        let BuyerState::OfferAccepted { offer } = &self.state else {
            return Err(PcpError::WrongState("accept_message needs OfferAccepted"));
        };
        let mid = self.agent.mandate_id();
        let mut a = Accept {
            version: VERSION.to_string(),
            offer_id: offer.offer_id(),
            mandate: None,
            agent_sig: None,
        };
        a.agent_sig = Some(self.agent.sign(&a.auth_message(&mid)));
        a.mandate = Some(self.agent.mandate().clone());
        Ok(a)
    }

    /// Give up where waiting can no longer succeed, and log why: no offer
    /// within `offer_wait_secs` of the request; offer expired before the
    /// invoice was accepted; invoice expired before paying. Never gives up
    /// once a payment may have left (`Paying`, `Paid`): only the rail
    /// decides those. Returns the error if it gave up.
    pub fn check_timeouts(&mut self, now: u64, offer_wait_secs: u64) -> Option<PcpError> {
        self.clock = self.clock.max(now);
        let e = match &self.state {
            BuyerState::Requested if now >= self.started_at.saturating_add(offer_wait_secs) => {
                PcpError::NoAnswer
            }
            BuyerState::OfferAccepted { offer } | BuyerState::BundleVerified { offer, .. }
                if now >= offer.offer_expires_at =>
            {
                PcpError::OfferExpired
            }
            BuyerState::InvoiceAccepted { offer, .. } if now >= offer.offer_expires_at => {
                PcpError::OfferExpired
            }
            BuyerState::InvoiceAccepted { invoice, .. } if now >= invoice.expires_at() => {
                PcpError::InvoiceExpired
            }
            _ => return None,
        };
        let _ = self.abort::<()>(e.clone());
        Some(e)
    }

    /// Everything to save after a step. Pair it with the agent's log.
    pub fn snapshot(&self) -> BuyerSnapshot {
        let state = match &self.state {
            BuyerState::Requested => BuyerStateRecord::Requested,
            BuyerState::OfferAccepted { offer } => BuyerStateRecord::OfferAccepted {
                offer: offer.clone(),
            },
            BuyerState::BundleVerified {
                offer,
                statement,
                bundle,
            } => BuyerStateRecord::BundleVerified {
                offer: offer.clone(),
                statement: statement.clone(),
                bundle: bundle.clone(),
            },
            BuyerState::InvoiceAccepted {
                offer,
                statement,
                bundle,
                invoice,
            } => BuyerStateRecord::InvoiceAccepted {
                offer: offer.clone(),
                statement: statement.clone(),
                bundle: bundle.clone(),
                invoice: invoice.clone(),
            },
            BuyerState::Paying {
                offer,
                statement,
                bundle,
                invoice,
            } => BuyerStateRecord::Paying {
                offer: offer.clone(),
                statement: statement.clone(),
                bundle: bundle.clone(),
                invoice: invoice.clone(),
            },
            BuyerState::Paid {
                offer,
                statement,
                bundle,
                invoice,
            } => BuyerStateRecord::Paid {
                offer: offer.clone(),
                statement: statement.clone(),
                bundle: bundle.clone(),
                invoice: invoice.clone(),
            },
            BuyerState::Delivered {
                receipt,
                bundle,
                result,
            } => BuyerStateRecord::Delivered {
                receipt: receipt.clone(),
                bundle: bundle.clone(),
                result: result.clone(),
            },
            BuyerState::Refunded => BuyerStateRecord::Refunded,
            BuyerState::Aborted(e) => BuyerStateRecord::Aborted { reason: e.code() },
        };
        BuyerSnapshot {
            schema: SNAPSHOT_SCHEMA,
            request: self.request.clone(),
            started_at: self.started_at,
            seller_mandate: self.seller_mandate.clone(),
            spent_msat: self.reserved_msat,
            hash_checked: self.hash_checked,
            clock: self.clock,
            state,
        }
    }

    /// Rebuild a purchase from a snapshot. The agent must already carry the
    /// cap (the sum of [`BuyerSnapshot::spent_msat`] over its purchases) and
    /// the principal log saved with it. Refuses a snapshot from another
    /// schema, another agent or mandate, or another job class.
    pub fn restore(
        agent: &Agent,
        job: Box<dyn JobClass>,
        backend: Box<dyn ProofBackend>,
        policy: BuyerPolicy,
        snap: BuyerSnapshot,
    ) -> Result<Buyer, PcpError> {
        if snap.schema != SNAPSHOT_SCHEMA {
            return Err(PcpError::Version);
        }
        let req = snap.request;
        if req.mandate.as_ref() != Some(agent.mandate()) {
            return Err(PcpError::RecordNotBound);
        }
        if req.job_id != job.job_id() || req.spec_hash != job.spec_hash() {
            return Err(PcpError::JobMismatch);
        }
        let state = match snap.state {
            BuyerStateRecord::Requested => BuyerState::Requested,
            BuyerStateRecord::OfferAccepted { offer } => BuyerState::OfferAccepted { offer },
            BuyerStateRecord::BundleVerified {
                offer,
                statement,
                bundle,
            } => BuyerState::BundleVerified {
                offer,
                statement,
                bundle,
            },
            BuyerStateRecord::InvoiceAccepted {
                offer,
                statement,
                bundle,
                invoice,
            } => BuyerState::InvoiceAccepted {
                offer,
                statement,
                bundle,
                invoice,
            },
            BuyerStateRecord::Paying {
                offer,
                statement,
                bundle,
                invoice,
            } => BuyerState::Paying {
                offer,
                statement,
                bundle,
                invoice,
            },
            BuyerStateRecord::Paid {
                offer,
                statement,
                bundle,
                invoice,
            } => BuyerState::Paid {
                offer,
                statement,
                bundle,
                invoice,
            },
            BuyerStateRecord::Delivered {
                receipt,
                bundle,
                result,
            } => BuyerState::Delivered {
                receipt,
                bundle,
                result,
            },
            BuyerStateRecord::Refunded => BuyerState::Refunded,
            BuyerStateRecord::Aborted { reason } => BuyerState::Aborted(PcpError::Recorded(reason)),
        };
        // Cross-references a valid run always leaves; a snapshot without
        // them (corrupt or edited) would only panic later, possibly after
        // the money left.
        let (offer, statement, invoice) = match &state {
            BuyerState::OfferAccepted { offer } => (Some(offer), None, None),
            BuyerState::BundleVerified {
                offer, statement, ..
            } => (Some(offer), Some(statement), None),
            BuyerState::InvoiceAccepted {
                offer,
                statement,
                invoice,
                ..
            }
            | BuyerState::Paying {
                offer,
                statement,
                invoice,
                ..
            }
            | BuyerState::Paid {
                offer,
                statement,
                invoice,
                ..
            } => (Some(offer), Some(statement), Some(invoice)),
            _ => (None, None, None),
        };
        if let Some(offer) = offer {
            let seller_ok = snap.seller_mandate.as_ref().is_some_and(|m| {
                m.agent_key == offer.mandate.as_ref().map_or([0; 32], |o| o.agent_key)
            });
            if !seller_ok || offer.buyer_nonce != req.buyer_nonce {
                return Err(PcpError::RecordNotBound);
            }
            if let Some(st) = statement {
                if st.offer_id != offer.offer_id() || st.buyer_nonce != req.buyer_nonce {
                    return Err(PcpError::RecordNotBound);
                }
                if let Some(inv) = invoice {
                    if inv.payment_hash != st.payment_hash {
                        return Err(PcpError::RecordNotBound);
                    }
                }
            }
        }
        Ok(Buyer {
            agent: agent.clone(),
            node: agent.mandate().payout_node.clone(),
            job,
            backend,
            policy,
            input: req.input.clone(),
            nonce: req.buyer_nonce,
            max_price_msat: req.max_price_msat,
            request_id: req.request_id(),
            request: req,
            started_at: snap.started_at,
            seller_mandate: snap.seller_mandate,
            reserved_msat: snap.spent_msat,
            hash_checked: snap.hash_checked,
            clock: snap.clock,
            state,
        })
    }

    /// The node this buyer pays from: its principal's.
    pub fn node(&self) -> &str {
        &self.node
    }

    /// The agent this purchase runs under.
    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    fn subject_id(&self) -> Hash32 {
        match &self.state {
            BuyerState::OfferAccepted { offer }
            | BuyerState::BundleVerified { offer, .. }
            | BuyerState::InvoiceAccepted { offer, .. }
            | BuyerState::Paying { offer, .. }
            | BuyerState::Paid { offer, .. } => offer.offer_id(),
            _ => self.request_id,
        }
    }

    fn abort_with<T>(&mut self, subject: Hash32, e: PcpError) -> Result<T, PcpError> {
        let cp = self.seller_mandate.as_ref().map(|m| m.agent_key);
        self.agent.record_refusal(subject, cp, &e, self.clock);
        self.state = BuyerState::Aborted(e.clone());
        Err(e)
    }

    fn abort<T>(&mut self, e: PcpError) -> Result<T, PcpError> {
        let subject = self.subject_id();
        self.abort_with(subject, e)
    }

    /// The seller refused the request (its `make_offer` returned `err`).
    /// Records the refusal in the principal's log and ends the purchase.
    /// Also valid after an accept was sent: the seller may refuse the
    /// accept (offer expired, not issued).
    pub fn refused_by_seller(&mut self, err: &PcpError) -> PcpError {
        if !matches!(
            self.state,
            BuyerState::Requested | BuyerState::OfferAccepted { .. }
        ) {
            return PcpError::WrongState("refused_by_seller needs Requested or OfferAccepted");
        }
        let e = PcpError::RefusedByCounterparty(err.code());
        let _ = self.abort::<()>(e.clone());
        e
    }

    /// Step 1 (SPEC 9, O1 and O2): accept or refuse the seller's terms and
    /// the seller's mandate, within this agent's own mandate.
    pub fn accept_offer(&mut self, offer: &Offer, now: u64) -> Result<(), PcpError> {
        if !matches!(self.state, BuyerState::Requested) {
            return Err(PcpError::WrongState("accept_offer needs Requested"));
        }
        self.clock = self.clock.max(now);
        let spec = self.job.spec_hash();
        let e = if offer.version != VERSION {
            Some(PcpError::Version)
        } else if offer.job_id != self.job.job_id() || offer.spec_hash != spec {
            Some(PcpError::JobMismatch)
        } else if offer.input_commitment != input_commitment(&self.input) {
            Some(PcpError::InputCommitmentMismatch)
        } else if offer.buyer_nonce != self.nonce {
            Some(PcpError::ReplayedOrMisdirected)
        } else if offer.price_msat > self.max_price_msat {
            Some(PcpError::PriceTooHigh {
                offered: offer.price_msat,
                max: self.max_price_msat,
            })
        } else if offer.price_msat > self.policy.max_deal_msat {
            Some(PcpError::DealAboveCeiling {
                price: offer.price_msat,
                ceiling: self.policy.max_deal_msat,
            })
        } else if now >= offer.offer_expires_at {
            Some(PcpError::OfferExpired)
        } else if offer.backend_id != self.backend.backend_id() {
            Some(PcpError::BackendNotAccepted)
        } else if !self.backend.is_secure() && !self.policy.allow_insecure_dev_backend {
            Some(PcpError::InsecureBackendRefused)
        } else if offer.enc_scheme != ENC_SCHEME {
            Some(PcpError::EncSchemeNotSupported)
        } else if offer.rail != self.policy.rail {
            Some(PcpError::RailNotSupported)
        } else {
            None
        };
        if let Some(e) = e {
            return self.abort_with(offer.offer_id(), e);
        }
        // O2: the seller's mandate, then this agent's own limits.
        let seller_m = match check_counterparty(
            offer.mandate.as_ref(),
            offer.agent_sig.as_ref(),
            Role::Seller,
            &spec,
            now,
            |mid| offer.auth_message(mid),
        ) {
            Ok(m) => m.clone(),
            Err(e) => return self.abort_with(offer.offer_id(), PcpError::CounterpartyMandate(e)),
        };
        self.seller_mandate = Some(seller_m.clone());
        let e = if offer.seller_node != seller_m.payout_node {
            Some(PcpError::CounterpartyMandate(
                MandateError::PayoutNodeMismatch,
            ))
        } else if let Err(e) = seller_m.check_amount(0, offer.price_msat) {
            // The seller's per-deal maximum (its cumulative total is the
            // seller's to track).
            Some(PcpError::CounterpartyMandate(e))
        } else if let Err(e) = self.agent.check_budget(offer.price_msat, now) {
            Some(PcpError::OwnMandate(e))
        } else {
            None
        };
        if let Some(e) = e {
            return self.abort_with(offer.offer_id(), e);
        }
        self.state = BuyerState::OfferAccepted {
            offer: offer.clone(),
        };
        Ok(())
    }

    /// Step 2 (SPEC 9, V1-V4): verify the proof bundle offline, before any
    /// payment. The buyer builds the statement it expects from its own state
    /// and takes only `ciphertext_hash` and `payment_hash` from the bundle.
    pub fn verify_bundle(&mut self, bundle: &ProofBundle) -> Result<(), PcpError> {
        let BuyerState::OfferAccepted { offer } = &self.state else {
            return Err(PcpError::WrongState("verify_bundle needs OfferAccepted"));
        };
        let offer = offer.clone();
        let offer_id = offer.offer_id();
        let st = &bundle.statement;
        let e = if bundle.version != VERSION || st.version != VERSION {
            Some(PcpError::Version)
        } else if bundle.backend_id != self.backend.backend_id() {
            Some(PcpError::BackendNotAccepted)
        } else if st.buyer_nonce != self.nonce {
            Some(PcpError::ReplayedOrMisdirected)
        } else if st.offer_id != offer_id {
            Some(PcpError::OfferMismatch)
        } else if st.job_id != self.job.job_id() || st.spec_hash != self.job.spec_hash() {
            Some(PcpError::JobMismatch)
        } else if st.input_commitment != input_commitment(&self.input) {
            Some(PcpError::InputCommitmentMismatch)
        } else if crypto::ciphertext_hash(&bundle.ciphertext) != st.ciphertext_hash {
            Some(PcpError::CiphertextHashMismatch)
        } else {
            None
        };
        if let Some(e) = e {
            return self.abort(e);
        }
        let expected = build_statement(
            self.job.as_ref(),
            input_commitment(&self.input),
            offer_id,
            self.nonce,
            &bundle.ciphertext,
            st.payment_hash,
        );
        if let Err(v) = self.backend.verify(self.job.as_ref(), &expected, bundle) {
            return self.abort(PcpError::ProofInvalid(v));
        }
        self.state = BuyerState::BundleVerified {
            offer,
            statement: expected,
            bundle: bundle.clone(),
        };
        Ok(())
    }

    /// Step 3 (SPEC 9, V5-V8): check the invoice against the proven `H`,
    /// the offer price, the seller principal's payout node and the buyer's
    /// timing policy.
    pub fn check_invoice(&mut self, binding: &InvoiceBinding, now: u64) -> Result<(), PcpError> {
        let BuyerState::BundleVerified {
            offer,
            statement,
            bundle,
        } = &self.state
        else {
            return Err(PcpError::WrongState("check_invoice needs BundleVerified"));
        };
        self.clock = self.clock.max(now);
        let payout_node = self
            .seller_mandate
            .as_ref()
            .map(|m| m.payout_node.as_str())
            .unwrap_or_default();
        let inv = &binding.invoice;
        let st_hash = statement.hash();
        let e = if binding.version != VERSION {
            Some(PcpError::Version)
        } else if binding.offer_id != offer.offer_id() || binding.statement_hash != st_hash {
            Some(PcpError::InvoiceBindingMismatch)
        } else if now >= offer.offer_expires_at {
            // SPEC: the offer is void after offer_expires_at; never pay on it.
            Some(PcpError::OfferExpired)
        } else if inv.payment_hash != statement.payment_hash {
            Some(PcpError::InvoiceHashMismatch)
        } else if inv.amount_msat != offer.price_msat {
            Some(PcpError::InvoiceAmountMismatch {
                invoice: inv.amount_msat,
                offer: offer.price_msat,
            })
        } else if inv.payee != offer.seller_node || inv.payee != payout_node {
            Some(PcpError::InvoicePayeeMismatch)
        } else if inv.description_hash != st_hash {
            Some(PcpError::InvoiceDescriptionMismatch)
        } else if now.saturating_add(self.policy.min_invoice_remaining_secs) >= inv.expires_at() {
            Some(PcpError::InvoiceExpiresTooSoon)
        } else if inv.min_htlc_secs > self.policy.htlc_secs {
            Some(PcpError::HtlcLockTooLong {
                asked: inv.min_htlc_secs,
                allowed: self.policy.htlc_secs,
            })
        } else {
            None
        };
        if let Some(e) = e {
            return self.abort(e);
        }
        self.state = BuyerState::InvoiceAccepted {
            offer: offer.clone(),
            statement: statement.clone(),
            bundle: bundle.clone(),
            invoice: inv.clone(),
        };
        Ok(())
    }

    /// Step 4 (P1) on the simulated ledger: as [`Buyer::pay_via`], and
    /// returns the ledger's HTLC id.
    pub fn pay(&mut self, ledger: &mut Ledger) -> Result<HtlcId, PcpError> {
        self.pay_via(ledger)?;
        let BuyerState::Paid { statement, .. } = &self.state else {
            unreachable!("pay_via succeeded")
        };
        Ok(ledger
            .latest_htlc(&self.node, &statement.payment_hash)
            .expect("the ledger just locked this HTLC")
            .id)
    }

    /// Step 4 (P1): reserve the price against the mandate's cap, then lock
    /// it in an HTLC to `H` from the principal's node, on any [`Rail`].
    ///
    /// The state is `Paying` from the reservation until the rail answers. If
    /// the payment call fails, the payment is looked up (a lost reply can
    /// hide an HTLC that left): in flight or settled means `Paid`; known not
    /// to have left means the reservation is released and the state goes
    /// back to `InvoiceAccepted`; a lookup that itself fails leaves the state
    /// `Paying` with the reservation held, for [`Buyer::recover_payment`].
    ///
    /// Runs P0 ([`Buyer::check_payment_hash`]) first; a `PaymentHashSeen`
    /// refusal leaves nothing reserved.
    pub fn pay_via(&mut self, rail: &mut dyn Rail) -> Result<(), PcpError> {
        self.check_payment_hash(rail)?;
        self.begin_pay(rail.rail_id(), rail.now())?;
        self.send_payment(rail)
    }

    /// Whether P0 has passed ([`Buyer::check_payment_hash`]).
    pub fn payment_hash_checked(&self) -> bool {
        self.hash_checked
    }

    /// Step P0 (SPEC 9), once per purchase and before any payment of ours:
    /// refuse `H` if this node already paid it (in flight or settled). Paying a reused `H` would be
    /// refused by the node, and the P1 lookup would then take the earlier
    /// payment for ours: a receipt and a cap charge for money that never
    /// left. A failed earlier payment does not count (its funds are back).
    /// A lookup error changes nothing; ask again.
    pub fn check_payment_hash(&mut self, rail: &mut dyn Rail) -> Result<(), PcpError> {
        let BuyerState::InvoiceAccepted {
            offer, statement, ..
        } = &self.state
        else {
            return Err(PcpError::WrongState("P0 needs InvoiceAccepted"));
        };
        if self.hash_checked {
            return Ok(());
        }
        if rail.rail_id() != offer.rail {
            return Err(PcpError::RailNotSupported);
        }
        let h = statement.payment_hash;
        let seen = matches!(
            rail.lookup_payment(&self.node, &h)?,
            PaymentStatus::InFlight | PaymentStatus::Settled { .. }
        );
        if seen {
            self.clock = self.clock.max(rail.now());
            return self.abort(PcpError::PaymentHashSeen);
        }
        self.hash_checked = true;
        Ok(())
    }

    /// First half of [`Buyer::pay_via`]: reserve the price against the cap
    /// and enter `Paying`, without touching the rail. A caller that saves
    /// state saves it here, before [`Buyer::send_payment`], so a crash
    /// during the payment call restarts in `Paying` with the reservation.
    pub fn begin_pay(&mut self, rail_id: &str, now: u64) -> Result<(), PcpError> {
        let BuyerState::InvoiceAccepted { invoice, offer, .. } = &self.state else {
            return Err(PcpError::WrongState("pay needs InvoiceAccepted"));
        };
        if !self.hash_checked {
            return Err(PcpError::WrongState("check_payment_hash before paying"));
        }
        if rail_id != offer.rail {
            return Err(PcpError::RailNotSupported);
        }
        // SPEC: the offer is void after offer_expires_at; never pay on it
        // (a buyer restarted late can reach here after the offer lapsed).
        if now >= offer.offer_expires_at {
            self.clock = self.clock.max(now);
            return self.abort(PcpError::OfferExpired);
        }
        let amount = invoice.amount_msat;
        self.clock = self.clock.max(now);
        if let Err(e) = self.agent.reserve(amount, now) {
            return self.abort(PcpError::OwnMandate(e));
        }
        self.reserved_msat = amount;
        self.enter_paying();
        Ok(())
    }

    /// Second half of [`Buyer::pay_via`]: make the payment call from
    /// `Paying`. On an error, looks the payment up ([`Buyer::recover_payment`]).
    pub fn send_payment(&mut self, rail: &mut dyn Rail) -> Result<(), PcpError> {
        let BuyerState::Paying { invoice, .. } = &self.state else {
            return Err(PcpError::WrongState("send_payment needs Paying"));
        };
        let invoice = invoice.clone();
        match rail.pay_invoice(&self.node, &invoice, self.policy.htlc_secs) {
            Ok(()) => {
                self.paying_to(true);
                Ok(())
            }
            Err(e) => match self.recover_payment(rail) {
                // The HTLC left despite the error: the payment stands.
                Ok(()) => Ok(()),
                // Known not to have left (released), or not known (held).
                Err(_) => Err(e.into()),
            },
        }
    }

    /// Resolve a `Paying` state from the payer's node: in flight or settled
    /// means `Paid` (returns `Ok`); never left or failed means the
    /// reservation is released and the state is `InvoiceAccepted` again
    /// (returns `Err(NotPaid)`; paying again re-checks the invoice's expiry);
    /// a lookup error keeps `Paying` and the reservation (returns the error).
    /// Called by [`Buyer::pay_via`], and after a restart in `Paying`.
    pub fn recover_payment(&mut self, rail: &mut dyn Rail) -> Result<(), PcpError> {
        let BuyerState::Paying { statement, .. } = &self.state else {
            return Err(PcpError::WrongState("recover_payment needs Paying"));
        };
        let h = statement.payment_hash;
        self.clock = self.clock.max(rail.now());
        match rail.lookup_payment(&self.node, &h) {
            Ok(PaymentStatus::InFlight) | Ok(PaymentStatus::Settled { .. }) => {
                self.paying_to(true);
                Ok(())
            }
            Ok(PaymentStatus::Unknown) | Ok(PaymentStatus::Failed { .. }) => {
                self.agent.release(self.reserved_msat);
                self.reserved_msat = 0;
                self.paying_to(false);
                Err(PcpError::NotPaid)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// `InvoiceAccepted` -> `Paying`.
    fn enter_paying(&mut self) {
        let BuyerState::InvoiceAccepted {
            offer,
            statement,
            bundle,
            invoice,
        } = std::mem::replace(&mut self.state, BuyerState::Requested)
        else {
            unreachable!("enter_paying needs InvoiceAccepted")
        };
        self.state = BuyerState::Paying {
            offer,
            statement,
            bundle,
            invoice,
        };
    }

    /// `Paying` -> `Paid` (the HTLC left) or back to `InvoiceAccepted`.
    fn paying_to(&mut self, left: bool) {
        let BuyerState::Paying {
            offer,
            statement,
            bundle,
            invoice,
        } = std::mem::replace(&mut self.state, BuyerState::Requested)
        else {
            unreachable!("paying_to needs Paying")
        };
        self.state = if left {
            BuyerState::Paid {
                offer,
                statement,
                bundle,
                invoice,
            }
        } else {
            BuyerState::InvoiceAccepted {
                offer,
                statement,
                bundle,
                invoice,
            }
        };
    }

    /// Steps P2-P6: watch the HTLC. When it settles, take `k`, check
    /// `SHA256(k) == H`, decrypt `C`, re-run the job check, and append the
    /// signed receipt to the principal's log.
    pub fn poll(&mut self, rail: &mut dyn Rail) -> Result<BuyerProgress, PcpError> {
        let BuyerState::Paid {
            offer, statement, ..
        } = &self.state
        else {
            return Err(PcpError::WrongState("poll needs Paid"));
        };
        let offer_id = offer.offer_id();
        let payment_hash = statement.payment_hash;
        self.clock = self.clock.max(rail.now());
        let (k, at) = match rail.lookup_payment(&self.node, &payment_hash)? {
            PaymentStatus::InFlight => return Ok(BuyerProgress::Waiting),
            PaymentStatus::Unknown => return Err(PcpError::Ledger(LedgerError::UnknownHtlc)),
            PaymentStatus::Failed { .. } => {
                self.agent.release(self.reserved_msat);
                self.reserved_msat = 0;
                let cp = self.seller_mandate.as_ref().map(|m| m.agent_key);
                self.agent
                    .record_refusal(offer_id, cp, &PcpError::Refunded, self.clock);
                self.state = BuyerState::Refunded;
                return Err(PcpError::Refunded);
            }
            PaymentStatus::Settled { preimage, at } => (preimage, at),
        };
        let BuyerState::Paid {
            statement,
            bundle,
            invoice,
            ..
        } = std::mem::replace(&mut self.state, BuyerState::Requested)
        else {
            unreachable!()
        };
        if crypto::payment_hash(&k) != statement.payment_hash {
            return self.abort_with(offer_id, PcpError::PreimageMismatch);
        }
        let Some(result) = crypto::decrypt(&k, &offer_id, &bundle.ciphertext) else {
            return self.abort_with(offer_id, PcpError::DecryptionFailed);
        };
        if self.policy.recheck_locally && !self.job.check(&self.input, &result) {
            return self.abort_with(offer_id, PcpError::PostPaymentCheckFailed);
        }
        let seller_m = self
            .seller_mandate
            .as_ref()
            .expect("an accepted offer has a seller mandate");
        let receipt = self.agent.record_deal(
            Receipt {
                version: VERSION.to_string(),
                role: Role::Buyer,
                mandate_id: [0u8; 32],
                principal_key: [0u8; 32],
                counterparty_mandate_id: seller_m.mandate_id(),
                counterparty_principal_key: seller_m.principal_key,
                agent_key: [0u8; 32],
                offer_id,
                statement_hash: statement.hash(),
                bundle_id: bundle.bundle_id(),
                payment_hash: statement.payment_hash,
                preimage: k,
                amount_msat: invoice.amount_msat,
                settled_at: at,
                agent_sig: Sig([0u8; 64]),
            },
            &bundle,
            &self.input,
        );
        self.state = BuyerState::Delivered {
            receipt,
            bundle,
            result,
        };
        Ok(BuyerProgress::Delivered)
    }

    /// The purchased result. Only available after settlement.
    pub fn result(&self) -> Result<&[u8], PcpError> {
        match &self.state {
            BuyerState::Delivered { result, .. } => Ok(result),
            BuyerState::Refunded => Err(PcpError::Refunded),
            _ => Err(PcpError::NotPaid),
        }
    }

    /// The receipt. Only available after settlement.
    pub fn receipt(&self) -> Result<&Receipt, PcpError> {
        match &self.state {
            BuyerState::Delivered { receipt, .. } => Ok(receipt),
            _ => Err(PcpError::NotPaid),
        }
    }
}

// ---------------------------------------------------------------------------
// Seller

/// Seller configuration.
#[derive(Clone, Debug)]
pub struct SellerConfig {
    pub price_msat: u64,
    /// Seconds an offer stays valid.
    pub offer_ttl_secs: u64,
    /// Seconds an invoice stays payable.
    pub invoice_expiry_secs: u64,
    /// Minimum HTLC lock the seller asks for.
    pub min_htlc_secs: u64,
    /// The seller refuses to reveal `k` if the HTLC times out sooner than
    /// this (on a real chain, a late preimage can lose the race to a refund).
    pub settle_margin_secs: u64,
    /// Reviewed job classes this seller will sell.
    pub registry: JobRegistry,
    /// Development only: sell job classes that are not in `registry`.
    pub allow_unregistered_job_classes: bool,
    /// The settlement rail named in offers. Default [`RAIL_SIM`];
    /// [`RAIL_BOLT11`] with a real node.
    pub rail: String,
    /// Most offers open at once (issued and unexpired, or accepted, or
    /// invoiced and not yet over). Beyond it a request gets `SellerBusy`.
    pub max_open_offers: usize,
    /// Most open offers per buyer principal.
    pub max_open_per_principal: usize,
    /// Most accepted offers waiting to be proven. An accept beyond it is
    /// answered [`AcceptStep::Busy`] and the buyer asks again.
    pub max_unproven: usize,
    /// Most refusals of requests and accepts logged per minute. More are
    /// counted, not logged, so a flood of bad requests cannot grow the log.
    pub refusals_logged_per_minute: u32,
    /// Serve only these principals (public keys), checked before anything
    /// else in a request: the defence for an invited window (SPEC 2.1, T2).
    /// `None` serves everyone. Offers issued before a restart with another
    /// list stay acceptable until they expire.
    pub allowed_principals: Option<Vec<Hash32>>,
}

impl SellerConfig {
    /// Defaults for a seller on Lightning with hold invoices. The final CLTV
    /// is LND's minimum (24 blocks). The settle margin is two blocks more than
    /// LND's own hold-expiry cancel, so the seller never tries to settle an
    /// HTLC its node is about to cancel. The offer lives 15 minutes: at least
    /// three times the slowest proving time measured for the reproducible
    /// RISC Zero guest on a 4-vCPU CI runner (159 s, the 2^18 test-suite job).
    pub fn lightning(price_msat: u64) -> Self {
        SellerConfig {
            price_msat,
            offer_ttl_secs: 900,
            invoice_expiry_secs: 600,
            min_htlc_secs: LN_FINAL_CLTV_BLOCKS * SECS_PER_BLOCK,
            settle_margin_secs: (LN_HOLD_EXPIRY_DELTA_BLOCKS + 2) * SECS_PER_BLOCK,
            rail: RAIL_BOLT11.to_string(),
            ..SellerConfig::default()
        }
    }
}

impl Default for SellerConfig {
    fn default() -> Self {
        SellerConfig {
            price_msat: 1_000_000,
            offer_ttl_secs: 600,
            invoice_expiry_secs: 600,
            min_htlc_secs: 600,
            settle_margin_secs: 120,
            registry: JobRegistry::reference(),
            allow_unregistered_job_classes: false,
            rail: RAIL_SIM.to_string(),
            max_open_offers: 8,
            max_open_per_principal: 1,
            max_unproven: 1,
            refusals_logged_per_minute: 10,
            allowed_principals: None,
        }
    }
}

/// Where an issued offer is (seller side).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "stage")]
pub enum OfferStage {
    /// Sent; the buyer has not accepted it.
    Issued,
    /// The buyer accepted it; the seller has not finished proving.
    Accepted,
    /// Proven: `k` exists and is recorded, the invoice may not exist yet.
    Proven {
        #[serde(with = "hex32")]
        payment_hash: Hash32,
    },
    /// Invoiced: bundle and invoice binding can be sent (and re-sent).
    Invoiced {
        #[serde(with = "hex32")]
        payment_hash: Hash32,
    },
    /// Over before an invoice existed (expired, or the seller refused).
    Closed { reason: String },
}

/// An offer the seller issued, with the request it answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedOffer {
    pub request: Request,
    pub offer: Offer,
    pub stage: OfferStage,
}

/// One sale from the moment `k` exists. Contains `k`: a seller's state is
/// as sensitive as the keys of its node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaleRecord {
    #[serde(with = "hex32")]
    pub key: [u8; 32],
    pub price_msat: u64,
    /// `k` was revealed and the receipt is in the principal's log.
    pub settled: bool,
    /// Amount settled (zero unless `settled`).
    pub settled_msat: u64,
    /// Ended without payment (cancelled, expired or refused).
    pub closed: bool,
    #[serde(with = "hex32")]
    pub offer_id: Hash32,
    pub bundle: ProofBundle,
    /// The invoice to `H`, once created (or found again after a restart).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice: Option<Invoice>,
    #[serde(with = "hexbytes")]
    pub input: Vec<u8>,
    pub buyer_mandate: Mandate,
}

impl SaleRecord {
    fn statement_hash(&self) -> Hash32 {
        self.bundle.statement.hash()
    }

    fn binding(&self) -> Option<InvoiceBinding> {
        self.invoice.as_ref().map(|invoice| InvoiceBinding {
            version: VERSION.to_string(),
            offer_id: self.offer_id,
            statement_hash: self.statement_hash(),
            invoice: invoice.clone(),
        })
    }
}

/// Everything a seller must keep across a restart, except its agent key,
/// mandate and principal log (kept by the caller with the agent) and its
/// configuration. Versioned separately from the wire messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SellerSnapshot {
    pub schema: u32,
    pub offers: Vec<IssuedOffer>,
    pub sales: Vec<SaleRecord>,
}

/// Version of [`SellerSnapshot`] and [`BuyerSnapshot`].
pub const SNAPSHOT_SCHEMA: u32 = 1;

impl SellerSnapshot {
    /// What the seller has sold under its mandate: the sum of settled sales.
    /// The seller's cap is restored from this, never from a counter.
    pub fn committed_msat(&self) -> u64 {
        self.sales
            .iter()
            .filter(|s| s.settled)
            .map(|s| s.settled_msat)
            .sum()
    }
}

/// What the seller does next after an [`Accept`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptStep {
    /// First accept: prove (call [`Seller::prove`], then [`Seller::invoice`]).
    Prove,
    /// Accepted before and not yet invoiced: the work is in progress (or
    /// resumes after a restart). Nothing to send yet.
    Pending,
    /// Already invoiced: send these again.
    Resend(Box<ProofBundle>, Box<InvoiceBinding>),
    /// The seller is proving for someone else: nothing changed, nothing
    /// logged; the buyer sends the accept again later.
    Busy,
}

/// What happened to one open sale on [`Seller::settle_paid`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaleOutcome {
    /// HTLC found and settled; `k` revealed; receipt in the principal's log.
    Settled {
        payment_hash: Hash32,
        amount_msat: u64,
    },
    /// No acceptable HTLC yet.
    NotPaid { payment_hash: Hash32 },
    /// HTLC found but `k` withheld for now (the node could not be read or
    /// the settle call failed). Tried again on the next pass.
    Withheld {
        payment_hash: Hash32,
        reason: PcpError,
    },
    /// The sale is over without payment: the seller cancelled the HTLC for a
    /// reason that can never clear (amount short, too close to timeout, own
    /// cap exceeded), or the invoice was cancelled or expired. Logged as a
    /// refusal; never polled again.
    Cancelled {
        payment_hash: Hash32,
        reason: PcpError,
    },
}

/// The seller's state machine. Holds `k` for each open sale and reveals it
/// only by settling an HTLC that pays the agreed price to the principal's
/// payout node.
///
/// Two ways to drive it. In one process: [`Seller::make_offer`] then
/// [`Seller::fulfil`]. Over a wire, with state saved between steps:
/// [`Seller::make_offer`], [`Seller::accept`] (the buyer's signed
/// [`Accept`]), [`Seller::prove`], [`Seller::invoice`], then
/// [`Seller::settle_paid`]; [`Seller::snapshot`] after each step, and
/// [`Seller::restore`] after a restart.
pub struct Seller {
    agent: Agent,
    /// The principal's payout node, from the mandate.
    node: NodeId,
    job: Box<dyn JobClass>,
    backend: Box<dyn ProofBackend>,
    cfg: SellerConfig,
    /// Issued offers by `offer_id`.
    offers: BTreeMap<Hash32, IssuedOffer>,
    /// `request_id` to `offer_id`: a request sent twice gets the same offer.
    by_request: BTreeMap<Hash32, Hash32>,
    /// Sales by payment hash `H`.
    sales: BTreeMap<Hash32, SaleRecord>,
    /// Refusal rate limit: start of the current minute and refusals logged
    /// in it. In memory only.
    refusal_window: (u64, u32),
    /// Refusals not logged because of the rate limit (since start).
    suppressed_refusals: u64,
}

impl Seller {
    pub fn new(
        agent: &Agent,
        job: Box<dyn JobClass>,
        backend: Box<dyn ProofBackend>,
        cfg: SellerConfig,
    ) -> Seller {
        Seller {
            agent: agent.clone(),
            node: agent.mandate().payout_node.clone(),
            job,
            backend,
            cfg,
            offers: BTreeMap::new(),
            by_request: BTreeMap::new(),
            sales: BTreeMap::new(),
            refusal_window: (0, 0),
            suppressed_refusals: 0,
        }
    }

    /// Log a refusal of a request or an accept, at most
    /// `refusals_logged_per_minute` per minute; count the rest.
    fn log_refusal(&mut self, subject: Hash32, cp: Option<PublicKey>, e: &PcpError, now: u64) {
        let (start, count) = self.refusal_window;
        let (start, count) = if now >= start.saturating_add(60) {
            (now, 0)
        } else {
            (start, count)
        };
        if count < self.cfg.refusals_logged_per_minute {
            self.agent.record_refusal(subject, cp, e, now);
            self.refusal_window = (start, count + 1);
        } else {
            self.refusal_window = (start, count);
            self.suppressed_refusals += 1;
        }
    }

    /// Refusals of requests and accepts that were counted but not logged.
    pub fn suppressed_refusals(&self) -> u64 {
        self.suppressed_refusals
    }

    /// Is this offer still taking a place (see `max_open_offers`)?
    fn is_open(&self, o: &IssuedOffer, now: u64) -> bool {
        match &o.stage {
            OfferStage::Issued => now < o.offer.offer_expires_at,
            OfferStage::Accepted | OfferStage::Proven { .. } => true,
            OfferStage::Invoiced { payment_hash } => self
                .sales
                .get(payment_hash)
                .is_some_and(|s| !s.settled && !s.closed),
            OfferStage::Closed { .. } => false,
        }
    }

    /// Drop offers that can no longer matter: issued or closed offers, and
    /// invoiced offers whose sale is over, once they expired more than an
    /// offer lifetime ago. Sales are kept (they hold the cap and `k`).
    /// Returns how many were dropped.
    pub fn purge(&mut self, now: u64) -> usize {
        let grace = self.cfg.offer_ttl_secs;
        let gone: Vec<Hash32> = self
            .offers
            .iter()
            .filter(|(_, o)| {
                now >= o.offer.offer_expires_at.saturating_add(grace)
                    && match &o.stage {
                        OfferStage::Issued | OfferStage::Closed { .. } => true,
                        OfferStage::Invoiced { payment_hash } => self
                            .sales
                            .get(payment_hash)
                            .is_none_or(|s| s.settled || s.closed),
                        OfferStage::Accepted | OfferStage::Proven { .. } => false,
                    }
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &gone {
            self.offers.remove(id);
        }
        self.by_request.retain(|_, id| !gone.contains(id));
        gone.len()
    }

    /// Rebuild a seller from a snapshot. The agent must already carry the
    /// cap ([`SellerSnapshot::committed_msat`]) and the principal log saved
    /// with it. Refuses a snapshot from another schema, or whose offers name
    /// another job class, backend or payout node than this configuration.
    pub fn restore(
        agent: &Agent,
        job: Box<dyn JobClass>,
        backend: Box<dyn ProofBackend>,
        cfg: SellerConfig,
        snap: SellerSnapshot,
    ) -> Result<Seller, PcpError> {
        if snap.schema != SNAPSHOT_SCHEMA {
            return Err(PcpError::Version);
        }
        let mut s = Seller::new(agent, job, backend, cfg);
        for o in snap.offers {
            if o.offer.job_id != s.job.job_id()
                || o.offer.spec_hash != s.job.spec_hash()
                || o.offer.backend_id != s.backend.backend_id()
                || o.offer.seller_node != s.node
            {
                return Err(PcpError::OfferMismatch);
            }
            let id = o.offer.offer_id();
            s.by_request.insert(o.request.request_id(), id);
            s.offers.insert(id, o);
        }
        for r in snap.sales {
            // `k` must open the hash it is filed under, and the sale must
            // belong to an offer of this snapshot.
            let h = r.bundle.statement.payment_hash;
            if crypto::payment_hash(&r.key) != h || r.bundle.statement.offer_id != r.offer_id {
                return Err(PcpError::RecordNotBound);
            }
            s.sales.insert(h, r);
        }
        // Every proven or invoiced offer has its sale: otherwise the next
        // repeated Accept would look up a sale that is not there.
        for (id, o) in &s.offers {
            if let OfferStage::Proven { payment_hash } | OfferStage::Invoiced { payment_hash } =
                &o.stage
            {
                if s.sales.get(payment_hash).is_none_or(|r| r.offer_id != *id) {
                    return Err(PcpError::RecordNotBound);
                }
            }
        }
        Ok(s)
    }

    /// Everything to save after a step. Pair it with the agent's log.
    pub fn snapshot(&self) -> SellerSnapshot {
        SellerSnapshot {
            schema: SNAPSHOT_SCHEMA,
            offers: self.offers.values().cloned().collect(),
            sales: self.sales.values().cloned().collect(),
        }
    }

    /// The node invoices pay: the principal's payout node.
    pub fn node(&self) -> &str {
        &self.node
    }

    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    /// An issued offer, by `offer_id`.
    pub fn issued(&self, offer_id: &Hash32) -> Option<&IssuedOffer> {
        self.offers.get(offer_id)
    }

    /// Offers the buyer accepted that still need [`Seller::prove`] or
    /// [`Seller::invoice`] (work to resume after a restart).
    pub fn unfinished(&self) -> Vec<(Hash32, OfferStage)> {
        self.offers
            .iter()
            .filter(|(_, o)| matches!(o.stage, OfferStage::Accepted | OfferStage::Proven { .. }))
            .map(|(id, o)| (*id, o.stage.clone()))
            .collect()
    }

    /// True when no offer awaits work and every sale is settled or closed.
    pub fn is_idle(&self) -> bool {
        self.unfinished().is_empty() && self.sales.values().all(|s| s.settled || s.closed)
    }

    /// Quote terms for a request (SPEC 9, S1 and S1m), and remember the
    /// offer. The same request (same `request_id`) gets the same offer while
    /// it is valid. Refusals are recorded in the principal's log.
    pub fn make_offer(&mut self, req: &Request, now: u64) -> Result<Offer, PcpError> {
        if let Some(o) = self
            .by_request
            .get(&req.request_id())
            .and_then(|id| self.offers.get(id))
        {
            if now < o.offer.offer_expires_at && o.request == *req {
                return Ok(o.offer.clone());
            }
        }
        let r = self.check_request(req, now).and_then(|offer| {
            // Caps, after the request checked out: a place per principal
            // and in total, so one requester cannot crowd out the rest.
            let principal = req.mandate.as_ref().map(|m| m.principal_key);
            let open: Vec<&IssuedOffer> = self
                .offers
                .values()
                .filter(|o| self.is_open(o, now))
                .collect();
            let mine = open
                .iter()
                .filter(|o| o.request.mandate.as_ref().map(|m| m.principal_key) == principal)
                .count();
            if open.len() >= self.cfg.max_open_offers || mine >= self.cfg.max_open_per_principal {
                Err(PcpError::SellerBusy)
            } else {
                Ok(offer)
            }
        });
        match &r {
            Ok(offer) => {
                let id = offer.offer_id();
                self.by_request.insert(req.request_id(), id);
                self.offers.insert(
                    id,
                    IssuedOffer {
                        request: req.clone(),
                        offer: offer.clone(),
                        stage: OfferStage::Issued,
                    },
                );
            }
            Err(e) => {
                let cp = req.mandate.as_ref().map(|m| m.agent_key);
                self.log_refusal(req.request_id(), cp, e, now);
            }
        }
        r
    }

    fn check_request(&self, req: &Request, now: u64) -> Result<Offer, PcpError> {
        let spec = self.job.spec_hash();
        let price = self.cfg.price_msat;
        if req.version != VERSION {
            return Err(PcpError::Version);
        }
        // Before any other work: a 32-byte comparison. A listed key still
        // goes through the full mandate check below; with a list, a request
        // without a mandate names no listed principal and is refused here.
        if let Some(list) = &self.cfg.allowed_principals {
            if !req
                .mandate
                .as_ref()
                .is_some_and(|m| list.contains(&m.principal_key))
            {
                return Err(PcpError::PrincipalNotAllowed);
            }
        }
        if req.job_id != self.job.job_id() || req.spec_hash != spec {
            return Err(PcpError::JobMismatch);
        }
        if input_commitment(&req.input) != req.input_commitment {
            return Err(PcpError::InputCommitmentMismatch);
        }
        if price > req.max_price_msat {
            return Err(PcpError::PriceTooHigh {
                offered: price,
                max: req.max_price_msat,
            });
        }
        if !self.cfg.allow_unregistered_job_classes && !self.cfg.registry.contains(&spec) {
            return Err(PcpError::JobClassNotRegistered);
        }
        // Own mandate: role, scope, expiry, per-deal maximum, cap.
        self.agent
            .mandate()
            .check(Role::Seller, &spec, now)
            .and_then(|()| self.agent.check_budget(price, now))
            .map_err(PcpError::OwnMandate)?;
        // The buyer's mandate: signature, role, scope, expiry, agent
        // signature, per-deal maximum, and the cap less what the buyer
        // agent declares it has spent.
        let buyer_m = check_counterparty(
            req.mandate.as_ref(),
            req.agent_sig.as_ref(),
            Role::Buyer,
            &spec,
            now,
            |mid| req.auth_message(mid),
        )
        .map_err(PcpError::CounterpartyMandate)?;
        buyer_m
            .check_amount(req.mandate_spent_msat, price)
            .map_err(PcpError::CounterpartyMandate)?;

        let mut offer = Offer {
            version: VERSION.to_string(),
            job_id: self.job.job_id().to_string(),
            spec_hash: spec,
            input_commitment: req.input_commitment,
            buyer_nonce: req.buyer_nonce,
            price_msat: price,
            offer_expires_at: now.saturating_add(self.cfg.offer_ttl_secs),
            seller_node: self.node.clone(),
            backend_id: self.backend.backend_id().to_string(),
            enc_scheme: ENC_SCHEME.to_string(),
            rail: self.cfg.rail.clone(),
            mandate: None,
            agent_sig: None,
        };
        offer.agent_sig = Some(
            self.agent
                .sign(&offer.auth_message(&self.agent.mandate_id())),
        );
        offer.mandate = Some(self.agent.mandate().clone());
        Ok(offer)
    }

    /// The buyer accepts an offer (SPEC 9, S1o). Checked before any proving:
    /// the offer must be one this seller issued and still valid, and the
    /// accept must be signed by the agent that sent the request, under its
    /// mandate. A repeated accept is not an error: it returns
    /// [`AcceptStep::Pending`] or [`AcceptStep::Resend`] and logs nothing.
    pub fn accept(&mut self, acc: &Accept, now: u64) -> Result<AcceptStep, PcpError> {
        // An offer that is already over: answer with the reason it ended,
        // logged once when it ended, not again for every repeat.
        if let Some(OfferStage::Closed { reason }) =
            self.offers.get(&acc.offer_id).map(|o| &o.stage)
        {
            return Err(PcpError::Recorded(reason.clone()));
        }
        let r = self.check_accept(acc, now);
        if let Err(e) = &r {
            let cp = acc.mandate.as_ref().map(|m| m.agent_key);
            self.log_refusal(acc.offer_id, cp, e, now);
        }
        r
    }

    fn check_accept(&mut self, acc: &Accept, now: u64) -> Result<AcceptStep, PcpError> {
        if acc.version != VERSION {
            return Err(PcpError::Version);
        }
        let spec = self.job.spec_hash();
        let Some(issued) = self.offers.get(&acc.offer_id) else {
            return Err(PcpError::OfferNotIssued);
        };
        // Signed by the agent that sent the request, under the same mandate.
        let buyer_m = check_counterparty(
            acc.mandate.as_ref(),
            acc.agent_sig.as_ref(),
            Role::Buyer,
            &spec,
            now,
            |mid| acc.auth_message(mid),
        )
        .map_err(PcpError::CounterpartyMandate)?;
        if issued.request.mandate.as_ref() != Some(buyer_m) {
            return Err(PcpError::CounterpartyMandate(
                MandateError::AgentKeyMismatch,
            ));
        }
        match &issued.stage {
            OfferStage::Issued => {}
            OfferStage::Accepted | OfferStage::Proven { .. } => return Ok(AcceptStep::Pending),
            OfferStage::Invoiced { payment_hash } => {
                let sale = &self.sales[payment_hash];
                return Ok(match sale.binding() {
                    Some(b) => AcceptStep::Resend(Box::new(sale.bundle.clone()), Box::new(b)),
                    None => AcceptStep::Pending,
                });
            }
            OfferStage::Closed { reason } => return Err(PcpError::Recorded(reason.clone())),
        }
        if now >= issued.offer.offer_expires_at {
            self.close_offer(&acc.offer_id, &PcpError::OfferExpired);
            return Err(PcpError::OfferExpired);
        }
        // One proof at a time (configurable): the next accept waits.
        if self.unfinished().len() >= self.cfg.max_unproven {
            return Ok(AcceptStep::Busy);
        }
        self.offers
            .get_mut(&acc.offer_id)
            .expect("checked above")
            .stage = OfferStage::Accepted;
        Ok(AcceptStep::Prove)
    }

    fn close_offer(&mut self, offer_id: &Hash32, reason: &PcpError) {
        if let Some(o) = self.offers.get_mut(offer_id) {
            o.stage = OfferStage::Closed {
                reason: reason.code(),
            };
        }
    }

    /// Close accepted offers that expired before they were proven (after a
    /// long outage). Logs each as a refusal. Returns their ids.
    pub fn expire_unproven(&mut self, now: u64) -> Vec<Hash32> {
        let ids: Vec<Hash32> = self
            .offers
            .iter()
            .filter(|(_, o)| {
                matches!(o.stage, OfferStage::Issued | OfferStage::Accepted)
                    && now >= o.offer.offer_expires_at
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &ids {
            let accepted = matches!(self.offers[id].stage, OfferStage::Accepted);
            self.close_offer(id, &PcpError::OfferExpired);
            if accepted {
                let cp = self.offers[id]
                    .request
                    .mandate
                    .as_ref()
                    .map(|m| m.agent_key);
                self.agent
                    .record_refusal(*id, cp, &PcpError::OfferExpired, now);
            }
        }
        ids
    }

    /// Package a result for sale in one call: check the offer, then
    /// [`Seller::prove`] and [`Seller::invoice`]. For a seller that keeps
    /// buyer and seller in one process; over a wire, use the steps.
    pub fn fulfil<R: RngCore + CryptoRng>(
        &mut self,
        req: &Request,
        offer: &Offer,
        result: Vec<u8>,
        rail: &mut dyn Rail,
        rng: &mut R,
    ) -> Result<(ProofBundle, InvoiceBinding), PcpError> {
        let offer_id = offer.offer_id();
        if let Err(e) = self.check_offer_is_mine(req, offer, rail) {
            let cp = req.mandate.as_ref().map(|m| m.agent_key);
            self.agent.record_refusal(offer_id, cp, &e, rail.now());
            return Err(e);
        }
        let entry = self.offers.entry(offer_id).or_insert_with(|| IssuedOffer {
            request: req.clone(),
            offer: offer.clone(),
            stage: OfferStage::Issued,
        });
        if entry.stage == OfferStage::Issued {
            entry.stage = OfferStage::Accepted;
        }
        self.by_request.insert(req.request_id(), offer_id);
        self.prove(&offer_id, result, rail.now(), rng)?;
        self.invoice(&offer_id, rail)
    }

    /// The offer is this seller's own, unchanged, for this request.
    fn check_offer_is_mine(
        &self,
        req: &Request,
        offer: &Offer,
        rail: &dyn Rail,
    ) -> Result<(), PcpError> {
        if rail.rail_id() != offer.rail {
            return Err(PcpError::RailNotSupported);
        }
        if offer.input_commitment != input_commitment(&req.input)
            || offer.buyer_nonce != req.buyer_nonce
        {
            return Err(PcpError::OfferMismatch);
        }
        // Fulfil only an offer this seller issued, with exactly the terms it
        // signed. `offer_id` covers every term (price, expiry, node, backend,
        // rail, ...), so an offer handed back with any term changed fails the
        // signature. Without this, a buyer who returns the offer over a wire
        // could set its own price or expiry.
        let issued_by_me = offer.agent_sig.as_ref().is_some_and(|sig| {
            crate::mandate::verify_sig(
                &self.agent.public_key(),
                &offer.auth_message(&self.agent.mandate_id()),
                sig,
            )
        });
        if !issued_by_me
            || offer.seller_node != self.node
            || offer.backend_id != self.backend.backend_id()
            || offer.job_id != self.job.job_id()
            || offer.spec_hash != self.job.spec_hash()
        {
            return Err(PcpError::OfferMismatch);
        }
        if req.mandate.is_none() {
            return Err(PcpError::CounterpartyMandate(MandateError::Missing));
        }
        Ok(())
    }

    /// Prove an accepted offer: check the result, pick a fresh `k`, encrypt,
    /// prove. Records the sale with `k` before any invoice exists, so save
    /// a snapshot after this call and before [`Seller::invoice`]. Refusals
    /// are logged and close the offer.
    pub fn prove<R: RngCore + CryptoRng>(
        &mut self,
        offer_id: &Hash32,
        result: Vec<u8>,
        now: u64,
        rng: &mut R,
    ) -> Result<(), PcpError> {
        let Some(issued) = self.offers.get(offer_id) else {
            return Err(PcpError::OfferNotIssued);
        };
        if issued.stage != OfferStage::Accepted {
            return Err(PcpError::WrongState("prove needs an accepted offer"));
        }
        let req = issued.request.clone();
        let offer = issued.offer.clone();
        let r = self.prove_inner(&req, &offer, result, now, rng);
        match r {
            Ok(h) => {
                self.offers.get_mut(offer_id).expect("present").stage =
                    OfferStage::Proven { payment_hash: h };
                Ok(())
            }
            Err(e) => {
                let cp = req.mandate.as_ref().map(|m| m.agent_key);
                self.agent.record_refusal(*offer_id, cp, &e, now);
                self.close_offer(offer_id, &e);
                Err(e)
            }
        }
    }

    fn prove_inner<R: RngCore + CryptoRng>(
        &mut self,
        req: &Request,
        offer: &Offer,
        result: Vec<u8>,
        now: u64,
        rng: &mut R,
    ) -> Result<Hash32, PcpError> {
        let Some(buyer_mandate) = req.mandate.clone() else {
            return Err(PcpError::CounterpartyMandate(MandateError::Missing));
        };
        // SPEC: the offer is void after offer_expires_at. Do not start (and,
        // in `invoice`, do not invoice) on a void offer.
        if now >= offer.offer_expires_at {
            return Err(PcpError::OfferExpired);
        }
        if !self.job.check(&req.input, &result) {
            return Err(PcpError::SellerResultInvalid);
        }
        let offer_id = offer.offer_id();
        let key = crypto::fresh_key(rng);
        let h = crypto::payment_hash(&key);
        let ciphertext = crypto::encrypt(&key, &offer_id, &result);
        let statement = build_statement(
            self.job.as_ref(),
            offer.input_commitment,
            offer_id,
            offer.buyer_nonce,
            &ciphertext,
            h,
        );
        let witness = Witness {
            input: req.input.clone(),
            result,
            key,
        };
        let bundle = self
            .backend
            .prove(self.job.as_ref(), &statement, &ciphertext, &witness)
            .map_err(PcpError::ProveFailed)?;
        self.sales.insert(
            h,
            SaleRecord {
                key,
                price_msat: offer.price_msat,
                settled: false,
                settled_msat: 0,
                closed: false,
                offer_id,
                bundle,
                invoice: None,
                input: req.input.clone(),
                buyer_mandate,
            },
        );
        Ok(h)
    }

    /// Create the invoice to `H` for a proven offer, payable to the
    /// principal's payout node, and return what to send the buyer. After a
    /// restart, an invoice the node already issued for `H` is found and
    /// reused (a second invoice to the same hash is refused). Refuses, and
    /// closes the sale, if the offer expired before an invoice existed.
    pub fn invoice(
        &mut self,
        offer_id: &Hash32,
        rail: &mut dyn Rail,
    ) -> Result<(ProofBundle, InvoiceBinding), PcpError> {
        let Some(issued) = self.offers.get(offer_id) else {
            return Err(PcpError::OfferNotIssued);
        };
        let h = match &issued.stage {
            OfferStage::Proven { payment_hash } | OfferStage::Invoiced { payment_hash } => {
                *payment_hash
            }
            _ => return Err(PcpError::WrongState("invoice needs a proven offer")),
        };
        let offer = issued.offer.clone();
        let cp = issued.request.mandate.as_ref().map(|m| m.agent_key);
        let sale = self.sales.get(&h).expect("a proven offer has a sale");
        if let Some(b) = sale.binding() {
            return Ok((sale.bundle.clone(), b));
        }
        if rail.rail_id() != offer.rail {
            return Err(PcpError::RailNotSupported);
        }
        let want = InvoiceRequest {
            payee: self.node.clone(),
            payment_hash: h,
            amount_msat: offer.price_msat,
            description_hash: sale.statement_hash(),
            expiry_secs: self.cfg.invoice_expiry_secs,
            min_htlc_secs: self.cfg.min_htlc_secs,
        };
        let found = match rail.find_invoice(&h)? {
            Some(inv) => Some(inv),
            None => {
                // Proving can take minutes: the offer may have lapsed.
                let now = rail.now();
                if now >= offer.offer_expires_at {
                    let e = PcpError::OfferExpired;
                    self.agent.record_refusal(*offer_id, cp, &e, now);
                    self.close_offer(offer_id, &e);
                    if let Some(s) = self.sales.get_mut(&h) {
                        s.closed = true;
                    }
                    return Err(e);
                }
                match rail.create_invoice(&want) {
                    Ok(inv) => Some(inv),
                    // The create may have reached the node although the call
                    // failed: look before giving up.
                    Err(e) => match rail.find_invoice(&h) {
                        Ok(Some(inv)) => Some(inv),
                        _ => return Err(e.into()),
                    },
                }
            }
        };
        let inv = found.expect("set above");
        if inv.payment_hash != h
            || inv.amount_msat != want.amount_msat
            || inv.description_hash != want.description_hash
            || inv.payee != self.node
        {
            return Err(PcpError::Rail(RailError::InvoiceMismatch("found invoice")));
        }
        let sale = self.sales.get_mut(&h).expect("present");
        sale.invoice = Some(inv);
        let out = (
            sale.bundle.clone(),
            sale.binding().expect("invoice just set"),
        );
        self.offers.get_mut(offer_id).expect("present").stage =
            OfferStage::Invoiced { payment_hash: h };
        Ok(out)
    }

    /// Test hook: the key of an open sale, to simulate a settle that reached
    /// the node while its reply was lost.
    #[cfg(test)]
    pub(crate) fn sale_key_for_test(&self, h: &Hash32) -> Option<[u8; 32]> {
        self.sales.get(h).map(|s| s.key)
    }

    /// Settle every open sale whose HTLC is locked for the full price with
    /// enough time left. This is the only place `k` ever leaves the seller.
    /// Each settlement appends a signed receipt to the principal's log.
    pub fn settle_paid(&mut self, rail: &mut dyn Rail) -> Vec<SaleOutcome> {
        let now = rail.now();
        let mut out = Vec::new();
        for (h, sale) in self
            .sales
            .iter_mut()
            .filter(|(_, s)| !s.settled && !s.closed && s.invoice.is_some())
        {
            let invoice_expires_at = sale.invoice.as_ref().map_or(0, |i| i.expires_at());
            let htlc = match rail.lookup_invoice(h) {
                Ok(Some(htlc)) => htlc,
                // No HTLC held. Once the invoice has expired none can arrive
                // any more (a refunded HTLC also reads as none), so the sale
                // is over.
                Ok(None) if now >= invoice_expires_at => {
                    // Also cancel the invoice at the node, so an HTLC that
                    // arrives late is refused at once instead of being held
                    // by a seller that no longer looks. Usually there is
                    // nothing to cancel; that is not an error here.
                    let _ = rail.cancel_invoice(&self.node, h);
                    out.push(close_sale(
                        &self.agent,
                        h,
                        sale,
                        PcpError::InvoiceExpired,
                        now,
                    ));
                    continue;
                }
                Ok(None) => {
                    out.push(SaleOutcome::NotPaid { payment_hash: *h });
                    continue;
                }
                Err(e) => {
                    out.push(SaleOutcome::Withheld {
                        payment_hash: *h,
                        reason: e.into(),
                    });
                    continue;
                }
            };
            if htlc.payee != self.node {
                out.push(SaleOutcome::NotPaid { payment_hash: *h });
                continue;
            }
            match htlc.state {
                IncomingState::Held => {}
                // Only this seller holds `k`, so a settled HTLC means an
                // earlier settle reached the node even though its reply was
                // lost. Record the sale now instead of losing the receipt.
                IncomingState::Settled => {
                    out.push(finish_sale(&self.agent, h, sale, htlc.amount_msat, now));
                    continue;
                }
                IncomingState::Canceled => {
                    out.push(close_sale(&self.agent, h, sale, PcpError::Refunded, now));
                    continue;
                }
            }
            // Reasons that can never clear for this HTLC: cancel it so the
            // buyer's funds come back now, not at the HTLC timeout. The cap
            // only grows, so a cap the HTLC would exceed never clears either.
            let permanent = if htlc.amount_msat < sale.price_msat {
                Some(PcpError::InvoiceAmountMismatch {
                    invoice: htlc.amount_msat,
                    offer: sale.price_msat,
                })
            } else if htlc.timeout_at.saturating_sub(now) < self.cfg.settle_margin_secs {
                Some(PcpError::SettleMarginTooShort)
            } else if let Err(e) = self.agent.check_budget(htlc.amount_msat, now) {
                Some(PcpError::OwnMandate(e))
            } else {
                None
            };
            if let Some(reason) = permanent {
                // If the cancel call fails the HTLC is still held: report it
                // as withheld and try the cancel again on the next pass.
                match rail.cancel_invoice(&self.node, h) {
                    Ok(()) => out.push(close_sale(&self.agent, h, sale, reason, now)),
                    Err(e) => out.push(SaleOutcome::Withheld {
                        payment_hash: *h,
                        reason: e.into(),
                    }),
                }
                continue;
            }
            match rail.settle_invoice(&self.node, h, sale.key) {
                Ok(()) => out.push(finish_sale(&self.agent, h, sale, htlc.amount_msat, now)),
                Err(e) => {
                    // The settle may have reached the node although the call
                    // failed (a lost reply). Look before reporting failure.
                    let settled = matches!(
                        rail.lookup_invoice(h),
                        Ok(Some(x)) if x.state == IncomingState::Settled
                    );
                    if settled {
                        out.push(finish_sale(&self.agent, h, sale, htlc.amount_msat, now));
                    } else {
                        out.push(SaleOutcome::Withheld {
                            payment_hash: *h,
                            reason: e.into(),
                        });
                    }
                }
            }
        }
        out
    }
}

/// End a sale without payment: mark it closed and log the reason as a
/// refusal about the offer.
fn close_sale(
    agent: &Agent,
    h: &Hash32,
    sale: &mut SaleRecord,
    reason: PcpError,
    at: u64,
) -> SaleOutcome {
    sale.closed = true;
    agent.record_refusal(
        sale.offer_id,
        Some(sale.buyer_mandate.agent_key),
        &reason,
        at,
    );
    SaleOutcome::Cancelled {
        payment_hash: *h,
        reason,
    }
}

/// Mark a sale settled, commit its amount against the seller's cap, and
/// append the signed receipt to the principal's log.
fn finish_sale(
    agent: &Agent,
    h: &Hash32,
    sale: &mut SaleRecord,
    amount_msat: u64,
    at: u64,
) -> SaleOutcome {
    sale.settled = true;
    sale.settled_msat = amount_msat;
    agent.commit(amount_msat);
    agent.record_deal(
        Receipt {
            version: VERSION.to_string(),
            role: Role::Seller,
            mandate_id: [0u8; 32],
            principal_key: [0u8; 32],
            counterparty_mandate_id: sale.buyer_mandate.mandate_id(),
            counterparty_principal_key: sale.buyer_mandate.principal_key,
            agent_key: [0u8; 32],
            offer_id: sale.offer_id,
            statement_hash: sale.statement_hash(),
            bundle_id: sale.bundle.bundle_id(),
            payment_hash: *h,
            preimage: sale.key,
            amount_msat,
            settled_at: at,
            agent_sig: Sig([0u8; 64]),
        },
        &sale.bundle,
        &sale.input,
    );
    SaleOutcome::Settled {
        payment_hash: *h,
        amount_msat,
    }
}
