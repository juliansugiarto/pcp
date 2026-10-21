//! Settlement rails (SPEC.md section 8): the one interface the protocol
//! uses to invoice, pay, settle and look up payments to `H`.
//!
//! Two implementations:
//!
//! - [`Ledger`], the in-memory HTLC simulation (`lightning-htlc-sim/0`),
//!   used by the tests and the demo;
//! - `lnd::LndRail` (feature `lnd`), a client for one LND node's REST API
//!   using hold invoices (`lightning-bolt11/0`). Not exercised in tests.
//!
//! A rail is the payer's or payee's own view of the network. It is not a
//! protocol party: it can delay or fail a payment, but it cannot settle one
//! without the preimage `k`.
//!
//! Node arguments: the simulated ledger holds every node, so each call
//! names the node it acts for. An LND rail is one node and refuses calls for
//! any other node id.

use crate::encoding::Hash32;
use crate::lightning::{HtlcState, Invoice, Ledger, LedgerError};

/// Rail identifier of the simulated ledger.
pub const RAIL_SIM: &str = "lightning-htlc-sim/0";
/// Rail identifier of real Lightning (BOLT11 invoices).
pub const RAIL_BOLT11: &str = "lightning-bolt11/0";

/// What a payee asks the rail to invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceRequest {
    /// The node that will be paid. In PCP: the seller principal's payout node.
    pub payee: String,
    /// `H`. The rail must not learn `k` before settlement, so this is a
    /// hold invoice on real Lightning.
    pub payment_hash: Hash32,
    pub amount_msat: u64,
    /// BOLT11 `h` tag. In PCP: `statement_hash`.
    pub description_hash: Hash32,
    /// Seconds the invoice stays payable.
    pub expiry_secs: u64,
    /// Minimum HTLC lock the payee asks for (BOLT11 `min_final_cltv_expiry`,
    /// in seconds; 600 s per block on a real chain).
    pub min_htlc_secs: u64,
}

/// An HTLC paying an invoice, as the payee's node sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingHtlc {
    /// The node the HTLC pays.
    pub payee: String,
    pub amount_msat: u64,
    /// Absolute time (rail clock) at and after which `k` is no longer
    /// accepted and the HTLC can only be refunded.
    pub timeout_at: u64,
    pub state: IncomingState,
}

/// State of an incoming HTLC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncomingState {
    /// Locked and held, waiting for the preimage (LND: invoice `ACCEPTED`).
    Held,
    /// Settled with the preimage.
    Settled,
    /// Refunded, timed out or cancelled.
    Canceled,
}

/// An outgoing payment, as the payer's node sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentStatus {
    /// No payment to this hash from this node.
    Unknown,
    /// HTLC locked, preimage not yet revealed.
    InFlight,
    /// Settled: the preimage came back.
    Settled { preimage: [u8; 32], at: u64 },
    /// Failed or refunded; funds are back with the payer.
    Failed { at: u64 },
}

/// Rail errors. The simulated ledger's errors are kept as they are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RailError {
    /// From the simulated ledger.
    Ledger(LedgerError),
    /// The call names a node this rail does not control.
    NotThisNode,
    /// The invoice presented does not match what the payee's node issued
    /// (on real Lightning: the BOLT11 string decodes to other terms).
    InvoiceMismatch(&'static str),
    /// The invoice has no BOLT11 string (real rail) or a malformed one.
    InvoiceMissing,
    /// Transport or node error (real rail).
    Node(String),
}

impl From<LedgerError> for RailError {
    fn from(e: LedgerError) -> Self {
        RailError::Ledger(e)
    }
}

/// The settlement interface the protocol state machines use.
pub trait Rail {
    /// `"lightning-htlc-sim/0"` or `"lightning-bolt11/0"`; carried in offers.
    fn rail_id(&self) -> &'static str;

    /// The rail's clock in seconds (manual on the simulation, Unix time on a
    /// real node).
    fn now(&self) -> u64;

    /// Payee: create an invoice to `payment_hash`. The payee's node must not
    /// settle it by itself: settlement happens only through
    /// [`Rail::settle_invoice`]. Reusing a payment hash is refused.
    fn create_invoice(&mut self, req: &InvoiceRequest) -> Result<Invoice, RailError>;

    /// Payer: pay `invoice` from node `payer`, locking the HTLC for at most
    /// `max_htlc_secs`. Returns once the HTLC is locked (or the payment has
    /// failed); it does not wait for settlement. The rail refuses an
    /// invoice that differs from what the payee's node issued.
    fn pay_invoice(
        &mut self,
        payer: &str,
        invoice: &Invoice,
        max_htlc_secs: u64,
    ) -> Result<(), RailError>;

    /// Payee: settle the held HTLC paying `payment_hash` by revealing
    /// `preimage`. This is the only way `k` leaves the seller.
    fn settle_invoice(
        &mut self,
        payee: &str,
        payment_hash: &Hash32,
        preimage: [u8; 32],
    ) -> Result<(), RailError>;

    /// Payee: the live or settled HTLC paying `payment_hash`, if any.
    fn lookup_invoice(&mut self, payment_hash: &Hash32) -> Result<Option<IncomingHtlc>, RailError>;

    /// Payer: the status of the latest payment from `payer` to `payment_hash`.
    fn lookup_payment(
        &mut self,
        payer: &str,
        payment_hash: &Hash32,
    ) -> Result<PaymentStatus, RailError>;
}

impl Rail for Ledger {
    fn rail_id(&self) -> &'static str {
        RAIL_SIM
    }

    fn now(&self) -> u64 {
        Ledger::now(self)
    }

    fn create_invoice(&mut self, req: &InvoiceRequest) -> Result<Invoice, RailError> {
        Ok(Ledger::create_invoice(
            self,
            &req.payee,
            req.payment_hash,
            req.amount_msat,
            req.expiry_secs,
            req.min_htlc_secs,
            req.description_hash,
        )?)
    }

    fn pay_invoice(
        &mut self,
        payer: &str,
        invoice: &Invoice,
        max_htlc_secs: u64,
    ) -> Result<(), RailError> {
        Ledger::pay(self, payer, invoice, max_htlc_secs)?;
        Ok(())
    }

    fn settle_invoice(
        &mut self,
        payee: &str,
        payment_hash: &Hash32,
        preimage: [u8; 32],
    ) -> Result<(), RailError> {
        let id = self
            .htlc_for(payment_hash)
            .ok_or(LedgerError::UnknownHtlc)?
            .id;
        Ok(Ledger::settle(self, payee, id, preimage)?)
    }

    fn lookup_invoice(&mut self, payment_hash: &Hash32) -> Result<Option<IncomingHtlc>, RailError> {
        Ok(self.htlc_for(payment_hash).map(|h| IncomingHtlc {
            payee: h.payee.clone(),
            amount_msat: h.amount_msat,
            timeout_at: h.timeout_at,
            state: match h.state {
                HtlcState::Locked => IncomingState::Held,
                HtlcState::Settled { .. } => IncomingState::Settled,
                HtlcState::Refunded { .. } => IncomingState::Canceled,
            },
        }))
    }

    fn lookup_payment(
        &mut self,
        payer: &str,
        payment_hash: &Hash32,
    ) -> Result<PaymentStatus, RailError> {
        // Anyone may return timed-out HTLCs to their payers; the payer's
        // node does it when it looks.
        self.refund_expired();
        Ok(match self.latest_htlc(payer, payment_hash) {
            None => PaymentStatus::Unknown,
            Some(h) => match h.state {
                HtlcState::Locked => PaymentStatus::InFlight,
                HtlcState::Settled { preimage, at } => PaymentStatus::Settled { preimage, at },
                HtlcState::Refunded { at } => PaymentStatus::Failed { at },
            },
        })
    }
}

#[cfg(feature = "lnd")]
pub mod lnd;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::sha256;

    fn req(payee: &str, k: &[u8; 32]) -> InvoiceRequest {
        InvoiceRequest {
            payee: payee.into(),
            payment_hash: sha256(k),
            amount_msat: 1_000,
            description_hash: [9u8; 32],
            expiry_secs: 600,
            min_htlc_secs: 60,
        }
    }

    #[test]
    fn ledger_is_a_rail() {
        let mut l = Ledger::new();
        l.open_node("alice", 10_000);
        l.open_node("bob", 0);
        let k = [42u8; 32];
        let h = sha256(&k);
        let rail: &mut dyn Rail = &mut l;
        assert_eq!(rail.rail_id(), RAIL_SIM);
        let inv = rail.create_invoice(&req("bob", &k)).unwrap();
        assert_eq!(inv.description_hash, [9u8; 32]);
        assert_eq!(
            rail.create_invoice(&req("bob", &k)),
            Err(RailError::Ledger(LedgerError::DuplicatePaymentHash))
        );
        assert_eq!(rail.lookup_invoice(&h), Ok(None));
        assert_eq!(rail.lookup_payment("alice", &h), Ok(PaymentStatus::Unknown));
        rail.pay_invoice("alice", &inv, 3600).unwrap();
        let held = rail.lookup_invoice(&h).unwrap().unwrap();
        assert_eq!(held.state, IncomingState::Held);
        assert_eq!((held.payee.as_str(), held.amount_msat), ("bob", 1_000));
        assert_eq!(
            rail.lookup_payment("alice", &h),
            Ok(PaymentStatus::InFlight)
        );
        assert_eq!(
            rail.settle_invoice("bob", &h, [1u8; 32]),
            Err(RailError::Ledger(LedgerError::PreimageMismatch))
        );
        rail.settle_invoice("bob", &h, k).unwrap();
        assert_eq!(
            rail.lookup_payment("alice", &h),
            Ok(PaymentStatus::Settled { preimage: k, at: 0 })
        );
        assert_eq!(
            rail.lookup_invoice(&h).unwrap().unwrap().state,
            IncomingState::Settled
        );
        assert_eq!(l.balance("bob"), 1_000);
    }

    #[test]
    fn ledger_rail_refunds_on_lookup_after_timeout() {
        let mut l = Ledger::new();
        l.open_node("alice", 10_000);
        l.open_node("bob", 0);
        let k = [42u8; 32];
        let h = sha256(&k);
        let inv = Rail::create_invoice(&mut l, &req("bob", &k)).unwrap();
        l.pay_invoice("alice", &inv, 3600).unwrap();
        l.advance(3600);
        assert_eq!(
            l.lookup_payment("alice", &h),
            Ok(PaymentStatus::Failed { at: 3600 })
        );
        assert_eq!(l.balance("alice"), 10_000);
        assert_eq!(l.lookup_invoice(&h), Ok(None));
        assert_eq!(
            l.settle_invoice("bob", &h, k),
            Err(RailError::Ledger(LedgerError::UnknownHtlc))
        );
    }
}
