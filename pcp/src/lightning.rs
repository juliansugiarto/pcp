//! A simulated Lightning HTLC ledger (SPEC.md section 8). No network.
//!
//! The ledger stands for "the Lightning network plus the two parties' nodes".
//! It is **not** a third party in the protocol: it models only what an HTLC
//! enforces, which is
//!
//! 1. funds locked by the payer can move to the payee **only** if the payee
//!    presents `k` with `SHA256(k) = payment_hash` before the timeout;
//! 2. presenting `k` makes `k` known to the payer (in real Lightning the
//!    preimage travels back along the route as the proof of payment);
//! 3. after the timeout, locked funds return to the payer and `k` is no
//!    longer accepted.
//!
//! Points 1 and 2 happen in one step, which is the atomicity PCP relies on:
//! no payment without `k`, no `k` (through the ledger) without payment.
//!
//! Nodes belong to principals, never to agents: a node may be opened with
//! the principal key that owns it ([`Ledger::open_principal_node`]), and
//! [`Ledger::principal_balance`] sums what a principal holds. In PCP the
//! seller's invoices pay the payout node named in the seller's mandate, and
//! the buyer pays from the node named in the buyer's mandate, so every
//! balance change lands on a principal.
//!
//! Time is a manual clock in seconds (`advance`). Invoices are not signed in
//! the simulation; BOLT11 invoices are, by the payee node's key (SPEC 8.1).
//!
//! The protocol talks to the ledger through the [`crate::rail::Rail`] trait,
//! which a real LND node also implements (feature `lnd`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::encoding::{hex32, sha256, Hash32};

/// A node identifier (a public key in real Lightning; a name here).
pub type NodeId = String;

/// A simulated BOLT11 invoice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invoice {
    /// The node that will be paid (and that signs a real invoice).
    pub payee: NodeId,
    /// Payment hash. In PCP this must equal the statement's `H`.
    #[serde(with = "hex32")]
    pub payment_hash: Hash32,
    /// Amount in millisatoshi.
    pub amount_msat: u64,
    /// Creation time (ledger clock, seconds).
    pub created_at: u64,
    /// Seconds after `created_at` during which the invoice may be paid.
    pub expiry_secs: u64,
    /// Minimum HTLC lock time the payee asks for (seconds; stands in for
    /// `min_final_cltv_expiry_delta`).
    pub min_htlc_secs: u64,
    /// BOLT11 `h` tag. In PCP: the `statement_hash` the invoice is for.
    #[serde(with = "hex32")]
    pub description_hash: Hash32,
    /// The BOLT11 string, on the real rail (`lightning-bolt11/0`). The
    /// fields above are then what the payer's own node decodes from it, and
    /// the payer's rail refuses to pay a string that decodes to anything
    /// else. Absent on the simulated rail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bolt11: Option<String>,
}

impl Invoice {
    /// Absolute time after which the invoice may no longer be paid.
    pub fn expires_at(&self) -> u64 {
        self.created_at.saturating_add(self.expiry_secs)
    }
}

/// Identifier of an HTLC on the ledger.
pub type HtlcId = u64;

/// State of an HTLC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HtlcState {
    /// Funds locked, waiting for the preimage or the timeout.
    Locked,
    /// Settled with this preimage; funds moved to the payee.
    Settled {
        #[serde(with = "hex32")]
        preimage: [u8; 32],
        at: u64,
    },
    /// Timed out; funds returned to the payer.
    Refunded { at: u64 },
}

/// A hash-time-locked contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Htlc {
    pub id: HtlcId,
    pub payer: NodeId,
    pub payee: NodeId,
    #[serde(with = "hex32")]
    pub payment_hash: Hash32,
    pub amount_msat: u64,
    /// Absolute time at and after which the HTLC can only be refunded.
    pub timeout_at: u64,
    pub state: HtlcState,
}

/// Ledger errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    UnknownNode,
    UnknownInvoice,
    /// An invoice for this payment hash already exists (hash reuse).
    DuplicatePaymentHash,
    /// The invoice presented differs from the one the payee registered.
    InvoiceTampered,
    InvoiceExpired,
    /// The invoice already has a live or settled HTLC.
    AlreadyPaid,
    InsufficientFunds,
    /// HTLC lock time below the invoice's `min_htlc_secs`.
    HtlcTooShort,
    UnknownHtlc,
    /// Only the HTLC's payee can settle it.
    NotPayee,
    /// The HTLC is not in the `Locked` state.
    NotLocked,
    /// The HTLC has timed out; the preimage is no longer accepted.
    HtlcExpired,
    /// `SHA256(preimage) != payment_hash`. Funds stay locked.
    PreimageMismatch,
    /// Refund requested before the timeout.
    NotYetExpired,
}

mod invoice_list {
    use super::{BTreeMap, Hash32, Invoice};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        m: &BTreeMap<Hash32, Invoice>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        m.values().collect::<Vec<_>>().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<Hash32, Invoice>, D::Error> {
        Ok(Vec::<Invoice>::deserialize(d)?
            .into_iter()
            .map(|i| (i.payment_hash, i))
            .collect())
    }
}

/// The simulated network. Serialisable so that two processes can share one
/// simulated network through a file (`node::sim_file`, tests only).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    now: u64,
    balances: BTreeMap<NodeId, u64>,
    owners: BTreeMap<NodeId, Hash32>,
    /// Keyed by payment hash; saved as a list (JSON keys are strings).
    #[serde(with = "invoice_list")]
    invoices: BTreeMap<Hash32, Invoice>,
    htlcs: BTreeMap<HtlcId, Htlc>,
    next_id: HtlcId,
}

impl Ledger {
    /// Empty ledger at time 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a node with a starting balance (stands in for channel liquidity).
    pub fn open_node(&mut self, node: &str, balance_msat: u64) {
        self.balances.insert(node.to_string(), balance_msat);
    }

    /// Open a node owned by a principal (identified by its public key).
    pub fn open_principal_node(&mut self, node: &str, principal_key: Hash32, balance_msat: u64) {
        self.open_node(node, balance_msat);
        self.owners.insert(node.to_string(), principal_key);
    }

    /// The principal that owns a node, if declared.
    pub fn owner(&self, node: &str) -> Option<Hash32> {
        self.owners.get(node).copied()
    }

    /// Total spendable balance of every node a principal owns.
    pub fn principal_balance(&self, principal_key: &Hash32) -> u64 {
        self.owners
            .iter()
            .filter(|(_, k)| *k == principal_key)
            .map(|(n, _)| self.balance(n))
            .sum()
    }

    /// Current clock.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Advance the clock.
    pub fn advance(&mut self, secs: u64) {
        self.now = self.now.saturating_add(secs);
    }

    /// Spendable balance of a node.
    pub fn balance(&self, node: &str) -> u64 {
        self.balances.get(node).copied().unwrap_or(0)
    }

    /// Payee creates an invoice. Reusing a payment hash is refused.
    pub fn create_invoice(
        &mut self,
        payee: &str,
        payment_hash: Hash32,
        amount_msat: u64,
        expiry_secs: u64,
        min_htlc_secs: u64,
        description_hash: Hash32,
    ) -> Result<Invoice, LedgerError> {
        if !self.balances.contains_key(payee) {
            return Err(LedgerError::UnknownNode);
        }
        if self.invoices.contains_key(&payment_hash) {
            return Err(LedgerError::DuplicatePaymentHash);
        }
        let inv = Invoice {
            payee: payee.to_string(),
            payment_hash,
            amount_msat,
            created_at: self.now,
            expiry_secs,
            min_htlc_secs,
            description_hash,
            bolt11: None,
        };
        self.invoices.insert(payment_hash, inv.clone());
        Ok(inv)
    }

    /// Payer pays an invoice: locks `amount_msat` in an HTLC that times out
    /// `htlc_secs` from now.
    pub fn pay(
        &mut self,
        payer: &str,
        invoice: &Invoice,
        htlc_secs: u64,
    ) -> Result<HtlcId, LedgerError> {
        let registered = self
            .invoices
            .get(&invoice.payment_hash)
            .ok_or(LedgerError::UnknownInvoice)?;
        if registered != invoice {
            return Err(LedgerError::InvoiceTampered);
        }
        if self.now >= invoice.expires_at() {
            return Err(LedgerError::InvoiceExpired);
        }
        if htlc_secs < invoice.min_htlc_secs {
            return Err(LedgerError::HtlcTooShort);
        }
        if self.htlcs.values().any(|h| {
            h.payment_hash == invoice.payment_hash && !matches!(h.state, HtlcState::Refunded { .. })
        }) {
            return Err(LedgerError::AlreadyPaid);
        }
        let bal = self
            .balances
            .get_mut(payer)
            .ok_or(LedgerError::UnknownNode)?;
        if *bal < invoice.amount_msat {
            return Err(LedgerError::InsufficientFunds);
        }
        *bal -= invoice.amount_msat;
        let id = self.next_id;
        self.next_id += 1;
        self.htlcs.insert(
            id,
            Htlc {
                id,
                payer: payer.to_string(),
                payee: invoice.payee.clone(),
                payment_hash: invoice.payment_hash,
                amount_msat: invoice.amount_msat,
                timeout_at: self.now.saturating_add(htlc_secs),
                state: HtlcState::Locked,
            },
        );
        Ok(id)
    }

    /// Payee settles by revealing the preimage. Atomic: on success the funds
    /// move and the preimage becomes visible to the payer in one step; on
    /// any failure nothing changes and the preimage is not recorded.
    pub fn settle(
        &mut self,
        payee: &str,
        id: HtlcId,
        preimage: [u8; 32],
    ) -> Result<(), LedgerError> {
        let now = self.now;
        let h = self.htlcs.get_mut(&id).ok_or(LedgerError::UnknownHtlc)?;
        if h.payee != payee {
            return Err(LedgerError::NotPayee);
        }
        if h.state != HtlcState::Locked {
            return Err(LedgerError::NotLocked);
        }
        if now >= h.timeout_at {
            return Err(LedgerError::HtlcExpired);
        }
        if sha256(&preimage) != h.payment_hash {
            return Err(LedgerError::PreimageMismatch);
        }
        h.state = HtlcState::Settled { preimage, at: now };
        let (to, amt) = (h.payee.clone(), h.amount_msat);
        *self.balances.entry(to).or_insert(0) += amt;
        Ok(())
    }

    /// Payee cancels the locked HTLC paying `payment_hash`: the funds go back
    /// to the payer now instead of at timeout (LND: CancelInvoice on a hold
    /// invoice). The preimage is never involved.
    pub fn cancel(&mut self, payee: &str, payment_hash: &Hash32) -> Result<(), LedgerError> {
        let now = self.now;
        let h = self
            .htlcs
            .values_mut()
            .find(|h| h.payment_hash == *payment_hash && h.state == HtlcState::Locked)
            .ok_or(LedgerError::UnknownHtlc)?;
        if h.payee != payee {
            return Err(LedgerError::NotPayee);
        }
        h.state = HtlcState::Refunded { at: now };
        *self.balances.entry(h.payer.clone()).or_insert(0) += h.amount_msat;
        Ok(())
    }

    /// Return every timed-out `Locked` HTLC to its payer. Returns the ids
    /// refunded. Anyone may call this; it only ever moves funds back.
    pub fn refund_expired(&mut self) -> Vec<HtlcId> {
        let now = self.now;
        let mut done = Vec::new();
        for h in self.htlcs.values_mut() {
            if h.state == HtlcState::Locked && now >= h.timeout_at {
                h.state = HtlcState::Refunded { at: now };
                *self.balances.entry(h.payer.clone()).or_insert(0) += h.amount_msat;
                done.push(h.id);
            }
        }
        done
    }

    /// Look up an HTLC (both parties can see its state, including the
    /// preimage once settled).
    pub fn htlc(&self, id: HtlcId) -> Option<&Htlc> {
        self.htlcs.get(&id)
    }

    /// The most recent HTLC from `payer` to a given hash, in any state
    /// (what the payer's node sees about its own payment).
    pub fn latest_htlc(&self, payer: &str, payment_hash: &Hash32) -> Option<&Htlc> {
        self.htlcs
            .values()
            .rev()
            .find(|h| h.payer == payer && h.payment_hash == *payment_hash)
    }

    /// The invoice issued to a payment hash, if any.
    pub fn invoice(&self, payment_hash: &Hash32) -> Option<&Invoice> {
        self.invoices.get(payment_hash)
    }

    /// Find the live or settled HTLC paying a given hash, if any (what the
    /// payee's node sees when a payment arrives).
    pub fn htlc_for(&self, payment_hash: &Hash32) -> Option<&Htlc> {
        self.htlcs.values().find(|h| {
            h.payment_hash == *payment_hash && !matches!(h.state, HtlcState::Refunded { .. })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Ledger, [u8; 32], Invoice) {
        let mut l = Ledger::new();
        l.open_node("alice", 10_000);
        l.open_node("bob", 0);
        let k = [42u8; 32];
        let inv = l
            .create_invoice("bob", sha256(&k), 1_000, 600, 60, [0u8; 32])
            .unwrap();
        (l, k, inv)
    }

    #[test]
    fn happy_settle_is_atomic() {
        let (mut l, k, inv) = setup();
        let id = l.pay("alice", &inv, 3600).unwrap();
        assert_eq!(l.balance("alice"), 9_000);
        assert_eq!(l.balance("bob"), 0, "locked, not yet paid");
        l.settle("bob", id, k).unwrap();
        assert_eq!(l.balance("bob"), 1_000);
        assert!(
            matches!(l.htlc(id).unwrap().state, HtlcState::Settled { preimage, .. } if preimage == k)
        );
        assert_eq!(
            l.settle("bob", id, k),
            Err(LedgerError::NotLocked),
            "no double settle"
        );
    }

    #[test]
    fn wrong_preimage_changes_nothing() {
        let (mut l, _k, inv) = setup();
        let id = l.pay("alice", &inv, 3600).unwrap();
        assert_eq!(
            l.settle("bob", id, [1u8; 32]),
            Err(LedgerError::PreimageMismatch)
        );
        assert_eq!(l.htlc(id).unwrap().state, HtlcState::Locked);
        assert_eq!(l.balance("bob"), 0);
    }

    #[test]
    fn timeout_refunds_and_blocks_late_preimage() {
        let (mut l, k, inv) = setup();
        let id = l.pay("alice", &inv, 3600).unwrap();
        l.advance(3600);
        assert_eq!(l.settle("bob", id, k), Err(LedgerError::HtlcExpired));
        assert_eq!(l.refund_expired(), vec![id]);
        assert_eq!(l.balance("alice"), 10_000);
        assert_eq!(l.balance("bob"), 0);
    }

    #[test]
    fn balances_accrue_to_principals() {
        let mut l = Ledger::new();
        let (p, q) = ([1u8; 32], [2u8; 32]);
        l.open_principal_node("p-node", p, 10_000);
        l.open_principal_node("q-node", q, 0);
        l.open_principal_node("q-node-2", q, 5);
        let k = [42u8; 32];
        let inv = l
            .create_invoice("q-node", sha256(&k), 1_000, 600, 60, [0u8; 32])
            .unwrap();
        let id = l.pay("p-node", &inv, 3600).unwrap();
        l.settle("q-node", id, k).unwrap();
        assert_eq!(l.principal_balance(&p), 9_000);
        assert_eq!(l.principal_balance(&q), 1_005);
        assert_eq!(l.owner("q-node"), Some(q));
        assert_eq!(l.owner("nobody"), None);
    }

    #[test]
    fn invoice_rules() {
        let (mut l, _k, inv) = setup();
        assert_eq!(
            l.create_invoice("bob", inv.payment_hash, 5, 600, 60, [0u8; 32]),
            Err(LedgerError::DuplicatePaymentHash)
        );
        assert_eq!(l.pay("alice", &inv, 10), Err(LedgerError::HtlcTooShort));
        let mut forged = inv.clone();
        forged.amount_msat = 1;
        assert_eq!(
            l.pay("alice", &forged, 3600),
            Err(LedgerError::InvoiceTampered)
        );
        l.advance(600);
        assert_eq!(l.pay("alice", &inv, 3600), Err(LedgerError::InvoiceExpired));
    }
}

#[cfg(test)]
mod serde_tests {
    use super::*;

    #[test]
    fn ledger_round_trips_through_json() {
        let mut l = Ledger::new();
        l.open_principal_node("alice", [1u8; 32], 10_000);
        l.open_node("bob", 0);
        let k = [42u8; 32];
        let inv = l
            .create_invoice("bob", sha256(&k), 1_000, 600, 60, [9u8; 32])
            .unwrap();
        l.pay("alice", &inv, 3600).unwrap();
        l.advance(7);
        let back: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(format!("{back:?}"), format!("{l:?}"));
    }
}
