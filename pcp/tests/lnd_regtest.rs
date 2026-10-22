//! The LND rail against two real LND nodes on regtest (feature `lnd`).
//!
//! Every test here is `#[ignore]`: they need the six variables that
//! `lnd_sale` reads (`PCP_BUYER_LND_*`, `PCP_SELLER_LND_*`) and a channel
//! from the buyer's node to the seller's node. The `lnd-regtest` workflow
//! sets that up and runs them with
//! `cargo test --features lnd --test lnd_regtest -- --ignored --test-threads=1`.
//!
//! They check the parts of the `Rail` contract that the happy-path sale in
//! `lnd_sale` does not reach: a reused payment hash, a presented invoice
//! that differs from what the payer's node decodes, a wrong preimage, and
//! a hold invoice cancelled by the payee (the buyer must see the payment
//! fail and get the funds back).

use std::time::Duration;

use pcp::encoding::sha256;
use pcp::lightning::LedgerError;
use pcp::rail::lnd::{LndConfig, LndRail, Track, LND_MIN_FINAL_CLTV};
use pcp::rail::{IncomingState, InvoiceRequest, PaymentStatus, Rail, RailError};
use rand::RngCore;

fn connect(who: &str) -> LndRail {
    let cfg = LndConfig::from_env(&format!("PCP_{who}_LND_")).expect("LND env vars");
    LndRail::connect(cfg).expect("node reachable")
}

fn fresh_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

fn request(seller: &LndRail, k: &[u8; 32], amount_msat: u64) -> InvoiceRequest {
    InvoiceRequest {
        payee: seller.node_id().to_string(),
        payment_hash: sha256(k),
        amount_msat,
        description_hash: sha256(b"pcp lnd_regtest"),
        expiry_secs: 600,
        min_htlc_secs: LND_MIN_FINAL_CLTV * 600,
    }
}

/// Poll until `f` returns `Some`, at most `tries` times, 500 ms apart.
fn wait_for<T>(tries: u32, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    for _ in 0..tries {
        if let Some(v) = f() {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    None
}

#[test]
#[ignore = "needs two LND regtest nodes (lnd-regtest workflow)"]
fn the_hold_invoice_reads_back_with_the_requested_terms() {
    let mut seller = connect("SELLER");
    let k = fresh_key();
    let req = request(&seller, &k, 2_000_000);
    let inv = seller.create_invoice(&req).expect("hold invoice");
    assert_eq!(inv.payment_hash, req.payment_hash);
    assert_eq!(inv.amount_msat, req.amount_msat);
    assert_eq!(inv.description_hash, req.description_hash);
    assert_eq!(inv.payee, seller.node_id());
    assert_eq!(inv.expiry_secs, 600);
    assert_eq!(inv.min_htlc_secs, LND_MIN_FINAL_CLTV * 600);
    assert!(inv.bolt11.as_deref().unwrap().starts_with("lnbcrt"));
    // Nothing paid yet: the payee sees no HTLC.
    assert_eq!(seller.lookup_invoice(&req.payment_hash), Ok(None));
    // A seller that crashed before recording the invoice finds it again.
    assert_eq!(
        seller.find_invoice(&req.payment_hash),
        Ok(Some(inv.clone()))
    );
    assert_eq!(seller.find_invoice(&fresh_key()), Ok(None));
    seller
        .cancel_hold_invoice(&req.payment_hash)
        .expect("cancel");
}

#[test]
#[ignore = "needs two LND regtest nodes (lnd-regtest workflow)"]
fn a_reused_payment_hash_is_refused() {
    let mut seller = connect("SELLER");
    let k = fresh_key();
    let req = request(&seller, &k, 1_000_000);
    seller.create_invoice(&req).expect("first invoice");
    let again = seller.create_invoice(&req);
    assert!(
        matches!(again, Err(RailError::Node(_))),
        "second invoice to the same hash must be refused, got {again:?}"
    );
    seller
        .cancel_hold_invoice(&req.payment_hash)
        .expect("cancel");
}

#[test]
#[ignore = "needs two LND regtest nodes (lnd-regtest workflow)"]
fn the_buyer_node_refuses_a_presented_invoice_with_other_terms() {
    let mut seller = connect("SELLER");
    let mut buyer = connect("BUYER");
    let buyer_id = buyer.node_id().to_string();
    let k = fresh_key();
    let req = request(&seller, &k, 1_000_000);
    let inv = seller.create_invoice(&req).expect("hold invoice");

    let mut cheaper = inv.clone();
    cheaper.amount_msat -= 1;
    assert_eq!(
        buyer.pay_invoice(&buyer_id, &cheaper, 40 * 600),
        Err(RailError::InvoiceMismatch("amount_msat"))
    );
    let mut other_desc = inv.clone();
    other_desc.description_hash = [0u8; 32];
    assert_eq!(
        buyer.pay_invoice(&buyer_id, &other_desc, 40 * 600),
        Err(RailError::InvoiceMismatch("description_hash"))
    );
    let mut no_bolt11 = inv.clone();
    no_bolt11.bolt11 = None;
    assert_eq!(
        buyer.pay_invoice(&buyer_id, &no_bolt11, 40 * 600),
        Err(RailError::InvoiceMissing)
    );
    // Nothing went out.
    assert_eq!(
        buyer.lookup_payment(&buyer_id, &req.payment_hash),
        Ok(PaymentStatus::Unknown)
    );
    assert_eq!(seller.lookup_invoice(&req.payment_hash), Ok(None));
    seller
        .cancel_hold_invoice(&req.payment_hash)
        .expect("cancel");
}

#[test]
#[ignore = "needs two LND regtest nodes (lnd-regtest workflow)"]
fn a_cancelled_hold_invoice_refunds_the_buyer() {
    let mut seller = connect("SELLER");
    let mut buyer = connect("BUYER");
    let buyer_id = buyer.node_id().to_string();
    let seller_id = seller.node_id().to_string();
    let k = fresh_key();
    let h = sha256(&k);
    let inv = seller
        .create_invoice(&request(&seller, &k, 1_500_000))
        .expect("hold invoice");
    buyer
        .pay_invoice(&buyer_id, &inv, 40 * 600)
        .expect("payment goes out");

    let held = wait_for(60, || match seller.lookup_invoice(&h) {
        Ok(Some(htlc)) if htlc.state == IncomingState::Held => Some(htlc),
        _ => None,
    })
    .expect("the seller's node holds the HTLC");
    assert_eq!(held.amount_msat, 1_500_000);
    assert_eq!(held.payee, seller_id);
    assert!(held.timeout_at > seller.now() + 600, "{held:?}");
    assert_eq!(
        buyer.lookup_payment(&buyer_id, &h),
        Ok(PaymentStatus::InFlight)
    );
    // The lookup above came from TrackPaymentV2, not the ListPayments
    // fallback: the track endpoint answers for this hash, and says
    // "never sent" for a hash the buyer never paid.
    match buyer.track_payment(&h) {
        Ok(Track::Found(p)) => assert_eq!(p["status"].as_str(), Some("IN_FLIGHT"), "{p}"),
        other => panic!("track_payment: {other:?}"),
    }
    assert_eq!(buyer.track_payment(&fresh_key()), Ok(Track::NeverSent));

    // A wrong preimage never reaches the node.
    assert_eq!(
        seller.settle_invoice(&seller_id, &h, [7u8; 32]),
        Err(RailError::Ledger(LedgerError::PreimageMismatch))
    );

    seller.cancel_hold_invoice(&h).expect("cancel");
    let status = wait_for(60, || match buyer.lookup_payment(&buyer_id, &h) {
        Ok(s @ PaymentStatus::Failed { .. }) => Some(s),
        _ => None,
    });
    assert!(status.is_some(), "the buyer sees the payment fail");
    assert_eq!(
        seller.lookup_invoice(&h).unwrap().map(|x| x.state),
        Some(IncomingState::Canceled)
    );
    // And k cannot be used any more.
    assert!(seller.settle_invoice(&seller_id, &h, k).is_err());
}
