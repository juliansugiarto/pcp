//! Protocol and threat tests. These live inside the crate so they can model a
//! malicious seller who has read the dev backend's source (crate-private
//! `prove_unchecked`, `unseal`). Tests that use only the public API are in
//! `tests/public_api.rs`.

use rand::rngs::OsRng;

use crate::crypto;
use crate::encoding::{Hash32, VERSION};
use crate::job::{input_commitment, JobClass, SudokuJob, TestSuiteJob};
use crate::lightning::{HtlcState, Ledger, LedgerError};
use crate::mandate::{
    adoption_count, Agent, LogEntry, Mandate, MandateError, MandateTerms, PrincipalLog, PublicKey,
    Role, SecretKey,
};
use crate::proof::{
    build_statement, InsecureDevTransparentBackend, ProofBackend, ProofBundle, ProveError,
    VerifyError, Witness,
};
use crate::protocol::*;
use crate::registry::JobRegistry;

const PRICE: u64 = 1_000_000;
const BUYER_FUNDS: u64 = 10_000_000;

fn puzzle9() -> Vec<u8> {
    SudokuJob::nine()
        .parse_grid("53..7.... 6..195... .98....6. 8...6...3 4..8.3..1 7...2...6 .6....28. ...419..5 ....8..79")
        .unwrap()
}

fn clamp_suite() -> Vec<u8> {
    TestSuiteJob::encode_suite(&[
        (-5, 0),
        (0, 0),
        (42, 42),
        (100, 100),
        (101, 100),
        (i64::MAX, 100),
    ])
}

const CLAMP_OK: &str = "if(x < 0, 0, if(x > 100, 100, x))";
const CLAMP_BAD: &str = "if(x < 0, 0, x)";

fn dev_policy() -> BuyerPolicy {
    BuyerPolicy {
        allow_insecure_dev_backend: true,
        ..BuyerPolicy::default()
    }
}

/// A principal and the agent it signed a mandate for.
pub(crate) struct Party {
    pub principal: SecretKey,
    pub agent: Agent,
    /// The agent key's seed, to rebuild the agent after a simulated restart.
    pub agent_seed: [u8; 32],
}

impl Party {
    pub fn principal_key(&self) -> PublicKey {
        self.principal.public_key()
    }
}

/// Every reference job class, for mandate scopes.
fn all_specs() -> Vec<Hash32> {
    JobRegistry::reference()
        .entries()
        .map(|e| e.spec_hash)
        .collect()
}

fn terms(role: Role, node: &str) -> MandateTerms {
    MandateTerms {
        role,
        scope: all_specs(),
        cap_msat: 10 * PRICE,
        per_deal_max_msat: 2 * PRICE,
        payout_node: node.to_string(),
        expires_at: 1_000_000,
    }
}

fn party_with(principal: SecretKey, t: MandateTerms) -> Party {
    let agent_key = SecretKey::generate(&mut OsRng);
    let agent_seed = agent_key.to_seed();
    let m = Mandate::sign(&principal, agent_key.public_key(), t, &mut OsRng);
    let agent = Agent::new(agent_key, m).unwrap();
    Party {
        principal,
        agent,
        agent_seed,
    }
}

fn party(t: MandateTerms) -> Party {
    party_with(SecretKey::generate(&mut OsRng), t)
}

/// Re-sign an offer as `agent` (models a seller, or a modified seller
/// client, that skips its own checks).
fn resign_offer(agent: &Agent, mut o: Offer) -> Offer {
    o.mandate = Some(agent.mandate().clone());
    o.agent_sig = Some(agent.sign(&o.auth_message(&agent.mandate_id())));
    o
}

/// Re-sign a request as `agent`.
fn resign_request(agent: &Agent, mut r: Request) -> Request {
    r.mandate = Some(agent.mandate().clone());
    r.agent_sig = Some(agent.sign(&r.auth_message(&agent.mandate_id())));
    r
}

/// An offer built by hand for `req`, signed by `agent`, bypassing every
/// seller-side check.
fn manual_offer(agent: &Agent, req: &Request, price: u64, seller_node: &str) -> Offer {
    resign_offer(
        agent,
        Offer {
            version: VERSION.to_string(),
            job_id: req.job_id.clone(),
            spec_hash: req.spec_hash,
            input_commitment: req.input_commitment,
            buyer_nonce: req.buyer_nonce,
            price_msat: price,
            offer_expires_at: 600,
            seller_node: seller_node.to_string(),
            backend_id: crate::proof::INSECURE_DEV_BACKEND_ID.to_string(),
            enc_scheme: crypto::ENC_SCHEME.to_string(),
            rail: RAIL_SIM.to_string(),
            mandate: None,
            agent_sig: None,
        },
    )
}

struct Fx {
    ledger: Ledger,
    buyer: Buyer,
    seller: Seller,
    req: Request,
    offer: Offer,
    bp: Party,
    sp: Party,
}

fn fixture_named<J: JobClass + Clone + 'static>(
    job: J,
    input: Vec<u8>,
    buyer: &str,
    ledger: Option<Ledger>,
) -> Fx {
    let sp = party(terms(Role::Seller, "seller"));
    let bp = party(terms(Role::Buyer, buyer));
    let mut ledger = ledger.unwrap_or_else(|| {
        let mut l = Ledger::new();
        l.open_principal_node("seller", sp.principal_key(), 0);
        l
    });
    ledger.open_principal_node(buyer, bp.principal_key(), BUYER_FUNDS);
    let (mut b, req) = Buyer::new(
        &bp.agent,
        Box::new(job.clone()),
        Box::new(InsecureDevTransparentBackend),
        dev_policy(),
        input,
        2 * PRICE,
        ledger.now(),
        &mut OsRng,
    )
    .unwrap();
    let mut seller = Seller::new(
        &sp.agent,
        Box::new(job),
        Box::new(InsecureDevTransparentBackend),
        SellerConfig {
            price_msat: PRICE,
            ..SellerConfig::default()
        },
    );
    let offer = seller.make_offer(&req, ledger.now()).unwrap();
    b.accept_offer(&offer, ledger.now()).unwrap();
    Fx {
        ledger,
        buyer: b,
        seller,
        req,
        offer,
        bp,
        sp,
    }
}

fn fixture<J: JobClass + Clone + 'static>(job: J, input: Vec<u8>) -> Fx {
    fixture_named(job, input, "buyer", None)
}

/// The atomicity invariant: the buyer has paid iff the buyer has `k`.
fn assert_atomic(fx: &Fx, buyer: &str) {
    let paid = fx.ledger.balance(buyer) < BUYER_FUNDS;
    let delivered = fx.buyer.result().is_ok();
    // A payment locked but neither settled nor refunded is "in flight":
    // funds are out of the balance but not with the seller either.
    let in_flight = matches!(fx.buyer.state(), BuyerState::Paid { .. });
    if !in_flight {
        assert_eq!(
            paid, delivered,
            "atomicity violated: paid={paid} delivered={delivered}"
        );
    }
}

// ---------------------------------------------------------------------------
// Happy paths

fn run_happy(mut fx: Fx, result: Vec<u8>) -> Fx {
    let (bundle, binding) = fx
        .seller
        .fulfil(&fx.req, &fx.offer, result, &mut fx.ledger, &mut OsRng)
        .unwrap();
    fx.buyer.verify_bundle(&bundle).unwrap();
    fx.buyer.check_invoice(&binding, fx.ledger.now()).unwrap();
    assert_eq!(fx.buyer.result(), Err(PcpError::NotPaid));
    fx.buyer.pay(&mut fx.ledger).unwrap();
    assert_eq!(fx.buyer.poll(&mut fx.ledger), Ok(BuyerProgress::Waiting));
    fx.ledger.advance(5);
    let outcomes = fx.seller.settle_paid(&mut fx.ledger);
    assert!(matches!(
        outcomes.as_slice(),
        [SaleOutcome::Settled {
            amount_msat: PRICE,
            ..
        }]
    ));
    assert_eq!(fx.buyer.poll(&mut fx.ledger), Ok(BuyerProgress::Delivered));
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS - PRICE);
    assert_eq!(fx.ledger.balance("seller"), PRICE);
    // Payouts land on the seller's principal, payments leave the buyer's.
    assert_eq!(fx.ledger.principal_balance(&fx.sp.principal_key()), PRICE);
    assert_eq!(
        fx.ledger.principal_balance(&fx.bp.principal_key()),
        BUYER_FUNDS - PRICE
    );
    assert_atomic(&fx, "buyer");
    fx
}

#[test]
fn happy_path_sudoku() {
    let job = SudokuJob::nine();
    let input = puzzle9();
    let solution = job.solve(&input).unwrap();
    let fx = run_happy(fixture(job, input.clone()), solution.clone());
    assert_eq!(fx.buyer.result().unwrap(), solution.as_slice());

    // The receipt lets a third party re-verify the sale offline.
    let receipt = fx.buyer.receipt().unwrap().clone();
    let BuyerState::Delivered { bundle, .. } = fx.buyer.state() else {
        panic!()
    };
    assert_eq!(receipt.verify(&job, &input, bundle).unwrap(), solution);
    let mut forged = receipt.clone();
    forged.preimage = [0u8; 32];
    assert_eq!(
        forged.verify(&job, &input, bundle),
        Err(PcpError::PreimageMismatch)
    );
}

#[test]
fn happy_path_four_by_four() {
    let job = SudokuJob::four();
    let input = job.parse_grid("1..4 ..1. .1.. 4..1").unwrap();
    let solution = job.solve(&input).unwrap();
    run_happy(fixture(job, input), solution);
}

#[test]
fn happy_path_patch_passes_tests() {
    let fx = run_happy(
        fixture(TestSuiteJob, clamp_suite()),
        CLAMP_OK.as_bytes().to_vec(),
    );
    assert_eq!(fx.buyer.result().unwrap(), CLAMP_OK.as_bytes());
}

// ---------------------------------------------------------------------------
// Threat: the seller sends a ciphertext of a wrong result

#[test]
fn honest_seller_and_backend_refuse_wrong_result() {
    let mut fx = fixture(TestSuiteJob, clamp_suite());
    let r = fx.seller.fulfil(
        &fx.req,
        &fx.offer,
        CLAMP_BAD.as_bytes().to_vec(),
        &mut fx.ledger,
        &mut OsRng,
    );
    assert_eq!(r.err(), Some(PcpError::SellerResultInvalid));

    // Even called directly, the backend will not prove a false statement.
    let k = crypto::fresh_key(&mut OsRng);
    let offer_id = fx.offer.offer_id();
    let c = crypto::encrypt(&k, &offer_id, CLAMP_BAD.as_bytes());
    let st = build_statement(
        &TestSuiteJob,
        input_commitment(&fx.req.input),
        offer_id,
        fx.req.buyer_nonce,
        &c,
        crypto::payment_hash(&k),
    );
    let w = Witness {
        input: fx.req.input.clone(),
        result: CLAMP_BAD.as_bytes().to_vec(),
        key: k,
    };
    assert_eq!(
        InsecureDevTransparentBackend
            .prove(&TestSuiteJob, &st, &c, &w)
            .err(),
        Some(ProveError::Unsatisfied(VerifyError::JobCheckFailed))
    );
}

/// A malicious seller who bypasses its own checks: forge a bundle whose
/// witness carries a wrong result.
fn forged_bundle(fx: &Fx, result: &[u8], encrypted: &[u8]) -> (ProofBundle, [u8; 32]) {
    let k = crypto::fresh_key(&mut OsRng);
    let offer_id = fx.offer.offer_id();
    let c = crypto::encrypt(&k, &offer_id, encrypted);
    let st = build_statement(
        &TestSuiteJob,
        input_commitment(&fx.req.input),
        offer_id,
        fx.req.buyer_nonce,
        &c,
        crypto::payment_hash(&k),
    );
    let w = Witness {
        input: fx.req.input.clone(),
        result: result.to_vec(),
        key: k,
    };
    (
        InsecureDevTransparentBackend::prove_unchecked(&st, &c, &w),
        k,
    )
}

#[test]
fn wrong_result_fails_verification_and_nothing_is_paid() {
    let mut fx = fixture(TestSuiteJob, clamp_suite());
    let (bundle, _) = forged_bundle(&fx, CLAMP_BAD.as_bytes(), CLAMP_BAD.as_bytes());
    assert_eq!(
        fx.buyer.verify_bundle(&bundle),
        Err(PcpError::ProofInvalid(VerifyError::JobCheckFailed))
    );
    assert!(matches!(fx.buyer.state(), BuyerState::Aborted(_)));
    assert!(matches!(
        fx.buyer.pay(&mut fx.ledger),
        Err(PcpError::WrongState(_))
    ));
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
    assert_atomic(&fx, "buyer");
}

#[test]
fn ciphertext_of_other_result_than_proven_fails() {
    // Witness says CLAMP_OK (passes) but C encrypts CLAMP_BAD.
    let mut fx = fixture(TestSuiteJob, clamp_suite());
    let (bundle, _) = forged_bundle(&fx, CLAMP_OK.as_bytes(), CLAMP_BAD.as_bytes());
    assert_eq!(
        fx.buyer.verify_bundle(&bundle),
        Err(PcpError::ProofInvalid(VerifyError::CiphertextMismatch))
    );
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
}

#[test]
fn swapped_ciphertext_after_proving_fails() {
    // Swap C only: the statement's ciphertext_hash no longer matches.
    let mut fx = fixture(TestSuiteJob, clamp_suite());
    let (bundle, _) = fx
        .seller
        .fulfil(
            &fx.req,
            &fx.offer,
            CLAMP_OK.as_bytes().to_vec(),
            &mut fx.ledger,
            &mut OsRng,
        )
        .unwrap();
    let mut b1 = bundle.clone();
    b1.ciphertext = crypto::encrypt(&[9u8; 32], &fx.offer.offer_id(), b"0");
    assert_eq!(
        fx.buyer.verify_bundle(&b1),
        Err(PcpError::CiphertextHashMismatch)
    );

    // Swap C and patch the statement to match: the proof is bound to the
    // original statement and no longer opens.
    let mut fx = fixture(TestSuiteJob, clamp_suite());
    let (bundle, _) = fx
        .seller
        .fulfil(
            &fx.req,
            &fx.offer,
            CLAMP_OK.as_bytes().to_vec(),
            &mut fx.ledger,
            &mut OsRng,
        )
        .unwrap();
    let mut b2 = bundle.clone();
    b2.ciphertext = crypto::encrypt(&[9u8; 32], &fx.offer.offer_id(), b"0");
    b2.statement.ciphertext_hash = crypto::ciphertext_hash(&b2.ciphertext);
    assert_eq!(
        fx.buyer.verify_bundle(&b2),
        Err(PcpError::ProofInvalid(VerifyError::ProofMalformed))
    );
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
}

// ---------------------------------------------------------------------------
// Threat: invoice does not match the proof

fn verified(job_input: (TestSuiteJob, Vec<u8>)) -> (Fx, ProofBundle, InvoiceBinding) {
    let mut fx = fixture(job_input.0, job_input.1);
    let (bundle, binding) = fx
        .seller
        .fulfil(
            &fx.req,
            &fx.offer,
            CLAMP_OK.as_bytes().to_vec(),
            &mut fx.ledger,
            &mut OsRng,
        )
        .unwrap();
    fx.buyer.verify_bundle(&bundle).unwrap();
    (fx, bundle, binding)
}

#[test]
fn seller_fulfils_only_offers_it_issued_unchanged() {
    // A buyer that hands the offer back with a lower price, a later expiry,
    // or no signature gets nothing proved and nothing invoiced.
    let fx = fixture(TestSuiteJob, clamp_suite());
    let mut cheap = fx.offer.clone();
    cheap.price_msat = 1;
    let mut forever = fx.offer.clone();
    forever.offer_expires_at = u64::MAX;
    let mut unsigned = fx.offer.clone();
    unsigned.agent_sig = None;
    for (name, o) in [
        ("price", cheap),
        ("expiry", forever),
        ("unsigned", unsigned),
    ] {
        let mut fx = fixture(TestSuiteJob, clamp_suite());
        // Same request as the offer was made for.
        let req = fx.req.clone();
        let o = Offer {
            buyer_nonce: req.buyer_nonce,
            input_commitment: req.input_commitment,
            ..o
        };
        let r = fx.seller.fulfil(
            &req,
            &o,
            CLAMP_OK.as_bytes().to_vec(),
            &mut fx.ledger,
            &mut OsRng,
        );
        assert!(
            matches!(r, Err(PcpError::OfferMismatch)),
            "{name}: {:?}",
            r.err()
        );
    }
    let _ = fx;
}

#[test]
fn lightning_presets_fit_lnd() {
    let b = BuyerPolicy::lightning();
    let s = SellerConfig::lightning(PRICE);
    assert_eq!(b.rail, RAIL_BOLT11);
    assert_eq!(s.rail, RAIL_BOLT11);
    // The buyer accepts the seller's final CLTV plus two LND hops.
    assert!(b.htlc_secs >= s.min_htlc_secs + 2 * LN_HOP_DELTA_BLOCKS * SECS_PER_BLOCK);
    // The seller's margin is above LND's hold-expiry cancel and below the
    // final CLTV, so a fresh HTLC can be settled.
    assert!(s.settle_margin_secs > LN_HOLD_EXPIRY_DELTA_BLOCKS * SECS_PER_BLOCK);
    assert!(s.settle_margin_secs < s.min_htlc_secs);
    // The offer outlives three of the slowest proofs measured for the
    // reproducible guest (159 s, the 2^18 test-suite job on a slow runner).
    assert!(s.offer_ttl_secs >= 3 * 159);
}

#[test]
fn seller_records_a_settle_whose_reply_was_lost() {
    // The node settled (the seller's call reached it) but the reply never
    // came back. On the next pass the seller must record the sale, commit the
    // amount against its cap and log the receipt, not report "not paid".
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    fx.buyer.check_invoice(&binding, fx.ledger.now()).unwrap();
    let htlc = fx.buyer.pay(&mut fx.ledger).unwrap();
    let k = fx
        .seller
        .sale_key_for_test(&binding.invoice.payment_hash)
        .unwrap();
    fx.ledger.settle("seller", htlc, k).unwrap();
    assert!(matches!(
        fx.seller.settle_paid(&mut fx.ledger).as_slice(),
        [SaleOutcome::Settled {
            amount_msat: PRICE,
            ..
        }]
    ));
    assert!(fx.seller.settle_paid(&mut fx.ledger).is_empty());
    assert_eq!(fx.buyer.poll(&mut fx.ledger), Ok(BuyerProgress::Delivered));
    assert_atomic(&fx, "buyer");
}

#[test]
fn seller_refuses_to_fulfil_an_expired_offer() {
    let mut fx = fixture(TestSuiteJob, clamp_suite());
    let wait = fx.offer.offer_expires_at - fx.ledger.now();
    fx.ledger.advance(wait);
    assert!(matches!(
        fx.seller.fulfil(
            &fx.req,
            &fx.offer,
            CLAMP_OK.as_bytes().to_vec(),
            &mut fx.ledger,
            &mut OsRng,
        ),
        Err(PcpError::OfferExpired)
    ));
}

#[test]
fn buyer_refuses_an_invoice_after_the_offer_expired() {
    // The seller invoiced in time, but the buyer only checks the invoice
    // after the offer is void: the offer no longer binds anyone, so no payment.
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    let wait = fx.offer.offer_expires_at - fx.ledger.now();
    fx.ledger.advance(wait);
    assert_eq!(
        fx.buyer.check_invoice(&binding, fx.ledger.now()),
        Err(PcpError::OfferExpired)
    );
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
}

#[test]
fn invoice_payment_hash_mismatch_is_refused() {
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    // Seller issues an invoice to a hash whose preimage is NOT the k that
    // decrypts C. Paying it would hand the seller money with no delivery.
    let other_k = [5u8; 32];
    let inv = fx
        .ledger
        .create_invoice(
            "seller",
            crypto::payment_hash(&other_k),
            PRICE,
            600,
            600,
            binding.statement_hash,
        )
        .unwrap();
    let bad = InvoiceBinding {
        invoice: inv,
        ..binding.clone()
    };
    assert_eq!(
        fx.buyer.check_invoice(&bad, fx.ledger.now()),
        Err(PcpError::InvoiceHashMismatch)
    );
    assert!(matches!(
        fx.buyer.pay(&mut fx.ledger),
        Err(PcpError::WrongState(_))
    ));
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
}

#[test]
fn invoice_amount_payee_description_and_timing_are_checked() {
    type Case = (Box<dyn Fn(&mut InvoiceBinding)>, fn(&PcpError) -> bool);
    let cases: Vec<Case> = vec![
        (Box::new(|b| b.invoice.amount_msat += 1), |e| {
            matches!(e, PcpError::InvoiceAmountMismatch { .. })
        }),
        (Box::new(|b| b.invoice.payee = "mallory".into()), |e| {
            *e == PcpError::InvoicePayeeMismatch
        }),
        (Box::new(|b| b.invoice.description_hash = [1u8; 32]), |e| {
            *e == PcpError::InvoiceDescriptionMismatch
        }),
        (Box::new(|b| b.statement_hash = [1u8; 32]), |e| {
            *e == PcpError::InvoiceBindingMismatch
        }),
        (Box::new(|b| b.invoice.expiry_secs = 30), |e| {
            *e == PcpError::InvoiceExpiresTooSoon
        }),
        (
            Box::new(|b| b.invoice.min_htlc_secs = 30 * 24 * 3600),
            |e| matches!(e, PcpError::HtlcLockTooLong { .. }),
        ),
    ];
    for (mutate, expect) in cases {
        let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
        let mut b = binding.clone();
        mutate(&mut b);
        let err = fx.buyer.check_invoice(&b, fx.ledger.now()).unwrap_err();
        assert!(expect(&err), "unexpected {err:?}");
    }
}

// ---------------------------------------------------------------------------
// Threat: wrong preimage; buyer refuses to pay; expiry

#[test]
fn wrong_preimage_cannot_settle_and_buyer_is_refunded() {
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    fx.buyer.check_invoice(&binding, fx.ledger.now()).unwrap();
    let htlc = fx.buyer.pay(&mut fx.ledger).unwrap();
    assert_eq!(
        fx.ledger.settle("seller", htlc, [7u8; 32]),
        Err(LedgerError::PreimageMismatch)
    );
    assert_eq!(fx.ledger.balance("seller"), 0);
    assert_eq!(fx.buyer.poll(&mut fx.ledger), Ok(BuyerProgress::Waiting));
    assert_eq!(fx.buyer.result(), Err(PcpError::NotPaid));
    // Seller goes silent; the HTLC times out.
    fx.ledger.advance(BuyerPolicy::default().htlc_secs);
    assert_eq!(fx.buyer.poll(&mut fx.ledger), Err(PcpError::Refunded));
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
    assert_eq!(fx.buyer.result(), Err(PcpError::Refunded));
    assert_atomic(&fx, "buyer");
}

#[test]
fn expiry_refunds_and_seller_does_not_reveal_late() {
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    fx.buyer.check_invoice(&binding, fx.ledger.now()).unwrap();
    let htlc = fx.buyer.pay(&mut fx.ledger).unwrap();
    // Seller comes back too close to the timeout: it withholds k, and
    // cancels the HTLC so the buyer's funds come back now, not at timeout.
    fx.ledger.advance(BuyerPolicy::default().htlc_secs - 60);
    let out = fx.seller.settle_paid(&mut fx.ledger);
    assert!(matches!(
        out.as_slice(),
        [SaleOutcome::Cancelled {
            reason: PcpError::SettleMarginTooShort,
            ..
        }]
    ));
    assert!(matches!(
        fx.ledger.htlc(htlc).unwrap().state,
        HtlcState::Refunded { .. }
    ));
    assert_eq!(fx.buyer.poll(&mut fx.ledger), Err(PcpError::Refunded));
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
    // The sale is over: never polled again, k stays secret, and the
    // seller's principal sees why in the log.
    assert!(fx.seller.settle_paid(&mut fx.ledger).is_empty());
    let log = fx.seller.agent().log();
    assert_eq!(
        log.refusals()
            .map(|r| r.reason.as_str())
            .collect::<Vec<_>>(),
        ["settle_margin_too_short"]
    );
    assert_eq!(log.receipts().count(), 0);
    assert_atomic(&fx, "buyer");
}

#[test]
fn unpaid_invoice_expires() {
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    fx.buyer.check_invoice(&binding, fx.ledger.now()).unwrap();
    fx.ledger.advance(binding.invoice.expiry_secs);
    assert_eq!(
        fx.buyer.pay(&mut fx.ledger),
        Err(PcpError::Ledger(LedgerError::InvoiceExpired))
    );
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
    // The payment never left: the reservation is back and the buyer can
    // still decide (here: walk away).
    assert!(matches!(
        fx.buyer.state(),
        BuyerState::InvoiceAccepted { .. }
    ));
    assert_eq!(fx.bp.agent.committed_msat(), 0);
    // The seller ends the sale once the invoice has expired.
    assert!(matches!(
        fx.seller.settle_paid(&mut fx.ledger).as_slice(),
        [SaleOutcome::Cancelled {
            reason: PcpError::InvoiceExpired,
            ..
        }]
    ));
    assert!(fx.seller.settle_paid(&mut fx.ledger).is_empty());
}

#[test]
fn buyer_who_never_pays_never_gets_k() {
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    fx.buyer.check_invoice(&binding, fx.ledger.now()).unwrap();
    // The buyer walks away. The seller has nothing to settle and reveals nothing.
    assert!(matches!(
        fx.seller.settle_paid(&mut fx.ledger).as_slice(),
        [SaleOutcome::NotPaid { .. }]
    ));
    assert_eq!(fx.buyer.result(), Err(PcpError::NotPaid));
    assert_eq!(fx.ledger.balance("seller"), 0);
    assert_atomic(&fx, "buyer");
}

// ---------------------------------------------------------------------------
// Threat: the buyer learns R without paying

#[test]
fn buyer_cannot_learn_result_before_paying() {
    let (fx, bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    let secret_src = CLAMP_OK;
    let wire = serde_json::to_string(&bundle).unwrap() + &serde_json::to_string(&binding).unwrap();
    let debug = format!("{bundle:?}{binding:?}");
    for haystack in [&wire, &debug] {
        assert!(!haystack.contains(secret_src), "plaintext R on the wire");
        assert!(
            !haystack.contains(&hex::encode(secret_src)),
            "hex R on the wire"
        );
        assert!(!haystack.contains("x > 100"), "fragment of R on the wire");
    }
    assert!(!bundle
        .ciphertext
        .windows(secret_src.len())
        .any(|w| w == secret_src.as_bytes()));
    assert!(!bundle
        .proof
        .windows(secret_src.len())
        .any(|w| w == secret_src.as_bytes()));
    // The only public key material is H, and H does not decrypt C.
    assert!(crypto::decrypt(
        &bundle.statement.payment_hash,
        &bundle.statement.offer_id,
        &bundle.ciphertext
    )
    .is_none());
    // The state machine withholds the result.
    assert_eq!(fx.buyer.result(), Err(PcpError::NotPaid));
    assert_eq!(fx.buyer.receipt().err(), Some(PcpError::NotPaid));

    // Sanity check that the seal really contains the witness (so the
    // assertions above are testing something): crate-internal unseal opens it.
    let w = InsecureDevTransparentBackend::unseal(&bundle.statement, &bundle.proof).unwrap();
    assert_eq!(w.result, secret_src.as_bytes());
    assert!(
        !format!("{w:?}").contains(secret_src),
        "Witness Debug is redacted"
    );
    // And k is not on the wire either.
    assert!(!wire.contains(&hex::encode(w.key)));
}

#[test]
fn buyer_refuses_insecure_backend_by_default() {
    let job = SudokuJob::four();
    let input = job.parse_grid("1..4 ..1. .1.. 4..1").unwrap();
    let bp = party(terms(Role::Buyer, "buyer"));
    let sp = party(terms(Role::Seller, "seller"));
    let (mut b, req) = Buyer::new(
        &bp.agent,
        Box::new(job),
        Box::new(InsecureDevTransparentBackend),
        BuyerPolicy::default(),
        input,
        PRICE,
        0,
        &mut OsRng,
    )
    .unwrap();
    let mut s = Seller::new(
        &sp.agent,
        Box::new(job),
        Box::new(InsecureDevTransparentBackend),
        SellerConfig {
            price_msat: PRICE,
            ..Default::default()
        },
    );
    let offer = s.make_offer(&req, 0).unwrap();
    assert_eq!(
        b.accept_offer(&offer, 0),
        Err(PcpError::InsecureBackendRefused)
    );
}

#[test]
fn offer_checks() {
    let job = SudokuJob::four();
    let input = job.parse_grid("1..4 ..1. .1.. 4..1").unwrap();
    let bp = party(terms(Role::Buyer, "buyer"));
    let sp = party(terms(Role::Seller, "seller"));
    let mk = || {
        Buyer::new(
            &bp.agent,
            Box::new(job),
            Box::new(InsecureDevTransparentBackend),
            dev_policy(),
            input.clone(),
            PRICE,
            0,
            &mut OsRng,
        )
        .unwrap()
    };
    let mut s = Seller::new(
        &sp.agent,
        Box::new(job),
        Box::new(InsecureDevTransparentBackend),
        SellerConfig {
            price_msat: PRICE,
            ..Default::default()
        },
    );
    let (_, req) = mk();
    let good = s.make_offer(&req, 0).unwrap();

    let (mut b, _) = mk();
    assert_eq!(
        b.accept_offer(&good, 0),
        Err(PcpError::ReplayedOrMisdirected),
        "offer for another nonce"
    );

    let (mut b, req) = mk();
    let mut o = s.make_offer(&req, 0).unwrap();
    o.price_msat = PRICE + 1;
    assert!(matches!(
        b.accept_offer(&o, 0),
        Err(PcpError::PriceTooHigh { .. })
    ));

    let (mut b, req) = mk();
    let o = s.make_offer(&req, 0).unwrap();
    assert_eq!(
        b.accept_offer(&o, o.offer_expires_at),
        Err(PcpError::OfferExpired)
    );

    let (mut b, req) = mk();
    let mut o = s.make_offer(&req, 0).unwrap();
    o.spec_hash = SudokuJob::nine().spec_hash();
    assert_eq!(b.accept_offer(&o, 0), Err(PcpError::JobMismatch));
}

// ---------------------------------------------------------------------------
// Threat: replay of a proof to another buyer

#[test]
fn proof_replayed_to_another_buyer_fails() {
    let job = SudokuJob::nine();
    let input = puzzle9();
    let solution = job.solve(&input).unwrap();

    // Alice buys the solution.
    let mut alice = fixture_named(job, input.clone(), "alice", None);
    let (bundle_a, binding_a) = alice
        .seller
        .fulfil(
            &alice.req,
            &alice.offer,
            solution.clone(),
            &mut alice.ledger,
            &mut OsRng,
        )
        .unwrap();

    // Bob asks for the same puzzle, on the same network.
    let ledger = std::mem::take(&mut alice.ledger);
    let mut bob = fixture_named(job, input.clone(), "bob", Some(ledger));

    // 1. Alice's bundle forwarded unchanged to Bob: wrong nonce.
    assert_eq!(
        bob.buyer.verify_bundle(&bundle_a),
        Err(PcpError::ReplayedOrMisdirected)
    );

    // 2. Rewrite the public fields to Bob's offer and nonce: the proof is
    //    bound to Alice's statement and no longer opens.
    let mut bob = fixture_named(
        job,
        input.clone(),
        "bob2",
        Some(std::mem::take(&mut bob.ledger)),
    );
    let mut rewritten = bundle_a.clone();
    rewritten.statement.buyer_nonce = bob.req.buyer_nonce;
    rewritten.statement.offer_id = bob.offer.offer_id();
    assert_eq!(
        bob.buyer.verify_bundle(&rewritten),
        Err(PcpError::ProofInvalid(VerifyError::ProofMalformed))
    );

    // 3. Alice's invoice offered to a Bob who has a valid bundle of his own:
    //    the binding names another offer and statement.
    let mut bob = fixture_named(
        job,
        input.clone(),
        "bob3",
        Some(std::mem::take(&mut bob.ledger)),
    );
    let (bundle_b, _binding_b) = bob
        .seller
        .fulfil(
            &bob.req,
            &bob.offer,
            solution.clone(),
            &mut bob.ledger,
            &mut OsRng,
        )
        .unwrap();
    bob.buyer.verify_bundle(&bundle_b).unwrap();
    assert_eq!(
        bob.buyer.check_invoice(&binding_a, bob.ledger.now()),
        Err(PcpError::InvoiceBindingMismatch)
    );
    // Fresh k per sale: Alice's and Bob's payment hashes differ.
    assert_ne!(
        bundle_a.statement.payment_hash,
        bundle_b.statement.payment_hash
    );
}

// ---------------------------------------------------------------------------
// Wire format

#[test]
fn messages_roundtrip_through_json() {
    let (mut fx, bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    let j = serde_json::to_string(&bundle).unwrap();
    let back: ProofBundle = serde_json::from_str(&j).unwrap();
    assert_eq!(back, bundle);
    assert_eq!(back.bundle_id(), bundle.bundle_id());
    let back: InvoiceBinding =
        serde_json::from_str(&serde_json::to_string(&binding).unwrap()).unwrap();
    assert_eq!(back, binding);
    let back: Offer = serde_json::from_str(&serde_json::to_string(&fx.offer).unwrap()).unwrap();
    assert_eq!(back.offer_id(), fx.offer.offer_id());
    let back: Request = serde_json::from_str(&serde_json::to_string(&fx.req).unwrap()).unwrap();
    assert_eq!(back, fx.req);

    fx.buyer.check_invoice(&binding, 0).unwrap();
    fx.buyer.pay(&mut fx.ledger).unwrap();
    fx.seller.settle_paid(&mut fx.ledger);
    fx.buyer.poll(&mut fx.ledger).unwrap();
    let receipt = fx.buyer.receipt().unwrap();
    let back: Receipt = serde_json::from_str(&serde_json::to_string(receipt).unwrap()).unwrap();
    assert_eq!(&back, receipt);

    // Uppercase hex is not canonical and is rejected.
    let upper = j.replacen(
        &hex::encode(bundle.statement.payment_hash),
        &hex::encode_upper(bundle.statement.payment_hash),
        1,
    );
    assert!(serde_json::from_str::<ProofBundle>(&upper).is_err());
}

// ---------------------------------------------------------------------------
// Conformance vectors (SPEC.md appendix A). A second implementation must
// reproduce these bytes exactly.

#[test]
fn conformance_vectors() {
    use crate::encoding::{tagged_hash, u64_be};
    let k = [0x11u8; 32];
    let offer_id = [0x22u8; 32];
    assert_eq!(
        hex::encode(tagged_hash("test", &[b"", b"abc", &u64_be(1)])),
        VECTORS[0]
    );
    assert_eq!(hex::encode(crypto::payment_hash(&k)), VECTORS[1]);
    assert_eq!(
        hex::encode(crypto::encrypt(&k, &offer_id, b"PCP")),
        VECTORS[2]
    );
    assert_eq!(hex::encode(SudokuJob::four().spec_hash()), VECTORS[3]);
    assert_eq!(hex::encode(SudokuJob::nine().spec_hash()), VECTORS[4]);
    assert_eq!(hex::encode(TestSuiteJob.spec_hash()), VECTORS[5]);
    assert_eq!(
        hex::encode(input_commitment(&TestSuiteJob::encode_suite(&[(-1, 1)]))),
        VECTORS[6]
    );
    let st = build_statement(
        &SudokuJob::four(),
        [0x33; 32],
        offer_id,
        [0x44; 32],
        b"C",
        crypto::payment_hash(&k),
    );
    assert_eq!(hex::encode(st.hash()), VECTORS[7]);
    let offer = Offer {
        version: "PCP/0".into(),
        job_id: "pcp/sudoku/v0".into(),
        spec_hash: SudokuJob::four().spec_hash(),
        input_commitment: [0x33; 32],
        buyer_nonce: [0x44; 32],
        price_msat: 1_000_000,
        offer_expires_at: 600,
        seller_node: "seller".into(),
        backend_id: crate::proof::INSECURE_DEV_BACKEND_ID.into(),
        enc_scheme: crypto::ENC_SCHEME.into(),
        rail: RAIL_SIM.into(),
        mandate: None,
        agent_sig: None,
    };
    assert_eq!(hex::encode(offer.offer_id()), VECTORS[8]);

    // Mandate (SPEC 2.1). Ed25519 is deterministic, so the signature is a
    // vector too.
    let principal = SecretKey::from_seed([0x55; 32]);
    let agent = SecretKey::from_seed([0x66; 32]);
    let mut m = Mandate {
        version: "PCP/0".into(),
        principal_key: principal.public_key(),
        agent_key: agent.public_key(),
        role: Role::Buyer,
        scope: vec![SudokuJob::four().spec_hash()],
        cap_msat: 5_000_000,
        per_deal_max_msat: 2_000_000,
        payout_node: "principal-node".into(),
        expires_at: 86_400,
        nonce: [0x77; 32],
        principal_sig: crate::mandate::Sig([0; 64]),
    };
    assert_eq!(hex::encode(m.principal_key), VECTORS[9]);
    assert_eq!(hex::encode(m.agent_key), VECTORS[10]);
    assert_eq!(hex::encode(m.mandate_id()), VECTORS[11]);
    m.principal_sig = principal.sign(&m.mandate_id());
    assert_eq!(hex::encode(m.principal_sig.0), VECTORS[12]);
    assert_eq!(m.verify_signature(), Ok(()));
}

/// Also recomputed independently by `tools/vectors.py` (hashlib +
/// `cryptography`'s ChaCha20Poly1305), which checks every vector in SPEC.md.
const VECTORS: [&str; 13] = [
    "69b1f5ad126e00c4f741eab035dc593a23728edb32ee92d98dfd442272842463",
    "02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc",
    "1b7e1354b4a7b7f40ad290a740585505a2001a",
    "977fe68aefda363451d6526e3598975c18f39fa3399a792e16650319448f36be",
    "0a3c3833260ed33c76cd735d4b005686f15f14b38f1aaa0422ac95e17797f5a0",
    "9aa91b2878399b36576180833e32dcd2b7f793b9c89dc24300cd4f1e35dcf3ea",
    "9e2497098d49db24713ed622b7220e02fa38b646b7e11925614d73ecfc746242",
    "48b2ecc5eccf1ec9f13e74019ff6a45aa7aae444a3cae5f4338f28aff28e39b8",
    "0e5dd77c4975f961abf06701b79ec912900f3ce5fc0cacb08856b92a5e8fc105",
    "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242",
    "34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746",
    "768febe650b08741e15fb538587b359df87bd48a6e78f7b93cfa7f7a5424c772",
    "60e9f0b666227078f8c10dadadd1862b9ba54be3d14ac6014a743cc5540d76f20d2a3ae5cf030a8d20975bf99248aef53e787ee8b9473853b04d6edc5bf09a0e",
];

#[test]
fn unknown_json_fields_are_rejected() {
    let (fx, _bundle, _binding) = verified((TestSuiteJob, clamp_suite()));
    let mut v: serde_json::Value = serde_json::to_value(&fx.offer).unwrap();
    v["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<Offer>(v).is_err());
}

// ---------------------------------------------------------------------------
// Mandates (SPEC 2.1), payout rule (SPEC 8.3), receipts and refusals to the
// principal (SPEC 5.4), job-class registry (SPEC 6.4), metrics (SPEC 14)

fn sudoku4() -> (SudokuJob, Vec<u8>, Vec<u8>) {
    let job = SudokuJob::four();
    let input = job.parse_grid("1..4 ..1. .1.. 4..1").unwrap();
    let sol = job.solve(&input).unwrap();
    (job, input, sol)
}

fn open(ledger: &mut Ledger, p: &Party, funds: u64) {
    ledger.open_principal_node(&p.agent.mandate().payout_node, p.principal_key(), funds);
}

fn sell_cfg(price: u64) -> SellerConfig {
    SellerConfig {
        price_msat: price,
        ..SellerConfig::default()
    }
}

fn new_buyer(agent: &Agent, max: u64, now: u64) -> Result<(Buyer, Request), PcpError> {
    let (job, input, _) = sudoku4();
    Buyer::new(
        agent,
        Box::new(job),
        Box::new(InsecureDevTransparentBackend),
        dev_policy(),
        input,
        max,
        now,
        &mut OsRng,
    )
}

fn new_seller(agent: &Agent, price: u64) -> Seller {
    Seller::new(
        agent,
        Box::new(SudokuJob::four()),
        Box::new(InsecureDevTransparentBackend),
        sell_cfg(price),
    )
}

/// One sudoku-4 deal between two agents on a shared ledger. A seller
/// refusal is reported to the buyer (and logged on both sides) and returned.
fn deal(ledger: &mut Ledger, buyer: &Agent, seller: &Agent, price: u64) -> Result<(), PcpError> {
    let (_, _, sol) = sudoku4();
    let (mut b, req) = new_buyer(buyer, 5 * PRICE, ledger.now())?;
    let mut s = new_seller(seller, price);
    let offer = match s.make_offer(&req, ledger.now()) {
        Ok(o) => o,
        Err(e) => {
            b.refused_by_seller(&e);
            return Err(e);
        }
    };
    b.accept_offer(&offer, ledger.now())?;
    let (bundle, binding) = s.fulfil(&req, &offer, sol, ledger, &mut OsRng)?;
    b.verify_bundle(&bundle)?;
    b.check_invoice(&binding, ledger.now())?;
    b.pay(ledger)?;
    s.settle_paid(ledger);
    assert_eq!(b.poll(ledger)?, BuyerProgress::Delivered);
    Ok(())
}

fn last_reason(agent: &Agent) -> String {
    agent
        .log()
        .refusals()
        .last()
        .expect("a refusal")
        .reason
        .clone()
}

#[test]
fn missing_mandate_is_refused_by_both_sides() {
    let bp = party(terms(Role::Buyer, "b"));
    let sp = party(terms(Role::Seller, "s"));
    let mut s = new_seller(&sp.agent, PRICE);

    // Seller side: a request with no mandate, or no agent signature.
    let (_, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    for strip in [
        (|r: &mut Request| r.mandate = None) as fn(&mut Request),
        |r| r.agent_sig = None,
    ] {
        let mut bare = req.clone();
        strip(&mut bare);
        assert_eq!(
            s.make_offer(&bare, 0),
            Err(PcpError::CounterpartyMandate(MandateError::Missing))
        );
        assert_eq!(last_reason(&sp.agent), "counterparty_mandate.missing");
    }
    // A mandate-free request also survives the wire as mandate-free.
    let mut bare = req.clone();
    bare.mandate = None;
    bare.agent_sig = None;
    let json = serde_json::to_string(&bare).unwrap();
    assert!(!json.contains("mandate\""));
    let back: Request = serde_json::from_str(&json).unwrap();
    assert_eq!(back.mandate, None);

    // Buyer side: an offer with no mandate, or no agent signature.
    for strip in [(|o: &mut Offer| o.mandate = None) as fn(&mut Offer), |o| {
        o.agent_sig = None
    }] {
        let (mut b, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
        let mut offer = s.make_offer(&req, 0).unwrap();
        strip(&mut offer);
        assert_eq!(
            b.accept_offer(&offer, 0),
            Err(PcpError::CounterpartyMandate(MandateError::Missing))
        );
        assert_eq!(last_reason(&bp.agent), "counterparty_mandate.missing");
    }
}

#[test]
fn wrong_signatures_are_refused() {
    let bp = party(terms(Role::Buyer, "b"));
    let sp = party(terms(Role::Seller, "s"));
    let mut s = new_seller(&sp.agent, PRICE);
    let (_, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();

    // The agent raises its own cap after the principal signed.
    let mut r = req.clone();
    r.mandate.as_mut().unwrap().cap_msat = u64::MAX;
    assert_eq!(
        s.make_offer(&r, 0),
        Err(PcpError::CounterpartyMandate(
            MandateError::SignatureInvalid
        ))
    );
    // The mandate names a different principal than the one who signed.
    let mut r = req.clone();
    r.mandate.as_mut().unwrap().principal_key = SecretKey::generate(&mut OsRng).public_key();
    assert_eq!(
        s.make_offer(&r, 0),
        Err(PcpError::CounterpartyMandate(
            MandateError::SignatureInvalid
        ))
    );
    // A valid mandate presented by someone without its agent key: the
    // request is signed by another agent.
    let other = party(terms(Role::Buyer, "x"));
    let mut r = resign_request(&other.agent, req.clone());
    r.mandate = req.mandate.clone();
    assert_eq!(
        s.make_offer(&r, 0),
        Err(PcpError::CounterpartyMandate(
            MandateError::AgentSignatureInvalid
        ))
    );
    // The request terms changed after the agent signed.
    let mut r = req.clone();
    r.mandate_spent_msat = 0;
    r.max_price_msat += 1;
    assert_eq!(
        s.make_offer(&r, 0),
        Err(PcpError::CounterpartyMandate(
            MandateError::AgentSignatureInvalid
        ))
    );

    // Buyer side: a stolen seller mandate on an offer signed by another agent.
    let thief = party(terms(Role::Seller, "s"));
    let (mut b, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    let mut o = manual_offer(&thief.agent, &req, PRICE, "s");
    o.mandate = Some(sp.agent.mandate().clone());
    assert_eq!(
        b.accept_offer(&o, 0),
        Err(PcpError::CounterpartyMandate(
            MandateError::AgentSignatureInvalid
        ))
    );

    // An agent key that is not the mandate's.
    let m = sp.agent.mandate().clone();
    assert_eq!(
        Agent::new(SecretKey::generate(&mut OsRng), m).err(),
        Some(PcpError::OwnMandate(MandateError::AgentKeyMismatch))
    );
}

#[test]
fn agent_may_not_be_its_own_principal() {
    // A principal that authorises its own key: refused when building the
    // agent, and refused by counterparties.
    let p = SecretKey::from_seed([9u8; 32]);
    let m = Mandate::sign(&p, p.public_key(), terms(Role::Buyer, "p"), &mut OsRng);
    assert_eq!(m.verify_signature(), Err(MandateError::SelfOwned));
    assert_eq!(
        Agent::new(SecretKey::from_seed([9u8; 32]), m.clone()).err(),
        Some(PcpError::OwnMandate(MandateError::SelfOwned))
    );

    let bp = party(terms(Role::Buyer, "b"));
    let sp = party(terms(Role::Seller, "s"));
    let (_, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    let mut r = req.clone();
    r.agent_sig = Some(p.sign(&r.auth_message(&m.mandate_id())));
    r.mandate = Some(m);
    assert_eq!(
        new_seller(&sp.agent, PRICE).make_offer(&r, 0),
        Err(PcpError::CounterpartyMandate(MandateError::SelfOwned))
    );
}

#[test]
fn expired_mandates_are_refused() {
    let short = |role, node: &str| MandateTerms {
        expires_at: 100,
        ..terms(role, node)
    };
    // Own mandate expired: the buyer does not even send the request.
    let bp = party(short(Role::Buyer, "b"));
    assert_eq!(
        new_buyer(&bp.agent, PRICE, 100).err(),
        Some(PcpError::OwnMandate(MandateError::Expired))
    );
    assert_eq!(last_reason(&bp.agent), "own_mandate.expired");

    // Buyer's mandate expired by the time the seller sees the request.
    let sp = party(terms(Role::Seller, "s"));
    let (_, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    assert_eq!(
        new_seller(&sp.agent, PRICE).make_offer(&req, 100),
        Err(PcpError::CounterpartyMandate(MandateError::Expired))
    );

    // Seller's mandate expired by the time the buyer sees the offer.
    let sp = party(short(Role::Seller, "s"));
    let bp = party(terms(Role::Buyer, "b"));
    let (mut b, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    let offer = new_seller(&sp.agent, PRICE).make_offer(&req, 0).unwrap();
    assert_eq!(
        b.accept_offer(&offer, 100),
        Err(PcpError::CounterpartyMandate(MandateError::Expired))
    );

    // Own mandate expires between accepting and paying: no payment.
    let bp = party(short(Role::Buyer, "b"));
    let sp = party(terms(Role::Seller, "s"));
    let mut ledger = Ledger::new();
    open(&mut ledger, &bp, BUYER_FUNDS);
    open(&mut ledger, &sp, 0);
    let (_, _, sol) = sudoku4();
    let (mut b, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    let mut s = new_seller(&sp.agent, PRICE);
    let offer = s.make_offer(&req, 0).unwrap();
    b.accept_offer(&offer, 0).unwrap();
    let (bundle, binding) = s
        .fulfil(&req, &offer, sol, &mut ledger, &mut OsRng)
        .unwrap();
    b.verify_bundle(&bundle).unwrap();
    b.check_invoice(&binding, 0).unwrap();
    ledger.advance(100);
    assert_eq!(
        b.pay(&mut ledger),
        Err(PcpError::OwnMandate(MandateError::Expired))
    );
    assert_eq!(ledger.balance("b"), BUYER_FUNDS);
    assert_eq!(bp.agent.committed_msat(), 0);
}

#[test]
fn scope_mismatch_is_refused() {
    let only9 = |role, node: &str| MandateTerms {
        scope: vec![SudokuJob::nine().spec_hash()],
        ..terms(role, node)
    };
    // Buyer's own scope does not cover sudoku 4x4.
    let narrow_b = party(only9(Role::Buyer, "b"));
    assert_eq!(
        new_buyer(&narrow_b.agent, PRICE, 0).err(),
        Some(PcpError::OwnMandate(MandateError::ScopeMismatch))
    );
    // The seller sees a buyer mandate that does not cover the job.
    let bp = party(terms(Role::Buyer, "b"));
    let sp = party(terms(Role::Seller, "s"));
    let (_, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    let r = resign_request(&narrow_b.agent, req.clone());
    assert_eq!(
        new_seller(&sp.agent, PRICE).make_offer(&r, 0),
        Err(PcpError::CounterpartyMandate(MandateError::ScopeMismatch))
    );
    // The seller's own scope does not cover the job.
    let narrow_s = party(only9(Role::Seller, "s"));
    assert_eq!(
        new_seller(&narrow_s.agent, PRICE).make_offer(&req, 0),
        Err(PcpError::OwnMandate(MandateError::ScopeMismatch))
    );
    // The buyer sees a seller mandate that does not cover the job.
    let (mut b, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    let o = manual_offer(&narrow_s.agent, &req, PRICE, "s");
    assert_eq!(
        b.accept_offer(&o, 0),
        Err(PcpError::CounterpartyMandate(MandateError::ScopeMismatch))
    );
    // A mandate for the wrong role.
    let (mut b, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    let o = manual_offer(&bp.agent, &req, PRICE, "b");
    assert_eq!(
        b.accept_offer(&o, 0),
        Err(PcpError::CounterpartyMandate(MandateError::WrongRole))
    );
}

#[test]
fn cap_is_enforced_across_deals() {
    let mut ledger = Ledger::new();
    let sp = party(terms(Role::Seller, "s"));
    open(&mut ledger, &sp, 0);

    // Cap of exactly two deals: the third is refused by the buyer's own
    // client before any request leaves.
    let bp = party(MandateTerms {
        cap_msat: 2 * PRICE,
        ..terms(Role::Buyer, "b")
    });
    open(&mut ledger, &bp, BUYER_FUNDS);
    deal(&mut ledger, &bp.agent, &sp.agent, PRICE).unwrap();
    deal(&mut ledger, &bp.agent, &sp.agent, PRICE).unwrap();
    assert_eq!(bp.agent.remaining_msat(), 0);
    assert_eq!(
        deal(&mut ledger, &bp.agent, &sp.agent, PRICE),
        Err(PcpError::OwnMandate(MandateError::CapExceeded {
            cap: 2 * PRICE,
            committed: 2 * PRICE,
            price: 5 * PRICE
        }))
    );
    assert_eq!(ledger.balance("b"), BUYER_FUNDS - 2 * PRICE);

    // Cap of 2.5 deals: the third request goes out, and the seller refuses
    // it from the buyer's declared spend.
    let bp = party(MandateTerms {
        cap_msat: 5 * PRICE / 2,
        ..terms(Role::Buyer, "b2")
    });
    open(&mut ledger, &bp, BUYER_FUNDS);
    deal(&mut ledger, &bp.agent, &sp.agent, PRICE).unwrap();
    deal(&mut ledger, &bp.agent, &sp.agent, PRICE).unwrap();
    let cap_err = MandateError::CapExceeded {
        cap: 5 * PRICE / 2,
        committed: 2 * PRICE,
        price: PRICE,
    };
    assert_eq!(
        deal(&mut ledger, &bp.agent, &sp.agent, PRICE),
        Err(PcpError::CounterpartyMandate(cap_err.clone()))
    );
    assert_eq!(last_reason(&sp.agent), "counterparty_mandate.cap_exceeded");
    assert_eq!(
        last_reason(&bp.agent),
        "refused_by_counterparty.counterparty_mandate.cap_exceeded"
    );
    // A seller that skips its checks gets refused by the buyer's own client.
    let (mut b, req) = new_buyer(&bp.agent, 5 * PRICE, 0).unwrap();
    let o = manual_offer(&sp.agent, &req, PRICE, "s");
    assert_eq!(b.accept_offer(&o, 0), Err(PcpError::OwnMandate(cap_err)));
    assert_eq!(ledger.balance("b2"), BUYER_FUNDS - 2 * PRICE);

    // Two purchases in flight at once share one cap: the second payment is
    // refused even though both offers were accepted.
    let bp = party(MandateTerms {
        cap_msat: 3 * PRICE / 2,
        ..terms(Role::Buyer, "b3")
    });
    open(&mut ledger, &bp, BUYER_FUNDS);
    let (_, _, sol) = sudoku4();
    let mut s = new_seller(&sp.agent, PRICE);
    let mut legs = Vec::new();
    for _ in 0..2 {
        let (mut b, req) = new_buyer(&bp.agent, PRICE, ledger.now()).unwrap();
        let offer = s.make_offer(&req, ledger.now()).unwrap();
        b.accept_offer(&offer, ledger.now()).unwrap();
        let (bundle, binding) = s
            .fulfil(&req, &offer, sol.clone(), &mut ledger, &mut OsRng)
            .unwrap();
        b.verify_bundle(&bundle).unwrap();
        b.check_invoice(&binding, ledger.now()).unwrap();
        legs.push(b);
    }
    legs[0].pay(&mut ledger).unwrap();
    assert!(matches!(
        legs[1].pay(&mut ledger),
        Err(PcpError::OwnMandate(MandateError::CapExceeded { .. }))
    ));
    assert_eq!(ledger.balance("b3"), BUYER_FUNDS - PRICE);
}

#[test]
fn refund_returns_the_reservation() {
    let mut ledger = Ledger::new();
    let sp = party(terms(Role::Seller, "s"));
    let bp = party(MandateTerms {
        cap_msat: PRICE,
        ..terms(Role::Buyer, "b")
    });
    open(&mut ledger, &sp, 0);
    open(&mut ledger, &bp, BUYER_FUNDS);
    let (_, _, sol) = sudoku4();
    let (mut b, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    let mut s = new_seller(&sp.agent, PRICE);
    let offer = s.make_offer(&req, 0).unwrap();
    b.accept_offer(&offer, 0).unwrap();
    let (bundle, binding) = s
        .fulfil(&req, &offer, sol, &mut ledger, &mut OsRng)
        .unwrap();
    b.verify_bundle(&bundle).unwrap();
    b.check_invoice(&binding, 0).unwrap();
    b.pay(&mut ledger).unwrap();
    assert_eq!(bp.agent.remaining_msat(), 0);
    ledger.advance(BuyerPolicy::default().htlc_secs);
    assert_eq!(b.poll(&mut ledger), Err(PcpError::Refunded));
    assert_eq!(bp.agent.remaining_msat(), PRICE);
    assert_eq!(last_reason(&bp.agent), "refunded");
    // The cap is usable again.
    deal(&mut ledger, &bp.agent, &sp.agent, PRICE).unwrap();
}

#[test]
fn per_deal_max_is_enforced() {
    let half = |role, node: &str| MandateTerms {
        per_deal_max_msat: PRICE / 2,
        ..terms(role, node)
    };
    let bp = party(terms(Role::Buyer, "b"));
    let sp = party(terms(Role::Seller, "s"));
    let small_b = party(half(Role::Buyer, "b"));
    let small_s = party(half(Role::Seller, "s"));
    let pd = MandateError::PerDealMaxExceeded {
        max: PRICE / 2,
        price: PRICE,
    };

    // Buyer's per-deal max: the seller refuses; and the buyer's own client
    // refuses an offer a modified seller sends anyway.
    let (mut b, req) = new_buyer(&small_b.agent, 5 * PRICE, 0).unwrap();
    assert_eq!(
        new_seller(&sp.agent, PRICE).make_offer(&req, 0),
        Err(PcpError::CounterpartyMandate(pd.clone()))
    );
    let o = manual_offer(&sp.agent, &req, PRICE, "s");
    assert_eq!(b.accept_offer(&o, 0), Err(PcpError::OwnMandate(pd.clone())));

    // Seller's per-deal max: the seller refuses its own offer; and the buyer
    // refuses one a modified seller sends anyway.
    let (mut b, req) = new_buyer(&bp.agent, 5 * PRICE, 0).unwrap();
    assert_eq!(
        new_seller(&small_s.agent, PRICE).make_offer(&req, 0),
        Err(PcpError::OwnMandate(pd.clone()))
    );
    let o = manual_offer(&small_s.agent, &req, PRICE, "s");
    assert_eq!(
        b.accept_offer(&o, 0),
        Err(PcpError::CounterpartyMandate(pd))
    );
}

#[test]
fn default_buyer_policy_has_a_per_deal_value_ceiling() {
    assert_eq!(BuyerPolicy::default().max_deal_msat, DEFAULT_MAX_DEAL_MSAT);
    let big = |role, node: &str| MandateTerms {
        cap_msat: 100 * DEFAULT_MAX_DEAL_MSAT,
        per_deal_max_msat: 10 * DEFAULT_MAX_DEAL_MSAT,
        ..terms(role, node)
    };
    let bp = party(big(Role::Buyer, "b"));
    let sp = party(big(Role::Seller, "s"));
    let price = DEFAULT_MAX_DEAL_MSAT + 1;
    let (_, input, _) = sudoku4();
    let mk = |policy: BuyerPolicy| {
        Buyer::new(
            &bp.agent,
            Box::new(SudokuJob::four()),
            Box::new(InsecureDevTransparentBackend),
            policy,
            input.clone(),
            2 * price,
            0,
            &mut OsRng,
        )
        .unwrap()
    };
    // The mandate would allow it; the default policy does not.
    let (mut b, req) = mk(dev_policy());
    let offer = new_seller(&sp.agent, price).make_offer(&req, 0).unwrap();
    assert_eq!(
        b.accept_offer(&offer, 0),
        Err(PcpError::DealAboveCeiling {
            price,
            ceiling: DEFAULT_MAX_DEAL_MSAT
        })
    );
    // At the ceiling, and with the ceiling raised explicitly, it passes.
    let (mut b, req) = mk(dev_policy());
    let offer = new_seller(&sp.agent, DEFAULT_MAX_DEAL_MSAT)
        .make_offer(&req, 0)
        .unwrap();
    b.accept_offer(&offer, 0).unwrap();
    let (mut b, req) = mk(BuyerPolicy {
        max_deal_msat: price,
        ..dev_policy()
    });
    let offer = new_seller(&sp.agent, price).make_offer(&req, 0).unwrap();
    b.accept_offer(&offer, 0).unwrap();
}

#[test]
fn payee_must_be_the_seller_principals_payout_node() {
    // The seller agent names its own node in the offer instead of its
    // principal's: refused before anything is paid.
    let bp = party(terms(Role::Buyer, "b"));
    let sp = party(terms(Role::Seller, "s-principal"));
    let (mut b, req) = new_buyer(&bp.agent, PRICE, 0).unwrap();
    let o = manual_offer(&sp.agent, &req, PRICE, "s-agent-own-node");
    assert_eq!(
        b.accept_offer(&o, 0),
        Err(PcpError::CounterpartyMandate(
            MandateError::PayoutNodeMismatch
        ))
    );

    // The invoice pays a node other than the payout node.
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    assert_eq!(binding.invoice.payee, fx.sp.agent.mandate().payout_node);
    let mut bad = binding.clone();
    bad.invoice.payee = "seller-agent-own-node".into();
    assert_eq!(
        fx.buyer.check_invoice(&bad, fx.ledger.now()),
        Err(PcpError::InvoicePayeeMismatch)
    );
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
    assert_eq!(last_reason(&fx.bp.agent), "invoice_payee_mismatch");
}

#[test]
fn principals_can_verify_every_deal_and_refusal() {
    let mut ledger = Ledger::new();
    let sp = party(terms(Role::Seller, "s"));
    let bp = party(MandateTerms {
        cap_msat: 5 * PRICE / 2,
        ..terms(Role::Buyer, "b")
    });
    open(&mut ledger, &sp, 0);
    open(&mut ledger, &bp, BUYER_FUNDS);
    deal(&mut ledger, &bp.agent, &sp.agent, PRICE).unwrap();
    ledger.advance(10);
    deal(&mut ledger, &bp.agent, &sp.agent, PRICE).unwrap();
    assert!(deal(&mut ledger, &bp.agent, &sp.agent, PRICE).is_err());
    let jobs: [&dyn JobClass; 1] = [&SudokuJob::four()];

    for (p, deals, refusals) in [(&bp, 2, 1), (&sp, 2, 1)] {
        let log = p.agent.log();
        // Exported as JSON lines and read back by the principal.
        let text = log.to_jsonl();
        assert_eq!(text.lines().count(), deals + refusals);
        let back = PrincipalLog::from_jsonl(&text).unwrap();
        assert_eq!(back, log);
        let sum = back.verify(p.agent.mandate(), &jobs).unwrap();
        assert_eq!(
            (sum.deals, sum.refusals, sum.total_msat),
            (deals, refusals, 2 * PRICE)
        );
        assert_eq!(sum.reasons.values().sum::<usize>(), refusals);
    }

    // Both receipts of one sale name each other's mandates and principals.
    let br = bp.agent.log().receipts().next().unwrap().clone();
    let sr = sp.agent.log().receipts().next().unwrap().clone();
    assert_eq!(br.role, Role::Buyer);
    assert_eq!(sr.role, Role::Seller);
    assert_eq!(br.offer_id, sr.offer_id);
    assert_eq!(br.counterparty_mandate_id, sp.agent.mandate_id());
    assert_eq!(sr.counterparty_mandate_id, bp.agent.mandate_id());
    assert_eq!(br.counterparty_principal_key, sp.principal_key());
    assert!(!br.is_self_payment());

    // Tampering with any line is caught.
    let text = bp.agent.log().to_jsonl();
    let edited = text.replacen(
        &format!("\"amount_msat\":{PRICE}"),
        &format!("\"amount_msat\":{}", PRICE - 1),
        1,
    );
    assert_ne!(edited, text);
    let err = PrincipalLog::from_jsonl(&edited)
        .unwrap()
        .verify(bp.agent.mandate(), &jobs)
        .unwrap_err();
    assert_eq!(err.index, 0);
    assert_eq!(err.error, PcpError::RecordSignatureInvalid);
    let edited = text.replacen("refused_by_counterparty", "refused_by_xounterparty", 1);
    let err = PrincipalLog::from_jsonl(&edited)
        .unwrap()
        .verify(bp.agent.mandate(), &jobs)
        .unwrap_err();
    assert_eq!(
        (err.index, err.error),
        (2, PcpError::RecordSignatureInvalid)
    );

    // Another principal's mandate does not claim this log.
    let other = party(terms(Role::Buyer, "b"));
    assert_eq!(
        bp.agent
            .log()
            .verify(other.agent.mandate(), &jobs)
            .unwrap_err()
            .error,
        PcpError::RecordNotBound
    );

    // A forged deal (wrong preimage, re-signed by the agent itself) fails
    // the offline re-verification.
    let mut forged = bp.agent.log();
    let LogEntry::Deal { receipt, .. } = &mut forged.entries_mut()[0] else {
        panic!()
    };
    receipt.preimage = [0u8; 32];
    receipt.agent_sig = bp.agent.sign(&receipt.receipt_id());
    assert_eq!(
        forged.verify(bp.agent.mandate(), &jobs).unwrap_err().error,
        PcpError::PreimageMismatch
    );
}

/// A job class that is not in the reference registry.
#[derive(Clone, Copy)]
struct ReverseJob;

impl JobClass for ReverseJob {
    fn job_id(&self) -> &'static str {
        "test/reverse/v0"
    }
    fn params(&self) -> Vec<u8> {
        Vec::new()
    }
    fn check(&self, input: &[u8], result: &[u8]) -> bool {
        input.iter().rev().eq(result.iter())
    }
}

#[test]
fn unregistered_job_class_is_refused_by_default() {
    assert!(!JobRegistry::reference().contains(&ReverseJob.spec_hash()));
    let scope = |role, node: &str| MandateTerms {
        scope: vec![ReverseJob.spec_hash()],
        ..terms(role, node)
    };
    let bp = party(scope(Role::Buyer, "b"));
    let sp = party(scope(Role::Seller, "s"));
    let mk = |dev: bool| {
        Buyer::new(
            &bp.agent,
            Box::new(ReverseJob),
            Box::new(InsecureDevTransparentBackend),
            BuyerPolicy {
                allow_unregistered_job_classes: dev,
                ..dev_policy()
            },
            b"abc".to_vec(),
            PRICE,
            0,
            &mut OsRng,
        )
    };
    let seller = |dev: bool| {
        Seller::new(
            &sp.agent,
            Box::new(ReverseJob),
            Box::new(InsecureDevTransparentBackend),
            SellerConfig {
                price_msat: PRICE,
                allow_unregistered_job_classes: dev,
                ..SellerConfig::default()
            },
        )
    };
    assert_eq!(mk(false).err(), Some(PcpError::JobClassNotRegistered));
    assert_eq!(last_reason(&bp.agent), "job_class_not_registered");
    let (mut b, req) = mk(true).unwrap();
    assert_eq!(
        seller(false).make_offer(&req, 0),
        Err(PcpError::JobClassNotRegistered)
    );

    // With the development flag on both sides, the deal goes through.
    let mut ledger = Ledger::new();
    open(&mut ledger, &bp, BUYER_FUNDS);
    open(&mut ledger, &sp, 0);
    let mut s = seller(true);
    let offer = s.make_offer(&req, 0).unwrap();
    b.accept_offer(&offer, 0).unwrap();
    let (bundle, binding) = s
        .fulfil(&req, &offer, b"cba".to_vec(), &mut ledger, &mut OsRng)
        .unwrap();
    b.verify_bundle(&bundle).unwrap();
    b.check_invoice(&binding, 0).unwrap();
    b.pay(&mut ledger).unwrap();
    s.settle_paid(&mut ledger);
    assert_eq!(b.poll(&mut ledger), Ok(BuyerProgress::Delivered));
    assert_eq!(b.result().unwrap(), b"cba");
}

#[test]
fn self_payments_are_flagged_and_excluded_from_metrics() {
    let mut ledger = Ledger::new();
    // One principal, two agents, trading with itself.
    let seed = crypto::fresh_key(&mut OsRng);
    let b1 = party_with(SecretKey::from_seed(seed), terms(Role::Buyer, "p"));
    let s1 = party_with(SecretKey::from_seed(seed), terms(Role::Seller, "p"));
    let pk = b1.principal_key();
    assert_eq!(s1.principal_key(), pk);
    ledger.open_principal_node("p", pk, BUYER_FUNDS);
    deal(&mut ledger, &b1.agent, &s1.agent, PRICE).unwrap();

    // And one sale between strangers.
    let b2 = party(terms(Role::Buyer, "b"));
    let s2 = party(terms(Role::Seller, "s"));
    open(&mut ledger, &b2, BUYER_FUNDS);
    open(&mut ledger, &s2, 0);
    deal(&mut ledger, &b2.agent, &s2.agent, PRICE).unwrap();

    let logs = [
        b1.agent.log(),
        s1.agent.log(),
        b2.agent.log(),
        s2.agent.log(),
    ];
    let receipts: Vec<_> = logs.iter().flat_map(|l| l.receipts().cloned()).collect();
    assert_eq!(receipts.len(), 4);
    assert!(receipts[0].is_self_payment() && receipts[1].is_self_payment());
    assert!(!receipts[2].is_self_payment());
    let c = adoption_count(&receipts);
    assert_eq!((c.counted, c.self_payments), (1, 1));
}

// ---------------------------------------------------------------------------
// One source of truth for the relation, and rails

#[test]
fn dev_backend_proves_exactly_the_statement_core_journal() {
    use crate::statement::{evaluate, JournalMismatch};
    let job = SudokuJob::nine();
    let input = puzzle9();
    let result = job.solve(&input).unwrap();
    let k = crypto::fresh_key(&mut OsRng);
    let (offer_id, nonce) = ([5u8; 32], [6u8; 32]);
    let c = crypto::encrypt(&k, &offer_id, &result);
    let st = build_statement(
        &job,
        input_commitment(&input),
        offer_id,
        nonce,
        &c,
        crypto::payment_hash(&k),
    );
    let w = Witness {
        input,
        result,
        key: k,
    };
    // The journal a zkVM guest would commit is the statement, and its bytes
    // are the statement_hash pre-image.
    let journal = evaluate(&w.statement_input(&st, &c)).unwrap();
    assert_eq!(journal, st.journal());
    assert_eq!(crate::encoding::sha256(&journal.to_bytes()), st.hash());
    assert_eq!(crate::proof::Statement::from(journal), st);
    let bundle = InsecureDevTransparentBackend
        .prove(&job, &st, &c, &w)
        .unwrap();
    assert_eq!(
        InsecureDevTransparentBackend.verify(&job, &st, &bundle),
        Ok(())
    );

    // A statement naming another H: the relation holds for k, the journal
    // differs, and the backend refuses with the core's verdict.
    let mut other = st.clone();
    other.payment_hash = crypto::payment_hash(&[9u8; 32]);
    assert_eq!(
        evaluate(&w.statement_input(&other, &c))
            .unwrap()
            .check_expected(&other.journal()),
        Err(JournalMismatch::PaymentHash)
    );
    assert_eq!(
        InsecureDevTransparentBackend
            .prove(&job, &other, &c, &w)
            .err(),
        Some(ProveError::Unsatisfied(VerifyError::PaymentHashMismatch))
    );
}

#[test]
fn rail_must_match_the_offer() {
    // A buyer on the simulated rail refuses an offer for real Lightning.
    let sp = party(terms(Role::Seller, "seller"));
    let bp = party(terms(Role::Buyer, "buyer"));
    let (mut b, req) = Buyer::new(
        &bp.agent,
        Box::new(SudokuJob::nine()),
        Box::new(InsecureDevTransparentBackend),
        dev_policy(),
        puzzle9(),
        2 * PRICE,
        0,
        &mut OsRng,
    )
    .unwrap();
    let mut o = manual_offer(&sp.agent, &req, PRICE, "seller");
    o.rail = RAIL_BOLT11.to_string();
    let o = resign_offer(&sp.agent, o);
    assert_eq!(b.accept_offer(&o, 0), Err(PcpError::RailNotSupported));

    // A seller configured for real Lightning does not invoice on the
    // simulation.
    let mut fx = fixture(SudokuJob::nine(), puzzle9());
    let mut seller = Seller::new(
        &fx.sp.agent,
        Box::new(SudokuJob::nine()),
        Box::new(InsecureDevTransparentBackend),
        SellerConfig {
            price_msat: PRICE,
            rail: RAIL_BOLT11.to_string(),
            ..SellerConfig::default()
        },
    );
    let offer = seller.make_offer(&fx.req, 0).unwrap();
    assert_eq!(offer.rail, RAIL_BOLT11);
    let sol = SudokuJob::nine().solve(&fx.req.input).unwrap();
    assert_eq!(
        seller
            .fulfil(&fx.req, &offer, sol, &mut fx.ledger, &mut OsRng)
            .err(),
        Some(PcpError::RailNotSupported)
    );
}

#[test]
fn run_sale_drives_a_whole_sale_over_a_rail() {
    use crate::sale::{run_sale, SaleParams};
    let sp = party(terms(Role::Seller, "seller"));
    let bp = party(terms(Role::Buyer, "buyer"));
    let mut ledger = Ledger::new();
    ledger.open_principal_node("seller", sp.principal_key(), 0);
    ledger.open_principal_node("buyer", bp.principal_key(), BUYER_FUNDS);
    let job = SudokuJob::nine();
    let input = puzzle9();
    let solution = job.solve(&input).unwrap();
    let mut lines = Vec::new();
    let report = run_sale(
        &bp.agent,
        &sp.agent,
        &|| Box::new(SudokuJob::nine()),
        &|| Box::new(InsecureDevTransparentBackend),
        input,
        solution.clone(),
        SaleParams {
            max_price_msat: 2 * PRICE,
            buyer_policy: dev_policy(),
            seller_config: SellerConfig {
                price_msat: PRICE,
                ..SellerConfig::default()
            },
            max_waits: 5,
        },
        &mut ledger,
        &mut |l| lines.push(l.to_string()),
    )
    .unwrap();
    assert_eq!(report.result, solution);
    assert_eq!(report.receipt.amount_msat, PRICE);
    assert_eq!(ledger.principal_balance(&sp.principal_key()), PRICE);
    assert!(lines.iter().any(|l| l.starts_with("8 buyer has k")));
}

// ---------------------------------------------------------------------------
// S1: payment calls that fail, and sales that end without payment

/// A rail over the simulated ledger whose calls can be made to fail, to
/// model a lost reply or an unreachable node.
struct FlakyRail<'a> {
    inner: &'a mut Ledger,
    /// `pay_invoice` locks the HTLC, then reports an error (lost reply).
    pay_lost_reply: bool,
    /// `pay_invoice` reports an error without paying.
    pay_fails: bool,
    /// `lookup_payment` reports an error (node unreachable).
    lookup_fails: bool,
}

impl<'a> FlakyRail<'a> {
    fn new(inner: &'a mut Ledger) -> Self {
        FlakyRail {
            inner,
            pay_lost_reply: false,
            pay_fails: false,
            lookup_fails: false,
        }
    }
}

impl crate::rail::Rail for FlakyRail<'_> {
    fn rail_id(&self) -> &'static str {
        self.inner.rail_id()
    }
    fn now(&self) -> u64 {
        crate::rail::Rail::now(self.inner)
    }
    fn create_invoice(
        &mut self,
        req: &crate::rail::InvoiceRequest,
    ) -> Result<crate::lightning::Invoice, crate::rail::RailError> {
        crate::rail::Rail::create_invoice(self.inner, req)
    }
    fn pay_invoice(
        &mut self,
        payer: &str,
        invoice: &crate::lightning::Invoice,
        max_htlc_secs: u64,
    ) -> Result<(), crate::rail::RailError> {
        if self.pay_fails {
            return Err(crate::rail::RailError::Node("connection reset".into()));
        }
        self.inner.pay_invoice(payer, invoice, max_htlc_secs)?;
        if self.pay_lost_reply {
            return Err(crate::rail::RailError::Node("reply lost".into()));
        }
        Ok(())
    }
    fn settle_invoice(
        &mut self,
        payee: &str,
        h: &Hash32,
        k: [u8; 32],
    ) -> Result<(), crate::rail::RailError> {
        self.inner.settle_invoice(payee, h, k)
    }
    fn cancel_invoice(&mut self, payee: &str, h: &Hash32) -> Result<(), crate::rail::RailError> {
        self.inner.cancel_invoice(payee, h)
    }
    fn lookup_invoice(
        &mut self,
        h: &Hash32,
    ) -> Result<Option<crate::rail::IncomingHtlc>, crate::rail::RailError> {
        self.inner.lookup_invoice(h)
    }
    fn find_invoice(
        &mut self,
        h: &Hash32,
    ) -> Result<Option<crate::lightning::Invoice>, crate::rail::RailError> {
        self.inner.find_invoice(h)
    }
    fn lookup_payment(
        &mut self,
        payer: &str,
        h: &Hash32,
    ) -> Result<crate::rail::PaymentStatus, crate::rail::RailError> {
        if self.lookup_fails {
            return Err(crate::rail::RailError::Node("node unreachable".into()));
        }
        self.inner.lookup_payment(payer, h)
    }
}

#[test]
fn pay_with_lost_reply_and_unreachable_node_keeps_the_reservation() {
    // The HTLC leaves, the reply is lost, and the lookup that should find
    // it fails too. The buyer must not release the reservation: the money
    // is out. Once the node answers, the payment is found and stands.
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    fx.buyer.check_invoice(&binding, fx.ledger.now()).unwrap();
    {
        let mut rail = FlakyRail::new(&mut fx.ledger);
        rail.pay_lost_reply = true;
        rail.lookup_fails = true;
        assert!(matches!(
            fx.buyer.pay_via(&mut rail),
            Err(PcpError::Rail(crate::rail::RailError::Node(_)))
        ));
    }
    assert!(matches!(fx.buyer.state(), BuyerState::Paying { .. }));
    assert_eq!(fx.bp.agent.committed_msat(), PRICE);
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS - PRICE);
    // Paying again from Paying is refused; only recovery leaves it.
    assert!(matches!(
        fx.buyer.pay(&mut fx.ledger),
        Err(PcpError::WrongState(_))
    ));
    {
        let mut rail = FlakyRail::new(&mut fx.ledger);
        rail.lookup_fails = true;
        assert!(fx.buyer.recover_payment(&mut rail).is_err());
    }
    assert!(matches!(fx.buyer.state(), BuyerState::Paying { .. }));
    assert_eq!(fx.bp.agent.committed_msat(), PRICE);
    fx.buyer.recover_payment(&mut fx.ledger).unwrap();
    assert!(matches!(fx.buyer.state(), BuyerState::Paid { .. }));
    fx.seller.settle_paid(&mut fx.ledger);
    assert_eq!(fx.buyer.poll(&mut fx.ledger), Ok(BuyerProgress::Delivered));
    assert_eq!(fx.bp.agent.committed_msat(), PRICE);
    assert_atomic(&fx, "buyer");
}

#[test]
fn pay_with_lost_reply_is_found_by_the_lookup() {
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    fx.buyer.check_invoice(&binding, fx.ledger.now()).unwrap();
    let mut rail = FlakyRail::new(&mut fx.ledger);
    rail.pay_lost_reply = true;
    fx.buyer.pay_via(&mut rail).unwrap();
    assert!(matches!(fx.buyer.state(), BuyerState::Paid { .. }));
    assert_eq!(fx.bp.agent.committed_msat(), PRICE);
}

#[test]
fn pay_that_never_left_releases_and_can_be_retried() {
    let (mut fx, _bundle, binding) = verified((TestSuiteJob, clamp_suite()));
    fx.buyer.check_invoice(&binding, fx.ledger.now()).unwrap();
    {
        let mut rail = FlakyRail::new(&mut fx.ledger);
        rail.pay_fails = true;
        assert!(fx.buyer.pay_via(&mut rail).is_err());
    }
    assert!(matches!(
        fx.buyer.state(),
        BuyerState::InvoiceAccepted { .. }
    ));
    assert_eq!(fx.bp.agent.committed_msat(), 0);
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS);
    fx.buyer.pay(&mut fx.ledger).unwrap();
    fx.seller.settle_paid(&mut fx.ledger);
    assert_eq!(fx.buyer.poll(&mut fx.ledger), Ok(BuyerProgress::Delivered));
    assert_eq!(fx.ledger.balance("buyer"), BUYER_FUNDS - PRICE);
    assert_atomic(&fx, "buyer");
}

#[test]
fn seller_cap_exceeded_at_settle_cancels_the_htlc() {
    // A seller whose cap fits one sale quotes two buyers (each quote fits on
    // its own). Both pay. The first settles; the second would exceed the
    // cap, which only grows, so the seller cancels that HTLC at once and
    // the second buyer is refunded without waiting for the timeout.
    let sp = party(MandateTerms {
        cap_msat: PRICE,
        ..terms(Role::Seller, "seller")
    });
    let mut ledger = Ledger::new();
    ledger.open_principal_node("seller", sp.principal_key(), 0);
    let mut seller = Seller::new(
        &sp.agent,
        Box::new(TestSuiteJob),
        Box::new(InsecureDevTransparentBackend),
        SellerConfig {
            price_msat: PRICE,
            ..SellerConfig::default()
        },
    );
    let mut buyers = Vec::new();
    for name in ["b1", "b2"] {
        let bp = party(terms(Role::Buyer, name));
        ledger.open_principal_node(name, bp.principal_key(), BUYER_FUNDS);
        let (mut b, req) = Buyer::new(
            &bp.agent,
            Box::new(TestSuiteJob),
            Box::new(InsecureDevTransparentBackend),
            dev_policy(),
            clamp_suite(),
            2 * PRICE,
            ledger.now(),
            &mut OsRng,
        )
        .unwrap();
        let offer = seller.make_offer(&req, ledger.now()).unwrap();
        b.accept_offer(&offer, ledger.now()).unwrap();
        let (bundle, binding) = seller
            .fulfil(
                &req,
                &offer,
                CLAMP_OK.as_bytes().to_vec(),
                &mut ledger,
                &mut OsRng,
            )
            .unwrap();
        b.verify_bundle(&bundle).unwrap();
        b.check_invoice(&binding, ledger.now()).unwrap();
        b.pay(&mut ledger).unwrap();
        buyers.push((name, b, bp));
    }
    let out = seller.settle_paid(&mut ledger);
    let settled = out
        .iter()
        .filter(|o| matches!(o, SaleOutcome::Settled { .. }))
        .count();
    let cancelled: Vec<_> = out
        .iter()
        .filter_map(|o| match o {
            SaleOutcome::Cancelled { reason, .. } => Some(reason.code()),
            _ => None,
        })
        .collect();
    assert_eq!(settled, 1);
    assert_eq!(cancelled, ["own_mandate.cap_exceeded"]);
    assert_eq!(sp.agent.committed_msat(), PRICE);
    assert!(seller.settle_paid(&mut ledger).is_empty());
    let mut delivered = 0;
    let mut refunded = 0;
    for (name, mut b, _bp) in buyers {
        match b.poll(&mut ledger) {
            Ok(BuyerProgress::Delivered) => {
                delivered += 1;
                assert_eq!(ledger.balance(name), BUYER_FUNDS - PRICE);
            }
            Err(PcpError::Refunded) => {
                refunded += 1;
                assert_eq!(ledger.balance(name), BUYER_FUNDS);
            }
            other => panic!("{name}: {other:?}"),
        }
    }
    assert_eq!((delivered, refunded), (1, 1));
}

// ---------------------------------------------------------------------------
// S1: Accept, and restarts at every step

fn sim_seller_cfg() -> SellerConfig {
    SellerConfig {
        price_msat: PRICE,
        ..SellerConfig::default()
    }
}

/// A restarted seller: the snapshot and the log go through JSON, as they
/// would through a file, and the agent is rebuilt from its key.
fn restart_seller(p: &Party, seller: &Seller) -> (Agent, Seller) {
    let snap: SellerSnapshot =
        serde_json::from_str(&serde_json::to_string(&seller.snapshot()).unwrap()).unwrap();
    let log = PrincipalLog::from_jsonl(&seller.agent().log().to_jsonl()).unwrap();
    let agent = Agent::restore(
        SecretKey::from_seed(p.agent_seed),
        p.agent.mandate().clone(),
        snap.committed_msat(),
        log,
    )
    .unwrap();
    let s = Seller::restore(
        &agent,
        Box::new(TestSuiteJob),
        Box::new(InsecureDevTransparentBackend),
        sim_seller_cfg(),
        snap,
    )
    .unwrap();
    (agent, s)
}

/// A restarted buyer, the same way.
fn restart_buyer(p: &Party, buyer: &Buyer) -> (Agent, Buyer) {
    let snap: BuyerSnapshot =
        serde_json::from_str(&serde_json::to_string(&buyer.snapshot()).unwrap()).unwrap();
    let log = PrincipalLog::from_jsonl(&buyer.agent().log().to_jsonl()).unwrap();
    let agent = Agent::restore(
        SecretKey::from_seed(p.agent_seed),
        p.agent.mandate().clone(),
        snap.spent_msat,
        log,
    )
    .unwrap();
    let b = Buyer::restore(
        &agent,
        Box::new(TestSuiteJob),
        Box::new(InsecureDevTransparentBackend),
        dev_policy(),
        snap,
    )
    .unwrap();
    (agent, b)
}

/// Two principals on one ledger, a buyer that has sent its request and a
/// seller that has quoted. No proving yet.
struct Wire {
    ledger: Ledger,
    bp: Party,
    sp: Party,
    buyer: Buyer,
    seller: Seller,
    offer: Offer,
}

fn wire() -> Wire {
    let sp = party(terms(Role::Seller, "seller"));
    let bp = party(terms(Role::Buyer, "buyer"));
    let mut ledger = Ledger::new();
    ledger.open_principal_node("seller", sp.principal_key(), 0);
    ledger.open_principal_node("buyer", bp.principal_key(), BUYER_FUNDS);
    let (buyer, req) = Buyer::new(
        &bp.agent,
        Box::new(TestSuiteJob),
        Box::new(InsecureDevTransparentBackend),
        dev_policy(),
        clamp_suite(),
        2 * PRICE,
        ledger.now(),
        &mut OsRng,
    )
    .unwrap();
    let mut seller = Seller::new(
        &sp.agent,
        Box::new(TestSuiteJob),
        Box::new(InsecureDevTransparentBackend),
        sim_seller_cfg(),
    );
    let offer = seller.make_offer(&req, ledger.now()).unwrap();
    Wire {
        ledger,
        bp,
        sp,
        buyer,
        seller,
        offer,
    }
}

fn prove_count(seller: &Seller) -> usize {
    seller.snapshot().sales.len()
}

#[test]
fn accept_runs_the_work_once_and_repeats_resend() {
    let mut w = wire();
    w.buyer.accept_offer(&w.offer, w.ledger.now()).unwrap();
    let acc = w.buyer.accept_message().unwrap();
    let id = w.offer.offer_id();
    assert_eq!(w.seller.accept(&acc, w.ledger.now()), Ok(AcceptStep::Prove));
    // Repeated while the work runs: nothing to do, nothing logged.
    assert_eq!(
        w.seller.accept(&acc, w.ledger.now()),
        Ok(AcceptStep::Pending)
    );
    w.seller
        .prove(
            &id,
            CLAMP_OK.as_bytes().to_vec(),
            w.ledger.now(),
            &mut OsRng,
        )
        .unwrap();
    assert_eq!(
        w.seller.accept(&acc, w.ledger.now()),
        Ok(AcceptStep::Pending)
    );
    let (bundle, binding) = w.seller.invoice(&id, &mut w.ledger).unwrap();
    // Repeated after invoicing: the same bundle and binding again.
    assert_eq!(
        w.seller.accept(&acc, w.ledger.now()),
        Ok(AcceptStep::Resend(
            Box::new(bundle.clone()),
            Box::new(binding.clone())
        ))
    );
    assert_eq!(prove_count(&w.seller), 1);
    assert_eq!(w.seller.agent().log().refusals().count(), 0);
    w.buyer.verify_bundle(&bundle).unwrap();
    w.buyer.check_invoice(&binding, w.ledger.now()).unwrap();
    w.buyer.pay(&mut w.ledger).unwrap();
    w.seller.settle_paid(&mut w.ledger);
    assert_eq!(w.buyer.poll(&mut w.ledger), Ok(BuyerProgress::Delivered));
    assert!(w.seller.is_idle());
}

#[test]
fn accept_for_an_offer_not_issued_or_not_signed_is_refused_without_proving() {
    let mut w = wire();
    w.buyer.accept_offer(&w.offer, w.ledger.now()).unwrap();
    let good = w.buyer.accept_message().unwrap();
    // An offer id this seller never issued (a tampered or invented offer).
    let mut other = good.clone();
    other.offer_id = [7u8; 32];
    assert_eq!(
        w.seller.accept(&other, w.ledger.now()),
        Err(PcpError::OfferNotIssued)
    );
    // Unsigned.
    let mut bare = good.clone();
    bare.agent_sig = None;
    assert_eq!(
        w.seller.accept(&bare, w.ledger.now()).map_err(|e| e.code()),
        Err("counterparty_mandate.missing".to_string())
    );
    // Signed by another buyer agent (someone who saw the offer).
    let mallory = party(terms(Role::Buyer, "mallory"));
    let mut forged = good.clone();
    forged.mandate = Some(mallory.agent.mandate().clone());
    forged.agent_sig = Some(
        mallory
            .agent
            .sign(&forged.auth_message(&mallory.agent.mandate_id())),
    );
    assert_eq!(
        w.seller
            .accept(&forged, w.ledger.now())
            .map_err(|e| e.code()),
        Err("counterparty_mandate.agent_key_mismatch".to_string())
    );
    assert_eq!(prove_count(&w.seller), 0);
    assert_eq!(w.seller.agent().log().refusals().count(), 3);
    // The real buyer's accept still works.
    assert_eq!(
        w.seller.accept(&good, w.ledger.now()),
        Ok(AcceptStep::Prove)
    );
}

#[test]
fn an_offer_handed_back_with_a_lower_price_is_refused() {
    // The audit's S1 case: a buyer returns the offer with its own price.
    // The seller fulfils only the offer it signed.
    let mut w = wire();
    let mut cheap = w.offer.clone();
    cheap.price_msat = 1;
    let req = w.buyer.request().clone();
    assert_eq!(
        w.seller.fulfil(
            &req,
            &cheap,
            CLAMP_OK.as_bytes().to_vec(),
            &mut w.ledger,
            &mut OsRng
        ),
        Err(PcpError::OfferMismatch)
    );
    assert_eq!(prove_count(&w.seller), 0);
}

#[test]
fn a_request_sent_twice_gets_the_same_offer() {
    let mut w = wire();
    let req = w.buyer.request().clone();
    assert_eq!(
        w.seller.make_offer(&req, w.ledger.now()),
        Ok(w.offer.clone())
    );
    assert_eq!(w.seller.snapshot().offers.len(), 1);
}

#[test]
fn seller_restarts_after_proving_and_finds_the_invoice_it_created() {
    // B1: the invoice reached the node, the seller died before recording it.
    let mut w = wire();
    w.buyer.accept_offer(&w.offer, w.ledger.now()).unwrap();
    let acc = w.buyer.accept_message().unwrap();
    let id = w.offer.offer_id();
    w.seller.accept(&acc, w.ledger.now()).unwrap();
    w.seller
        .prove(
            &id,
            CLAMP_OK.as_bytes().to_vec(),
            w.ledger.now(),
            &mut OsRng,
        )
        .unwrap();
    // Saved here (k on disk, no invoice yet).
    let (_a, mut restarted) = restart_seller(&w.sp, &w.seller);
    let (_b0, first) = w.seller.invoice(&id, &mut w.ledger).unwrap();
    // The process dies; the restarted seller resumes from the saved state.
    assert_eq!(restarted.unfinished().len(), 1);
    let (bundle, binding) = restarted.invoice(&id, &mut w.ledger).unwrap();
    assert_eq!(binding, first, "the invoice found again is the one issued");
    w.seller = restarted;
    w.buyer.verify_bundle(&bundle).unwrap();
    w.buyer.check_invoice(&binding, w.ledger.now()).unwrap();
    w.buyer.pay(&mut w.ledger).unwrap();
    w.seller.settle_paid(&mut w.ledger);
    assert_eq!(w.buyer.poll(&mut w.ledger), Ok(BuyerProgress::Delivered));
    assert_eq!(w.seller.agent().log().receipts().count(), 1);
}

#[test]
fn every_step_survives_a_restart_on_both_sides() {
    // Restart both sides after every step and finish the sale. One receipt
    // on each side, caps restored from the saved records.
    let mut w = wire();
    let id = w.offer.offer_id();
    let restart = |w: &mut Wire| {
        let (_sa, s) = restart_seller(&w.sp, &w.seller);
        let (_ba, b) = restart_buyer(&w.bp, &w.buyer);
        w.seller = s;
        w.buyer = b;
    };
    restart(&mut w);
    w.buyer.accept_offer(&w.offer, w.ledger.now()).unwrap();
    restart(&mut w);
    let acc = w.buyer.accept_message().unwrap();
    w.seller.accept(&acc, w.ledger.now()).unwrap();
    restart(&mut w);
    w.seller
        .prove(
            &id,
            CLAMP_OK.as_bytes().to_vec(),
            w.ledger.now(),
            &mut OsRng,
        )
        .unwrap();
    restart(&mut w);
    let (bundle, binding) = w.seller.invoice(&id, &mut w.ledger).unwrap();
    restart(&mut w);
    w.buyer.verify_bundle(&bundle).unwrap();
    restart(&mut w);
    w.buyer.check_invoice(&binding, w.ledger.now()).unwrap();
    restart(&mut w);
    w.buyer.pay(&mut w.ledger).unwrap();
    restart(&mut w);
    assert_eq!(w.buyer.agent().committed_msat(), PRICE);
    assert!(matches!(
        w.seller.settle_paid(&mut w.ledger).as_slice(),
        [SaleOutcome::Settled { .. }]
    ));
    restart(&mut w);
    assert_eq!(w.seller.agent().committed_msat(), PRICE);
    assert!(w.seller.settle_paid(&mut w.ledger).is_empty());
    assert_eq!(w.buyer.poll(&mut w.ledger), Ok(BuyerProgress::Delivered));
    restart(&mut w);
    assert!(w.buyer.is_done());
    assert_eq!(w.buyer.result(), Ok(CLAMP_OK.as_bytes()));
    assert_eq!(w.buyer.agent().committed_msat(), PRICE);
    assert_eq!(w.buyer.agent().log().receipts().count(), 1);
    assert_eq!(w.seller.agent().log().receipts().count(), 1);
    let jobs: [&dyn JobClass; 1] = [&TestSuiteJob];
    w.buyer
        .agent()
        .log()
        .verify(w.bp.agent.mandate(), &jobs)
        .unwrap();
    w.seller
        .agent()
        .log()
        .verify(w.sp.agent.mandate(), &jobs)
        .unwrap();
}

#[test]
fn a_settle_saved_before_it_happened_is_recorded_once() {
    // B2: the seller saved its state, then settled at the node, then died
    // before saving again. The restarted seller sees the HTLC settled and
    // records the sale once: state and log were saved together.
    let mut w = wire();
    let id = w.offer.offer_id();
    w.buyer.accept_offer(&w.offer, w.ledger.now()).unwrap();
    let acc = w.buyer.accept_message().unwrap();
    w.seller.accept(&acc, w.ledger.now()).unwrap();
    w.seller
        .prove(
            &id,
            CLAMP_OK.as_bytes().to_vec(),
            w.ledger.now(),
            &mut OsRng,
        )
        .unwrap();
    let (bundle, binding) = w.seller.invoice(&id, &mut w.ledger).unwrap();
    w.buyer.verify_bundle(&bundle).unwrap();
    w.buyer.check_invoice(&binding, w.ledger.now()).unwrap();
    w.buyer.pay(&mut w.ledger).unwrap();
    let (_a, mut restarted) = restart_seller(&w.sp, &w.seller);
    w.seller.settle_paid(&mut w.ledger);
    // Dies here. Restart from the earlier save.
    assert!(matches!(
        restarted.settle_paid(&mut w.ledger).as_slice(),
        [SaleOutcome::Settled { .. }]
    ));
    assert!(restarted.settle_paid(&mut w.ledger).is_empty());
    assert_eq!(restarted.agent().log().receipts().count(), 1);
    assert_eq!(restarted.agent().committed_msat(), PRICE);
}

#[test]
fn buyer_restarted_in_paying_finds_the_payment() {
    let mut w = wire();
    let id = w.offer.offer_id();
    w.buyer.accept_offer(&w.offer, w.ledger.now()).unwrap();
    let acc = w.buyer.accept_message().unwrap();
    w.seller.accept(&acc, w.ledger.now()).unwrap();
    w.seller
        .prove(
            &id,
            CLAMP_OK.as_bytes().to_vec(),
            w.ledger.now(),
            &mut OsRng,
        )
        .unwrap();
    let (bundle, binding) = w.seller.invoice(&id, &mut w.ledger).unwrap();
    w.buyer.verify_bundle(&bundle).unwrap();
    w.buyer.check_invoice(&binding, w.ledger.now()).unwrap();
    // The payment leaves; the node is unreachable for the lookup; the buyer
    // saves `Paying` and dies.
    {
        let mut rail = FlakyRail::new(&mut w.ledger);
        rail.pay_lost_reply = true;
        rail.lookup_fails = true;
        assert!(w.buyer.pay_via(&mut rail).is_err());
    }
    let (_a, mut b) = restart_buyer(&w.bp, &w.buyer);
    assert!(matches!(b.state(), BuyerState::Paying { .. }));
    assert_eq!(b.agent().committed_msat(), PRICE);
    b.recover_payment(&mut w.ledger).unwrap();
    w.seller.settle_paid(&mut w.ledger);
    assert_eq!(b.poll(&mut w.ledger), Ok(BuyerProgress::Delivered));
    assert_eq!(w.ledger.balance("buyer"), BUYER_FUNDS - PRICE);
}

#[test]
fn buyer_gives_up_only_where_no_money_is_out() {
    let mut w = wire();
    // No offer within the wait.
    let (bp2, _) = (party(terms(Role::Buyer, "b2")), ());
    let (mut lonely, _req) = Buyer::new(
        &bp2.agent,
        Box::new(TestSuiteJob),
        Box::new(InsecureDevTransparentBackend),
        dev_policy(),
        clamp_suite(),
        PRICE,
        0,
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(lonely.check_timeouts(59, 60), None);
    assert_eq!(lonely.check_timeouts(60, 60), Some(PcpError::NoAnswer));
    assert!(lonely.is_done());
    // Offer accepted, never answered: gives up when the offer expires.
    w.buyer.accept_offer(&w.offer, w.ledger.now()).unwrap();
    assert_eq!(
        w.buyer.check_timeouts(w.offer.offer_expires_at - 1, 60),
        None
    );
    assert_eq!(
        w.buyer.check_timeouts(w.offer.offer_expires_at, 60),
        Some(PcpError::OfferExpired)
    );
    assert_eq!(
        w.buyer
            .agent()
            .log()
            .refusals()
            .map(|r| r.reason.clone())
            .collect::<Vec<_>>(),
        ["offer_expired"]
    );
    // Paid: never gives up, however late.
    let mut x = wire();
    let id = x.offer.offer_id();
    x.buyer.accept_offer(&x.offer, x.ledger.now()).unwrap();
    let acc = x.buyer.accept_message().unwrap();
    x.seller.accept(&acc, x.ledger.now()).unwrap();
    x.seller
        .prove(
            &id,
            CLAMP_OK.as_bytes().to_vec(),
            x.ledger.now(),
            &mut OsRng,
        )
        .unwrap();
    let (bundle, binding) = x.seller.invoice(&id, &mut x.ledger).unwrap();
    x.buyer.verify_bundle(&bundle).unwrap();
    x.buyer.check_invoice(&binding, x.ledger.now()).unwrap();
    x.buyer.pay(&mut x.ledger).unwrap();
    assert_eq!(x.buyer.check_timeouts(u64::MAX, 60), None);
}

#[test]
fn snapshots_from_another_schema_or_agent_are_refused() {
    let w = wire();
    let mut snap = w.seller.snapshot();
    snap.schema = 2;
    assert!(matches!(
        Seller::restore(
            &w.sp.agent,
            Box::new(TestSuiteJob),
            Box::new(InsecureDevTransparentBackend),
            sim_seller_cfg(),
            snap
        ),
        Err(PcpError::Version)
    ));
    let other = party(terms(Role::Buyer, "other"));
    assert!(matches!(
        Buyer::restore(
            &other.agent,
            Box::new(TestSuiteJob),
            Box::new(InsecureDevTransparentBackend),
            dev_policy(),
            w.buyer.snapshot()
        ),
        Err(PcpError::RecordNotBound)
    ));
    // A seller whose configured backend differs refuses the saved offers.
    struct OtherBackend;
    impl ProofBackend for OtherBackend {
        fn backend_id(&self) -> &'static str {
            "other/0"
        }
        fn is_secure(&self) -> bool {
            false
        }
        fn prove(
            &self,
            _: &dyn JobClass,
            _: &crate::proof::Statement,
            _: &[u8],
            _: &Witness,
        ) -> Result<ProofBundle, ProveError> {
            unreachable!()
        }
        fn verify(
            &self,
            _: &dyn JobClass,
            _: &crate::proof::Statement,
            _: &ProofBundle,
        ) -> Result<(), VerifyError> {
            unreachable!()
        }
    }
    assert!(matches!(
        Seller::restore(
            &w.sp.agent,
            Box::new(TestSuiteJob),
            Box::new(OtherBackend),
            sim_seller_cfg(),
            w.seller.snapshot()
        ),
        Err(PcpError::OfferMismatch)
    ));
}
