//! Fuzz harnesses for pcp (design note 17, Fable review 18).
//!
//! Each `fN_*` function takes arbitrary bytes and must never panic, never
//! hang, and never let a stranger's message move a party further than an
//! honest message would. `cargo fuzz run fN_*` (nightly) drives them with
//! libFuzzer; `cargo test` (stable) runs them over seeds and pseudo-random
//! inputs (tests/seeds.rs).
//!
//! Who sends the bytes:
//! - F1, F2: the network, to either role (JSON messages; the seller loop).
//! - F3: a seller, to the buyer (offer, bundle, invoice binding).
//! - F4: a receipt's journal and the guest input encoding.
//! - F5: job inputs (buyer to seller) and results (seller to buyer).
//! - F6: the disk (state.json written by an earlier run, maybe corrupted).
//! - F7: the LND node, or anything between it and us.

use std::sync::OnceLock;
use std::time::Instant;

use pcp::job::{JobClass, SudokuJob, TestSuiteJob};
use pcp::lightning::Ledger;
use pcp::mandate::{Agent, Mandate, MandateTerms, Role, SecretKey};
use pcp::node::wire::WireMsg;
use pcp::proof::{InsecureDevTransparentBackend, ProofBundle};
use pcp::protocol::{
    Accept, Buyer, BuyerPolicy, BuyerSnapshot, BuyerState, InvoiceBinding, Offer, Request, Seller,
    SellerConfig, SellerSnapshot,
};
use pcp::statement::{evaluate_with, known_job, Journal, StatementInput};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::Value;

// ---------------------------------------------------------------------------
// A fixed, deterministic world: one buyer, one seller, one honest sale.

const NOW: u64 = 1_000;
const PRICE: u64 = 1_500_000;

fn agent(seed: u64, role: Role, node: &str, scope: Vec<[u8; 32]>) -> Agent {
    agent_with(seed, role, node, scope, 2_000_000, 10_000_000)
}

fn agent_with(
    seed: u64,
    role: Role,
    node: &str,
    scope: Vec<[u8; 32]>,
    per_deal_max_msat: u64,
    cap_msat: u64,
) -> Agent {
    let mut rng = StdRng::seed_from_u64(seed);
    let principal = SecretKey::generate(&mut rng);
    let key = SecretKey::generate(&mut rng);
    let m = Mandate::sign(
        &principal,
        key.public_key(),
        MandateTerms {
            role,
            scope,
            cap_msat,
            per_deal_max_msat,
            payout_node: node.to_string(),
            expires_at: 86_400,
        },
        &mut rng,
    );
    Agent::new(key, m).expect("mandate verifies")
}

fn job() -> SudokuJob {
    SudokuJob::four()
}

fn puzzle() -> Vec<u8> {
    job().parse_grid("1..4 ..1. .1.. 4..1").expect("puzzle")
}

fn policy() -> BuyerPolicy {
    BuyerPolicy {
        allow_insecure_dev_backend: true,
        ..BuyerPolicy::default()
    }
}

/// A fresh buyer, the same every time (same keys, same nonce).
fn buyer() -> (Buyer, Request) {
    let a = agent(1, Role::Buyer, "alice-node", vec![job().spec_hash()]);
    let mut rng = StdRng::seed_from_u64(11);
    Buyer::new(
        &a,
        Box::new(job()),
        Box::new(InsecureDevTransparentBackend),
        policy(),
        puzzle(),
        2_000_000,
        NOW,
        &mut rng,
    )
    .expect("buyer")
}

fn seller() -> Seller {
    let a = agent(2, Role::Seller, "bob-node", vec![job().spec_hash()]);
    Seller::new(
        &a,
        Box::new(job()),
        Box::new(InsecureDevTransparentBackend),
        SellerConfig {
            price_msat: PRICE,
            ..SellerConfig::default()
        },
    )
}

/// The honest transcript, as JSON: request, offer, bundle, binding.
pub struct Honest {
    pub request: Value,
    pub offer: Value,
    pub bundle: Value,
    pub binding: Value,
    pub seller_snapshot: Value,
    pub buyer_snapshot: Value,
}

pub fn honest() -> &'static Honest {
    static H: OnceLock<Honest> = OnceLock::new();
    H.get_or_init(|| {
        let (mut b, req) = buyer();
        let mut s = seller();
        let mut ledger = Ledger::new();
        ledger.advance(NOW);
        let bp = agent(1, Role::Buyer, "alice-node", vec![]);
        let sp = agent(2, Role::Seller, "bob-node", vec![]);
        ledger.open_principal_node("alice-node", bp.mandate().principal_key, 5_000_000);
        ledger.open_principal_node("bob-node", sp.mandate().principal_key, 0);
        let offer = s.make_offer(&req, NOW).expect("offer");
        b.accept_offer(&offer, NOW).expect("accept offer");
        let result = job().solve(&puzzle()).expect("solvable");
        let mut rng = StdRng::seed_from_u64(22);
        let (bundle, binding) = s
            .fulfil(&req, &offer, result, &mut ledger, &mut rng)
            .expect("fulfil");
        b.verify_bundle(&bundle).expect("honest bundle verifies");
        b.check_invoice(&binding, NOW)
            .expect("honest invoice checks");
        let j = |v: &dyn erased::Ser| v.json();
        Honest {
            request: j(&req),
            offer: j(&offer),
            bundle: j(&bundle),
            binding: j(&binding),
            seller_snapshot: j(&s.snapshot()),
            buyer_snapshot: j(&b.snapshot()),
        }
    })
}

mod erased {
    pub trait Ser {
        fn json(&self) -> serde_json::Value;
    }
    impl<T: serde::Serialize> Ser for T {
        fn json(&self) -> serde_json::Value {
            serde_json::to_value(self).expect("serializes")
        }
    }
}

/// Small reader over fuzz bytes.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn u8(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }
    fn u16(&mut self) -> u16 {
        u16::from(self.u8()) << 8 | u16::from(self.u8())
    }
    fn rest(&mut self) -> &[u8] {
        std::mem::take(&mut self.0)
    }
}

/// Every leaf of a JSON value, as a path of keys and indices.
fn leaves(v: &Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                path.push(k.clone());
                leaves(x, path, out);
                path.pop();
            }
        }
        Value::Array(a) if !a.is_empty() && a.len() <= 64 => {
            for (i, x) in a.iter().enumerate() {
                path.push(i.to_string());
                leaves(x, path, out);
                path.pop();
            }
        }
        _ => out.push(path.clone()),
    }
}

fn at<'v>(v: &'v mut Value, path: &[String]) -> Option<&'v mut Value> {
    let mut cur = v;
    for p in path {
        cur = match cur {
            Value::Object(m) => m.get_mut(p)?,
            Value::Array(a) => a.get_mut(p.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Replace one leaf of `v` by a value read from `b`: a nearby number, a
/// flipped hex digit, a JSON value, or a string.
fn mutate(v: &Value, b: &mut Bytes) -> (Value, Vec<String>) {
    let mut paths = Vec::new();
    leaves(v, &mut Vec::new(), &mut paths);
    let path = paths[b.u16() as usize % paths.len()].clone();
    let mut m = v.clone();
    let kind = b.u8() % 4;
    let leaf = at(&mut m, &path).expect("leaf exists");
    *leaf = match (kind, leaf.clone()) {
        (0, Value::Number(n)) => {
            let x = n.as_u64().unwrap_or(0);
            let d = u64::from(b.u8());
            Value::from(if b.u8() & 1 == 0 {
                x.wrapping_add(d)
            } else {
                x.wrapping_sub(d)
            })
        }
        (0 | 1, Value::String(s)) if !s.is_empty() => {
            let mut c: Vec<char> = s.chars().collect();
            let i = b.u16() as usize % c.len();
            c[i] = char::from(b"0123456789abcdefABCDEF xg"[b.u8() as usize % 25]);
            Value::String(c.into_iter().collect())
        }
        (2, _) => serde_json::from_slice(b.rest()).unwrap_or(Value::Null),
        _ => Value::String(String::from_utf8_lossy(b.rest()).into_owned()),
    };
    (m, path)
}

// ---------------------------------------------------------------------------
// F1: JSON messages from the network.

pub fn f1_messages(data: &[u8]) {
    fn round<T: serde::Serialize + serde::de::DeserializeOwned>(data: &[u8]) {
        if let Ok(x) = serde_json::from_slice::<T>(data) {
            let once = serde_json::to_vec(&x).expect("serializes");
            let again: T = serde_json::from_slice(&once).expect("own output decodes");
            assert_eq!(
                once,
                serde_json::to_vec(&again).expect("serializes"),
                "unstable encoding"
            );
        }
    }
    round::<Request>(data);
    round::<Offer>(data);
    round::<Accept>(data);
    round::<ProofBundle>(data);
    round::<InvoiceBinding>(data);
    round::<WireMsg>(data);
    round::<BuyerSnapshot>(data);
    round::<SellerSnapshot>(data);
    if let Ok(r) = serde_json::from_slice::<Request>(data) {
        let _ = r.request_id();
    }
    if let Ok(o) = serde_json::from_slice::<Offer>(data) {
        let _ = o.offer_id();
    }
}

// ---------------------------------------------------------------------------
// F2: the seller, fed requests and accepts from strangers.

pub fn f2_seller(data: &[u8]) {
    let h = honest();
    let mut b = Bytes(data);
    let mut s = seller();
    for _ in 0..(b.u8() % 6 + 1) {
        let which = b.u8() % 3;
        let now = NOW + u64::from(b.u8()) * 10;
        match which {
            0 => {
                let (v, _) = mutate(&h.request, &mut b);
                if let Ok(req) = serde_json::from_value::<Request>(v) {
                    let _ = s.make_offer(&req, now);
                }
            }
            1 => {
                if let Ok(req) = serde_json::from_value::<Request>(h.request.clone()) {
                    if let Ok(offer) = s.make_offer(&req, now) {
                        let acc = Accept {
                            version: "PCP/0".into(),
                            offer_id: offer.offer_id(),
                            mandate: req.mandate.clone(),
                            agent_sig: None,
                        };
                        let (v, _) = mutate(&serde_json::to_value(&acc).unwrap(), &mut b);
                        if let Ok(acc) = serde_json::from_value::<Accept>(v) {
                            let _ = s.accept(&acc, now);
                        }
                    }
                }
            }
            _ => {
                if let Ok(acc) = serde_json::from_slice::<Accept>(b.rest()) {
                    let _ = s.accept(&acc, now);
                }
            }
        }
        // Nothing a stranger sends starts work without a valid signed Accept.
        assert!(
            s.unfinished().is_empty(),
            "work started without a valid Accept"
        );
    }
}

// ---------------------------------------------------------------------------
// F3: the buyer, fed the honest seller's messages with one field changed.

/// Fields whose change an honest buyer may accept: the BOLT11 string is
/// checked by the buyer's node only at payment, and the invoice's timing
/// may move inside the buyer's limits.
fn may_change(path: &[String]) -> bool {
    matches!(
        path.last().map(String::as_str),
        Some("bolt11" | "created_at" | "expiry_secs" | "min_htlc_secs")
    )
}

pub fn f3_buyer(data: &[u8]) {
    let _ = f3_outcome(data);
}

/// F3, reporting (a bound field changed, the buyer reached InvoiceAccepted).
pub fn f3_outcome(data: &[u8]) -> (bool, bool) {
    let h = honest();
    let mut b = Bytes(data);
    let target = b.u8() % 3;
    let (offer, bundle, binding, changed) = {
        let (mut o, mut bu, mut bi) = (h.offer.clone(), h.bundle.clone(), h.binding.clone());
        let slot = match target {
            0 => &mut o,
            1 => &mut bu,
            _ => &mut bi,
        };
        let (m, path) = mutate(slot, &mut b);
        let changed = m != *slot && !may_change(&path);
        *slot = m;
        (o, bu, bi, changed)
    };
    let (Ok(offer), Ok(bundle), Ok(binding)) = (
        serde_json::from_value::<Offer>(offer),
        serde_json::from_value::<ProofBundle>(bundle),
        serde_json::from_value::<InvoiceBinding>(binding),
    ) else {
        return (changed, false);
    };
    let (mut buyer, _) = buyer();
    let _ = buyer
        .accept_offer(&offer, NOW)
        .and_then(|_| buyer.verify_bundle(&bundle))
        .and_then(|_| buyer.check_invoice(&binding, NOW));
    if let BuyerState::InvoiceAccepted {
        offer,
        statement,
        invoice,
        ..
    } = buyer.state()
    {
        // A changed bound field must never get here.
        assert!(!changed, "a changed field passed every check");
        // Whatever got here pays the right hash, amount and node.
        assert_eq!(invoice.payment_hash, statement.payment_hash);
        assert_eq!(invoice.amount_msat, offer.price_msat);
        assert_eq!(invoice.payee, offer.seller_node);
        assert_eq!(statement.offer_id, offer.offer_id());
        return (changed, true);
    }
    (changed, false)
}

// ---------------------------------------------------------------------------
// F4: the guest input encoding and the journal.

pub fn f4_statement(data: &[u8]) {
    if let Some(si) = StatementInput::decode(data) {
        assert_eq!(
            si.encode(),
            data,
            "StatementInput decode/encode is not exact"
        );
        if let Some(job) = known_job(&si.spec_hash) {
            let _ = evaluate_with(job, &si);
        }
        let _ = evaluate_with(&job(), &si);
    }
    if let Some(j) = Journal::from_bytes(data) {
        assert_eq!(j.to_bytes(), data, "Journal parse is not strict");
        let _ = j.statement_hash();
    }
}

// ---------------------------------------------------------------------------
// F5: job inputs and results from strangers. Bounded time.

pub fn f5_jobs(data: &[u8]) {
    let t = Instant::now();
    let mut b = Bytes(data);
    let split = b.u8() as usize;
    let rest = b.rest();
    let (x, y) = rest.split_at(split.min(rest.len()));
    for j in [SudokuJob::four(), SudokuJob::nine()] {
        let _ = j.check(x, y);
        if let Some(r) = pcp::node::work::solve_sudoku(&j, x, pcp::node::work::MAX_NODES) {
            assert!(j.check(x, &r), "the bounded solver returned a wrong grid");
        }
    }
    let _ = TestSuiteJob.check(x, y);
    let _ = TestSuiteJob::decode_suite(x);
    let _ = TestSuiteJob.run(x, y);
    assert!(
        t.elapsed().as_secs() < 10,
        "a job check or the bounded solver took {:?}",
        t.elapsed()
    );
}

// ---------------------------------------------------------------------------
// F6: state.json from disk, maybe corrupted. Restore refuses or restores;
// a restored party then never panics on a repeat message.

pub fn f6_restore(data: &[u8]) {
    let h = honest();
    let mut b = Bytes(data);
    let role = b.u8() % 2;
    let base = if role == 0 {
        &h.seller_snapshot
    } else {
        &h.buyer_snapshot
    };
    let (v, _) = mutate(base, &mut b);
    if role == 0 {
        let Ok(snap) = serde_json::from_value::<SellerSnapshot>(v) else {
            return;
        };
        let a = agent(2, Role::Seller, "bob-node", vec![job().spec_hash()]);
        let cfg = SellerConfig {
            price_msat: PRICE,
            ..SellerConfig::default()
        };
        if let Ok(mut s) = Seller::restore(
            &a,
            Box::new(job()),
            Box::new(InsecureDevTransparentBackend),
            cfg,
            snap.clone(),
        ) {
            let _ = s.unfinished();
            let _ = s.is_idle();
            // A repeated Accept for every saved offer (what a stranger can send).
            for o in &snap.offers {
                let acc = Accept {
                    version: "PCP/0".into(),
                    offer_id: o.offer.offer_id(),
                    mandate: o.request.mandate.clone(),
                    agent_sig: None,
                };
                let _ = s.accept(&acc, NOW);
            }
            let _ = s.snapshot();
        }
    } else {
        let Ok(snap) = serde_json::from_value::<BuyerSnapshot>(v) else {
            return;
        };
        let a = agent(1, Role::Buyer, "alice-node", vec![job().spec_hash()]);
        if let Ok(mut buyer) = Buyer::restore(
            &a,
            Box::new(job()),
            Box::new(InsecureDevTransparentBackend),
            policy(),
            snap,
        ) {
            let _ = buyer.check_timeouts(NOW + 10_000, 60);
            let _ = buyer.snapshot();
        }
    }
}

// ---------------------------------------------------------------------------
// F7: what the LND node sends back.

pub fn f7_lnd(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    pcp::rail::lnd::fuzzing::parse_all(&text, &[7u8; 32]);
}

// ---------------------------------------------------------------------------
// Differential corpus for an independent verifier (written from the SPEC,
// not from this code): the buyer's inputs and this implementation's verdict.

/// One case: the messages a buyer receives (one field possibly changed),
/// what the buyer knows, and where this implementation stopped and why.
pub fn differential_case(data: &[u8]) -> Option<Value> {
    let h = honest();
    let mut b = Bytes(data);
    let target = b.u8() % 4;
    let (mut o, mut bu, mut bi) = (h.offer.clone(), h.bundle.clone(), h.binding.clone());
    let mut changed_path = Vec::new();
    if target < 3 {
        let slot = match target {
            0 => &mut o,
            1 => &mut bu,
            _ => &mut bi,
        };
        let (m, path) = mutate(slot, &mut b);
        *slot = m;
        changed_path = path;
    }
    // A message that does not parse is an HTTP 400 at its stage (SPEC 5.5),
    // recorded rather than dropped (Fable review 29, item 5).
    let (mut buyer, _) = buyer();
    let p = policy();
    let verdict = (|| {
        let r400 = |stage: &str| serde_json::json!({ "stage": stage, "code": "http_400" });
        let Ok(offer) = serde_json::from_value::<Offer>(o.clone()) else {
            return r400("offer");
        };
        if let Err(e) = buyer.accept_offer(&offer, NOW) {
            return serde_json::json!({ "stage": "offer", "code": e.code() });
        }
        let Ok(bundle) = serde_json::from_value::<ProofBundle>(bu.clone()) else {
            return r400("bundle");
        };
        if let Err(e) = buyer.verify_bundle(&bundle) {
            return serde_json::json!({ "stage": "bundle", "code": e.code() });
        }
        let Ok(binding) = serde_json::from_value::<InvoiceBinding>(bi.clone()) else {
            return r400("invoice");
        };
        match buyer.check_invoice(&binding, NOW) {
            Err(e) => serde_json::json!({ "stage": "invoice", "code": e.code() }),
            Ok(()) => serde_json::json!({ "stage": "accepted", "code": null }),
        }
    })();
    Some(serde_json::json!({
        "changed": changed_path,
        "request": h.request,
        "offer": o,
        "bundle": bu,
        "binding": bi,
        "now": NOW,
        "buyer": {
            "max_price_msat": 2_000_000u64,
            "accepted_backend_id": "INSECURE-dev-transparent/0",
            "allow_insecure_dev_backend": p.allow_insecure_dev_backend,
            "htlc_secs": p.htlc_secs,
            "min_invoice_remaining_secs": p.min_invoice_remaining_secs,
            "max_deal_msat": p.max_deal_msat,
            "rail": p.rail,
            "payout_node": "alice-node",
        },
        "verdict": verdict,
    }))
}

// ---------------------------------------------------------------------------
// Boundary corpus for the independent checker (pcp/tools/independent): the
// honest offer, bundle and binding, judged by buyers whose limits sit at,
// just below and just above what the deal needs, at times around each
// deadline. Single-field mutations (differential_case) never reach these.

/// One buyer policy and clock, as the corpus records it.
struct Edge {
    now: u64,
    max_price_msat: u64,
    max_deal_msat: u64,
    htlc_secs: u64,
    min_invoice_remaining_secs: u64,
    allow_insecure: bool,
    own_per_deal_msat: u64,
    own_cap_msat: u64,
}

fn judge(e: &Edge) -> Value {
    judge_offer(e, &honest().offer, "boundary")
}

fn judge_offer(e: &Edge, offer_json: &Value, label: &str) -> Value {
    let h = honest();
    let offer: Offer = serde_json::from_value(offer_json.clone()).expect("offer");
    let bundle: ProofBundle = serde_json::from_value(h.bundle.clone()).expect("bundle");
    let binding: InvoiceBinding = serde_json::from_value(h.binding.clone()).expect("binding");
    let a = agent_with(
        1,
        Role::Buyer,
        "alice-node",
        vec![job().spec_hash()],
        e.own_per_deal_msat,
        e.own_cap_msat,
    );
    let p = BuyerPolicy {
        allow_insecure_dev_backend: e.allow_insecure,
        htlc_secs: e.htlc_secs,
        min_invoice_remaining_secs: e.min_invoice_remaining_secs,
        max_deal_msat: e.max_deal_msat,
        ..BuyerPolicy::default()
    };
    let mut rng = StdRng::seed_from_u64(11);
    let (mut buyer, req) = Buyer::new(
        &a,
        Box::new(job()),
        Box::new(InsecureDevTransparentBackend),
        p.clone(),
        puzzle(),
        e.max_price_msat,
        NOW,
        &mut rng,
    )
    .expect("buyer");
    let verdict = match buyer.accept_offer(&offer, e.now) {
        Err(x) => serde_json::json!({ "stage": "offer", "code": x.code() }),
        Ok(()) => match buyer.verify_bundle(&bundle) {
            Err(x) => serde_json::json!({ "stage": "bundle", "code": x.code() }),
            Ok(()) => match buyer.check_invoice(&binding, e.now) {
                Err(x) => serde_json::json!({ "stage": "invoice", "code": x.code() }),
                Ok(()) => serde_json::json!({ "stage": "accepted", "code": null }),
            },
        },
    };
    serde_json::json!({
        "changed": [label],
        "request": serde_json::to_value(&req).expect("request"),
        "offer": offer_json,
        "bundle": h.bundle,
        "binding": h.binding,
        "now": e.now,
        "buyer": {
            "max_price_msat": e.max_price_msat,
            "accepted_backend_id": "INSECURE-dev-transparent/0",
            "allow_insecure_dev_backend": p.allow_insecure_dev_backend,
            "htlc_secs": p.htlc_secs,
            "min_invoice_remaining_secs": p.min_invoice_remaining_secs,
            "max_deal_msat": p.max_deal_msat,
            "rail": p.rail,
            "payout_node": "alice-node",
        },
        "verdict": verdict,
    })
}

/// Every combination of limits at, below and above the deal, at times
/// around the offer's and the invoice's deadlines.
pub fn boundary_cases() -> Vec<Value> {
    let h = honest();
    let offer: Offer = serde_json::from_value(h.offer.clone()).expect("offer");
    let binding: InvoiceBinding = serde_json::from_value(h.binding.clone()).expect("binding");
    let inv = &binding.invoice;
    let price = offer.price_msat;
    let lock = inv.min_htlc_secs;
    let remain = BuyerPolicy::default().min_invoice_remaining_secs;
    // The last second the invoice still has `remain` left, and the offer's end.
    let inv_edge = inv.expires_at().saturating_sub(remain);
    let off_edge = offer.offer_expires_at;
    let mut times = vec![NOW];
    for t in [inv_edge, off_edge] {
        times.extend([t.saturating_sub(1), t, t + 1]);
    }
    times.sort_unstable();
    times.dedup();
    let mut out = Vec::new();
    for &now in &times {
        for max_price_msat in [price, price - 1] {
            for max_deal_msat in [price, price - 1] {
                for htlc_secs in [lock, lock - 1] {
                    for allow_insecure in [true, false] {
                        for (own_per_deal_msat, own_cap_msat) in [
                            (2_000_000, 10_000_000),
                            (price, price),
                            (price - 1, 10_000_000),
                            (2_000_000, price - 1),
                        ] {
                            out.push(judge(&Edge {
                                now,
                                max_price_msat,
                                max_deal_msat,
                                htlc_secs,
                                min_invoice_remaining_secs: remain,
                                allow_insecure,
                                own_per_deal_msat,
                                own_cap_msat,
                            }));
                        }
                    }
                }
            }
        }
    }
    out
}

/// The honest offer under a seller mandate with other terms, signed for
/// real (principal and agent keys of the seller in [`seller`]), so the
/// buyer's mandate checks after the signatures are reached: role, expiry,
/// scope, self-owned, version, payout node, per-deal maximum (SPEC 2.1).
pub fn mandate_cases() -> Vec<Value> {
    let h = honest();
    // The seller's keys, regenerated as `agent(2, ...)` makes them.
    let mut rng = StdRng::seed_from_u64(2);
    let principal = SecretKey::generate(&mut rng);
    let key = SecretKey::generate(&mut rng);
    let honest_terms = || MandateTerms {
        role: Role::Seller,
        scope: vec![job().spec_hash()],
        cap_msat: 10_000_000,
        per_deal_max_msat: 2_000_000,
        payout_node: "bob-node".to_string(),
        expires_at: 86_400,
    };
    let offer: Offer = serde_json::from_value(h.offer.clone()).expect("offer");
    let mut cases: Vec<(&str, Mandate)> = Vec::new();
    let sign = |principal: &SecretKey, t: MandateTerms| {
        Mandate::sign(
            principal,
            key.public_key(),
            t,
            &mut StdRng::seed_from_u64(7),
        )
    };
    cases.push(("mandate:honest", sign(&principal, honest_terms())));
    cases.push((
        "mandate:role",
        sign(
            &principal,
            MandateTerms {
                role: Role::Buyer,
                ..honest_terms()
            },
        ),
    ));
    for (name, at) in [
        ("mandate:expires_at_now", NOW),
        ("mandate:expires_at_now+1", NOW + 1),
    ] {
        cases.push((
            name,
            sign(
                &principal,
                MandateTerms {
                    expires_at: at,
                    ..honest_terms()
                },
            ),
        ));
    }
    cases.push((
        "mandate:scope",
        sign(
            &principal,
            MandateTerms {
                scope: vec![[9; 32]],
                ..honest_terms()
            },
        ),
    ));
    cases.push((
        "mandate:scope_empty",
        sign(
            &principal,
            MandateTerms {
                scope: vec![],
                ..honest_terms()
            },
        ),
    ));
    cases.push((
        "mandate:payout_node",
        sign(
            &principal,
            MandateTerms {
                payout_node: "other-node".into(),
                ..honest_terms()
            },
        ),
    ));
    for (name, max) in [
        ("mandate:per_deal_price-1", PRICE - 1),
        ("mandate:per_deal_price", PRICE),
    ] {
        cases.push((
            name,
            sign(
                &principal,
                MandateTerms {
                    per_deal_max_msat: max,
                    ..honest_terms()
                },
            ),
        ));
    }
    // The agent as its own principal.
    cases.push(("mandate:self_owned", sign(&key, honest_terms())));
    // Another version, re-signed by the principal.
    let mut v = sign(&principal, honest_terms());
    v.version = "PCP/1".into();
    v.principal_sig = principal.sign(&v.mandate_id());
    cases.push(("mandate:version", v));
    let e = Edge {
        now: NOW,
        max_price_msat: 2_000_000,
        max_deal_msat: BuyerPolicy::default().max_deal_msat,
        htlc_secs: BuyerPolicy::default().htlc_secs,
        min_invoice_remaining_secs: BuyerPolicy::default().min_invoice_remaining_secs,
        allow_insecure: true,
        own_per_deal_msat: 2_000_000,
        own_cap_msat: 10_000_000,
    };
    cases
        .into_iter()
        .map(|(name, m)| {
            let sig = key.sign(&offer.auth_message(&m.mandate_id()));
            let o = Offer {
                mandate: Some(m),
                agent_sig: Some(sig),
                ..offer.clone()
            };
            judge_offer(&e, &serde_json::to_value(&o).expect("offer"), name)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Second corpus for the independent checker (design note 28): R0, the own
// mandate at O2, and JSON transport (SPEC 3.3, 5.5).

/// A job class that is not in the reference registry.
struct Unregistered(&'static str, Vec<u8>);

impl JobClass for Unregistered {
    fn job_id(&self) -> &'static str {
        self.0
    }
    fn params(&self) -> Vec<u8> {
        self.1.clone()
    }
    fn check(&self, _input: &[u8], _result: &[u8]) -> bool {
        false
    }
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The buyer's principal and agent keys, as `agent(1, ...)` makes them.
fn buyer_keys() -> (SecretKey, SecretKey) {
    let mut rng = StdRng::seed_from_u64(1);
    (SecretKey::generate(&mut rng), SecretKey::generate(&mut rng))
}

fn buyer_terms() -> MandateTerms {
    MandateTerms {
        role: Role::Buyer,
        scope: vec![job().spec_hash()],
        cap_msat: 10_000_000,
        per_deal_max_msat: 2_000_000,
        payout_node: "alice-node".to_string(),
        expires_at: 86_400,
    }
}

/// The request `Buyer::new` would send for this mandate and job, built
/// without running R0 (so a request R0 refuses can still be recorded).
fn request_for(key: &SecretKey, m: &Mandate, job: &dyn JobClass, committed: u64) -> Request {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    StdRng::seed_from_u64(11).fill_bytes(&mut nonce);
    let input = puzzle();
    let mut req = Request {
        version: pcp::encoding::VERSION.to_string(),
        job_id: job.job_id().to_string(),
        spec_hash: job.spec_hash(),
        input_commitment: pcp::job::input_commitment(&input),
        input,
        buyer_nonce: nonce,
        max_price_msat: 2_000_000,
        mandate_spent_msat: committed,
        mandate: None,
        agent_sig: None,
    };
    req.agent_sig = Some(key.sign(&req.auth_message(&m.mandate_id())));
    req.mandate = Some(m.clone());
    req
}

/// One R0 case: the buyer's own mandate `m` (signed for the buyer's agent
/// key), `committed` against its cap, R0 run at `r0_now`, the honest offer,
/// bundle and binding judged at `now`. The Rust verdict at R0 is the
/// refusal of `Agent::restore` (an agent is never bound to a mandate that
/// does not verify) or of `Buyer::new`.
#[allow(clippy::too_many_arguments)]
fn judge_request(
    label: &str,
    m: Mandate,
    job: Box<dyn JobClass>,
    allow_unregistered: bool,
    committed: u64,
    r0_now: u64,
    now: u64,
) -> Value {
    let h = honest();
    let (_, key) = buyer_keys();
    let agent_key = hex_of(&key.public_key());
    let req = request_for(&key, &m, job.as_ref(), committed);
    let p = BuyerPolicy {
        allow_insecure_dev_backend: true,
        allow_unregistered_job_classes: allow_unregistered,
        ..BuyerPolicy::default()
    };
    let verdict = match Agent::restore(key, m, committed, Default::default()) {
        Err(e) => serde_json::json!({ "stage": "request", "code": e.code() }),
        Ok(a) => match Buyer::new(
            &a,
            job,
            Box::new(InsecureDevTransparentBackend),
            p.clone(),
            puzzle(),
            2_000_000,
            r0_now,
            &mut StdRng::seed_from_u64(11),
        ) {
            Err(e) => serde_json::json!({ "stage": "request", "code": e.code() }),
            Ok((mut b, sent)) => {
                // The request recorded is the one Buyer::new sends.
                assert_eq!(sent, req, "request_for differs from Buyer::new ({label})");
                let offer: Offer = serde_json::from_value(h.offer.clone()).expect("offer");
                let bundle: ProofBundle =
                    serde_json::from_value(h.bundle.clone()).expect("bundle");
                let binding: InvoiceBinding =
                    serde_json::from_value(h.binding.clone()).expect("binding");
                match b.accept_offer(&offer, now) {
                    Err(x) => serde_json::json!({ "stage": "offer", "code": x.code() }),
                    Ok(()) => match b.verify_bundle(&bundle) {
                        Err(x) => serde_json::json!({ "stage": "bundle", "code": x.code() }),
                        Ok(()) => match b.check_invoice(&binding, now) {
                            Err(x) => {
                                serde_json::json!({ "stage": "invoice", "code": x.code() })
                            }
                            Ok(()) => serde_json::json!({ "stage": "accepted", "code": null }),
                        },
                    },
                }
            }
        },
    };
    serde_json::json!({
        "changed": [label],
        "request": serde_json::to_value(&req).expect("request"),
        "offer": h.offer,
        "bundle": h.bundle,
        "binding": h.binding,
        "now": now,
        "r0_now": r0_now,
        "buyer": {
            "max_price_msat": 2_000_000u64,
            "accepted_backend_id": "INSECURE-dev-transparent/0",
            "allow_insecure_dev_backend": p.allow_insecure_dev_backend,
            "allow_unregistered_job_classes": p.allow_unregistered_job_classes,
            "agent_key": agent_key,
            "htlc_secs": p.htlc_secs,
            "min_invoice_remaining_secs": p.min_invoice_remaining_secs,
            "max_deal_msat": p.max_deal_msat,
            "rail": p.rail,
            "payout_node": "alice-node",
        },
        "verdict": verdict,
    })
}

/// R0 and the own mandate at O2: registry, role, expiry, scope, version,
/// signature, self-owned, cap, each at and around its boundary.
pub fn request_cases() -> Vec<Value> {
    let (principal, key) = buyer_keys();
    let sign = |p: &SecretKey, t: MandateTerms| {
        Mandate::sign(p, key.public_key(), t, &mut StdRng::seed_from_u64(5))
    };
    let honest_m = || sign(&principal, buyer_terms());
    let sudoku = || -> Box<dyn JobClass> { Box::new(job()) };
    let mut out = Vec::new();
    let mut r0 = |label: &str, m: Mandate, job: Box<dyn JobClass>, allow: bool, committed: u64| {
        out.push(judge_request(label, m, job, allow, committed, NOW, NOW));
    };

    r0("r0:honest", honest_m(), sudoku(), false, 0);
    // Registry (6.4): a class with other parameters, and another job id.
    for (name, id, params) in [
        ("r0:unregistered_params", "pcp/sudoku/v0", vec![16u8]),
        ("r0:unregistered_job", "pcp/unreviewed/v0", vec![4u8]),
    ] {
        for allow in [false, true] {
            let class = Unregistered(id, params.clone());
            let m = sign(
                &principal,
                MandateTerms {
                    scope: vec![class.spec_hash()],
                    ..buyer_terms()
                },
            );
            r0(
                &format!("{name}:allow={allow}"),
                m,
                Box::new(Unregistered(id, params.clone())),
                allow,
                0,
            );
        }
    }
    // The own mandate (2.1 order).
    r0(
        "r0:role",
        sign(&principal, MandateTerms { role: Role::Seller, ..buyer_terms() }),
        sudoku(),
        false,
        0,
    );
    for (name, at) in [
        ("r0:expires_at_now", NOW),
        ("r0:expires_at_now+1", NOW + 1),
        ("r0:expires_at_now-1", NOW - 1),
    ] {
        r0(
            name,
            sign(&principal, MandateTerms { expires_at: at, ..buyer_terms() }),
            sudoku(),
            false,
            0,
        );
    }
    r0(
        "r0:scope_other",
        sign(&principal, MandateTerms { scope: vec![[9; 32]], ..buyer_terms() }),
        sudoku(),
        false,
        0,
    );
    r0(
        "r0:scope_empty",
        sign(&principal, MandateTerms { scope: vec![], ..buyer_terms() }),
        sudoku(),
        false,
        0,
    );
    let mut v = honest_m();
    v.version = "PCP/1".into();
    v.principal_sig = principal.sign(&v.mandate_id());
    r0("r0:version", v, sudoku(), false, 0);
    let mut bad = honest_m();
    bad.principal_sig.0[0] ^= 1;
    r0("r0:signature", bad, sudoku(), false, 0);
    // The agent as its own principal: the key signs its own mandate.
    r0("r0:self_owned", sign(&key, buyer_terms()), sudoku(), false, 0);
    // A mandate made for another agent key (2.1, agent start).
    let other = SecretKey::from_seed([7; 32]).public_key();
    r0(
        "r0:agent_key_mismatch",
        Mandate::sign(&principal, other, buyer_terms(), &mut StdRng::seed_from_u64(5)),
        sudoku(),
        false,
        0,
    );
    // Two faults at once: the order decides (agent start before R0).
    let class = Unregistered("pcp/sudoku/v0", vec![16u8]);
    let mut both = sign(
        &principal,
        MandateTerms {
            scope: vec![class.spec_hash()],
            ..buyer_terms()
        },
    );
    both.principal_sig.0[0] ^= 1;
    r0("r0:unregistered+signature", both, Box::new(class), false, 0);
    // R0 does not check the price ceiling against the per-deal maximum
    // (the price is not known yet): max_price 2,000,000 over 1,999,999.
    r0(
        "r0:max_price_over_per_deal",
        sign(&principal, MandateTerms { per_deal_max_msat: 1_999_999, ..buyer_terms() }),
        sudoku(),
        false,
        0,
    );
    // Cap: committed below, at and above it. R0 asks committed < cap.
    let cap = buyer_terms().cap_msat;
    for (name, c) in [
        ("r0:committed_cap-price", cap - PRICE),
        ("r0:committed_cap-price+1", cap - PRICE + 1),
        ("r0:committed_cap-1", cap - 1),
        ("r0:committed_cap", cap),
        ("r0:committed_cap+1", cap + 1),
    ] {
        r0(name, honest_m(), sudoku(), false, c);
    }
    // The own mandate expires between R0 and the offer (O2).
    let t = NOW + 100;
    for (name, at) in [
        ("o2:own_expires_at_t-1", t - 1),
        ("o2:own_expires_at_t", t),
        ("o2:own_expires_at_t+1", t + 1),
    ] {
        let m = sign(&principal, MandateTerms { expires_at: at, ..buyer_terms() });
        out.push(judge_request(name, m, Box::new(job()), false, 0, NOW, t));
    }
    out
}

/// A u64 one past the largest, as JSON text (serde_json's `Value` cannot
/// hold it): written as this string, then replaced in the serialized case.
pub const OVERFLOW_SENTINEL: &str = "__pcp_u64_overflow__";
const OVERFLOW_TEXT: &str = "18446744073709551616";

/// Every single-leaf transport defect of the honest offer, bundle and
/// binding: uppercase, short or non-hex hex; a number out of range, signed,
/// fractional or quoted; a value replaced by null, removed, or upper-cased;
/// an unknown field beside it. The Rust verdict parses each message from
/// its JSON text at its stage (a parse failure is HTTP 400, SPEC 5.5).
/// Returns the cases as JSON lines (text, because of the overflow value).
pub fn transport_cases() -> Vec<String> {
    let h = honest();
    let msgs = [&h.offer, &h.bundle, &h.binding];
    let mut out = Vec::new();
    for (mi, msg) in msgs.iter().enumerate() {
        let mut paths = Vec::new();
        leaves(msg, &mut Vec::new(), &mut paths);
        let mut parents: Vec<Vec<String>> = paths
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| p[..p.len() - 1].to_vec())
            .collect();
        parents.sort();
        parents.dedup();
        let mut variants: Vec<(String, Value)> = Vec::new();
        for path in &paths {
            let leaf = at(&mut (*msg).clone(), path).expect("leaf").clone();
            let name = path.join(".");
            let mut put = |kind: &str, x: Option<Value>| {
                let mut m = (*msg).clone();
                match x {
                    Some(x) => *at(&mut m, path).expect("leaf") = x,
                    None => {
                        let (last, parent) = path.split_last().expect("path");
                        match at(&mut m, parent).expect("parent") {
                            Value::Object(o) => {
                                o.remove(last);
                            }
                            Value::Array(a) => {
                                a.remove(last.parse::<usize>().expect("index"));
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                variants.push((format!("{name}:{kind}"), m));
            };
            match &leaf {
                Value::String(s) => {
                    let hex = !s.is_empty() && s.bytes().all(|c| c.is_ascii_hexdigit());
                    if hex {
                        if s.bytes().any(|c| c.is_ascii_lowercase()) {
                            put("upper", Some(Value::from(s.to_ascii_uppercase())));
                        }
                        put("short", Some(Value::from(&s[..s.len() - 1])));
                        put("nonhex", Some(Value::from(format!("g{}", &s[1..]))));
                    } else if s.bytes().any(|c| c.is_ascii_lowercase()) {
                        put("upper", Some(Value::from(s.to_ascii_uppercase())));
                    }
                }
                Value::Number(n) => {
                    put("overflow", Some(Value::from(OVERFLOW_SENTINEL)));
                    put("negative", Some(Value::from(-1)));
                    put("fraction", Some(serde_json::json!(1.5)));
                    put("quoted", Some(Value::from(n.to_string())));
                }
                _ => {}
            }
            put("null", Some(Value::Null));
            put("removed", None);
        }
        // The optional BOLT11 string of the real rail (SPEC 5.3), absent on
        // the simulated rail, so no leaf above reaches it.
        if mi == 2 {
            let mut m = (*msg).clone();
            if let Some(Value::Object(o)) = at(&mut m, &["invoice".to_string()]) {
                o.insert("bolt11".into(), Value::from("lnbcrt15u1pexample"));
                variants.push(("invoice.bolt11:added".to_string(), m));
            }
        }
        for parent in &parents {
            let mut m = (*msg).clone();
            if let Some(Value::Object(o)) = at(&mut m, parent) {
                o.insert("unknown_field".into(), Value::from(1));
                let name = if parent.is_empty() { "(top)".to_string() } else { parent.join(".") };
                variants.push((format!("{name}:unknown_field"), m));
            }
        }
        for (label, m) in variants {
            let text = |v: &Value| {
                serde_json::to_string(v)
                    .expect("json")
                    .replace(&format!("\"{OVERFLOW_SENTINEL}\""), OVERFLOW_TEXT)
            };
            let mut texts = [text(&h.offer), text(&h.bundle), text(&h.binding)];
            texts[mi] = text(&m);
            let (mut buyer, _) = buyer();
            let verdict = (|| {
                let offer: Offer = match serde_json::from_str(&texts[0]) {
                    Ok(o) => o,
                    Err(_) => return serde_json::json!({ "stage": "offer", "code": "http_400" }),
                };
                if let Err(e) = buyer.accept_offer(&offer, NOW) {
                    return serde_json::json!({ "stage": "offer", "code": e.code() });
                }
                let bundle: ProofBundle = match serde_json::from_str(&texts[1]) {
                    Ok(b) => b,
                    Err(_) => return serde_json::json!({ "stage": "bundle", "code": "http_400" }),
                };
                if let Err(e) = buyer.verify_bundle(&bundle) {
                    return serde_json::json!({ "stage": "bundle", "code": e.code() });
                }
                let binding: InvoiceBinding = match serde_json::from_str(&texts[2]) {
                    Ok(b) => b,
                    Err(_) => return serde_json::json!({ "stage": "invoice", "code": "http_400" }),
                };
                match buyer.check_invoice(&binding, NOW) {
                    Err(e) => serde_json::json!({ "stage": "invoice", "code": e.code() }),
                    Ok(()) => serde_json::json!({ "stage": "accepted", "code": null }),
                }
            })();
            let p = policy();
            let head = serde_json::json!({
                "set": "transport",
                "changed": [label],
                "request": h.request,
                "now": NOW,
                "buyer": {
                    "max_price_msat": 2_000_000u64,
                    "accepted_backend_id": "INSECURE-dev-transparent/0",
                    "allow_insecure_dev_backend": p.allow_insecure_dev_backend,
                    "htlc_secs": p.htlc_secs,
                    "min_invoice_remaining_secs": p.min_invoice_remaining_secs,
                    "max_deal_msat": p.max_deal_msat,
                    "rail": p.rail,
                    "payout_node": "alice-node",
                },
                "verdict": verdict,
            });
            // Splice the three messages in as text.
            let head = serde_json::to_string(&head).expect("json");
            out.push(format!(
                "{},\"offer\":{},\"bundle\":{},\"binding\":{}}}",
                &head[..head.len() - 1],
                texts[0],
                texts[1],
                texts[2]
            ));
        }
    }
    out
}
