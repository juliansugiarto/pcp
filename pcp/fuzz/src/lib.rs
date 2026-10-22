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
    let mut rng = StdRng::seed_from_u64(seed);
    let principal = SecretKey::generate(&mut rng);
    let key = SecretKey::generate(&mut rng);
    let m = Mandate::sign(
        &principal,
        key.public_key(),
        MandateTerms {
            role,
            scope,
            cap_msat: 10_000_000,
            per_deal_max_msat: 2_000_000,
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
