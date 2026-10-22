//! `pcp-audit`: check a buyer's or seller's state directory after a run.
//!
//! Reads `state.json` (state and principal log), checks that it belongs to
//! the agent and mandate in the directory, re-verifies every log entry
//! (signatures, receipts against bundles and inputs, cap), and checks that
//! the state and the log agree: one receipt per settled payment hash and
//! none for a sale that did not settle, a cap equal to what the records
//! hold, every sale over. Prints a JSON summary. Exit 0 if consistent (and
//! as expected), 1 otherwise, 2 on usage.

use std::collections::BTreeMap;

use pcp::job::{JobClass, SudokuJob, TestSuiteJob};
use pcp::mandate::Role;
use pcp::node::cli::{fail, Args};
use pcp::node::store::{write_json, StateDir};
use pcp::protocol::{BuyerSnapshot, BuyerStateRecord, OfferStage, SellerSnapshot};

const USAGE: &str = "\
pcp-audit --state DIR [--expect-state Delivered|Refunded|Aborted]
          [--expect-reason CODE] [--expect-settled N] [--expect-proofs N]
          [--expect-refusals N] [--out FILE]

The role is read from the mandate in DIR. Buyer: --expect-state and
--expect-reason. Seller: --expect-settled (settled sales) and
--expect-proofs (sales that reached proving).";

#[derive(serde::Serialize, Default)]
struct Report {
    role: String,
    ok: bool,
    problems: Vec<String>,
    log_deals: usize,
    log_refusals: usize,
    refusal_reasons: BTreeMap<String, usize>,
    committed_msat: u64,
    /// Buyer: final state and reason.
    state: Option<String>,
    reason: Option<String>,
    /// Seller: sales by outcome, and offers.
    settled: usize,
    closed: usize,
    open: usize,
    proofs: usize,
    offers: usize,
}

fn push(v: &mut Vec<String>, m: String) {
    v.push(m);
}

fn main() {
    let a = Args::parse(USAGE, &[]);
    let dir = StateDir::open(&a.path("state")).unwrap_or_else(|e| fail(USAGE, &e.to_string()));
    let (key, mandate) = dir
        .agent_key_and_mandate()
        .unwrap_or_else(|e| fail(USAGE, &e.to_string()));
    let jobs: [&dyn JobClass; 3] = [&SudokuJob::four(), &SudokuJob::nine(), &TestSuiteJob];
    let mut r = Report {
        role: mandate.role.as_str().to_string(),
        ..Report::default()
    };

    // Receipts per payment hash, from the log.
    let receipts_by_hash = |log: &pcp::mandate::PrincipalLog| {
        let mut m: BTreeMap<[u8; 32], (usize, u64)> = BTreeMap::new();
        for rc in log.receipts() {
            let e = m.entry(rc.payment_hash).or_default();
            e.0 += 1;
            e.1 += rc.amount_msat;
        }
        m
    };

    match mandate.role {
        Role::Seller => {
            let Some(saved) = dir
                .load::<SellerSnapshot>()
                .unwrap_or_else(|e| fail(USAGE, &e.to_string()))
            else {
                fail(USAGE, "no state.json");
            };
            if let Err(m) = saved.check(&key, &mandate) {
                push(&mut r.problems, m);
            }
            let log = saved.log();
            match log.verify(&mandate, &jobs) {
                Ok(s) => {
                    r.log_deals = s.deals;
                    r.log_refusals = s.refusals;
                    r.refusal_reasons = s.reasons;
                }
                Err(e) => push(
                    &mut r.problems,
                    format!("log entry {}: {}", e.index, e.error.code()),
                ),
            }
            let snap = &saved.state;
            r.committed_msat = snap.committed_msat();
            r.offers = snap.offers.len();
            r.proofs = snap.sales.len();
            let by_hash = receipts_by_hash(&log);
            let mut settled_total = 0;
            for s in &snap.sales {
                let h = s.bundle.statement.payment_hash;
                let (n, amt) = by_hash.get(&h).copied().unwrap_or((0, 0));
                if s.settled {
                    r.settled += 1;
                    settled_total += s.settled_msat;
                    if n != 1 || amt != s.settled_msat {
                        push(
                            &mut r.problems,
                            format!("settled sale {}: {n} receipts", hex::encode(h)),
                        );
                    }
                } else {
                    if n != 0 {
                        push(
                            &mut r.problems,
                            format!("unsettled sale {}: {n} receipts", hex::encode(h)),
                        );
                    }
                    if s.closed {
                        r.closed += 1;
                    } else {
                        r.open += 1;
                        push(
                            &mut r.problems,
                            format!("sale {} still open", hex::encode(h)),
                        );
                    }
                }
            }
            if by_hash.len() != r.settled {
                push(&mut r.problems, "a receipt without a settled sale".into());
            }
            if settled_total != r.committed_msat {
                push(
                    &mut r.problems,
                    "cap does not equal the settled sales".into(),
                );
            }
            for o in &snap.offers {
                if matches!(o.stage, OfferStage::Accepted | OfferStage::Proven { .. }) {
                    push(
                        &mut r.problems,
                        format!("offer {} unfinished", hex::encode(o.offer.offer_id())),
                    );
                }
            }
            if let Some(n) = a.get("expect-settled") {
                if n.parse::<usize>().ok() != Some(r.settled) {
                    push(
                        &mut r.problems,
                        format!("expected {n} settled, found {}", r.settled),
                    );
                }
            }
            if let Some(n) = a.get("expect-proofs") {
                if n.parse::<usize>().ok() != Some(r.proofs) {
                    push(
                        &mut r.problems,
                        format!("expected {n} proofs, found {}", r.proofs),
                    );
                }
            }
        }
        Role::Buyer => {
            let Some(saved) = dir
                .load::<BuyerSnapshot>()
                .unwrap_or_else(|e| fail(USAGE, &e.to_string()))
            else {
                fail(USAGE, "no state.json");
            };
            if let Err(m) = saved.check(&key, &mandate) {
                push(&mut r.problems, m);
            }
            let log = saved.log();
            match log.verify(&mandate, &jobs) {
                Ok(s) => {
                    r.log_deals = s.deals;
                    r.log_refusals = s.refusals;
                    r.refusal_reasons = s.reasons;
                }
                Err(e) => push(
                    &mut r.problems,
                    format!("log entry {}: {}", e.index, e.error.code()),
                ),
            }
            let snap = &saved.state;
            r.committed_msat = snap.spent_msat;
            let by_hash = receipts_by_hash(&log);
            let (state, reason) = match &snap.state {
                BuyerStateRecord::Delivered { receipt, .. } => {
                    let (n, amt) = by_hash
                        .get(&receipt.payment_hash)
                        .copied()
                        .unwrap_or((0, 0));
                    if n != 1 || by_hash.len() != 1 {
                        push(
                            &mut r.problems,
                            format!("delivered with {} receipts", log.receipts().count()),
                        );
                    }
                    if amt != snap.spent_msat {
                        push(&mut r.problems, "cap does not equal the amount paid".into());
                    }
                    ("Delivered", None)
                }
                BuyerStateRecord::Refunded => ("Refunded", Some("refunded".to_string())),
                BuyerStateRecord::Aborted { reason } => ("Aborted", Some(reason.clone())),
                other => {
                    push(
                        &mut r.problems,
                        format!("purchase not over: {other:?}")
                            .chars()
                            .take(80)
                            .collect(),
                    );
                    ("Open", None)
                }
            };
            if state != "Delivered" {
                if !by_hash.is_empty() {
                    push(
                        &mut r.problems,
                        format!("{state} but {} receipts", by_hash.len()),
                    );
                }
                if state == "Refunded" && snap.spent_msat != 0 {
                    push(
                        &mut r.problems,
                        "refunded but the cap still holds the price".into(),
                    );
                }
            }
            r.state = Some(state.to_string());
            r.reason = reason;
            if let Some(want) = a.get("expect-state") {
                if want != state {
                    push(&mut r.problems, format!("expected {want}, found {state}"));
                }
            }
            if let Some(want) = a.get("expect-reason") {
                if r.reason.as_deref() != Some(want) {
                    push(
                        &mut r.problems,
                        format!("expected reason {want}, found {:?}", r.reason),
                    );
                }
            }
        }
    }
    if let Some(n) = a.get("expect-refusals") {
        if n.parse::<usize>().ok() != Some(r.log_refusals) {
            push(
                &mut r.problems,
                format!(
                    "expected {n} refusals in the log, found {} {:?}",
                    r.log_refusals, r.refusal_reasons
                ),
            );
        }
    }
    r.ok = r.problems.is_empty();
    let json = serde_json::to_string_pretty(&r).expect("report serialises");
    println!("{json}");
    if let Some(out) = a.get("out") {
        write_json(std::path::Path::new(out), &r).unwrap_or_else(|e| fail(USAGE, &e.to_string()));
    }
    std::process::exit(if r.ok { 0 } else { 1 })
}
