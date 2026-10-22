//! PCP as two processes: a seller and a buyer, each with its own state
//! directory, talking over a [`wire::DirTransport`] and paying over a
//! [`crate::rail::Rail`] (a real LND node, or [`sim_file`] in tests).
//!
//! Each loop saves its state ([`store::StateDir::save`]) after every step
//! and before every side effect that depends on it, so a process killed at
//! any point restarts into a state from which the sale still ends cleanly:
//! delivered, refunded, or refused with a logged reason. The rules, from
//! the S1 review:
//!
//! - the seller saves `k` before the invoice exists, and finds the invoice
//!   again after a restart ([`crate::protocol::Seller::invoice`]);
//! - the buyer saves `Paying`, with the reservation, before the payment
//!   call, and resolves it from its node after a restart;
//! - state and principal log are one file, so a sale is never recorded
//!   twice or lost from the log;
//! - every message is idempotent to receive: repeats are answered or
//!   dropped, never refused.
//!
//! Crash points: setting `PCP_CRASH_AT=<point>` aborts the process at that
//! point, for the crash tests. Each step has a `:pre` point (the side effect
//! happened, the state is not saved yet) and a `:post` point (saved, the
//! next message not sent yet). See [`CRASH_POINTS`].

pub mod cli;
#[cfg(feature = "http")]
pub mod http;
pub mod sim_file;
pub mod store;
pub mod wire;
pub mod work;

/// A counterparty's refusal reason, reduced to what a reason code can hold
/// (SPEC 5.4a: `a-z`, digits, `_`, `.`, `-`, `:`) and at most 128 characters.
pub fn reason_code(s: &str) -> String {
    let kept: String = s
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-:".contains(*c))
        .take(128)
        .collect();
    if kept.is_empty() {
        "unreadable_reason".into()
    } else {
        kept
    }
}

use std::path::PathBuf;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;

use crate::job::JobClass;
use crate::mandate::Agent;
use crate::proof::ProofBackend;
use crate::protocol::{
    AcceptStep, Buyer, BuyerPolicy, BuyerProgress, BuyerSnapshot, BuyerState, OfferStage, PcpError,
    SaleOutcome, Seller, SellerConfig, SellerSnapshot,
};
use crate::rail::Rail;

use store::{StateDir, StoreError};
use wire::{Wire, WireMsg};

/// Every named crash point, seller first.
pub const CRASH_POINTS: &[&str] = &[
    "seller:offer:pre",
    "seller:offer:post",
    "seller:accept:pre",
    "seller:accept:post",
    "seller:k:pre",
    "seller:k:post",
    "seller:invoice:pre",
    "seller:invoice:post",
    "seller:settle:pre",
    "seller:settle:post",
    "buyer:request:post",
    "buyer:offer:pre",
    "buyer:accept:post",
    "buyer:invoice:pre",
    "buyer:paying:post",
    "buyer:pay:pre",
    "buyer:pay:post",
    "buyer:settle:pre",
    "buyer:settle:post",
];

/// Abort the process here if `PCP_CRASH_AT` names this point. Uses
/// `abort`, not `exit`: nothing is flushed or cleaned up, as in a kill.
pub fn crash_point(name: &str) {
    if std::env::var("PCP_CRASH_AT").is_ok_and(|v| v == name) {
        eprintln!("PCP_CRASH_AT={name}: aborting");
        std::process::abort();
    }
}

/// Sleep here if `PCP_PAUSE_AT` is `<name>:<seconds>`. A test hook, like
/// [`crash_point`]: it lets a test change the world (stop a node) while the
/// process is past a given point.
pub fn pause_point(name: &str) {
    if let Ok(v) = std::env::var("PCP_PAUSE_AT") {
        if let Some((n, secs)) = v.rsplit_once(':') {
            if n == name {
                let secs: u64 = secs.parse().unwrap_or(0);
                eprintln!("PCP_PAUSE_AT={name}: pausing {secs} s");
                std::thread::sleep(Duration::from_secs(secs));
            }
        }
    }
}

/// Errors that stop a loop. Protocol refusals do not: they are logged and
/// the sale ends.
#[derive(Debug)]
pub enum NodeError {
    Store(StoreError),
    /// The state directory belongs to another agent, mandate or setup.
    Mismatch(String),
    Protocol(PcpError),
    /// The deadline passed before the stop condition was met.
    Deadline,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Store(e) => write!(f, "{e}"),
            NodeError::Mismatch(m) => write!(f, "state does not match this setup: {m}"),
            NodeError::Protocol(e) => write!(f, "{e} ({})", e.code()),
            NodeError::Deadline => write!(f, "deadline passed"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<StoreError> for NodeError {
    fn from(e: StoreError) -> Self {
        NodeError::Store(e)
    }
}

impl From<PcpError> for NodeError {
    fn from(e: PcpError) -> Self {
        NodeError::Protocol(e)
    }
}

// ---------------------------------------------------------------------------
// Seller

/// A seller process.
pub struct SellerRun<'a> {
    pub state_dir: PathBuf,
    pub wire: Box<dyn Wire>,
    pub rail: &'a mut dyn Rail,
    pub make_job: &'a dyn Fn() -> Box<dyn JobClass>,
    pub make_backend: &'a dyn Fn() -> Box<dyn ProofBackend>,
    pub cfg: SellerConfig,
    /// The seller's work: the result for an input, or `None` if it cannot
    /// do the job (the accept is then refused).
    pub work: &'a dyn Fn(&[u8]) -> Option<Vec<u8>>,
    pub poll: Duration,
    /// Exit once this many sales are over and nothing is pending.
    pub sales: usize,
    /// Also exit when nothing is pending and no message arrived for this
    /// long (a buyer that went away).
    pub quiet_exit: Duration,
    /// Give up (error) after this long.
    pub deadline: Duration,
    pub log: &'a mut dyn FnMut(&str),
}

/// What a seller process did, for its caller and the audit.
#[derive(Debug, Default)]
pub struct SellerSummary {
    pub settled: usize,
    pub cancelled: usize,
    pub refused: usize,
    pub proofs_made: usize,
    pub committed_msat: u64,
}

fn open_seller(run: &SellerRun) -> Result<(StateDir, Seller), NodeError> {
    let dir = StateDir::open(&run.state_dir)?;
    let (key, mandate) = dir.agent_key_and_mandate()?;
    let seller = match dir.load::<SellerSnapshot>()? {
        Some(saved) => {
            saved.check(&key, &mandate).map_err(NodeError::Mismatch)?;
            let agent = Agent::restore(key, mandate, saved.state.committed_msat(), saved.log())?;
            Seller::restore(
                &agent,
                (run.make_job)(),
                (run.make_backend)(),
                run.cfg.clone(),
                saved.state,
            )
            .map_err(|e| NodeError::Mismatch(e.code()))?
        }
        None => {
            let agent = Agent::new(key, mandate)?;
            let s = Seller::new(
                &agent,
                (run.make_job)(),
                (run.make_backend)(),
                run.cfg.clone(),
            );
            dir.save(&s.snapshot(), s.agent())?;
            s
        }
    };
    Ok((dir, seller))
}

/// Run a seller until its stop condition. Resumes from the state directory.
pub fn run_seller(mut run: SellerRun) -> Result<SellerSummary, NodeError> {
    let (dir, mut seller) = open_seller(&run)?;
    let save = |s: &Seller| dir.save(&s.snapshot(), s.agent());
    {
        // What strangers may read before asking (unsigned; the signed
        // offer is what binds the seller).
        let job = (run.make_job)();
        let backend = (run.make_backend)();
        run.wire.set_info(serde_json::json!({
            "version": crate::encoding::VERSION,
            "job_id": job.job_id(),
            "spec_hash": hex::encode(job.spec_hash()),
            "price_msat": run.cfg.price_msat,
            "backend_id": backend.backend_id(),
            "rail": run.cfg.rail,
            "seller_node": seller.node(),
            "offer_ttl_secs": run.cfg.offer_ttl_secs,
            "mandate": seller.agent().mandate(),
        }));
    }
    // What a queueing transport may refuse before the loop sees it.
    run.wire.set_principals(run.cfg.allowed_principals.clone());
    let known: Vec<_> = seller
        .snapshot()
        .offers
        .iter()
        .filter_map(wire::KnownOffer::of)
        .collect();
    run.wire.know_offers(&known);
    let start = Instant::now();
    let mut last_msg = Instant::now();
    let mut summary = SellerSummary::default();
    // Refusals are written to the text log only as often as to the
    // principal's log (rate-limited); the rest are counted, once a minute.
    let mut unshown = 0u64;
    let mut unshown_since = Instant::now();
    let mut early_seen = 0u64;
    (run.log)(&format!(
        "seller up: {} offers, {} sales on record",
        seller.snapshot().offers.len(),
        seller.snapshot().sales.len()
    ));
    loop {
        let now = run.rail.now();
        // 1. Messages.
        for (name, msg) in run.wire.receive()? {
            let log_len = seller.agent().log_len();
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    (run.log)(&format!("unreadable message {name}: {e}"));
                    continue;
                }
            };
            match msg {
                WireMsg::Request { request } => match seller.make_offer(&request, now) {
                    Ok(offer) => {
                        // Only messages that lead somewhere keep a quiet
                        // seller up; refused traffic does not.
                        last_msg = Instant::now();
                        crash_point("seller:offer:pre");
                        save(&seller)?;
                        crash_point("seller:offer:post");
                        if let Some(k) = seller
                            .issued(&offer.offer_id())
                            .and_then(wire::KnownOffer::of)
                        {
                            run.wire.know_offers(&[k]);
                        }
                        run.wire.send(&WireMsg::Offer {
                            offer: offer.clone(),
                        })?;
                        (run.log)(&format!("offer {} sent", short(&offer.offer_id())));
                    }
                    Err(e) => {
                        // Save only if the refusal was logged (refusals are
                        // rate-limited): a flood of bad requests must not
                        // rewrite the state file per message.
                        let logged = seller.agent().log_len() != log_len;
                        if logged {
                            save(&seller)?;
                        }
                        summary.refused += 1;
                        run.wire.send(&WireMsg::Refused {
                            subject_id: request.request_id(),
                            reason: e.code(),
                        })?;
                        if logged {
                            (run.log)(&format!("request refused: {}", e.code()));
                        } else {
                            unshown += 1;
                        }
                    }
                },
                WireMsg::Accept { accept } => match seller.accept(&accept, now) {
                    Ok(AcceptStep::Prove) => {
                        last_msg = Instant::now();
                        crash_point("seller:accept:pre");
                        save(&seller)?;
                        crash_point("seller:accept:post");
                        (run.log)(&format!("accept {} : proving", short(&accept.offer_id)));
                    }
                    Ok(AcceptStep::Pending) | Ok(AcceptStep::Busy) => last_msg = Instant::now(),
                    Ok(AcceptStep::Resend(bundle, binding)) => {
                        last_msg = Instant::now();
                        run.wire.send(&WireMsg::Bundle {
                            bundle: *bundle,
                            binding: *binding,
                        })?;
                        (run.log)(&format!("bundle {} sent again", short(&accept.offer_id)));
                    }
                    Err(e) => {
                        let logged = seller.agent().log_len() != log_len;
                        if logged {
                            save(&seller)?;
                        }
                        summary.refused += 1;
                        run.wire.send(&WireMsg::Refused {
                            subject_id: accept.offer_id,
                            reason: e.code(),
                        })?;
                        if logged {
                            (run.log)(&format!("accept refused: {}", e.code()));
                        } else {
                            unshown += 1;
                        }
                    }
                },
                other => (run.log)(&format!("ignored {}", other.name())),
            }
            run.wire.ack(&name)?;
        }
        if unshown_since.elapsed() >= Duration::from_secs(60) {
            show_unshown(&mut run, &mut unshown, &mut early_seen);
            unshown_since = Instant::now();
        }

        // 2. Work: prove and invoice accepted offers (also after a restart).
        for (id, stage) in seller.unfinished() {
            if stage == OfferStage::Accepted {
                let input = seller
                    .issued(&id)
                    .map(|o| o.request.input.clone())
                    .unwrap_or_default();
                let result = (run.work)(&input).unwrap_or_default();
                let t = Instant::now();
                match seller.prove(&id, result, run.rail.now(), &mut OsRng) {
                    Ok(()) => {
                        summary.proofs_made += 1;
                        (run.log)(&format!(
                            "proved {} in {:.3} s",
                            short(&id),
                            t.elapsed().as_secs_f64()
                        ));
                        crash_point("seller:k:pre");
                        save(&seller)?;
                        crash_point("seller:k:post");
                    }
                    Err(e) => {
                        save(&seller)?;
                        // The offer is closed: tell the buyer once, now.
                        run.wire.send(&WireMsg::Refused {
                            subject_id: id,
                            reason: e.code(),
                        })?;
                        (run.log)(&format!("not proven: {}", e.code()));
                        continue;
                    }
                }
            }
            match seller.invoice(&id, run.rail) {
                Ok((bundle, binding)) => {
                    crash_point("seller:invoice:pre");
                    save(&seller)?;
                    crash_point("seller:invoice:post");
                    run.wire.send(&WireMsg::Bundle { bundle, binding })?;
                    (run.log)(&format!("invoice {} sent", short(&id)));
                }
                Err(e) => {
                    save(&seller)?;
                    // Closed (the offer lapsed before an invoice existed):
                    // tell the buyer once. Otherwise a rail error: retried.
                    if matches!(
                        seller.issued(&id).map(|o| &o.stage),
                        Some(OfferStage::Closed { .. })
                    ) {
                        run.wire.send(&WireMsg::Refused {
                            subject_id: id,
                            reason: e.code(),
                        })?;
                    }
                    (run.log)(&format!("invoice {}: {}", short(&id), e.code()));
                }
            }
        }

        // 3. Settle what is paid; end what can no longer be.
        let outcomes = seller.settle_paid(run.rail);
        let changed = outcomes.iter().any(|o| {
            matches!(
                o,
                SaleOutcome::Settled { .. } | SaleOutcome::Cancelled { .. }
            )
        });
        if changed {
            crash_point("seller:settle:pre");
            save(&seller)?;
            crash_point("seller:settle:post");
        }
        for o in &outcomes {
            match o {
                SaleOutcome::Settled { amount_msat, .. } => {
                    summary.settled += 1;
                    (run.log)(&format!("SETTLED: revealed k, {amount_msat} msat"));
                }
                SaleOutcome::Cancelled { reason, .. } => {
                    summary.cancelled += 1;
                    (run.log)(&format!("sale cancelled: {}", reason.code()));
                }
                SaleOutcome::Withheld { reason, .. } => {
                    (run.log)(&format!("k withheld for now: {}", reason.code()))
                }
                SaleOutcome::NotPaid { .. } => {}
            }
        }
        let expired = seller.expire_unproven(run.rail.now()).len();
        if expired + seller.purge(run.rail.now()) > 0 {
            save(&seller)?;
        }

        // 4. Stop?
        let snap = seller.snapshot();
        let over = snap.sales.iter().filter(|s| s.settled || s.closed).count();
        if seller.is_idle() && (over >= run.sales || last_msg.elapsed() >= run.quiet_exit) {
            show_unshown(&mut run, &mut unshown, &mut early_seen);
            summary.committed_msat = snap.committed_msat();
            (run.log)(&format!(
                "seller done: {} sales over, committed {} msat",
                over, summary.committed_msat
            ));
            return Ok(summary);
        }
        if start.elapsed() >= run.deadline {
            show_unshown(&mut run, &mut unshown, &mut early_seen);
            return Err(NodeError::Deadline);
        }
        std::thread::sleep(run.poll);
    }
}

/// One line for the refusals the text log did not show: those over the
/// per-minute limit, and those the transport refused before its queue.
fn show_unshown(run: &mut SellerRun, unshown: &mut u64, early_seen: &mut u64) {
    let early = run.wire.refused_before_queue();
    let new_early = early.saturating_sub(*early_seen);
    if *unshown > 0 || new_early > 0 {
        (run.log)(&format!(
            "refusals not shown: {} by the seller, {} before the queue",
            *unshown, new_early
        ));
    }
    *unshown = 0;
    *early_seen = early;
}

// ---------------------------------------------------------------------------
// Buyer

/// A buyer process. One purchase per state directory in S1.
pub struct BuyerRun<'a> {
    pub state_dir: PathBuf,
    pub wire: Box<dyn Wire>,
    pub rail: &'a mut dyn Rail,
    pub make_job: &'a dyn Fn() -> Box<dyn JobClass>,
    pub make_backend: &'a dyn Fn() -> Box<dyn ProofBackend>,
    pub policy: BuyerPolicy,
    /// The job input, used only to start a new purchase.
    pub input: Vec<u8>,
    pub max_price_msat: u64,
    pub poll: Duration,
    /// Resend the request or the accept this often while waiting.
    pub resend: Duration,
    /// Give up on a request with no offer after this long.
    pub offer_wait_secs: u64,
    pub deadline: Duration,
    /// Test only: send the accept for another offer id (a tampered offer).
    pub tamper_accept: bool,
    pub log: &'a mut dyn FnMut(&str),
}

/// How a purchase ended.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BuyerSummary {
    /// `Delivered`, `Refunded` or `Aborted`.
    pub state: String,
    /// Reason code when not delivered.
    pub reason: Option<String>,
    /// The result `R` (hex), when delivered.
    pub result_hex: Option<String>,
    pub spent_msat: u64,
}

fn open_buyer(run: &BuyerRun) -> Result<(StateDir, Buyer, bool), NodeError> {
    let dir = StateDir::open(&run.state_dir)?;
    let (key, mandate) = dir.agent_key_and_mandate()?;
    match dir.load::<BuyerSnapshot>()? {
        Some(saved) => {
            saved.check(&key, &mandate).map_err(NodeError::Mismatch)?;
            let agent = Agent::restore(key, mandate, saved.state.spent_msat, saved.log())?;
            let b = Buyer::restore(
                &agent,
                (run.make_job)(),
                (run.make_backend)(),
                run.policy.clone(),
                saved.state,
            )
            .map_err(|e| NodeError::Mismatch(e.code()))?;
            Ok((dir, b, false))
        }
        None => {
            let agent = Agent::new(key, mandate)?;
            let (b, _req) = Buyer::new(
                &agent,
                (run.make_job)(),
                (run.make_backend)(),
                run.policy.clone(),
                run.input.clone(),
                run.max_price_msat,
                run.rail.now(),
                &mut OsRng,
            )?;
            Ok((dir, b, true))
        }
    }
}

fn summary_of(b: &Buyer) -> BuyerSummary {
    let (reason, result_hex) = match b.state() {
        BuyerState::Delivered { result, .. } => (None, Some(hex::encode(result))),
        BuyerState::Refunded => (Some("refunded".into()), None),
        BuyerState::Aborted(e) => (Some(e.code()), None),
        _ => (None, None),
    };
    BuyerSummary {
        state: b.state().name().to_string(),
        reason,
        result_hex,
        spent_msat: b.spent_msat(),
    }
}

/// Run a buyer until its purchase is over. Resumes from the state directory.
pub fn run_buyer(run: BuyerRun) -> Result<BuyerSummary, NodeError> {
    let (dir, mut buyer, fresh) = open_buyer(&run)?;
    let save = |b: &Buyer| dir.save(&b.snapshot(), b.agent());
    let start = Instant::now();
    if fresh {
        save(&buyer)?;
        crash_point("buyer:request:post");
        run.wire.send(&WireMsg::Request {
            request: buyer.request().clone(),
        })?;
        (run.log)("request sent");
    } else {
        (run.log)(&format!("buyer resumed in {}", buyer.state().name()));
        pause_point("buyer:resumed");
    }
    // After a restart in Paying: find out from the node whether the money
    // left. A lookup error keeps Paying and is retried below.
    let mut last_resend = Instant::now();
    // The offer id named in the accept this process sent, if any.
    let mut sent_accept: Option<crate::encoding::Hash32> = None;
    loop {
        let now = run.rail.now();
        // 1. Messages.
        for (name, msg) in run.wire.receive()? {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    (run.log)(&format!("unreadable message {name}: {e}"));
                    continue;
                }
            };
            match msg {
                WireMsg::Offer { offer } => {
                    if matches!(buyer.state(), BuyerState::Requested) {
                        match buyer.accept_offer(&offer, now) {
                            Ok(()) => {
                                crash_point("buyer:offer:pre");
                                save(&buyer)?;
                                sent_accept = Some(send_accept(&run, &buyer)?);
                                crash_point("buyer:accept:post");
                                (run.log)(&format!(
                                    "offer accepted: {} msat, backend {}",
                                    offer.price_msat, offer.backend_id
                                ));
                            }
                            Err(e) => {
                                save(&buyer)?;
                                (run.log)(&format!("offer refused: {}", e.code()));
                            }
                        }
                    }
                }
                WireMsg::Bundle { bundle, binding } => {
                    if matches!(buyer.state(), BuyerState::OfferAccepted { .. }) {
                        let t = Instant::now();
                        let r = buyer
                            .verify_bundle(&bundle)
                            .and_then(|()| buyer.check_invoice(&binding, now));
                        match r {
                            Ok(()) => {
                                (run.log)(&format!(
                                    "proof verified in {:.3} s, invoice checked, before paying",
                                    t.elapsed().as_secs_f64()
                                ));
                                crash_point("buyer:invoice:pre");
                                save(&buyer)?;
                            }
                            Err(e) => {
                                save(&buyer)?;
                                (run.log)(&format!("bundle refused: {}", e.code()));
                            }
                        }
                    }
                }
                WireMsg::Refused { subject_id, reason } => {
                    // Only a refusal of this purchase's request or offer.
                    let ours = subject_id == buyer.request().request_id()
                        || buyer_offer_id(&buyer) == Some(subject_id)
                        || sent_accept == Some(subject_id);
                    if !ours {
                        (run.log)(&format!("ignored a refusal of {}", short(&subject_id)));
                        run.wire.ack(&name)?;
                        continue;
                    }
                    // The reason is the seller's text: keep it a reason code,
                    // so it cannot write escapes to the terminal or grow the
                    // saved state.
                    let reason = reason_code(&reason);
                    let e = buyer.refused_by_seller(&PcpError::Recorded(reason.clone()));
                    if !matches!(e, PcpError::WrongState(_)) {
                        save(&buyer)?;
                        (run.log)(&format!("seller refused: {reason}"));
                    }
                }
                other => (run.log)(&format!("ignored {}", other.name())),
            }
            run.wire.ack(&name)?;
        }

        // 2. Act on the current state.
        match buyer.state() {
            BuyerState::Requested | BuyerState::OfferAccepted { .. }
                if last_resend.elapsed() >= run.resend =>
            {
                last_resend = Instant::now();
                if matches!(buyer.state(), BuyerState::Requested) {
                    run.wire.send(&WireMsg::Request {
                        request: buyer.request().clone(),
                    })?;
                } else {
                    sent_accept = Some(send_accept(&run, &buyer)?);
                }
            }
            BuyerState::InvoiceAccepted { .. } => {
                // P0, once, saved before any payment of ours; then pay. A
                // refusal or an error falls through to the loop's tail
                // (timeouts, deadline, sleep), never `continue`: a lookup
                // error is not terminal and must not spin.
                let ready = buyer.payment_hash_checked()
                    || match buyer.check_payment_hash(run.rail) {
                        Ok(()) => {
                            save(&buyer)?;
                            true
                        }
                        Err(e) => {
                            save(&buyer)?;
                            (run.log)(&format!("not paying: {}", e.code()));
                            false
                        }
                    };
                let ready = ready
                    && match buyer.begin_pay(run.rail.rail_id(), run.rail.now()) {
                        Ok(()) => true,
                        Err(e) => {
                            save(&buyer)?;
                            (run.log)(&format!("not paying: {}", e.code()));
                            false
                        }
                    };
                if ready {
                    save(&buyer)?;
                    crash_point("buyer:paying:post");
                    match buyer.send_payment(run.rail) {
                        Ok(()) => {
                            crash_point("buyer:pay:pre");
                            save(&buyer)?;
                            crash_point("buyer:pay:post");
                            (run.log)("paid: HTLC to H on its way");
                        }
                        Err(e) => {
                            save(&buyer)?;
                            (run.log)(&format!("payment not sent: {}", e.code()));
                        }
                    }
                }
            }
            BuyerState::Paying { .. } => match buyer.recover_payment(run.rail) {
                Ok(()) => {
                    save(&buyer)?;
                    (run.log)("payment found at the node: it left");
                }
                Err(PcpError::NotPaid) => {
                    save(&buyer)?;
                    (run.log)("payment never left: reservation released");
                }
                Err(e) => (run.log)(&format!("payment status unknown: {}", e.code())),
            },
            BuyerState::Paid { .. } => match buyer.poll(run.rail) {
                Ok(BuyerProgress::Delivered) => {
                    crash_point("buyer:settle:pre");
                    save(&buyer)?;
                    crash_point("buyer:settle:post");
                    (run.log)("DELIVERED: have k, decrypted C, re-checked R");
                }
                Ok(BuyerProgress::Waiting) => {}
                Err(PcpError::Refunded) => {
                    save(&buyer)?;
                    (run.log)("REFUNDED");
                }
                Err(e) if buyer.is_done() => {
                    save(&buyer)?;
                    (run.log)(&format!("aborted after payment: {}", e.code()));
                }
                Err(e) => (run.log)(&format!("poll: {}", e.code())),
            },
            _ => {}
        }
        if buyer
            .check_timeouts(run.rail.now(), run.offer_wait_secs)
            .is_some()
        {
            save(&buyer)?;
        }

        if buyer.is_done() {
            let s = summary_of(&buyer);
            store::write_json(&run.state_dir.join("result.json"), &s)?;
            (run.log)(&format!(
                "buyer done: {} {}",
                s.state,
                s.reason.clone().unwrap_or_default()
            ));
            return Ok(s);
        }
        if start.elapsed() >= run.deadline {
            return Err(NodeError::Deadline);
        }
        std::thread::sleep(run.poll);
    }
}

/// Send the accept; returns the offer id it names (what a refusal of it
/// will name).
fn send_accept(run: &BuyerRun, buyer: &Buyer) -> Result<crate::encoding::Hash32, NodeError> {
    let mut accept = buyer.accept_message()?;
    if run.tamper_accept {
        // Test only: an accept for an offer the seller never issued, as if
        // the buyer had changed a term (any term changes offer_id).
        accept.offer_id[0] ^= 1;
    }
    let id = accept.offer_id;
    run.wire.send(&WireMsg::Accept { accept })?;
    Ok(id)
}

/// The offer this purchase accepted, if any.
fn buyer_offer_id(b: &Buyer) -> Option<crate::encoding::Hash32> {
    match b.state() {
        BuyerState::OfferAccepted { offer }
        | BuyerState::BundleVerified { offer, .. }
        | BuyerState::InvoiceAccepted { offer, .. }
        | BuyerState::Paying { offer, .. }
        | BuyerState::Paid { offer, .. } => Some(offer.offer_id()),
        _ => None,
    }
}

fn short(h: &[u8; 32]) -> String {
    hex::encode(&h[..6])
}

#[cfg(test)]
mod tests {
    #[test]
    fn refusal_reasons_are_reduced_to_codes() {
        assert_eq!(super::reason_code("seller_busy"), "seller_busy");
        assert_eq!(
            super::reason_code("refused_by_counterparty.offer_not_issued"),
            "refused_by_counterparty.offer_not_issued"
        );
        assert_eq!(super::reason_code("\u{1b}[2Jowned\n"), "2owned");
        assert_eq!(super::reason_code(&"x".repeat(10_000)).len(), 128);
        assert_eq!(super::reason_code("\u{1b}"), "unreadable_reason");
    }

    use super::sim_file::{self, SimFileRail};
    use super::store::StateDir;
    use super::wire::{DirTransport, WireMsg};
    use crate::mandate::{Agent, Mandate, MandateTerms, Role, SecretKey};
    use crate::protocol::SellerSnapshot;
    use crate::rail::{InvoiceRequest, Rail, RailError};
    use rand::rngs::OsRng;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pcp-node-{name}-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn agent_and_mandate(role: Role) -> (SecretKey, Mandate) {
        let principal = SecretKey::generate(&mut OsRng);
        let key = SecretKey::generate(&mut OsRng);
        let m = Mandate::sign(
            &principal,
            key.public_key(),
            MandateTerms {
                role,
                scope: vec![],
                cap_msat: 1,
                per_deal_max_msat: 1,
                payout_node: "n".into(),
                expires_at: 10,
            },
            &mut OsRng,
        );
        (key, m)
    }

    #[test]
    fn both_loops_stop_at_their_deadline() {
        use super::{run_buyer, run_seller, BuyerRun, NodeError, SellerRun};
        use crate::job::{JobClass, SudokuJob};
        use crate::proof::{InsecureDevTransparentBackend, ProofBackend};
        use crate::protocol::{BuyerPolicy, SellerConfig};
        use std::time::Duration;
        let job = SudokuJob::four();
        let mandate = |role| {
            let principal = SecretKey::generate(&mut OsRng);
            let key = SecretKey::generate(&mut OsRng);
            let m = Mandate::sign(
                &principal,
                key.public_key(),
                MandateTerms {
                    role,
                    scope: vec![job.spec_hash()],
                    cap_msat: 10_000_000,
                    per_deal_max_msat: 10_000_000,
                    payout_node: "n".into(),
                    expires_at: 1_000_000,
                },
                &mut OsRng,
            );
            (key, m)
        };
        let make_job = || Box::new(job) as Box<dyn JobClass>;
        let make_backend = || Box::new(InsecureDevTransparentBackend) as Box<dyn ProofBackend>;
        let d = tmp("deadline");
        let mut ledger = crate::lightning::Ledger::new();

        let (key, m) = mandate(Role::Seller);
        StateDir::open(&d.join("seller"))
            .unwrap()
            .init_agent(&key, &m)
            .unwrap();
        let work = |_: &[u8]| None;
        let r = run_seller(SellerRun {
            state_dir: d.join("seller"),
            wire: Box::new(DirTransport::new(&d.join("si"), &d.join("bi")).unwrap()),
            rail: &mut ledger,
            make_job: &make_job,
            make_backend: &make_backend,
            cfg: SellerConfig::default(),
            work: &work,
            poll: Duration::from_millis(1),
            sales: 1,
            quiet_exit: Duration::from_secs(3600),
            deadline: Duration::ZERO,
            log: &mut |_| {},
        });
        assert!(matches!(r, Err(NodeError::Deadline)), "{r:?}");

        let (key, m) = mandate(Role::Buyer);
        StateDir::open(&d.join("buyer"))
            .unwrap()
            .init_agent(&key, &m)
            .unwrap();
        let r = run_buyer(BuyerRun {
            state_dir: d.join("buyer"),
            wire: Box::new(DirTransport::new(&d.join("bi"), &d.join("si")).unwrap()),
            rail: &mut ledger,
            make_job: &make_job,
            make_backend: &make_backend,
            policy: BuyerPolicy {
                allow_insecure_dev_backend: true,
                ..BuyerPolicy::default()
            },
            input: job.parse_grid("1..4 ..1. .1.. 4..1").unwrap(),
            max_price_msat: 2_000_000,
            poll: Duration::from_millis(1),
            resend: Duration::from_secs(5),
            offer_wait_secs: 3600,
            deadline: Duration::ZERO,
            tamper_accept: false,
            log: &mut |_| {},
        });
        assert!(matches!(r, Err(NodeError::Deadline)), "{r:?}");
    }

    #[test]
    fn a_state_dir_is_held_by_one_process_and_freed_when_dropped() {
        let d = tmp("lock");
        let first = StateDir::open(&d).unwrap();
        assert!(matches!(
            StateDir::open(&d),
            Err(super::store::StoreError::Locked(_))
        ));
        drop(first);
        StateDir::open(&d).unwrap();
    }

    #[test]
    fn saved_state_round_trips_and_refuses_another_agent() {
        let d = tmp("state");
        let dir = StateDir::open(&d).unwrap();
        let (key, m) = agent_and_mandate(Role::Seller);
        dir.init_agent(&key, &m).unwrap();
        let (k2, m2) = dir.agent_key_and_mandate().unwrap();
        assert_eq!(k2.public_key(), key.public_key());
        assert_eq!(m2, m);
        let agent = Agent::new(k2, m2).unwrap();
        dir.save(&SellerSnapshot::default(), &agent).unwrap();
        let saved = dir.load::<SellerSnapshot>().unwrap().unwrap();
        saved.check(&key, &m).unwrap();
        let (other, om) = agent_and_mandate(Role::Seller);
        assert!(saved.check(&other, &om).is_err());
        // No temporary file is left behind.
        assert!(!d.join("state.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join("state.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "state.json readable by others");
        }
    }

    #[test]
    fn a_resent_message_replaces_the_earlier_copy() {
        let a = tmp("a");
        let b = tmp("b");
        let ta = DirTransport::new(&a, &b).unwrap();
        let tb = DirTransport::new(&b, &a).unwrap();
        let m = WireMsg::Refused {
            subject_id: [3u8; 32],
            reason: "x".into(),
        };
        ta.send(&m).unwrap();
        ta.send(&m).unwrap();
        let got = tb.receive().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1.as_ref().unwrap(), &m);
        tb.ack(&got[0].0).unwrap();
        tb.ack(&got[0].0).unwrap();
        assert!(tb.receive().unwrap().is_empty());
    }

    #[test]
    fn a_sim_file_rail_acts_only_for_its_node() {
        let d = tmp("sim");
        let f = d.join("sim.json");
        sim_file::create(
            &f,
            &[("seller", [1u8; 32], 0), ("buyer", [2u8; 32], 10_000)],
        )
        .unwrap();
        let mut seller = SimFileRail::new(&f, "seller");
        let mut buyer = SimFileRail::new(&f, "buyer");
        let k = [9u8; 32];
        let req = InvoiceRequest {
            payee: "seller".into(),
            payment_hash: crate::crypto::payment_hash(&k),
            amount_msat: 1_000,
            description_hash: [0u8; 32],
            expiry_secs: 600,
            min_htlc_secs: 60,
        };
        assert_eq!(buyer.create_invoice(&req), Err(RailError::NotThisNode));
        let inv = seller.create_invoice(&req).unwrap();
        assert_eq!(
            seller.pay_invoice("buyer", &inv, 3600),
            Err(RailError::NotThisNode)
        );
        buyer.pay_invoice("buyer", &inv, 3600).unwrap();
        assert_eq!(
            buyer.settle_invoice("seller", &req.payment_hash, k),
            Err(RailError::NotThisNode)
        );
        // The buyer's rail does not see the seller's incoming HTLC.
        assert_eq!(buyer.lookup_invoice(&req.payment_hash), Ok(None));
        assert!(seller.lookup_invoice(&req.payment_hash).unwrap().is_some());
        seller
            .settle_invoice("seller", &req.payment_hash, k)
            .unwrap();
        assert_eq!(sim_file::balance(&f, "seller").unwrap(), 1_000);
        assert_eq!(sim_file::balance(&f, "buyer").unwrap(), 9_000);
    }
}
