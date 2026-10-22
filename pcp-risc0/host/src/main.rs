//! PCP/0 with a real proof: the RISC Zero backend, and a sale that uses it.
//!
//! `Risc0Backend` implements `pcp::proof::ProofBackend`:
//!
//! - `prove` runs the statement core in the clear first (a sound prover
//!   refuses a false statement before spending prover time), then proves the
//!   guest **locally** with `LocalProver` and a succinct (STARK, transparent,
//!   no trusted setup) receipt. Remote proving is off by construction: the
//!   `bonsai` feature of risc0-zkvm is not enabled, and `LocalProver` is used
//!   directly instead of `default_prover()`, which would follow
//!   `RISC0_PROVER` / `BONSAI_API_KEY` from the environment. A proving
//!   service would learn R and k. Dev mode (fake receipts) is refused.
//! - `verify` is `pcp_risc0_verify::verify_receipt`, the code a verify-only
//!   buyer runs: public fields, size cap, no fake receipt, receipt valid for
//!   the image id (exit code 0), journal equal to the expected statement.
//!
//! `backend_id` is `risc0-zkvm-3-succinct/<image id hex>`, so the offer
//! (whose `offer_id` commits to `backend_id`) names the exact guest binary.
//!
//! STATUS: built and run in CI against risc0-zkvm 3.0.6, 21 October 2026.
//! Over the simulated rail, sudoku n=4, sudoku n=9 and the test-suite job
//! each settled with a real proof. With the guest built reproducibly in
//! Docker (`RISC0_USE_DOCKER=1`, builder r0.1.97.0, image id `cc6e7b82…e328`), a sudoku sale
//! and a test-suite sale settled over two LND v0.21.4 nodes on regtest
//! (`real-sale` workflow). Not audited. See ../README.md and ../COSTS.md.
//!
//! Usage (see ../../pcp/RUN.md), from `pcp-risc0/` (`--rail lnd` needs
//! `--features lnd`):
//!
//! ```text
//! cargo run --release -p pcp-risc0-host -- [--job sudoku9|sudoku4|testsuite] [--rail sim|lnd] [--execute-only]
//! ```
//!
//! With `--role sell|buy` it runs one side as its own process instead
//! (state directory, directory wire, restarts): see `two_process.rs`.

mod two_process;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

use methods::{PCP_GUEST_ELF, PCP_GUEST_ID};
use pcp::crypto;
use pcp::job::{JobClass, SudokuJob, TestSuiteJob};
use pcp::lightning::Ledger;
use pcp::mandate::{Agent, Mandate, MandateTerms, Role, SecretKey};
use pcp::proof::{ProofBackend, ProofBundle, ProveError, Statement, VerifyError, Witness};
use pcp::protocol::{BuyerPolicy, SellerConfig};
use pcp::sale::{run_sale, SaleParams, SaleRails};
use pcp::statement::evaluate_with;
use rand::rngs::OsRng;
use risc0_zkvm::{Digest, Executor, ExecutorEnv, InnerReceipt, LocalProver, Prover, ProverOpts};

/// What one proof cost, for the cost table.
#[derive(Clone, Debug, Default)]
pub struct ProveStats {
    pub segments: usize,
    pub total_cycles: u64,
    pub user_cycles: u64,
    pub prove_secs: f64,
    pub receipt_bytes: usize,
}

/// The RISC Zero proof backend. Local proving only.
pub struct Risc0Backend {
    image_id: Digest,
    backend_id: &'static str,
    /// Filled by `prove`, read by the cost report.
    pub last_stats: Rc<RefCell<Option<ProveStats>>>,
}

impl Risc0Backend {
    /// A backend pinned to the guest built in `methods/`. A buyer pins the
    /// image id it built (or obtained) itself; this is what makes a receipt
    /// mean "the PCP/0 statement core ran".
    pub fn new(stats: Rc<RefCell<Option<ProveStats>>>) -> Risc0Backend {
        let image_id = Digest::from(PCP_GUEST_ID);
        // ProofBackend::backend_id returns &'static str; one small leak per
        // process.
        let backend_id: &'static str =
            Box::leak(pcp_risc0_verify::backend_id_for(&image_id).into_boxed_str());
        Risc0Backend {
            image_id,
            backend_id,
            last_stats: stats,
        }
    }

    fn opts() -> ProverOpts {
        // Succinct: one constant-size STARK receipt. Never Groth16: it needs
        // a trusted setup (SPEC.md T9) and Docker, and PCP/0 verifies
        // off-chain. Dev mode off whatever RISC0_DEV_MODE says.
        ProverOpts::succinct().with_dev_mode(false)
    }

    fn env_for(input: &[u8]) -> Result<ExecutorEnv<'static>, ProveError> {
        ExecutorEnv::builder()
            .write_frame(input)
            .build()
            .map_err(|e| ProveError::Backend(format!("executor env: {e}")))
    }
}

impl ProofBackend for Risc0Backend {
    fn backend_id(&self) -> &'static str {
        self.backend_id
    }

    fn is_secure(&self) -> bool {
        true
    }

    fn prove(
        &self,
        job: &dyn JobClass,
        statement: &Statement,
        ciphertext: &[u8],
        witness: &Witness,
    ) -> Result<ProofBundle, ProveError> {
        // Refuse a false statement in the clear, with the same verdicts as
        // every other backend, before any proving.
        let input = witness.statement_input(statement, ciphertext);
        let journal = evaluate_with(job, &input).map_err(|e| ProveError::Unsatisfied(e.into()))?;
        journal
            .check_expected(&statement.journal())
            .map_err(|e| ProveError::Unsatisfied(e.into()))?;

        let env = Self::env_for(&input.encode())?;
        let t = Instant::now();
        let info = LocalProver::new("pcp-local")
            .prove_with_opts(env, PCP_GUEST_ELF, &Self::opts())
            .map_err(|e| ProveError::Backend(format!("local prover: {e}")))?;
        let prove_secs = t.elapsed().as_secs_f64();
        if matches!(info.receipt.inner, InnerReceipt::Fake(_)) {
            return Err(ProveError::Backend("prover returned a fake receipt".into()));
        }
        if info.receipt.journal.bytes != journal.to_bytes() {
            return Err(ProveError::Backend(
                "guest journal differs from the statement".into(),
            ));
        }
        let proof = bincode::serialize(&info.receipt)
            .map_err(|e| ProveError::Backend(format!("serialize receipt: {e}")))?;
        *self.last_stats.borrow_mut() = Some(ProveStats {
            segments: info.stats.segments,
            total_cycles: info.stats.total_cycles,
            user_cycles: info.stats.user_cycles,
            prove_secs,
            receipt_bytes: proof.len(),
        });
        Ok(ProofBundle {
            version: statement.version.clone(),
            backend_id: self.backend_id.to_string(),
            statement: statement.clone(),
            ciphertext: ciphertext.to_vec(),
            proof,
        })
    }

    fn verify(
        &self,
        job: &dyn JobClass,
        statement: &Statement,
        bundle: &ProofBundle,
    ) -> Result<(), VerifyError> {
        // The same checks a verify-only buyer runs (pcp-risc0-verify).
        pcp_risc0_verify::verify_receipt(self.image_id, self.backend_id, job, statement, bundle)
    }
}

// ---------------------------------------------------------------------------
// The demo sale and the cost report

struct Args {
    job: String,
    rail: String,
    execute_only: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        job: "sudoku9".into(),
        rail: "sim".into(),
        execute_only: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--job" => a.job = it.next().unwrap_or_default(),
            "--rail" => a.rail = it.next().unwrap_or_default(),
            "--execute-only" => a.execute_only = true,
            _ => {
                eprintln!("usage: pcp-risc0 [--job sudoku9|sudoku4|testsuite] [--rail sim|lnd] [--execute-only]");
                std::process::exit(2);
            }
        }
    }
    a
}

/// (job factory, input, the seller's result)
type JobCase = (fn() -> Box<dyn JobClass>, Vec<u8>, Vec<u8>);

fn job_case(name: &str) -> JobCase {
    match name {
        "sudoku9" => {
            let j = SudokuJob::nine();
            let input = j
                .parse_grid("53..7.... 6..195... .98....6. 8...6...3 4..8.3..1 7...2...6 .6....28. ...419..5 ....8..79")
                .unwrap();
            let r = j.solve(&input).unwrap();
            (|| Box::new(SudokuJob::nine()), input, r)
        }
        "sudoku4" => {
            let j = SudokuJob::four();
            let input = j.parse_grid("1..4 ..1. .1.. 4..1").unwrap();
            let r = j.solve(&input).unwrap();
            (|| Box::new(SudokuJob::four()), input, r)
        }
        "testsuite" => {
            let suite = TestSuiteJob::encode_suite(&[
                (-5, 0),
                (0, 0),
                (42, 42),
                (100, 100),
                (101, 100),
                (i64::MAX, 100),
                (i64::MIN, 0),
            ]);
            (
                || Box::new(TestSuiteJob),
                suite,
                b"if(x < 0, 0, if(x > 100, 100, x))".to_vec(),
            )
        }
        other => {
            eprintln!("unknown job {other}");
            std::process::exit(2)
        }
    }
}

/// Peak resident set size of this process, in MiB.
fn peak_rss_mib() -> f64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage writes into the struct we pass.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return f64::NAN;
    }
    let raw = ru.ru_maxrss as f64;
    if cfg!(target_os = "macos") {
        raw / (1024.0 * 1024.0) // bytes on macOS
    } else {
        raw / 1024.0 // KiB on Linux
    }
}

fn agent_for(role: Role, node: &str, job: &dyn JobClass, now: u64) -> Agent {
    let principal = SecretKey::generate(&mut OsRng);
    let agent_key = SecretKey::generate(&mut OsRng);
    let m = Mandate::sign(
        &principal,
        agent_key.public_key(),
        MandateTerms {
            role,
            scope: vec![job.spec_hash()],
            cap_msat: 50_000_000,
            per_deal_max_msat: 10_000_000,
            payout_node: node.to_string(),
            expires_at: now + 86_400,
        },
        &mut OsRng,
    );
    Agent::new(agent_key, m).expect("mandate verifies")
}

/// Cycle count only: run the guest in the executor, no proof.
fn execute_only(make_job: fn() -> Box<dyn JobClass>, input: Vec<u8>, result: Vec<u8>) {
    let job = make_job();
    let key = crypto::fresh_key(&mut OsRng);
    let offer_id = [0x22; 32];
    let si = pcp::statement::StatementInput {
        spec_hash: job.spec_hash(),
        ciphertext: crypto::encrypt(&key, &offer_id, &result),
        input,
        result,
        key,
        offer_id,
        buyer_nonce: [0x44; 32],
    };
    let env = Risc0Backend::env_for(&si.encode()).expect("env");
    let t = Instant::now();
    let session = LocalProver::new("pcp-local")
        .execute(env, PCP_GUEST_ELF)
        .expect("guest runs");
    let cycles: u64 = session.segments.iter().map(|s| u64::from(s.cycles)).sum();
    // Each segment is proven at its padded size 2^po2 (user cycles plus
    // paging and reserved cycles, rounded up): the total a prove reports.
    let total: u64 = session.segments.iter().map(|s| 1u64 << s.po2).sum();
    let po2s: Vec<String> = session.segments.iter().map(|s| s.po2.to_string()).collect();
    println!(
        "execute-only: {} segment(s), {} user cycles, total {} (po2 {}), {:.3} s, journal {} bytes, peak RSS {:.0} MiB",
        session.segments.len(),
        cycles,
        total,
        po2s.join(","),
        t.elapsed().as_secs_f64(),
        session.journal.bytes.len(),
        peak_rss_mib()
    );
}

fn main() {
    if std::env::args().any(|a| a == "--role") {
        println!(
            "guest image id {}",
            hex::encode(Digest::from(PCP_GUEST_ID).as_bytes())
        );
        two_process::run();
    }
    let args = parse_args();
    let (make_job, input, result) = job_case(&args.job);
    println!(
        "guest image id {}",
        hex::encode(Digest::from(PCP_GUEST_ID).as_bytes())
    );
    if args.execute_only {
        execute_only(make_job, input, result);
        return;
    }

    let stats = Rc::new(RefCell::new(None));
    let stats_for_backend = stats.clone();
    let make_backend =
        move || -> Box<dyn ProofBackend> { Box::new(Risc0Backend::new(stats_for_backend.clone())) };
    let price = 1_000_000;
    let job = make_job();

    let mut ledger;
    #[cfg(feature = "lnd")]
    let mut two;
    let (rails, buyer_node, seller_node, policy, cfg): (
        &mut dyn SaleRails,
        String,
        String,
        BuyerPolicy,
        SellerConfig,
    ) = match args.rail.as_str() {
        "sim" => {
            ledger = Ledger::new();
            ledger.open_node("buyer-node", 10_000_000);
            ledger.open_node("seller-node", 0);
            let cfg = SellerConfig {
                price_msat: price,
                ..SellerConfig::default()
            };
            (
                &mut ledger,
                "buyer-node".into(),
                "seller-node".into(),
                BuyerPolicy::default(),
                cfg,
            )
        }
        #[cfg(feature = "lnd")]
        "lnd" => {
            use pcp::rail::lnd::{LndConfig, LndRail};
            let connect = |p: &str| {
                LndRail::connect(LndConfig::from_env(p).unwrap_or_else(|e| panic!("{e}")))
                    .unwrap_or_else(|e| panic!("{p}: {e:?}"))
            };
            two = pcp::sale::TwoNodes {
                buyer: connect("PCP_BUYER_LND_"),
                seller: connect("PCP_SELLER_LND_"),
                poll_interval: std::time::Duration::from_millis(500),
            };
            let (b, s) = (
                two.buyer.node_id().to_string(),
                two.seller.node_id().to_string(),
            );
            // Lightning presets: timelocks in whole blocks that fit LND's
            // minimum final CLTV and its default per-hop delta.
            let policy = BuyerPolicy::lightning();
            let cfg = SellerConfig::lightning(price);
            (&mut two, b, s, policy, cfg)
        }
        other => {
            eprintln!("unknown rail {other} (lnd needs --features lnd)");
            std::process::exit(2)
        }
    };
    let now = rails.buyer().now();
    let buyer_agent = agent_for(Role::Buyer, &buyer_node, job.as_ref(), now);
    let seller_agent = agent_for(Role::Seller, &seller_node, job.as_ref(), now);
    let report = run_sale(
        &buyer_agent,
        &seller_agent,
        &move || make_job(),
        &make_backend,
        input,
        result,
        SaleParams {
            max_price_msat: price,
            buyer_policy: policy,
            seller_config: cfg,
            max_waits: 120,
        },
        rails,
        &mut |l| println!("  [{l}]"),
    );
    match report {
        Ok(r) => {
            let s = stats.borrow().clone().unwrap_or_default();
            let shown = match args.job.as_str() {
                "testsuite" => format!("f(x) = {}", String::from_utf8_lossy(&r.result)),
                "sudoku4" => SudokuJob::four().render(&r.result),
                _ => SudokuJob::nine().render(&r.result),
            };
            println!("SETTLED. Result R:\n{shown}");
            println!(
                "cost-row,job={},backend={},segments={},user_cycles={},total_cycles={},prove_s={:.3},verify_s={:.3},receipt_bytes={},settle_s={:.3},peak_rss_mib={:.0}",
                args.job,
                r.backend_id,
                s.segments,
                s.user_cycles,
                s.total_cycles,
                s.prove_secs,
                r.verify_time.as_secs_f64(),
                s.receipt_bytes,
                r.settle_time.as_secs_f64(),
                peak_rss_mib()
            );
        }
        Err(e) => {
            eprintln!("FAILED: {e} ({})", e.code());
            std::process::exit(1);
        }
    }
}
