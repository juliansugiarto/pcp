//! `pcp-sell`: a PCP seller process that solves sudoku, with the INSECURE
//! dev proof backend. It answers requests over a directory wire, proves,
//! invoices, and settles; it saves its state after every step and resumes
//! from it after a restart.

use std::time::Duration;

use pcp::node::cli::{fail, job_factory, logger, rail, sudoku, Args};
use pcp::node::wire::DirTransport;
use pcp::node::{run_seller, SellerRun};
use pcp::proof::{InsecureDevTransparentBackend, ProofBackend};
use pcp::protocol::SellerConfig;
use pcp::rail::RAIL_BOLT11;

const USAGE: &str = "\
pcp-sell --state DIR --inbox DIR --peer-inbox DIR --rail (sim:FILE:NODE|lnd)
         [--job sudoku9|sudoku4] [--price-msat N] [--sales N]
         [--quiet-exit-secs N] [--deadline-secs N] [--poll-ms N] [--allow-sim]
         [--work-delay-ms N] [--invoice-expiry-secs N]

Proof backend: InsecureDevTransparentBackend (NO zero knowledge; tests only).
Exit 0 when --sales sales are over and nothing is pending, or when nothing
is pending and no message came for --quiet-exit-secs. --work-delay-ms (tests)
makes each job take at least that long, so messages arrive during the work.";

fn main() {
    let a = Args::parse(USAGE, &["allow-sim"]);
    let job = sudoku(a.get("job").unwrap_or("sudoku9")).unwrap_or_else(|| fail(USAGE, "--job"));
    let mut rail = rail(a.req("rail"), a.flag("allow-sim"), USAGE);
    let price = a.num("price-msat", 1_000_000);
    let mut cfg = if rail.rail_id() == RAIL_BOLT11 {
        SellerConfig::lightning(price)
    } else {
        SellerConfig {
            price_msat: price,
            ..SellerConfig::default()
        }
    };
    cfg.invoice_expiry_secs = a.num("invoice-expiry-secs", cfg.invoice_expiry_secs);
    let wire = DirTransport::new(&a.path("inbox"), &a.path("peer-inbox"))
        .unwrap_or_else(|e| fail(USAGE, &e.to_string()));
    println!("WARNING: proof backend = InsecureDevTransparentBackend (no zero knowledge).");
    let make_job = job_factory(job);
    let make_backend = || Box::new(InsecureDevTransparentBackend) as Box<dyn ProofBackend>;
    let delay = Duration::from_millis(a.num("work-delay-ms", 0));
    let work = move |input: &[u8]| {
        std::thread::sleep(delay);
        job.solve(input)
    };
    let mut log = logger("seller");
    let r = run_seller(SellerRun {
        state_dir: a.path("state"),
        wire,
        rail: rail.as_mut(),
        make_job: &make_job,
        make_backend: &make_backend,
        cfg,
        work: &work,
        poll: Duration::from_millis(a.num("poll-ms", 200)),
        sales: a.num("sales", 1) as usize,
        quiet_exit: Duration::from_secs(a.num("quiet-exit-secs", 30)),
        deadline: Duration::from_secs(a.num("deadline-secs", 600)),
        log: &mut log,
    });
    match r {
        Ok(s) => println!(
            "seller summary: settled {} cancelled {} refused {} proofs {} committed_msat {}",
            s.settled, s.cancelled, s.refused, s.proofs_made, s.committed_msat
        ),
        Err(e) => {
            eprintln!("seller stopped: {e}");
            std::process::exit(1)
        }
    }
}
