//! `pcp-buy`: a PCP buyer process for one sudoku purchase, accepting the
//! INSECURE dev proof backend. It verifies the proof before paying, saves
//! its state after every step, and resumes from it after a restart.
//!
//! Exit codes: 0 delivered, 10 refunded, 11 aborted (refused or gave up),
//! 1 stopped by an error or the deadline, 2 usage.

use std::time::Duration;

use pcp::node::cli::{self, fail, job_factory, logger, rail, sudoku, Args, DEFAULT_PUZZLE9};
use pcp::node::{run_buyer, BuyerRun};
use pcp::proof::{InsecureDevTransparentBackend, ProofBackend};
use pcp::protocol::BuyerPolicy;
use pcp::rail::RAIL_BOLT11;

const USAGE: &str = "\
pcp-buy --state DIR (--seller-url URL | --inbox DIR --peer-inbox DIR)
        --rail (sim:FILE:NODE|lnd) [--allow-insecure-transport] [--job sudoku9|sudoku4] [--puzzle TEXT] [--max-price-msat N]
        [--offer-wait-secs N] [--resend-secs N] [--deadline-secs N]
        [--poll-ms N] [--allow-sim] [--tamper-accept]

Accepts the INSECURE dev proof backend (tests only). --tamper-accept sends
an accept for an offer the seller never issued (a test of the seller).
--seller-url talks to a seller over HTTP (feature http, SPEC 5.5); it must be
https:// unless --allow-insecure-transport (tests on loopback).";

fn main() {
    let a = Args::parse(USAGE, cli::FLAGS);
    let job = sudoku(a.get("job").unwrap_or("sudoku9")).unwrap_or_else(|| fail(USAGE, "--job"));
    let input = job
        .parse_grid(a.get("puzzle").unwrap_or(DEFAULT_PUZZLE9))
        .unwrap_or_else(|| fail(USAGE, "--puzzle does not parse"));
    let mut rail = rail(a.req("rail"), a.flag("allow-sim"), USAGE);
    let mut policy = if rail.rail_id() == RAIL_BOLT11 {
        BuyerPolicy::lightning()
    } else {
        BuyerPolicy::default()
    };
    policy.allow_insecure_dev_backend = true;
    let wire = cli::wire(&a, USAGE);
    let make_job = job_factory(job);
    let make_backend = || Box::new(InsecureDevTransparentBackend) as Box<dyn ProofBackend>;
    let mut log = logger("buyer");
    let r = run_buyer(BuyerRun {
        state_dir: a.path("state"),
        wire,
        rail: rail.as_mut(),
        make_job: &make_job,
        make_backend: &make_backend,
        policy,
        input,
        max_price_msat: a.num("max-price-msat", 2_000_000),
        poll: Duration::from_millis(a.num("poll-ms", 200)),
        resend: Duration::from_secs(a.num("resend-secs", 5)),
        offer_wait_secs: a.num("offer-wait-secs", 120),
        deadline: Duration::from_secs(a.num("deadline-secs", 600)),
        tamper_accept: a.flag("tamper-accept"),
        log: &mut log,
    });
    match r {
        Ok(s) => {
            println!(
                "buyer summary: {} {} spent_msat {}",
                s.state,
                s.reason.clone().unwrap_or_default(),
                s.spent_msat
            );
            if let Some(hex_r) = &s.result_hex {
                if let Ok(grid) = hex::decode(hex_r) {
                    println!("{}", job.render(&grid));
                }
            }
            std::process::exit(match s.state.as_str() {
                "Delivered" => 0,
                "Refunded" => 10,
                _ => 11,
            })
        }
        Err(e) => {
            eprintln!("buyer stopped: {e}");
            std::process::exit(1)
        }
    }
}
