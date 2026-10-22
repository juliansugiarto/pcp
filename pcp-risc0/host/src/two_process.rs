//! `pcp-risc0 --role sell|buy ...`: the seller or the buyer as its own
//! process, with real RISC Zero proofs, through `pcp::node` (state
//! directory, directory wire, restart after a crash). Takes the same
//! options as `pcp-sell` and `pcp-buy`, so `pcp/tools/crash-matrix.sh` can
//! drive it (`SELL_BIN`, `BUY_BIN`).
//!
//! The seller sells the demo job's result for the demo input only.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use pcp::node::cli::{fail, logger, rail, Args};
use pcp::node::wire::DirTransport;
use pcp::node::{run_buyer, run_seller, BuyerRun, SellerRun};
use pcp::proof::ProofBackend;
use pcp::protocol::{BuyerPolicy, SellerConfig};
use pcp::rail::RAIL_BOLT11;

use crate::{job_case, Risc0Backend};

const USAGE: &str = "\
pcp-risc0 --role sell|buy --state DIR --inbox DIR --peer-inbox DIR
          --rail (lnd|sim:FILE:NODE) [--job sudoku9|sudoku4|testsuite]
          [--allow-sim] [--price-msat N] [--max-price-msat N] [--sales N]
          [--quiet-exit-secs N] [--deadline-secs N] [--poll-ms N]
          [--resend-secs N] [--offer-wait-secs N] [--invoice-expiry-secs N]
          [--tamper-accept]

Options as for pcp-sell / pcp-buy. Proof backend: RISC Zero, local proving.";

pub fn run() -> ! {
    let a = Args::parse(USAGE, &["allow-sim", "tamper-accept"]);
    let role = a.req("role").to_string();
    let job_name = a.get("job").unwrap_or("sudoku9").to_string();
    let (make_job, input, result) = job_case(&job_name);
    let mut rail = rail(a.req("rail"), a.flag("allow-sim"), USAGE);
    let wire = DirTransport::new(&a.path("inbox"), &a.path("peer-inbox"))
        .unwrap_or_else(|e| fail(USAGE, &e.to_string()));
    let stats = Rc::new(RefCell::new(None));
    let s2 = stats.clone();
    let make_backend = move || Box::new(Risc0Backend::new(s2.clone())) as Box<dyn ProofBackend>;
    let make_job = move || make_job();
    let lightning = rail.rail_id() == RAIL_BOLT11;
    match role.as_str() {
        "sell" => {
            let price = a.num("price-msat", 1_000_000);
            let mut cfg = if lightning {
                SellerConfig::lightning(price)
            } else {
                SellerConfig {
                    price_msat: price,
                    ..SellerConfig::default()
                }
            };
            cfg.invoice_expiry_secs = a.num("invoice-expiry-secs", cfg.invoice_expiry_secs);
            let demo_input = input.clone();
            let work = move |inp: &[u8]| (inp == demo_input.as_slice()).then(|| result.clone());
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
                deadline: Duration::from_secs(a.num("deadline-secs", 900)),
                log: &mut log,
            });
            match r {
                Ok(s) => {
                    println!(
                        "seller summary: settled {} cancelled {} refused {} proofs {} committed_msat {}",
                        s.settled, s.cancelled, s.refused, s.proofs_made, s.committed_msat
                    );
                    if let Some(p) = stats.borrow().clone() {
                        println!(
                            "prove-row,job={job_name},segments={},user_cycles={},total_cycles={},prove_s={:.3},receipt_bytes={},peak_rss_mib={:.0}",
                            p.segments,
                            p.user_cycles,
                            p.total_cycles,
                            p.prove_secs,
                            p.receipt_bytes,
                            crate::peak_rss_mib()
                        );
                    }
                    std::process::exit(0)
                }
                Err(e) => {
                    eprintln!("seller stopped: {e}");
                    std::process::exit(1)
                }
            }
        }
        "buy" => {
            let policy = if lightning {
                BuyerPolicy::lightning()
            } else {
                BuyerPolicy::default()
            };
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
                deadline: Duration::from_secs(a.num("deadline-secs", 900)),
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
        _ => fail(USAGE, "--role must be sell or buy"),
    }
}
