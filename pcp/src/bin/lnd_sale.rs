//! A sudoku sale over two real LND nodes (regtest), with the INSECURE dev
//! proof backend. Feature `lnd`. Run against LND v0.19.3-beta and
//! v0.21.4-beta on regtest by `.github/workflows/lnd-regtest.yml`; for a
//! local run see pcp/RUN.md.
//!
//! The point of this binary is the rail, not the proof: it checks that hold
//! invoices, payment and settlement on real LND behave the way the
//! simulated ledger does. For a real proof, run the RISC Zero host in
//! `../pcp-risc0/` with `--rail lnd`.
//!
//! Environment (paths as Polar shows them on each node's "Connect" tab):
//!
//! ```text
//! PCP_SELLER_LND_REST_URL  PCP_SELLER_LND_MACAROON  PCP_SELLER_LND_TLS_CERT
//! PCP_BUYER_LND_REST_URL   PCP_BUYER_LND_MACAROON   PCP_BUYER_LND_TLS_CERT
//! ```
//!
//! The two nodes need a channel from the buyer's node to the seller's node
//! with at least 10 000 sat of outbound liquidity on the buyer's side.

use std::time::Duration;

use pcp::job::{JobClass, SudokuJob};
use pcp::mandate::{Agent, Mandate, MandateTerms, Role, SecretKey};
use pcp::proof::InsecureDevTransparentBackend;
use pcp::protocol::{BuyerPolicy, SellerConfig};
use pcp::rail::lnd::{LndConfig, LndRail};
use pcp::rail::Rail;
use pcp::sale::{run_sale, SaleParams, TwoNodes};
use rand::rngs::OsRng;

/// Settings for a regtest run: the Lightning presets
/// ([`BuyerPolicy::lightning`], [`SellerConfig::lightning`]), whose
/// timelocks fit LND's minimum final CLTV (24 blocks) and its default
/// per-hop delta.
pub fn regtest_terms(price_msat: u64) -> (BuyerPolicy, SellerConfig) {
    (
        BuyerPolicy::lightning(),
        SellerConfig::lightning(price_msat),
    )
}

fn agent_for(principal: &SecretKey, role: Role, node: &str, job: &dyn JobClass, now: u64) -> Agent {
    let agent_key = SecretKey::generate(&mut OsRng);
    let m = Mandate::sign(
        principal,
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

fn main() {
    let connect = |who: &str| -> LndRail {
        let prefix = format!("PCP_{who}_LND_");
        let cfg = LndConfig::from_env(&prefix).unwrap_or_else(|e| {
            eprintln!("{e}. See pcp/RUN.md, the LND regtest section.");
            std::process::exit(2)
        });
        LndRail::connect(cfg).unwrap_or_else(|e| {
            eprintln!("cannot reach the {who} node: {e:?}");
            std::process::exit(2)
        })
    };
    let seller_rail = connect("SELLER");
    let buyer_rail = connect("BUYER");
    println!("seller node {}", seller_rail.node_id());
    println!("buyer node  {}", buyer_rail.node_id());
    println!("WARNING: proof backend = InsecureDevTransparentBackend (no zero knowledge).");
    println!("         This run tests the Lightning rail only. Regtest sats only.");

    let job = SudokuJob::nine();
    let input = job
        .parse_grid("53..7.... 6..195... .98....6. 8...6...3 4..8.3..1 7...2...6 .6....28. ...419..5 ....8..79")
        .expect("puzzle parses");
    let solution = job.solve(&input).expect("solvable");

    let now = seller_rail.now();
    let seller_principal = SecretKey::generate(&mut OsRng);
    let buyer_principal = SecretKey::generate(&mut OsRng);
    let seller_agent = agent_for(
        &seller_principal,
        Role::Seller,
        seller_rail.node_id(),
        &job,
        now,
    );
    let buyer_agent = agent_for(
        &buyer_principal,
        Role::Buyer,
        buyer_rail.node_id(),
        &job,
        now,
    );

    let price = 1_000_000; // 1 000 sat
    let (mut policy, cfg) = regtest_terms(price);
    policy.allow_insecure_dev_backend = true;

    let mut rails = TwoNodes {
        buyer: buyer_rail,
        seller: seller_rail,
        poll_interval: Duration::from_millis(500),
    };
    let r = run_sale(
        &buyer_agent,
        &seller_agent,
        &|| Box::new(SudokuJob::nine()),
        &|| Box::new(InsecureDevTransparentBackend),
        input,
        solution.clone(),
        SaleParams {
            max_price_msat: price,
            buyer_policy: policy,
            seller_config: cfg,
            max_waits: 120,
        },
        &mut rails,
        &mut |l| println!("  [{l}]"),
    );
    match r {
        Ok(rep) => {
            assert_eq!(rep.result, solution);
            println!(
                "SETTLED over LND: {} msat, preimage {}",
                rep.receipt.amount_msat,
                hex::encode(rep.receipt.preimage)
            );
            println!("result:\n{}", job.render(&rep.result));
        }
        Err(e) => {
            eprintln!("FAILED: {e} ({})", e.code());
            std::process::exit(1);
        }
    }
}
