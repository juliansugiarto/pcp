//! `pcp-setup`: create a seller and a buyer for a two-process test run, or
//! one side alone (`--buyer-only`, `--seller-only`) to deal with a
//! counterparty someone else runs.
//!
//! For each role: a principal key (kept in `<root>/<role>-principal.key`,
//! outside the agent's directory: the agent never holds it), a fresh agent
//! key, and the mandate the principal signs for it, written into the
//! agent's state directory. With `--sim`, also a TEST-ONLY simulated
//! network file with both principals' nodes.
//!
//! This is a test helper. A real principal signs a mandate with its own
//! key, on its own machine.

use pcp::mandate::{Mandate, MandateTerms, Role, SecretKey};
use pcp::node::cli::{fail, Args};
use pcp::node::sim_file;
use pcp::node::store::{write_atomic, StateDir};
use pcp::registry::JobRegistry;
use rand::rngs::OsRng;

const USAGE: &str = "\
pcp-setup --root DIR --seller-node ID --buyer-node ID [--sim FILE]
          [--cap-msat N] [--per-deal-msat N] [--buyer-funds-msat N]
          [--valid-secs N]
pcp-setup --root DIR --buyer-node ID --buyer-only [--cap-msat N]
          [--per-deal-msat N] [--valid-secs N]
pcp-setup --root DIR --seller-node ID --seller-only [--cap-msat N]
          [--per-deal-msat N] [--valid-secs N]

A node ID may be given as from-env:PREFIX (feature lnd): the id of the LND
node configured by PREFIX{REST_URL,MACAROON,TLS_CERT}.

Creates DIR/seller and DIR/buyer (agent state directories), DIR/seller-inbox
and DIR/buyer-inbox (the wire), and the principals' keys in DIR. With --sim,
FILE becomes a TEST-ONLY simulated network holding both nodes. With
--buyer-only, only DIR/buyer, DIR/buyer-principal.key and DIR/buyer-inbox:
what a buyer needs to buy from a seller it does not run (--seller-only: the
same for a seller). Limits default to a cap of 50,000 sat and 10,000 sat
per deal.";

fn main() {
    let a = Args::parse(USAGE, &["buyer-only", "seller-only"]);
    let root = a.path("root");
    let buyer_only = a.flag("buyer-only");
    let seller_only = a.flag("seller-only");
    if buyer_only && seller_only {
        fail(USAGE, "--buyer-only or --seller-only, not both");
    }
    if buyer_only && (a.get("seller-node").is_some() || a.get("sim").is_some()) {
        fail(USAGE, "--buyer-only takes no --seller-node or --sim");
    }
    if seller_only && (a.get("buyer-node").is_some() || a.get("sim").is_some()) {
        fail(USAGE, "--seller-only takes no --buyer-node or --sim");
    }
    let seller_node = if buyer_only {
        String::new()
    } else {
        node_id(a.req("seller-node"))
    };
    let buyer_node = if seller_only {
        String::new()
    } else {
        node_id(a.req("buyer-node"))
    };
    let cap = a.num("cap-msat", 50_000_000);
    let per_deal = a.num("per-deal-msat", 10_000_000);
    let valid = a.num("valid-secs", 7 * 86_400);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let sim = a.get("sim").map(std::path::PathBuf::from);
    // On the sim rail the clock starts at 0 when the file is created; on
    // LND it is Unix time.
    let expires_at = if sim.is_some() { valid } else { now + valid };
    let scope: Vec<_> = JobRegistry::reference()
        .entries()
        .map(|e| e.spec_hash)
        .collect();
    let mut principals = Vec::new();
    let roles: &[(Role, &String)] = if buyer_only {
        &[(Role::Buyer, &buyer_node)]
    } else if seller_only {
        &[(Role::Seller, &seller_node)]
    } else {
        &[(Role::Seller, &seller_node), (Role::Buyer, &buyer_node)]
    };
    for &(role, node) in roles {
        let name = role.as_str();
        let principal = SecretKey::generate(&mut OsRng);
        let agent_key = SecretKey::generate(&mut OsRng);
        let mandate = Mandate::sign(
            &principal,
            agent_key.public_key(),
            MandateTerms {
                role,
                scope: scope.clone(),
                cap_msat: cap,
                per_deal_max_msat: per_deal,
                payout_node: node.clone(),
                expires_at,
            },
            &mut OsRng,
        );
        let dir = StateDir::open(&root.join(name)).unwrap_or_else(|e| fail(USAGE, &e.to_string()));
        if dir.path().join("mandate.json").exists() {
            fail(
                USAGE,
                &format!("{} is already set up", dir.path().display()),
            );
        }
        dir.init_agent(&agent_key, &mandate)
            .unwrap_or_else(|e| fail(USAGE, &e.to_string()));
        write_atomic(
            &root.join(format!("{name}-principal.key")),
            format!("{}\n", hex::encode(principal.to_seed())).as_bytes(),
        )
        .unwrap_or_else(|e| fail(USAGE, &e.to_string()));
        std::fs::create_dir_all(root.join(format!("{name}-inbox")))
            .unwrap_or_else(|e| fail(USAGE, &e.to_string()));
        println!(
            "{name}: agent {} node {node}",
            hex::encode(agent_key.public_key())
        );
        principals.push((node.clone(), principal.public_key()));
    }
    if let Some(sim) = sim {
        let funds = a.num("buyer-funds-msat", 100_000_000);
        sim_file::create(
            &sim,
            &[
                (principals[0].0.as_str(), principals[0].1, 0),
                (principals[1].0.as_str(), principals[1].1, funds),
            ],
        )
        .unwrap_or_else(|e| fail(USAGE, &e));
        println!("sim network: {} (TEST ONLY)", sim.display());
    }
}

/// A node id as given, or read from an LND node (`from-env:PREFIX`).
fn node_id(arg: &str) -> String {
    match arg.strip_prefix("from-env:") {
        None => arg.to_string(),
        Some(prefix) => lnd_node_id(prefix),
    }
}

#[cfg(feature = "lnd")]
fn lnd_node_id(prefix: &str) -> String {
    use pcp::rail::lnd::{LndConfig, LndRail};
    let cfg = LndConfig::from_env(prefix).unwrap_or_else(|e| fail(USAGE, &e));
    let rail = LndRail::connect(cfg).unwrap_or_else(|e| fail(USAGE, &format!("{e:?}")));
    rail.node_id().to_string()
}

#[cfg(not(feature = "lnd"))]
fn lnd_node_id(_prefix: &str) -> String {
    fail(USAGE, "from-env: needs the lnd feature")
}
