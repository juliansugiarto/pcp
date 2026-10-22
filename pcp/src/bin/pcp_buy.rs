//! `pcp-buy`: a PCP buyer process for one sudoku purchase, accepting the
//! INSECURE dev proof backend. It verifies the proof before paying, saves
//! its state after every step, and resumes from it after a restart.
//!
//! Exit codes: 0 delivered, 10 refunded, 11 aborted (refused or gave up),
//! 1 stopped by an error or the deadline, 2 usage.

use pcp::node::cli::{self, Args};
use pcp::proof::{InsecureDevTransparentBackend, ProofBackend};

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
    let make_backend = || Box::new(InsecureDevTransparentBackend) as Box<dyn ProofBackend>;
    cli::run_buy(&a, USAGE, &make_backend, true)
}
