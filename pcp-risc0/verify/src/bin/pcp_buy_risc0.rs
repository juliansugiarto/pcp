//! `pcp-buy-risc0`: a PCP buyer process that verifies real RISC Zero
//! receipts and builds without the RISC Zero toolchain. Same options and
//! exit codes as `pcp-buy`, plus `--image-id HEX` (default: the pinned id,
//! see ../../IMAGE-ID.md). The dev backend is refused.

use pcp::node::cli::{self, fail, Args};
use pcp::proof::ProofBackend;
use pcp_risc0_verify::{parse_image_id, Risc0Verifier, PINNED_IMAGE_ID};

const USAGE: &str = "\
pcp-buy-risc0 --state DIR (--seller-url URL | --inbox DIR --peer-inbox DIR)
              --rail (lnd|sim:FILE:NODE) [--image-id HEX] [--job sudoku9|sudoku4]
              [--puzzle TEXT] [--max-price-msat N] [--offer-wait-secs N]
              [--resend-secs N] [--deadline-secs N] [--poll-ms N]
              [--allow-sim] [--allow-insecure-transport]

Verifies RISC Zero succinct receipts of the PCP/0 guest against --image-id
(default: the pinned id). An offer naming another guest is refused
(backend_not_accepted). Exit 0 delivered, 10 refunded, 11 aborted, 1 error.";

fn main() {
    let a = Args::parse(USAGE, cli::FLAGS);
    let id_hex = a.get("image-id").unwrap_or(PINNED_IMAGE_ID).to_string();
    let image_id =
        parse_image_id(&id_hex).unwrap_or_else(|| fail(USAGE, "--image-id: 64 hex characters"));
    println!("verifying against guest image id {id_hex}");
    let make_backend = move || Box::new(Risc0Verifier::new(image_id)) as Box<dyn ProofBackend>;
    cli::run_buy(&a, USAGE, &make_backend, false)
}
