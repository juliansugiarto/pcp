//! One sale, end to end, over any proof backend and any settlement rail.
//!
//! A driver for programs that run a real instance (the LND regtest binary
//! `lnd_sale`, the RISC Zero host in `../pcp-risc0/`). It runs the buyer and
//! the seller in one process, in the order of SPEC.md section 9, and
//! measures the steps that go into the cost table. The two sides still only
//! talk through PCP messages and their own rails.

use std::time::{Duration, Instant};

use rand::rngs::OsRng;

use crate::job::JobClass;
use crate::lightning::Ledger;
use crate::mandate::Agent;
use crate::proof::ProofBackend;
use crate::protocol::{
    Buyer, BuyerPolicy, BuyerProgress, PcpError, Receipt, SaleOutcome, Seller, SellerConfig,
};
use crate::rail::Rail;

/// The buyer's and the seller's views of the settlement rail.
pub trait SaleRails {
    /// The buyer principal's node.
    fn buyer(&mut self) -> &mut dyn Rail;
    /// The seller principal's node.
    fn seller(&mut self) -> &mut dyn Rail;
    /// Let time pass between polls (advance the simulated clock, or sleep).
    fn wait(&mut self);
}

/// On the simulated ledger both principals' nodes live in one ledger; a
/// wait advances its clock by one second.
impl SaleRails for Ledger {
    fn buyer(&mut self) -> &mut dyn Rail {
        self
    }
    fn seller(&mut self) -> &mut dyn Rail {
        self
    }
    fn wait(&mut self) {
        self.advance(1);
    }
}

/// Two separate rails (for example two LND nodes) and a real-time wait.
pub struct TwoNodes<B: Rail, S: Rail> {
    pub buyer: B,
    pub seller: S,
    pub poll_interval: Duration,
}

impl<B: Rail, S: Rail> SaleRails for TwoNodes<B, S> {
    fn buyer(&mut self) -> &mut dyn Rail {
        &mut self.buyer
    }
    fn seller(&mut self) -> &mut dyn Rail {
        &mut self.seller
    }
    fn wait(&mut self) {
        std::thread::sleep(self.poll_interval);
    }
}

/// Terms and policies for one sale.
pub struct SaleParams {
    pub max_price_msat: u64,
    pub buyer_policy: BuyerPolicy,
    pub seller_config: SellerConfig,
    /// Give up after this many waits for the HTLC to lock or settle.
    pub max_waits: u32,
}

/// What happened, with the numbers for the cost table.
#[derive(Debug)]
pub struct SaleReport {
    pub result: Vec<u8>,
    pub receipt: Receipt,
    pub backend_id: String,
    pub ciphertext_bytes: usize,
    pub proof_bytes: usize,
    /// Seller: encrypt, prove and create the invoice (`Seller::fulfil`).
    pub fulfil_time: Duration,
    /// Buyer: verify the bundle before paying (`Buyer::verify_bundle`).
    pub verify_time: Duration,
    /// From the buyer's payment to the buyer holding `k` and `R`.
    pub settle_time: Duration,
}

/// Run one sale: request, offer, fulfil (prove), verify, check invoice, pay,
/// settle, deliver. `make_job` and `make_backend` are called once per side.
/// `result` is the seller's work. `log` receives one line per step.
#[allow(clippy::too_many_arguments)]
pub fn run_sale(
    buyer_agent: &Agent,
    seller_agent: &Agent,
    make_job: &dyn Fn() -> Box<dyn JobClass>,
    make_backend: &dyn Fn() -> Box<dyn ProofBackend>,
    input: Vec<u8>,
    result: Vec<u8>,
    params: SaleParams,
    rails: &mut dyn SaleRails,
    log: &mut dyn FnMut(&str),
) -> Result<SaleReport, PcpError> {
    let now = rails.buyer().now();
    let (mut buyer, req) = Buyer::new(
        buyer_agent,
        make_job(),
        make_backend(),
        params.buyer_policy,
        input,
        params.max_price_msat,
        now,
        &mut OsRng,
    )?;
    log("1 request sent");

    let mut seller = Seller::new(
        seller_agent,
        make_job(),
        make_backend(),
        params.seller_config,
    );
    let now = rails.seller().now();
    let offer = match seller.make_offer(&req, now) {
        Ok(o) => o,
        Err(e) => {
            buyer.refused_by_seller(&e);
            return Err(e);
        }
    };
    buyer.accept_offer(&offer, rails.buyer().now())?;
    log(&format!(
        "2 offer accepted: {} msat, backend {}, rail {}",
        offer.price_msat, offer.backend_id, offer.rail
    ));

    let t = Instant::now();
    let (bundle, binding) = seller.fulfil(&req, &offer, result, rails.seller(), &mut OsRng)?;
    let fulfil_time = t.elapsed();
    log(&format!(
        "3 seller proved and invoiced in {:.3} s: C {} bytes, proof {} bytes",
        fulfil_time.as_secs_f64(),
        bundle.ciphertext.len(),
        bundle.proof.len()
    ));

    let t = Instant::now();
    buyer.verify_bundle(&bundle)?;
    let verify_time = t.elapsed();
    log(&format!(
        "4 buyer verified the proof in {:.3} s, before paying",
        verify_time.as_secs_f64()
    ));
    buyer.check_invoice(&binding, rails.buyer().now())?;
    log("5 invoice checked: hash, amount, payee, description, expiry");

    let t = Instant::now();
    buyer.pay_via(rails.buyer())?;
    log("6 paid: HTLC to H on its way");

    let mut settled = false;
    for _ in 0..params.max_waits {
        if !settled {
            for o in seller.settle_paid(rails.seller()) {
                match o {
                    SaleOutcome::Settled { amount_msat, .. } => {
                        settled = true;
                        log(&format!(
                            "7 seller settled: revealed k, {amount_msat} msat received"
                        ));
                    }
                    SaleOutcome::Withheld { reason, .. } => {
                        log(&format!("7 seller withholds k: {}", reason.code()))
                    }
                    SaleOutcome::Cancelled { reason, .. } => {
                        log(&format!("7 seller cancelled the sale: {}", reason.code()))
                    }
                    SaleOutcome::NotPaid { .. } => {}
                }
            }
        }
        if buyer.poll(rails.buyer())? == BuyerProgress::Delivered {
            let settle_time = t.elapsed();
            log(&format!(
                "8 buyer has k, decrypted C and re-checked R ({:.3} s after paying)",
                settle_time.as_secs_f64()
            ));
            return Ok(SaleReport {
                result: buyer.result()?.to_vec(),
                receipt: buyer.receipt()?.clone(),
                backend_id: bundle.backend_id.clone(),
                ciphertext_bytes: bundle.ciphertext.len(),
                proof_bytes: bundle.proof.len(),
                fulfil_time,
                verify_time,
                settle_time,
            });
        }
        rails.wait();
    }
    Err(PcpError::NotPaid)
}
