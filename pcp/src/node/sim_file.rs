//! TEST ONLY: the simulated ledger in a file, shared by two processes.
//!
//! Lets the buyer and the seller run as separate processes, and be killed
//! and restarted, without Lightning nodes. Each call locks the file, loads
//! the ledger, acts, and writes it back atomically.
//!
//! What it cannot show, and the LND runs must: a payment registered with
//! no HTLC yet, a lookup that fails because the node is down, two nodes
//! that disagree for a moment, LND's own expiry handling. See
//! `docs` / Fable's S1 review, question 5.
//!
//! Each rail is pinned to one node: a seller's rail cannot pay and a
//! buyer's rail cannot settle, as with a real node (`RailError::NotThisNode`).
//!
//! The clock is wall time: seconds since the file was created. Timeouts
//! pass while a process is dead, as they would on a real network.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::encoding::Hash32;
use crate::lightning::{Invoice, Ledger};
use crate::rail::{IncomingHtlc, InvoiceRequest, PaymentStatus, Rail, RailError, RAIL_SIM};

use super::store::write_atomic;

#[derive(Serialize, Deserialize)]
struct SimFile {
    /// Unix time the simulated network started; its clock is wall time
    /// since then.
    epoch: u64,
    ledger: Ledger,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Create a simulated network file with principal nodes and balances.
pub fn create(path: &Path, nodes: &[(&str, Hash32, u64)]) -> Result<(), String> {
    let mut ledger = Ledger::new();
    for (name, principal, msat) in nodes {
        ledger.open_principal_node(name, *principal, *msat);
    }
    let f = SimFile {
        epoch: unix_now(),
        ledger,
    };
    write_atomic(path, &serde_json::to_vec(&f).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

/// Balance of a node in a simulated network file (for checks).
pub fn balance(path: &Path, node: &str) -> Result<u64, String> {
    let f: SimFile = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(f.ledger.balance(node))
}

/// One node's view of a simulated network file.
pub struct SimFileRail {
    path: PathBuf,
    node: String,
}

impl SimFileRail {
    pub fn new(path: &Path, node: &str) -> SimFileRail {
        SimFileRail {
            path: path.to_path_buf(),
            node: node.to_string(),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node
    }

    fn mine(&self, node: &str) -> Result<(), RailError> {
        if node == self.node {
            Ok(())
        } else {
            Err(RailError::NotThisNode)
        }
    }

    /// Run `f` on the ledger under the file lock, at the current wall time,
    /// and save the result.
    fn with<T>(&self, f: impl FnOnce(&mut Ledger) -> Result<T, RailError>) -> Result<T, RailError> {
        let node_err =
            |e: String| RailError::Node(format!("sim file {}: {e}", self.path.display()));
        let lock_path = self.path.with_extension("lock");
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| node_err(e.to_string()))?;
        lock.lock().map_err(|e| node_err(e.to_string()))?;
        let bytes = fs::read(&self.path).map_err(|e| node_err(e.to_string()))?;
        let mut sim: SimFile =
            serde_json::from_slice(&bytes).map_err(|e| node_err(e.to_string()))?;
        let target = unix_now().saturating_sub(sim.epoch);
        let now = Rail::now(&sim.ledger);
        if target > now {
            sim.ledger.advance(target - now);
        }
        let out = f(&mut sim.ledger);
        let json = serde_json::to_vec(&sim).map_err(|e| node_err(e.to_string()))?;
        write_atomic(&self.path, &json).map_err(|e| node_err(e.to_string()))?;
        out
    }
}

impl Rail for SimFileRail {
    fn rail_id(&self) -> &'static str {
        RAIL_SIM
    }

    fn now(&self) -> u64 {
        // Read without the lock: the epoch never changes.
        fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice::<SimFile>(&b).ok())
            .map(|s| unix_now().saturating_sub(s.epoch))
            .unwrap_or(0)
    }

    fn create_invoice(&mut self, req: &InvoiceRequest) -> Result<Invoice, RailError> {
        self.mine(&req.payee)?;
        self.with(|l| Rail::create_invoice(l, req))
    }

    fn pay_invoice(
        &mut self,
        payer: &str,
        invoice: &Invoice,
        max_htlc_secs: u64,
    ) -> Result<(), RailError> {
        self.mine(payer)?;
        self.with(|l| l.pay_invoice(payer, invoice, max_htlc_secs))
    }

    fn settle_invoice(&mut self, payee: &str, h: &Hash32, k: [u8; 32]) -> Result<(), RailError> {
        self.mine(payee)?;
        self.with(|l| l.settle_invoice(payee, h, k))
    }

    fn cancel_invoice(&mut self, payee: &str, h: &Hash32) -> Result<(), RailError> {
        self.mine(payee)?;
        self.with(|l| l.cancel_invoice(payee, h))
    }

    fn lookup_invoice(&mut self, h: &Hash32) -> Result<Option<IncomingHtlc>, RailError> {
        let node = self.node.clone();
        self.with(|l| {
            // Refund timed-out HTLCs first, as a node does when it looks.
            l.refund_expired();
            Ok(l.lookup_invoice(h)?.filter(|x| x.payee == node))
        })
    }

    fn find_invoice(&mut self, h: &Hash32) -> Result<Option<Invoice>, RailError> {
        let node = self.node.clone();
        self.with(|l| Ok(l.find_invoice(h)?.filter(|i| i.payee == node)))
    }

    fn lookup_payment(&mut self, payer: &str, h: &Hash32) -> Result<PaymentStatus, RailError> {
        self.mine(payer)?;
        self.with(|l| l.lookup_payment(payer, h))
    }
}
