//! # PCP/0: proof-contingent payment (v0 reference implementation)
//!
//! A payment settles **if and only if** a verifier-accepted proof of
//! specified work is delivered, atomically, between parties who need not
//! know or trust each other, with no escrow, no platform and no court.
//!
//! Mechanism (ZKCP-style): the seller computes the result `R`, picks a random
//! key `k`, publishes `C = Enc_k(R)`, `H = SHA256(k)` and a proof that
//! `C` encrypts a result passing the job check under the key whose hash is
//! `H`. The buyer verifies the proof **before** paying, then pays a
//! Lightning invoice with payment hash `H`. The seller can only claim the
//! payment by revealing `k`, which lets the buyer decrypt `C`.
//!
//! Every buyer and seller is an agent acting for a principal (a human, or
//! an organisation a human controls) under a signed `mandate::Mandate`:
//! scope, cumulative cap, per-deal maximum, expiry. Payouts go to the
//! principal's node; signed receipts and refusals go to the principal's
//! log; only reviewed job classes (`registry::JobRegistry`) are traded by
//! default. A mandate proves authorisation by a key, not humanity or legal
//! identity, and no issuer is privileged.
//!
//! See `SPEC.md` for the normative description.
//!
//! ## Features
//!
//! - `std` (default): the whole protocol.
//! - without `std`: `no_std + alloc`, only [`encoding`], [`crypto`], [`job`]
//!   and [`statement`]. This is what a zkVM guest links (`../pcp-risc0/`).
//! - `lnd`: the LND REST settlement rail (`rail::lnd`).
//!
//! ## v0 limits (read these)
//!
//! - The only proof backend in this crate, `proof::InsecureDevTransparentBackend`,
//!   is **INSECURE**: its proof contains the witness under a seal whose key is
//!   in the source. It provides no zero knowledge. The RISC Zero backend lives
//!   in `../pcp-risc0/` and is not built here.
//! - Lightning is simulated by `lightning::Ledger` unless the `lnd` feature
//!   is used against real nodes.

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

pub mod crypto;
pub mod encoding;
pub mod job;
pub mod statement;

#[cfg(feature = "std")]
pub mod lightning;
#[cfg(feature = "std")]
pub mod mandate;
#[cfg(feature = "std")]
pub mod node;
#[cfg(feature = "std")]
pub mod proof;
#[cfg(feature = "std")]
pub mod protocol;
#[cfg(feature = "std")]
pub mod rail;
#[cfg(feature = "std")]
pub mod registry;
#[cfg(feature = "std")]
pub mod sale;

#[cfg(all(test, feature = "std"))]
mod tests;
