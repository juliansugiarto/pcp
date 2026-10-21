//! Job classes (SPEC.md section 6).
//!
//! A job class is a deterministic predicate `check(input, result) -> bool`
//! plus the parameters that fix it. Its `spec_hash` plays the role that the
//! guest image id plays in a zkVM backend: it names *exactly* which predicate
//! the proof is about.
//!
//! Rules for a job class to be in scope for PCP/0:
//! - `check` is a pure function of `(params, input, result)`: no clock, no
//!   network, no randomness, no floating point, no environment.
//! - `check` terminates on every input within a bound the class documents.
//! - Inputs and results are bytes with a canonical encoding the class defines.

pub mod sudoku;
pub mod testsuite;

pub use sudoku::SudokuJob;
pub use testsuite::TestSuiteJob;

use alloc::vec::Vec;

use crate::encoding::{tagged_hash, Hash32};

/// A deterministic, checkable job class.
pub trait JobClass {
    /// Stable identifier, e.g. `"pcp/sudoku/v0"`.
    fn job_id(&self) -> &'static str;

    /// Canonical encoding of the class parameters (e.g. grid size).
    fn params(&self) -> Vec<u8>;

    /// The predicate. Must be deterministic and total (never panic).
    fn check(&self, input: &[u8], result: &[u8]) -> bool;

    /// `tagged_hash("spec", [job_id, params])`.
    fn spec_hash(&self) -> Hash32 {
        tagged_hash("spec", &[self.job_id().as_bytes(), &self.params()])
    }
}

/// `tagged_hash("input", [input])`: the buyer's commitment to the job input.
pub fn input_commitment(input: &[u8]) -> Hash32 {
    tagged_hash("input", &[input])
}
