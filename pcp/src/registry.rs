//! The local registry of reviewed job classes (SPEC.md section 6.4).
//!
//! The reference client buys and sells only job classes
//! whose `spec_hash` is in its registry. An entry means the class was
//! **reviewed and tested** against the rules of SPEC section 6 and its
//! conformance vectors. It does not mean the class is safe or harmless; it
//! is a record of what was looked at.
//!
//! The registry is a local value, not a service. Anyone can fork it; nobody
//! is asked for permission to add to it. Unregistered classes are refused
//! by default; `allow_unregistered_job_classes` exists for development only.

use std::collections::BTreeMap;

use crate::encoding::Hash32;
use crate::job::{JobClass, SudokuJob, TestSuiteJob};

/// One reviewed job class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryEntry {
    pub spec_hash: Hash32,
    /// The class's `job_id`, e.g. `pcp/sudoku/v0`.
    pub name: String,
    /// Version of the class definition this entry was reviewed at.
    pub version: String,
    /// What was reviewed and tested.
    pub review_note: String,
}

/// `spec_hash -> entry`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobRegistry {
    entries: BTreeMap<Hash32, RegistryEntry>,
}

impl JobRegistry {
    /// No entries.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The classes shipped with v0. None of them takes as input or returns
    /// a third party's secret or credential, an exploit, personal data, or
    /// anything acting in the physical world (SPEC 6.3).
    pub fn reference() -> Self {
        let mut r = Self::empty();
        for (job, note) in [
            (
                &SudokuJob::four() as &dyn JobClass,
                "4x4 sudoku validity. Pure, total, n*n bytes. Conformance vector A.4.",
            ),
            (
                &SudokuJob::nine(),
                "9x9 sudoku validity. Pure, total, n*n bytes. Conformance vector A.5.",
            ),
            (
                &TestSuiteJob,
                "Toy expression language over one i64 against the buyer's own (x, expected) \
                 vectors. Pure, bounded size and depth. Conformance vectors A.6, A.7.",
            ),
        ] {
            r.insert(RegistryEntry {
                spec_hash: job.spec_hash(),
                name: job.job_id().to_string(),
                version: "v0".to_string(),
                review_note: note.to_string(),
            });
        }
        r
    }

    pub fn insert(&mut self, entry: RegistryEntry) {
        self.entries.insert(entry.spec_hash, entry);
    }

    pub fn get(&self, spec_hash: &Hash32) -> Option<&RegistryEntry> {
        self.entries.get(spec_hash)
    }

    pub fn contains(&self, spec_hash: &Hash32) -> bool {
        self.entries.contains_key(spec_hash)
    }

    pub fn entries(&self) -> impl Iterator<Item = &RegistryEntry> {
        self.entries.values()
    }
}
