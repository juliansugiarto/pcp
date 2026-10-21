//! Independent-review tests for the SHA-256 chip, written by a reviewer who did not write the chip.
//!
//! 1. `layout_selectors_rotations_and_ownership`: an `Assignment` recorder
//!    (no MockProver) that re-derives the layout, counts selector ROWS (not
//!    `.enable` calls), checks every rotation of every gate against the cells
//!    the same region assigned, enumerates every copy constraint, and prints
//!    the ownership table.
//! 2. `compensated_attacks_are_rejected`: MockProver with a malicious witness
//!    where everything downstream of the tampered cell is recomputed and the
//!    instance H is the forged digest, so only the one constraint under test
//!    can reject. Acceptance = unsound.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use halo2_proofs::{
    circuit::{SimpleFloorPlanner, Value},
    dev::{MockProver, VerifyFailure},
    pasta::Fp,
    plonk::{
        Any, Assigned, Assignment, Circuit, Column, ConstraintSystem, Error, Fixed, FloorPlanner,
        Instance, Selector,
    },
};

use crate::{
    circuit::{SaleCircuit, K},
    sha256::{self, poc_hook, poc_hook::Attack},
    suite, PublicInputs,
};

// ---------------------------------------------------------------------------
// Recorder

#[derive(Default)]
struct Region {
    name: String,
    cells: BTreeSet<(Column<Any>, usize)>,
    selectors: BTreeMap<usize, BTreeSet<usize>>, // selector index -> rows
}

#[derive(Default)]
struct Rec {
    regions: Vec<Region>,
    cur: Option<Region>,
    sel_index: HashMap<Selector, usize>,
    advice_count: HashMap<(Column<Any>, usize), usize>, // (col,row) -> times assigned
    copies: Vec<((Column<Any>, usize), (Column<Any>, usize))>,
}

impl Rec {
    fn sel(&mut self, s: &Selector) -> usize {
        // Selector(index, _) is pub(crate); recover the index from Debug.
        let d = format!("{:?}", s);
        let n: usize = d.trim_start_matches("Selector(").split(',').next().unwrap().parse().unwrap();
        self.sel_index.insert(*s, n);
        n
    }
}

impl Assignment<Fp> for Rec {
    fn enter_region<NR, N>(&mut self, name: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        assert!(self.cur.is_none());
        self.cur = Some(Region { name: name().into(), ..Default::default() });
    }
    fn exit_region(&mut self) {
        self.regions.push(self.cur.take().unwrap());
    }
    fn enable_selector<A, AR>(&mut self, _: A, s: &Selector, row: usize) -> Result<(), Error>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let i = self.sel(s);
        self.cur.as_mut().unwrap().selectors.entry(i).or_default().insert(row);
        Ok(())
    }
    fn query_instance(&self, _: Column<Instance>, _: usize) -> Result<Value<Fp>, Error> {
        Ok(Value::unknown())
    }
    fn assign_advice<V, VR, A, AR>(
        &mut self,
        _: A,
        column: Column<halo2_proofs::plonk::Advice>,
        row: usize,
        _: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<Fp>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        *self.advice_count.entry((column.into(), row)).or_default() += 1;
        if let Some(r) = self.cur.as_mut() {
            r.cells.insert((column.into(), row));
        }
        Ok(())
    }
    fn assign_fixed<V, VR, A, AR>(
        &mut self,
        _: A,
        column: Column<Fixed>,
        row: usize,
        _: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<Fp>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        if let Some(r) = self.cur.as_mut() {
            r.cells.insert((column.into(), row));
        }
        Ok(())
    }
    fn copy(&mut self, lc: Column<Any>, lr: usize, rc: Column<Any>, rr: usize) -> Result<(), Error> {
        self.copies.push(((lc, lr), (rc, rr)));
        Ok(())
    }
    fn fill_from_row(&mut self, _: Column<Fixed>, _: usize, _: Value<Assigned<Fp>>) -> Result<(), Error> {
        Ok(())
    }
    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }
    fn pop_namespace(&mut self, _: Option<String>) {}
}

fn sample() -> ([u8; 81], [u8; 81]) {
    let p = suite::parse_grid(include_str!("../examples/puzzle.txt")).unwrap();
    let s = suite::parse_grid(include_str!("../examples/solution.txt")).unwrap();
    (p, s)
}

#[test]
fn layout_selectors_rotations_and_ownership() {
    poc_hook::clear();
    let mut cs = ConstraintSystem::<Fp>::default();
    let cfg = SaleCircuit::configure(&mut cs);
    let sha = cfg.sha.clone();
    let mut rec = Rec::default();
    // The real floor planner uses cs.constants[0]; that is the SHA `constants`
    // column (first `enable_constant` call in `configure`).
    SimpleFloorPlanner::synthesize(&mut rec, &SaleCircuit::default(), cfg.clone(), vec![sha.constants])
        .unwrap();

    let sidx = |s: Selector| -> usize {
        let d = format!("{:?}", s);
        d.trim_start_matches("Selector(").split(',').next().unwrap().parse().unwrap()
    };
    let q_init = sidx(sha.q_init);
    let q_round = sidx(sha.q_round);
    let q_sw = sidx(sha.q_sched_word);
    let q_s = sidx(sha.q_sched);
    let q_dig = sidx(sha.q_digest);

    // ---- selector row sets, globally (distinct rows) ----
    let mut rows: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for r in &rec.regions {
        for (s, rs) in &r.selectors {
            rows.entry(*s).or_default().extend(rs.iter().copied());
        }
    }
    let count = |s: usize| rows.get(&s).map(|r| r.len()).unwrap_or(0);
    assert_eq!(count(q_init), 4, "q_init rows");
    assert_eq!(count(q_round), 64, "q_round rows");
    assert_eq!(count(q_sw), 16, "q_sched_word rows");
    assert_eq!(count(q_s), 48, "q_sched rows");
    assert_eq!(count(q_dig), 8, "q_digest rows");
    // contiguity and ordering
    let contiguous = |s: usize| {
        let r = &rows[&s];
        let (a, b) = (*r.iter().next().unwrap(), *r.iter().last().unwrap());
        assert_eq!(b - a + 1, r.len(), "selector {s} rows not contiguous");
        (a, b)
    };
    let (sw0, sw1) = contiguous(q_sw);
    let (s0, s1) = contiguous(q_s);
    let (i0, i1) = contiguous(q_init);
    let (r0, r1) = contiguous(q_round);
    let (d0, d1) = contiguous(q_dig);
    assert_eq!(s0, sw1 + 1, "q_sched follows q_sched_word");
    assert_eq!(r0, i1 + 1, "q_round follows q_init");
    println!("selector rows: sched_word {sw0}..={sw1} sched {s0}..={s1} init {i0}..={i1} round {r0}..={r1} digest {d0}..={d1}");
    // No selector row shared between two SHA selectors.
    for (a, b) in [(q_init, q_round), (q_sw, q_s), (q_init, q_sw), (q_round, q_s), (q_dig, q_round), (q_dig, q_s)] {
        assert!(rows[&a].is_disjoint(&rows[&b]));
    }

    // ---- per-gate rotation sets (transcribed from ShaChip::configure) ----
    let adv = |c: Column<halo2_proofs::plonk::Advice>| -> Column<Any> { c.into() };
    let fix = |c: Column<Fixed>| -> Column<Any> { c.into() };
    let mut gates: Vec<(&str, usize, Vec<(Column<Any>, i32)>)> = Vec::new();
    {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push((adv(sha.abit[i]), 0));
            v.push((adv(sha.ebit[i]), 0));
        }
        v.push((adv(sha.aval), 0));
        v.push((adv(sha.eval), 0));
        gates.push(("iv seed", q_init, v));
    }
    {
        let mut v = Vec::new();
        for i in 0..32 {
            for rot in [0, -1, -2, -3] {
                v.push((adv(sha.abit[i]), rot));
                v.push((adv(sha.ebit[i]), rot));
            }
        }
        for c in [sha.aval, sha.eval] {
            v.push((adv(c), 0));
            v.push((adv(c), -4));
        }
        for c in [sha.s0, sha.s1, sha.chc, sha.majc, sha.wc, sha.ecar, sha.acar] {
            v.push((adv(c), 0));
        }
        v.push((fix(sha.kcol), 0));
        gates.push(("round", q_round, v));
    }
    {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push((adv(sha.abit[i]), 0));
        }
        v.push((adv(sha.aval), 0));
        gates.push(("schedule given", q_sw, v));
    }
    {
        let mut v = Vec::new();
        for i in 0..32 {
            for rot in [0, -15, -2] {
                v.push((adv(sha.abit[i]), rot));
            }
        }
        for rot in [0, -16, -7] {
            v.push((adv(sha.aval), rot));
        }
        for c in [sha.s0, sha.s1, sha.acar] {
            v.push((adv(c), 0));
        }
        gates.push(("schedule word", q_s, v));
    }
    {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push((adv(sha.abit[i]), 0));
        }
        for c in [sha.aval, sha.wc, sha.acar] {
            v.push((adv(c), 0));
        }
        v.push((fix(sha.kcol), 0));
        gates.push(("digest", q_dig, v));
    }

    // ---- every rotation of every enabled gate lands on a cell assigned by
    //      the SAME region (items 1 and 3) ----
    let mut checked = 0usize;
    for r in &rec.regions {
        for (gname, s, cells) in &gates {
            if let Some(srows) = r.selectors.get(s) {
                let first = *r.cells.iter().map(|(_, row)| row).min().unwrap();
                for &row in srows {
                    for (col, rot) in cells {
                        let target = row as i64 + *rot as i64;
                        assert!(target >= first as i64, "gate {gname} at row {row} reaches above region '{}' (first row {first})", r.name);
                        assert!(r.cells.contains(&(*col, target as usize)), "gate {gname} at row {row}: {:?}@{rot} (row {target}) not assigned in region '{}'", col, r.name);
                        checked += 1;
                    }
                }
            }
        }
    }
    println!("rotation checks: {checked} (gate,row,cell) triples all assigned in-region");

    // ---- no advice cell assigned twice (item 12) ----
    let dups: Vec<_> = rec.advice_count.iter().filter(|(_, n)| **n > 1).collect();
    assert!(dups.is_empty(), "cells assigned more than once: {dups:?}");

    // ---- ownership table: every assigned SHA advice cell has a gate at
    //      rotation 0 that constrains it (bool/pack/equation/range) or is a
    //      copy endpoint (wc). ----
    let sha_cols: Vec<(String, Column<Any>)> = {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push((format!("abit[{i}]"), adv(sha.abit[i])));
        }
        for i in 0..32 {
            v.push((format!("ebit[{i}]"), adv(sha.ebit[i])));
        }
        for (n, c) in [("aval", sha.aval), ("eval", sha.eval), ("s0", sha.s0), ("s1", sha.s1), ("chc", sha.chc), ("majc", sha.majc), ("wc", sha.wc), ("acar", sha.acar), ("ecar", sha.ecar)] {
            v.push((n.to_string(), adv(c)));
        }
        v
    };
    // owner selectors per column
    let owners: HashMap<Column<Any>, Vec<usize>> = sha_cols
        .iter()
        .map(|(n, c)| {
            let v = if n.starts_with("abit") {
                vec![q_init, q_round, q_sw, q_s, q_dig]
            } else if n.starts_with("ebit") || n == "eval" || n == "ecar" || n == "chc" || n == "majc" {
                if n.starts_with("ebit") || n == "eval" { vec![q_init, q_round] } else { vec![q_round] }
            } else if n == "aval" {
                vec![q_init, q_round, q_sw, q_s, q_dig]
            } else if n == "s0" || n == "s1" {
                vec![q_round, q_s]
            } else if n == "acar" {
                vec![q_round, q_s, q_dig]
            } else if n == "wc" {
                vec![q_round, q_dig]
            } else {
                unreachable!()
            };
            (*c, v)
        })
        .collect();
    let copy_endpoints: BTreeSet<(Column<Any>, usize)> =
        rec.copies.iter().flat_map(|(a, b)| [*a, *b]).collect();
    let mut table: BTreeMap<(String, String), BTreeMap<String, usize>> = BTreeMap::new();
    let selname = |s: usize| -> &'static str {
        if s == q_init { "q_init" } else if s == q_round { "q_round" } else if s == q_sw { "q_sched_word" } else if s == q_s { "q_sched" } else if s == q_dig { "q_digest" } else { "OTHER" }
    };
    for r in &rec.regions {
        for (n, c) in &sha_cols {
            for (col, row) in r.cells.iter().filter(|(col, _)| col == c) {
                let own: Vec<usize> = owners[c].iter().copied().filter(|s| r.selectors.get(s).map(|rs| rs.contains(row)).unwrap_or(false)).collect();
                assert!(own.len() == 1, "cell {n}@{row} in '{}' has {} owning gates: {:?}", r.name, own.len(), own);
                let is_copy = copy_endpoints.contains(&(*col, *row));
                if n == "wc" {
                    assert!(is_copy, "wc@{row} must be a copy endpoint");
                }
                let kind = format!("{}{}", selname(own[0]), if is_copy { "+copy" } else { "" });
                let key = (r.name.clone(), if n.starts_with("abit") { "abit[*]".into() } else if n.starts_with("ebit") { "ebit[*]".into() } else { n.clone() });
                *table.entry(key).or_default().entry(kind).or_default() += 1;
            }
        }
    }
    println!("--- ownership table (region, column) -> owner: cell count ---");
    for ((reg, col), kinds) in &table {
        println!("{reg:22} {col:8} {:?}", kinds);
    }

    // ---- copies: classify every copy constraint touching a SHA column ----
    let name_of = |c: &Column<Any>| -> String {
        for (n, cc) in &sha_cols {
            if cc == c {
                return n.clone();
            }
        }
        if *c == fix(sha.constants) {
            return "constants(fixed)".into();
        }
        if c.column_type() == &Any::Instance {
            return "instance".into();
        }
        if *c == adv(cfg.a[2]) {
            return "work[2]=k cell".into();
        }
        format!("{:?}", c)
    };
    let mut classes: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (a, b) in &rec.copies {
        let touches = sha_cols.iter().any(|(_, c)| c == &a.0 || c == &b.0);
        if touches {
            *classes.entry((name_of(&a.0), name_of(&b.0))).or_default() += 1;
        }
    }
    println!("--- copy constraints touching SHA columns ---");
    for (k, n) in &classes {
        println!("{:?}: {n}", k);
    }
    let get = |x: &str, y: &str| classes.get(&(x.to_string(), y.to_string())).copied().unwrap_or(0) + classes.get(&(y.to_string(), x.to_string())).copied().unwrap_or(0);
    assert_eq!(get("work[2]=k cell", "aval"), 8, "key -> W_0..7");
    assert_eq!(get("constants(fixed)", "aval"), 12, "padding (8) + A seed (4)");
    assert_eq!(get("constants(fixed)", "eval"), 4, "E seed");
    assert_eq!(get("aval", "wc"), 68, "W_t -> round (64) + A[63..60] -> digest (4)");
    assert_eq!(get("eval", "wc"), 4, "E[63..60] -> digest");
    assert_eq!(get("aval", "instance"), 8, "digest -> H");
    let total: usize = classes.values().sum();
    assert_eq!(total, 8 + 12 + 4 + 68 + 4 + 8, "no other copy touches a SHA column");

    // Region row ranges for the report.
    for r in &rec.regions {
        if r.name.starts_with("sha") || r.name == "key words" {
            let lo = r.cells.iter().map(|(_, row)| *row).min().unwrap();
            let hi = r.cells.iter().map(|(_, row)| *row).max().unwrap();
            println!("region '{}': rows {lo}..={hi}", r.name);
        }
    }
}

// ---------------------------------------------------------------------------
// Compensated attacks

fn key_words(key: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap()))
}

fn classify(fails: &[VerifyFailure]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for f in fails {
        let k = match f {
            VerifyFailure::Permutation { column, .. } => format!("Permutation({column})"),
            VerifyFailure::ConstraintNotSatisfied { constraint, .. } => format!("{constraint}"),
            VerifyFailure::CellNotAssigned { .. } => "CellNotAssigned".into(),
            VerifyFailure::InstanceCellNotAssigned { .. } => "InstanceCellNotAssigned".into(),
            VerifyFailure::ConstraintPoisoned { .. } => "ConstraintPoisoned".into(),
            VerifyFailure::Lookup { .. } => "Lookup".into(),
        };
        *m.entry(k).or_default() += 1;
    }
    m
}

#[test]
fn compensated_attacks_are_rejected() {
    use sha2::{Digest, Sha256};
    let (p, s) = sample();
    let key = [0x11u8; 32];
    let kw = key_words(&key);
    let honest: [u8; 32] = Sha256::digest(key).into();

    // (attack, name, the only failure kinds allowed, as substrings of the Display form)
    let cases: Vec<(Attack, &str, Vec<&str>)> = vec![
        (Attack::KeyWord { i: 0, delta: 1 }, "SELLER: SHA on k' != Poseidon k (W_0 copy)", vec!["Permutation"]),
        (Attack::KeyWord { i: 7, delta: 0x8000_0000 }, "SELLER: W_7 copy", vec!["Permutation"]),
        (Attack::RoundW { t: 20, delta: 1 }, "C-3: round 20 consumes W_20+1", vec!["Permutation"]),
        (Attack::RoundW { t: 3, delta: 0xffff }, "C-3: round 3 consumes key word W_3+d", vec!["Permutation"]),
        (Attack::DigestOperand { m: 0, delta: 1 }, "C-4: digest operand A[63]+1", vec!["Permutation"]),
        (Attack::DigestOperand { m: 7, delta: 5 }, "C-4: digest operand E[60]+5", vec!["Permutation"]),
        (Attack::RoundEFieldCarry { t: 63, delta: 1 }, "C-2: E[63] shifted, carry solved in field", vec!["Constraint 72 in gate 1"]),
        (Attack::RoundAFieldCarry { t: 63, delta: 1 }, "C-2: A[63] shifted, carry solved in field", vec!["Constraint 73 in gate 1"]),
        (Attack::RoundAFieldCarry { t: 0, delta: 0x1234 }, "C-2: A[0] shifted, carry in field", vec!["Constraint 73 in gate 1"]),
        (Attack::SchedFieldCarry { i: 40, delta: 1 }, "C-2: W_40 shifted, schedule carry in field", vec!["Constraint 36 in gate 3"]),
        (Attack::DigestFieldCarry { m: 3, delta: 1 }, "C-2: H[3] shifted, digest carry in field", vec!["Constraint 34 in gate 4"]),
        (Attack::S0Shift { t: 10 }, "s0 += 2^32 with acar += 1 (A equation holds)", vec!["Constraint 66 in gate 1", "Constraint 73 in gate 1"]),
        (Attack::SeedA { r: 0, delta: 1 }, "free-IV: seed d=IV3+1 overwritten after constant copy", vec!["Permutation"]),
        (Attack::SeedA { r: 3, delta: 0x8000_0000 }, "free-IV: seed a=IV0+2^31", vec!["Permutation"]),
    ];

    poc_hook::clear();
    let base = PublicInputs {
        givens: p,
        ciphertext: suite::encrypt(&s, &key),
        payment_hash: honest,
        binding: [0x22; 32],
    };
    assert!(MockProver::run(K, &SaleCircuit::new(s, key), vec![base.instance()]).unwrap().verify().is_ok());

    let mut report = String::new();
    for (atk, name, expect) in cases {
        // forged digest = what the attacked trace produces
        let tr = sha256::compute_trace_attacked(kw, atk);
        let mut forged = [0u8; 32];
        for m in 0..8 {
            forged[4 * m..4 * m + 4].copy_from_slice(&tr.digest[m].to_be_bytes());
        }
        if matches!(atk, Attack::S0Shift { .. }) {
            // ownership probe, not a forgery: the digest is unchanged
            assert_eq!(forged, honest);
        } else {
            assert_ne!(forged, honest, "{name}: attack must change the digest to be meaningful");
        }
        let public = PublicInputs { payment_hash: forged, ..base.clone() };
        poc_hook::set_attack(atk);
        let res = MockProver::run(K, &SaleCircuit::new(s, key), vec![public.instance()]).unwrap().verify();
        poc_hook::clear();
        match res {
            Ok(()) => panic!("CRITICAL: attack '{name}' ({atk:?}) ACCEPTED with H != SHA256(k)"),
            Err(fails) => {
                let c = classify(&fails);
                report.push_str(&format!("{name}: rejected by {:?}\n", c));
                for k in c.keys() {
                    assert!(expect.iter().any(|e| k.contains(e)), "{name}: unexpected failure kind {k} (expected only {expect:?}); all: {c:?}");
                }
            }
        }
    }
    println!("--- compensated attacks ---\n{report}");
}
