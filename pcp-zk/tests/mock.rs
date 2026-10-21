//! Constraint-level tests with halo2's MockProver (fast; no real proof).

use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};
use pcp_zk::{
    circuit::{SaleCircuit, K, ROW_BINDING, ROW_CIPHERTEXT, ROW_GIVENS, ROW_PAYMENT_HASH},
    suite, PublicInputs,
};

pub fn sample() -> ([u8; 81], [u8; 81]) {
    let p = suite::parse_grid(include_str!("../examples/puzzle.txt")).unwrap();
    let s = suite::parse_grid(include_str!("../examples/solution.txt")).unwrap();
    assert!(suite::sudoku_valid(&p, &s));
    (p, s)
}

const KEY: [u8; 32] = [0x11; 32];
const BINDING: [u8; 32] = [0x22; 32];

fn public_for(givens: &[u8; 81], solution: &[u8; 81], key: &[u8; 32]) -> PublicInputs {
    PublicInputs {
        givens: *givens,
        ciphertext: suite::encrypt(solution, key),
        payment_hash: suite::payment_hash(key),
        binding: BINDING,
    }
}

fn run(circuit: SaleCircuit, instance: Vec<Fp>) -> bool {
    MockProver::run(K, &circuit, vec![instance]).unwrap().verify().is_ok()
}

#[test]
fn honest_sale_satisfies_every_constraint() {
    let (p, s) = sample();
    let public = public_for(&p, &s, &KEY);
    let prover = MockProver::run(K, &SaleCircuit::new(s, KEY), vec![public.instance()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn in_circuit_sha256_matches_standard_sha256_for_random_keys() {
    let (p, s) = sample();
    for seed in 0u8..3 {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(seed * 101));
        let public = public_for(&p, &s, &key);
        assert!(run(SaleCircuit::new(s, key), public.instance()), "seed {seed}");
        // Flip one bit of H: must fail.
        let mut bad = public.clone();
        bad.payment_hash[31 - seed as usize] ^= 1;
        assert!(!run(SaleCircuit::new(s, key), bad.instance()));
    }
}

#[test]
fn wrong_key_for_h_fails() {
    let (p, s) = sample();
    let public = public_for(&p, &s, &KEY);
    let mut other = KEY;
    other[0] ^= 0x80;
    assert!(!run(SaleCircuit::new(s, other), public.instance()));
}

#[test]
fn ciphertext_must_be_encryption_of_witness() {
    let (p, s) = sample();
    let mut public = public_for(&p, &s, &KEY);
    public.ciphertext[40] += Fp::one();
    assert!(!run(SaleCircuit::new(s, KEY), public.instance()));
}

#[test]
fn ciphertext_under_another_key_fails() {
    // C made with k' but H = SHA256(k): the buyer would get k and not decrypt.
    let (p, s) = sample();
    let mut public = public_for(&p, &s, &KEY);
    public.ciphertext = suite::encrypt(&s, &[0x33; 32]);
    assert!(!run(SaleCircuit::new(s, KEY), public.instance()));
}

#[test]
fn wrong_solutions_cannot_satisfy_the_circuit() {
    let (p, s) = sample();
    // (a) swap two cells in a row (breaks columns/boxes and a given or two)
    let mut a = s;
    a.swap(2, 3);
    // (b) a cell set to 0 and (c) to 10, encrypted consistently
    let mut b = s;
    b[4] = 0;
    let mut c = s;
    c[4] = 10;
    // (d) a grid where every row/col/box has sum 45 and product 9! but is not
    // a permutation is impossible to express with valid givens; use a grid of
    // rows {1,2,4,4,4,5,7,9,9} shifted, with no givens.
    let row = [1u8, 2, 4, 4, 4, 5, 7, 9, 9];
    let d: [u8; 81] = core::array::from_fn(|i| row[(i % 9 + i / 9) % 9]);
    // (e) a valid sudoku that ignores a given
    let mut e_givens = p;
    e_givens[2] = 9; // the solution has 4 there
    for (givens, sol) in [(p, a), (p, b), (p, c), ([0u8; 81], d), (e_givens, s)] {
        let public = public_for(&givens, &sol, &KEY);
        assert!(!run(SaleCircuit::new(sol, KEY), public.instance()));
    }
}

#[test]
fn every_public_input_is_constrained() {
    let (p, s) = sample();
    let public = public_for(&p, &s, &KEY);
    let base = public.instance();
    for row in [ROW_GIVENS + 2, ROW_GIVENS + 0, ROW_CIPHERTEXT + 80, ROW_PAYMENT_HASH, ROW_PAYMENT_HASH + 7, ROW_BINDING, ROW_BINDING + 7] {
        let mut inst = base.clone();
        inst[row] += Fp::one();
        // binding rows are copied into advice cells assigned from the instance,
        // so the MockProver sees the change consistently; their binding
        // effect is tested on real proofs in tests/prove.rs.
        let ok = run(SaleCircuit::new(s, KEY), inst);
        if row >= ROW_BINDING {
            assert!(ok);
        } else {
            assert!(!ok, "row {row}");
        }
    }
    let _ = Value::<()>::unknown();
}
