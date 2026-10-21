//! Adversarial and honest tests for the in-house SHA-256 chip (`src/sha256.rs`).
//!
//! The adversarial tests mutate exactly one honest witness value through the
//! `sha256::poc_hook` test hook and assert that halo2's `MockProver` then
//! REJECTS the circuit. Together they cover every constraint class of the chip:
//! booleanity, bit/packed consistency, the round constants, the IV, every
//! carry, the message-schedule recurrence, the inter-round state, the final
//! words, the padding, and the binding of the SHA key words to the Poseidon
//! key cells.
//!
//! The honest tests check that the in-circuit digest equals `sha2::Sha256` for
//! many random keys and for edge keys.

use halo2_proofs::dev::MockProver;

use crate::{
    circuit::{SaleCircuit, K},
    sha256::poc_hook::{self, Tamper},
    suite, PublicInputs,
};

const BINDING: [u8; 32] = [0x22; 32];

fn sample() -> ([u8; 81], [u8; 81]) {
    let p = suite::parse_grid(include_str!("../examples/puzzle.txt")).unwrap();
    let s = suite::parse_grid(include_str!("../examples/solution.txt")).unwrap();
    assert!(suite::sudoku_valid(&p, &s));
    (p, s)
}

fn public_for(givens: &[u8; 81], solution: &[u8; 81], key: &[u8; 32]) -> PublicInputs {
    PublicInputs {
        givens: *givens,
        ciphertext: suite::encrypt(solution, key),
        payment_hash: suite::payment_hash(key),
        binding: BINDING,
    }
}

fn accepts(circuit: &SaleCircuit, public: &PublicInputs) -> bool {
    MockProver::run(K, circuit, vec![public.instance()])
        .unwrap()
        .verify()
        .is_ok()
}

/// Each `(tag, index, tamper, name)` must make an honest witness fail.
fn tamper_cases() -> Vec<(u32, u32, Tamper, &'static str)> {
    vec![
        // non-boolean bit: set bit 5 of A[10] to the field value 2.
        (poc_hook::TAG_ROUND_A, 10, Tamper::Bit(5, 2), "non-boolean bit"),
        // packed value disagrees with the bits.
        (poc_hook::TAG_ROUND_E, 20, Tamper::PackDelta(1), "packed != bits"),
        // wrong IV word: the seed bits no longer match the pinned IV constant.
        // (K_t and the IV constant are FIXED columns, not prover advice; a
        // tamper on them is vacuous, so they are checked by known-answer tests
        // below. These seed tampers hit the advice BITS that must decompose the
        // pinned IV constant.)
        (poc_hook::TAG_SEED_A, 0, Tamper::WordDelta(1), "wrong IV word (a)"),
        (poc_hook::TAG_SEED_E, 3, Tamper::WordDelta(0x8000_0000), "wrong IV word (h)"),
        // tampered carries.
        (poc_hook::TAG_ROUND_ACAR, 30, Tamper::CarryDelta(1), "tampered A carry"),
        (poc_hook::TAG_ROUND_ECAR, 15, Tamper::CarryDelta(1), "tampered E carry"),
        (poc_hook::TAG_SCHED_CARRY, 25, Tamper::CarryDelta(1), "tampered schedule carry"),
        (poc_hook::TAG_DIGEST_CARRY, 2, Tamper::CarryDelta(1), "tampered digest carry"),
        // tampered message word W_t for t >= 16 (schedule recurrence breaks).
        (poc_hook::TAG_SCHED_WORD, 16, Tamper::WordDelta(1), "tampered W_16"),
        (poc_hook::TAG_SCHED_WORD, 47, Tamper::WordDelta(0x1234), "tampered W_47"),
        // tampered inter-round state.
        (poc_hook::TAG_ROUND_E, 35, Tamper::WordDelta(1), "tampered E[35]"),
        (poc_hook::TAG_ROUND_A, 7, Tamper::WordDelta(0xdead), "tampered A[7]"),
        // tampered final word (round 63) and tampered digest output word.
        (poc_hook::TAG_ROUND_A, 63, Tamper::WordDelta(1), "tampered final A[63]"),
        (poc_hook::TAG_ROUND_E, 63, Tamper::WordDelta(1), "tampered final E[63]"),
        (poc_hook::TAG_DIGEST, 1, Tamper::WordDelta(1), "tampered digest word"),
        // tampered padding word (bits disagree with the pinned constant).
        (poc_hook::TAG_SCHED_WORD, 8, Tamper::WordDelta(1), "tampered padding 0x80000000"),
        (poc_hook::TAG_SCHED_WORD, 15, Tamper::WordDelta(1), "tampered padding length"),
        // key word in SHA != key word in Poseidon packing: the SHA message
        // bits are forced equal to the key cell that Poseidon packs, so shifting
        // the SHA key bits breaks the packing of W_i against that shared cell.
        (poc_hook::TAG_SCHED_WORD, 0, Tamper::WordDelta(1), "SHA key != Poseidon key (word 0)"),
        (poc_hook::TAG_SCHED_WORD, 7, Tamper::WordDelta(0x55), "SHA key != Poseidon key (word 7)"),
    ]
}

#[test]
fn every_sha_constraint_rejects_a_tampered_witness() {
    let (p, s) = sample();
    let key = [0x11u8; 32];
    let public = public_for(&p, &s, &key);

    // Baseline: with no tamper, the honest witness is accepted.
    poc_hook::clear();
    assert!(accepts(&SaleCircuit::new(s, key), &public), "honest baseline must pass");

    for (tag, index, tam, name) in tamper_cases() {
        poc_hook::set(tag, index, tam);
        let ok = accepts(&SaleCircuit::new(s, key), &public);
        poc_hook::clear();
        assert!(!ok, "tamper '{name}' was accepted but must be rejected");
    }
}

#[test]
fn round_constants_and_iv_are_the_fips_known_answer() {
    use crate::sha256::{IV, ROUND_CONSTANTS};
    // FIPS 180-4 section 4.2.2 (first and last two words) and 5.3.3 IV.
    assert_eq!(ROUND_CONSTANTS[0], 0x428a2f98);
    assert_eq!(ROUND_CONSTANTS[1], 0x71374491);
    assert_eq!(ROUND_CONSTANTS[62], 0xbef9a3f7);
    assert_eq!(ROUND_CONSTANTS[63], 0xc67178f2);
    // SHA-256 of the empty string begins with the standard IV feed-forward, so
    // simplest KAT is the full table checksum against the canonical values.
    const FIPS_K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    const FIPS_IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    assert_eq!(ROUND_CONSTANTS, FIPS_K, "round constants must be the FIPS table");
    assert_eq!(IV, FIPS_IV, "IV must be the standard SHA-256 IV");
}

#[test]
fn selector_enable_counts_match_the_layout() {
    // NOTE (review L-1): this counts `.enable(..)` CALLS, not distinct rows, so
    // two enables on one row would pass here. The row-exact check (distinct,
    // contiguous rows per selector) is `review_tests::layout_selectors_rotations_and_ownership`.
    // A missing or extra `.enable(..)` in the chip changes these counts, so the
    // exact layout is pinned: 4 IV-seed rows, 64 rounds, 16 given schedule
    // words (8 key + 8 padding), 48 computed schedule words, 8 digest rows.
    let (p, s) = sample();
    let key = [0x11u8; 32];
    let public = public_for(&p, &s, &key);
    poc_hook::clear();
    poc_hook::reset_counts();
    let _ = accepts(&SaleCircuit::new(s, key), &public);
    let c = poc_hook::counts();
    // The floor planner may synthesize more than once; every selector is
    // counted the same number of passes, so normalise by the IV-seed count
    // (expected 4 per pass) and check the exact per-pass layout.
    assert!(c[poc_hook::SEL_INIT] > 0 && c[poc_hook::SEL_INIT] % 4 == 0, "unexpected seed count {}", c[poc_hook::SEL_INIT]);
    let u = c[poc_hook::SEL_INIT] / 4;
    assert_eq!(c[poc_hook::SEL_INIT], 4 * u, "IV seed rows");
    assert_eq!(c[poc_hook::SEL_ROUND], 64 * u, "compression rounds");
    assert_eq!(c[poc_hook::SEL_SCHED_WORD], 16 * u, "given schedule words");
    assert_eq!(c[poc_hook::SEL_SCHED], 48 * u, "computed schedule words");
    assert_eq!(c[poc_hook::SEL_DIGEST], 8 * u, "digest rows");
}

#[test]
fn instance_endianness_known_answer_and_negative() {
    // H is written big-endian per 32-bit word. Honest passes; reversing the
    // bytes within one output word must fail.
    let (p, s) = sample();
    let key = [0x11u8; 32];
    poc_hook::clear();
    let public = public_for(&p, &s, &key);
    assert!(accepts(&SaleCircuit::new(s, key), &public));
    // Reverse the 4 bytes of H word 0 (a non-palindromic word for this key).
    let mut bad = public.clone();
    let w: [u8; 4] = bad.payment_hash[0..4].try_into().unwrap();
    let rev = [w[3], w[2], w[1], w[0]];
    assert_ne!(w, rev, "word 0 must be non-palindromic for a meaningful test");
    bad.payment_hash[0..4].copy_from_slice(&rev);
    assert!(!accepts(&SaleCircuit::new(s, key), &bad), "byte-reversed H word must fail");
}

#[test]
fn in_circuit_sha256_equals_sha2_for_many_keys() {
    let (p, s) = sample();
    poc_hook::clear();

    let mut keys: Vec<[u8; 32]> = Vec::new();
    // 20 pseudo-random keys.
    for seed in 0u64..20 {
        let mut k = [0u8; 32];
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
        for b in k.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        keys.push(k);
    }
    // Edge keys.
    keys.push([0x00; 32]);
    keys.push([0xff; 32]);
    keys.push(core::array::from_fn(|i| if i % 2 == 0 { 0xaa } else { 0x55 }));
    keys.push(core::array::from_fn(|i| if i % 2 == 0 { 0x55 } else { 0xaa }));

    for key in &keys {
        let public = public_for(&p, &s, key);
        // The circuit constrains its digest to the instance H = sha2(key), so
        // acceptance proves the in-circuit SHA-256 equals sha2::Sha256.
        assert!(accepts(&SaleCircuit::new(s, *key), &public), "honest key {:02x?}", &key[..4]);
        // And a single flipped bit of H is rejected.
        let mut bad = public.clone();
        bad.payment_hash[0] ^= 1;
        assert!(!accepts(&SaleCircuit::new(s, *key), &bad), "flipped H accepted for {:02x?}", &key[..4]);
    }
}
