//! An in-house, auditable SHA-256 chip for exactly one compression of a
//! 64-byte (512-bit) block whose first 32 bytes are the private key words and
//! whose remaining 32 bytes are the fixed padding of a 256-bit message
//! (`0x80000000`, six zero words, then the bit length `256`).
//!
//! This replaces the vendored halo2_gadgets Table16 gadget, which an
//! independent review (`review/2026-10-21-soundness-review.md`) and a
//! reproduced proof-of-concept found to be unsound. The chip here is new and
//! UNAUDITED; see README.md.
//!
//! # Design
//!
//! Every 32-bit word is represented as 32 boolean advice cells in one row
//! (one column per bit, little-endian: bit `i` has weight `2^i`) together with
//! a packed value cell. A "word" gate enforces `b*(1-b)=0` for each bit and
//! `packed = sum_i b_i 2^i`.
//!
//! The compression uses the standard recurrence in which only two new words
//! are produced per round. Writing `A[t]` and `E[t]` for the working variables
//! after round `t` (with `A[-1..-4]` and `E[-1..-4]` seeded from the IV so
//! that `a=A[-1], b=A[-2], c=A[-3], d=A[-4]` and `e=E[-1], f=E[-2], g=E[-3],
//! h=E[-4]`):
//!
//! ```text
//! T1    = h + Sigma1(e) + Ch(e,f,g) + K_t + W_t   = E[t-4] + Sigma1(E[t-1]) + Ch(E[t-1],E[t-2],E[t-3]) + K_t + W_t
//! T2    = Sigma0(a) + Maj(a,b,c)                   = Sigma0(A[t-1]) + Maj(A[t-1],A[t-2],A[t-3])
//! E[t]  = d + T1 = A[t-4] + T1
//! A[t]  = T1 + T2
//! ```
//!
//! Each `A[t]` and `E[t]` occupies one row, so the history `A[t-1..t-4]` and
//! `E[t-1..t-4]` is reachable by the *fixed* rotations `-1,-2,-3,-4`. No value
//! is copied between rounds, and no value is a fresh unconstrained witness: the
//! only cross-region copies are the key words into `W_0..W_7`, the message
//! words into the rounds, and the digest words out to the instance.
//!
//! Rotations and shifts are re-indexing of the bit cells (`rotr(x,n)` bit `j`
//! is `x[(j+n) mod 32]`; `shr(x,n)` bit `j` is `x[j+n]` or `0`). `Sigma`,
//! `sigma`, `Ch` and `Maj` are expressed directly as the packed sum of their
//! per-bit boolean polynomials, so no extra bit columns or range checks are
//! needed for them (each per-bit value is provably boolean):
//!
//! ```text
//! XOR(x,y)       = x + y - 2xy
//! XOR3(x,y,z)    = x + y + z - 2(xy+xz+yz) + 4xyz
//! Ch(e,f,g)_i    = e_i f_i + (1-e_i) g_i
//! Maj(a,b,c)_i   = a_i b_i + a_i c_i + b_i c_i - 2 a_i b_i c_i
//! ```
//!
//! Addition mod `2^32` is `sum(packed inputs) = packed_out + carry * 2^32`
//! with `packed_out` fully bit-decomposed (so `packed_out in [0, 2^32)`) and
//! the carry constrained to its exact range by a product polynomial. Because
//! every addend is `< 2^32` and the number of addends is small, the honest sum
//! is `< 2^36 < p`, so the equation holds over the integers and the
//! `(packed_out, carry)` split is unique. Carry bounds: message schedule
//! `0..=3` (4 addends), `E[t]` `0..=5` (6 addends), `A[t]` `0..=6` (7 addends),
//! feed-forward `0..=1` (2 addends).
//!
//! The round constants `K_t` and the digest `IV` addends live in a fixed
//! column (part of the verifying key, not prover advice). The IV seed words
//! and the padding words are pinned with `assign_advice_from_constant`.

use ff::Field as _; // Fp::invert, used by the test-only attack bookkeeping
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

type Cell = AssignedCell<Fp, Fp>;

/// SHA-256 initial hash value (FIPS 180-4, 5.3.3).
pub const IV: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 round constants (FIPS 180-4, 4.2.2).
pub const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Fixed padding words `W_8..W_15` for a single-block, 32-byte message.
pub const PADDING: [u32; 8] = [0x8000_0000, 0, 0, 0, 0, 0, 0, 256];

// -------------------------------------------------------------------------
// Test-only witness-perturbation hooks. The adversarial test suite sets one
// tamper at a time and asserts the circuit then rejects the witness. Outside
// `cargo test` of this crate, `get` is a constant `None` (no thread-local, no
// branch taken) so the hooks have no effect on real proofs.
#[allow(dead_code)]
pub(crate) mod poc_hook {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum Tamper {
        #[default]
        None,
        /// Assign bit `usize` of the current word to this raw field value
        /// (`2` makes it non-boolean; a flipped `0`/`1` breaks the packing).
        Bit(usize, u64),
        /// Add this to the packed value witness, leaving the bits alone.
        PackDelta(u32),
        /// Add this to a carry witness.
        CarryDelta(u64),
        /// Shift a produced word by this (both its bits and its packed value),
        /// so the word gate still holds but the gate that produced it fails.
        WordDelta(u32),
    }

    pub const TAG_NONE: u32 = 0;
    pub const TAG_SCHED_WORD: u32 = 1; // index = i in 0..64 (W_i word)
    pub const TAG_SCHED_CARRY: u32 = 2; // index = i
    pub const TAG_ROUND_A: u32 = 3; // index = t (A[t])
    pub const TAG_ROUND_E: u32 = 4; // index = t (E[t])
    pub const TAG_ROUND_ACAR: u32 = 5;
    pub const TAG_ROUND_ECAR: u32 = 6;
    pub const TAG_DIGEST: u32 = 7; // index = m in 0..8
    pub const TAG_DIGEST_CARRY: u32 = 8;
    pub const TAG_SEED_A: u32 = 9; // index = r in 0..4 (IV seed A rows)
    pub const TAG_SEED_E: u32 = 10; // index = r in 0..4 (IV seed E rows)

    #[cfg(test)]
    thread_local! {
        static TAMPER: std::cell::Cell<(u32, u32, Tamper)> =
            const { std::cell::Cell::new((0, 0, Tamper::None)) };
        /// Per-selector enable counts: [init, round, sched_word, sched, digest].
        static COUNTS: std::cell::Cell<[u32; 5]> = const { std::cell::Cell::new([0; 5]) };
    }

    /// Selector indices for the enable counter.
    pub const SEL_INIT: usize = 0;
    pub const SEL_ROUND: usize = 1;
    pub const SEL_SCHED_WORD: usize = 2;
    pub const SEL_SCHED: usize = 3;
    pub const SEL_DIGEST: usize = 4;

    #[cfg(test)]
    pub fn count(i: usize) {
        COUNTS.with(|c| {
            let mut a = c.get();
            a[i] += 1;
            c.set(a);
        });
    }
    #[cfg(not(test))]
    #[inline(always)]
    pub fn count(_i: usize) {}
    #[cfg(test)]
    pub fn reset_counts() {
        COUNTS.with(|c| c.set([0; 5]));
    }
    #[cfg(test)]
    pub fn counts() -> [u32; 5] {
        COUNTS.with(|c| c.get())
    }

    #[cfg(test)]
    pub fn get(tag: u32, index: u32) -> Tamper {
        TAMPER.with(|c| {
            let (t, i, tam) = c.get();
            if t == tag && i == index {
                tam
            } else {
                Tamper::None
            }
        })
    }
    #[cfg(not(test))]
    #[inline(always)]
    pub fn get(_tag: u32, _index: u32) -> Tamper {
        Tamper::None
    }

    #[cfg(test)]
    pub fn set(tag: u32, index: u32, tam: Tamper) {
        TAMPER.with(|c| c.set((tag, index, tam)));
    }
    #[cfg(test)]
    pub fn clear() {
        TAMPER.with(|c| c.set((TAG_NONE, 0, Tamper::None)));
        ATTACK.with(|c| c.set(Attack::None));
    }

    // ---- REVIEW ADDITION: compensated attacks -------------------------------
    // Unlike `Tamper`, an `Attack` recomputes the whole trace downstream of the
    // tampered cell, so every gate except the one under test is satisfied and
    // the instance H is set to the forged digest. If MockProver accepts, the
    // chip is unsound.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum Attack {
        #[default]
        None,
        /// Round `t` consumes `W_t + delta` (the `wc` cell is overwritten after
        /// `copy_advice`); the schedule cell keeps the honest W_t. C-3 class.
        RoundW { t: usize, delta: u32 },
        /// Digest row `m` consumes `operand + delta` (overwritten after copy).
        /// C-4 class.
        DigestOperand { m: usize, delta: u32 },
        /// `E[t] := E[t] + delta` with the E carry solved in the field. C-2.
        RoundEFieldCarry { t: usize, delta: u32 },
        /// `A[t] := A[t] + delta` with the A carry solved in the field. C-2.
        RoundAFieldCarry { t: usize, delta: u32 },
        /// `W_i := W_i + delta` (i >= 16) with the schedule carry in the field.
        SchedFieldCarry { i: usize, delta: u32 },
        /// `H[m] := H[m] + delta` with the digest carry in the field.
        DigestFieldCarry { m: usize, delta: u32 },
        /// `s0 += 2^32`, `acar += 1` at round t: the A equation still holds.
        S0Shift { t: usize },
        /// Seed row r: `aval` overwritten (after the constant copy) with
        /// `IV + delta`, bits consistent, trace propagated. Free-IV class.
        SeedA { r: usize, delta: u32 },
        /// Schedule row i < 8: `aval` overwritten (after the key copy) with
        /// `k_i + delta`; SHA runs on the forged key, Poseidon on the real one.
        /// This is the seller attack: H != SHA256(k).
        KeyWord { i: usize, delta: u32 },
    }

    #[cfg(test)]
    thread_local! {
        static ATTACK: std::cell::Cell<Attack> = const { std::cell::Cell::new(Attack::None) };
    }
    #[cfg(test)]
    pub fn attack() -> Attack {
        ATTACK.with(|c| c.get())
    }
    #[cfg(not(test))]
    #[inline(always)]
    pub fn attack() -> Attack {
        Attack::None
    }
    #[cfg(test)]
    pub fn set_attack(a: Attack) {
        ATTACK.with(|c| c.set(a));
    }
}

// -------------------------------------------------------------------------
// Pure-Rust reference for the honest witness.

fn bits_of(x: u32) -> [bool; 32] {
    core::array::from_fn(|i| (x >> i) & 1 == 1)
}

fn upper_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn upper_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
fn lower_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
fn lower_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ ((!e) & g)
}
fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

/// The full honest trace: every value the chip assigns, so the witness
/// assignment is a direct table lookup. `w[0..8]` are filled by the caller
/// from the key; the rest is derived.
#[derive(Clone, Debug)]
pub(crate) struct Trace {
    w: [u32; 64],
    wcar: [u64; 64],   // schedule carries (only 16..64 meaningful)
    a_seq: [u32; 68],  // row r holds A[r-4]; rows 0..4 are the IV seed
    e_seq: [u32; 68],  // row r holds E[r-4]
    s0: [u32; 68],     // Sigma0(A[t-1]) at round row r=t+4
    s1: [u32; 68],     // Sigma1(E[t-1])
    chv: [u32; 68],    // Ch(E[t-1],E[t-2],E[t-3])
    majv: [u32; 68],   // Maj(A[t-1],A[t-2],A[t-3])
    acar: [u64; 68],   // A[t] carry
    ecar: [u64; 68],   // E[t] carry
    pub(crate) digest: [u32; 8],
    digest_car: [u64; 8],
    // REVIEW ADDITION (attack bookkeeping; honest values when no attack):
    w_in: [u32; 64],       // the W consumed by round t (== w[t] honestly)
    operand: [u32; 8],     // the operand consumed by digest row m
    carry_fp: Option<(u32, u32, Fp)>, // (tag, index, field value) carry override
    s0_shift_row: Option<usize>,      // row where s0 += 2^32 and acar += 1
}

fn inv232() -> Fp {
    Fp::from(1u64 << 32).invert().unwrap()
}

#[cfg(test)]
fn compute_trace(key_words: [u32; 8]) -> Trace {
    compute_trace_attacked(key_words, poc_hook::Attack::None)
}

pub(crate) fn compute_trace_attacked(key_words: [u32; 8], atk: poc_hook::Attack) -> Trace {
    use poc_hook::Attack;
    let mut carry_fp = None;
    let mut w = [0u32; 64];
    w[..8].copy_from_slice(&key_words);
    if let Attack::KeyWord { i, delta } = atk {
        w[i] = w[i].wrapping_add(delta);
    }
    w[8..16].copy_from_slice(&PADDING);
    let mut wcar = [0u64; 64];
    for i in 16..64 {
        let s0 = lower_sigma0(w[i - 15]);
        let s1 = lower_sigma1(w[i - 2]);
        let sum = w[i - 16] as u64 + w[i - 7] as u64 + s0 as u64 + s1 as u64;
        w[i] = sum as u32;
        wcar[i] = sum >> 32;
        if let Attack::SchedFieldCarry { i: ai, delta } = atk {
            if ai == i {
                let forged = w[i].wrapping_add(delta);
                w[i] = forged;
                carry_fp = Some((
                    poc_hook::TAG_SCHED_CARRY,
                    i as u32,
                    (Fp::from(sum) - Fp::from(forged as u64)) * inv232(),
                ));
            }
        }
    }
    let mut w_in = w;
    if let Attack::RoundW { t, delta } = atk {
        w_in[t] = w[t].wrapping_add(delta);
    }
    let mut s0_shift_row = None;

    // Seed: row0=A[-4]=d=IV3, row1=A[-3]=IV2, row2=A[-2]=IV1, row3=A[-1]=a=IV0.
    let mut a_seq = [0u32; 68];
    let mut e_seq = [0u32; 68];
    a_seq[0] = IV[3];
    a_seq[1] = IV[2];
    a_seq[2] = IV[1];
    a_seq[3] = IV[0];
    e_seq[0] = IV[7];
    e_seq[1] = IV[6];
    e_seq[2] = IV[5];
    e_seq[3] = IV[4];
    if let Attack::SeedA { r, delta } = atk {
        a_seq[r] = a_seq[r].wrapping_add(delta);
    }

    let mut s0 = [0u32; 68];
    let mut s1 = [0u32; 68];
    let mut chv = [0u32; 68];
    let mut majv = [0u32; 68];
    let mut acar = [0u64; 68];
    let mut ecar = [0u64; 68];
    for t in 0..64usize {
        let r = t + 4;
        let a1 = a_seq[r - 1];
        let a2 = a_seq[r - 2];
        let a3 = a_seq[r - 3];
        let a4 = a_seq[r - 4]; // d
        let e1 = e_seq[r - 1];
        let e2 = e_seq[r - 2];
        let e3 = e_seq[r - 3];
        let e4 = e_seq[r - 4]; // h
        let s1v = upper_sigma1(e1);
        let chvv = ch(e1, e2, e3);
        let s0v = upper_sigma0(a1);
        let majvv = maj(a1, a2, a3);
        s1[r] = s1v;
        chv[r] = chvv;
        s0[r] = s0v;
        majv[r] = majvv;
        // E[t] = d + h + Sigma1 + Ch + K + W
        let sum_e = a4 as u64
            + e4 as u64
            + s1v as u64
            + chvv as u64
            + ROUND_CONSTANTS[t] as u64
            + w_in[t] as u64;
        e_seq[r] = sum_e as u32;
        ecar[r] = sum_e >> 32;
        if let Attack::RoundEFieldCarry { t: at, delta } = atk {
            if at == t {
                let forged = e_seq[r].wrapping_add(delta);
                e_seq[r] = forged;
                carry_fp = Some((
                    poc_hook::TAG_ROUND_ECAR,
                    t as u32,
                    (Fp::from(sum_e) - Fp::from(forged as u64)) * inv232(),
                ));
            }
        }
        // A[t] = h + Sigma1 + Ch + K + W + Sigma0 + Maj
        let sum_a = e4 as u64
            + s1v as u64
            + chvv as u64
            + ROUND_CONSTANTS[t] as u64
            + w_in[t] as u64
            + s0v as u64
            + majvv as u64;
        a_seq[r] = sum_a as u32;
        acar[r] = sum_a >> 32;
        if let Attack::RoundAFieldCarry { t: at, delta } = atk {
            if at == t {
                let forged = a_seq[r].wrapping_add(delta);
                a_seq[r] = forged;
                carry_fp = Some((
                    poc_hook::TAG_ROUND_ACAR,
                    t as u32,
                    (Fp::from(sum_a) - Fp::from(forged as u64)) * inv232(),
                ));
            }
        }
        if let Attack::S0Shift { t: at } = atk {
            if at == t {
                s0_shift_row = Some(r);
            }
        }
    }

    // Digest: H = final working vars + IV.
    // a=A[63]=a_seq[67], b=A[62], c=A[61], d=A[60]; e=E[63],...,h=E[60].
    let final_words = [
        a_seq[67], a_seq[66], a_seq[65], a_seq[64], e_seq[67], e_seq[66], e_seq[65], e_seq[64],
    ];
    let mut operand = final_words;
    if let Attack::DigestOperand { m, delta } = atk {
        operand[m] = operand[m].wrapping_add(delta);
    }
    let mut digest = [0u32; 8];
    let mut digest_car = [0u64; 8];
    for m in 0..8 {
        let sum = operand[m] as u64 + IV[m] as u64;
        digest[m] = sum as u32;
        digest_car[m] = sum >> 32;
        if let Attack::DigestFieldCarry { m: am, delta } = atk {
            if am == m {
                let forged = digest[m].wrapping_add(delta);
                digest[m] = forged;
                carry_fp = Some((
                    poc_hook::TAG_DIGEST_CARRY,
                    m as u32,
                    (Fp::from(sum) - Fp::from(forged as u64)) * inv232(),
                ));
            }
        }
    }

    Trace {
        w_in,
        operand,
        carry_fp,
        s0_shift_row,
        w,
        wcar,
        a_seq,
        e_seq,
        s0,
        s1,
        chv,
        majv,
        acar,
        ecar,
        digest,
        digest_car,
    }
}

// -------------------------------------------------------------------------
// Expression helpers (per-bit boolean polynomials).

fn xor2(x: Expression<Fp>, y: Expression<Fp>) -> Expression<Fp> {
    x.clone() + y.clone() - Expression::Constant(Fp::from(2)) * x * y
}
fn xor3(x: Expression<Fp>, y: Expression<Fp>, z: Expression<Fp>) -> Expression<Fp> {
    let two = Expression::Constant(Fp::from(2));
    let four = Expression::Constant(Fp::from(4));
    x.clone() + y.clone() + z.clone()
        - two * (x.clone() * y.clone() + x.clone() * z.clone() + y.clone() * z.clone())
        + four * x * y * z
}
/// `Ch_i = e f + (1-e) g = e f + g - e g`.
fn ch_bit(e: Expression<Fp>, f: Expression<Fp>, g: Expression<Fp>) -> Expression<Fp> {
    e.clone() * f + g.clone() - e * g
}
/// `Maj_i = ab + ac + bc - 2abc`.
fn maj_bit(a: Expression<Fp>, b: Expression<Fp>, c: Expression<Fp>) -> Expression<Fp> {
    let two = Expression::Constant(Fp::from(2));
    a.clone() * b.clone() + a.clone() * c.clone() + b.clone() * c.clone()
        - two * a * b * c
}

fn pow2(i: usize) -> Expression<Fp> {
    Expression::Constant(Fp::from(1u64 << i))
}
fn two32() -> Expression<Fp> {
    Expression::Constant(Fp::from(1u64 << 32))
}
/// `prod_{i=0}^{hi} (x - i) == 0`: constrains `x in {0,..,hi}`.
fn range_poly(x: Expression<Fp>, hi: u64) -> Expression<Fp> {
    let mut acc = Expression::Constant(Fp::one());
    for i in 0..=hi {
        acc = acc * (x.clone() - Expression::Constant(Fp::from(i)));
    }
    acc
}

// -------------------------------------------------------------------------

/// Configuration for [`ShaChip`].
#[derive(Clone, Debug)]
pub struct ShaConfig {
    /// A bits (compression) / W bits (schedule). Little-endian, one col per bit.
    pub(crate) abit: [Column<Advice>; 32],
    /// E bits (compression only).
    pub(crate) ebit: [Column<Advice>; 32],
    /// A packed (compression) / W packed (schedule). Equality-enabled.
    pub(crate) aval: Column<Advice>,
    /// E packed (compression). Equality-enabled.
    pub(crate) eval: Column<Advice>,
    /// Sigma0 / lower-sigma0 packed.
    pub(crate) s0: Column<Advice>,
    /// Sigma1 / lower-sigma1 packed.
    pub(crate) s1: Column<Advice>,
    /// Ch packed.
    pub(crate) chc: Column<Advice>,
    /// Maj packed.
    pub(crate) majc: Column<Advice>,
    /// Message word copied into a round (and operand copied into a digest row).
    /// Equality-enabled.
    pub(crate) wc: Column<Advice>,
    /// A-side carry (compression) / schedule carry / digest carry.
    pub(crate) acar: Column<Advice>,
    /// E-side carry (compression).
    pub(crate) ecar: Column<Advice>,
    /// Round constant `K_t` (rounds) / IV addend (digest). Fixed.
    pub(crate) kcol: Column<Fixed>,
    /// A fixed column enabled for constants (IV seed, padding words).
    #[allow(dead_code)]
    pub(crate) constants: Column<Fixed>,
    /// Advice columns exposed for the parent circuit to reuse for Poseidon and
    /// the sudoku gates (disjoint rows; every gate is selector-guarded).
    pub work: [Column<Advice>; 5],

    pub(crate) q_init: Selector,          // IV seed rows: booleanity + pack
    pub(crate) q_round: Selector,         // compression rounds
    pub(crate) q_sched_word: Selector,    // schedule given words W_0..W_15: booleanity + pack
    pub(crate) q_sched: Selector,         // schedule computed words W_16..W_63
    pub(crate) q_digest: Selector,        // feed-forward + output
}

/// The auditable SHA-256 chip.
#[derive(Clone, Debug)]
pub struct ShaChip {
    config: ShaConfig,
}

impl ShaChip {
    pub fn construct(config: ShaConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ShaConfig {
        &self.config
    }

    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> ShaConfig {
        let abit: [Column<Advice>; 32] = core::array::from_fn(|_| meta.advice_column());
        let ebit: [Column<Advice>; 32] = core::array::from_fn(|_| meta.advice_column());
        let aval = meta.advice_column();
        let eval = meta.advice_column();
        let s0 = meta.advice_column();
        let s1 = meta.advice_column();
        let chc = meta.advice_column();
        let majc = meta.advice_column();
        let wc = meta.advice_column();
        let acar = meta.advice_column();
        let ecar = meta.advice_column();
        let work: [Column<Advice>; 5] = core::array::from_fn(|_| meta.advice_column());

        let kcol = meta.fixed_column();
        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        for c in [aval, eval, wc] {
            meta.enable_equality(c);
        }
        for c in work {
            meta.enable_equality(c);
        }

        let q_init = meta.selector();
        let q_round = meta.selector();
        let q_sched_word = meta.selector();
        let q_sched = meta.selector();
        let q_digest = meta.selector();

        // Index maps for rotations/shifts.
        let rotr = |n: usize, j: usize| (j + n) % 32;

        // ---- word decomposition helper (booleanity + packing) ----
        // Returns constraints that `bits` are boolean and `val == sum bits 2^i`.
        // Built inline in each gate because the queried rotation is always cur.

        // ---- IV seed rows ----
        meta.create_gate("sha: iv seed word", |meta| {
            let q = meta.query_selector(q_init);
            let mut cs: Vec<Expression<Fp>> = Vec::new();
            let mut acc_a = Expression::Constant(Fp::zero());
            let mut acc_e = Expression::Constant(Fp::zero());
            for i in 0..32 {
                let a = meta.query_advice(abit[i], Rotation::cur());
                let e = meta.query_advice(ebit[i], Rotation::cur());
                cs.push(a.clone() * (Expression::Constant(Fp::one()) - a.clone()));
                cs.push(e.clone() * (Expression::Constant(Fp::one()) - e.clone()));
                acc_a = acc_a + a * pow2(i);
                acc_e = acc_e + e * pow2(i);
            }
            cs.push(meta.query_advice(aval, Rotation::cur()) - acc_a);
            cs.push(meta.query_advice(eval, Rotation::cur()) - acc_e);
            Constraints::with_selector(q, cs)
        });

        // ---- compression round ----
        meta.create_gate("sha: round", |meta| {
            let q = meta.query_selector(q_round);
            let mut cs: Vec<Expression<Fp>> = Vec::new();

            // booleanity + packing of this row's A and E words
            let mut acc_a = Expression::Constant(Fp::zero());
            let mut acc_e = Expression::Constant(Fp::zero());
            for i in 0..32 {
                let a = meta.query_advice(abit[i], Rotation::cur());
                let e = meta.query_advice(ebit[i], Rotation::cur());
                cs.push(a.clone() * (Expression::Constant(Fp::one()) - a.clone()));
                cs.push(e.clone() * (Expression::Constant(Fp::one()) - e.clone()));
                acc_a = acc_a + a * pow2(i);
                acc_e = acc_e + e * pow2(i);
            }
            let av = meta.query_advice(aval, Rotation::cur());
            let ev = meta.query_advice(eval, Rotation::cur());
            cs.push(av.clone() - acc_a);
            cs.push(ev.clone() - acc_e);

            // Sigma0(A[t-1]) = Sigma0 of abit at Rotation(-1).
            let a1 = |meta: &mut halo2_proofs::plonk::VirtualCells<Fp>, j: usize| {
                meta.query_advice(abit[j], Rotation(-1))
            };
            let mut acc_s0 = Expression::Constant(Fp::zero());
            for j in 0..32 {
                let t = xor3(a1(meta, rotr(2, j)), a1(meta, rotr(13, j)), a1(meta, rotr(22, j)));
                acc_s0 = acc_s0 + t * pow2(j);
            }
            cs.push(meta.query_advice(s0, Rotation::cur()) - acc_s0);

            // Sigma1(E[t-1]) = Sigma1 of ebit at Rotation(-1).
            let e1 = |meta: &mut halo2_proofs::plonk::VirtualCells<Fp>, j: usize| {
                meta.query_advice(ebit[j], Rotation(-1))
            };
            let mut acc_s1 = Expression::Constant(Fp::zero());
            for j in 0..32 {
                let t = xor3(e1(meta, rotr(6, j)), e1(meta, rotr(11, j)), e1(meta, rotr(25, j)));
                acc_s1 = acc_s1 + t * pow2(j);
            }
            cs.push(meta.query_advice(s1, Rotation::cur()) - acc_s1);

            // Ch(E[t-1],E[t-2],E[t-3]) from ebit at Rotation(-1,-2,-3).
            let mut acc_ch = Expression::Constant(Fp::zero());
            for j in 0..32 {
                let e = meta.query_advice(ebit[j], Rotation(-1));
                let f = meta.query_advice(ebit[j], Rotation(-2));
                let g = meta.query_advice(ebit[j], Rotation(-3));
                acc_ch = acc_ch + ch_bit(e, f, g) * pow2(j);
            }
            cs.push(meta.query_advice(chc, Rotation::cur()) - acc_ch);

            // Maj(A[t-1],A[t-2],A[t-3]) from abit at Rotation(-1,-2,-3).
            let mut acc_maj = Expression::Constant(Fp::zero());
            for j in 0..32 {
                let a = meta.query_advice(abit[j], Rotation(-1));
                let b = meta.query_advice(abit[j], Rotation(-2));
                let c = meta.query_advice(abit[j], Rotation(-3));
                acc_maj = acc_maj + maj_bit(a, b, c) * pow2(j);
            }
            cs.push(meta.query_advice(majc, Rotation::cur()) - acc_maj);

            let s0v = meta.query_advice(s0, Rotation::cur());
            let s1v = meta.query_advice(s1, Rotation::cur());
            let chv = meta.query_advice(chc, Rotation::cur());
            let majv = meta.query_advice(majc, Rotation::cur());
            let kt = meta.query_fixed(kcol);
            let wt = meta.query_advice(wc, Rotation::cur());
            let d = meta.query_advice(aval, Rotation(-4)); // A[t-4]
            let h = meta.query_advice(eval, Rotation(-4)); // E[t-4]
            let ecarry = meta.query_advice(ecar, Rotation::cur());
            let acarry = meta.query_advice(acar, Rotation::cur());

            // E[t] = d + h + Sigma1 + Ch + K + W - ecar*2^32
            cs.push(
                d.clone() + h.clone() + s1v.clone() + chv.clone() + kt.clone() + wt.clone()
                    - ev
                    - ecarry.clone() * two32(),
            );
            // A[t] = h + Sigma1 + Ch + K + W + Sigma0 + Maj - acar*2^32
            cs.push(
                h + s1v + chv + kt + wt + s0v + majv - av - acarry.clone() * two32(),
            );
            cs.push(range_poly(ecarry, 5));
            cs.push(range_poly(acarry, 6));

            Constraints::with_selector(q, cs)
        });

        // ---- schedule: given words W_0..W_15 (booleanity + pack) ----
        meta.create_gate("sha: schedule given word", |meta| {
            let q = meta.query_selector(q_sched_word);
            let mut cs: Vec<Expression<Fp>> = Vec::new();
            let mut acc = Expression::Constant(Fp::zero());
            for i in 0..32 {
                let a = meta.query_advice(abit[i], Rotation::cur());
                cs.push(a.clone() * (Expression::Constant(Fp::one()) - a.clone()));
                acc = acc + a * pow2(i);
            }
            cs.push(meta.query_advice(aval, Rotation::cur()) - acc);
            Constraints::with_selector(q, cs)
        });

        // ---- schedule: computed words W_16..W_63 ----
        meta.create_gate("sha: schedule word", |meta| {
            let q = meta.query_selector(q_sched);
            let mut cs: Vec<Expression<Fp>> = Vec::new();

            // booleanity + packing of W[i] (abit/aval at cur)
            let mut acc = Expression::Constant(Fp::zero());
            for i in 0..32 {
                let a = meta.query_advice(abit[i], Rotation::cur());
                cs.push(a.clone() * (Expression::Constant(Fp::one()) - a.clone()));
                acc = acc + a * pow2(i);
            }
            let wv = meta.query_advice(aval, Rotation::cur());
            cs.push(wv.clone() - acc);

            // lower_sigma0(W[i-15]) from abit at Rotation(-15).
            let x15 = |meta: &mut halo2_proofs::plonk::VirtualCells<Fp>, j: usize| {
                meta.query_advice(abit[j], Rotation(-15))
            };
            let mut acc_s0 = Expression::Constant(Fp::zero());
            for j in 0..32 {
                // rotr7 ^ rotr18 ^ shr3
                let r7 = x15(meta, rotr(7, j));
                let r18 = x15(meta, rotr(18, j));
                let t = if j + 3 < 32 {
                    xor3(r7, r18, x15(meta, j + 3))
                } else {
                    xor2(r7, r18)
                };
                acc_s0 = acc_s0 + t * pow2(j);
            }
            cs.push(meta.query_advice(s0, Rotation::cur()) - acc_s0);

            // lower_sigma1(W[i-2]) from abit at Rotation(-2).
            let x2 = |meta: &mut halo2_proofs::plonk::VirtualCells<Fp>, j: usize| {
                meta.query_advice(abit[j], Rotation(-2))
            };
            let mut acc_s1 = Expression::Constant(Fp::zero());
            for j in 0..32 {
                // rotr17 ^ rotr19 ^ shr10
                let r17 = x2(meta, rotr(17, j));
                let r19 = x2(meta, rotr(19, j));
                let t = if j + 10 < 32 {
                    xor3(r17, r19, x2(meta, j + 10))
                } else {
                    xor2(r17, r19)
                };
                acc_s1 = acc_s1 + t * pow2(j);
            }
            cs.push(meta.query_advice(s1, Rotation::cur()) - acc_s1);

            // W[i] = W[i-16] + W[i-7] + sigma0 + sigma1 - carry*2^32
            let w16 = meta.query_advice(aval, Rotation(-16));
            let w7 = meta.query_advice(aval, Rotation(-7));
            let s0v = meta.query_advice(s0, Rotation::cur());
            let s1v = meta.query_advice(s1, Rotation::cur());
            let carry = meta.query_advice(acar, Rotation::cur());
            cs.push(w16 + w7 + s0v + s1v - wv - carry.clone() * two32());
            cs.push(range_poly(carry, 3));

            Constraints::with_selector(q, cs)
        });

        // ---- digest / feed-forward ----
        meta.create_gate("sha: digest", |meta| {
            let q = meta.query_selector(q_digest);
            let mut cs: Vec<Expression<Fp>> = Vec::new();
            let mut acc = Expression::Constant(Fp::zero());
            for i in 0..32 {
                let a = meta.query_advice(abit[i], Rotation::cur());
                cs.push(a.clone() * (Expression::Constant(Fp::one()) - a.clone()));
                acc = acc + a * pow2(i);
            }
            let outv = meta.query_advice(aval, Rotation::cur());
            cs.push(outv.clone() - acc);
            let operand = meta.query_advice(wc, Rotation::cur());
            let iv = meta.query_fixed(kcol);
            let carry = meta.query_advice(acar, Rotation::cur());
            cs.push(operand + iv - outv - carry.clone() * two32());
            cs.push(carry.clone() * (carry - Expression::Constant(Fp::one())));
            Constraints::with_selector(q, cs)
        });

        ShaConfig {
            abit,
            ebit,
            aval,
            eval,
            s0,
            s1,
            chc,
            majc,
            wc,
            acar,
            ecar,
            kcol,
            constants,
            work,
            q_init,
            q_round,
            q_sched_word,
            q_sched,
            q_digest,
        }
    }

    /// SHA-256 of a single 64-byte block: `key_words[0..8]` are the first 8
    /// message words (copy-constrained to the caller's key cells), the rest is
    /// the fixed 256-bit-message padding. Returns the 8 digest words as
    /// equality-enabled packed cells, in `H[0..8]` order (big-endian u32).
    ///
    /// `key_cells` are the caller's 8 key-word cells (the same cells it packs
    /// for Poseidon); they are copy-constrained into `W_0..W_7`.
    #[allow(clippy::type_complexity)]
    pub fn digest(
        &self,
        layouter: &mut impl Layouter<Fp>,
        key_cells: &[Cell; 8],
        key_words: [Value<u32>; 8],
    ) -> Result<[Cell; 8], Error> {
        let cfg = &self.config;

        // Gather the key words into one Value<[u32;8]> and derive the trace.
        let kw: Value<[u32; 8]> = {
            let mut acc = Value::known([0u32; 8]);
            for (i, v) in key_words.iter().enumerate() {
                acc = acc.zip(*v).map(|(mut a, w)| {
                    a[i] = w;
                    a
                });
            }
            acc
        };
        let atk = poc_hook::attack();
        let trace: Value<Trace> = kw.map(move |k| compute_trace_attacked(k, atk));

        // ---- message schedule ----
        let w_cells = layouter.assign_region(
            || "sha message schedule",
            |mut region| {
                let mut w_cells: Vec<Cell> = Vec::with_capacity(64);
                for i in 0..64usize {
                    let wi: Value<u32> = trace.clone().map(|t| t.w[i]);
                    // honest bit witnesses (with optional per-bit tamper)
                    assign_bits(&mut region, &cfg.abit, i, wi, poc_hook::TAG_SCHED_WORD, i as u32)?;

                    if i < 8 {
                        // W_i = key word: copy the caller's cell into `aval`.
                        let mut cell = key_cells[i].copy_advice(|| "W=key", &mut region, cfg.aval, i)?;
                        if let poc_hook::Attack::KeyWord { i: ai, .. } = atk {
                            if ai == i {
                                // REVIEW ATTACK: overwrite the copied cell's value.
                                cell = region.assign_advice(|| "ATTACK key", cfg.aval, i, || {
                                    trace.clone().map(|t| Fp::from(t.w[i] as u64))
                                })?;
                            }
                        }
                        cfg.q_sched_word.enable(&mut region, i)?;
                        poc_hook::count(poc_hook::SEL_SCHED_WORD);
                        w_cells.push(cell);
                    } else if i < 16 {
                        // padding constant
                        let cell = region.assign_advice_from_constant(
                            || "W pad",
                            cfg.aval,
                            i,
                            Fp::from(PADDING[i - 8] as u64),
                        )?;
                        cfg.q_sched_word.enable(&mut region, i)?;
                        poc_hook::count(poc_hook::SEL_SCHED_WORD);
                        w_cells.push(cell);
                    } else {
                        cfg.q_sched.enable(&mut region, i)?;
                        poc_hook::count(poc_hook::SEL_SCHED);
                        region.assign_advice(|| "sigma0", cfg.s0, i, || {
                            trace.clone().map(|t| Fp::from(lower_sigma0(t.w[i - 15]) as u64))
                        })?;
                        region.assign_advice(|| "sigma1", cfg.s1, i, || {
                            trace.clone().map(|t| Fp::from(lower_sigma1(t.w[i - 2]) as u64))
                        })?;
                        assign_carry(
                            &mut region,
                            cfg.acar,
                            i,
                            trace.clone().map(|t| t.carry(poc_hook::TAG_SCHED_CARRY, i as u32, t.wcar[i])),
                            poc_hook::TAG_SCHED_CARRY,
                            i as u32,
                        )?;
                        let cell = assign_val(
                            &mut region,
                            cfg.aval,
                            i,
                            wi,
                            poc_hook::TAG_SCHED_WORD,
                            i as u32,
                        )?;
                        w_cells.push(cell);
                    }
                }
                Ok(w_cells)
            },
        )?;

        // ---- compression ----
        let (a_cells, e_cells) = layouter.assign_region(
            || "sha compression",
            |mut region| {
                // IV seed rows 0..4: A rows hold IV3,IV2,IV1,IV0; E rows IV7..IV4.
                let a_seed = [IV[3], IV[2], IV[1], IV[0]];
                let e_seed = [IV[7], IV[6], IV[5], IV[4]];
                for r in 0..4usize {
                    cfg.q_init.enable(&mut region, r)?;
                    poc_hook::count(poc_hook::SEL_INIT);
                    assign_bits(&mut region, &cfg.abit, r, trace.clone().map(|t| t.a_seq[r]), poc_hook::TAG_SEED_A, r as u32)?;
                    assign_bits(&mut region, &cfg.ebit, r, Value::known(e_seed[r]), poc_hook::TAG_SEED_E, r as u32)?;
                    region.assign_advice_from_constant(|| "A seed", cfg.aval, r, Fp::from(a_seed[r] as u64))?;
                    region.assign_advice_from_constant(|| "E seed", cfg.eval, r, Fp::from(e_seed[r] as u64))?;
                    if let poc_hook::Attack::SeedA { r: ar, .. } = atk {
                        if ar == r {
                            // REVIEW ATTACK: overwrite the constant-copied cell's value.
                            region.assign_advice(|| "ATTACK seed", cfg.aval, r, || {
                                trace.clone().map(|t| Fp::from(t.a_seq[r] as u64))
                            })?;
                        }
                    }
                }
                // Round cells, indexed by `t` in 0..64 (A[t] at a_cells[t]).
                let mut a_cells: Vec<Cell> = Vec::with_capacity(64);
                let mut e_cells: Vec<Cell> = Vec::with_capacity(64);
                for t in 0..64usize {
                    let r = t + 4;
                    cfg.q_round.enable(&mut region, r)?;
                    poc_hook::count(poc_hook::SEL_ROUND);
                    // intermediates
                    region.assign_advice(|| "s0", cfg.s0, r, || trace.clone().map(|tr| {
                        let shift = if tr.s0_shift_row == Some(r) { Fp::from(1u64 << 32) } else { Fp::zero() };
                        Fp::from(tr.s0[r] as u64) + shift
                    }))?;
                    region.assign_advice(|| "s1", cfg.s1, r, || trace.clone().map(|tr| Fp::from(tr.s1[r] as u64)))?;
                    region.assign_advice(|| "ch", cfg.chc, r, || trace.clone().map(|tr| Fp::from(tr.chv[r] as u64)))?;
                    region.assign_advice(|| "maj", cfg.majc, r, || trace.clone().map(|tr| Fp::from(tr.majv[r] as u64)))?;
                    // K_t: a fixed column, so it is part of the verifying key and
                    // the prover cannot choose it (known-answer tested separately).
                    region.assign_fixed(|| "K", cfg.kcol, r, || Value::known(Fp::from(ROUND_CONSTANTS[t] as u64)))?;
                    // W_t copied in
                    w_cells[t].copy_advice(|| "W", &mut region, cfg.wc, r)?;
                    if let poc_hook::Attack::RoundW { t: at, .. } = atk {
                        if at == t {
                            // REVIEW ATTACK: overwrite the copied W_t value.
                            region.assign_advice(|| "ATTACK wc", cfg.wc, r, || {
                                trace.clone().map(|tr| Fp::from(tr.w_in[t] as u64))
                            })?;
                        }
                    }
                    // carries
                    assign_carry(&mut region, cfg.ecar, r, trace.clone().map(|tr| tr.carry(poc_hook::TAG_ROUND_ECAR, t as u32, tr.ecar[r])), poc_hook::TAG_ROUND_ECAR, t as u32)?;
                    assign_carry(&mut region, cfg.acar, r, trace.clone().map(|tr| {
                        let extra = if tr.s0_shift_row == Some(r) { 1 } else { 0 };
                        tr.carry(poc_hook::TAG_ROUND_ACAR, t as u32, tr.acar[r] + extra)
                    }), poc_hook::TAG_ROUND_ACAR, t as u32)?;
                    // A[t], E[t] words + bits
                    let av: Value<u32> = trace.clone().map(|tr| tr.a_seq[r]);
                    let ev: Value<u32> = trace.clone().map(|tr| tr.e_seq[r]);
                    assign_bits(&mut region, &cfg.abit, r, av, poc_hook::TAG_ROUND_A, t as u32)?;
                    assign_bits(&mut region, &cfg.ebit, r, ev, poc_hook::TAG_ROUND_E, t as u32)?;
                    let ac = assign_val(&mut region, cfg.aval, r, av, poc_hook::TAG_ROUND_A, t as u32)?;
                    let ec = assign_val(&mut region, cfg.eval, r, ev, poc_hook::TAG_ROUND_E, t as u32)?;
                    a_cells.push(ac);
                    e_cells.push(ec);
                }
                Ok((a_cells, e_cells))
            },
        )?;

        // ---- digest / feed-forward ----
        // H[0..4] = A[63..60] + IV[0..4); H[4..8] = E[63..60] + IV[4..8).
        let operands: [Cell; 8] = [
            a_cells[63].clone(),
            a_cells[62].clone(),
            a_cells[61].clone(),
            a_cells[60].clone(),
            e_cells[63].clone(),
            e_cells[62].clone(),
            e_cells[61].clone(),
            e_cells[60].clone(),
        ];
        let out = layouter.assign_region(
            || "sha digest",
            |mut region| {
                let mut outs: Vec<Cell> = Vec::with_capacity(8);
                for m in 0..8usize {
                    cfg.q_digest.enable(&mut region, m)?;
                    poc_hook::count(poc_hook::SEL_DIGEST);
                    operands[m].copy_advice(|| "operand", &mut region, cfg.wc, m)?;
                    if let poc_hook::Attack::DigestOperand { m: am, .. } = atk {
                        if am == m {
                            // REVIEW ATTACK: overwrite the copied operand value.
                            region.assign_advice(|| "ATTACK operand", cfg.wc, m, || {
                                trace.clone().map(|t| Fp::from(t.operand[m] as u64))
                            })?;
                        }
                    }
                    region.assign_fixed(|| "IV", cfg.kcol, m, || Value::known(Fp::from(IV[m] as u64)))?;
                    assign_carry(&mut region, cfg.acar, m, trace.clone().map(|t| t.carry(poc_hook::TAG_DIGEST_CARRY, m as u32, t.digest_car[m])), poc_hook::TAG_DIGEST_CARRY, m as u32)?;
                    let hv: Value<u32> = trace.clone().map(|t| t.digest[m]);
                    assign_bits(&mut region, &cfg.abit, m, hv, poc_hook::TAG_DIGEST, m as u32)?;
                    let cell = assign_val(&mut region, cfg.aval, m, hv, poc_hook::TAG_DIGEST, m as u32)?;
                    outs.push(cell);
                }
                Ok(outs)
            },
        )?;
        Ok(out.try_into().unwrap())
    }
}

// -------------------------------------------------------------------------
// Assignment helpers (honest, with optional test-only tamper).

/// Honest packed word with an optional additive word-shift (WordDelta).
fn tamper_pack(x: u32, tag: u32, index: u32) -> u32 {
    match poc_hook::get(tag, index) {
        poc_hook::Tamper::PackDelta(d) => x.wrapping_add(d),
        poc_hook::Tamper::WordDelta(d) => x.wrapping_add(d),
        _ => x,
    }
}
fn tamper_carry(c: Fp, tag: u32, index: u32) -> Fp {
    match poc_hook::get(tag, index) {
        poc_hook::Tamper::CarryDelta(d) => c + Fp::from(d),
        _ => c,
    }
}

impl Trace {
    /// The carry to assign: the attack's field override if it targets this
    /// (tag, index), else the honest integer carry.
    fn carry(&self, tag: u32, index: u32, honest: u64) -> Fp {
        match self.carry_fp {
            Some((t, i, v)) if t == tag && i == index => v,
            _ => Fp::from(honest),
        }
    }
}

/// The 32 bit-cell field values for `word` at `offset`, honouring a tamper:
/// `WordDelta` shifts the whole word before decomposing (bits stay boolean and
/// consistent with the shifted word), while `Bit` overrides one bit cell with
/// an arbitrary field value (possibly non-boolean).
fn assign_bits(
    region: &mut halo2_proofs::circuit::Region<'_, Fp>,
    cols: &[Column<Advice>; 32],
    offset: usize,
    word: Value<u32>,
    tag: u32,
    index: u32,
) -> Result<(), Error> {
    for i in 0..32 {
        let b = word.map(move |w| match poc_hook::get(tag, index) {
            poc_hook::Tamper::Bit(bi, v) if bi == i => Fp::from(v),
            poc_hook::Tamper::WordDelta(d) => Fp::from(bits_of(w.wrapping_add(d))[i] as u64),
            _ => Fp::from(bits_of(w)[i] as u64),
        });
        region.assign_advice(|| "bit", cols[i], offset, || b)?;
    }
    Ok(())
}

fn assign_val(
    region: &mut halo2_proofs::circuit::Region<'_, Fp>,
    col: Column<Advice>,
    offset: usize,
    word: Value<u32>,
    tag: u32,
    index: u32,
) -> Result<Cell, Error> {
    region.assign_advice(|| "val", col, offset, || {
        word.map(|w| Fp::from(tamper_pack(w, tag, index) as u64))
    })
}

fn assign_carry(
    region: &mut halo2_proofs::circuit::Region<'_, Fp>,
    col: Column<Advice>,
    offset: usize,
    carry: Value<Fp>,
    tag: u32,
    index: u32,
) -> Result<(), Error> {
    region.assign_advice(|| "carry", col, offset, || {
        carry.map(|c| tamper_carry(c, tag, index))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_matches_sha2_reference() {
        use sha2::{Digest, Sha256};
        for seed in 0u32..40 {
            let key: [u8; 32] = core::array::from_fn(|i| {
                (i as u32 * 2654435761 + seed * 40503).to_le_bytes()[i % 4]
            });
            let kw: [u32; 8] =
                core::array::from_fn(|i| u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap()));
            let tr = compute_trace(kw);
            let mut bytes = [0u8; 32];
            for m in 0..8 {
                bytes[4 * m..4 * m + 4].copy_from_slice(&tr.digest[m].to_be_bytes());
            }
            let expect: [u8; 32] = Sha256::digest(key).into();
            assert_eq!(bytes, expect, "seed {seed}");
        }
    }
}
