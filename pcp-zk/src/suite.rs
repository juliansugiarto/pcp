//! Cipher suite `zk-poseidon-ctr/0`: the encryption the circuit proves.
//!
//! ```text
//! k      32 bytes from a CSPRNG, fresh for every offer, never reused
//! H      SHA256(k)                                   (plain SHA-256: the Lightning payment hash)
//! k_hi   the first 16 bytes of k, big-endian, as a field element (< 2^128)
//! k_lo   the last 16 bytes of k, big-endian, as a field element (< 2^128)
//! kk     Poseidon_3(TAG_KK, k_hi, k_lo)              (keystream key, domain separated)
//! s_j    Poseidon_2(kk, j)          for j = 0..80    (one field element per cell)
//! c_j    r_j + s_j   (mod p)                         (field addition)
//! ```
//!
//! `p` is the Pallas base field modulus (about 2^254). `Poseidon_L` is
//! `halo2_poseidon`'s `P128Pow5T3` permutation (width 3, rate 2, R_F = 8,
//! R_P = 56, the Orchard parameters) in `ConstantLength<L>` sponge mode, whose
//! capacity element encodes `L`, so the 3-input key derivation and the 2-input
//! keystream calls are domain separated by length as well as by `TAG_KK`.
//!
//! Decryption: `r_j = c_j - s_j`, which must be an integer in `1..=9`.

use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};
use ff::PrimeField;
use halo2_proofs::pasta::Fp;
use sha2::{Digest, Sha256};

/// Suite identifier (the value an offer's `enc_scheme` would carry).
pub const SUITE_ID: &str = "zk-poseidon-ctr/0";

/// Number of sudoku cells.
pub const CELLS: usize = 81;

/// Domain tag of the keystream key derivation: the ASCII bytes
/// `"pcpzk/kk"` read as a big-endian u64.
pub const TAG_KK: u64 = u64::from_be_bytes(*b"pcpzk/kk");

/// The payment hash `H = SHA256(k)`.
pub fn payment_hash(k: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(k).into()
}

/// `(k_hi, k_lo)`: the two 128-bit big-endian halves of `k` as field elements.
pub fn key_halves(k: &[u8; 32]) -> (Fp, Fp) {
    let hi = u128::from_be_bytes(k[..16].try_into().unwrap());
    let lo = u128::from_be_bytes(k[16..].try_into().unwrap());
    (Fp::from_u128(hi), Fp::from_u128(lo))
}

/// The keystream key `kk = Poseidon_3(TAG_KK, k_hi, k_lo)`.
pub fn keystream_key(k: &[u8; 32]) -> Fp {
    let (hi, lo) = key_halves(k);
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
        Fp::from(TAG_KK),
        hi,
        lo,
    ])
}

/// The 81 keystream elements `s_j = Poseidon_2(kk, j)`.
pub fn keystream(k: &[u8; 32]) -> Vec<Fp> {
    let kk = keystream_key(k);
    (0..CELLS as u64)
        .map(|j| {
            poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
                .hash([kk, Fp::from(j)])
        })
        .collect()
}

/// `C = Enc_k(R)`: `c_j = r_j + s_j`.
pub fn encrypt(solution: &[u8; CELLS], k: &[u8; 32]) -> Vec<Fp> {
    keystream(k)
        .into_iter()
        .zip(solution.iter())
        .map(|(s, &r)| Fp::from(r as u64) + s)
        .collect()
}

/// `R = Dec_k(C)`. Returns `None` unless every `c_j - s_j` is in `1..=9`.
pub fn decrypt(ciphertext: &[Fp], k: &[u8; 32]) -> Option<[u8; CELLS]> {
    if ciphertext.len() != CELLS {
        return None;
    }
    let mut out = [0u8; CELLS];
    for (j, (c, s)) in ciphertext.iter().zip(keystream(k)).enumerate() {
        let r = *c - s;
        out[j] = (1..=9u8).find(|&v| Fp::from(v as u64) == r)?;
    }
    Some(out)
}

/// The 27 sudoku groups (9 rows, 9 columns, 9 boxes) as cell indices.
pub fn groups() -> Vec<[usize; 9]> {
    let mut g = Vec::with_capacity(27);
    for r in 0..9 {
        g.push(core::array::from_fn(|i| r * 9 + i));
    }
    for c in 0..9 {
        g.push(core::array::from_fn(|i| i * 9 + c));
    }
    for b in 0..9 {
        let (br, bc) = ((b / 3) * 3, (b % 3) * 3);
        g.push(core::array::from_fn(|i| (br + i / 3) * 9 + bc + i % 3));
    }
    g
}

/// `pcp/sudoku/v0` with `n = 9`, in the clear: every cell in `1..=9`, every
/// given preserved, every row, column and box a permutation of `1..=9`.
pub fn sudoku_valid(givens: &[u8; CELLS], solution: &[u8; CELLS]) -> bool {
    if givens.iter().any(|&g| g > 9) || solution.iter().any(|&r| !(1..=9).contains(&r)) {
        return false;
    }
    if givens.iter().zip(solution).any(|(&g, &r)| g != 0 && g != r) {
        return false;
    }
    groups().iter().all(|grp| {
        let mut seen = [false; 10];
        grp.iter().all(|&i| !std::mem::replace(&mut seen[solution[i] as usize], true))
    })
}

/// Parse 81 cells written as digits (`.` also means blank); whitespace ignored.
pub fn parse_grid(text: &str) -> Result<[u8; CELLS], String> {
    let cells: Vec<u8> = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '.' => Ok(0),
            '0'..='9' => Ok(c as u8 - b'0'),
            _ => Err(format!("unexpected character {c:?} in grid")),
        })
        .collect::<Result<_, _>>()?;
    cells
        .try_into()
        .map_err(|v: Vec<u8>| format!("grid has {} cells, expected 81", v.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_payment_hash_vector() {
        // SPEC.md appendix A, vector 2.
        assert_eq!(
            hex::encode(payment_hash(&[0x11; 32])),
            "02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc"
        );
    }

    #[test]
    fn roundtrip_and_key_sensitivity() {
        let r: [u8; CELLS] = core::array::from_fn(|i| (i % 9) as u8 + 1);
        let c = encrypt(&r, &[7; 32]);
        assert_eq!(decrypt(&c, &[7; 32]), Some(r));
        assert_eq!(decrypt(&c, &[8; 32]), None);
        let s = keystream(&[7; 32]);
        assert!(s.iter().enumerate().all(|(i, a)| s[i + 1..].iter().all(|b| a != b)));
    }

    #[test]
    fn sum_and_product_are_not_enough() {
        // Rows of {1,2,4,4,4,5,7,9,9}: sum 45 and product 9! = 362880, but not a
        // permutation. Our check (and the circuit) rejects it.
        let bad_row = [1u8, 2, 4, 4, 4, 5, 7, 9, 9];
        assert_eq!(bad_row.iter().map(|&x| x as u32).sum::<u32>(), 45);
        assert_eq!(bad_row.iter().map(|&x| x as u32).product::<u32>(), 362880);
        let mut grid = [0u8; CELLS];
        for r in 0..9 {
            for c in 0..9 {
                grid[r * 9 + c] = bad_row[(c + r) % 9];
            }
        }
        assert!(!sudoku_valid(&[0; CELLS], &grid));
    }
}
