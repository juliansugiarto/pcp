//! The halo2 circuit for a ZKCP sudoku sale under suite `zk-poseidon-ctr/0`.
//!
//! Public (one instance column, [`INSTANCE_LEN`] rows):
//!
//! | rows      | value                                                      |
//! |-----------|------------------------------------------------------------|
//! | 0..81     | givens `g_j` (0 = blank, else 1..9)                        |
//! | 81..162   | ciphertext `c_j` (field elements)                          |
//! | 162..170  | `H = SHA256(k)` as 8 big-endian u32 words                  |
//! | 170..178  | offer binding (32 bytes, e.g. `offer_id`) as 8 u32 words   |
//!
//! Private: the solution `r_j` and the key `k` (8 u32 words).
//!
//! Constraints:
//!
//! * `k`: each word is decomposed into 8 nibbles, each looked up in `0..16`,
//!   so each word is a 32-bit integer; `k_hi`, `k_lo` are the packed halves.
//! * `H`: one SHA-256 compression by the in-house chip ([`crate::sha256`]) of
//!   the 64-byte block `k || padding`. The chip copy-constrains `W_0..W_7` to
//!   the same `k` word cells used for the Poseidon packing, keeps `K_t` and the
//!   IV in fixed columns, and returns the 8 digest words, which equal the
//!   public `H` words.
//! * keystream: `kk = Poseidon_3(TAG_KK, k_hi, k_lo)`, `s_j = Poseidon_2(kk, j)`
//!   (halo2_gadgets Pow5 chip, `P128Pow5T3`).
//! * encryption: `r_j + s_j = c_j`.
//! * range: `r_j - 1` and `9 - r_j` are written to the nibble column and both
//!   looked up in `0..16`, so `r_j` is in `1..=9`.
//! * givens: `g_j * (r_j - g_j) = 0`.
//! * distinctness: for each of the 27 groups and each of its 36 pairs,
//!   `(r_a - r_b) * inv = 1` with a witnessed inverse. With every cell in
//!   `1..=9`, nine pairwise distinct cells are a permutation of `1..=9`.
//! * binding: the 8 binding words are copied into advice cells, so they take
//!   part in the permutation argument (and, like every instance value, in the
//!   Fiat-Shamir transcript).

use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
        TableColumn,
    },
    poly::Rotation,
};

use crate::sha256::{ShaChip, ShaConfig};
use crate::suite::{groups, CELLS, TAG_KK};

/// log2 of the number of rows. The SHA-256 lookup table of Table16 is gone;
/// the floor is now set by Poseidon (83 permutations) and the sudoku gates.
pub const K: u32 = 13;

pub const ROW_GIVENS: usize = 0;
pub const ROW_CIPHERTEXT: usize = 81;
pub const ROW_PAYMENT_HASH: usize = 162;
pub const ROW_BINDING: usize = 170;
pub const INSTANCE_LEN: usize = 178;

type Cell = AssignedCell<Fp, Fp>;

#[derive(Clone, Debug)]
pub struct SaleConfig {
    pub(crate) sha: ShaConfig,
    poseidon: Pow5Config<Fp, 3, 2>,
    /// Nibble column (looked up in `nib_table` where `q_nib` is on).
    rc: Column<Advice>,
    pub(crate) a: [Column<Advice>; 5],
    instance: Column<Instance>,
    nib_table: TableColumn,
    q_nib: Selector,
    q_dec: Selector,
    q_pack: Selector,
    q_enc: Selector,
    q_neq: Selector,
}

/// The witness. `Value::unknown()` everywhere for key generation.
#[derive(Clone, Debug, Default)]
pub struct SaleCircuit {
    pub solution: Value<[u8; CELLS]>,
    pub key: Value<[u8; 32]>,
}

impl SaleCircuit {
    pub fn new(solution: [u8; CELLS], key: [u8; 32]) -> Self {
        SaleCircuit {
            solution: Value::known(solution),
            key: Value::known(key),
        }
    }
}

fn pow16(t: usize) -> Fp {
    Fp::from(1u64 << (4 * t))
}

impl Circuit<Fp> for SaleCircuit {
    type Config = SaleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> SaleConfig {
        let sha = ShaChip::configure(meta);

        // The sudoku, packing and Poseidon gates reuse the SHA chip's five
        // equality-enabled "work" advice columns plus one extra; regions never
        // overlap and every gate is selector-guarded, so this keeps the advice
        // and permutation column count (and prover memory) down.
        let [w0, w1, w2, w3, w4] = sha.work;
        let a9 = meta.advice_column(); // Poseidon partial S-box
        meta.enable_equality(a9);

        // Poseidon (Pow5, P128Pow5T3): state in three equality-enabled columns.
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, [w0, w1, w2], a9, rc_a, rc_b);

        let rc = meta.advice_column();
        let a = [w0, w1, w2, w3, w4];
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let nib_table = meta.lookup_table_column();

        let q_nib = meta.complex_selector();
        let q_dec = meta.selector();
        let q_pack = meta.selector();
        let q_enc = meta.selector();
        let q_neq = meta.selector();

        meta.lookup(|meta| {
            let q = meta.query_selector(q_nib);
            let v = meta.query_advice(rc, Rotation::cur());
            vec![(q * v, nib_table)]
        });

        // a[2] (this row) = sum_t rc[row + t] * 16^(7 - t): big-endian nibbles.
        meta.create_gate("nibble decomposition", |meta| {
            let q = meta.query_selector(q_dec);
            let word = meta.query_advice(a[2], Rotation::cur());
            let mut acc = Expression::Constant(Fp::zero());
            for t in 0..8 {
                acc = acc + meta.query_advice(rc, Rotation(t as i32)) * pow16(7 - t);
            }
            vec![q * (acc - word)]
        });

        // a[4] = a[0] * 2^96 + a[1] * 2^64 + a[2] * 2^32 + a[3]
        meta.create_gate("pack four words", |meta| {
            let q = meta.query_selector(q_pack);
            let w: Vec<_> = (0..4).map(|i| meta.query_advice(a[i], Rotation::cur())).collect();
            let packed = meta.query_advice(a[4], Rotation::cur());
            let two32 = Fp::from(1u64 << 32);
            let acc = ((w[0].clone() * two32 + w[1].clone()) * two32 + w[2].clone()) * two32
                + w[3].clone();
            vec![q * (acc - packed)]
        });

        // r + s = c ; g * (r - g) = 0 ;
        // rc(cur) = r - 1 and rc(next) = 9 - r, both nibble-checked, so r is in 1..=9.
        meta.create_gate("encrypt, givens, range", |meta| {
            let q = meta.query_selector(q_enc);
            let r = meta.query_advice(a[0], Rotation::cur());
            let s = meta.query_advice(a[1], Rotation::cur());
            let c = meta.query_advice(a[2], Rotation::cur());
            let g = meta.query_advice(a[3], Rotation::cur());
            let lo = meta.query_advice(rc, Rotation::cur());
            let hi = meta.query_advice(rc, Rotation::next());
            let one = Expression::Constant(Fp::one());
            let nine = Expression::Constant(Fp::from(9));
            vec![
                q.clone() * (r.clone() + s - c),
                q.clone() * g.clone() * (r.clone() - g),
                q.clone() * (lo - (r.clone() - one)),
                q * (hi - (nine - r)),
            ]
        });

        // (x - y) * inv = 1
        meta.create_gate("pairwise distinct", |meta| {
            let q = meta.query_selector(q_neq);
            let x = meta.query_advice(a[0], Rotation::cur());
            let y = meta.query_advice(a[1], Rotation::cur());
            let inv = meta.query_advice(a[2], Rotation::cur());
            vec![q * ((x - y) * inv - Expression::Constant(Fp::one()))]
        });

        SaleConfig {
            sha,
            poseidon,
            rc,
            a,
            instance,
            nib_table,
            q_nib,
            q_dec,
            q_pack,
            q_enc,
            q_neq,
        }
    }

    fn synthesize(&self, cfg: SaleConfig, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_table(
            || "nibble table",
            |mut table| {
                for i in 0..16u64 {
                    table.assign_cell(|| "nib", cfg.nib_table, i as usize, || {
                        Value::known(Fp::from(i))
                    })?;
                }
                Ok(())
            },
        )?;

        // ---- key words, range checked ------------------------------------
        let key_words: Vec<Value<u32>> = (0..8)
            .map(|i| {
                self.key
                    .map(|k| u32::from_be_bytes(k[4 * i..4 * i + 4].try_into().unwrap()))
            })
            .collect();
        let k_cells = layouter.assign_region(
            || "key words",
            |mut region| {
                let mut cells = Vec::with_capacity(8);
                for (i, w) in key_words.iter().enumerate() {
                    let row = 8 * i;
                    cfg.q_dec.enable(&mut region, row)?;
                    let cell = region.assign_advice(|| "k word", cfg.a[2], row, || {
                        w.map(|w| Fp::from(w as u64))
                    })?;
                    assign_nibbles(&mut region, &cfg, row, *w)?;
                    cells.push(cell);
                }
                Ok(cells)
            },
        )?;
        let (k_hi, k_lo) = layouter.assign_region(
            || "pack key halves",
            |mut region| {
                let mut halves = Vec::new();
                for (row, words) in k_cells.chunks(4).enumerate() {
                    cfg.q_pack.enable(&mut region, row)?;
                    for (i, w) in words.iter().enumerate() {
                        w.copy_advice(|| "word", &mut region, cfg.a[i], row)?;
                    }
                    let packed = words.iter().fold(Value::known(Fp::zero()), |acc, w| {
                        acc.zip(w.value()).map(|(acc, w)| acc * Fp::from(1u64 << 32) + w)
                    });
                    halves.push(region.assign_advice(|| "packed", cfg.a[4], row, || packed)?);
                }
                Ok((halves[0].clone(), halves[1].clone()))
            },
        )?;

        // ---- H = SHA256(k) -------------------------------------------------
        // One block: k (8 words) || 0x80000000 || 0 x 6 || bit length 256.
        // The in-house chip copy-constrains W_0..W_7 to `k_cells` (the same
        // cells packed for Poseidon) and returns the 8 digest words.
        let sha_chip = ShaChip::construct(cfg.sha.clone());
        let key_cells: [Cell; 8] = k_cells.clone().try_into().unwrap();
        let key_word_arr: [Value<u32>; 8] = key_words.clone().try_into().unwrap();
        let h_cells = sha_chip.digest(&mut layouter, &key_cells, key_word_arr)?;
        for (i, cell) in h_cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), cfg.instance, ROW_PAYMENT_HASH + i)?;
        }

        // ---- keystream ----------------------------------------------------
        let (tag, idx) = layouter.assign_region(
            || "poseidon constants",
            |mut region| {
                let tag = region.assign_advice_from_constant(|| "TAG_KK", cfg.a[0], 0, Fp::from(TAG_KK))?;
                let mut idx = Vec::with_capacity(CELLS);
                for j in 0..CELLS {
                    idx.push(region.assign_advice_from_constant(
                        || "j",
                        cfg.a[1],
                        j,
                        Fp::from(j as u64),
                    )?);
                }
                Ok((tag, idx))
            },
        )?;
        let kk = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            Pow5Chip::construct(cfg.poseidon.clone()),
            layouter.namespace(|| "kk init"),
        )?
        .hash(layouter.namespace(|| "kk"), [tag, k_hi, k_lo])?;
        let mut stream: Vec<Cell> = Vec::with_capacity(CELLS);
        for (j, jc) in idx.into_iter().enumerate() {
            let s = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                Pow5Chip::construct(cfg.poseidon.clone()),
                layouter.namespace(|| format!("s_{j} init")),
            )?
            .hash(layouter.namespace(|| format!("s_{j}")), [kk.clone(), jc])?;
            stream.push(s);
        }

        // ---- encryption, range, givens --------------------------------------
        let r_cells = layouter.assign_region(
            || "encrypt",
            |mut region| {
                let mut rs = Vec::with_capacity(CELLS);
                for j in 0..CELLS {
                    let row = 2 * j;
                    cfg.q_enc.enable(&mut region, row)?;
                    cfg.q_nib.enable(&mut region, row)?;
                    cfg.q_nib.enable(&mut region, row + 1)?;
                    let rv = self.solution.map(|sol| Fp::from(sol[j] as u64));
                    let r = region.assign_advice(|| "r", cfg.a[0], row, || rv)?;
                    region.assign_advice(|| "r - 1", cfg.rc, row, || rv.map(|r| r - Fp::one()))?;
                    region.assign_advice(|| "9 - r", cfg.rc, row + 1, || {
                        rv.map(|r| Fp::from(9) - r)
                    })?;
                    stream[j].copy_advice(|| "s", &mut region, cfg.a[1], row)?;
                    region.assign_advice_from_instance(
                        || "c",
                        cfg.instance,
                        ROW_CIPHERTEXT + j,
                        cfg.a[2],
                        row,
                    )?;
                    region.assign_advice_from_instance(
                        || "g",
                        cfg.instance,
                        ROW_GIVENS + j,
                        cfg.a[3],
                        row,
                    )?;
                    rs.push(r);
                }
                Ok(rs)
            },
        )?;

        // ---- distinctness ---------------------------------------------------
        layouter.assign_region(
            || "pairwise distinct",
            |mut region| {
                let mut row = 0;
                for grp in groups() {
                    for x in 0..9 {
                        for y in x + 1..9 {
                            cfg.q_neq.enable(&mut region, row)?;
                            let a = r_cells[grp[x]].copy_advice(|| "x", &mut region, cfg.a[0], row)?;
                            let b = r_cells[grp[y]].copy_advice(|| "y", &mut region, cfg.a[1], row)?;
                            let inv = a.value().zip(b.value()).map(|(a, b)| {
                                Option::<Fp>::from((*a - *b).invert()).unwrap_or(Fp::zero())
                            });
                            region.assign_advice(|| "inv", cfg.a[2], row, || inv)?;
                            row += 1;
                        }
                    }
                }
                Ok(())
            },
        )?;

        // ---- offer binding ----------------------------------------------------
        layouter.assign_region(
            || "offer binding",
            |mut region| {
                for i in 0..8 {
                    region.assign_advice_from_instance(
                        || "binding",
                        cfg.instance,
                        ROW_BINDING + i,
                        cfg.a[0],
                        i,
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

/// Write the 8 big-endian nibbles of `word` into `rc[row..row + 8]`, with the
/// nibble lookup on.
fn assign_nibbles(
    region: &mut halo2_proofs::circuit::Region<'_, Fp>,
    cfg: &SaleConfig,
    row: usize,
    word: Value<u32>,
) -> Result<(), Error> {
    for t in 0..8 {
        cfg.q_nib.enable(region, row + t)?;
        region.assign_advice(|| "nibble", cfg.rc, row + t, || {
            word.map(|w| Fp::from(((w >> (4 * (7 - t))) & 0xf) as u64))
        })?;
    }
    Ok(())
}
