//! End-to-end tests with real halo2 proofs (IPA, k = 17). Slow: each proof
//! takes tens of seconds on 2 CPUs. The setup and one honest proof are shared.

use std::sync::OnceLock;

use ff::{Field, PrimeField};
use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{ProvingKey, VerifyingKey},
    poly::commitment::Params,
};
use pcp_zk::{circuit::SaleCircuit, suite, PublicInputs, ProveError};
use rand_core::{OsRng, RngCore, SeedableRng};

struct Setup {
    params: Params<EqAffine>,
    vk: VerifyingKey<EqAffine>,
    pk: ProvingKey<EqAffine>,
}

struct Sale {
    givens: [u8; 81],
    solution: [u8; 81],
    key: [u8; 32],
    binding: [u8; 32],
    proof: Vec<u8>,
    public: PublicInputs,
}

fn setup() -> &'static Setup {
    static S: OnceLock<Setup> = OnceLock::new();
    S.get_or_init(|| {
        let params = pcp_zk::params_cached(&pcp_zk::default_params_path());
        let vk = pcp_zk::verifying_key(&params);
        let pk = pcp_zk::proving_key(&params, pcp_zk::verifying_key(&params));
        Setup { params, vk, pk }
    })
}

fn sample() -> ([u8; 81], [u8; 81]) {
    let p = suite::parse_grid(include_str!("../examples/puzzle.txt")).unwrap();
    let s = suite::parse_grid(include_str!("../examples/solution.txt")).unwrap();
    (p, s)
}

fn sale() -> &'static Sale {
    static S: OnceLock<Sale> = OnceLock::new();
    S.get_or_init(|| {
        let st = setup();
        let (givens, solution) = sample();
        let mut binding = [0u8; 32];
        OsRng.fill_bytes(&mut binding);
        let (proof, public, key) =
            pcp_zk::sell(&st.params, &st.pk, &givens, &solution, &binding).unwrap();
        Sale { givens, solution, key, binding, proof, public }
    })
}

fn verifies(public: &PublicInputs, proof: &[u8]) -> bool {
    let st = setup();
    pcp_zk::verify(&st.params, &st.vk, public, proof)
}

#[test]
fn valid_sale_verifies_and_buyer_decrypts_after_payment() {
    let s = sale();
    assert!(verifies(&s.public, &s.proof));
    // Through the JSON file format, as the CLI does.
    let back = PublicInputs::from_json(&s.public.to_json()).unwrap();
    assert_eq!(back, s.public);
    assert!(verifies(&back, &s.proof));
    // After payment the buyer holds k (the preimage of H) and decrypts.
    assert_eq!(suite::payment_hash(&s.key), s.public.payment_hash);
    let r = suite::decrypt(&s.public.ciphertext, &s.key).unwrap();
    assert_eq!(r, s.solution);
    assert!(suite::sudoku_valid(&s.givens, &r));
    assert_eq!(s.public.binding, s.binding);
}

#[test]
fn tampered_public_inputs_fail() {
    let s = sale();
    let mut c = s.public.clone();
    c.ciphertext[0] += Fp::ONE;
    assert!(!verifies(&c, &s.proof), "tampered C");

    let mut c = s.public.clone();
    c.ciphertext.swap(3, 4);
    assert!(!verifies(&c, &s.proof), "reordered C");

    let mut h = s.public.clone();
    h.payment_hash[17] ^= 0x01;
    assert!(!verifies(&h, &s.proof), "tampered H");

    let mut g = s.public.clone();
    g.givens[1] = 0; // removing a given
    assert!(!verifies(&g, &s.proof), "tampered givens (removed)");
    let mut g = s.public.clone();
    g.givens[2] = 4; // adding a given that is even true for the solution
    assert!(!verifies(&g, &s.proof), "tampered givens (added)");

    let mut b = s.public.clone();
    b.binding[0] ^= 0x80;
    assert!(!verifies(&b, &s.proof), "proof replayed under another offer binding");
}

#[test]
fn malformed_proofs_fail() {
    let s = sale();
    let mut p = s.proof.clone();
    let mid = p.len() / 2;
    p[mid] ^= 1;
    assert!(!verifies(&s.public, &p), "bit flip");
    assert!(!verifies(&s.public, &s.proof[..s.proof.len() - 1]), "truncated");
    let mut p = s.proof.clone();
    p.push(0);
    assert!(!verifies(&s.public, &p), "trailing byte");
    assert!(!verifies(&s.public, &[]), "empty");
}

#[test]
fn wrong_solution_cannot_produce_a_valid_proof() {
    let st = setup();
    let (givens, solution) = sample();
    let mut bad = solution;
    bad.swap(0, 1); // breaks the givens and two columns and a box
    let key = [0x42; 32];
    // An honest prover refuses.
    assert!(matches!(
        pcp_zk::prove_with_key(&st.params, &st.pk, &givens, &bad, &key, &[0; 32]),
        Err(ProveError::InvalidWitness(_))
    ));
    // A cheating prover running halo2 on the false statement gets a proof
    // that does not verify.
    let public = PublicInputs {
        givens,
        ciphertext: suite::encrypt(&bad, &key),
        payment_hash: suite::payment_hash(&key),
        binding: [0; 32],
    };
    let proof = pcp_zk::prove_unchecked(&st.params, &st.pk, &public, SaleCircuit::new(bad, key), OsRng)
        .unwrap();
    assert!(!verifies(&public, &proof));
}

#[test]
fn zero_knowledge_blinding_is_on() {
    // halo2 0.3 has no ZK switch; blinding is unconditional. Assert it is
    // there and that it is fed by the prover's RNG: if blinding were off,
    // two proofs of the same statement would be byte-identical.
    assert!(pcp_zk::blinding_rows() >= 1, "no blinding rows");
    let st = setup();
    let s = sale();
    let circuit = || SaleCircuit::new(s.solution, s.key);
    let p1 = pcp_zk::prove_unchecked(&st.params, &st.pk, &s.public, circuit(), OsRng).unwrap();
    assert_ne!(p1, s.proof, "two proofs of one statement are identical: no blinding");
    assert!(verifies(&s.public, &p1));
    // Same seed, same proof: the only source of difference is the RNG.
    let seeded = |seed| rand_chacha_like(seed);
    let a = pcp_zk::prove_unchecked(&st.params, &st.pk, &s.public, circuit(), seeded(7)).unwrap();
    let b = pcp_zk::prove_unchecked(&st.params, &st.pk, &s.public, circuit(), seeded(7)).unwrap();
    assert_eq!(a, b);
}

/// A deterministic RNG for the test above (StdRng-like, from rand_core's
/// block RNG would need another crate; a xorshift is enough here).
fn rand_chacha_like(seed: u64) -> XorShift {
    XorShift::seed_from_u64(seed)
}

struct XorShift(u64);
impl RngCore for XorShift {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl SeedableRng for XorShift {
    type Seed = [u8; 8];
    fn from_seed(seed: [u8; 8]) -> Self {
        XorShift(u64::from_le_bytes(seed) | 1)
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn proof_and_public_inputs_do_not_contain_r_or_k() {
    let s = sale();
    let json = s.public.to_json();
    let files: [&[u8]; 2] = [&s.proof, json.as_bytes()];
    let k_hex = hex::encode(s.key);
    let r_ascii: String = s.solution.iter().map(|d| char::from(b'0' + d)).collect();
    let (k_hi, k_lo) = suite::key_halves(&s.key);
    let kk = suite::keystream_key(&s.key);
    for f in files {
        // k: raw, every 8-byte window, hex; derived secrets k_hi, k_lo, kk.
        assert!(!contains(f, &s.key));
        for w in s.key.windows(8) {
            assert!(!contains(f, w));
        }
        assert!(!contains(f, k_hex.as_bytes()));
        for x in [k_hi, k_lo, kk] {
            assert!(!contains(f, &x.to_repr()));
            assert!(!contains(f, hex::encode(x.to_repr()).as_bytes()));
        }
        // R: raw bytes, ASCII digits (whole and per row), and each keystream
        // element (which would reveal r_j = c_j - s_j).
        assert!(!contains(f, &s.solution));
        for row in r_ascii.as_bytes().chunks(9) {
            assert!(!contains(f, row));
        }
        for sj in suite::keystream(&s.key) {
            assert!(!contains(f, &sj.to_repr()));
        }
    }
    // The public givens string is the puzzle, not the solution.
    assert!(!json.contains(&r_ascii));
}
