//! PCP/0 zero-knowledge backend experiment: a halo2 proof (IPA commitments
//! over the Pasta curves, transparent setup, zero knowledge by blinding) of
//! the ZKCP sudoku sale statement, with the cipher suite `zk-poseidon-ctr/0`.
//!
//! NOT AUDITED. See README.md.

pub mod circuit;
pub mod sha256;
pub mod suite;

#[cfg(test)]
mod adversarial;
#[cfg(test)]
mod review_tests;

use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ConstraintSystem, ProvingKey,
        SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use ff::PrimeField;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use circuit::{SaleCircuit, INSTANCE_LEN, K};
use suite::CELLS;

/// Backend identifier (what an offer's `backend_id` would carry).
pub const BACKEND_ID: &str = "halo2-ipa-pasta/pcp-sudoku9-zk-poseidon-ctr/0";

/// Public inputs of one sale. Everything here is known to the buyer before
/// paying; none of it is `R` or `k`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub givens: [u8; CELLS],
    pub ciphertext: Vec<Fp>,
    pub payment_hash: [u8; 32],
    pub binding: [u8; 32],
}

fn words(b: &[u8; 32]) -> impl Iterator<Item = Fp> + '_ {
    b.chunks(4)
        .map(|c| Fp::from(u32::from_be_bytes(c.try_into().unwrap()) as u64))
}

impl PublicInputs {
    /// Validate shapes and ranges that the verifier checks natively.
    pub fn check_shape(&self) -> Result<(), String> {
        if self.givens.iter().any(|&g| g > 9) {
            return Err("given out of range".into());
        }
        if self.ciphertext.len() != CELLS {
            return Err("ciphertext must have 81 elements".into());
        }
        Ok(())
    }

    /// The instance column, in the layout of [`circuit`].
    pub fn instance(&self) -> Vec<Fp> {
        let mut v = Vec::with_capacity(INSTANCE_LEN);
        v.extend(self.givens.iter().map(|&g| Fp::from(g as u64)));
        v.extend(self.ciphertext.iter().copied());
        v.extend(words(&self.payment_hash));
        v.extend(words(&self.binding));
        assert_eq!(v.len(), INSTANCE_LEN);
        v
    }
}

/// JSON form of [`PublicInputs`]. Field elements are 32-byte little-endian
/// canonical encodings in lowercase hex; non-canonical encodings are rejected.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicInputsJson {
    pub suite: String,
    pub backend_id: String,
    pub givens: String,
    pub ciphertext: Vec<String>,
    pub payment_hash: String,
    pub binding: String,
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("uppercase hex".into());
    }
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())
}

impl PublicInputs {
    pub fn to_json(&self) -> String {
        let j = PublicInputsJson {
            suite: suite::SUITE_ID.into(),
            backend_id: BACKEND_ID.into(),
            givens: self.givens.iter().map(|g| char::from(b'0' + g)).collect(),
            ciphertext: self
                .ciphertext
                .iter()
                .map(|c| hex::encode(c.to_repr()))
                .collect(),
            payment_hash: hex::encode(self.payment_hash),
            binding: hex::encode(self.binding),
        };
        serde_json::to_string_pretty(&j).unwrap()
    }

    pub fn from_json(s: &str) -> Result<Self, String> {
        let j: PublicInputsJson = serde_json::from_str(s).map_err(|e| e.to_string())?;
        if j.suite != suite::SUITE_ID || j.backend_id != BACKEND_ID {
            return Err("unknown suite or backend".into());
        }
        let ciphertext = j
            .ciphertext
            .iter()
            .map(|h| {
                let repr = hex32(h)?;
                Option::<Fp>::from(Fp::from_repr(repr))
                    .ok_or_else(|| "non-canonical field element".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let p = PublicInputs {
            givens: suite::parse_grid(&j.givens)?,
            ciphertext,
            payment_hash: hex32(&j.payment_hash)?,
            binding: hex32(&j.binding)?,
        };
        p.check_shape()?;
        Ok(p)
    }
}

/// Transparent parameters: `Params::new(K)` derives every generator by
/// hashing to the curve. Nobody chooses them; prover and verifier compute
/// them independently.
pub fn params() -> Params<EqAffine> {
    Params::new(K)
}

/// SHA-256 of the serialized `Params::new(K)` (see [`params_cached`]).
/// Anyone can recompute it by deleting the cache file.
pub const PARAMS_SHA256: &str =
    "76ebe6b75b5281cb1dcc2eb04888968573758672b521522f62abedf6366bb876";

/// [`params`] with a local cache file. The parameters are deterministic, so
/// caching does not add trust: a cached file is used only if its SHA-256
/// equals [`PARAMS_SHA256`]; otherwise the parameters are regenerated and the
/// file rewritten. (Generating them takes minutes on 2 CPUs; see COSTS.md.)
pub fn params_cached(path: &std::path::Path) -> Params<EqAffine> {
    use sha2::{Digest, Sha256};
    if let Ok(bytes) = std::fs::read(path) {
        if hex::encode(Sha256::digest(&bytes)) == PARAMS_SHA256 {
            if let Ok(p) = Params::read(&mut &bytes[..]) {
                return p;
            }
        }
    }
    let p = params();
    let mut bytes = Vec::new();
    p.write(&mut bytes).expect("serialize params");
    if hex::encode(Sha256::digest(&bytes)) != PARAMS_SHA256 {
        eprintln!(
            "[pcp-zk] note: generated params hash {} differs from the pinned {}",
            hex::encode(Sha256::digest(&bytes)),
            PARAMS_SHA256
        );
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, &bytes);
    p
}

/// Default cache location: `$PCP_ZK_PARAMS`, else `target/params-k17.bin`
/// inside this crate's directory.
pub fn default_params_path() -> std::path::PathBuf {
    if let Some(p) = std::env::var_os("PCP_ZK_PARAMS") {
        return p.into();
    }
    std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/target/params-k13.bin"))
}

/// The verifying key, computed by the verifier itself from the circuit
/// definition (never received from the seller).
pub fn verifying_key(params: &Params<EqAffine>) -> VerifyingKey<EqAffine> {
    keygen_vk(params, &SaleCircuit::default()).expect("keygen_vk")
}

/// A human-comparable identity for the verifying key: SHA-256 over
/// `"pcp-zk/vk-fingerprint/v0" || len || format!("{:?}", vk.pinned())`.
/// `pinned()` is the representation halo2 itself hashes into the transcript
/// (`transcript_repr`), so it covers the domain, the constraint system, the
/// fixed commitments and the permutation. A proof already fails against a
/// different key; this lets a person check WHICH circuit they are verifying
/// against, e.g. that the source they built is the one a bundle names.
pub fn vk_fingerprint(vk: &VerifyingKey<EqAffine>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let s = format!("{:?}", vk.pinned());
    let mut h = Sha256::new();
    h.update(b"pcp-zk/vk-fingerprint/v0");
    h.update((s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
    h.finalize().into()
}

pub fn proving_key(params: &Params<EqAffine>, vk: VerifyingKey<EqAffine>) -> ProvingKey<EqAffine> {
    keygen_pk(params, vk, &SaleCircuit::default()).expect("keygen_pk")
}

/// Number of blinding rows halo2 reserves at the end of every advice column.
/// halo2_proofs 0.3 has no switch for zero knowledge: every advice column
/// (and the permutation and lookup columns) gets this many uniformly random
/// rows from the prover's RNG, and the vanishing argument adds a random
/// polynomial. This function lets code and tests assert it is non-zero.
pub fn blinding_rows() -> usize {
    let mut cs = ConstraintSystem::<Fp>::default();
    <SaleCircuit as halo2_proofs::plonk::Circuit<Fp>>::configure(&mut cs);
    cs.blinding_factors()
}

#[derive(Debug)]
pub enum ProveError {
    /// The seller's own witness fails the statement (checked in the clear
    /// first; an honest prover refuses).
    InvalidWitness(&'static str),
    Halo2(halo2_proofs::plonk::Error),
}

/// Seller side, the normal entry point: draws a fresh 32-byte `k` from the OS
/// CSPRNG (so `k`, and with it the keystream, is never reused across offers),
/// computes `C` and `H`, and proves the statement. Returns the proof, the
/// public inputs and `k`, which the seller keeps until the payment settles.
pub fn sell(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    givens: &[u8; CELLS],
    solution: &[u8; CELLS],
    binding: &[u8; 32],
) -> Result<(Vec<u8>, PublicInputs, [u8; 32]), ProveError> {
    let mut key = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut key);
    let (proof, public) = prove_with_key(params, pk, givens, solution, &key, binding)?;
    Ok((proof, public, key))
}

/// Like [`sell`] with a caller-chosen `k`. For tests and conformance vectors
/// only: a seller MUST NOT reuse `k` (see README, "Kunci baru per penawaran").
/// Randomness for blinding comes from the OS CSPRNG.
pub fn prove_with_key(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    givens: &[u8; CELLS],
    solution: &[u8; CELLS],
    key: &[u8; 32],
    binding: &[u8; 32],
) -> Result<(Vec<u8>, PublicInputs), ProveError> {
    if !suite::sudoku_valid(givens, solution) {
        return Err(ProveError::InvalidWitness("solution does not solve the puzzle"));
    }
    let public = PublicInputs {
        givens: *givens,
        ciphertext: suite::encrypt(solution, key),
        payment_hash: suite::payment_hash(key),
        binding: *binding,
    };
    let proof = prove_unchecked(params, pk, &public, SaleCircuit::new(*solution, *key), OsRng)
        .map_err(ProveError::Halo2)?;
    Ok((proof, public))
}

/// Run the halo2 prover without any native check (used by tests to show that
/// a false statement yields a proof that does not verify).
pub fn prove_unchecked<R: rand_core::RngCore>(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    public: &PublicInputs,
    circuit: SaleCircuit,
    rng: R,
) -> Result<Vec<u8>, halo2_proofs::plonk::Error> {
    assert!(blinding_rows() > 0, "zero knowledge requires blinding rows");
    let instance = public.instance();
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        params,
        pk,
        &[circuit],
        &[&[&instance[..]]],
        rng,
        &mut transcript,
    )?;
    Ok(transcript.finalize())
}

/// Buyer side: accept iff the proof verifies against the buyer's own public
/// inputs and the verifier-computed key.
pub fn verify(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    public: &PublicInputs,
    proof: &[u8],
) -> bool {
    if public.check_shape().is_err() {
        return false;
    }
    let instance = public.instance();
    let strategy = SingleVerifier::new(params);
    let mut rest: &[u8] = proof;
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&mut rest);
    let ok = verify_proof(params, vk, strategy, &[&[&instance[..]]], &mut transcript).is_ok();
    drop(transcript);
    // Reject trailing bytes: the proof is exactly what the verifier read.
    ok && rest.is_empty()
}

/// Peak resident memory of this process so far, in KiB (Linux `VmHWM`).
pub fn peak_rss_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find(|l| l.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}
