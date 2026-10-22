//! Verify-only RISC Zero backend for PCP/0.
//!
//! A buyer needs to check a receipt, not to make one. This crate verifies
//! succinct receipts of the PCP/0 guest against a pinned image id, with
//! `risc0-zkvm` built without its `client`, `prove` and `bonsai` features:
//! no guest build, no RISC Zero toolchain (rzup), no Docker, no prover.
//!
//! The image id is pinned in [`PINNED_IMAGE_ID`]. It is the id of the guest
//! built reproducibly in Docker (see `../IMAGE-ID.md`); anyone can rebuild
//! the guest and compare. A seller whose offer names another guest is
//! refused before anything is proven (`backend_not_accepted`).
//!
//! The prover (`pcp-risc0-host`) uses [`verify_receipt`] too, so both sides
//! run the same checks.

use pcp::job::JobClass;
use pcp::proof::{
    check_bundle_public, ProofBackend, ProofBundle, ProveError, Statement, VerifyError, Witness,
};
use pcp::statement::Journal;
use risc0_zkvm::{
    Digest, InnerReceipt, Journal as R0Journal, Receipt, ReceiptClaim, ReceiptMetadata,
    SuccinctReceipt, VerifierContext,
};
use serde::de::IgnoredAny;
use serde::Deserialize;

/// Image id of the PCP/0 guest, built reproducibly in Docker (builder
/// `r0.1.97.0`, risc0-zkvm 3.0.6). See `../IMAGE-ID.md`. CI checks that the
/// guest it builds has this id.
pub const PINNED_IMAGE_ID: &str =
    "cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328";

/// Largest receipt deserialised (a succinct receipt is about 224 KB).
pub const MAX_RECEIPT_BYTES: usize = 512 * 1024;

/// Depth of RISC Zero's tree of allowed recursion programs
/// (`ALLOWED_CODE_MERKLE_DEPTH` in risc0-zkvm 3.0.6, not exported). Every
/// honest inclusion proof has exactly this many digests.
pub const CONTROL_TREE_DEPTH: usize = 8;

/// `risc0_zkvm::Receipt` as it is serialised, with only the succinct inner
/// receipt allowed. Deserialising `Receipt` itself would accept a
/// composite receipt, which nests (`CompositeReceipt` holds assumption
/// receipts that can be composite again): bincode has no depth limit, and
/// a 200 KB blob nested 10,000 deep overflows the stack and kills the
/// buyer. Here the other variants are `IgnoredAny`, which bincode refuses
/// at once. The variants are in `InnerReceipt`'s order (bincode encodes
/// the index).
#[derive(Deserialize)]
enum SuccinctOnly {
    #[allow(dead_code)]
    Composite(IgnoredAny),
    Succinct(Box<SuccinctReceipt<ReceiptClaim>>),
    #[allow(dead_code)]
    Groth16(IgnoredAny),
    #[allow(dead_code)]
    Fake(IgnoredAny),
}

#[derive(Deserialize)]
struct WireReceipt {
    inner: SuccinctOnly,
    journal: R0Journal,
    // Not bound to the proof; `Receipt::new` recomputes it.
    #[allow(dead_code)]
    metadata: ReceiptMetadata,
}

/// Decode a receipt from an untrusted seller: at most
/// [`MAX_RECEIPT_BYTES`], succinct (one STARK) only. Composite receipts
/// (unbounded nesting), Groth16 receipts (a trusted setup, SPEC T9) and
/// fake receipts are refused before any verification.
pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt, VerifyError> {
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(VerifyError::ProofMalformed);
    }
    let w: WireReceipt = bincode::deserialize(bytes).map_err(|_| VerifyError::ProofMalformed)?;
    match w.inner {
        SuccinctOnly::Succinct(s) => {
            // The verifier hashes one pair per digest (up to about 16 K in
            // 512 KiB) and never reads index bits past the depth, so a
            // longer path or a larger index is refused here (Fable, note 22).
            let p = &s.control_inclusion_proof;
            if p.digests.len() != CONTROL_TREE_DEPTH || p.index >= 1 << CONTROL_TREE_DEPTH {
                return Err(VerifyError::ProofMalformed);
            }
            Ok(Receipt::new(InnerReceipt::Succinct(*s), w.journal.bytes))
        }
        _ => Err(VerifyError::ProofMalformed),
    }
}

/// `risc0-zkvm-3-succinct/<image id hex>`: what an offer names.
pub fn backend_id_for(image_id: &Digest) -> String {
    format!("risc0-zkvm-3-succinct/{}", hex::encode(image_id.as_bytes()))
}

/// Parse a 64-hex-character image id.
pub fn parse_image_id(hex_id: &str) -> Option<Digest> {
    let b = hex::decode(hex_id).ok()?;
    let a: [u8; 32] = b.try_into().ok()?;
    Some(Digest::from(a))
}

/// The checks of SPEC 9 for a RISC Zero bundle: public fields, a succinct
/// receipt of bounded size ([`decode_receipt`]), valid for `image_id` with
/// dev mode off and exit code 0 (`verify_with_context` checks
/// `ReceiptClaim::ok(image_id, journal digest)`), journal equal to the
/// buyer's own expected statement.
pub fn verify_receipt(
    image_id: Digest,
    backend_id: &str,
    job: &dyn JobClass,
    statement: &Statement,
    bundle: &ProofBundle,
) -> Result<(), VerifyError> {
    check_bundle_public(backend_id, job, statement, bundle)?;
    let receipt = decode_receipt(&bundle.proof)?;
    let ctx = VerifierContext::default().with_dev_mode(false);
    receipt
        .verify_with_context(&ctx, image_id)
        .map_err(|_| VerifyError::ReceiptInvalid)?;
    let journal = Journal::from_bytes(&receipt.journal.bytes).ok_or(VerifyError::ProofMalformed)?;
    journal.check_expected(&statement.journal())?;
    Ok(())
}

/// A [`ProofBackend`] that verifies and never proves.
pub struct Risc0Verifier {
    image_id: Digest,
    backend_id: &'static str,
}

impl Risc0Verifier {
    pub fn new(image_id: Digest) -> Risc0Verifier {
        // backend_id returns &'static str; one small leak per verifier.
        let backend_id: &'static str = Box::leak(backend_id_for(&image_id).into_boxed_str());
        Risc0Verifier {
            image_id,
            backend_id,
        }
    }

    /// Pinned to [`PINNED_IMAGE_ID`].
    pub fn pinned() -> Risc0Verifier {
        Risc0Verifier::new(parse_image_id(PINNED_IMAGE_ID).expect("pinned id is 32 bytes of hex"))
    }
}

impl ProofBackend for Risc0Verifier {
    fn backend_id(&self) -> &'static str {
        self.backend_id
    }

    fn is_secure(&self) -> bool {
        true
    }

    fn prove(
        &self,
        _job: &dyn JobClass,
        _statement: &Statement,
        _ciphertext: &[u8],
        _witness: &Witness,
    ) -> Result<ProofBundle, ProveError> {
        Err(ProveError::Backend(
            "verify-only build: this backend cannot prove".into(),
        ))
    }

    fn verify(
        &self,
        job: &dyn JobClass,
        statement: &Statement,
        bundle: &ProofBundle,
    ) -> Result<(), VerifyError> {
        verify_receipt(self.image_id, self.backend_id, job, statement, bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_id_parses_and_names_the_backend() {
        let v = Risc0Verifier::pinned();
        assert_eq!(
            v.backend_id(),
            format!("risc0-zkvm-3-succinct/{PINNED_IMAGE_ID}")
        );
        assert!(parse_image_id("00").is_none());
        assert!(parse_image_id(&"zz".repeat(32)).is_none());
    }

    /// A composite receipt whose assumption is a composite receipt, and so
    /// on, `depth` deep, in bincode's layout: variant 0 (u32), segments
    /// (empty Vec, u64 length), assumption_receipts (Vec of one, u64).
    fn nested_composite(depth: usize) -> Vec<u8> {
        let mut b = Vec::new();
        for _ in 0..depth {
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&0u64.to_le_bytes());
            b.extend_from_slice(&1u64.to_le_bytes());
        }
        b
    }

    #[test]
    fn a_deeply_nested_composite_receipt_is_refused_without_recursing() {
        // 200,000 bytes, 10,000 levels: overflows the stack when decoded as
        // risc0_zkvm::Receipt (checked once by hand: process aborts).
        let blob = nested_composite(10_000);
        assert!(blob.len() < MAX_RECEIPT_BYTES);
        assert!(matches!(
            decode_receipt(&blob),
            Err(VerifyError::ProofMalformed)
        ));
    }

    #[test]
    fn only_succinct_receipts_decode() {
        for variant in [0u32, 2, 3, 4] {
            let mut b = variant.to_le_bytes().to_vec();
            b.extend_from_slice(&[0u8; 64]);
            assert!(decode_receipt(&b).is_err(), "variant {variant}");
        }
        assert!(decode_receipt(&vec![0u8; MAX_RECEIPT_BYTES + 1]).is_err());
    }
}
