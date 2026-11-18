//! A receipt made by risc0-zkvm 3.0.6 must be refused by this verifier
//! (risc0-zkvm 3.1.0), cleanly. Upstream 3.1.0 regenerated the recursion and
//! rv32im circuits, so the two versions have different verifier parameters;
//! a buyer must never accept a proof of the older circuits.
//!
//! The fixture is a genuine succinct receipt from CI (real-sale, October
//! 2026) for the 3.0.6 guest `cc6e7b82…e328`. It was valid under 3.0.6.

const OLD_IMAGE_ID: &str = "cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328";
const OLD_RECEIPT: &[u8] = include_bytes!("data/receipt-3.0.6-cc6e7b82.bin");

#[test]
fn a_receipt_of_risc0_3_0_6_is_refused() {
    // The layout did not change, so it still decodes.
    let receipt = pcp_risc0_verify::decode_receipt(OLD_RECEIPT).expect("decodes");
    let image_id = pcp_risc0_verify::parse_image_id(OLD_IMAGE_ID).expect("hex");
    // Even against the image id it was made for, verification fails, and the
    // reason is the verifier parameters, not the claim.
    let err = receipt.verify(image_id).expect_err("an old-circuit receipt must not verify");
    let text = err.to_string();
    assert!(
        text.contains("version of the verifier"),
        "expected a verifier-parameters mismatch, got: {text}"
    );
}
