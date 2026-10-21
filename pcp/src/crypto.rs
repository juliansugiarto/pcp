//! The encryption scheme `chacha20poly1305-k/0` (SPEC.md section 4).
//!
//! ```text
//! k          32 random bytes, fresh for every proof bundle, never reused
//! H          SHA256(k)                                   (Lightning payment hash)
//! enc_key    tagged_hash("enc-key", [k])
//! nonce      12 zero bytes (safe only because enc_key is single-use)
//! aad        tagged_hash("enc-aad", [offer_id])
//! C          ChaCha20-Poly1305(enc_key, nonce, R, aad)   (ciphertext || 16-byte tag)
//! ```
//!
//! Encryption is deterministic given (k, R, offer_id), so a verifier holding
//! the witness can recompute C exactly. That is what lets a proof backend
//! check the relation `C = Enc_k(R)`.

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
#[cfg(feature = "std")]
use rand::{CryptoRng, RngCore};

use crate::encoding::{sha256, tagged_hash, Hash32};

/// Identifier of the encryption scheme, carried in offers.
pub const ENC_SCHEME: &str = "chacha20poly1305-k/0";

/// Draw a fresh 32-byte key `k` (the Lightning preimage). Not available
/// without `std`: the statement core never draws randomness.
#[cfg(feature = "std")]
pub fn fresh_key<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    k
}

/// `H = SHA256(k)`. Plain SHA-256, as BOLT11 requires.
pub fn payment_hash(k: &[u8; 32]) -> Hash32 {
    sha256(k)
}

fn cipher(k: &[u8; 32]) -> ChaCha20Poly1305 {
    let enc_key = tagged_hash("enc-key", &[k]);
    ChaCha20Poly1305::new(Key::from_slice(&enc_key))
}

fn aad(offer_id: &Hash32) -> Hash32 {
    tagged_hash("enc-aad", &[offer_id])
}

/// `C = Enc_k(R)` bound to `offer_id`.
pub fn encrypt(k: &[u8; 32], offer_id: &Hash32, result: &[u8]) -> Vec<u8> {
    let aad = aad(offer_id);
    cipher(k)
        .encrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: result,
                aad: &aad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption does not fail for in-memory buffers")
}

/// Decrypt `C` with `k`. Fails if the key, the offer binding or the
/// ciphertext is wrong.
pub fn decrypt(k: &[u8; 32], offer_id: &Hash32, ciphertext: &[u8]) -> Option<Vec<u8>> {
    let aad = aad(offer_id);
    cipher(k)
        .decrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .ok()
}

/// `tagged_hash("ciphertext", [C])`, carried in the statement.
pub fn ciphertext_hash(ciphertext: &[u8]) -> Hash32 {
    tagged_hash("ciphertext", &[ciphertext])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_binding() {
        let k = [7u8; 32];
        let offer = [1u8; 32];
        let c = encrypt(&k, &offer, b"hello");
        assert_eq!(c, encrypt(&k, &offer, b"hello"), "deterministic");
        assert_eq!(decrypt(&k, &offer, &c).unwrap(), b"hello");
        assert!(decrypt(&[8u8; 32], &offer, &c).is_none(), "wrong key");
        assert!(decrypt(&k, &[2u8; 32], &c).is_none(), "wrong offer binding");
    }
}
