//! Canonical encoding (SPEC.md section 3).
//!
//! Every identifier and commitment in PCP/0 is a *tagged hash* over a
//! length-prefixed list of fields. JSON is only the transport; hashes are
//! never computed over JSON text.
//!
//! ```text
//! lp(x)                = u32_be(len(x)) || x
//! tagged_hash(t, f..)  = SHA256( lp("PCP/0/" || t) || lp(f1) || lp(f2) || ... )
//! u64 field            = 8 bytes big-endian
//! string field         = UTF-8 bytes
//! hash field           = 32 raw bytes
//! ```
//!
//! The one exception is the Lightning payment hash `H = SHA256(k)`, which is
//! plain SHA-256 so that any BOLT11 node can use it unchanged.

use alloc::{format, vec::Vec};

use sha2::{Digest, Sha256};

/// Protocol version string carried in every message.
pub const VERSION: &str = "PCP/0";

/// A 32-byte hash.
pub type Hash32 = [u8; 32];

/// Length-prefix a field (u32 big-endian length, then the bytes).
pub fn lp(out: &mut Vec<u8>, field: &[u8]) {
    let len: u32 = field
        .len()
        .try_into()
        .expect("PCP/0 fields are limited to u32::MAX bytes");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
}

/// Canonical byte string for a tag and a list of fields (the hash pre-image).
pub fn canonical_bytes(tag: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    let full_tag = format!("{VERSION}/{tag}");
    lp(&mut out, full_tag.as_bytes());
    for f in fields {
        lp(&mut out, f);
    }
    out
}

/// Domain-separated hash over length-prefixed fields.
pub fn tagged_hash(tag: &str, fields: &[&[u8]]) -> Hash32 {
    sha256(&canonical_bytes(tag, fields))
}

/// Plain SHA-256.
pub fn sha256(data: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// u64 as 8 bytes big-endian.
pub fn u64_be(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}

/// Serde helper: `[u8; 32]` as lowercase hex.
#[cfg(feature = "std")]
pub mod hex32 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 || s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(D::Error::custom("expected 64 lowercase hex characters"));
        }
        let v = hex::decode(&s).map_err(D::Error::custom)?;
        v.try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

/// Serde helper: `Vec<u8>` as lowercase hex.
#[cfg(feature = "std")]
pub mod hexbytes {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(D::Error::custom("expected lowercase hex"));
        }
        hex::decode(&s).map_err(D::Error::custom)
    }
}

/// Serde helper: `Vec<[u8; 32]>` as a list of lowercase hex strings.
#[cfg(feature = "std")]
pub mod hex32vec {
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        v.iter().map(hex::encode).collect::<Vec<_>>().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        v.iter()
            .map(|s| {
                if s.len() != 64 || s.chars().any(|c| c.is_ascii_uppercase()) {
                    return Err(D::Error::custom("expected 64 lowercase hex characters"));
                }
                let b = hex::decode(s).map_err(D::Error::custom)?;
                b.try_into()
                    .map_err(|_| D::Error::custom("expected 32 bytes"))
            })
            .collect()
    }
}

/// Serde helper: `Option<[u8; 32]>` as lowercase hex or `null`.
#[cfg(feature = "std")]
pub mod hex32opt {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(h) => s.serialize_some(&hex::encode(h)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let Some(s) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        if s.len() != 64 || s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(D::Error::custom("expected 64 lowercase hex characters"));
        }
        let v = hex::decode(&s).map_err(D::Error::custom)?;
        v.try_into()
            .map(Some)
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_prevents_concatenation_ambiguity() {
        assert_ne!(
            tagged_hash("t", &[b"ab", b"c"]),
            tagged_hash("t", &[b"a", b"bc"])
        );
        assert_ne!(tagged_hash("t1", &[b"x"]), tagged_hash("t2", &[b"x"]));
    }
}
