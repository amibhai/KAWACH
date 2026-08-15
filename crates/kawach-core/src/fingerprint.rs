//! Non-invertible identifiers for secret values (DESIGN.md **I3**).
//!
//! A finding records *where* a secret is, never *what* it is. To answer the questions
//! that make discovery useful — "is the value in this `.env` the same one that is in
//! Vault?", "is this Vault secret referenced by anything?" — we need a stable identity
//! for a value that is not the value.
//!
//! ```text
//! fingerprint = truncate_128( HMAC-SHA256(K_install, "kawach/fp/v1" ‖ value) )
//! ```
//!
//! **Why HMAC and not a bare hash.** A bare SHA-256 of `changeme123` is reversible by
//! anyone with a wordlist. Keying with an installation-scoped secret means an
//! adversary needs both the findings database *and* the separately stored key before a
//! dictionary attack is even possible.
//!
//! **Why no plaintext prefix.** Many scanners store the first four characters "for
//! identification". Four characters of an AWS access key ID is a meaningful reduction
//! of the search space and a gift to whoever steals the findings database. KAWACH
//! stores zero plaintext characters.

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{KawachError, Result};
use crate::hex;
use crate::rng;

type HmacSha256 = Hmac<Sha256>;

const FINGERPRINT_DOMAIN: &[u8] = b"kawach/fp/v1";
const FINGERPRINT_LEN: usize = 16;

/// Installation-scoped HMAC key for fingerprinting.
///
/// Stored outside the findings database, mode `0600`. Zeroized on drop. Deliberately
/// not derivable from anything else: two KAWACH installations produce unrelated
/// fingerprints for the same value, which limits the damage of a leaked database
/// (cross-installation correlation is not a capability we need).
pub struct FingerprintKey(Zeroizing<[u8; 32]>);

impl FingerprintKey {
    /// Generate a fresh key from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rng::fill(&mut k);
        Self(Zeroizing::new(k))
    }

    /// Load a key from its 64-character hex encoding.
    ///
    /// # Errors
    /// [`KawachError::MalformedFingerprintKey`] if the input is not 32 bytes of hex.
    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s.trim()).ok_or(KawachError::MalformedFingerprintKey)?;
        let arr: [u8; 32] = raw.try_into().map_err(|_| KawachError::MalformedFingerprintKey)?;
        Ok(Self(Zeroizing::new(arr)))
    }

    /// Hex encoding, for writing the key file.
    ///
    /// This is the one place key material is rendered as text. It is not `Display`,
    /// so it cannot be reached by accident from a format string.
    #[must_use]
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0.as_slice()))
    }

    /// Compute the fingerprint of `value`.
    #[must_use]
    pub fn fingerprint(&self, value: &[u8]) -> Fingerprint {
        let mut mac = HmacSha256::new_from_slice(self.0.as_slice())
            .expect("HMAC-SHA256 accepts keys of any length");
        mac.update(FINGERPRINT_DOMAIN);
        mac.update(value);
        let full = mac.finalize().into_bytes();
        let mut out = [0u8; FINGERPRINT_LEN];
        out.copy_from_slice(&full[..FINGERPRINT_LEN]);
        Fingerprint(out)
    }
}

impl fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FingerprintKey([REDACTED])")
    }
}

/// A 128-bit truncated keyed hash of a secret value: safe to persist, log, and compare.
///
/// 128 bits is chosen for collision resistance at estate scale: a birthday collision
/// requires ~2^64 distinct secrets, which no real environment approaches.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

impl Fingerprint {
    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }

    /// Short form for human-facing tables. Still non-invertible: it is a prefix of a
    /// keyed hash, not of the secret.
    #[must_use]
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.short())
    }
}

impl serde::Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let raw = hex::decode(&s).ok_or_else(|| serde::de::Error::custom("malformed fingerprint"))?;
        let arr: [u8; FINGERPRINT_LEN] = raw
            .try_into()
            .map_err(|_| serde::de::Error::custom("fingerprint must be 16 bytes"))?;
        Ok(Self(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;

    #[test]
    fn same_value_same_fingerprint_under_one_key() {
        let key = FingerprintKey::generate();
        let a = SecretString::from_string("shared-db-password".into());
        let b = SecretString::from_string("shared-db-password".into());
        assert_eq!(a.fingerprint(&key), b.fingerprint(&key));
    }

    #[test]
    fn different_installations_do_not_correlate() {
        let (k1, k2) = (FingerprintKey::generate(), FingerprintKey::generate());
        let v = SecretString::from_string("shared-db-password".into());
        assert_ne!(v.fingerprint(&k1), v.fingerprint(&k2));
    }

    #[test]
    fn fingerprint_leaks_no_plaintext_in_any_rendering() {
        let key = FingerprintKey::generate();
        let secret = SecretString::from_string("canary-plaintext-value".into());
        let fp = secret.fingerprint(&key);
        for rendering in [format!("{fp}"), format!("{fp:?}"), fp.short(), serde_json::to_string(&fp).unwrap()] {
            assert!(!rendering.contains("canary"));
            assert!(!rendering.contains("plaintext"));
        }
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = FingerprintKey::generate();
        let hexed = key.to_hex();
        assert!(!format!("{key:?}").contains(hexed.as_str()));
    }

    #[test]
    fn key_round_trips_through_hex() {
        let key = FingerprintKey::generate();
        let restored = FingerprintKey::from_hex(&key.to_hex()).unwrap();
        let v = SecretString::from_string("v".into());
        assert_eq!(v.fingerprint(&key), v.fingerprint(&restored));
    }

    #[test]
    fn malformed_keys_are_rejected() {
        assert!(FingerprintKey::from_hex("not-hex").is_err());
        assert!(FingerprintKey::from_hex("aabb").is_err());
    }

    #[test]
    fn fingerprint_serde_round_trips() {
        let key = FingerprintKey::generate();
        let fp = SecretString::from_string("x".into()).fingerprint(&key);
        let json = serde_json::to_string(&fp).unwrap();
        assert_eq!(serde_json::from_str::<Fingerprint>(&json).unwrap(), fp);
    }
}
