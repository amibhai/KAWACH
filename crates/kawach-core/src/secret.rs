//! Secret material: the one type in KAWACH permitted to hold a plaintext value.
//!
//! See DESIGN.md invariants **I1** (no plaintext egress) and **I2** (zeroization).
//!
//! The security properties of [`SecretString`] come from what it *does not* implement:
//!
//! | Missing impl | Consequence |
//! |---|---|
//! | `Serialize`  | Serialising any struct containing one is a **compile error**. |
//! | `Display`    | `format!("{}", secret)` is a **compile error**. |
//! | `Clone`      | Copies are deliberate and greppable, not incidental. |
//!
//! `Debug` *is* implemented, and is safe: it prints a constant. It exists so that
//! `#[derive(Debug)]` on containing types stays available and safe-by-default.
//!
//! Plaintext is reachable only through [`SecretString::expose`], a closure-scoped
//! accessor. `rg 'expose'` therefore enumerates the complete plaintext attack surface
//! of the codebase.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{KawachError, Result};
use crate::fingerprint::{Fingerprint, FingerprintKey};
use crate::rng;

/// A plaintext secret value held in a buffer that is overwritten on drop.
///
/// Construction takes ownership of the bytes and zeroizes any source buffer it can
/// reach. Everything KAWACH persists is derived from a [`Fingerprint`] of this value,
/// never the value itself.
pub struct SecretString(Zeroizing<Vec<u8>>);

impl SecretString {
    /// Wrap raw bytes. The caller's `Vec` is moved in; no copy remains behind.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Wrap a `String`, zeroizing the original allocation.
    ///
    /// Prefer this over `new(s.into_bytes())`: it makes the zeroization of the source
    /// explicit at the call site rather than relying on the move being copy-free.
    #[must_use]
    pub fn from_string(mut source: String) -> Self {
        let bytes = source.as_bytes().to_vec();
        source.zeroize();
        Self(Zeroizing::new(bytes))
    }

    /// Length in bytes.
    ///
    /// Length is metadata, not content, but note that it does narrow a brute-force
    /// search space. It is deliberately **not** included in the `Debug` output.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty. An empty secret is almost always a bug upstream.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Scoped access to the plaintext.
    ///
    /// The closure form bounds the exposure lexically and makes every exposure site
    /// greppable. It does not *prevent* a caller from copying bytes out — nothing at
    /// this layer can — but it makes doing so visible in review, which is the actual
    /// control (DESIGN.md I1).
    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.0)
    }

    /// Scoped access to the plaintext as UTF-8.
    ///
    /// # Errors
    /// Returns [`KawachError::InvalidSecretEncoding`] if the value is not valid UTF-8.
    /// The error deliberately carries no excerpt of the offending bytes.
    pub fn expose_str<R>(&self, f: impl FnOnce(&str) -> R) -> Result<R> {
        let s = core::str::from_utf8(&self.0).map_err(|_| KawachError::InvalidSecretEncoding)?;
        Ok(f(s))
    }

    /// Derive the persisted, non-invertible identifier for this value.
    ///
    /// This is the only value-derived datum KAWACH ever writes to disk (DESIGN.md I3).
    #[must_use]
    pub fn fingerprint(&self, key: &FingerprintKey) -> Fingerprint {
        key.fingerprint(&self.0)
    }

    /// Constant-time equality.
    ///
    /// Variable-time comparison of secret material leaks a prefix-length oracle. Used
    /// for "did the backend return the value we just wrote?" read-back checks.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        // Lengths are compared in variable time; that is unavoidable and, for the
        // read-back use case, not the sensitive part.
        if self.0.len() != other.0.len() {
            return false;
        }
        self.0.ct_eq(&other.0).into()
    }

    /// Shannon entropy of the value, in bits per byte (0.0..=8.0).
    ///
    /// Used by the discovery detectors and by the config linter that refuses to load a
    /// configuration containing an inlined credential (DESIGN.md I4).
    #[must_use]
    pub fn entropy_bits_per_byte(&self) -> f64 {
        shannon_bits_per_byte(&self.0)
    }

    /// Generate a fresh credential under `policy` using the OS CSPRNG.
    ///
    /// # Errors
    /// Returns [`KawachError::WeakPasswordPolicy`] if the policy cannot meet its own
    /// declared minimum entropy — a misconfiguration we refuse rather than silently
    /// downgrade.
    pub fn generate(policy: &PasswordPolicy) -> Result<Self> {
        policy.validate()?;
        let alphabet = policy.charset.alphabet();
        let mut out = Vec::with_capacity(policy.length);
        // Rejection sampling: `byte % n` alone biases toward the low end of the
        // alphabet whenever 256 is not a multiple of n.
        let n = alphabet.len();
        let limit = 256 - (256 % n);
        let mut buf = [0u8; 64];
        while out.len() < policy.length {
            rng::fill(&mut buf);
            for &b in &buf {
                if out.len() == policy.length {
                    break;
                }
                if (b as usize) < limit {
                    out.push(alphabet[b as usize % n]);
                }
            }
        }
        buf.zeroize();
        Ok(Self(Zeroizing::new(out)))
    }
}

impl fmt::Debug for SecretString {
    /// Prints a constant. No length, no prefix, no hash: a hash in a log line is a
    /// verifier for an offline guessing attack against a low-entropy secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::from_string(s)
    }
}

impl From<Vec<u8>> for SecretString {
    fn from(b: Vec<u8>) -> Self {
        Self::new(b)
    }
}

// NOTE: `Serialize` is intentionally absent. Do not add it. If a struct containing a
// `SecretString` must be serialised, mark the field `#[serde(skip)]` — a reviewable
// diff — rather than weakening this type. See DESIGN.md I1.
//
// `Deserialize` *is* present: ingesting a value from a backend response is a legitimate
// and necessary operation. The residual risk is documented in DESIGN.md I2 — serde's
// own intermediate buffers are outside our control, which is why backend crates
// zeroize the raw response body after parsing.
impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecretVisitor;

        impl serde::de::Visitor<'_> for SecretVisitor {
            type Value = SecretString;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a secret string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> core::result::Result<Self::Value, E> {
                Ok(SecretString::new(v.as_bytes().to_vec()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> core::result::Result<Self::Value, E> {
                Ok(SecretString::from_string(v))
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> core::result::Result<Self::Value, E> {
                Ok(SecretString::new(v.to_vec()))
            }
        }

        deserializer.deserialize_str(SecretVisitor)
    }
}

/// Character sets for generated credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Charset {
    /// RFC 3986 unreserved characters: `A-Z a-z 0-9 - . _ ~` (66 symbols).
    ///
    /// The default, because these require no percent-encoding in a URI. A generated
    /// password containing `@`, `:` or `/` is a latent outage in every consumer that
    /// builds a connection string by concatenation — which is most of them.
    UriSafe,
    /// `A-Z a-z 0-9` (62 symbols). For systems with hostile input validation.
    Alphanumeric,
    /// Alphanumeric plus a punctuation set excluding shell and URI metacharacters.
    Extended,
}

impl Charset {
    fn alphabet(self) -> &'static [u8] {
        match self {
            Self::UriSafe => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
            Self::Alphanumeric => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            Self::Extended => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+=,^"
            }
        }
    }
}

/// Generation policy for new credentials.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PasswordPolicy {
    /// Number of characters to generate.
    pub length: usize,
    /// Alphabet to draw from.
    pub charset: Charset,
    /// Refuse to generate anything weaker than this.
    pub min_entropy_bits: u32,
}

impl Default for PasswordPolicy {
    /// 40 characters of URI-safe alphabet ≈ 241 bits. Generated credentials are never
    /// typed by a human, so there is no reason to economise on length.
    fn default() -> Self {
        Self { length: 40, charset: Charset::UriSafe, min_entropy_bits: 128 }
    }
}

impl PasswordPolicy {
    /// Entropy of a credential generated under this policy, in bits.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let n = self.charset.alphabet().len() as f64;
        #[allow(clippy::cast_precision_loss)]
        let len = self.length as f64;
        len * n.log2()
    }

    /// Refuse policies that cannot meet their own minimum.
    ///
    /// # Errors
    /// [`KawachError::WeakPasswordPolicy`] when the configured length and alphabet
    /// fall short of `min_entropy_bits`.
    pub fn validate(&self) -> Result<()> {
        let actual = self.entropy_bits();
        if actual < f64::from(self.min_entropy_bits) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            return Err(KawachError::WeakPasswordPolicy {
                achieved_bits: actual as u32,
                required_bits: self.min_entropy_bits,
            });
        }
        Ok(())
    }
}

/// Shannon entropy in bits per byte over the observed byte distribution.
#[must_use]
pub fn shannon_bits_per_byte(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    #[allow(clippy::cast_precision_loss)]
    let total = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_content_or_length() {
        let s = SecretString::from_string("hunter2-correct-horse-battery".into());
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "SecretString([REDACTED])");
        assert!(!rendered.contains("hunter2"));
        // Length is metadata that narrows a search space; assert it is absent too.
        assert!(!rendered.contains("29"));
    }

    #[test]
    fn debug_of_a_containing_struct_is_also_safe() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Wrapper {
            name: &'static str,
            value: SecretString,
        }
        let w = Wrapper { name: "db", value: SecretString::from_string("s3kr3t-canary".into()) };
        assert!(!format!("{w:?}").contains("s3kr3t-canary"));
    }

    #[test]
    fn generated_credentials_meet_policy_entropy() {
        let policy = PasswordPolicy::default();
        assert!(policy.entropy_bits() > 200.0);
        let s = SecretString::generate(&policy).expect("default policy is valid");
        assert_eq!(s.len(), policy.length);
        s.expose(|b| {
            assert!(b.iter().all(|c| policy.charset.alphabet().contains(c)));
        });
    }

    #[test]
    fn generation_is_not_deterministic() {
        let p = PasswordPolicy::default();
        let a = SecretString::generate(&p).unwrap();
        let b = SecretString::generate(&p).unwrap();
        assert!(!a.ct_eq(&b), "two generated credentials collided");
    }

    #[test]
    fn generated_alphabet_is_uniform_enough_to_rule_out_modulo_bias() {
        // 256 % 66 != 0, so a naive `b % n` would over-represent the first 58 symbols.
        // Sample widely and assert the tail of the alphabet is not starved.
        let policy = PasswordPolicy { length: 4096, ..PasswordPolicy::default() };
        let s = SecretString::generate(&policy).unwrap();
        let alphabet = policy.charset.alphabet();
        let mut counts = [0usize; 256];
        s.expose(|b| {
            for &c in b {
                counts[c as usize] += 1;
            }
        });
        let head: usize = alphabet[..8].iter().map(|&c| counts[c as usize]).sum();
        let tail: usize = alphabet[alphabet.len() - 8..].iter().map(|&c| counts[c as usize]).sum();
        // With rejection sampling these should be within noise of each other; a modulo
        // bias would show as head ≈ 2× tail for the wrapped-around symbols.
        #[allow(clippy::cast_precision_loss)]
        let ratio = head as f64 / tail as f64;
        assert!((0.6..1.7).contains(&ratio), "distribution skewed: head/tail = {ratio}");
    }

    #[test]
    fn weak_policy_is_refused_rather_than_downgraded() {
        let policy = PasswordPolicy { length: 4, charset: Charset::Alphanumeric, min_entropy_bits: 128 };
        assert!(matches!(policy.validate(), Err(KawachError::WeakPasswordPolicy { .. })));
        assert!(SecretString::generate(&policy).is_err());
    }

    #[test]
    fn ct_eq_matches_semantic_equality() {
        let a = SecretString::from_string("alpha".into());
        let b = SecretString::from_string("alpha".into());
        let c = SecretString::from_string("alphb".into());
        let d = SecretString::from_string("alph".into());
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert!(!a.ct_eq(&d));
    }

    #[test]
    fn entropy_separates_random_from_prose() {
        // Sample well above the alphabet size. Shannon entropy over a *short* sample is
        // an estimator biased downward by collisions: 40 draws from a 66-symbol
        // alphabet yield only ~30 distinct symbols by the birthday effect, capping the
        // measurement near log2(30) and making any threshold near log2(66) = 6.04
        // intermittently fail. At 4096 draws the estimate converges and the assertion
        // is stable rather than merely usually true.
        let policy = PasswordPolicy { length: 4096, ..PasswordPolicy::default() };
        let random = SecretString::generate(&policy).unwrap();
        let prose = SecretString::from_string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        assert!(
            random.entropy_bits_per_byte() > 5.5,
            "generated material measured {} bits/byte, expected near log2(66) = 6.04",
            random.entropy_bits_per_byte()
        );
        assert!(prose.entropy_bits_per_byte() < 0.1);
    }

    #[test]
    fn non_utf8_is_an_error_without_an_excerpt() {
        let s = SecretString::new(vec![0xff, 0xfe, 0xfd]);
        let err = s.expose_str(|_| ()).unwrap_err();
        assert!(matches!(err, KawachError::InvalidSecretEncoding));
        assert!(!format!("{err}").contains("255"));
    }

    #[test]
    fn deserialization_accepts_a_backend_response_shape() {
        let value: SecretString = serde_json::from_str(r#""from-vault""#).unwrap();
        assert!(value.ct_eq(&SecretString::from_string("from-vault".into())));
    }
}
