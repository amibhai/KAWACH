//! Error types that structurally cannot carry secret material (DESIGN.md **I1**).
//!
//! Error strings are one of the most common leak paths in credential tooling: a
//! backend returns `connection refused: postgres://app:hunter2@db:5432/app`, someone
//! wraps it in `anyhow!`, and the plaintext is now in a log aggregator with a 90-day
//! retention.
//!
//! Two defences here:
//!
//! 1. No variant of [`KawachError`] holds a [`crate::secret::SecretString`], so a leak
//!    via the error type is a compile error, not a review failure.
//! 2. Free-form text from a foreign system is wrapped in [`SafeDetail`], which scrubs
//!    high-entropy tokens at construction time. Belt and braces: the type system stops
//!    *our* secrets, and the scrubber stops secrets we never knew we were holding.

use core::fmt;

use crate::refs::{BackendId, SecretRef, SourceId};
use crate::scope::ScopeDenial;

/// Convenience alias.
pub type Result<T> = core::result::Result<T, KawachError>;

/// The KAWACH error type.
///
/// `#[non_exhaustive]` so that adding a variant is not a breaking change for plugin
/// authors — and so nobody writes an exhaustive match that would need editing to add a
/// new refusal reason.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KawachError {
    /// A reference was not covered by the configured scope allowlist, or was excluded
    /// by a deny rule. This is a refusal, not a failure.
    #[error("out of scope: {reference} ({denial})")]
    OutOfScope {
        /// The reference that was refused.
        reference: SecretRef,
        /// Which rule made the decision.
        denial: ScopeDenial,
    },

    /// A mutating operation was attempted without a [`crate::capability::CommitToken`].
    ///
    /// In practice this is unreachable from safe code — the token is a required
    /// argument — and exists for engines that check the mode before dispatching.
    #[error("refusing to {operation}: dry-run is the default; re-run with --apply")]
    DryRunRefusal {
        /// Human-readable name of the refused operation.
        operation: &'static str,
    },

    /// The configured generation policy cannot meet its own minimum entropy.
    #[error("password policy yields {achieved_bits} bits, below the required {required_bits}")]
    WeakPasswordPolicy {
        /// What the policy actually achieves.
        achieved_bits: u32,
        /// What it declares it requires.
        required_bits: u32,
    },

    /// A secret value was not valid UTF-8 where UTF-8 was required.
    ///
    /// Carries no excerpt of the offending bytes, by design.
    #[error("secret value is not valid UTF-8")]
    InvalidSecretEncoding,

    /// The fingerprint key file was not 32 bytes of hex.
    #[error("fingerprint key is malformed (expected 64 hex characters)")]
    MalformedFingerprintKey,

    /// A secret backend failed.
    #[error("backend {backend} failed during {operation}: {detail}")]
    Backend {
        /// Which backend.
        backend: BackendId,
        /// Which operation.
        operation: &'static str,
        /// Scrubbed detail from the foreign system.
        detail: SafeDetail,
    },

    /// A rotation provider failed.
    #[error("provider {provider} failed during {operation}: {detail}")]
    Provider {
        /// Which provider kind.
        provider: String,
        /// Which operation.
        operation: &'static str,
        /// Scrubbed detail from the foreign system.
        detail: SafeDetail,
    },

    /// A discovery source failed.
    ///
    /// The field is `source_id`, not `source`: `thiserror` reserves a field named
    /// `source` for the underlying [`std::error::Error`] cause, and a chained foreign
    /// error is exactly the unscrubbed text this type exists to keep out.
    #[error("discovery source {source_id} failed: {detail}")]
    Discovery {
        /// Which source.
        source_id: SourceId,
        /// Scrubbed detail.
        detail: SafeDetail,
    },

    /// The audit log could not be written.
    ///
    /// This is always fatal to the operation that triggered it: if we cannot record
    /// what we are about to do, we do not do it (DESIGN.md I5).
    #[error("audit log write failed: {detail}")]
    Audit {
        /// Scrubbed detail.
        detail: SafeDetail,
    },

    /// The rotation journal could not be written or was inconsistent.
    #[error("rotation journal error: {detail}")]
    Journal {
        /// Scrubbed detail.
        detail: SafeDetail,
    },

    /// An event was delivered to the rotation state machine that its current state
    /// does not accept. Always a bug in the engine, never in operator input.
    #[error("illegal rotation transition: {from} does not accept {event}")]
    IllegalTransition {
        /// Current state.
        from: &'static str,
        /// Rejected event.
        event: &'static str,
    },

    /// Configuration was invalid.
    #[error("configuration error at {location}: {detail}")]
    Config {
        /// Where in the configuration.
        location: String,
        /// Scrubbed detail.
        detail: SafeDetail,
    },

    /// KAWACH detected that it holds more privilege than it needs (DESIGN.md I6).
    #[error("refusing to run: {detail}")]
    ExcessivePrivilege {
        /// What was detected.
        detail: SafeDetail,
    },
}

/// Free-form text from a foreign system, scrubbed of anything that looks like a
/// credential.
///
/// Constructing a `SafeDetail` is the *only* way to get third-party text into a
/// [`KawachError`]. The scrubber replaces any token whose Shannon entropy and length
/// suggest secret material, and any `scheme://user:password@host` userinfo component,
/// with a marker.
///
/// This is heuristic and therefore defence in depth, not a primary control. The
/// primary control is that we never put our own secrets here in the first place.
#[derive(Clone, PartialEq, Eq)]
pub struct SafeDetail(String);

/// Tokens at least this long are entropy-screened. Shorter tokens carry too little
/// material to be worth the false-positive rate.
const SCRUB_MIN_LEN: usize = 16;
/// Bits-per-byte above which a long token is assumed to be secret material.
const SCRUB_ENTROPY_THRESHOLD: f64 = 3.5;
/// What replaces a suspicious token.
const SCRUB_MARKER: &str = "[HIGH-ENTROPY-REDACTED]";

impl SafeDetail {
    /// Scrub and wrap a message.
    #[must_use]
    pub fn new(message: impl AsRef<str>) -> Self {
        Self(scrub(message.as_ref()))
    }

    /// Scrub and wrap a foreign error's `Display` output.
    #[must_use]
    pub fn from_error(e: &dyn std::error::Error) -> Self {
        Self::new(e.to_string())
    }

    /// A message the caller guarantees contains no foreign text.
    ///
    /// Use for our own static strings only. Named to be conspicuous in review.
    #[must_use]
    pub fn trusted_static(message: &'static str) -> Self {
        Self(message.to_owned())
    }

    /// The scrubbed text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for SafeDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafeDetail({:?})", self.0)
    }
}

impl serde::Serialize for SafeDetail {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// Replace URI userinfo and high-entropy tokens with a marker.
fn scrub(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut token = String::new();

    let flush = |token: &mut String, out: &mut String| {
        if !token.is_empty() {
            out.push_str(&scrub_token(token));
            token.clear();
        }
    };

    for ch in input.chars() {
        // Token boundary set is deliberately wide: anything that is not plausibly part
        // of a credential ends the token.
        if ch.is_whitespace() || matches!(ch, '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '<' | '>') {
            flush(&mut token, &mut out);
            out.push(ch);
        } else {
            token.push(ch);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// Scrub a single whitespace-delimited token.
fn scrub_token(token: &str) -> String {
    // A URI with userinfo: strip the credential, keep the shape so the message stays
    // diagnostically useful.
    if let Some(scheme_end) = token.find("://") {
        let rest = &token[scheme_end + 3..];
        if let Some(at) = rest.find('@') {
            let userinfo = &rest[..at];
            if let Some(colon) = userinfo.find(':') {
                return format!(
                    "{}://{}:{}@{}",
                    &token[..scheme_end],
                    &userinfo[..colon],
                    SCRUB_MARKER,
                    &rest[at + 1..]
                );
            }
        }
        return token.to_owned();
    }

    // `key=value` and `key: value` forms: screen the value half only, so we keep the
    // key name — which is the diagnostically useful part — and drop the value.
    for sep in ['=', ':'] {
        if let Some(idx) = token.find(sep) {
            let (key, value) = token.split_at(idx);
            let value = &value[1..];
            if is_suspicious(value) {
                return format!("{key}{sep}{SCRUB_MARKER}");
            }
        }
    }

    if is_suspicious(token) {
        return SCRUB_MARKER.to_owned();
    }
    token.to_owned()
}

/// Length + entropy heuristic for "this looks like secret material".
fn is_suspicious(token: &str) -> bool {
    if token.len() < SCRUB_MIN_LEN {
        return false;
    }
    // Paths, URLs and dotted identifiers are long and structured, not secret.
    if token.contains('/') || token.contains('\\') {
        return false;
    }
    crate::secret::shannon_bits_per_byte(token.as_bytes()) >= SCRUB_ENTROPY_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_uri_userinfo() {
        let d = SafeDetail::new("connection refused: postgres://app:hunter2SuperSecret@db:5432/app");
        assert!(!d.as_str().contains("hunter2SuperSecret"));
        assert!(d.as_str().contains("postgres://app:"));
        // The host survives, because that is the diagnostically useful part.
        assert!(d.as_str().contains("db:5432/app"));
    }

    /// Assemble a vendor-shaped credential fixture at run time.
    ///
    /// Credential-shaped test data is built from fragments rather than written as a
    /// literal. A `hvs.`-prefixed string sitting in this file *is* a Vault token as far
    /// as any secret scanner is concerned, and GitHub push protection rejects a commit
    /// containing one — correctly. The alternative is to allowlist our own repository,
    /// and a secrets-hardening tool that does that has refuted its own premise
    /// (DESIGN.md §13).
    ///
    /// Fidelity is unaffected: [`SafeDetail`] scrubs on length and entropy, never on
    /// vendor prefix, so the value under test is identical either way.
    fn vendor_shaped(prefix: &str, body: &str) -> String {
        format!("{prefix}{body}")
    }

    #[test]
    fn scrubs_high_entropy_bare_tokens() {
        let token = vendor_shaped("AKIA", "I44QH8DHBEXAMPLE7cQ2vX9pLm3K");
        let d = SafeDetail::new(format!("rejected token {token}"));
        assert!(!d.as_str().contains(&token));
        assert!(d.as_str().contains("rejected token"));
    }

    #[test]
    fn scrubs_the_value_half_of_key_equals_value() {
        let d = SafeDetail::new("bad request password=Xq7pLm3KvN9zR2wT5yB8sD4fG6hJ1kA0");
        assert!(!d.as_str().contains("Xq7pLm3KvN9zR2wT5yB8sD4fG6hJ1kA0"));
        assert!(d.as_str().contains("password="), "key name should survive: {d}");
    }

    #[test]
    fn preserves_ordinary_diagnostics() {
        let msg = "connection timed out after 30s contacting vault.internal";
        assert_eq!(SafeDetail::new(msg).as_str(), msg);
    }

    #[test]
    fn preserves_paths_which_are_long_but_not_secret() {
        let msg = "no such file: /etc/kawach/instances/production/config.yaml";
        assert_eq!(SafeDetail::new(msg).as_str(), msg);
    }

    #[test]
    fn error_display_never_contains_a_secret_it_was_given() {
        let token = vendor_shaped("hvs.", "CAESIJk3nQ8xR2wT5yB8sD4fG6hJ1kA0");
        let err = KawachError::Backend {
            backend: BackendId::new("vault-prod"),
            operation: "stage",
            detail: SafeDetail::new(format!("403 from https://vault.internal token={token}")),
        };
        let rendered = format!("{err}");
        assert!(!rendered.contains(&token), "a backend error leaked the token it carried");
        assert!(rendered.contains("vault-prod"), "the diagnostically useful part must survive");
    }
}
