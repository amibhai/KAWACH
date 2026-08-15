//! Non-secret identifiers: backends, secrets, versions, credentials, runs.
//!
//! Everything in this module is safe to log, persist, and print. That is the point —
//! it is the vocabulary the rest of the system uses so that secret *values* never need
//! to appear in an interface.

use core::fmt;
use std::collections::BTreeMap;

use crate::rng;

/// Identifier of a configured secret backend, e.g. `vault-prod`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct BackendId(String);

impl BackendId {
    /// Wrap a backend identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BackendId({})", self.0)
    }
}

/// Identifier of a configured discovery source, e.g. `repo-monorepo`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct SourceId(String);

impl SourceId {
    /// Wrap a source identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SourceId({})", self.0)
    }
}

/// A reference to a secret in a backend. Location only — never a value.
///
/// This is the *unauthorized* form. To pass it to a backend it must first be turned
/// into a [`crate::scope::ScopedRef`] by [`crate::scope::Scope::authorize`], which is
/// how scope enforcement is made unforgettable (DESIGN.md §5.2).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct SecretRef {
    /// Which backend holds it.
    pub backend: BackendId,
    /// Backend-specific path or ARN.
    pub path: String,
}

impl SecretRef {
    /// Construct a reference.
    #[must_use]
    pub fn new(backend: BackendId, path: impl Into<String>) -> Self {
        Self { backend, path: path.into() }
    }

    /// Parse the canonical `backend:path` form used in configuration and on the CLI.
    ///
    /// Splits on the *first* colon only: ARNs contain colons, and splitting on the
    /// last one would silently mangle them.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (backend, path) = s.split_once(':')?;
        if backend.is_empty() || path.is_empty() {
            return None;
        }
        Some(Self::new(BackendId::new(backend), path))
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.backend, self.path)
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretRef({self})")
    }
}

/// A backend-assigned version identifier (Vault KV version, AWS version id).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct VersionId(String);

impl VersionId {
    /// Wrap a version identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The kind of credential a [`crate::traits::RotationProvider`] handles, e.g.
/// `postgres_ab_roles`. A `String` rather than an enum so that out-of-tree providers
/// need no change to this crate.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct CredentialKind(String);

impl CredentialKind {
    /// Wrap a credential kind.
    #[must_use]
    pub fn new(kind: impl Into<String>) -> Self {
        Self(kind.into())
    }

    /// The kind as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An opaque, **non-secret** handle to a credential in its home system.
///
/// For PostgreSQL this is a role name; for an API vendor it is a key id. It is what
/// makes provider operations idempotent (DESIGN.md §6.3): `revoke(handle)` is safe to
/// retry because it names a specific credential rather than "the current one".
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct CredentialHandle {
    /// Which provider kind issued it.
    pub kind: CredentialKind,
    /// Provider-scoped identifier (role name, key id).
    pub id: String,
    /// Non-secret provider metadata, e.g. `{"role": "billing_b"}`.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl CredentialHandle {
    /// Construct a handle with no labels.
    #[must_use]
    pub fn new(kind: CredentialKind, id: impl Into<String>) -> Self {
        Self { kind, id: id.into(), labels: BTreeMap::new() }
    }

    /// Attach a non-secret label.
    #[must_use]
    pub fn with_label(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.labels.insert(k.into(), v.into());
        self
    }
}

impl fmt::Display for CredentialHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind, self.id)
    }
}

/// Identifier of a single KAWACH invocation.
///
/// Threads through the audit log, the rotation journal and every capability token, so
/// that "what did that 3am run actually do" is one grep.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct RunId(String);

impl RunId {
    /// Generate a fresh run identifier (128 bits of CSPRNG output, hex encoded).
    #[must_use]
    pub fn generate() -> Self {
        Self(rng::hex_id(16))
    }

    /// Wrap an existing identifier, e.g. when resuming a journalled run.
    #[must_use]
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RunId({})", self.0)
    }
}

/// Monotonic sequence number of an audit-log entry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditSeq(pub u64);

impl fmt::Display for AuditSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_ref_parses_the_canonical_form() {
        let r = SecretRef::parse("vault-prod:secret/data/app/db").unwrap();
        assert_eq!(r.backend.as_str(), "vault-prod");
        assert_eq!(r.path, "secret/data/app/db");
        assert_eq!(r.to_string(), "vault-prod:secret/data/app/db");
    }

    #[test]
    fn secret_ref_splits_on_the_first_colon_so_arns_survive() {
        let r = SecretRef::parse("aws-prod:arn:aws:secretsmanager:eu-west-1:123:secret:app/db").unwrap();
        assert_eq!(r.backend.as_str(), "aws-prod");
        assert_eq!(r.path, "arn:aws:secretsmanager:eu-west-1:123:secret:app/db");
    }

    #[test]
    fn secret_ref_rejects_malformed_input() {
        assert!(SecretRef::parse("no-colon").is_none());
        assert!(SecretRef::parse(":path").is_none());
        assert!(SecretRef::parse("backend:").is_none());
    }

    #[test]
    fn run_ids_are_unique_and_hex() {
        let (a, b) = (RunId::generate(), RunId::generate());
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 32);
        assert!(a.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }
}
