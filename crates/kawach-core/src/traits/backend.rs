//! [`SecretBackend`]: the publication half of a rotation.

use async_trait::async_trait;

use crate::capability::{CommitToken, ReadWitness};
use crate::error::Result;
use crate::model::{BackendCapabilities, PublishedState, SecretMetadata};
use crate::refs::{BackendId, SecretRef, VersionId};
use crate::scope::{Scope, ScopedRef};
use crate::secret::SecretString;

/// A store that holds secret values and that consumers read from.
///
/// Note the argument types, which carry the invariants:
///
/// * every addressing method takes a [`ScopedRef`], which can only be produced by
///   [`Scope::authorize`] — out-of-scope access is unrepresentable;
/// * [`read`](SecretBackend::read) takes a [`ReadWitness`], which only exists after a
///   durable audit record — unaudited plaintext access is unrepresentable;
/// * every mutating method takes a [`CommitToken`], which only exists in `--apply`
///   mode — mutation during a dry run is unrepresentable.
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// This backend's configured identifier.
    fn id(&self) -> &BackendId;

    /// What this backend can do. Must be honest: the engine's recovery strategy
    /// depends on it.
    fn capabilities(&self) -> BackendCapabilities;

    /// Enumerate secrets visible to KAWACH within `scope`.
    ///
    /// Returns unauthorized [`SecretRef`]s: enumeration may legitimately surface paths
    /// outside the allowlist, and the caller decides what to do with them (typically
    /// [`Scope::authorize_all`], which filters). Returning `ScopedRef` here would
    /// conflate "I can see it" with "I may touch it".
    ///
    /// # Errors
    /// Backend or transport failures, as [`crate::error::KawachError::Backend`].
    async fn list(&self, scope: &Scope) -> Result<Vec<SecretRef>>;

    /// Metadata for one secret. Never reads the value.
    ///
    /// This is the workhorse of the audit pillar: age, version count and access time
    /// are all obtainable without a plaintext read, so a full posture assessment
    /// touches no secret material at all.
    ///
    /// # Errors
    /// Backend or transport failures.
    async fn describe(&self, reference: &ScopedRef) -> Result<SecretMetadata>;

    /// Read a plaintext value.
    ///
    /// The highest-risk operation in the system, and the reason [`ReadWitness`]
    /// exists. Used sparingly: read-back verification after a publish, and explicit
    /// operator-requested reads. Never used by the audit pillar.
    ///
    /// # Errors
    /// Backend or transport failures. Implementations must not include any part of the
    /// value in the error.
    async fn read(&self, reference: &ScopedRef, witness: &ReadWitness<'_>) -> Result<SecretString>;

    /// Write a new version *without* making it current, where the backend can.
    ///
    /// For backends with [`BackendCapabilities::atomic_promote`] this is a genuine
    /// stage (AWS `AWSPENDING`). For those without it — Vault KV v2, where a write is
    /// immediately current — `stage` performs the write and `promote` is a no-op, and
    /// the backend reports `atomic_promote: false` so the engine knows publication and
    /// staging collapsed into one step and adjusts its recovery accordingly.
    ///
    /// # Errors
    /// Backend or transport failures.
    async fn stage(
        &self,
        reference: &ScopedRef,
        value: SecretString,
        commit: &CommitToken,
    ) -> Result<VersionId>;

    /// Make a staged version the one consumers read.
    ///
    /// # Errors
    /// Backend or transport failures.
    async fn promote(
        &self,
        reference: &ScopedRef,
        version: &VersionId,
        commit: &CommitToken,
    ) -> Result<()>;

    /// Republish a prior version, for the compensation path (DESIGN.md §6.4).
    ///
    /// Implemented as a *forward write* of the earlier value rather than a destructive
    /// version rollback, so that the backend's own history remains a complete record of
    /// what happened — including the fact that a rotation was rolled back.
    ///
    /// # Errors
    /// Backend or transport failures; [`crate::error::KawachError::Backend`] if the
    /// backend is not versioned.
    async fn restore(
        &self,
        reference: &ScopedRef,
        version: &VersionId,
        commit: &CommitToken,
    ) -> Result<()>;

    /// Observe what is currently published, for reconciliation after a crash or a lost
    /// acknowledgement (DESIGN.md L3).
    ///
    /// Returns fingerprints, not values, so reconciliation costs no plaintext read.
    ///
    /// # Errors
    /// Backend or transport failures.
    async fn observe_published(&self, reference: &ScopedRef) -> Result<PublishedState>;
}
