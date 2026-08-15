//! [`RotationProvider`]: the home-system half of a rotation.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::capability::CommitToken;
use crate::error::{KawachError, Result, SafeDetail};
use crate::model::{DrainPolicy, DrainReport, Preflight, VerificationReport, WorldState};
use crate::refs::{CredentialHandle, CredentialKind, RunId};
use crate::scope::ScopedRef;
use crate::secret::{PasswordPolicy, SecretString};

/// Flat, dotted-key provider settings, e.g. `roles.a = "billing_a"`.
///
/// Deliberately flat and string-typed rather than an arbitrary nested value tree.
/// Configuration that drives credential rotation should be readable at a glance and
/// diffable line by line; nested structures invite the kind of "I did not realise that
/// key was inherited" mistake that a security tool cannot afford.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ProviderSettings(BTreeMap<String, String>);

impl ProviderSettings {
    /// Empty settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a key, builder style.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }

    /// Look up an optional setting.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Look up a required setting.
    ///
    /// # Errors
    /// [`KawachError::Config`] naming the missing key. Providers use this rather than
    /// defaulting, so a typo in configuration surfaces as a refusal rather than as a
    /// rotation against the wrong role.
    pub fn require(&self, key: &str) -> Result<&str> {
        self.get(key).ok_or_else(|| KawachError::Config {
            location: key.to_owned(),
            detail: SafeDetail::trusted_static("required provider setting is missing"),
        })
    }

    /// Look up a required setting and parse it.
    ///
    /// # Errors
    /// [`KawachError::Config`] if the key is missing or does not parse.
    pub fn require_parsed<T: std::str::FromStr>(&self, key: &str) -> Result<T> {
        self.require(key)?.parse().map_err(|_| KawachError::Config {
            location: key.to_owned(),
            detail: SafeDetail::trusted_static("provider setting has the wrong type"),
        })
    }

    /// Iterate over all settings, for the dry-run plan output.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// Everything a provider needs to know about one rotation.
#[derive(Clone, Debug)]
pub struct RotationTarget {
    /// The run this rotation belongs to.
    pub run: RunId,
    /// Where the value is published for consumers.
    pub reference: ScopedRef,
    /// Which provider handles it.
    pub kind: CredentialKind,
    /// Provider-specific configuration.
    pub settings: ProviderSettings,
    /// How to generate the new credential.
    pub policy: PasswordPolicy,
    /// How to know when consumers have converged.
    pub drain: DrainPolicy,
    /// The credential currently in use, where known.
    ///
    /// `None` on a first rotation, or where the provider must discover it via
    /// [`RotationProvider::observe`].
    pub active: Option<CredentialHandle>,
}

/// A freshly provisioned credential.
///
/// Holds a [`SecretString`], and therefore has no `Serialize` impl — this type cannot
/// be journalled or logged, which is exactly the intent. What *is* journalled is the
/// [`CredentialHandle`], which is not secret.
#[derive(Debug)]
pub struct NewCredential {
    /// Non-secret identity of the credential in its home system.
    pub handle: CredentialHandle,
    /// The value. Zeroized on drop.
    pub value: SecretString,
}

/// A wall-clock deadline for a bounded operation.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    /// A deadline `d` from now.
    #[must_use]
    pub fn in_(d: Duration) -> Self {
        Self { at: Instant::now() + d }
    }

    /// Whether the deadline has passed.
    #[must_use]
    pub fn expired(&self) -> bool {
        Instant::now() >= self.at
    }

    /// Time left, or zero.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.at.saturating_duration_since(Instant::now())
    }
}

/// A credential type KAWACH can rotate: PostgreSQL roles, an API vendor's keys, and so
/// on.
///
/// The methods correspond one-to-one with the effectful transitions of the state
/// machine, which is what lets the engine reason about them uniformly. Read-only
/// methods take no [`CommitToken`] and are safe to call during a dry run; effectful
/// methods require one and therefore cannot run during a dry run at all.
#[async_trait]
pub trait RotationProvider: Send + Sync {
    /// The credential type this provider handles.
    fn kind(&self) -> CredentialKind;

    /// How this provider determines that consumers have converged.
    ///
    /// A provider that returns [`crate::model::DrainStrategy::Unsupported`] causes the
    /// engine to refuse drain-based rotation for its targets rather than proceed on an
    /// unobservable assumption.
    fn drain_policy(&self) -> DrainPolicy;

    /// Check readiness without changing anything.
    ///
    /// This is what makes a dry run useful rather than merely safe: it is where
    /// "you have not granted `pg_read_all_stats`, so the drain check would be blind"
    /// is discovered — *before* an operator schedules the rotation, not during it.
    ///
    /// # Errors
    /// Connectivity or configuration failures.
    async fn preflight(&self, target: &RotationTarget) -> Result<Preflight>;

    /// Ask the home system what is actually true.
    ///
    /// The reconciliation primitive. After a crash in an unknown-outcome state
    /// (DESIGN.md §6.3), the engine calls this to decide whether the interrupted step
    /// took effect, instead of assuming.
    ///
    /// # Errors
    /// Connectivity failures. A failure here leaves the run in its unknown-outcome
    /// state, which is correct: we would rather stay stuck than guess.
    async fn observe(&self, target: &RotationTarget) -> Result<WorldState>;

    /// Create a new credential. Must be idempotent for a given handle.
    ///
    /// # Errors
    /// Any failure to provision. The engine compensates by revoking whatever may have
    /// been created, which is why this must be idempotent.
    async fn provision(&self, target: &RotationTarget, commit: &CommitToken) -> Result<NewCredential>;

    /// Prove the new credential works — on a fresh connection, doing the application's
    /// actual work.
    ///
    /// Takes no [`CommitToken`]: verification must not mutate. It does take the
    /// plaintext, because proving a credential works requires using it; this is one of
    /// the few places a value legitimately crosses a trait boundary.
    ///
    /// Implementations must verify **authorisation, not merely authentication**. A
    /// `SELECT 1` that succeeds on a role with no table grants "verifies" a credential
    /// that cannot do the application's job, after which the engine would revoke the
    /// working one (DESIGN.md L8).
    ///
    /// # Errors
    /// Connectivity failures. A *failed check* is not an error — it is a
    /// [`VerificationReport`] with `passed: false`, which the state machine handles as
    /// a normal rollback path rather than an exception.
    async fn verify(
        &self,
        target: &RotationTarget,
        candidate: &SecretString,
    ) -> Result<VerificationReport>;

    /// Wait until no consumer is using `handle`, or until `deadline`.
    ///
    /// Takes no [`CommitToken`]: draining observes, it does not mutate. Returning
    /// `complete: false` is not an error; the engine escalates to an operator rather
    /// than revoking on an incomplete drain.
    ///
    /// # Errors
    /// Connectivity failures during observation.
    async fn drain(
        &self,
        target: &RotationTarget,
        handle: &CredentialHandle,
        deadline: Deadline,
    ) -> Result<DrainReport>;

    /// Render `handle` unusable. Must be idempotent.
    ///
    /// For PostgreSQL this sets the role's password to a fresh random value that is
    /// generated, applied, and immediately dropped — never `DROP ROLE`, which fails or
    /// cascades badly when the role owns objects (DESIGN.md §6.6).
    ///
    /// # Errors
    /// Any failure to revoke. The engine escalates to an operator: a live credential
    /// that should be dead is a finding, not something to retry silently forever.
    async fn revoke(
        &self,
        target: &RotationTarget,
        handle: &CredentialHandle,
        commit: &CommitToken,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_settings_are_refused_not_defaulted() {
        let s = ProviderSettings::new().with("roles.a", "billing_a");
        assert_eq!(s.require("roles.a").unwrap(), "billing_a");
        let err = s.require("roles.b").unwrap_err();
        assert!(matches!(err, KawachError::Config { .. }));
        assert!(format!("{err}").contains("roles.b"));
    }

    #[test]
    fn typed_settings_reject_the_wrong_type() {
        let s = ProviderSettings::new().with("max_connections", "not-a-number");
        assert!(s.require_parsed::<u32>("max_connections").is_err());
        let s = s.with("timeout_secs", "30");
        assert_eq!(s.require_parsed::<u64>("timeout_secs").unwrap(), 30);
    }

    #[test]
    fn deadlines_expire() {
        let d = Deadline::in_(Duration::from_millis(0));
        assert!(d.expired());
        assert_eq!(d.remaining(), Duration::ZERO);
        assert!(!Deadline::in_(Duration::from_secs(60)).expired());
    }

    #[test]
    fn new_credential_debug_does_not_leak_the_value() {
        let c = NewCredential {
            handle: CredentialHandle::new(CredentialKind::new("postgres"), "billing_b"),
            value: SecretString::from_string("canary-provisioned".into()),
        };
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("canary-provisioned"));
        assert!(rendered.contains("billing_b"));
    }
}
