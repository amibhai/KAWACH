//! Metadata types: everything KAWACH persists about a secret, and nothing it holds.
//!
//! Every type in this module is safe to serialise — which is enforced by the fact that
//! none of them can hold a [`crate::secret::SecretString`], and a `SecretString` has no
//! `Serialize` impl. `#[derive(Serialize)]` on a struct containing one does not
//! compile (DESIGN.md **I1**, **I3**).

use std::collections::BTreeMap;
use std::path::PathBuf;

use time::OffsetDateTime;

use crate::fingerprint::Fingerprint;
use crate::refs::{CredentialHandle, SecretRef, SourceId, VersionId};

/// What a backend knows about a secret, without reading its value.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SecretMetadata {
    /// Where it lives.
    pub reference: SecretRef,
    /// Creation time, if the backend records one.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub created_at: Option<OffsetDateTime>,
    /// Time of the most recent value change, if known.
    ///
    /// The single strongest input to the risk model: it bounds how long a leaked copy
    /// has been usable.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub last_changed_at: Option<OffsetDateTime>,
    /// Most recent access time, if the backend records one. Used for orphan detection.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub last_accessed_at: Option<OffsetDateTime>,
    /// The version consumers currently read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<VersionId>,
    /// Number of retained versions, where the backend is versioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_count: Option<u32>,
    /// Non-secret backend labels/tags.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl SecretMetadata {
    /// Minimal metadata for a reference the backend can see but describe no further.
    #[must_use]
    pub fn bare(reference: SecretRef) -> Self {
        Self {
            reference,
            created_at: None,
            last_changed_at: None,
            last_accessed_at: None,
            current_version: None,
            version_count: None,
            labels: BTreeMap::new(),
        }
    }

    /// Whole days since the value last changed, if known.
    #[must_use]
    pub fn age_days(&self, now: OffsetDateTime) -> Option<i64> {
        self.last_changed_at.map(|t| (now - t).whole_days())
    }
}

/// What a backend declares it can do.
///
/// The engine adapts its recovery strategy to these rather than assuming a semantic
/// the backend does not have (DESIGN.md §5.3, L3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackendCapabilities {
    /// `stage` and `promote` are distinct operations, so a new version can exist
    /// without consumers seeing it. AWS Secrets Manager: true (staging labels).
    /// Vault KV v2: false — a write is immediately current.
    pub atomic_promote: bool,
    /// Prior versions are addressable, so `restore` can republish one.
    pub versioned: bool,
    /// A written value can be read back, which is what makes reconciliation after a
    /// lost acknowledgement possible. A backend without this must be operated with
    /// operator-confirmed publication.
    pub readback: bool,
    /// `list` enumerates secrets, so discovery can enumerate the backend.
    pub listing: bool,
}

impl BackendCapabilities {
    /// The most conservative capability set: assume nothing.
    #[must_use]
    pub const fn minimal() -> Self {
        Self { atomic_promote: false, versioned: false, readback: false, listing: false }
    }
}

/// What is currently published at a reference, from the backend's point of view.
///
/// Note this carries a [`Fingerprint`], never a value: reconciliation asks "is what is
/// published the thing I wrote?", which fingerprints answer without a plaintext read.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublishedState {
    /// The version consumers currently read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<VersionId>,
    /// Fingerprint of the currently published value, where the backend permits a
    /// read-back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_fingerprint: Option<Fingerprint>,
    /// A staged-but-not-promoted version, for backends with `atomic_promote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_version: Option<VersionId>,
}

impl PublishedState {
    /// Nothing is published.
    #[must_use]
    pub fn empty() -> Self {
        Self { current_version: None, current_fingerprint: None, staged_version: None }
    }
}

/// A credential observed in its home system.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObservedCredential {
    /// Which credential.
    pub handle: CredentialHandle,
    /// Whether the target system currently accepts it.
    pub live: bool,
    /// Sessions currently authenticated with it, where observable. `None` means the
    /// provider cannot see this — which the engine treats as "cannot drain safely",
    /// not as zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_sessions: Option<u64>,
    /// Last observed use, where the target system records it.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub last_used_at: Option<OffsetDateTime>,
}

/// The provider's view of reality, used to reconcile an unknown-outcome state.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorldState {
    /// Credentials the provider can see for this target.
    pub credentials: Vec<ObservedCredential>,
}

impl WorldState {
    /// Look up one observed credential.
    #[must_use]
    pub fn get(&self, handle: &CredentialHandle) -> Option<&ObservedCredential> {
        self.credentials.iter().find(|c| &c.handle == handle)
    }

    /// Whether the named credential is live. Absent means not live.
    #[must_use]
    pub fn is_live(&self, handle: &CredentialHandle) -> bool {
        self.get(handle).is_some_and(|c| c.live)
    }
}

/// One check performed during verification.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerificationCheck {
    /// Stable identifier, e.g. `connect`, `privilege_probe`.
    pub id: String,
    /// Whether it passed.
    pub passed: bool,
    /// Human-readable detail. Provider-supplied text is scrubbed before it lands here.
    pub detail: String,
}

/// The outcome of proving a new credential works.
///
/// The state machine advances past `Verifying` only on `passed == true`, and
/// [`crate::traits::RotationProvider::verify`] is required to prove the credential can
/// do the application's actual work — not merely authenticate (DESIGN.md L8).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerificationReport {
    /// Overall result. True only if every check passed.
    pub passed: bool,
    /// Individual checks, for the operator-facing report.
    pub checks: Vec<VerificationCheck>,
}

impl VerificationReport {
    /// Build a report, deriving `passed` from the checks.
    ///
    /// Deriving rather than accepting it prevents a provider from reporting an overall
    /// pass alongside a failed check.
    #[must_use]
    pub fn from_checks(checks: Vec<VerificationCheck>) -> Self {
        let passed = !checks.is_empty() && checks.iter().all(|c| c.passed);
        Self { passed, checks }
    }

    /// The checks that failed.
    #[must_use]
    pub fn failures(&self) -> Vec<&VerificationCheck> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }
}

/// How a provider knows when consumers have stopped using the old credential.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DrainStrategy {
    /// Poll the target system for sessions authenticated with the old credential.
    /// The only strategy that provides evidence rather than a guess.
    ObserveSessions,
    /// Wait a fixed period, then assume convergence.
    ///
    /// Explicitly weaker: it assumes rather than observes. Available for targets with
    /// no session visibility, and reported as a reduced-assurance rotation.
    Elapsed,
    /// The provider cannot drain. The engine refuses drain-based rotation for this
    /// target rather than proceeding blind.
    Unsupported,
}

/// Drain configuration for a rotation target.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DrainPolicy {
    /// How convergence is determined.
    pub strategy: DrainStrategy,
    /// How long to wait before giving up and escalating to an operator.
    #[serde(with = "duration_secs")]
    pub deadline: std::time::Duration,
    /// How often to re-check.
    #[serde(with = "duration_secs")]
    pub poll_interval: std::time::Duration,
}

impl Default for DrainPolicy {
    fn default() -> Self {
        Self {
            strategy: DrainStrategy::ObserveSessions,
            deadline: std::time::Duration::from_secs(900),
            poll_interval: std::time::Duration::from_secs(5),
        }
    }
}

/// The result of a drain attempt.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DrainReport {
    /// Whether the old credential is now unused.
    pub complete: bool,
    /// Sessions still using the old credential at the last observation. `None` where
    /// the strategy cannot observe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_sessions: Option<u64>,
    /// How long the drain ran.
    #[serde(with = "duration_secs")]
    pub elapsed: std::time::Duration,
    /// Which strategy produced this result.
    pub strategy: DrainStrategy,
}

/// A preflight finding: something an operator should know before a rotation runs.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreflightFinding {
    /// Stable identifier, e.g. `missing_pg_read_all_stats`.
    pub id: String,
    /// Whether this alone blocks the rotation.
    pub blocking: bool,
    /// What was found, and what the operator should do.
    pub detail: String,
}

/// The result of a dry-run-safe readiness check.
///
/// Preflight performs no mutation and requires no [`crate::capability::CommitToken`],
/// which is what lets a dry run produce a genuinely useful report.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Preflight {
    /// Findings, blocking and advisory.
    pub findings: Vec<PreflightFinding>,
}

impl Preflight {
    /// A clean preflight.
    #[must_use]
    pub fn ready() -> Self {
        Self { findings: Vec::new() }
    }

    /// Whether any finding blocks the rotation.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.findings.iter().any(|f| f.blocking)
    }
}

/// Where a discovered secret was found.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Location {
    /// A file in a scanned tree.
    File {
        /// Path, relative to the scan root.
        path: PathBuf,
        /// 1-based line number.
        line: u32,
        /// The commit that introduced the line, where the tree is a git worktree.
        ///
        /// "When did this leak" is the first question in an incident, and the answer
        /// changes the blast radius.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        introduced_by: Option<String>,
    },
    /// A CI/CD pipeline variable.
    CiVariable {
        /// The CI system, e.g. `github_actions`.
        system: String,
        /// Repository or project identifier.
        project: String,
        /// Variable name.
        name: String,
    },
    /// An environment variable on a container or pod.
    ContainerEnv {
        /// Container or pod identifier.
        container: String,
        /// Variable name.
        name: String,
    },
    /// A secret enumerated from a backend.
    Backend {
        /// Where it lives.
        reference: SecretRef,
    },
}

/// One discovered credential-shaped thing.
///
/// Note what is *not* here: the value. A `Finding` cannot hold one — there is no field
/// for it and no way to add one without also removing `Serialize` (DESIGN.md I3).
///
/// Not `Eq`: it carries measured floats. Findings are compared by
/// [`Fingerprint`] and [`Location`], never by structural equality of the whole record.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Which source produced it.
    pub source: SourceId,
    /// Which detector fired, e.g. `aws_access_key_id`, `entropy_generic`.
    pub detector: String,
    /// Where it is.
    pub location: Location,
    /// Keyed hash of the value, for correlation across findings and backends.
    pub fingerprint: Fingerprint,
    /// Detector confidence, 0.0–1.0.
    ///
    /// **Ordinal, not calibrated.** Comparable between findings; not a probability.
    /// See DESIGN.md §8.4.
    pub confidence: f32,
    /// Measured Shannon entropy of the candidate, in bits per byte.
    pub entropy_bits_per_byte: f64,
    /// The key or variable name the value was bound to, where there was one. Strong
    /// evidence, and safe: a name is not a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    /// When it was observed.
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

/// Counters from a completed scan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanStats {
    /// Items inspected (files, variables, backend entries).
    pub items_scanned: u64,
    /// Items skipped, e.g. binaries or files over the size limit.
    pub items_skipped: u64,
    /// Findings emitted.
    pub findings: u64,
}

/// Serialise `Duration` as whole seconds, so config and reports stay human-editable.
mod duration_secs {
    use std::time::Duration;

    pub(super) fn serialize<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        use serde::Deserialize;
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::FingerprintKey;
    use crate::refs::BackendId;
    use crate::secret::SecretString;
    use time::Duration as TimeDuration;

    #[test]
    fn a_finding_serialises_without_any_plaintext() {
        let key = FingerprintKey::generate();
        let secret = SecretString::from_string("canary-value-do-not-log".into());
        let finding = Finding {
            source: SourceId::new("repo"),
            detector: "entropy_generic".into(),
            location: Location::File { path: "app/.env".into(), line: 12, introduced_by: None },
            fingerprint: secret.fingerprint(&key),
            confidence: 0.8,
            entropy_bits_per_byte: 4.2,
            key_name: Some("DATABASE_PASSWORD".into()),
            observed_at: OffsetDateTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("canary-value-do-not-log"));
        // The key *name* is retained: it is evidence, and it is not a value.
        assert!(json.contains("DATABASE_PASSWORD"));
    }

    #[test]
    fn verification_cannot_report_an_overall_pass_with_a_failed_check() {
        let report = VerificationReport::from_checks(vec![
            VerificationCheck { id: "connect".into(), passed: true, detail: "ok".into() },
            VerificationCheck { id: "privilege_probe".into(), passed: false, detail: "permission denied".into() },
        ]);
        assert!(!report.passed);
        assert_eq!(report.failures().len(), 1);
    }

    #[test]
    fn an_empty_verification_is_not_a_pass() {
        // A provider that runs no checks has proven nothing; treating that as success
        // would let a rotation revoke a working credential on no evidence.
        assert!(!VerificationReport::from_checks(vec![]).passed);
    }

    #[test]
    fn age_is_computed_from_the_last_change() {
        let now = OffsetDateTime::UNIX_EPOCH + TimeDuration::days(1000);
        let mut m = SecretMetadata::bare(SecretRef::new(BackendId::new("v"), "p"));
        assert_eq!(m.age_days(now), None);
        m.last_changed_at = Some(OffsetDateTime::UNIX_EPOCH + TimeDuration::days(153));
        assert_eq!(m.age_days(now), Some(847));
    }

    #[test]
    fn unobservable_sessions_are_not_zero_sessions() {
        let handle = CredentialHandle::new(crate::refs::CredentialKind::new("postgres"), "billing_a");
        let world = WorldState {
            credentials: vec![ObservedCredential {
                handle: handle.clone(),
                live: true,
                active_sessions: None,
                last_used_at: None,
            }],
        };
        assert!(world.is_live(&handle));
        assert_eq!(world.get(&handle).unwrap().active_sessions, None);
    }

    #[test]
    fn drain_policy_round_trips_durations_as_seconds() {
        let p = DrainPolicy::default();
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("900"));
        assert_eq!(serde_json::from_str::<DrainPolicy>(&json).unwrap(), p);
    }
}
