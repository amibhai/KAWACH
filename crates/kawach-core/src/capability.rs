//! Unforgeable capability tokens (DESIGN.md **I5**, **I7**, §5.2).
//!
//! Two of KAWACH's invariants are enforced here, by construction rather than by
//! discipline:
//!
//! * **Dry-run cannot mutate.** Every mutating trait method requires a
//!   [`CommitToken`]. The token has a private constructor and is minted only by
//!   [`ExecutionMode::Apply`]. In dry-run mode there is no token, so a provider —
//!   including a buggy or malicious third-party one — *cannot* perform a mutation. It
//!   is not ignoring a boolean; it lacks an argument it cannot construct.
//!
//! * **No unaudited read of a secret value.** [`ReadWitness::issue`] writes and
//!   durably flushes an access-intent record *before* returning the witness, and
//!   `SecretBackend::read` requires one. There is no code path that reads a plaintext
//!   value without an audit record already on disk. If the caller drops the witness
//!   without completing it — a panic mid-read, say — `Drop` records the abandonment,
//!   so even the crash is evidence.

use core::fmt;

use crate::error::Result;
use crate::refs::{AuditSeq, RunId};
use crate::scope::ScopedRef;

/// Events that `kawach-core` itself emits into the audit log.
///
/// Deliberately small. The richer event vocabulary lives in `kawach-audit`; this enum
/// exists so that `kawach-core` can require an audit record without depending on the
/// audit crate (which depends on this one).
///
/// Deliberately **not** `#[non_exhaustive]`, unlike the other public enums in this
/// crate. This is an internal seam between two KAWACH crates, not an extension point,
/// and exhaustiveness is the forcing function we want: adding a variant here must break
/// `kawach-audit`'s build, so a new event cannot be silently dropped from the audit log
/// by a wildcard arm. An event that is emitted but never recorded is the exact failure
/// invariant I5 exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum CoreAuditEvent {
    /// An `--apply` run acquired the authority to mutate.
    CommitTokenMinted {
        /// The run acquiring authority.
        run: RunId,
        /// Who confirmed, and why.
        confirmation: Confirmation,
    },
    /// A plaintext read is about to be attempted.
    AccessIntent {
        /// The run performing the read.
        run: RunId,
        /// What is being read, as `backend:path`.
        reference: String,
        /// Why, in the operator's words or the engine's.
        purpose: String,
    },
    /// A plaintext read finished.
    AccessOutcome {
        /// The intent entry this completes.
        intent_seq: AuditSeq,
        /// How it ended.
        outcome: ReadOutcome,
    },
}

/// How a witnessed read ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReadOutcome {
    /// The value was read.
    Success,
    /// The backend refused or failed.
    Failed,
    /// The witness was dropped without completion — a panic or an early return.
    /// Recorded by `Drop`, so an unexplained gap is itself a signal.
    Abandoned,
}

/// The sink `kawach-core` writes capability-related audit records to.
///
/// Implemented by `kawach-audit`. Declared here to keep the dependency edge pointing
/// one way (DESIGN.md §5.1: no cycles).
pub trait AuditAnchor: Send + Sync {
    /// Append an entry and make it durable before returning.
    ///
    /// Implementations **must** `fsync` before returning `Ok`. The invariant is "the
    /// record exists before the action", and a buffered write does not provide it.
    ///
    /// # Errors
    /// Any failure to make the record durable. Callers treat this as fatal: if we
    /// cannot record what we are about to do, we do not do it.
    fn record(&self, event: CoreAuditEvent) -> Result<AuditSeq>;
}

/// An operator's explicit authorisation for a mutating run.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Confirmation {
    /// Who is acting. Sourced from the environment, not self-asserted on the CLI.
    pub operator: String,
    /// Free-text reason, recorded in the audit log.
    pub reason: String,
    /// Optional change-management reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

impl Confirmation {
    /// Construct a confirmation.
    #[must_use]
    pub fn new(operator: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { operator: operator.into(), reason: reason.into(), ticket: None }
    }

    /// Attach a change-management reference.
    #[must_use]
    pub fn with_ticket(mut self, ticket: impl Into<String>) -> Self {
        self.ticket = Some(ticket.into());
        self
    }
}

/// Whether this run may change the world.
///
/// [`ExecutionMode::DryRun`] is the default everywhere. Constructing
/// [`ExecutionMode::Apply`] requires a [`Confirmation`], which the CLI obtains from an
/// explicit `--apply` plus an interactive prompt or an equivalent non-interactive
/// attestation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Plan and report; perform no mutation. The default, everywhere, always.
    #[default]
    DryRun,
    /// Mutate, under the recorded confirmation.
    Apply(Confirmation),
}

impl ExecutionMode {
    /// Whether this mode permits mutation.
    #[must_use]
    pub fn is_apply(&self) -> bool {
        matches!(self, Self::Apply(_))
    }

    /// Mint the authority to mutate, if this mode has any.
    ///
    /// Returns `Ok(None)` in dry-run: not an error, just an absence of authority. On
    /// `Apply`, writes a durable `CommitTokenMinted` record *before* returning the
    /// token, so authority never exists without a trace of its acquisition.
    ///
    /// # Errors
    /// Propagates audit-write failures. A failure here denies the token, which means
    /// the run degrades to a dry run rather than proceeding unaudited.
    pub fn commit_token(&self, anchor: &dyn AuditAnchor, run: &RunId) -> Result<Option<CommitToken>> {
        match self {
            Self::DryRun => Ok(None),
            Self::Apply(confirmation) => {
                let seq = anchor.record(CoreAuditEvent::CommitTokenMinted {
                    run: run.clone(),
                    confirmation: confirmation.clone(),
                })?;
                Ok(Some(CommitToken { run: run.clone(), minted_at: seq }))
            }
        }
    }
}

/// Proof that this run is permitted to change the world.
///
/// Private fields, no public constructor, and deliberately not `Clone`: authority
/// should be passed by reference, not duplicated. Every mutating method on
/// [`crate::traits::SecretBackend`] and [`crate::traits::RotationProvider`] takes one.
#[derive(Debug, PartialEq, Eq)]
pub struct CommitToken {
    run: RunId,
    minted_at: AuditSeq,
}

impl CommitToken {
    /// The run this authority belongs to.
    #[must_use]
    pub fn run(&self) -> &RunId {
        &self.run
    }

    /// The audit sequence number at which this authority was granted.
    #[must_use]
    pub fn minted_at(&self) -> AuditSeq {
        self.minted_at
    }

    /// Mint a token without an audit record, for unit tests only.
    ///
    /// Behind `cfg(test)` in this crate plus the `test-support` feature for downstream
    /// crates' tests. It is not compiled into a release binary, so the production
    /// invariant is unaffected.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test() -> Self {
        Self { run: RunId::from_string("test-run"), minted_at: AuditSeq(0) }
    }
}

/// What a plaintext read is for. Recorded before the read happens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadIntent {
    /// The run performing the read.
    pub run: RunId,
    /// What is being read.
    pub reference: String,
    /// Why. Free text, shown in the audit log and in incident review.
    pub purpose: String,
}

impl ReadIntent {
    /// Construct an intent for an already-authorized reference.
    ///
    /// Takes a [`ScopedRef`] rather than a [`crate::refs::SecretRef`]: you cannot even
    /// express the intent to read something that is out of scope.
    #[must_use]
    pub fn new(run: &RunId, reference: &ScopedRef, purpose: impl Into<String>) -> Self {
        Self { run: run.clone(), reference: reference.to_string(), purpose: purpose.into() }
    }
}

/// Proof that a plaintext read was recorded before it happened.
///
/// Required by `SecretBackend::read`. Issued only by [`ReadWitness::issue`], which
/// writes the intent record first. Completing the witness records the outcome;
/// dropping it without completing records an abandonment.
pub struct ReadWitness<'a> {
    anchor: &'a dyn AuditAnchor,
    intent_seq: AuditSeq,
    intent: ReadIntent,
    completed: std::cell::Cell<bool>,
}

impl<'a> ReadWitness<'a> {
    /// Record the intent to read, then issue the witness that permits it.
    ///
    /// # Errors
    /// Propagates audit-write failures — in which case no witness exists, and the read
    /// therefore cannot happen. That ordering is the invariant.
    pub fn issue(anchor: &'a dyn AuditAnchor, intent: ReadIntent) -> Result<Self> {
        let intent_seq = anchor.record(CoreAuditEvent::AccessIntent {
            run: intent.run.clone(),
            reference: intent.reference.clone(),
            purpose: intent.purpose.clone(),
        })?;
        Ok(Self { anchor, intent_seq, intent, completed: std::cell::Cell::new(false) })
    }

    /// The sequence number of the intent record.
    #[must_use]
    pub fn intent_seq(&self) -> AuditSeq {
        self.intent_seq
    }

    /// What this witness authorises.
    #[must_use]
    pub fn intent(&self) -> &ReadIntent {
        &self.intent
    }

    /// Record how the read ended.
    ///
    /// Consumes the witness so it cannot authorise a second read. A witness is
    /// single-use by construction: one audit record, one read.
    ///
    /// # Errors
    /// Propagates audit-write failures. Note that the read has already happened by
    /// this point, so the caller should treat a failure here as an integrity incident
    /// rather than a read failure.
    pub fn complete(self, outcome: ReadOutcome) -> Result<()> {
        self.completed.set(true);
        self.anchor
            .record(CoreAuditEvent::AccessOutcome { intent_seq: self.intent_seq, outcome })
            .map(|_| ())
    }
}

impl Drop for ReadWitness<'_> {
    /// A witness that was never completed means a read whose outcome we do not know.
    /// Record that rather than leaving a dangling intent, which would be
    /// indistinguishable from a truncated log.
    fn drop(&mut self) {
        if !self.completed.get() {
            // Best effort: we are in a drop, quite possibly during unwinding, so there
            // is nothing to propagate an error to. A failure here leaves a dangling
            // intent record, which `kawach audit verify` reports as an anomaly.
            let _ = self.anchor.record(CoreAuditEvent::AccessOutcome {
                intent_seq: self.intent_seq,
                outcome: ReadOutcome::Abandoned,
            });
        }
    }
}

impl fmt::Debug for ReadWitness<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadWitness")
            .field("intent_seq", &self.intent_seq)
            .field("reference", &self.intent.reference)
            .field("completed", &self.completed.get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingAnchor {
        events: Mutex<Vec<CoreAuditEvent>>,
        fail: bool,
    }

    impl RecordingAnchor {
        fn failing() -> Self {
            Self { fail: true, ..Self::default() }
        }
        fn events(&self) -> Vec<CoreAuditEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    impl AuditAnchor for RecordingAnchor {
        fn record(&self, event: CoreAuditEvent) -> Result<AuditSeq> {
            if self.fail {
                return Err(crate::error::KawachError::Audit {
                    detail: crate::error::SafeDetail::trusted_static("disk full"),
                });
            }
            let mut events = self.events.lock().unwrap();
            events.push(event);
            Ok(AuditSeq(events.len() as u64))
        }
    }

    fn intent(run: &RunId) -> ReadIntent {
        ReadIntent { run: run.clone(), reference: "vault-prod:secret/app/db".into(), purpose: "read-back verify".into() }
    }

    #[test]
    fn dry_run_yields_no_authority_to_mutate() {
        let anchor = RecordingAnchor::default();
        let token = ExecutionMode::DryRun.commit_token(&anchor, &RunId::generate()).unwrap();
        assert!(token.is_none(), "dry-run must not be able to mint a commit token");
        assert!(anchor.events().is_empty(), "dry-run must not write a mint record");
    }

    #[test]
    fn apply_mints_a_token_and_records_it_first() {
        let anchor = RecordingAnchor::default();
        let run = RunId::generate();
        let mode = ExecutionMode::Apply(Confirmation::new("alice", "quarterly rotation").with_ticket("CHG-42"));
        let token = mode.commit_token(&anchor, &run).unwrap().expect("apply mode mints");
        assert_eq!(token.run(), &run);
        match &anchor.events()[..] {
            [CoreAuditEvent::CommitTokenMinted { run: r, confirmation }] => {
                assert_eq!(r, &run);
                assert_eq!(confirmation.operator, "alice");
                assert_eq!(confirmation.ticket.as_deref(), Some("CHG-42"));
            }
            other => panic!("unexpected audit trail: {other:?}"),
        }
    }

    #[test]
    fn an_unwritable_audit_log_denies_authority() {
        // If we cannot record that we are about to mutate, we do not get to mutate.
        let anchor = RecordingAnchor::failing();
        let mode = ExecutionMode::Apply(Confirmation::new("alice", "rotation"));
        assert!(mode.commit_token(&anchor, &RunId::generate()).is_err());
    }

    #[test]
    fn a_read_is_recorded_before_the_witness_exists() {
        let anchor = RecordingAnchor::default();
        let run = RunId::generate();
        let witness = ReadWitness::issue(&anchor, intent(&run)).unwrap();
        // The intent record is already durable at this point — before any read.
        assert!(matches!(anchor.events()[0], CoreAuditEvent::AccessIntent { .. }));
        witness.complete(ReadOutcome::Success).unwrap();
        assert!(matches!(
            anchor.events()[1],
            CoreAuditEvent::AccessOutcome { outcome: ReadOutcome::Success, .. }
        ));
    }

    #[test]
    fn an_unwritable_audit_log_denies_the_read() {
        let anchor = RecordingAnchor::failing();
        let err = ReadWitness::issue(&anchor, intent(&RunId::generate()));
        assert!(err.is_err(), "no witness may be issued if the intent cannot be recorded");
    }

    #[test]
    fn dropping_a_witness_records_the_abandonment() {
        let anchor = RecordingAnchor::default();
        let run = RunId::generate();
        {
            let _witness = ReadWitness::issue(&anchor, intent(&run)).unwrap();
            // Simulate an early return or a panic between issue and completion.
        }
        let events = anchor.events();
        assert_eq!(events.len(), 2, "an abandoned read must still produce an outcome record");
        assert!(matches!(
            events[1],
            CoreAuditEvent::AccessOutcome { outcome: ReadOutcome::Abandoned, .. }
        ));
    }

    #[test]
    fn a_panicking_read_still_records_an_outcome() {
        let anchor = RecordingAnchor::default();
        let run = RunId::generate();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _witness = ReadWitness::issue(&anchor, intent(&run)).unwrap();
            panic!("backend exploded mid-read");
        }));
        assert!(result.is_err());
        let events = anchor.events();
        assert!(matches!(
            events.last().unwrap(),
            CoreAuditEvent::AccessOutcome { outcome: ReadOutcome::Abandoned, .. }
        ));
    }

    #[test]
    fn completing_a_witness_does_not_also_record_abandonment() {
        let anchor = RecordingAnchor::default();
        let witness = ReadWitness::issue(&anchor, intent(&RunId::generate())).unwrap();
        witness.complete(ReadOutcome::Failed).unwrap();
        assert_eq!(anchor.events().len(), 2, "exactly one intent and one outcome");
    }
}
