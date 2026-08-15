//! The rotation state machine (DESIGN.md §6).
//!
//! ## Why the in-flight states exist
//!
//! The obvious machine is `Pending → Provisioned → Verified → Published → Completed`.
//! It cannot answer the only question that matters after a crash: **did the step I was
//! in the middle of actually happen?**
//!
//! So every effectful step is bracketed by an *in-flight* state — `Provisioning` sits
//! between `Pending` and `Provisioned`. The transition *into* the in-flight state is
//! journalled and `fsync`ed **before** the effect is attempted, which makes the
//! in-flight state itself the write-ahead intent record. Recovery then has an exact
//! meaning for each state:
//!
//! * a settled state (`Pending`, `Provisioned`, …) — the world matches the journal;
//!   resume;
//! * an in-flight state (`Provisioning`, `Publishing`, …) — **outcome unknown**; ask
//!   reality via [`crate::state::Observation`] and reconcile.
//!
//! Without the in-flight states, `Pending` is ambiguous between "nothing happened" and
//! "possibly everything happened", and the only safe action is to do nothing, forever.
//!
//! ## Why compensation mirrors the forward path
//!
//! Once the new credential is published, some consumers have already adopted it. A
//! naive rollback that revoked the new credential would break exactly those consumers
//! — the recovery path causing the outage the tool exists to prevent. Compensation is
//! therefore the forward path run backwards, *with a drain on the way*:
//! `RestoringPublication → ReverseDraining → RevokingNew`. At every point in that
//! sequence at least one credential is live and published, which is safety property
//! **S2** in [`crate::safety`].

use core::fmt;

use kawach_core::{KawachError, Result};

/// A state of one rotation run.
///
/// `Copy` and data-free by design: all associated data lives in the journal, which
/// keeps the state space small enough to model-check exhaustively
/// ([`crate::safety`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationState {
    /// Intent recorded; nothing has happened yet.
    Pending,
    /// A provision call is in flight. **Outcome unknown.**
    Provisioning,
    /// The new credential exists in its home system, unpublished.
    Provisioned,
    /// A verification is in flight. Side-effect free, so safe to repeat.
    Verifying,
    /// The new credential is proven to work.
    Verified,
    /// A publish is in flight. **Outcome unknown.**
    Publishing,
    /// Consumers can now read the new value. Both credentials are valid.
    Published,
    /// Waiting for consumers to stop using the old credential.
    Draining,
    /// No consumer is using the old credential.
    Drained,
    /// A revoke of the old credential is in flight. **Outcome unknown.**
    Revoking,

    // ---- compensation (mirror of the forward path, §6.4) ----
    /// Republishing the old value. Safe: the old credential is still live, because we
    /// never revoke before `Drained`.
    RestoringPublication,
    /// Waiting for consumers that adopted the new credential to fall back to the old.
    ReverseDraining,
    /// Revoking the new credential. Reached only once nothing references it.
    RevokingNew,

    // ---- terminal ----
    /// Rotation succeeded: old revoked, new live and published.
    Completed,
    /// Rotation abandoned safely: the estate is as it was before the run.
    RolledBack,
    /// Any automatic action from here could cause an outage, or one already failed.
    /// A human decides, guided by the journal's [`RemediationHint`].
    NeedsOperator,
}

impl RotationState {
    /// The initial state of every run.
    pub const START: Self = Self::Pending;

    /// Whether no further transition is possible.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::RolledBack | Self::NeedsOperator)
    }

    /// Whether an effect was attempted whose outcome is unknown.
    ///
    /// Exactly the states a crash can leave requiring reconciliation.
    #[must_use]
    pub fn is_in_flight(self) -> bool {
        self.pending_step().is_some()
    }

    /// Which effectful step this state is in the middle of, if any.
    #[must_use]
    pub fn pending_step(self) -> Option<Step> {
        Some(match self {
            Self::Provisioning => Step::Provision,
            Self::Verifying => Step::Verify,
            Self::Publishing => Step::Publish,
            Self::Draining => Step::Drain,
            Self::Revoking => Step::RevokeOld,
            Self::RestoringPublication => Step::RestorePublication,
            Self::ReverseDraining => Step::ReverseDrain,
            Self::RevokingNew => Step::RevokeNew,
            _ => return None,
        })
    }

    /// Whether this state is on the compensation path.
    #[must_use]
    pub fn is_compensating(self) -> bool {
        matches!(self, Self::RestoringPublication | Self::ReverseDraining | Self::RevokingNew)
    }

    /// Stable name for journalling, audit records, and error messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Provisioning => "Provisioning",
            Self::Provisioned => "Provisioned",
            Self::Verifying => "Verifying",
            Self::Verified => "Verified",
            Self::Publishing => "Publishing",
            Self::Published => "Published",
            Self::Draining => "Draining",
            Self::Drained => "Drained",
            Self::Revoking => "Revoking",
            Self::RestoringPublication => "RestoringPublication",
            Self::ReverseDraining => "ReverseDraining",
            Self::RevokingNew => "RevokingNew",
            Self::Completed => "Completed",
            Self::RolledBack => "RolledBack",
            Self::NeedsOperator => "NeedsOperator",
        }
    }

    /// Every state, for exhaustive exploration and for `--help` output.
    pub const ALL: [Self; 16] = [
        Self::Pending,
        Self::Provisioning,
        Self::Provisioned,
        Self::Verifying,
        Self::Verified,
        Self::Publishing,
        Self::Published,
        Self::Draining,
        Self::Drained,
        Self::Revoking,
        Self::RestoringPublication,
        Self::ReverseDraining,
        Self::RevokingNew,
        Self::Completed,
        Self::RolledBack,
        Self::NeedsOperator,
    ];
}

impl fmt::Display for RotationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An effectful step, i.e. a call into a provider or a backend.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// `RotationProvider::provision`
    Provision,
    /// `RotationProvider::verify` — read-only, safe to repeat.
    Verify,
    /// `SecretBackend::stage` + `promote`
    Publish,
    /// `RotationProvider::drain` — read-only, safe to repeat.
    Drain,
    /// `RotationProvider::revoke` on the old credential.
    RevokeOld,
    /// `SecretBackend::restore` of the previous value.
    RestorePublication,
    /// `RotationProvider::drain` on the new credential, during compensation.
    ReverseDrain,
    /// `RotationProvider::revoke` on the new credential, during compensation.
    RevokeNew,
}

impl Step {
    /// Whether this step changes the world.
    ///
    /// Read-only steps need no [`kawach_core::CommitToken`] and can be repeated freely
    /// after a crash, which is why their in-flight states reconcile by simply retrying.
    #[must_use]
    pub fn is_mutating(self) -> bool {
        !matches!(self, Self::Verify | Self::Drain | Self::ReverseDrain)
    }
}

/// Which credential consumers currently read.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishedSide {
    /// The pre-rotation value.
    Old,
    /// The new value.
    New,
    /// The backend could not tell us — e.g. it has no read-back capability, or it
    /// returned something matching neither fingerprint.
    Unknown,
}

/// What the world actually looks like, gathered after a crash by calling
/// `RotationProvider::observe` and `SecretBackend::observe_published`.
///
/// This is the input that makes crash recovery *sound* rather than a guess.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct Observation {
    /// Does the home system currently accept the new credential?
    pub new_live: bool,
    /// Does it currently accept the old credential?
    pub old_live: bool,
    /// Which value is published.
    pub published: PublishedSide,
}

/// Everything that can drive a transition.
///
/// Data-free apart from [`RotationEvent::Reconciled`], which keeps the reachable
/// space finite and exhaustively checkable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RotationEvent {
    /// Begin provisioning.
    StartProvision,
    /// A new credential now exists.
    ProvisionOk,
    /// Provisioning failed.
    ProvisionFailed,
    /// Begin verification.
    StartVerify,
    /// The new credential does the application's actual work.
    VerifyOk,
    /// It does not.
    VerifyFailed,
    /// Begin publication.
    StartPublish,
    /// Consumers can now read the new value.
    PublishOk,
    /// Publication failed.
    PublishFailed,
    /// Begin the drain.
    StartDrain,
    /// No consumer is using the old credential.
    DrainComplete,
    /// The drain deadline expired with consumers still on the old credential.
    DrainTimeout,
    /// An operator asked to abandon a rotation that has already published.
    AbortRequested,
    /// Begin revoking the old credential.
    StartRevoke,
    /// The old credential is dead.
    RevokeOk,
    /// It could not be revoked.
    RevokeFailed,
    /// The old value is published again.
    RestoreOk,
    /// It could not be republished.
    RestoreFailed,
    /// Consumers have fallen back to the old credential.
    ReverseDrainComplete,
    /// They have not, and the deadline expired.
    ReverseDrainTimeout,
    /// The new credential is dead.
    RevokeNewOk,
    /// It could not be revoked.
    RevokeNewFailed,
    /// Reality was observed after a crash or a lost acknowledgement.
    Reconciled(Observation),
}

impl RotationEvent {
    /// Stable name for journalling and error messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::StartProvision => "StartProvision",
            Self::ProvisionOk => "ProvisionOk",
            Self::ProvisionFailed => "ProvisionFailed",
            Self::StartVerify => "StartVerify",
            Self::VerifyOk => "VerifyOk",
            Self::VerifyFailed => "VerifyFailed",
            Self::StartPublish => "StartPublish",
            Self::PublishOk => "PublishOk",
            Self::PublishFailed => "PublishFailed",
            Self::StartDrain => "StartDrain",
            Self::DrainComplete => "DrainComplete",
            Self::DrainTimeout => "DrainTimeout",
            Self::AbortRequested => "AbortRequested",
            Self::StartRevoke => "StartRevoke",
            Self::RevokeOk => "RevokeOk",
            Self::RevokeFailed => "RevokeFailed",
            Self::RestoreOk => "RestoreOk",
            Self::RestoreFailed => "RestoreFailed",
            Self::ReverseDrainComplete => "ReverseDrainComplete",
            Self::ReverseDrainTimeout => "ReverseDrainTimeout",
            Self::RevokeNewOk => "RevokeNewOk",
            Self::RevokeNewFailed => "RevokeNewFailed",
            Self::Reconciled(_) => "Reconciled",
        }
    }

    /// Every non-reconciliation event, for exhaustive exploration.
    pub const ALL_PLAIN: [Self; 22] = [
        Self::StartProvision,
        Self::ProvisionOk,
        Self::ProvisionFailed,
        Self::StartVerify,
        Self::VerifyOk,
        Self::VerifyFailed,
        Self::StartPublish,
        Self::PublishOk,
        Self::PublishFailed,
        Self::StartDrain,
        Self::DrainComplete,
        Self::DrainTimeout,
        Self::AbortRequested,
        Self::StartRevoke,
        Self::RevokeOk,
        Self::RevokeFailed,
        Self::RestoreOk,
        Self::RestoreFailed,
        Self::ReverseDrainComplete,
        Self::ReverseDrainTimeout,
        Self::RevokeNewOk,
        Self::RevokeNewFailed,
    ];
}

impl fmt::Display for RotationEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The transition function.
///
/// Total in the sense that it never panics, and partial in the sense that it *rejects*
/// events a state does not accept. Rejection is deliberate: an unexpected event is a
/// bug in the engine, and silently ignoring it is how a rotation ends up half-applied.
///
/// # Errors
/// [`KawachError::IllegalTransition`] naming the state and the event.
pub fn next(state: RotationState, event: RotationEvent) -> Result<RotationState> {
    use RotationEvent as E;
    use RotationState as S;

    // Reconciliation is legal from any state and is handled separately: it is a
    // question about reality, not a step in the protocol.
    if let E::Reconciled(observation) = event {
        return Ok(reconcile(state, observation));
    }

    let to = match (state, event) {
        // ---- forward path ----
        (S::Pending, E::StartProvision) => S::Provisioning,
        (S::Provisioning, E::ProvisionOk) => S::Provisioned,
        (S::Provisioned, E::StartVerify) => S::Verifying,
        (S::Verifying, E::VerifyOk) => S::Verified,
        (S::Verified, E::StartPublish) => S::Publishing,
        (S::Publishing, E::PublishOk) => S::Published,
        (S::Published, E::StartDrain) => S::Draining,
        (S::Draining, E::DrainComplete) => S::Drained,
        (S::Drained, E::StartRevoke) => S::Revoking,
        (S::Revoking, E::RevokeOk) => S::Completed,

        // ---- failures before publication: nothing was ever visible to consumers, so
        // compensation is only "undo the provision". Steps 1-2 of the mirror are
        // vacuous and are skipped rather than executed as no-ops.
        (S::Provisioning, E::ProvisionFailed) | (S::Verifying, E::VerifyFailed) => S::RevokingNew,

        // ---- failures after publication: the full mirror, because consumers may
        // already have adopted the new credential (§6.4).
        (S::Publishing, E::PublishFailed)
        | (S::Published | S::Draining | S::Drained, E::AbortRequested) => S::RestoringPublication,

        // ---- operator abort from a settled state ----
        // Before publication nothing is visible to consumers, so compensation is just
        // the revoke. `Drained` is deliberately grouped with the post-publication arm
        // above: the old credential is unused but still *live*, so restoring is safe
        // and is the only way back.
        (S::Provisioned | S::Verified, E::AbortRequested) => S::RevokingNew,
        (S::Pending, E::AbortRequested) => S::RolledBack,

        // ---- refusals: automatic action from here could cause an outage ----
        //
        // A drain timeout does NOT roll back. Consumers may be split across both
        // credentials; both are valid; the safe move is to keep them that way and page
        // a human. Rolling back automatically would be a *choice* to disrupt whoever
        // already migrated.
        (S::Draining, E::DrainTimeout)
        // The old credential is still live when it should be dead. Retrying forever
        // would hide it; the operator needs to know.
        | (S::Revoking, E::RevokeFailed)
        // We could not put the old value back. Both credentials are still live, so
        // there is no outage — but we are now in a state no further automation should
        // touch.
        | (S::RestoringPublication, E::RestoreFailed)
        // Consumers did not fall back. Revoking the new credential now would break
        // them, which is precisely what compensation exists to avoid.
        | (S::ReverseDraining, E::ReverseDrainTimeout)
        | (S::RevokingNew, E::RevokeNewFailed) => S::NeedsOperator,

        // ---- compensation path ----
        (S::RestoringPublication, E::RestoreOk) => S::ReverseDraining,
        (S::ReverseDraining, E::ReverseDrainComplete) => S::RevokingNew,
        (S::RevokingNew, E::RevokeNewOk) => S::RolledBack,

        // ---- everything else is a bug in the caller ----
        _ => {
            return Err(KawachError::IllegalTransition {
                from: state.name(),
                event: event.name(),
            })
        }
    };
    Ok(to)
}

/// Resolve an unknown-outcome state against observed reality.
///
/// Called on recovery for any state where [`RotationState::is_in_flight`] holds. For
/// settled and terminal states it is the identity: there is nothing to reconcile.
///
/// The rules encode one idea — *believe the world, not the journal* — with a bias
/// toward the state that requires the least additional trust:
///
/// | In-flight state | Observation | Resolution |
/// |---|---|---|
/// | `Provisioning` | new credential exists | `Provisioned` — the call landed |
/// | `Provisioning` | it does not | `Pending` — retry from the top |
/// | `Verifying` | (any) | `Provisioned` — verification has no effects; just redo it |
/// | `Publishing` | backend has the new value | `Published` — the write landed, the ack was lost |
/// | `Publishing` | backend has the old value | `Verified` — the write did not land |
/// | `Draining` | (any) | `Published` — draining has no effects; redo it |
/// | `Revoking` | old credential is dead | `Completed` |
/// | `Revoking` | old credential is live | `Drained` — retry the revoke |
/// | `RestoringPublication` | backend has the old value | `ReverseDraining` |
/// | `RevokingNew` | new credential is dead | `RolledBack` |
///
/// Anything the observation cannot resolve — a backend that reports
/// [`PublishedSide::Unknown`] where the answer matters — escalates rather than
/// guessing.
#[must_use]
pub fn reconcile(state: RotationState, observed: Observation) -> RotationState {
    use RotationState as S;

    match state {
        S::Provisioning => {
            if observed.new_live {
                S::Provisioned
            } else {
                S::Pending
            }
        }
        // Verification and draining are read-only, so an interrupted one can simply be
        // repeated. Return to the state that precedes the step.
        S::Verifying => S::Provisioned,
        S::Draining => S::Published,
        S::Publishing => match observed.published {
            PublishedSide::New => S::Published,
            PublishedSide::Old => S::Verified,
            PublishedSide::Unknown => S::NeedsOperator,
        },
        S::Revoking => {
            if observed.old_live {
                S::Drained
            } else {
                S::Completed
            }
        }
        S::RestoringPublication => match observed.published {
            // The restore landed; continue the mirror.
            PublishedSide::Old => S::ReverseDraining,
            // It did not; the step will be retried from here.
            PublishedSide::New => S::RestoringPublication,
            PublishedSide::Unknown => S::NeedsOperator,
        },
        S::ReverseDraining => match observed.published {
            PublishedSide::Old => S::ReverseDraining,
            // Publication is not where compensation left it. Something outside this
            // run changed the backend; do not compound it.
            _ => S::NeedsOperator,
        },
        S::RevokingNew => {
            if observed.new_live {
                S::RevokingNew
            } else {
                S::RolledBack
            }
        }
        // Settled and terminal states have nothing in flight.
        settled => settled,
    }
}

/// Structured guidance attached to every escalation.
///
/// Every field is either a fixed string or a state/event name — never interpolated
/// foreign text, so an escalation can never become a leak path (DESIGN.md I1).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemediationHint {
    /// Stable machine-readable code, for alert routing.
    pub code: String,
    /// What is true of the world right now.
    pub world_state: String,
    /// What KAWACH declined to do, and why.
    pub refused: String,
    /// What the operator should do.
    pub operator_action: String,
}

impl RemediationHint {
    /// The hint for a given escalation, or `None` if the transition is not an
    /// escalation.
    #[must_use]
    pub fn for_escalation(from: RotationState, event: RotationEvent) -> Option<Self> {
        use RotationEvent as E;
        use RotationState as S;

        let (code, world_state, refused, operator_action) = match (from, event) {
            (S::Draining, E::DrainTimeout) => (
                "drain_timeout",
                "Both credentials are valid. The new value is published; some consumers \
                 are still authenticating with the old credential.",
                "Refused to revoke the old credential. Consumers are still using it, so \
                 revoking would drop their connections.",
                "Find the consumers still on the old credential (the journal records the \
                 last observed session count) and restart or reload them. Then re-run \
                 `kawach rotate resume <run-id>`. There is no outage in the meantime.",
            ),
            (S::Revoking, E::RevokeFailed) => (
                "revoke_failed",
                "The new credential is live and published. The old credential could not \
                 be revoked and may still be usable.",
                "Refused to retry indefinitely, which would leave a credential that \
                 should be dead quietly alive.",
                "Revoke the old credential manually in its home system, then mark the run \
                 complete with `kawach rotate resolve <run-id> --revoked`. Until then, \
                 treat the old credential as live.",
            ),
            (S::RestoringPublication, E::RestoreFailed) => (
                "restore_failed",
                "Both credentials are live. The backend still publishes the new value; \
                 the attempt to republish the old one failed.",
                "Refused to revoke the new credential, which consumers may be using.",
                "Restore the previous version in the backend manually, or abandon the \
                 rollback and complete the rotation forward with \
                 `kawach rotate resume <run-id> --forward`.",
            ),
            (S::ReverseDraining, E::ReverseDrainTimeout) => (
                "reverse_drain_timeout",
                "The old value is published again and both credentials are live. Some \
                 consumers are still using the new credential.",
                "Refused to revoke the new credential while consumers hold it.",
                "Restart the consumers still on the new credential, then resume. \
                 Completing the rotation forward is also safe from here.",
            ),
            (S::RevokingNew, E::RevokeNewFailed) => (
                "revoke_new_failed",
                "The old value is published and live. The new credential could not be \
                 revoked and remains usable.",
                "Refused to leave an unreferenced live credential unreported.",
                "Revoke the new credential manually. It is unreferenced, so this cannot \
                 affect consumers.",
            ),
            (_, E::Reconciled(_)) => (
                "reconciliation_inconclusive",
                "Recovery could not determine which value is published.",
                "Refused to act on an unknown publication state.",
                "Inspect the backend and confirm which value is current, then use \
                 `kawach rotate resolve <run-id>`.",
            ),
            _ => return None,
        };

        Some(Self {
            code: code.to_owned(),
            world_state: world_state.to_owned(),
            refused: refused.to_owned(),
            operator_action: operator_action.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(new_live: bool, old_live: bool, published: PublishedSide) -> Observation {
        Observation { new_live, old_live, published }
    }

    #[test]
    fn the_happy_path_reaches_completed() {
        let mut s = RotationState::START;
        for e in [
            RotationEvent::StartProvision,
            RotationEvent::ProvisionOk,
            RotationEvent::StartVerify,
            RotationEvent::VerifyOk,
            RotationEvent::StartPublish,
            RotationEvent::PublishOk,
            RotationEvent::StartDrain,
            RotationEvent::DrainComplete,
            RotationEvent::StartRevoke,
            RotationEvent::RevokeOk,
        ] {
            s = next(s, e).expect("happy path must be legal");
        }
        assert_eq!(s, RotationState::Completed);
    }

    #[test]
    fn verification_failure_never_touches_consumers() {
        let s = next(RotationState::Verifying, RotationEvent::VerifyFailed).unwrap();
        // Straight to revoking the new credential: nothing was published, so the
        // restore and reverse-drain steps of the mirror are vacuous.
        assert_eq!(s, RotationState::RevokingNew);
        assert_eq!(next(s, RotationEvent::RevokeNewOk).unwrap(), RotationState::RolledBack);
    }

    #[test]
    fn a_post_publication_abort_runs_the_full_mirror() {
        let mut s = next(RotationState::Draining, RotationEvent::AbortRequested).unwrap();
        assert_eq!(s, RotationState::RestoringPublication);
        s = next(s, RotationEvent::RestoreOk).unwrap();
        assert_eq!(s, RotationState::ReverseDraining, "must drain before revoking the new credential");
        s = next(s, RotationEvent::ReverseDrainComplete).unwrap();
        assert_eq!(s, RotationState::RevokingNew);
        assert_eq!(next(s, RotationEvent::RevokeNewOk).unwrap(), RotationState::RolledBack);
    }

    #[test]
    fn a_drain_timeout_escalates_rather_than_revoking_or_rolling_back() {
        let s = next(RotationState::Draining, RotationEvent::DrainTimeout).unwrap();
        assert_eq!(s, RotationState::NeedsOperator);
        let hint = RemediationHint::for_escalation(RotationState::Draining, RotationEvent::DrainTimeout)
            .expect("every escalation carries a hint");
        assert_eq!(hint.code, "drain_timeout");
        assert!(hint.operator_action.contains("resume"));
    }

    #[test]
    fn every_escalating_transition_carries_a_hint() {
        for from in RotationState::ALL {
            for event in RotationEvent::ALL_PLAIN {
                if next(from, event).ok() == Some(RotationState::NeedsOperator) {
                    assert!(
                        RemediationHint::for_escalation(from, event).is_some(),
                        "{from} + {event} escalates with no remediation hint"
                    );
                }
            }
        }
    }

    #[test]
    fn illegal_events_are_rejected_not_ignored() {
        // The classic dangerous bug: jumping straight to revocation.
        let err = next(RotationState::Provisioned, RotationEvent::StartRevoke).unwrap_err();
        assert!(matches!(err, KawachError::IllegalTransition { .. }));
        assert!(format!("{err}").contains("Provisioned"));

        assert!(next(RotationState::Pending, RotationEvent::PublishOk).is_err());
        assert!(next(RotationState::Completed, RotationEvent::StartProvision).is_err());
    }

    #[test]
    fn terminal_states_accept_nothing() {
        for terminal in [RotationState::Completed, RotationState::RolledBack, RotationState::NeedsOperator] {
            assert!(terminal.is_terminal());
            for event in RotationEvent::ALL_PLAIN {
                assert!(next(terminal, event).is_err(), "{terminal} accepted {event}");
            }
        }
    }

    #[test]
    fn in_flight_states_are_exactly_those_with_a_pending_step() {
        let in_flight: Vec<_> = RotationState::ALL.into_iter().filter(|s| s.is_in_flight()).collect();
        assert_eq!(
            in_flight,
            vec![
                RotationState::Provisioning,
                RotationState::Verifying,
                RotationState::Publishing,
                RotationState::Draining,
                RotationState::Revoking,
                RotationState::RestoringPublication,
                RotationState::ReverseDraining,
                RotationState::RevokingNew,
            ]
        );
    }

    #[test]
    fn a_lost_publish_acknowledgement_resolves_forward() {
        // The write landed but the response never arrived.
        let s = reconcile(RotationState::Publishing, obs(true, true, PublishedSide::New));
        assert_eq!(s, RotationState::Published);
    }

    #[test]
    fn a_failed_publish_resolves_backward_to_a_retryable_state() {
        let s = reconcile(RotationState::Publishing, obs(true, true, PublishedSide::Old));
        assert_eq!(s, RotationState::Verified, "the credential is still verified; only the publish is redone");
    }

    #[test]
    fn an_unknown_publication_state_escalates_rather_than_guessing() {
        assert_eq!(
            reconcile(RotationState::Publishing, obs(true, true, PublishedSide::Unknown)),
            RotationState::NeedsOperator
        );
    }

    #[test]
    fn a_crash_during_provisioning_resolves_from_the_world_not_the_journal() {
        assert_eq!(
            reconcile(RotationState::Provisioning, obs(true, true, PublishedSide::Old)),
            RotationState::Provisioned
        );
        assert_eq!(
            reconcile(RotationState::Provisioning, obs(false, true, PublishedSide::Old)),
            RotationState::Pending
        );
    }

    #[test]
    fn a_crash_during_revocation_does_not_assume_success() {
        assert_eq!(
            reconcile(RotationState::Revoking, obs(true, true, PublishedSide::New)),
            RotationState::Drained,
            "the old credential is still live, so the revoke must be retried"
        );
        assert_eq!(
            reconcile(RotationState::Revoking, obs(true, false, PublishedSide::New)),
            RotationState::Completed
        );
    }

    #[test]
    fn read_only_steps_reconcile_by_simply_repeating() {
        // Neither verification nor draining changes anything, so an interrupted one is
        // resolved by returning to the state that precedes it.
        for o in [obs(true, true, PublishedSide::Old), obs(false, false, PublishedSide::Unknown)] {
            assert_eq!(reconcile(RotationState::Verifying, o), RotationState::Provisioned);
            assert_eq!(reconcile(RotationState::Draining, o), RotationState::Published);
        }
        assert!(!Step::Verify.is_mutating());
        assert!(!Step::Drain.is_mutating());
        assert!(Step::Provision.is_mutating());
    }

    #[test]
    fn settled_and_terminal_states_reconcile_to_themselves() {
        let o = obs(true, true, PublishedSide::New);
        for s in RotationState::ALL.into_iter().filter(|s| !s.is_in_flight()) {
            assert_eq!(reconcile(s, o), s, "{s} should have nothing to reconcile");
        }
    }
}
