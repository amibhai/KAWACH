//! What a rotation run produces: a dry-run plan, or the terminal result of an apply.

use kawach_core::{CredentialHandle, CredentialKind, Preflight, RunId, VersionId};
use kawach_rotation::{RemediationHint, RotationState, Step};

/// One step the engine would take, as reported by a dry run.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PlannedStep {
    /// Which effectful step.
    pub step: Step,
    /// What it would do, in the operator's terms.
    pub description: String,
    /// Whether it changes the world. Dry runs perform none of these.
    pub mutating: bool,
}

/// The result of planning a rotation without performing it.
///
/// A dry run is not merely "the apply path with the writes skipped" — that design
/// inevitably drifts. It is a distinct, read-only traversal that calls only the
/// non-mutating trait methods (`preflight`, `observe`, `describe`), none of which take a
/// [`kawach_core::CommitToken`]. A dry run therefore *cannot* mutate: it holds no
/// authority to.
#[derive(Clone, Debug, serde::Serialize)]
pub struct RotationPlan {
    /// Which run produced this plan.
    pub run: RunId,
    /// Where the value is published, as `backend:path`.
    pub reference: String,
    /// Which provider handles it.
    pub kind: CredentialKind,
    /// The credential currently in use, if one could be observed.
    pub active: Option<CredentialHandle>,
    /// Provider readiness findings.
    pub preflight: Preflight,
    /// The steps an apply would take, in order.
    pub steps: Vec<PlannedStep>,
    /// Whether anything blocks the rotation from proceeding.
    pub blocked: bool,
}

impl RotationPlan {
    /// The blocking preflight findings, if any.
    #[must_use]
    pub fn blockers(&self) -> Vec<&kawach_core::PreflightFinding> {
        self.preflight.findings.iter().filter(|f| f.blocking).collect()
    }
}

/// How a rotation ended.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RotationOutcome {
    /// Nothing was changed; here is what an apply would do.
    DryRun(Box<RotationPlan>),
    /// The new credential is live and published; the old one is revoked.
    Completed {
        /// Which run.
        run: RunId,
        /// The credential now in use.
        new_handle: CredentialHandle,
        /// The version consumers now read.
        version: Option<VersionId>,
    },
    /// The rotation was abandoned and the estate is as it was before the run.
    RolledBack {
        /// Which run.
        run: RunId,
        /// Why the rotation was abandoned.
        reason: String,
    },
    /// Automatic action from here could cause an outage, or one already failed.
    ///
    /// **Not an error.** It is a deliberate, successful refusal: the engine reached a
    /// state where the safe move is to stop and hand over to a human, and it recorded
    /// exactly why. Treating this as a failure would push operators toward retry loops,
    /// which is the behaviour this design exists to prevent.
    NeedsOperator {
        /// Which run.
        run: RunId,
        /// The state the machine stopped in before escalating.
        stopped_at: RotationState,
        /// Structured guidance: what is true, what was refused, what to do.
        hint: Option<RemediationHint>,
    },
}

impl RotationOutcome {
    /// Whether the rotation reached its goal.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// Whether a human must now act.
    #[must_use]
    pub fn needs_operator(&self) -> bool {
        matches!(self, Self::NeedsOperator { .. })
    }

    /// Process exit code for the CLI.
    ///
    /// `NeedsOperator` is deliberately distinct from both success and failure: an
    /// operator's alerting should be able to tell "rotation is incomplete and waiting
    /// for a human" apart from "the tool crashed".
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::DryRun(_) | Self::Completed { .. } => 0,
            Self::RolledBack { .. } => 1,
            Self::NeedsOperator { .. } => 2,
        }
    }

    /// One-line human summary.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::DryRun(plan) => format!(
                "dry run: {} step(s) planned for {}{}",
                plan.steps.len(),
                plan.reference,
                if plan.blocked { " (BLOCKED)" } else { "" }
            ),
            Self::Completed { new_handle, .. } => {
                format!("rotation complete; {new_handle} is live, previous credential revoked")
            }
            Self::RolledBack { reason, .. } => format!("rolled back safely: {reason}"),
            Self::NeedsOperator { stopped_at, hint, .. } => match hint {
                Some(h) => format!("NEEDS OPERATOR at {stopped_at}: {}", h.world_state),
                None => format!("NEEDS OPERATOR at {stopped_at}"),
            },
        }
    }
}
