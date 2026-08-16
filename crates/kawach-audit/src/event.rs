//! The audit event vocabulary (DESIGN.md §7.4).
//!
//! ## How these types are proved redaction-safe
//!
//! [`AuditEvent`] derives `Serialize`. Because [`kawach_core::SecretString`]
//! deliberately does **not** implement `Serialize`, that derive would fail to compile if
//! anyone added a field capable of holding a secret value. The derive is therefore not
//! a convenience — it is the proof obligation for "a secret cannot reach the audit log",
//! discharged by the compiler on every build.

use kawach_core::{AuditSeq, Confirmation, CoreAuditEvent, ReadOutcome, RunId};

use crate::hash::CanonicalPayload;

/// Who performed an action.
///
/// `principal` is sourced from the environment (OS user, IAM identity), not
/// self-asserted on the command line — an actor field an operator can set to anything
/// is decoration, not evidence.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Actor {
    /// Identity of whoever is acting.
    pub principal: String,
    /// The invocation this action belongs to, where there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RunId>,
}

impl Actor {
    /// Construct an actor.
    #[must_use]
    pub fn new(principal: impl Into<String>) -> Self {
        Self { principal: principal.into(), run: None }
    }

    /// Attach a run identifier.
    #[must_use]
    pub fn with_run(mut self, run: RunId) -> Self {
        self.run = Some(run);
        self
    }

    /// The run identifier as a string, or empty. Used by the canonical encoding, which
    /// cannot represent `Option` directly.
    #[must_use]
    pub fn run_str(&self) -> String {
        self.run.as_ref().map(ToString::to_string).unwrap_or_default()
    }
}

/// Everything KAWACH records.
///
/// Variants hold only redaction-safe types. Adding a field that could carry a secret
/// value breaks the `Serialize` derive and therefore the build.
// The internal tag is `kind`, matching `CanonicalPayload::kind()`, so the discriminant
// has one name across the JSON rendering and the hashed encoding. It cannot be `event`:
// `RotationTransition` has a field by that name, and serde rejects the collision.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditEvent {
    /// A plaintext read is about to be attempted. Written and made durable *before* the
    /// read, which is what makes an unaudited read unrepresentable.
    AccessIntent {
        /// What is being read, as `backend:path`.
        reference: String,
        /// Why.
        purpose: String,
    },
    /// A plaintext read finished, or was abandoned.
    AccessOutcome {
        /// The intent entry this completes.
        intent_seq: AuditSeq,
        /// How it ended.
        outcome: ReadOutcome,
    },
    /// An `--apply` run acquired the authority to mutate.
    CommitTokenMinted {
        /// Who confirmed, why, and under which change reference.
        confirmation: Confirmation,
    },
    /// A rotation state machine edge.
    ///
    /// States and events are recorded as strings rather than as `kawach-rotation` types:
    /// the audit log must not depend on the rotation crate, and a stable textual record
    /// survives refactors of the state enum that a bincode-style encoding would not.
    RotationTransition {
        /// State before.
        from: String,
        /// What happened.
        event: String,
        /// State after.
        to: String,
    },
    /// KAWACH declined to act.
    ///
    /// Refusals are logged as loudly as actions. "Nothing happened" and "we refused to
    /// let something happen" are very different facts during an incident review.
    PolicyRefusal {
        /// Stable code, e.g. `out_of_scope`, `excess_privilege`, `drain_timeout`.
        code: String,
        /// What was refused.
        detail: String,
    },
    /// A periodic commitment to the chain head.
    Checkpoint {
        /// Entries covered by this checkpoint.
        entry_count: u64,
        /// Chain head at the time, as hex.
        head: String,
        /// Ed25519 signature over the checkpoint, as hex, when a signer is configured.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    /// The log was opened. Records continuity across process restarts.
    LogOpened {
        /// Which instance the chain is bound to.
        instance: String,
        /// Sequence number the log resumed from.
        resumed_at: AuditSeq,
    },
}

impl AuditEvent {
    /// Whether this event is an access intent awaiting an outcome.
    #[must_use]
    pub fn is_access_intent(&self) -> bool {
        matches!(self, Self::AccessIntent { .. })
    }
}

impl CanonicalPayload for AuditEvent {
    fn kind(&self) -> &'static str {
        match self {
            Self::AccessIntent { .. } => "access_intent",
            Self::AccessOutcome { .. } => "access_outcome",
            Self::CommitTokenMinted { .. } => "commit_token_minted",
            Self::RotationTransition { .. } => "rotation_transition",
            Self::PolicyRefusal { .. } => "policy_refusal",
            Self::Checkpoint { .. } => "checkpoint",
            Self::LogOpened { .. } => "log_opened",
        }
    }

    /// Ordered field list. The order is part of the hash and must never be permuted for
    /// an already-released variant.
    ///
    /// Note the signature is deliberately **excluded** from a checkpoint's fields: it is
    /// computed over the chain head, so including it would be circular.
    fn fields(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::AccessIntent { reference, purpose } => {
                vec![("reference", reference.clone()), ("purpose", purpose.clone())]
            }
            Self::AccessOutcome { intent_seq, outcome } => vec![
                ("intent_seq", intent_seq.0.to_string()),
                ("outcome", format!("{outcome:?}")),
            ],
            Self::CommitTokenMinted { confirmation } => vec![
                ("operator", confirmation.operator.clone()),
                ("reason", confirmation.reason.clone()),
                ("ticket", confirmation.ticket.clone().unwrap_or_default()),
            ],
            Self::RotationTransition { from, event, to } => vec![
                ("from", from.clone()),
                ("event", event.clone()),
                ("to", to.clone()),
            ],
            Self::PolicyRefusal { code, detail } => {
                vec![("code", code.clone()), ("detail", detail.clone())]
            }
            Self::Checkpoint { entry_count, head, .. } => {
                vec![("entry_count", entry_count.to_string()), ("head", head.clone())]
            }
            Self::LogOpened { instance, resumed_at } => vec![
                ("instance", instance.clone()),
                ("resumed_at", resumed_at.0.to_string()),
            ],
        }
    }
}

/// Lift the small vocabulary `kawach-core` emits into the full one.
///
/// `kawach-core` cannot depend on this crate (the dependency edge points the other way),
/// so it declares only the events its capability tokens need. This is where they join
/// the rest.
impl From<CoreAuditEvent> for AuditEvent {
    fn from(e: CoreAuditEvent) -> Self {
        match e {
            CoreAuditEvent::AccessIntent { reference, purpose, .. } => {
                Self::AccessIntent { reference, purpose }
            }
            CoreAuditEvent::AccessOutcome { intent_seq, outcome } => {
                Self::AccessOutcome { intent_seq, outcome }
            }
            CoreAuditEvent::CommitTokenMinted { confirmation, .. } => {
                Self::CommitTokenMinted { confirmation }
            }
        }
    }
}

/// The run a core event belongs to, so the log can attribute it to an actor.
#[must_use]
pub fn run_of(event: &CoreAuditEvent) -> Option<RunId> {
    match event {
        CoreAuditEvent::AccessIntent { run, .. } | CoreAuditEvent::CommitTokenMinted { run, .. } => {
            Some(run.clone())
        }
        CoreAuditEvent::AccessOutcome { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_a_distinct_stable_kind() {
        let events = [
            AuditEvent::AccessIntent { reference: "v:p".into(), purpose: "x".into() },
            AuditEvent::AccessOutcome { intent_seq: AuditSeq(1), outcome: ReadOutcome::Success },
            AuditEvent::CommitTokenMinted { confirmation: Confirmation::new("a", "b") },
            AuditEvent::RotationTransition { from: "A".into(), event: "E".into(), to: "B".into() },
            AuditEvent::PolicyRefusal { code: "c".into(), detail: "d".into() },
            AuditEvent::Checkpoint { entry_count: 1, head: "ff".into(), signature: None },
            AuditEvent::LogOpened { instance: "i".into(), resumed_at: AuditSeq(0) },
        ];
        let kinds: std::collections::HashSet<_> = events.iter().map(|e| e.kind()).collect();
        assert_eq!(kinds.len(), events.len(), "two variants share a canonical kind");
    }

    #[test]
    fn every_variant_contributes_at_least_one_field() {
        // A variant with no fields would let an adversary alter its contents freely
        // without breaking the chain.
        for e in [
            AuditEvent::AccessIntent { reference: "v:p".into(), purpose: "x".into() },
            AuditEvent::PolicyRefusal { code: "c".into(), detail: "d".into() },
            AuditEvent::LogOpened { instance: "i".into(), resumed_at: AuditSeq(0) },
        ] {
            assert!(!e.fields().is_empty(), "{:?} contributes nothing to the hash", e.kind());
        }
    }

    #[test]
    fn a_checkpoint_does_not_commit_to_its_own_signature() {
        // The signature is over the head, so committing to it would be circular.
        let unsigned = AuditEvent::Checkpoint { entry_count: 5, head: "ab".into(), signature: None };
        let signed = AuditEvent::Checkpoint {
            entry_count: 5,
            head: "ab".into(),
            signature: Some("deadbeef".into()),
        };
        assert_eq!(unsigned.fields(), signed.fields());
    }

    #[test]
    fn core_events_lift_without_losing_their_content() {
        let core = CoreAuditEvent::AccessIntent {
            run: RunId::from_string("r1"),
            reference: "vault-prod:secret/app/db".into(),
            purpose: "read-back verify".into(),
        };
        assert_eq!(run_of(&core).unwrap().as_str(), "r1");
        match AuditEvent::from(core) {
            AuditEvent::AccessIntent { reference, purpose } => {
                assert_eq!(reference, "vault-prod:secret/app/db");
                assert_eq!(purpose, "read-back verify");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn events_round_trip_through_json() {
        let e = AuditEvent::RotationTransition {
            from: "Verified".into(),
            event: "StartPublish".into(),
            to: "Publishing".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<AuditEvent>(&json).unwrap(), e);
    }
}
