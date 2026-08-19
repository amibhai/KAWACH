//! The rotation engine: the driver that runs the state machine against real systems.
//!
//! `kawach-rotation` owns the *protocol* — which transitions are legal, and what each
//! state means. This crate owns the *execution*: performing each effect, journalling
//! before and after, writing audit records, and turning infrastructure failures into
//! state machine events rather than exceptions.
//!
//! ## The loop
//!
//! ```text
//! while not terminal:
//!     settled   -> emit the Start* event, journal it, enter the in-flight state
//!     in-flight -> perform the effect, journal the outcome event
//! ```
//!
//! That is the whole engine. The transition *into* an in-flight state is journalled and
//! `fsync`ed **before** the effect is attempted, which is what makes the in-flight state
//! a write-ahead intent record (DESIGN.md §6.3).
//!
//! ## Failures are events, not errors
//!
//! A provider returning `Err` from `provision` is not an engine error — it is a
//! `ProvisionFailed` event, which the state machine already knows how to compensate for.
//! Only failures that break the *protocol itself* — a journal that cannot be written, an
//! audit record that cannot be made durable — propagate as errors, because at that point
//! we can no longer promise the run is recoverable and must stop touching things.
//!
//! ## The consequence of holding plaintext only in memory
//!
//! A new credential's value lives in memory and nowhere else. So if the process dies
//! after provisioning but before publishing, **the value is gone and unrecoverable**:
//! the credential exists in the target system, but nothing knows its password.
//!
//! Recovery therefore cannot resume forward from `Provisioned` or `Verified`. It must
//! compensate — revoke the orphaned credential and let the operator start again. The
//! state machine already permits exactly this (`AbortRequested` from either state), and
//! [`RotationEngine::recover`] uses it. Past publication the plaintext is no longer
//! needed, since draining and revoking work on handles, so recovery from `Published`
//! onward resumes forward normally.

use kawach_audit::{AuditEvent, AuditLog};
use kawach_core::{
    CommitToken, CredentialHandle, Deadline, ExecutionMode, KawachError, NewCredential, Preflight,
    PreflightFinding, Result, RotationProvider, RotationTarget, RunId, SafeDetail, SecretBackend,
    SecretString, VersionId,
};
use kawach_rotation::{
    next, reconcile, Journal, Observation, PublishedSide, RecoveredRun, Record, RemediationHint,
    RotationEvent, RotationState, Step,
};

use crate::outcome::{PlannedStep, RotationOutcome, RotationPlan};

/// Mutable state carried through one run.
///
/// Holds a [`SecretString`], so this type has no `Serialize` impl and cannot be
/// journalled, logged, or shipped anywhere — which is the intent. What *is* journalled
/// is the handle and the version, neither of which is secret.
struct RunContext {
    old_handle: Option<CredentialHandle>,
    new_handle: Option<CredentialHandle>,
    new_value: Option<SecretString>,
    previous_version: Option<VersionId>,
    written_version: Option<VersionId>,
    failure_reason: Option<String>,
}

impl RunContext {
    fn new(target: &RotationTarget) -> Self {
        Self {
            old_handle: target.active.clone(),
            new_handle: None,
            new_value: None,
            previous_version: None,
            written_version: None,
            failure_reason: None,
        }
    }
}

/// Drives one rotation from `Pending` to a terminal state.
pub struct RotationEngine<'a> {
    backend: &'a dyn SecretBackend,
    provider: &'a dyn RotationProvider,
    audit: &'a AuditLog,
    journal: Journal,
    run: RunId,
}

impl<'a> RotationEngine<'a> {
    /// Begin a new run, creating its journal in `state_dir`.
    ///
    /// # Errors
    /// [`KawachError::Journal`] if a journal for this run already exists — which would
    /// mean forking the history of a single run.
    pub fn start(
        state_dir: &std::path::Path,
        run: RunId,
        backend: &'a dyn SecretBackend,
        provider: &'a dyn RotationProvider,
        audit: &'a AuditLog,
    ) -> Result<Self> {
        let journal = Journal::create(state_dir, &run)?;
        Ok(Self { backend, provider, audit, journal, run })
    }

    /// Reopen an interrupted run for recovery.
    ///
    /// # Errors
    /// [`KawachError::Journal`] if the journal is missing or inconsistent.
    pub fn resume(
        state_dir: &std::path::Path,
        run: RunId,
        backend: &'a dyn SecretBackend,
        provider: &'a dyn RotationProvider,
        audit: &'a AuditLog,
    ) -> Result<(Self, RecoveredRun)> {
        let (journal, recovered) = Journal::reopen(state_dir, &run)?;
        Ok((Self { backend, provider, audit, journal, run }, recovered))
    }

    /// The run this engine is driving.
    #[must_use]
    pub fn run(&self) -> &RunId {
        &self.run
    }

    /// Plan or perform a rotation, according to `mode`.
    ///
    /// In [`ExecutionMode::DryRun`] this returns a plan and performs no effects — it
    /// cannot, since no [`CommitToken`] exists to pass to a mutating method.
    ///
    /// # Errors
    /// Journal or audit failures. Provider and backend failures are handled by the state
    /// machine and reported through [`RotationOutcome`], not as errors.
    pub async fn execute(
        &mut self,
        target: &RotationTarget,
        mode: &ExecutionMode,
    ) -> Result<RotationOutcome> {
        self.journal.append(Record::RunStarted {
            reference: target.reference.to_string(),
            kind: target.kind.clone(),
            mode: if mode.is_apply() { "apply".into() } else { "dry-run".into() },
        })?;

        match mode.commit_token(self.audit, &self.run)? {
            None => Ok(RotationOutcome::DryRun(Box::new(self.plan(target).await?))),
            Some(commit) => {
                let mut ctx = RunContext::new(target);
                self.drive(RotationState::START, target, &mut ctx, &commit).await
            }
        }
    }

    /// Recover an interrupted run.
    ///
    /// Reconciles any unknown-outcome state against observed reality, then either
    /// resumes forward or compensates. See the module docs for why a crash between
    /// provisioning and publishing forces compensation rather than resumption.
    ///
    /// # Errors
    /// Journal or audit failures.
    pub async fn recover(
        &mut self,
        target: &RotationTarget,
        recovered: &RecoveredRun,
        mode: &ExecutionMode,
    ) -> Result<RotationOutcome> {
        let Some(commit) = mode.commit_token(self.audit, &self.run)? else {
            // Recovery mutates, so it is refused in dry-run like any other mutation. The
            // plan still tells the operator what would happen.
            return Ok(RotationOutcome::DryRun(Box::new(self.plan(target).await?)));
        };

        let mut ctx = RunContext::new(target);
        ctx.new_handle = recovered.handle.clone();
        ctx.previous_version = recovered.previous_version.clone();
        ctx.written_version = recovered.written_version.clone();

        let mut state = recovered.state;

        // Resolve an unknown-outcome state by asking reality rather than assuming.
        if state.is_in_flight() {
            let observed = self.observe(target, &ctx).await?;
            let resolved = reconcile(state, observed);
            self.journal.record_transition(state, RotationEvent::Reconciled(observed), resolved)?;
            self.audit.append(AuditEvent::RotationTransition {
                from: state.name().to_owned(),
                event: "Reconciled".to_owned(),
                to: resolved.name().to_owned(),
            })?;
            state = resolved;
        }

        // The plaintext died with the process. A credential exists in the target system
        // that nobody knows the password for, so the only sound move is to revoke it and
        // let the operator start again.
        if matches!(state, RotationState::Provisioned | RotationState::Verified) {
            // One message, set once: `note_refusal` records it in the audit log and
            // carries it through to the outcome the operator sees.
            self.note_refusal(
                "value_lost_on_crash",
                "the new credential's value was lost when the process died, because \
                 plaintext is held only in memory; it can never be published, so it is being \
                 revoked and the rotation must be re-run",
                &mut ctx,
            )?;
            state = self.transition(state, RotationEvent::AbortRequested)?;
        }

        self.drive(state, target, &mut ctx, &commit).await
    }

    // -----------------------------------------------------------------------
    // Dry run
    // -----------------------------------------------------------------------

    /// Read-only traversal. Calls only non-mutating trait methods.
    async fn plan(&self, target: &RotationTarget) -> Result<RotationPlan> {
        let mut preflight = self.provider.preflight(target).await.unwrap_or_else(|e| Preflight {
            findings: vec![PreflightFinding {
                id: "preflight_unavailable".into(),
                blocking: true,
                detail: format!("provider preflight could not run: {e}"),
            }],
        });

        let world = self.provider.observe(target).await.ok();
        let active = target.active.clone().or_else(|| {
            world
                .as_ref()
                .and_then(|w| w.credentials.iter().find(|c| c.live).map(|c| c.handle.clone()))
        });

        // Rotating means replacing something. If nothing is there to replace, this is a
        // bootstrap — a different operation with different safety properties, because
        // there is no working credential to fall back to if verification fails.
        if active.is_none() {
            preflight.findings.push(PreflightFinding {
                id: "no_active_credential".into(),
                blocking: true,
                detail: "no active credential could be identified; KAWACH rotates existing \
                         credentials and will not bootstrap a first one, because there would \
                         be no working credential to fall back to if the new one failed"
                    .into(),
            });
        }

        let steps = vec![
            PlannedStep {
                step: Step::Provision,
                description: format!("provision a new {} credential (the inactive side)", target.kind),
                mutating: true,
            },
            PlannedStep {
                step: Step::Verify,
                description: "prove the new credential can do the application's work, on a fresh \
                              connection"
                    .into(),
                mutating: false,
            },
            PlannedStep {
                step: Step::Publish,
                description: format!("publish the new value to {}", target.reference),
                mutating: true,
            },
            PlannedStep {
                step: Step::Drain,
                description: format!(
                    "wait for consumers to stop using the old credential ({:?}, deadline {}s)",
                    target.drain.strategy,
                    target.drain.deadline.as_secs()
                ),
                mutating: false,
            },
            PlannedStep {
                step: Step::RevokeOld,
                description: "revoke the old credential".into(),
                mutating: true,
            },
        ];

        Ok(RotationPlan {
            run: self.run.clone(),
            reference: target.reference.to_string(),
            kind: target.kind.clone(),
            active,
            blocked: preflight.is_blocked(),
            preflight,
            steps,
        })
    }

    // -----------------------------------------------------------------------
    // The loop
    // -----------------------------------------------------------------------

    async fn drive(
        &mut self,
        mut state: RotationState,
        target: &RotationTarget,
        ctx: &mut RunContext,
        commit: &CommitToken,
    ) -> Result<RotationOutcome> {
        let mut last_escalation: Option<RemediationHint> = None;
        let mut escalated_from = state;

        while !state.is_terminal() {
            let event = if state.is_in_flight() {
                self.perform(state, target, ctx, commit).await?
            } else {
                start_event(state).ok_or(KawachError::IllegalTransition {
                    from: state.name(),
                    event: "no start event",
                })?
            };

            if let Some(hint) = RemediationHint::for_escalation(state, event) {
                last_escalation = Some(hint.clone());
                escalated_from = state;
                self.journal.append(Record::Escalation { hint })?;
            }

            state = self.transition(state, event)?;
        }

        self.journal.append(Record::RunFinished { terminal: state })?;

        Ok(match state {
            RotationState::Completed => RotationOutcome::Completed {
                run: self.run.clone(),
                new_handle: ctx.new_handle.clone().ok_or(KawachError::Journal {
                    detail: SafeDetail::trusted_static(
                        "completed without recording the new credential's handle",
                    ),
                })?,
                version: ctx.written_version.clone(),
            },
            RotationState::RolledBack => RotationOutcome::RolledBack {
                run: self.run.clone(),
                reason: ctx
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| "the rotation was abandoned".to_owned()),
            },
            _ => RotationOutcome::NeedsOperator {
                run: self.run.clone(),
                stopped_at: escalated_from,
                hint: last_escalation,
            },
        })
    }

    /// Apply one transition, making it durable in the journal and the audit log before
    /// returning. Journal first: it is the recovery source of truth.
    fn transition(&mut self, from: RotationState, event: RotationEvent) -> Result<RotationState> {
        let to = next(from, event)?;
        self.journal.record_transition(from, event, to)?;
        self.audit.append(AuditEvent::RotationTransition {
            from: from.name().to_owned(),
            event: event.name().to_owned(),
            to: to.name().to_owned(),
        })?;
        Ok(to)
    }

    /// Perform the effect an in-flight state is in the middle of, and report the event
    /// that results.
    async fn perform(
        &mut self,
        state: RotationState,
        target: &RotationTarget,
        ctx: &mut RunContext,
        commit: &CommitToken,
    ) -> Result<RotationEvent> {
        let Some(step) = state.pending_step() else {
            return Err(KawachError::IllegalTransition {
                from: state.name(),
                event: "perform on a settled state",
            });
        };

        Ok(match step {
            Step::Provision => match self.provider.provision(target, commit).await {
                Ok(NewCredential { handle, value }) => {
                    // The handle is journalled immediately: it is what makes the revoke
                    // idempotent if we die before the value is ever used.
                    self.journal.append(Record::HandleAssigned { handle: handle.clone() })?;
                    ctx.new_handle = Some(handle);
                    ctx.new_value = Some(value);
                    RotationEvent::ProvisionOk
                }
                Err(e) => {
                    self.note_failure("provision", &e, ctx)?;
                    RotationEvent::ProvisionFailed
                }
            },

            Step::Verify => {
                let Some(value) = ctx.new_value.as_ref() else {
                    self.note_refusal("verify_without_value", "no credential value is held", ctx)?;
                    return Ok(RotationEvent::VerifyFailed);
                };
                match self.provider.verify(target, value).await {
                    Ok(report) if report.passed => RotationEvent::VerifyOk,
                    Ok(report) => {
                        let failed: Vec<_> = report.failures().iter().map(|c| c.id.clone()).collect();
                        self.note_refusal(
                            "verification_failed",
                            &format!("checks failed: {}", failed.join(", ")),
                            ctx,
                        )?;
                        RotationEvent::VerifyFailed
                    }
                    Err(e) => {
                        self.note_failure("verify", &e, ctx)?;
                        RotationEvent::VerifyFailed
                    }
                }
            }

            Step::Publish => {
                // Capture what is published now, so compensation knows what to restore,
                // and make it durable BEFORE the write. A baseline held only in memory
                // is lost in precisely the crash that makes it necessary, after which
                // recovery cannot tell the old published version from the new one.
                match self.backend.observe_published(&target.reference).await {
                    Ok(published) => {
                        ctx.previous_version = published.current_version;
                        self.journal.append(Record::PublicationBaseline {
                            previous: ctx.previous_version.clone(),
                        })?;
                    }
                    Err(e) => {
                        self.note_failure("observe_published", &e, ctx)?;
                        return Ok(RotationEvent::PublishFailed);
                    }
                }

                let Some(value) = ctx.new_value.take() else {
                    self.note_refusal("publish_without_value", "no credential value is held", ctx)?;
                    return Ok(RotationEvent::PublishFailed);
                };

                match self.backend.stage(&target.reference, value, commit).await {
                    Ok(version) => {
                        // Backends without atomic promotion made the value current with
                        // the write itself; calling promote would be a meaningless
                        // second write.
                        if self.backend.capabilities().atomic_promote {
                            if let Err(e) =
                                self.backend.promote(&target.reference, &version, commit).await
                            {
                                self.note_failure("promote", &e, ctx)?;
                                return Ok(RotationEvent::PublishFailed);
                            }
                        }
                        self.journal.append(Record::VersionAssigned {
                            previous: ctx.previous_version.clone(),
                            written: version.clone(),
                        })?;
                        ctx.written_version = Some(version);
                        RotationEvent::PublishOk
                    }
                    Err(e) => {
                        self.note_failure("stage", &e, ctx)?;
                        RotationEvent::PublishFailed
                    }
                }
            }

            Step::Drain => {
                let Some(old) = ctx.old_handle.clone() else {
                    // Nothing to drain from, so nothing can still be using it.
                    return Ok(RotationEvent::DrainComplete);
                };
                match self.provider.drain(target, &old, Deadline::in_(target.drain.deadline)).await
                {
                    Ok(report) if report.complete => RotationEvent::DrainComplete,
                    Ok(report) => {
                        let remaining = report
                            .remaining_sessions
                            .map_or_else(|| "an unknown number of".to_owned(), |n| n.to_string());
                        self.note_refusal(
                            "drain_incomplete",
                            &format!("{remaining} session(s) still using the old credential"),
                            ctx,
                        )?;
                        RotationEvent::DrainTimeout
                    }
                    // A drain we cannot observe is not a drain that completed. Treating
                    // an error as success here is precisely how a rotation tool drops
                    // connections.
                    Err(e) => {
                        self.note_failure("drain", &e, ctx)?;
                        RotationEvent::DrainTimeout
                    }
                }
            }

            Step::RevokeOld => {
                let Some(old) = ctx.old_handle.clone() else {
                    return Ok(RotationEvent::RevokeOk);
                };
                match self.provider.revoke(target, &old, commit).await {
                    Ok(()) => RotationEvent::RevokeOk,
                    Err(e) => {
                        self.note_failure("revoke", &e, ctx)?;
                        RotationEvent::RevokeFailed
                    }
                }
            }

            Step::RestorePublication => {
                let Some(previous) = ctx.previous_version.clone() else {
                    // Nothing was published before this run, so there is nothing to put
                    // back; compensation continues to revoking the new credential.
                    return Ok(RotationEvent::RestoreOk);
                };
                // Restoring may require reading the prior value (Vault KV v2 has no
                // native version promotion), so it is performed under an audited
                // witness like any other plaintext access.
                let witness = kawach_core::ReadWitness::issue(
                    self.audit,
                    kawach_core::ReadIntent::new(
                        &target.run,
                        &target.reference,
                        "restore the previous value during rotation compensation",
                    ),
                )?;
                let restored = self.backend.restore(&target.reference, &previous, commit, &witness).await;
                witness.complete(if restored.is_ok() {
                    kawach_core::ReadOutcome::Success
                } else {
                    kawach_core::ReadOutcome::Failed
                })?;
                match restored {
                    Ok(()) => RotationEvent::RestoreOk,
                    Err(e) => {
                        self.note_failure("restore", &e, ctx)?;
                        RotationEvent::RestoreFailed
                    }
                }
            }

            Step::ReverseDrain => {
                let Some(new) = ctx.new_handle.clone() else {
                    return Ok(RotationEvent::ReverseDrainComplete);
                };
                match self.provider.drain(target, &new, Deadline::in_(target.drain.deadline)).await
                {
                    Ok(report) if report.complete => RotationEvent::ReverseDrainComplete,
                    Ok(_) => {
                        self.note_refusal(
                            "reverse_drain_incomplete",
                            "consumers are still using the new credential; it cannot be revoked",
                            ctx,
                        )?;
                        RotationEvent::ReverseDrainTimeout
                    }
                    Err(e) => {
                        self.note_failure("reverse_drain", &e, ctx)?;
                        RotationEvent::ReverseDrainTimeout
                    }
                }
            }

            Step::RevokeNew => {
                let Some(new) = ctx.new_handle.clone() else {
                    return Ok(RotationEvent::RevokeNewOk);
                };
                match self.provider.revoke(target, &new, commit).await {
                    Ok(()) => RotationEvent::RevokeNewOk,
                    Err(e) => {
                        self.note_failure("revoke_new", &e, ctx)?;
                        RotationEvent::RevokeNewFailed
                    }
                }
            }
        })
    }

    /// Gather reality for reconciliation.
    async fn observe(&self, target: &RotationTarget, ctx: &RunContext) -> Result<Observation> {
        let world = self.provider.observe(target).await?;
        let published = self.backend.observe_published(&target.reference).await?;

        let new_live = ctx.new_handle.as_ref().is_some_and(|h| world.is_live(h));
        let old_live = ctx.old_handle.as_ref().is_some_and(|h| world.is_live(h));

        // Which value is published is decided by version identity. A backend that cannot
        // tell us reports Unknown, and the state machine escalates rather than guessing.
        let side = match (&published.current_version, &ctx.written_version, &ctx.previous_version) {
            (Some(current), Some(written), _) if current == written => PublishedSide::New,
            (Some(current), _, Some(previous)) if current == previous => PublishedSide::Old,
            (None, _, None) => PublishedSide::Old,
            _ => PublishedSide::Unknown,
        };

        Ok(Observation { new_live, old_live, published: side })
    }

    fn note_failure(
        &mut self,
        operation: &str,
        error: &KawachError,
        ctx: &mut RunContext,
    ) -> Result<()> {
        // `KawachError`'s Display is already scrubbed through `SafeDetail`, so this
        // cannot become a leak path.
        let detail = format!("{operation} failed: {error}");
        ctx.failure_reason = Some(detail.clone());
        self.audit
            .append(AuditEvent::PolicyRefusal { code: format!("{operation}_failed"), detail })?;
        Ok(())
    }

    fn note_refusal(&mut self, code: &str, detail: &str, ctx: &mut RunContext) -> Result<()> {
        ctx.failure_reason = Some(detail.to_owned());
        self.audit.append(AuditEvent::PolicyRefusal {
            code: code.to_owned(),
            detail: detail.to_owned(),
        })?;
        Ok(())
    }
}

/// The event that moves a settled state into its next in-flight state.
fn start_event(state: RotationState) -> Option<RotationEvent> {
    Some(match state {
        RotationState::Pending => RotationEvent::StartProvision,
        RotationState::Provisioned => RotationEvent::StartVerify,
        RotationState::Verified => RotationEvent::StartPublish,
        RotationState::Published => RotationEvent::StartDrain,
        RotationState::Drained => RotationEvent::StartRevoke,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_settled_non_terminal_state_has_a_start_event() {
        // Otherwise the engine would stall in a state it cannot leave. The model
        // checker's liveness property S4 would not catch this: it explores the protocol,
        // not the driver.
        for state in RotationState::ALL {
            if state.is_terminal() || state.is_in_flight() {
                continue;
            }
            assert!(
                start_event(state).is_some(),
                "{state} is settled and non-terminal but the engine cannot leave it"
            );
        }
    }

    #[test]
    fn start_events_are_legal_transitions() {
        for state in RotationState::ALL {
            if let Some(event) = start_event(state) {
                assert!(next(state, event).is_ok(), "{state} rejects its own start event");
            }
        }
    }
}
