//! The engine's unhappy paths, driven through fault injection.
//!
//! The happy path is one test here. The other fifteen are failures, because a rotation
//! tool that only handles the happy path is dangerous — and because every failure branch
//! must land in a state the model checker already proved safe.
//!
//! Each test asserts on the **world**, not just the return value: is the old credential
//! still live, which value do consumers read, was anything revoked that should not have
//! been. A run that reports `RolledBack` while leaving consumers pointed at a dead
//! credential would pass a return-value assertion and still be an outage.

use std::sync::Arc;

use kawach_audit::{verify_file, Actor, AuditLog, CheckpointPolicy};
use kawach_core::{
    BackendId, BackendScope, Confirmation, CredentialHandle, CredentialKind, ExecutionMode,
    RotationProvider, RunId, Scope, ScopedRef, SecretBackend, SecretRef, VersionId,
};
use kawach_engine::mock::{BackendFaults, MockBackend, MockProvider, MockWorld, ProviderFaults};
use kawach_engine::{RotationEngine, RotationOutcome};
use kawach_rotation::{replay, Journal, Record, RotationEvent, RotationState};

const INSTANCE: &str = "kawach-engine-test";
const OLD: &str = "app_a";

struct Harness {
    _dir: tempfile::TempDir,
    state_dir: std::path::PathBuf,
    audit: AuditLog,
    world: Arc<MockWorld>,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let audit = AuditLog::open(dir.path().join("audit.jsonl"), INSTANCE, Actor::new("alice"))
            .unwrap()
            .with_checkpoint_policy(CheckpointPolicy::disabled());
        Self { _dir: dir, state_dir, audit, world: MockWorld::with_active_credential(OLD) }
    }

    fn scoped(&self) -> ScopedRef {
        Scope::empty()
            .with_backend(
                BackendId::new("mock"),
                BackendScope { allow: vec!["app/db".into()], deny: vec![] },
            )
            .authorize(&SecretRef::new(BackendId::new("mock"), "app/db"))
            .unwrap()
    }

    /// The chain must verify after every scenario, including the ones that escalate.
    fn assert_audit_intact(&self) {
        let report = verify_file(self.audit.path(), INSTANCE).unwrap();
        assert!(report.is_intact(), "audit chain broken: {}", report.summary());
    }

    fn journal_state(&self, run: &RunId) -> RotationState {
        replay(&self.state_dir.join(Journal::file_name(run))).unwrap().state
    }
}

fn apply() -> ExecutionMode {
    ExecutionMode::Apply(Confirmation::new("alice", "test rotation"))
}

/// Run one rotation to completion under the given faults.
async fn run(
    h: &Harness,
    backend_faults: BackendFaults,
    provider_faults: ProviderFaults,
) -> (RotationOutcome, RunId) {
    let backend = MockBackend::vault_like(h.world.clone()).with_faults(backend_faults);
    let provider = MockProvider::new(h.world.clone(), OLD).with_faults(provider_faults);
    let run = RunId::generate();
    let target = provider.target(h.scoped(), run.clone());

    let mut engine =
        RotationEngine::start(&h.state_dir, run.clone(), &backend, &provider, &h.audit).unwrap();
    let outcome = engine.execute(&target, &apply()).await.unwrap();
    (outcome, run)
}

// ---------------------------------------------------------------------------
// The one happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_clean_rotation_completes_and_consumers_read_the_new_credential() {
    let h = Harness::new();
    let (outcome, run) = run(&h, BackendFaults::default(), ProviderFaults::default()).await;

    assert!(outcome.is_completed(), "{}", outcome.summary());
    assert_eq!(outcome.exit_code(), 0);

    let RotationOutcome::Completed { new_handle, .. } = &outcome else { panic!() };
    assert!(h.world.is_live(&new_handle.id), "the new credential must be live");
    assert!(!h.world.is_live(OLD), "the old credential must be revoked");
    assert!(
        h.world.consumers_read_credential(&new_handle.id),
        "consumers must read exactly the value that was provisioned and verified"
    );
    assert_eq!(h.journal_state(&run), RotationState::Completed);
    h.assert_audit_intact();
}

// ---------------------------------------------------------------------------
// Dry run
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_dry_run_performs_no_mutation_whatsoever() {
    let h = Harness::new();
    let backend = MockBackend::vault_like(h.world.clone());
    let provider = MockProvider::new(h.world.clone(), OLD);
    let run = RunId::generate();
    let target = provider.target(h.scoped(), run.clone());

    let mut engine =
        RotationEngine::start(&h.state_dir, run, &backend, &provider, &h.audit).unwrap();
    let outcome = engine.execute(&target, &ExecutionMode::DryRun).await.unwrap();

    // The load-bearing assertion of invariant I7. Not "no writes were intended" — no
    // mutating call reached the world at all, because no CommitToken existed to make one.
    assert_eq!(
        h.world.mutations(),
        Vec::<String>::new(),
        "a dry run mutated the world: {:?}",
        h.world.mutations()
    );
    assert!(h.world.is_live(OLD));
    assert_eq!(h.world.published_version().unwrap().as_str(), "v1");

    let RotationOutcome::DryRun(plan) = &outcome else { panic!("{}", outcome.summary()) };
    assert!(!plan.blocked);
    assert_eq!(plan.steps.len(), 5);
    assert_eq!(plan.active.as_ref().unwrap().id, OLD);
    assert_eq!(outcome.exit_code(), 0);
    h.assert_audit_intact();
}

#[tokio::test]
async fn a_dry_run_surfaces_blocking_preflight_findings() {
    let h = Harness::new();
    let backend = MockBackend::vault_like(h.world.clone());
    let provider = MockProvider::new(h.world.clone(), OLD)
        .with_faults(ProviderFaults { preflight_blocks: true, ..Default::default() });
    let run = RunId::generate();
    let target = provider.target(h.scoped(), run.clone());

    let mut engine =
        RotationEngine::start(&h.state_dir, run, &backend, &provider, &h.audit).unwrap();
    let outcome = engine.execute(&target, &ExecutionMode::DryRun).await.unwrap();

    let RotationOutcome::DryRun(plan) = &outcome else { panic!() };
    assert!(plan.blocked, "a blocking preflight finding must block the plan");
    assert_eq!(plan.blockers().len(), 1);
}

#[tokio::test]
async fn rotating_when_nothing_is_active_is_refused_as_a_bootstrap() {
    // Rotation replaces something. With no active credential there is nothing to fall
    // back to if verification fails, so this is a different and more dangerous
    // operation, and the plan says so rather than proceeding.
    let h = Harness::new();
    let backend = MockBackend::vault_like(h.world.clone());
    let provider = MockProvider::new(h.world.clone(), OLD);
    let run = RunId::generate();
    let mut target = provider.target(h.scoped(), run.clone());
    target.active = None;
    // Nothing live in the world either, so `observe` cannot supply one.
    let provider = MockProvider::new(MockWorld::empty(), "none");

    let mut engine =
        RotationEngine::start(&h.state_dir, run, &backend, &provider, &h.audit).unwrap();
    let outcome = engine.execute(&target, &ExecutionMode::DryRun).await.unwrap();

    let RotationOutcome::DryRun(plan) = &outcome else { panic!() };
    assert!(plan.blocked);
    assert!(plan.blockers().iter().any(|f| f.id == "no_active_credential"));
}

// ---------------------------------------------------------------------------
// Failures before publication: consumers are never touched
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_provision_leaves_the_estate_untouched() {
    let h = Harness::new();
    let (outcome, run) = run(
        &h,
        BackendFaults::default(),
        ProviderFaults { fail_provision: true, ..Default::default() },
    )
    .await;

    assert!(matches!(outcome, RotationOutcome::RolledBack { .. }), "{}", outcome.summary());
    assert!(h.world.is_live(OLD), "the old credential must be untouched");
    assert_eq!(h.world.published_version().unwrap().as_str(), "v1", "nothing was published");
    assert_eq!(h.journal_state(&run), RotationState::RolledBack);
    h.assert_audit_intact();
}

#[tokio::test]
async fn a_failed_verification_revokes_the_new_credential_and_spares_the_old() {
    let h = Harness::new();
    let (outcome, run) = run(
        &h,
        BackendFaults::default(),
        ProviderFaults { verification_fails: true, ..Default::default() },
    )
    .await;

    assert!(matches!(outcome, RotationOutcome::RolledBack { .. }), "{}", outcome.summary());
    assert!(h.world.is_live(OLD), "an unverified rotation must not touch the working credential");
    assert!(!h.world.is_live("cred-1"), "the unverified credential must be revoked");
    assert_eq!(
        h.world.published_version().unwrap().as_str(),
        "v1",
        "an unverified value must never reach consumers"
    );
    assert_eq!(h.journal_state(&run), RotationState::RolledBack);
    h.assert_audit_intact();
}

#[tokio::test]
async fn a_verification_error_is_treated_as_a_failure_not_a_pass() {
    // Connectivity failure during verification must not be optimistically read as
    // success; that would revoke a working credential on no evidence.
    let h = Harness::new();
    let (outcome, _) = run(
        &h,
        BackendFaults::default(),
        ProviderFaults { fail_verify: true, ..Default::default() },
    )
    .await;

    assert!(matches!(outcome, RotationOutcome::RolledBack { .. }), "{}", outcome.summary());
    assert!(h.world.is_live(OLD));
    h.assert_audit_intact();
}

// ---------------------------------------------------------------------------
// Failures after publication: the full mirrored compensation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_publish_runs_the_mirror_and_returns_consumers_to_the_old_value() {
    let h = Harness::new();
    let (outcome, run) = run(
        &h,
        BackendFaults { fail_stage: true, ..Default::default() },
        ProviderFaults::default(),
    )
    .await;

    assert!(matches!(outcome, RotationOutcome::RolledBack { .. }), "{}", outcome.summary());
    assert!(h.world.is_live(OLD), "the old credential must still work");
    assert!(!h.world.is_live("cred-1"), "the new credential must be revoked");
    assert!(
        h.world.consumers_read_credential(OLD),
        "consumers must be reading the original value again"
    );
    assert_eq!(h.journal_state(&run), RotationState::RolledBack);
    h.assert_audit_intact();
}

#[tokio::test]
async fn a_failed_promote_on_a_staging_backend_compensates() {
    // AWS-shaped backend: staging and promotion are distinct, so promotion can fail
    // after a successful stage.
    let h = Harness::new();
    let backend = MockBackend::staging_label_like(h.world.clone())
        .with_faults(BackendFaults { fail_promote: true, ..Default::default() });
    let provider = MockProvider::new(h.world.clone(), OLD);
    let run = RunId::generate();
    let target = provider.target(h.scoped(), run.clone());

    let mut engine =
        RotationEngine::start(&h.state_dir, run.clone(), &backend, &provider, &h.audit).unwrap();
    let outcome = engine.execute(&target, &apply()).await.unwrap();

    assert!(matches!(outcome, RotationOutcome::RolledBack { .. }), "{}", outcome.summary());
    assert!(h.world.is_live(OLD));
    assert!(!h.world.is_live("cred-1"));
    // Promotion never happened, so consumers were never moved off v1 in the first place.
    assert!(h.world.consumers_read_credential(OLD));
    h.assert_audit_intact();
}

// ---------------------------------------------------------------------------
// Refusals: the engine stops rather than risking an outage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_drain_that_never_completes_escalates_and_leaves_both_credentials_valid() {
    let h = Harness::new();
    let (outcome, run) = run(
        &h,
        BackendFaults::default(),
        ProviderFaults { drain_never_completes: true, ..Default::default() },
    )
    .await;

    assert!(outcome.needs_operator(), "{}", outcome.summary());
    assert_eq!(outcome.exit_code(), 2, "escalation must be distinguishable from success or crash");

    // The property that makes this safe: nobody is broken. Consumers on either
    // credential keep working while a human investigates.
    assert!(h.world.is_live(OLD), "the old credential must NOT be revoked on an incomplete drain");
    assert!(h.world.is_live("cred-1"), "the new credential is live and published");
    assert!(h.world.consumers_read_credential("cred-1"));

    let RotationOutcome::NeedsOperator { hint, stopped_at, .. } = &outcome else { panic!() };
    assert_eq!(*stopped_at, RotationState::Draining);
    let hint = hint.as_ref().expect("every escalation carries a hint");
    assert_eq!(hint.code, "drain_timeout");
    assert!(hint.operator_action.contains("resume"));

    assert_eq!(h.journal_state(&run), RotationState::NeedsOperator);
    h.assert_audit_intact();
}

#[tokio::test]
async fn a_drain_error_is_not_read_as_a_completed_drain() {
    // The subtlest way to drop connections: treat "I could not observe the drain" as
    // "the drain finished". The old credential must survive.
    let h = Harness::new();
    let (outcome, _) = run(
        &h,
        BackendFaults::default(),
        ProviderFaults { drain_never_completes: true, ..Default::default() },
    )
    .await;

    assert!(outcome.needs_operator());
    assert!(h.world.is_live(OLD));
}

#[tokio::test]
async fn a_failed_revoke_escalates_rather_than_retrying_forever() {
    let h = Harness::new();
    let (outcome, run) = run(
        &h,
        BackendFaults::default(),
        ProviderFaults { fail_revoke_old: true, ..Default::default() },
    )
    .await;

    assert!(outcome.needs_operator(), "{}", outcome.summary());
    let RotationOutcome::NeedsOperator { hint, .. } = &outcome else { panic!() };
    assert_eq!(hint.as_ref().unwrap().code, "revoke_failed");

    // The rotation itself succeeded; only the cleanup failed. Consumers are on the new
    // credential, and the old one is reported as still live rather than assumed dead.
    assert!(h.world.consumers_read_credential("cred-1"));
    assert!(h.world.is_live(OLD), "a failed revoke must leave the old credential reported live");
    assert_eq!(h.journal_state(&run), RotationState::NeedsOperator);
    h.assert_audit_intact();
}

#[tokio::test]
async fn a_failed_restore_escalates_without_revoking_anything() {
    let h = Harness::new();
    let (outcome, _) = run(
        &h,
        BackendFaults { fail_stage: true, fail_restore: true, ..Default::default() },
        ProviderFaults::default(),
    )
    .await;

    assert!(outcome.needs_operator(), "{}", outcome.summary());
    let RotationOutcome::NeedsOperator { hint, .. } = &outcome else { panic!() };
    assert_eq!(hint.as_ref().unwrap().code, "restore_failed");

    // Compensation could not put the old value back, so neither credential is revoked.
    // Both remain usable; a human decides which way to go.
    assert!(h.world.is_live(OLD));
    assert!(h.world.is_live("cred-1"));
    h.assert_audit_intact();
}

#[tokio::test]
async fn a_stalled_reverse_drain_refuses_to_revoke_the_new_credential() {
    // The mirror's own safety property: consumers that already adopted the new
    // credential must not have it pulled out from under them during a rollback.
    let h = Harness::new();
    let (outcome, _) = run(
        &h,
        BackendFaults { fail_stage: true, ..Default::default() },
        ProviderFaults { reverse_drain_never_completes: true, ..Default::default() },
    )
    .await;

    assert!(outcome.needs_operator(), "{}", outcome.summary());
    let RotationOutcome::NeedsOperator { hint, .. } = &outcome else { panic!() };
    assert_eq!(hint.as_ref().unwrap().code, "reverse_drain_timeout");
    assert!(h.world.is_live("cred-1"), "the new credential must survive a stalled reverse drain");
    assert!(h.world.is_live(OLD));
    h.assert_audit_intact();
}

// ---------------------------------------------------------------------------
// Crash recovery
// ---------------------------------------------------------------------------

/// Journal a run up to `Publishing` and then stop, as a killed process would.
fn crash_during_publish(h: &Harness, run: &RunId) -> CredentialHandle {
    let handle = CredentialHandle::new(CredentialKind::new("mock_ab"), "cred-1");
    let mut journal = Journal::create(&h.state_dir, run).unwrap();
    journal
        .append(Record::RunStarted {
            reference: "mock:app/db".into(),
            kind: CredentialKind::new("mock_ab"),
            mode: "apply".into(),
        })
        .unwrap();

    let mut state = RotationState::START;
    for event in [
        RotationEvent::StartProvision,
        RotationEvent::ProvisionOk,
        RotationEvent::StartVerify,
        RotationEvent::VerifyOk,
        RotationEvent::StartPublish,
    ] {
        let to = kawach_rotation::next(state, event).unwrap();
        journal.record_transition(state, event, to).unwrap();
        state = to;
        if event == RotationEvent::ProvisionOk {
            journal.append(Record::HandleAssigned { handle: handle.clone() }).unwrap();
        }
        if event == RotationEvent::StartPublish {
            // What the engine durably records after entering Publishing and before
            // attempting the write. Without it recovery cannot tell the old published
            // version from the new one and must escalate.
            journal
                .append(Record::PublicationBaseline { previous: Some(VersionId::new("v1")) })
                .unwrap();
        }
    }
    assert_eq!(state, RotationState::Publishing);
    handle
}

#[tokio::test]
async fn recovery_compensates_when_the_plaintext_died_with_the_process() {
    // The write never landed, so reconciliation resolves Publishing -> Verified. But the
    // value existed only in the memory of a dead process, so it can never be published.
    // Resuming forward is impossible; the sound move is to revoke and start over.
    let h = Harness::new();
    let run = RunId::generate();
    let handle = crash_during_publish(&h, &run);
    // The provisioned credential is live in the world, as it would be after a real crash.
    let backend = MockBackend::vault_like(h.world.clone());
    let provider = MockProvider::new(h.world.clone(), OLD);
    let _ = provider
        .provision(
            &provider.target(h.scoped(), run.clone()),
            &kawach_core::CommitToken::for_test(),
        )
        .await
        .unwrap();

    let (mut engine, recovered) =
        RotationEngine::resume(&h.state_dir, run.clone(), &backend, &provider, &h.audit).unwrap();
    assert_eq!(recovered.state, RotationState::Publishing);
    assert!(recovered.needs_reconciliation());
    assert_eq!(recovered.handle.as_ref().unwrap().id, handle.id);

    let target = provider.target(h.scoped(), run.clone());
    let outcome = engine.recover(&target, &recovered, &apply()).await.unwrap();

    assert!(matches!(outcome, RotationOutcome::RolledBack { .. }), "{}", outcome.summary());
    let RotationOutcome::RolledBack { reason, .. } = &outcome else { panic!() };
    assert!(
        reason.contains("lost when the process died") && reason.contains("re-run"),
        "the operator must be told what happened and what to do: {reason}"
    );

    assert!(h.world.is_live(OLD), "the working credential must survive recovery");
    assert!(!h.world.is_live("cred-1"), "the orphaned credential must be revoked");
    assert!(h.world.consumers_read_credential(OLD));
    assert_eq!(h.journal_state(&run), RotationState::RolledBack);
    h.assert_audit_intact();
}

#[tokio::test]
async fn recovery_resumes_forward_when_the_write_had_already_landed() {
    // The publish succeeded and the acknowledgement was lost. Past publication the
    // plaintext is no longer needed — draining and revoking work on handles — so the
    // run can and should finish.
    let h = Harness::new();
    let run = RunId::generate();
    crash_during_publish(&h, &run);

    let backend = MockBackend::vault_like(h.world.clone());
    let provider = MockProvider::new(h.world.clone(), OLD);
    let target = provider.target(h.scoped(), run.clone());

    // Reproduce the world as it would be if the write had landed: the credential exists
    // and its value is what consumers read.
    let new = provider.provision(&target, &kawach_core::CommitToken::for_test()).await.unwrap();
    let version = backend
        .stage(&h.scoped(), new.value, &kawach_core::CommitToken::for_test())
        .await
        .unwrap();

    let (mut engine, mut recovered) =
        RotationEngine::resume(&h.state_dir, run.clone(), &backend, &provider, &h.audit).unwrap();
    // The journal recorded the version before the crash.
    recovered.written_version = Some(version);
    recovered.handle = Some(new.handle.clone());

    let outcome = engine.recover(&target, &recovered, &apply()).await.unwrap();

    assert!(outcome.is_completed(), "{}", outcome.summary());
    assert!(!h.world.is_live(OLD), "the old credential should be revoked on a completed run");
    assert!(h.world.is_live(&new.handle.id));
    assert!(h.world.consumers_read_credential(&new.handle.id));
    assert_eq!(h.journal_state(&run), RotationState::Completed);
    h.assert_audit_intact();
}

#[tokio::test]
async fn recovery_in_dry_run_mode_changes_nothing() {
    let h = Harness::new();
    let run = RunId::generate();
    crash_during_publish(&h, &run);

    let backend = MockBackend::vault_like(h.world.clone());
    let provider = MockProvider::new(h.world.clone(), OLD);
    let target = provider.target(h.scoped(), run.clone());

    let (mut engine, recovered) =
        RotationEngine::resume(&h.state_dir, run, &backend, &provider, &h.audit).unwrap();
    let outcome = engine.recover(&target, &recovered, &ExecutionMode::DryRun).await.unwrap();

    assert!(matches!(outcome, RotationOutcome::DryRun(_)));
    assert_eq!(h.world.mutations(), Vec::<String>::new(), "recovery mutates only under --apply");
    h.assert_audit_intact();
}

// ---------------------------------------------------------------------------
// Cross-cutting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_run_leaves_a_replayable_journal_and_an_intact_chain() {
    // Whatever happens, the two durable records must agree with the outcome. A run whose
    // journal disagrees with reality is unrecoverable by definition.
    let cases: Vec<(&str, BackendFaults, ProviderFaults)> = vec![
        ("clean", BackendFaults::default(), ProviderFaults::default()),
        (
            "verify_fails",
            BackendFaults::default(),
            ProviderFaults { verification_fails: true, ..Default::default() },
        ),
        (
            "publish_fails",
            BackendFaults { fail_stage: true, ..Default::default() },
            ProviderFaults::default(),
        ),
        (
            "drain_stalls",
            BackendFaults::default(),
            ProviderFaults { drain_never_completes: true, ..Default::default() },
        ),
        (
            "revoke_fails",
            BackendFaults::default(),
            ProviderFaults { fail_revoke_old: true, ..Default::default() },
        ),
    ];

    for (name, bf, pf) in cases {
        let h = Harness::new();
        let (outcome, run) = run(&h, bf, pf).await;

        let recovered = replay(&h.state_dir.join(Journal::file_name(&run))).unwrap();
        assert!(recovered.is_complete(), "{name}: journal did not reach a terminal state");
        assert!(!recovered.needs_reconciliation(), "{name}: terminal runs need no reconciliation");

        let expected = match &outcome {
            RotationOutcome::Completed { .. } => RotationState::Completed,
            RotationOutcome::RolledBack { .. } => RotationState::RolledBack,
            RotationOutcome::NeedsOperator { .. } => RotationState::NeedsOperator,
            RotationOutcome::DryRun(_) => unreachable!("apply mode never yields a plan"),
            other => panic!("{name}: unexpected outcome {}", other.summary()),
        };
        assert_eq!(recovered.state, expected, "{name}: journal disagrees with the outcome");
        h.assert_audit_intact();
    }
}

#[tokio::test]
async fn the_old_credential_is_never_revoked_before_the_new_one_is_published() {
    // Safety property S1, asserted against the engine rather than the model: at the
    // moment the old credential dies, consumers must already be reading the new value.
    let h = Harness::new();
    let (outcome, _) = run(&h, BackendFaults::default(), ProviderFaults::default()).await;
    let RotationOutcome::Completed { new_handle, .. } = &outcome else { panic!() };

    let mutations = h.world.mutations();
    let publish_at = mutations.iter().position(|m| m == "backend.stage").expect("published");
    let revoke_at = mutations
        .iter()
        .position(|m| m == &format!("provider.revoke:{OLD}"))
        .expect("old credential revoked");

    assert!(
        publish_at < revoke_at,
        "the old credential was revoked before the new value was published: {mutations:?}"
    );
    assert!(h.world.consumers_read_credential(&new_handle.id));
}
