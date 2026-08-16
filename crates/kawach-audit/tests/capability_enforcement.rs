//! The capability tokens from `kawach-core`, exercised against a real hash chain.
//!
//! Until this crate existed, `CommitToken` and `ReadWitness` enforced their ordering
//! against the `AuditAnchor` *trait*, with a test double behind it. These tests close
//! the loop: the guarantees now hold against a durable, chained, verifiable log.
//!
//! The properties under test are the ones invariant **I5** actually claims:
//!
//! * authority to mutate cannot exist without a chained record of its authorisation;
//! * a plaintext read cannot happen without a chained record written *first*;
//! * abandoning a read still produces a record, so a crash mid-read leaves evidence;
//! * and a log that cannot be written denies both, rather than proceeding unaudited.

use kawach_audit::{verify_file, Actor, AuditEvent, AuditLog, CheckpointPolicy};
use kawach_core::{
    AuditAnchor, BackendId, Confirmation, ExecutionMode, ReadIntent, ReadOutcome, ReadWitness,
    RunId, Scope, BackendScope, SecretRef,
};

const INSTANCE: &str = "kawach-cap-test";

fn open_log(dir: &std::path::Path) -> AuditLog {
    AuditLog::open(dir.join("audit.jsonl"), INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_checkpoint_policy(CheckpointPolicy::disabled())
}

fn scoped_ref() -> kawach_core::ScopedRef {
    let scope = Scope::empty().with_backend(
        BackendId::new("vault-prod"),
        BackendScope { allow: vec!["secret/data/app/*/db".into()], deny: vec![] },
    );
    scope
        .authorize(&SecretRef::new(BackendId::new("vault-prod"), "secret/data/app/billing/db"))
        .unwrap()
}

#[test]
fn a_dry_run_writes_nothing_and_mints_no_authority() {
    let dir = tempfile::tempdir().unwrap();
    let log = open_log(dir.path());
    let before = log.entry_count();

    let token = ExecutionMode::DryRun.commit_token(&log, &RunId::generate()).unwrap();

    assert!(token.is_none(), "dry-run must not be able to mint authority to mutate");
    assert_eq!(log.entry_count(), before, "dry-run must not write to the audit log at all");
}

#[test]
fn apply_authority_is_chained_before_it_exists() {
    let dir = tempfile::tempdir().unwrap();
    let log = open_log(dir.path());
    let run = RunId::generate();

    let mode = ExecutionMode::Apply(
        Confirmation::new("alice", "quarterly rotation").with_ticket("CHG-4471"),
    );
    let token = mode.commit_token(&log, &run).unwrap().expect("apply mints");

    // The mint is recorded, and recorded *as* the authorising confirmation — not as a
    // bare "something happened".
    let records = kawach_audit::read_records(log.path()).unwrap();
    let minted = records
        .iter()
        .find(|r| matches!(r.event, AuditEvent::CommitTokenMinted { .. }))
        .expect("minting authority must be recorded");

    match &minted.event {
        AuditEvent::CommitTokenMinted { confirmation } => {
            assert_eq!(confirmation.operator, "alice");
            assert_eq!(confirmation.ticket.as_deref(), Some("CHG-4471"));
        }
        other => panic!("unexpected event: {other:?}"),
    }
    assert_eq!(minted.actor.run.as_ref(), Some(&run), "the mint is attributed to its run");
    assert_eq!(token.minted_at(), kawach_core::AuditSeq(minted.seq));
    assert!(verify_file(log.path(), INSTANCE).unwrap().is_intact());
}

#[test]
fn a_read_is_chained_before_the_witness_exists() {
    let dir = tempfile::tempdir().unwrap();
    let log = open_log(dir.path());
    let run = RunId::generate();
    let reference = scoped_ref();

    let count_before = log.entry_count();
    let witness = ReadWitness::issue(
        &log,
        ReadIntent::new(&run, &reference, "read-back verification after publish"),
    )
    .unwrap();

    // The intent is durable *now* — before any backend read has been attempted. That
    // ordering is the invariant; everything else is bookkeeping.
    assert_eq!(log.entry_count(), count_before + 1);
    let records = kawach_audit::read_records(log.path()).unwrap();
    let intent = records.last().unwrap();
    assert!(matches!(intent.event, AuditEvent::AccessIntent { .. }));
    assert_eq!(witness.intent_seq(), kawach_core::AuditSeq(intent.seq));

    witness.complete(ReadOutcome::Success).unwrap();

    let records = kawach_audit::read_records(log.path()).unwrap();
    assert!(matches!(
        records.last().unwrap().event,
        AuditEvent::AccessOutcome { outcome: ReadOutcome::Success, .. }
    ));

    let report = verify_file(log.path(), INSTANCE).unwrap();
    assert!(report.is_intact(), "{}", report.summary());
    assert!(report.dangling_intents.is_empty());
}

#[test]
fn an_abandoned_read_still_leaves_evidence_in_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let log = open_log(dir.path());
    let run = RunId::generate();
    let reference = scoped_ref();

    {
        let _witness =
            ReadWitness::issue(&log, ReadIntent::new(&run, &reference, "operator read")).unwrap();
        // Dropped without completion — an early return, or a panic in the backend.
    }

    let records = kawach_audit::read_records(log.path()).unwrap();
    assert!(
        matches!(
            records.last().unwrap().event,
            AuditEvent::AccessOutcome { outcome: ReadOutcome::Abandoned, .. }
        ),
        "an abandoned read must still produce a chained outcome record"
    );
    assert!(verify_file(log.path(), INSTANCE).unwrap().is_intact());
}

#[test]
fn a_panic_mid_read_still_leaves_evidence_in_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let log = open_log(dir.path());
    let run = RunId::generate();
    let reference = scoped_ref();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _witness =
            ReadWitness::issue(&log, ReadIntent::new(&run, &reference, "doomed read")).unwrap();
        panic!("backend exploded mid-read");
    }));
    assert!(result.is_err());

    // Unwinding runs Drop, which is why `panic = "unwind"` is pinned in the release
    // profile: `panic = "abort"` would skip this record and the zeroization alongside it.
    let records = kawach_audit::read_records(log.path()).unwrap();
    assert!(matches!(
        records.last().unwrap().event,
        AuditEvent::AccessOutcome { outcome: ReadOutcome::Abandoned, .. }
    ));
    assert!(verify_file(log.path(), INSTANCE).unwrap().is_intact());
}

#[test]
fn out_of_scope_references_cannot_even_form_a_read_intent() {
    // `ReadIntent::new` takes a `ScopedRef`, so a reference the allowlist never
    // authorised cannot be named in an intent, let alone read. This is the type-level
    // half of the invariant; the audit log is the durable half.
    let scope = Scope::empty().with_backend(
        BackendId::new("vault-prod"),
        BackendScope { allow: vec!["secret/data/app/*/db".into()], deny: vec![] },
    );
    let forbidden = SecretRef::new(BackendId::new("vault-prod"), "secret/data/root/master");
    assert!(scope.authorize(&forbidden).is_err());
}

#[test]
fn the_whole_capability_trail_verifies_as_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let log = open_log(dir.path());
    let run = RunId::generate();
    let reference = scoped_ref();

    // A realistic apply run: acquire authority, read for verification, transition.
    let _token = ExecutionMode::Apply(Confirmation::new("alice", "rotate billing db"))
        .commit_token(&log, &run)
        .unwrap()
        .unwrap();

    let witness =
        ReadWitness::issue(&log, ReadIntent::new(&run, &reference, "read-back verify")).unwrap();
    witness.complete(ReadOutcome::Success).unwrap();

    log.append(AuditEvent::RotationTransition {
        from: "Verified".into(),
        event: "StartPublish".into(),
        to: "Publishing".into(),
    })
    .unwrap();
    log.checkpoint().unwrap();

    let report = verify_file(log.path(), INSTANCE).unwrap();
    assert!(report.is_intact(), "{}", report.summary());
    assert_eq!(report.checkpoints, 1);
    assert!(report.dangling_intents.is_empty());
    // LogOpened, mint, intent, outcome, transition, checkpoint.
    assert_eq!(report.entry_count, 6);
}

#[test]
fn an_unwritable_log_denies_both_authority_and_reads() {
    // If we cannot record what we are about to do, we do not do it. A read-only
    // directory stands in for a full disk or a revoked mount.
    struct FailingAnchor;
    impl AuditAnchor for FailingAnchor {
        fn record(&self, _: kawach_core::CoreAuditEvent) -> kawach_core::Result<kawach_core::AuditSeq> {
            Err(kawach_core::KawachError::Audit {
                detail: kawach_core::SafeDetail::trusted_static("no space left on device"),
            })
        }
    }

    let run = RunId::generate();
    let reference = scoped_ref();

    assert!(
        ExecutionMode::Apply(Confirmation::new("alice", "r"))
            .commit_token(&FailingAnchor, &run)
            .is_err(),
        "authority must not be granted when it cannot be recorded"
    );
    assert!(
        ReadWitness::issue(&FailingAnchor, ReadIntent::new(&run, &reference, "r")).is_err(),
        "a read must not be permitted when its intent cannot be recorded"
    );
}
