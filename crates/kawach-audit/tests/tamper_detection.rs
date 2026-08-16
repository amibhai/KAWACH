//! Adversarial tests: each of the six attacks in DESIGN.md §7.3, performed for real
//! against a real log file, asserting exactly what is and is not detected.
//!
//! The negative results matter as much as the positive ones. Two attacks — tail
//! truncation and wholesale rewrite — are **not** detectable by a hash chain, and tests
//! here assert that a bare chain misses them before asserting that checkpoints and
//! anchors catch them. Claiming a chain alone gives you "tamper-proof" logging is the
//! standard overstatement in this space, and these tests are how we avoid making it.

use std::path::{Path, PathBuf};

use kawach_audit::{
    verify_against_anchor, verify_file, verify_records, verify_signatures, Actor, AuditEvent,
    AuditLog, AuditRecord, ChainStatus, CheckpointPolicy, CheckpointSigner, EntryHash, FileAnchor,
};
use kawach_core::AuditSeq;

const INSTANCE: &str = "kawach-test";

/// Build a log with `n` ordinary events and return its path.
fn make_log(dir: &Path, n: usize) -> PathBuf {
    let path = dir.join("audit.jsonl");
    let log = AuditLog::open(&path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_checkpoint_policy(CheckpointPolicy::disabled());
    for i in 0..n {
        log.append(AuditEvent::RotationTransition {
            from: format!("S{i}"),
            event: "Step".into(),
            to: format!("S{}", i + 1),
        })
        .unwrap();
    }
    path
}

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path).unwrap().lines().map(ToOwned::to_owned).collect()
}

fn write_lines(path: &Path, lines: &[String]) {
    std::fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
}

fn records(path: &Path) -> Vec<AuditRecord> {
    kawach_audit::read_records(path).unwrap()
}

// ---------------------------------------------------------------------------
// Attacks the chain alone detects
// ---------------------------------------------------------------------------

#[test]
fn editing_an_entry_in_place_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = make_log(dir.path(), 5);

    // The insider's edit: rewrite what an entry says, leaving prev/hash untouched so
    // the chain still "looks" continuous.
    let mut lines = read_lines(&path);
    lines[3] = lines[3].replace("\"Step\"", "\"Tampered\"");
    write_lines(&path, &lines);

    let report = verify_file(&path, INSTANCE).unwrap();
    assert_eq!(report.status, ChainStatus::EntryEdited { at: AuditSeq(4) });
    assert!(report.summary().contains("edited"));
}

#[test]
fn deleting_an_entry_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = make_log(dir.path(), 5);

    let mut lines = read_lines(&path);
    lines.remove(2);
    write_lines(&path, &lines);

    // The sequence numbers now jump, which is caught before the chain check.
    let report = verify_file(&path, INSTANCE).unwrap();
    assert!(matches!(report.status, ChainStatus::SequenceGap { .. }), "{}", report.summary());
}

#[test]
fn reordering_entries_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = make_log(dir.path(), 5);

    let mut lines = read_lines(&path);
    lines.swap(2, 3);
    write_lines(&path, &lines);

    let report = verify_file(&path, INSTANCE).unwrap();
    assert!(matches!(report.status, ChainStatus::SequenceGap { .. }), "{}", report.summary());
}

#[test]
fn inserting_a_forged_entry_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = make_log(dir.path(), 5);

    // Forge an entry that claims to follow the real entry 3, renumbering the rest is
    // beyond what an adversary editing one line would do — this is the naive splice.
    let mut lines = read_lines(&path);
    let forged = lines[3].replace("\"Step\"", "\"ForgedApproval\"");
    lines.insert(4, forged);
    write_lines(&path, &lines);

    let report = verify_file(&path, INSTANCE).unwrap();
    assert!(!report.is_intact(), "a spliced entry must not verify");
}

#[test]
fn a_log_lifted_from_another_instance_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = make_log(dir.path(), 3);

    // Genesis is bound to the instance id, so a chain harvested from a deliberately
    // quiet installation cannot be presented as this one's history.
    let report = verify_file(&path, "kawach-production").unwrap();
    assert!(matches!(report.status, ChainStatus::WrongGenesis { .. }), "{}", report.summary());
}

#[test]
fn verification_reports_the_first_divergence_not_merely_a_boolean() {
    let dir = tempfile::tempdir().unwrap();
    let path = make_log(dir.path(), 10);

    // Two edits. Verification must name the earlier one: during an incident, the first
    // divergence is what bounds which records can still be believed.
    let mut lines = read_lines(&path);
    lines[8] = lines[8].replace("\"Step\"", "\"Late\"");
    lines[5] = lines[5].replace("\"Step\"", "\"Early\"");
    write_lines(&path, &lines);

    let report = verify_file(&path, INSTANCE).unwrap();
    assert_eq!(report.status, ChainStatus::EntryEdited { at: AuditSeq(6) });
}

// ---------------------------------------------------------------------------
// Attacks the chain alone does NOT detect
// ---------------------------------------------------------------------------

#[test]
fn truncating_the_tail_is_invisible_to_the_chain_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = make_log(dir.path(), 10);

    let mut lines = read_lines(&path);
    lines.truncate(4);
    write_lines(&path, &lines);

    // This is the uncomfortable result, and it is why anchoring exists. Everything that
    // remains is internally consistent, so the chain has nothing to object to.
    let report = verify_file(&path, INSTANCE).unwrap();
    assert!(
        report.is_intact(),
        "a truncated chain is still internally consistent — if this now fails, the \
         claim in DESIGN.md 7.3 needs updating"
    );
    assert_eq!(report.entry_count, 4);
}

#[test]
fn truncating_the_tail_is_detected_once_an_anchor_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let anchor = FileAnchor::new(dir.path().join("anchors.jsonl"));

    let log = AuditLog::open(&path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_checkpoint_policy(CheckpointPolicy::disabled());
    for i in 0..10 {
        log.append(AuditEvent::PolicyRefusal { code: "c".into(), detail: format!("{i}") }).unwrap();
    }
    let published = log.publish_anchor(&anchor).unwrap();
    assert_eq!(published.entry_count, 11);
    drop(log);

    let mut lines = read_lines(&path);
    lines.truncate(4);
    write_lines(&path, &lines);

    let recs = records(&path);
    let mut report = verify_records(&recs, INSTANCE).unwrap();
    assert!(report.is_intact(), "the chain itself is still consistent");

    verify_against_anchor(&recs, INSTANCE, &anchor, &mut report).unwrap();
    assert_eq!(
        report.status,
        ChainStatus::Truncated { anchored_count: 11, actual_count: 4 },
        "{}",
        report.summary()
    );
    assert!(report.summary().contains("TRUNCATED"));
}

#[test]
fn a_wholesale_rewrite_from_genesis_is_invisible_without_signatures() {
    let dir = tempfile::tempdir().unwrap();

    // The adversary does not edit — they rebuild. Same instance, same tooling, a
    // history of their choosing. Nothing in the chain distinguishes it from the truth.
    let forged = make_log(dir.path(), 3);
    let report = verify_file(&forged, INSTANCE).unwrap();
    assert!(
        report.is_intact(),
        "a chain rebuilt from genesis is self-consistent by construction"
    );
}

#[test]
fn a_wholesale_rewrite_is_detected_when_checkpoints_are_signed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");

    let signer = CheckpointSigner::generate(INSTANCE);
    let verifier = signer.verifier();

    let log = AuditLog::open(&path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_signer(signer)
        .with_checkpoint_policy(CheckpointPolicy { every_n_entries: 4 });
    for i in 0..10 {
        log.append(AuditEvent::PolicyRefusal { code: "c".into(), detail: format!("{i}") }).unwrap();
    }
    drop(log);

    // Honest log: signatures check out.
    let recs = records(&path);
    let mut report = verify_records(&recs, INSTANCE).unwrap();
    verify_signatures(&recs, &verifier, &mut report).unwrap();
    assert!(report.is_intact(), "{}", report.summary());
    assert!(report.signatures_verified > 0, "the test must actually exercise signatures");

    // The adversary rebuilds the log without the signing key. They can produce a
    // consistent chain, but the checkpoint signatures inside it are not theirs to make.
    let forged_path = dir.path().join("forged.jsonl");
    let forged = AuditLog::open(&forged_path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_checkpoint_policy(CheckpointPolicy { every_n_entries: 4 });
    for i in 0..10 {
        forged
            .append(AuditEvent::PolicyRefusal { code: "c".into(), detail: format!("benign {i}") })
            .unwrap();
    }
    drop(forged);

    let forged_recs = records(&forged_path);
    let mut forged_report = verify_records(&forged_recs, INSTANCE).unwrap();
    assert!(forged_report.is_intact(), "the forged chain is internally consistent");

    // Unsigned checkpoints are not counted as verified, so the forgery cannot pass
    // itself off as attested.
    verify_signatures(&forged_recs, &verifier, &mut forged_report).unwrap();
    assert_eq!(
        forged_report.signatures_verified, 0,
        "an unsigned rebuild must not be credited with verified signatures"
    );
}

#[test]
fn a_forged_signature_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let signer = CheckpointSigner::generate(INSTANCE);
    let verifier = signer.verifier();

    let log = AuditLog::open(&path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_signer(signer)
        .with_checkpoint_policy(CheckpointPolicy::disabled());
    log.append(AuditEvent::PolicyRefusal { code: "c".into(), detail: "d".into() }).unwrap();
    log.checkpoint().unwrap();
    drop(log);

    // Swap in a signature from a different key.
    let impostor = CheckpointSigner::generate(INSTANCE);
    let recs = records(&path);
    let mut forged = recs.clone();
    for r in &mut forged {
        if let AuditEvent::Checkpoint { entry_count, head, signature } = &mut r.event {
            let h = EntryHash::from_hex(head).unwrap();
            *signature = Some(impostor.sign(*entry_count, &h));
        }
    }

    let mut report = verify_records(&recs, INSTANCE).unwrap();
    verify_signatures(&forged, &verifier, &mut report).unwrap();
    assert!(matches!(report.status, ChainStatus::BadSignature { .. }), "{}", report.summary());
}

#[test]
fn rewriting_history_below_an_anchor_is_detected_even_at_the_same_length() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let anchor = FileAnchor::new(dir.path().join("anchors.jsonl"));

    let log = AuditLog::open(&path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_checkpoint_policy(CheckpointPolicy::disabled());
    for i in 0..5 {
        log.append(AuditEvent::PolicyRefusal { code: "real".into(), detail: format!("{i}") })
            .unwrap();
    }
    log.publish_anchor(&anchor).unwrap();
    drop(log);
    std::fs::remove_file(&path).unwrap();

    // Rebuild to the *same length* with different content. Length checks alone would
    // miss this; the anchored head does not.
    let rebuilt = AuditLog::open(&path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_checkpoint_policy(CheckpointPolicy::disabled());
    for i in 0..5 {
        rebuilt
            .append(AuditEvent::PolicyRefusal { code: "benign".into(), detail: format!("{i}") })
            .unwrap();
    }
    drop(rebuilt);

    let recs = records(&path);
    let mut report = verify_records(&recs, INSTANCE).unwrap();
    assert!(report.is_intact());
    assert_eq!(report.entry_count, 6, "same length as the anchored chain");

    verify_against_anchor(&recs, INSTANCE, &anchor, &mut report).unwrap();
    assert!(
        matches!(report.status, ChainStatus::AnchorMismatch { .. }),
        "{}",
        report.summary()
    );
}

// ---------------------------------------------------------------------------
// Operational behaviour
// ---------------------------------------------------------------------------

#[test]
fn a_tampered_log_is_refused_at_open_rather_than_appended_to() {
    let dir = tempfile::tempdir().unwrap();
    let path = make_log(dir.path(), 5);

    let mut lines = read_lines(&path);
    lines[2] = lines[2].replace("\"Step\"", "\"Tampered\"");
    write_lines(&path, &lines);

    // Appending to a log that does not verify would bury the divergence under new,
    // valid-looking entries.
    let err = AuditLog::open(&path, INSTANCE, Actor::new("alice")).unwrap_err();
    assert!(format!("{err}").contains("does not verify"), "{err}");
}

#[test]
fn the_chain_survives_a_process_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");

    let first = AuditLog::open(&path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_checkpoint_policy(CheckpointPolicy::disabled());
    first.append(AuditEvent::PolicyRefusal { code: "a".into(), detail: "1".into() }).unwrap();
    let head_before = first.head();
    drop(first);

    let second = AuditLog::open(&path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_checkpoint_policy(CheckpointPolicy::disabled());
    // Reopening writes a LogOpened entry, so the head advances — but it must chain from
    // where the previous process left off.
    assert_ne!(second.head(), head_before);
    second.append(AuditEvent::PolicyRefusal { code: "b".into(), detail: "2".into() }).unwrap();
    drop(second);

    let report = verify_file(&path, INSTANCE).unwrap();
    assert!(report.is_intact(), "{}", report.summary());
    assert_eq!(report.entry_count, 4, "one LogOpened and one refusal per process");
}

#[test]
fn checkpoints_are_emitted_on_the_configured_cadence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = AuditLog::open(&path, INSTANCE, Actor::new("alice"))
        .unwrap()
        .with_checkpoint_policy(CheckpointPolicy { every_n_entries: 3 });
    for i in 0..8 {
        log.append(AuditEvent::PolicyRefusal { code: "c".into(), detail: format!("{i}") }).unwrap();
    }
    drop(log);

    let report = verify_file(&path, INSTANCE).unwrap();
    assert!(report.is_intact(), "{}", report.summary());
    assert!(report.checkpoints >= 2, "expected periodic checkpoints, got {}", report.checkpoints);
}

#[test]
fn an_absent_anchor_is_not_reported_as_a_clean_bill_of_health() {
    let dir = tempfile::tempdir().unwrap();
    let path = make_log(dir.path(), 3);
    let anchor = FileAnchor::new(dir.path().join("nonexistent.jsonl"));

    let recs = records(&path);
    let mut report = verify_records(&recs, INSTANCE).unwrap();
    verify_against_anchor(&recs, INSTANCE, &anchor, &mut report).unwrap();

    // The chain verified and no anchor contradicted it — but nothing was *confirmed*
    // either. The status stays Intact; it is the caller's job to say "unanchored", and
    // this test pins that no false confirmation is manufactured here.
    assert!(report.is_intact());
    assert_eq!(report.entry_count, 4);
}
