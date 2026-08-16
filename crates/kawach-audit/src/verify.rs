//! Chain verification.
//!
//! Verification reports the **first divergent sequence number**, not a boolean. During
//! an incident the question is never "was it tampered with" — by the time you are
//! looking, you suspect it was. The question is *when it started*, because that bounds
//! which records you can still believe.

use std::path::Path;

use kawach_core::{AuditSeq, KawachError, Result, SafeDetail};

use crate::checkpoint::{Anchor, CheckpointVerifier};
use crate::event::AuditEvent;
use crate::hash::EntryHash;
use crate::log::{read_records, AuditRecord};

/// What verification found.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainStatus {
    /// Every entry chains correctly and every checked signature is valid.
    Intact,
    /// An entry's stored hash does not match its contents: it was edited in place.
    EntryEdited {
        /// Where the divergence starts.
        at: AuditSeq,
    },
    /// An entry's `prev` does not match the previous entry's hash: an entry was
    /// inserted, deleted, or reordered.
    ChainBroken {
        /// Where the divergence starts.
        at: AuditSeq,
        /// The hash the chain arrived with.
        expected: EntryHash,
        /// The hash the record claims to follow.
        found: EntryHash,
    },
    /// Sequence numbers are not contiguous from 1.
    SequenceGap {
        /// The sequence number that was expected.
        expected: AuditSeq,
        /// What was found instead.
        found: AuditSeq,
    },
    /// The first entry does not chain from this instance's genesis hash.
    ///
    /// Either the log belongs to a different instance, or its opening entries were
    /// removed and the remainder re-chained.
    WrongGenesis {
        /// The genesis hash this instance requires.
        expected: EntryHash,
        /// What the first record claims to follow.
        found: EntryHash,
    },
    /// A checkpoint's signature did not verify.
    BadSignature {
        /// Which checkpoint.
        at: AuditSeq,
    },
    /// The log is shorter than the last external anchor: its tail was truncated.
    ///
    /// **This is the finding a hash chain alone cannot produce.**
    Truncated {
        /// Entries the anchor attests to.
        anchored_count: u64,
        /// Entries actually present.
        actual_count: u64,
    },
    /// The log is long enough but its head disagrees with the anchor: history was
    /// rewritten below the anchored point.
    AnchorMismatch {
        /// Entries the anchor attests to.
        anchored_count: u64,
        /// The head the anchor attests to.
        anchored_head: EntryHash,
        /// The head actually present at that count.
        actual_head: EntryHash,
    },
}

/// The result of verifying a log.
#[derive(Clone, Debug)]
pub struct VerificationReport {
    /// What was found.
    pub status: ChainStatus,
    /// Entries present.
    pub entry_count: u64,
    /// Chain head, if any entries were read.
    pub head: Option<EntryHash>,
    /// Checkpoints encountered.
    pub checkpoints: usize,
    /// Checkpoint signatures verified. Below `checkpoints` when no verifier was
    /// supplied — which is reported rather than presented as success.
    pub signatures_verified: usize,
    /// Access intents with no corresponding outcome.
    ///
    /// Not tampering: a dangling intent is the signature of a process that died between
    /// recording its intent to read and recording the result, which is exactly what
    /// `ReadWitness`'s `Drop` handler exists to prevent. More than a handful is a
    /// finding.
    pub dangling_intents: Vec<AuditSeq>,
}

impl VerificationReport {
    /// Whether the chain verified.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.status == ChainStatus::Intact
    }

    /// One-line human summary.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.status {
            ChainStatus::Intact => {
                format!("intact, {} entries, head {}", self.entry_count, self.head.map_or_else(|| "-".into(), |h| h.short()))
            }
            ChainStatus::EntryEdited { at } => format!("entry {at} was edited in place"),
            ChainStatus::ChainBroken { at, .. } => {
                format!("chain broken at {at}: an entry was inserted, deleted, or reordered")
            }
            ChainStatus::SequenceGap { expected, found } => {
                format!("sequence gap: expected {expected}, found {found}")
            }
            ChainStatus::WrongGenesis { .. } => {
                "first entry does not chain from this instance's genesis".to_owned()
            }
            ChainStatus::BadSignature { at } => format!("checkpoint at {at} has an invalid signature"),
            ChainStatus::Truncated { anchored_count, actual_count } => format!(
                "TRUNCATED: anchor attests to {anchored_count} entries, only {actual_count} present"
            ),
            ChainStatus::AnchorMismatch { anchored_count, .. } => {
                format!("history was rewritten at or below anchored entry {anchored_count}")
            }
        }
    }
}

/// Verify a log file's chain.
///
/// Signature and anchor checks are separate calls ([`verify_signatures`],
/// [`verify_against_anchor`]) because they need material this function does not have.
///
/// # Errors
/// [`KawachError::Audit`] on I/O failure or a malformed record.
pub fn verify_file(path: &Path, instance: &str) -> Result<VerificationReport> {
    verify_records(&read_records(path)?, instance)
}

/// Verify an already-read sequence of records.
///
/// # Errors
/// Never returns `Err` for tampering — that is a [`ChainStatus`], not an error. Errors
/// are reserved for the caller's problems, not the log's.
pub fn verify_records(records: &[AuditRecord], instance: &str) -> Result<VerificationReport> {
    let genesis = EntryHash::genesis(instance);
    let mut expected_prev = genesis;
    let mut expected_seq = 1u64;
    let mut checkpoints = 0usize;
    let mut open_intents: Vec<AuditSeq> = Vec::new();
    let mut status = ChainStatus::Intact;
    let mut head = None;

    for record in records {
        if record.seq != expected_seq {
            status = ChainStatus::SequenceGap {
                expected: AuditSeq(expected_seq),
                found: AuditSeq(record.seq),
            };
            break;
        }

        if record.prev != expected_prev {
            status = if expected_seq == 1 {
                ChainStatus::WrongGenesis { expected: genesis, found: record.prev }
            } else {
                ChainStatus::ChainBroken {
                    at: AuditSeq(record.seq),
                    expected: expected_prev,
                    found: record.prev,
                }
            };
            break;
        }

        // The record's own contents must produce its stored hash. This is what catches
        // an in-place edit that left `prev` and `hash` untouched.
        if record.recompute_hash() != record.hash {
            status = ChainStatus::EntryEdited { at: AuditSeq(record.seq) };
            break;
        }

        match &record.event {
            AuditEvent::Checkpoint { .. } => checkpoints += 1,
            AuditEvent::AccessIntent { .. } => open_intents.push(AuditSeq(record.seq)),
            AuditEvent::AccessOutcome { intent_seq, .. } => {
                open_intents.retain(|s| s != intent_seq);
            }
            _ => {}
        }

        expected_prev = record.hash;
        head = Some(record.hash);
        expected_seq += 1;
    }

    Ok(VerificationReport {
        status,
        entry_count: expected_seq - 1,
        head,
        checkpoints,
        signatures_verified: 0,
        dangling_intents: open_intents,
    })
}

/// Check every checkpoint signature in a log.
///
/// Updates `report.signatures_verified`, and downgrades the status on the first invalid
/// signature.
///
/// # Errors
/// [`KawachError::Audit`] on a malformed checkpoint head.
pub fn verify_signatures(
    records: &[AuditRecord],
    verifier: &CheckpointVerifier,
    report: &mut VerificationReport,
) -> Result<()> {
    let mut verified = 0usize;
    for record in records {
        let AuditEvent::Checkpoint { entry_count, head, signature } = &record.event else {
            continue;
        };
        let Some(signature) = signature else { continue };
        let head = EntryHash::from_hex(head).ok_or_else(|| KawachError::Audit {
            detail: SafeDetail::trusted_static("checkpoint records a malformed head hash"),
        })?;
        if verifier.verify(*entry_count, &head, signature) {
            verified += 1;
        } else {
            report.status = ChainStatus::BadSignature { at: AuditSeq(record.seq) };
            break;
        }
    }
    report.signatures_verified = verified;
    Ok(())
}

/// Compare a log against its most recent external anchor.
///
/// **This is the only check that can detect tail truncation.** A chain is internally
/// consistent after its last N entries are deleted; only an outside record of how long
/// it used to be reveals the loss.
///
/// # Errors
/// Propagates anchor read failures.
pub fn verify_against_anchor(
    records: &[AuditRecord],
    instance: &str,
    anchor: &dyn Anchor,
    report: &mut VerificationReport,
) -> Result<()> {
    let Some(anchored) = anchor.latest(instance)? else {
        // No anchor is not a failure, but it is not a clean bill of health either: the
        // tail is simply unprotected. The caller reports this distinctly.
        return Ok(());
    };

    if report.entry_count < anchored.entry_count {
        report.status = ChainStatus::Truncated {
            anchored_count: anchored.entry_count,
            actual_count: report.entry_count,
        };
        return Ok(());
    }

    // The log is long enough. Check that it agrees with the anchor at the anchored
    // point — otherwise history below the anchor was rewritten and re-extended.
    let at_anchor = records
        .iter()
        .find(|r| r.seq == anchored.entry_count)
        .map(|r| r.hash);
    if let Some(actual_head) = at_anchor {
        if actual_head != anchored.head {
            report.status = ChainStatus::AnchorMismatch {
                anchored_count: anchored.entry_count,
                anchored_head: anchored.head,
                actual_head,
            };
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Actor;
    use crate::log::AuditLog;
    use kawach_core::Confirmation;

    fn log_with(dir: &Path, events: usize) -> (std::path::PathBuf, String) {
        let path = dir.join("audit.jsonl");
        let instance = "kawach-test".to_owned();
        let log = AuditLog::open(&path, &instance, Actor::new("alice"))
            .unwrap()
            .with_checkpoint_policy(crate::log::CheckpointPolicy::disabled());
        for i in 0..events {
            log.append(AuditEvent::PolicyRefusal {
                code: "out_of_scope".into(),
                detail: format!("refusal {i}"),
            })
            .unwrap();
        }
        (path, instance)
    }

    #[test]
    fn an_untouched_log_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let (path, instance) = log_with(dir.path(), 5);
        let report = verify_file(&path, &instance).unwrap();
        assert!(report.is_intact(), "{}", report.summary());
        assert_eq!(report.entry_count, 6, "5 refusals plus the LogOpened entry");
    }

    #[test]
    fn a_log_from_another_instance_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = log_with(dir.path(), 2);
        let report = verify_file(&path, "kawach-different").unwrap();
        assert!(matches!(report.status, ChainStatus::WrongGenesis { .. }));
    }

    #[test]
    fn dangling_intents_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, "i", Actor::new("alice")).unwrap();
        log.append(AuditEvent::AccessIntent { reference: "v:p".into(), purpose: "x".into() })
            .unwrap();
        log.append(AuditEvent::CommitTokenMinted { confirmation: Confirmation::new("a", "b") })
            .unwrap();

        let report = verify_file(&path, "i").unwrap();
        assert!(report.is_intact());
        assert_eq!(report.dangling_intents.len(), 1);
        assert_eq!(report.dangling_intents[0], AuditSeq(2));
    }

    #[test]
    fn a_completed_intent_is_not_dangling() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, "i", Actor::new("alice")).unwrap();
        let seq = log
            .append(AuditEvent::AccessIntent { reference: "v:p".into(), purpose: "x".into() })
            .unwrap();
        log.append(AuditEvent::AccessOutcome {
            intent_seq: seq,
            outcome: kawach_core::ReadOutcome::Success,
        })
        .unwrap();

        assert!(verify_file(&path, "i").unwrap().dangling_intents.is_empty());
    }
}
