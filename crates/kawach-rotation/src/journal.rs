//! The write-ahead journal: how a crashed rotation is recovered rather than guessed at.
//!
//! ## Protocol
//!
//! The transition *into* an in-flight state **is** the intent record. There is no
//! separate "about to do X" entry, because the state machine already encodes it:
//!
//! ```text
//! 1. append Transition{ Verified -> Publishing } + fsync   ← durable BEFORE the effect
//! 2. call backend.stage() / backend.promote()
//! 3. append Transition{ Publishing -> Published } + fsync  ← durable AFTER the effect
//! ```
//!
//! A crash lands in exactly one of three places:
//!
//! | Crash point | Journal tail | Recovery |
//! |---|---|---|
//! | before 1 | a settled state | resume; no effect occurred |
//! | between 1 and 3 | an **in-flight** state | outcome unknown → `observe()` and [`crate::state::reconcile`] |
//! | after 3 | a settled state | resume; the effect definitely occurred |
//!
//! ## Torn writes
//!
//! A crash can also land *inside* step 1's write, leaving a partial final line. That is
//! not corruption, it is the expected shape of an interrupted append, and recovery
//! treats it as such: a partial **final** line is discarded (the transition never became
//! durable, so by definition the effect had not been attempted). A malformed line
//! anywhere else is real corruption and is a hard error — quietly skipping it would
//! silently rewrite history.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use kawach_core::{
    CredentialHandle, CredentialKind, KawachError, Result, RunId, SafeDetail, VersionId,
};
use time::OffsetDateTime;

use crate::state::{RemediationHint, RotationEvent, RotationState};

/// One journalled fact.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum Record {
    /// Opening entry: what this run intends to do.
    RunStarted {
        /// Where the value is published, as `backend:path`.
        reference: String,
        /// Which provider handles it.
        kind: CredentialKind,
        /// `dry-run` or `apply`. A dry run journals its plan and performs no effects.
        mode: String,
    },
    /// A state machine edge. Written *before* the effect when entering an in-flight
    /// state, and *after* it when leaving one.
    Transition {
        /// State before.
        from: RotationState,
        /// What happened.
        event: RotationEvent,
        /// State after.
        to: RotationState,
    },
    /// The provider named the credential it created. Non-secret, and what makes
    /// `revoke` idempotent after a crash.
    HandleAssigned {
        /// The new credential's handle.
        handle: CredentialHandle,
    },
    /// The backend named the version it wrote. Needed by the compensation path to know
    /// what to restore.
    VersionAssigned {
        /// The version that was current before this run published, if any.
        previous: Option<VersionId>,
        /// The version this run wrote.
        written: VersionId,
    },
    /// The run stopped and needs a human.
    Escalation {
        /// Structured guidance. Fixed strings only — never interpolated foreign text.
        hint: RemediationHint,
    },
    /// Closing entry.
    RunFinished {
        /// Which terminal state was reached.
        terminal: RotationState,
    },
}

/// A journal line.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JournalEntry {
    /// Monotonic within a run, starting at 1.
    pub seq: u64,
    /// When it was written. Informational: ordering comes from `seq`, not the clock.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// Which run.
    pub run: RunId,
    /// What happened.
    pub record: Record,
}

/// An append-only, `fsync`-per-entry journal for one rotation run.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: File,
    run: RunId,
    seq: u64,
}

impl Journal {
    /// File name for a run's journal within a state directory.
    #[must_use]
    pub fn file_name(run: &RunId) -> String {
        format!("{run}.jsonl")
    }

    /// Create a new journal. Fails if one already exists for this run.
    ///
    /// # Errors
    /// [`KawachError::Journal`] on any I/O failure.
    pub fn create(dir: &Path, run: &RunId) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(io_err)?;
        let path = dir.join(Self::file_name(run));
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)
            .map_err(io_err)?;
        Ok(Self { path, file, run: run.clone(), seq: 0 })
    }

    /// Re-open an existing journal for appending, positioned after its last entry.
    ///
    /// # Errors
    /// [`KawachError::Journal`] on I/O failure or on mid-file corruption.
    pub fn reopen(dir: &Path, run: &RunId) -> Result<(Self, RecoveredRun)> {
        let path = dir.join(Self::file_name(run));
        let recovered = replay(&path)?;
        let file = OpenOptions::new().append(true).open(&path).map_err(io_err)?;
        let journal = Self { path, file, run: run.clone(), seq: recovered.last_seq };
        Ok((journal, recovered))
    }

    /// The run this journal belongs to.
    #[must_use]
    pub fn run(&self) -> &RunId {
        &self.run
    }

    /// Where the journal lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a record and make it durable before returning.
    ///
    /// The `fsync` is the entire point: a buffered write provides no ordering
    /// guarantee against the effect that follows it, so "intent before effect" would
    /// become "intent probably before effect", which is not a recovery protocol.
    ///
    /// # Errors
    /// [`KawachError::Journal`] on serialisation or I/O failure. Callers must treat a
    /// failure here as fatal to the step: if the intent is not durable, the effect must
    /// not be attempted.
    pub fn append(&mut self, record: Record) -> Result<u64> {
        self.seq += 1;
        let entry = JournalEntry {
            seq: self.seq,
            at: OffsetDateTime::now_utc(),
            run: self.run.clone(),
            record,
        };
        let mut line = serde_json::to_string(&entry).map_err(|e| KawachError::Journal {
            detail: SafeDetail::from_error(&e),
        })?;
        line.push('\n');
        self.file.write_all(line.as_bytes()).map_err(io_err)?;
        self.file.sync_data().map_err(io_err)?;
        Ok(self.seq)
    }

    /// Record a transition. Convenience over [`Journal::append`].
    ///
    /// # Errors
    /// As [`Journal::append`].
    pub fn record_transition(
        &mut self,
        from: RotationState,
        event: RotationEvent,
        to: RotationState,
    ) -> Result<u64> {
        self.append(Record::Transition { from, event, to })
    }
}

/// The reconstructed state of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredRun {
    /// Which run.
    pub run: RunId,
    /// Where the state machine got to.
    pub state: RotationState,
    /// The new credential's handle, if one was provisioned.
    pub handle: Option<CredentialHandle>,
    /// The version this run wrote, if it published.
    pub written_version: Option<VersionId>,
    /// The version that was current before this run published.
    pub previous_version: Option<VersionId>,
    /// The last escalation, if the run stopped for a human.
    pub escalation: Option<RemediationHint>,
    /// Sequence number of the last durable entry.
    pub last_seq: u64,
    /// Whether the journal's final line was a torn write, discarded during recovery.
    ///
    /// Surfaced rather than hidden: it tells an operator the process died mid-append,
    /// which is a different story from a clean shutdown.
    pub torn_tail: bool,
}

impl RecoveredRun {
    /// Whether recovery must call `observe()` before it can proceed.
    ///
    /// True exactly when the run stopped in an in-flight state, i.e. an effect was
    /// attempted whose outcome is unknown.
    #[must_use]
    pub fn needs_reconciliation(&self) -> bool {
        self.state.is_in_flight()
    }

    /// Whether the run finished and needs nothing further.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state.is_terminal()
    }
}

/// Rebuild a run's state from its journal.
///
/// # Errors
/// [`KawachError::Journal`] on I/O failure, on a malformed line that is not the final
/// one, on a sequence gap, or on a journal whose transitions do not chain.
pub fn replay(path: &Path) -> Result<RecoveredRun> {
    let file = File::open(path).map_err(io_err)?;
    let reader = BufReader::new(file);

    let mut run: Option<RunId> = None;
    let mut state = RotationState::START;
    let mut handle = None;
    let mut written_version = None;
    let mut previous_version = None;
    let mut escalation = None;
    let mut last_seq = 0u64;
    let mut torn_tail = false;

    let lines: Vec<std::io::Result<String>> = reader.lines().collect();
    let line_count = lines.len();

    for (index, line) in lines.into_iter().enumerate() {
        let line = line.map_err(io_err)?;
        if line.trim().is_empty() {
            continue;
        }
        let is_last = index + 1 == line_count;

        let entry: JournalEntry = match serde_json::from_str(&line) {
            Ok(entry) => entry,
            // An interrupted append leaves a partial final line. The transition never
            // became durable, so the effect had not been attempted: discard it.
            Err(_) if is_last => {
                torn_tail = true;
                break;
            }
            // Anywhere else, this is corruption. Refuse rather than silently rewriting
            // history — a rotation journal that lies is worse than no journal.
            Err(e) => {
                return Err(KawachError::Journal {
                    detail: SafeDetail::new(format!("malformed entry at line {}: {e}", index + 1)),
                })
            }
        };

        if entry.seq != last_seq + 1 {
            return Err(KawachError::Journal {
                detail: SafeDetail::new(format!(
                    "sequence gap: expected {}, found {}",
                    last_seq + 1,
                    entry.seq
                )),
            });
        }
        last_seq = entry.seq;
        run.get_or_insert(entry.run.clone());

        match entry.record {
            Record::RunStarted { .. } => {}
            Record::Transition { from, to, .. } => {
                if from != state {
                    return Err(KawachError::Journal {
                        detail: SafeDetail::new(format!(
                            "transition at seq {} starts from {from}, but the journal is at {state}",
                            entry.seq
                        )),
                    });
                }
                state = to;
            }
            Record::HandleAssigned { handle: h } => handle = Some(h),
            Record::VersionAssigned { previous, written } => {
                previous_version = previous;
                written_version = Some(written);
            }
            Record::Escalation { hint } => escalation = Some(hint),
            Record::RunFinished { terminal } => {
                if terminal != state {
                    return Err(KawachError::Journal {
                        detail: SafeDetail::new(format!(
                            "run finished as {terminal} but the journal is at {state}"
                        )),
                    });
                }
            }
        }
    }

    let run = run.ok_or_else(|| KawachError::Journal {
        detail: SafeDetail::trusted_static("journal is empty"),
    })?;

    Ok(RecoveredRun {
        run,
        state,
        handle,
        written_version,
        previous_version,
        escalation,
        last_seq,
        torn_tail,
    })
}

/// List the runs with a journal in `dir`, oldest first.
///
/// # Errors
/// [`KawachError::Journal`] on I/O failure.
pub fn list_runs(dir: &Path) -> Result<Vec<RunId>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut runs = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(id) = name.strip_suffix(".jsonl") {
            runs.push(RunId::from_string(id));
        }
    }
    runs.sort();
    Ok(runs)
}

fn io_err(e: std::io::Error) -> KawachError {
    KawachError::Journal { detail: SafeDetail::from_error(&e) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{next, Observation, PublishedSide};

    fn kind() -> CredentialKind {
        CredentialKind::new("postgres_ab_roles")
    }

    /// Drive a journal through a sequence of events exactly as the engine would.
    fn drive(journal: &mut Journal, events: &[RotationEvent]) -> RotationState {
        let mut state = RotationState::START;
        for &event in events {
            let to = next(state, event).expect("test drives only legal transitions");
            journal.record_transition(state, event, to).unwrap();
            state = to;
        }
        state
    }

    #[test]
    fn a_completed_run_replays_to_completed() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        let mut journal = Journal::create(dir.path(), &run).unwrap();
        journal
            .append(Record::RunStarted {
                reference: "vault-prod:secret/data/app/db".into(),
                kind: kind(),
                mode: "apply".into(),
            })
            .unwrap();
        let terminal = drive(
            &mut journal,
            &[
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
            ],
        );
        journal.append(Record::RunFinished { terminal }).unwrap();

        let recovered = replay(journal.path()).unwrap();
        assert_eq!(recovered.state, RotationState::Completed);
        assert!(recovered.is_complete());
        assert!(!recovered.needs_reconciliation());
        assert_eq!(recovered.run, run);
    }

    #[test]
    fn a_crash_mid_publish_replays_to_an_in_flight_state() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        let mut journal = Journal::create(dir.path(), &run).unwrap();
        journal
            .append(Record::RunStarted {
                reference: "vault-prod:secret/data/app/db".into(),
                kind: kind(),
                mode: "apply".into(),
            })
            .unwrap();
        // The engine wrote the intent (the transition *into* Publishing), then the
        // process died before the backend call returned.
        let state = drive(
            &mut journal,
            &[
                RotationEvent::StartProvision,
                RotationEvent::ProvisionOk,
                RotationEvent::StartVerify,
                RotationEvent::VerifyOk,
                RotationEvent::StartPublish,
            ],
        );
        assert_eq!(state, RotationState::Publishing);
        drop(journal);

        let recovered = replay(&dir.path().join(Journal::file_name(&run))).unwrap();
        assert_eq!(recovered.state, RotationState::Publishing);
        assert!(recovered.needs_reconciliation(), "an in-flight state must force an observe()");

        // Recovery asks reality: the write had landed, the acknowledgement was lost.
        let resolved = crate::state::reconcile(
            recovered.state,
            Observation { new_live: true, old_live: true, published: PublishedSide::New },
        );
        assert_eq!(resolved, RotationState::Published);
    }

    #[test]
    fn the_handle_survives_a_crash_so_revoke_stays_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        let handle = CredentialHandle::new(kind(), "billing_b").with_label("role", "billing_b");
        {
            let mut journal = Journal::create(dir.path(), &run).unwrap();
            journal
                .append(Record::RunStarted {
                    reference: "vault-prod:x".into(),
                    kind: kind(),
                    mode: "apply".into(),
                })
                .unwrap();
            drive(&mut journal, &[RotationEvent::StartProvision]);
            journal.append(Record::HandleAssigned { handle: handle.clone() }).unwrap();
            drive(&mut journal, &[]);
        }
        let recovered = replay(&dir.path().join(Journal::file_name(&run))).unwrap();
        assert_eq!(recovered.handle, Some(handle));
    }

    #[test]
    fn a_torn_final_line_is_discarded_not_treated_as_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        let path = dir.path().join(Journal::file_name(&run));
        {
            let mut journal = Journal::create(dir.path(), &run).unwrap();
            journal
                .append(Record::RunStarted {
                    reference: "vault-prod:x".into(),
                    kind: kind(),
                    mode: "apply".into(),
                })
                .unwrap();
            drive(&mut journal, &[RotationEvent::StartProvision, RotationEvent::ProvisionOk]);
        }
        // Simulate a process death partway through an append.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(br#"{"seq":4,"at":"2026-01-01T00:00:00Z","run":"x","rec"#).unwrap();
        drop(f);

        let recovered = replay(&path).unwrap();
        assert!(recovered.torn_tail, "the torn write should be reported, not hidden");
        assert_eq!(recovered.state, RotationState::Provisioned, "state comes from durable entries only");
    }

    #[test]
    fn corruption_in_the_middle_of_a_journal_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        let path = dir.path().join(Journal::file_name(&run));
        {
            let mut journal = Journal::create(dir.path(), &run).unwrap();
            journal
                .append(Record::RunStarted {
                    reference: "vault-prod:x".into(),
                    kind: kind(),
                    mode: "apply".into(),
                })
                .unwrap();
            drive(&mut journal, &[RotationEvent::StartProvision, RotationEvent::ProvisionOk]);
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = contents.lines().collect();
        lines[1] = "{ not json";
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let err = replay(&path).unwrap_err();
        assert!(matches!(err, KawachError::Journal { .. }));
        assert!(format!("{err}").contains("line 2"));
    }

    #[test]
    fn a_journal_whose_transitions_do_not_chain_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        let path = dir.path().join(Journal::file_name(&run));
        let mut journal = Journal::create(dir.path(), &run).unwrap();
        journal
            .append(Record::RunStarted { reference: "v:x".into(), kind: kind(), mode: "apply".into() })
            .unwrap();
        // A forged entry claiming we were already Drained.
        journal
            .append(Record::Transition {
                from: RotationState::Drained,
                event: RotationEvent::StartRevoke,
                to: RotationState::Revoking,
            })
            .unwrap();
        drop(journal);

        let err = replay(&path).unwrap_err();
        assert!(format!("{err}").contains("starts from Drained"));
    }

    #[test]
    fn a_sequence_gap_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        let path = dir.path().join(Journal::file_name(&run));
        {
            let mut journal = Journal::create(dir.path(), &run).unwrap();
            journal
                .append(Record::RunStarted { reference: "v:x".into(), kind: kind(), mode: "apply".into() })
                .unwrap();
            drive(&mut journal, &[RotationEvent::StartProvision, RotationEvent::ProvisionOk]);
        }
        // Delete an entry from the middle: the classic "hide what happened" edit.
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();

        let err = replay(&path).unwrap_err();
        assert!(format!("{err}").contains("sequence gap"));
    }

    #[test]
    fn reopening_continues_the_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        {
            let mut journal = Journal::create(dir.path(), &run).unwrap();
            journal
                .append(Record::RunStarted { reference: "v:x".into(), kind: kind(), mode: "apply".into() })
                .unwrap();
            drive(&mut journal, &[RotationEvent::StartProvision]);
        }
        let (mut journal, recovered) = Journal::reopen(dir.path(), &run).unwrap();
        assert_eq!(recovered.state, RotationState::Provisioning);
        assert_eq!(recovered.last_seq, 2);
        let seq = journal.record_transition(
            RotationState::Provisioning,
            RotationEvent::ProvisionOk,
            RotationState::Provisioned,
        )
        .unwrap();
        assert_eq!(seq, 3);
        assert_eq!(replay(journal.path()).unwrap().state, RotationState::Provisioned);
    }

    #[test]
    fn creating_a_journal_twice_for_one_run_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        let _first = Journal::create(dir.path(), &run).unwrap();
        assert!(
            Journal::create(dir.path(), &run).is_err(),
            "a second journal would fork the history of one run"
        );
    }

    #[test]
    fn runs_are_discoverable_for_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (RunId::generate(), RunId::generate());
        for run in [&a, &b] {
            let mut j = Journal::create(dir.path(), run).unwrap();
            j.append(Record::RunStarted { reference: "v:x".into(), kind: kind(), mode: "apply".into() })
                .unwrap();
        }
        let found = list_runs(dir.path()).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.contains(&a) && found.contains(&b));
    }

    #[test]
    fn an_escalation_is_recoverable_with_its_guidance() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::generate();
        let mut journal = Journal::create(dir.path(), &run).unwrap();
        journal
            .append(Record::RunStarted { reference: "v:x".into(), kind: kind(), mode: "apply".into() })
            .unwrap();
        let state = drive(
            &mut journal,
            &[
                RotationEvent::StartProvision,
                RotationEvent::ProvisionOk,
                RotationEvent::StartVerify,
                RotationEvent::VerifyOk,
                RotationEvent::StartPublish,
                RotationEvent::PublishOk,
                RotationEvent::StartDrain,
                RotationEvent::DrainTimeout,
            ],
        );
        assert_eq!(state, RotationState::NeedsOperator);
        let hint = RemediationHint::for_escalation(RotationState::Draining, RotationEvent::DrainTimeout)
            .unwrap();
        journal.append(Record::Escalation { hint: hint.clone() }).unwrap();

        let recovered = replay(journal.path()).unwrap();
        assert_eq!(recovered.state, RotationState::NeedsOperator);
        assert_eq!(recovered.escalation.unwrap().code, "drain_timeout");
    }
}
