//! The append-only audit log itself.
//!
//! Records are JSONL — one object per line — so the log stays greppable and recoverable
//! with ordinary tools during an incident, when the last thing anyone wants is a custom
//! decoder. The chain, however, is computed over the structural encoding in
//! [`crate::hash`], never over the JSON text.
//!
//! ## Durability is the whole point
//!
//! [`AuditLog::append`] `fsync`s before returning. The invariant it exists to serve is
//! "the record is durable *before* the action happens" ([`kawach_core::ReadWitness`]),
//! and a buffered write provides no ordering guarantee against the effect that follows
//! it. A log that is fast but occasionally behind reality is not an audit log.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kawach_core::{AuditAnchor, AuditSeq, CoreAuditEvent, KawachError, Result, SafeDetail};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::checkpoint::{Anchor, AnchorRecord, CheckpointSigner};
use crate::event::{run_of, Actor, AuditEvent};
use crate::hash::{canonical_entry, EntryHash};

/// One line of the audit log.
///
/// `at` is a **string**, not a parsed timestamp, and deliberately so: it is the exact
/// text that went into the hash. Storing a parsed value and re-formatting it during
/// verification would make chain integrity depend on the formatter round-tripping
/// byte-for-byte across library versions — a fragile thing to hang tamper detection on.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    /// Monotonic, starting at 1.
    pub seq: u64,
    /// RFC 3339 timestamp, exactly as hashed.
    ///
    /// Informational for ordering purposes: the chain provides ordering independent of
    /// any clock. Do not build alerting on these alone (DESIGN.md L4).
    pub at: String,
    /// Who acted.
    pub actor: Actor,
    /// Previous entry's hash, or the genesis hash for `seq == 1`.
    pub prev: EntryHash,
    /// This entry's hash.
    pub hash: EntryHash,
    /// What happened.
    pub event: AuditEvent,
}

impl AuditRecord {
    /// Recompute this record's hash from its contents.
    ///
    /// The heart of verification: if the recomputed hash differs from the stored one,
    /// the record was edited after it was written.
    #[must_use]
    pub fn recompute_hash(&self) -> EntryHash {
        let canonical = canonical_entry(
            self.seq,
            &self.prev,
            &self.at,
            &self.actor.principal,
            &self.actor.run_str(),
            &self.event,
        );
        self.prev.chain(&canonical)
    }

    /// Parse the timestamp, for display.
    ///
    /// # Errors
    /// [`KawachError::Audit`] if the stored text is not valid RFC 3339.
    pub fn timestamp(&self) -> Result<OffsetDateTime> {
        OffsetDateTime::parse(&self.at, &Rfc3339).map_err(|_| KawachError::Audit {
            detail: SafeDetail::trusted_static("audit record has a malformed timestamp"),
        })
    }
}

/// How often to emit a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointPolicy {
    /// Emit a checkpoint every N entries. Zero disables checkpointing.
    pub every_n_entries: u64,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self { every_n_entries: 64 }
    }
}

impl CheckpointPolicy {
    /// Never checkpoint. For tests and for short-lived processes.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { every_n_entries: 0 }
    }
}

struct Inner {
    file: File,
    seq: u64,
    head: EntryHash,
}

/// A hash-chained, append-only audit log.
///
/// Implements [`AuditAnchor`], so the capability tokens in `kawach-core` — which until
/// now enforced ordering against a trait with nothing behind it — are backed by a real
/// chain: no `CommitToken` is minted and no `ReadWitness` issued without a durable,
/// chained entry preceding it.
pub struct AuditLog {
    path: PathBuf,
    instance: String,
    actor: Actor,
    inner: Mutex<Inner>,
    policy: CheckpointPolicy,
    signer: Option<CheckpointSigner>,
}

impl AuditLog {
    /// Open (or create) the log at `path`, bound to `instance`.
    ///
    /// On an existing log the chain is **verified during replay**, so a tampered log is
    /// refused at open rather than silently appended to. This costs a full read of the
    /// file, which we were doing anyway to recover the head.
    ///
    /// # Errors
    /// [`KawachError::Audit`] on I/O failure or if the existing chain does not verify.
    pub fn open(
        path: impl Into<PathBuf>,
        instance: impl Into<String>,
        actor: Actor,
    ) -> Result<Self> {
        let path = path.into();
        let instance = instance.into();

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(io_err)?;
            }
        }

        let (seq, head) = if path.exists() {
            let report = crate::verify::verify_file(&path, &instance)?;
            if !report.is_intact() {
                return Err(KawachError::Audit {
                    detail: SafeDetail::new(format!(
                        "refusing to append to a log that does not verify: {}",
                        report.summary()
                    )),
                });
            }
            (report.entry_count, report.head.unwrap_or_else(|| EntryHash::genesis(&instance)))
        } else {
            (0, EntryHash::genesis(&instance))
        };

        let file = OpenOptions::new().create(true).append(true).open(&path).map_err(io_err)?;

        let log = Self {
            path,
            instance: instance.clone(),
            actor,
            inner: Mutex::new(Inner { file, seq, head }),
            policy: CheckpointPolicy::default(),
            signer: None,
        };
        log.append(AuditEvent::LogOpened { instance, resumed_at: AuditSeq(seq) })?;
        Ok(log)
    }

    /// Attach a checkpoint signer.
    #[must_use]
    pub fn with_signer(mut self, signer: CheckpointSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Set the checkpoint policy.
    #[must_use]
    pub fn with_checkpoint_policy(mut self, policy: CheckpointPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Where the log lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The instance this chain is bound to.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// The current chain head.
    #[must_use]
    pub fn head(&self) -> EntryHash {
        self.inner.lock().expect("audit log mutex poisoned").head
    }

    /// How many entries the chain holds.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.inner.lock().expect("audit log mutex poisoned").seq
    }

    /// Append an event under the log's default actor.
    ///
    /// # Errors
    /// [`KawachError::Audit`] on serialisation or I/O failure. Callers must treat this
    /// as fatal to whatever they were about to do: if we cannot record the action, we do
    /// not take it.
    pub fn append(&self, event: AuditEvent) -> Result<AuditSeq> {
        self.append_as(self.actor.clone(), event)
    }

    /// Append an event attributed to a specific actor.
    ///
    /// # Errors
    /// As [`AuditLog::append`].
    pub fn append_as(&self, actor: Actor, event: AuditEvent) -> Result<AuditSeq> {
        let seq = {
            let mut inner = self.inner.lock().expect("audit log mutex poisoned");
            Self::write_entry(&mut inner, &actor, event)?
        };
        self.maybe_checkpoint(seq)?;
        Ok(AuditSeq(seq))
    }

    /// Write one entry. Assumes the lock is held; does not trigger checkpointing, which
    /// would recurse.
    fn write_entry(inner: &mut Inner, actor: &Actor, event: AuditEvent) -> Result<u64> {
        let seq = inner.seq + 1;
        let at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| KawachError::Audit {
                detail: SafeDetail::trusted_static("failed to format audit timestamp"),
            })?;

        let canonical =
            canonical_entry(seq, &inner.head, &at, &actor.principal, &actor.run_str(), &event);
        let hash = inner.head.chain(&canonical);

        let record = AuditRecord {
            seq,
            at,
            actor: actor.clone(),
            prev: inner.head,
            hash,
            event,
        };
        let mut line = serde_json::to_string(&record)
            .map_err(|e| KawachError::Audit { detail: SafeDetail::from_error(&e) })?;
        line.push('\n');

        inner.file.write_all(line.as_bytes()).map_err(io_err)?;
        // Durable before we return, and therefore durable before the caller acts.
        inner.file.sync_data().map_err(io_err)?;

        inner.seq = seq;
        inner.head = hash;
        Ok(seq)
    }

    /// Emit a checkpoint if the policy calls for one at this sequence number.
    fn maybe_checkpoint(&self, seq: u64) -> Result<()> {
        let n = self.policy.every_n_entries;
        if n == 0 || seq % n != 0 {
            return Ok(());
        }
        self.checkpoint().map(|_| ())
    }

    /// Emit a checkpoint now, signing it if a signer is configured.
    ///
    /// # Errors
    /// As [`AuditLog::append`].
    pub fn checkpoint(&self) -> Result<AuditSeq> {
        let mut inner = self.inner.lock().expect("audit log mutex poisoned");
        let head = inner.head;
        let entry_count = inner.seq;
        let signature = self.signer.as_ref().map(|s| s.sign(entry_count, &head));
        let event = AuditEvent::Checkpoint {
            entry_count,
            head: head.to_hex(),
            signature,
        };
        let seq = Self::write_entry(&mut inner, &self.actor, event)?;
        Ok(AuditSeq(seq))
    }

    /// Publish the current head to an external anchor.
    ///
    /// This is what makes tail truncation detectable (DESIGN.md §7.3). The anchor's
    /// value comes from its store's ACL, not from this call — see [`Anchor`].
    ///
    /// # Errors
    /// Propagates anchor failures. An anchor that cannot be published is a real finding:
    /// from this point the log's tail is unprotected.
    pub fn publish_anchor(&self, anchor: &dyn Anchor) -> Result<AnchorRecord> {
        let (head, entry_count) = {
            let inner = self.inner.lock().expect("audit log mutex poisoned");
            (inner.head, inner.seq)
        };
        let at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| KawachError::Audit {
                detail: SafeDetail::trusted_static("failed to format anchor timestamp"),
            })?;
        let record = AnchorRecord { instance: self.instance.clone(), entry_count, head, at };
        anchor.publish(&record)?;
        Ok(record)
    }
}

/// This is the impl that turns `kawach-core`'s capability tokens from a well-typed
/// intention into an enforced one.
impl AuditAnchor for AuditLog {
    fn record(&self, event: CoreAuditEvent) -> Result<AuditSeq> {
        let mut actor = self.actor.clone();
        if let Some(run) = run_of(&event) {
            actor = actor.with_run(run);
        }
        self.append_as(actor, AuditEvent::from(event))
    }
}

impl core::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuditLog")
            .field("path", &self.path)
            .field("instance", &self.instance)
            .field("entries", &self.entry_count())
            .field("signed", &self.signer.is_some())
            .finish()
    }
}

/// Read every record from a log file.
///
/// Performs no verification — see [`crate::verify`] for that.
///
/// # Errors
/// [`KawachError::Audit`] on I/O failure or a malformed line.
pub fn read_records(path: &Path) -> Result<Vec<AuditRecord>> {
    let file = File::open(path).map_err(io_err)?;
    let mut records = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(io_err)?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecord = serde_json::from_str(&line).map_err(|e| KawachError::Audit {
            detail: SafeDetail::new(format!("malformed audit record at line {}: {e}", index + 1)),
        })?;
        records.push(record);
    }
    Ok(records)
}

fn io_err(e: std::io::Error) -> KawachError {
    KawachError::Audit { detail: SafeDetail::from_error(&e) }
}
