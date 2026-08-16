//! Signed checkpoints and external anchoring (DESIGN.md §7.3).
//!
//! A hash chain on its own has two gaps, and both are routinely glossed over by tools
//! that advertise "tamper-proof" logs:
//!
//! 1. **Tail truncation.** Delete the last *N* entries and everything remaining still
//!    verifies perfectly. The chain proves internal consistency, not completeness.
//! 2. **Wholesale rewrite.** An adversary who can write the file can recompute a
//!    consistent chain from genesis. Nothing in the chain itself says otherwise.
//!
//! Two mechanisms close them, and neither is the chain:
//!
//! * **Signed checkpoints** — a periodic Ed25519 signature over `(instance, count,
//!   head)`. An adversary without the signing key can *destroy* the log but cannot
//!   forge a consistent replacement, which turns a silent rewrite into a visible
//!   failure. The key must live outside the log's own trust domain, or it is merely a
//!   second file the same adversary can read.
//! * **External anchoring** — periodically publishing the head to a system whose ACL
//!   grants KAWACH `create` but not `update` or `delete`. Truncation past the last
//!   anchor is then detectable by comparison, and forging it requires compromising a
//!   *second* system holding *different* credentials.
//!
//! The result is **tamper-evident**, not tamper-proof. An adversary with local root can
//! still delete the log file. The guarantee is that you will know.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kawach_core::{hex, KawachError, Result, SafeDetail};
use zeroize::Zeroizing;

use crate::hash::{EntryHash, DOMAIN_CHECKPOINT};

/// The exact bytes a checkpoint signature covers.
///
/// Domain-separated and length-prefixed for the same reason the chain encoding is: a
/// signature over ambiguous bytes can be replayed under a different interpretation.
/// Binding `instance` prevents a checkpoint from one installation being presented as
/// evidence for another.
fn checkpoint_message(instance: &str, entry_count: u64, head: &EntryHash) -> Vec<u8> {
    let mut msg = Vec::with_capacity(96);
    msg.extend_from_slice(DOMAIN_CHECKPOINT);
    #[allow(clippy::cast_possible_truncation)]
    let len = instance.len() as u32;
    msg.extend_from_slice(&len.to_le_bytes());
    msg.extend_from_slice(instance.as_bytes());
    msg.extend_from_slice(&entry_count.to_le_bytes());
    msg.extend_from_slice(head.as_bytes());
    msg
}

/// Holds the Ed25519 private key that signs checkpoints.
///
/// The key is zeroized on drop. It should be released to the process at startup from a
/// secret backend rather than sitting next to the log — a signing key stored beside the
/// thing it authenticates protects against nobody who can reach the log.
pub struct CheckpointSigner {
    key: SigningKey,
    instance: String,
}

impl CheckpointSigner {
    /// Generate a fresh signing key.
    #[must_use]
    pub fn generate(instance: impl Into<String>) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed.as_mut());
        Self { key: SigningKey::from_bytes(&seed), instance: instance.into() }
    }

    /// Load a signing key from its 64-character hex seed.
    ///
    /// # Errors
    /// [`KawachError::Audit`] if the input is not 32 bytes of hex.
    pub fn from_hex(instance: impl Into<String>, seed_hex: &str) -> Result<Self> {
        let raw = hex::decode(seed_hex.trim()).ok_or_else(|| KawachError::Audit {
            detail: SafeDetail::trusted_static("checkpoint signing key is not valid hex"),
        })?;
        let seed = Zeroizing::new(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
            KawachError::Audit {
                detail: SafeDetail::trusted_static("checkpoint signing key must be 32 bytes"),
            }
        })?);
        Ok(Self { key: SigningKey::from_bytes(&seed), instance: instance.into() })
    }

    /// The public half, as hex, for distribution to verifiers.
    #[must_use]
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().as_bytes())
    }

    /// The matching verifier.
    #[must_use]
    pub fn verifier(&self) -> CheckpointVerifier {
        CheckpointVerifier { key: self.key.verifying_key(), instance: self.instance.clone() }
    }

    /// Sign a checkpoint, returning the signature as hex.
    #[must_use]
    pub fn sign(&self, entry_count: u64, head: &EntryHash) -> String {
        let msg = checkpoint_message(&self.instance, entry_count, head);
        hex::encode(&self.key.sign(&msg).to_bytes())
    }
}

impl core::fmt::Debug for CheckpointSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckpointSigner")
            .field("instance", &self.instance)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Verifies checkpoint signatures. Holds only public key material.
#[derive(Clone, Debug)]
pub struct CheckpointVerifier {
    key: VerifyingKey,
    instance: String,
}

impl CheckpointVerifier {
    /// Load a verifying key from its 64-character hex encoding.
    ///
    /// # Errors
    /// [`KawachError::Audit`] if the input is not a valid Ed25519 public key.
    pub fn from_hex(instance: impl Into<String>, key_hex: &str) -> Result<Self> {
        let raw = hex::decode(key_hex.trim()).ok_or_else(|| KawachError::Audit {
            detail: SafeDetail::trusted_static("checkpoint verifying key is not valid hex"),
        })?;
        let bytes = <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| KawachError::Audit {
            detail: SafeDetail::trusted_static("checkpoint verifying key must be 32 bytes"),
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| KawachError::Audit {
            detail: SafeDetail::trusted_static("checkpoint verifying key is not a valid Ed25519 point"),
        })?;
        Ok(Self { key, instance: instance.into() })
    }

    /// Whether `signature_hex` is a valid signature over this checkpoint.
    ///
    /// Returns `false` rather than an error for a malformed signature: from the
    /// verifier's point of view "not a signature" and "not a valid signature" are the
    /// same finding.
    #[must_use]
    pub fn verify(&self, entry_count: u64, head: &EntryHash, signature_hex: &str) -> bool {
        let Some(raw) = hex::decode(signature_hex.trim()) else { return false };
        let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else { return false };
        let signature = Signature::from_bytes(&bytes);
        let msg = checkpoint_message(&self.instance, entry_count, head);
        self.key.verify(&msg, &signature).is_ok()
    }
}

/// A published commitment to the chain head at a point in time.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnchorRecord {
    /// Which instance's chain.
    pub instance: String,
    /// How many entries the chain held.
    pub entry_count: u64,
    /// The head hash at that point.
    pub head: EntryHash,
    /// When it was published, RFC 3339.
    pub at: String,
}

/// An append-only external store for chain heads.
///
/// The security property comes entirely from the *store's* access control, not from
/// this trait: KAWACH must be able to `create` an anchor and must **not** be able to
/// `update` or `delete` one. An anchor KAWACH can rewrite is an anchor its attacker can
/// rewrite.
pub trait Anchor: Send + Sync {
    /// Publish a new anchor. Must not overwrite an existing one.
    ///
    /// # Errors
    /// Implementation-specific I/O or API failures.
    fn publish(&self, record: &AnchorRecord) -> Result<()>;

    /// The most recently published anchor for `instance`, if any.
    ///
    /// # Errors
    /// Implementation-specific I/O or API failures.
    fn latest(&self, instance: &str) -> Result<Option<AnchorRecord>>;
}

/// An anchor backed by a local append-only file.
///
/// # Security caveat
///
/// **A local file provides no protection against a local adversary (A3).** Anyone who
/// can rewrite the audit log can rewrite a file sitting beside it. This implementation
/// exists to exercise the seam in tests and to support the one deployment where it is
/// genuinely useful: a path on a remote WORM or append-only mount that KAWACH's own
/// host credentials cannot rewrite.
///
/// The anchors that carry real weight — a Vault path granted `create` without `update`,
/// or an S3 bucket with Object Lock — arrive with those backends in phases 5 and 6.
#[derive(Debug)]
pub struct FileAnchor {
    path: PathBuf,
}

impl FileAnchor {
    /// Anchor to a file at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Anchor for FileAnchor {
    fn publish(&self, record: &AnchorRecord) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(io_err)?;
        let mut line = serde_json::to_string(record)
            .map_err(|e| KawachError::Audit { detail: SafeDetail::from_error(&e) })?;
        line.push('\n');
        file.write_all(line.as_bytes()).map_err(io_err)?;
        file.sync_data().map_err(io_err)?;
        Ok(())
    }

    fn latest(&self, instance: &str) -> Result<Option<AnchorRecord>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let file = std::fs::File::open(&self.path).map_err(io_err)?;
        let mut best: Option<AnchorRecord> = None;
        for line in BufReader::new(file).lines() {
            let line = line.map_err(io_err)?;
            if line.trim().is_empty() {
                continue;
            }
            let record: AnchorRecord = serde_json::from_str(&line)
                .map_err(|e| KawachError::Audit { detail: SafeDetail::from_error(&e) })?;
            if record.instance != instance {
                continue;
            }
            // Highest entry_count wins. Taking the last line instead would let an
            // adversary who can append (but not rewrite) roll the anchor *backwards*
            // and hide a truncation.
            //
            // Written as an explicit match rather than `is_none_or`, which is stable
            // only since 1.82 and would silently raise the workspace MSRV of 1.75.
            let supersedes = match &best {
                None => true,
                Some(current) => record.entry_count > current.entry_count,
            };
            if supersedes {
                best = Some(record);
            }
        }
        Ok(best)
    }
}

fn io_err(e: std::io::Error) -> KawachError {
    KawachError::Audit { detail: SafeDetail::from_error(&e) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(seed: &str) -> EntryHash {
        EntryHash::genesis(seed)
    }

    #[test]
    fn a_signature_verifies_under_the_matching_key() {
        let signer = CheckpointSigner::generate("kawach-prod");
        let h = head("x");
        let sig = signer.sign(42, &h);
        assert!(signer.verifier().verify(42, &h, &sig));
    }

    #[test]
    fn a_signature_does_not_verify_under_a_different_key() {
        let signer = CheckpointSigner::generate("kawach-prod");
        let impostor = CheckpointSigner::generate("kawach-prod");
        let h = head("x");
        assert!(!impostor.verifier().verify(42, &head("x"), &signer.sign(42, &h)));
    }

    #[test]
    fn a_signature_is_bound_to_the_count_and_the_head() {
        // Both must be committed to: binding only the head would let an adversary claim
        // a stale head covered more entries than it did, and vice versa.
        let signer = CheckpointSigner::generate("i");
        let v = signer.verifier();
        let sig = signer.sign(42, &head("x"));
        assert!(v.verify(42, &head("x"), &sig));
        assert!(!v.verify(43, &head("x"), &sig), "entry count is not bound");
        assert!(!v.verify(42, &head("y"), &sig), "head is not bound");
    }

    #[test]
    fn a_signature_is_bound_to_the_instance() {
        // Otherwise a checkpoint from a quiet instance could be presented as evidence
        // for a busy one.
        let signer = CheckpointSigner::generate("kawach-prod");
        let other_instance = CheckpointVerifier::from_hex("kawach-staging", &signer.verifying_key_hex()).unwrap();
        let sig = signer.sign(42, &head("x"));
        assert!(signer.verifier().verify(42, &head("x"), &sig));
        assert!(!other_instance.verify(42, &head("x"), &sig));
    }

    #[test]
    fn malformed_signatures_are_rejected_rather_than_erroring() {
        let v = CheckpointSigner::generate("i").verifier();
        for bad in ["", "zz", "abcd", &"ab".repeat(64)] {
            assert!(!v.verify(1, &head("x"), bad));
        }
    }

    #[test]
    fn keys_round_trip_through_hex() {
        let signer = CheckpointSigner::generate("i");
        let verifier = CheckpointVerifier::from_hex("i", &signer.verifying_key_hex()).unwrap();
        let sig = signer.sign(7, &head("x"));
        assert!(verifier.verify(7, &head("x"), &sig));
    }

    #[test]
    fn malformed_keys_are_refused() {
        assert!(CheckpointSigner::from_hex("i", "not-hex").is_err());
        assert!(CheckpointSigner::from_hex("i", "aabb").is_err());
        assert!(CheckpointVerifier::from_hex("i", "aabb").is_err());
        assert!(CheckpointVerifier::from_hex("i", "").is_err());
    }

    #[test]
    fn an_arbitrary_well_formed_key_verifies_nothing() {
        // Loading a verifying key checks length and Edwards-point decompression, and
        // most 32-byte strings decompress successfully — so `from_hex` succeeding says
        // nothing about whether the key corresponds to anyone. The security-relevant
        // property is not that bogus keys are rejected at load, but that they validate
        // no signature anyone else produced.
        let arbitrary = CheckpointVerifier::from_hex("i", &"ff".repeat(32))
            .expect("this encoding happens to decompress");
        let signer = CheckpointSigner::generate("i");
        assert!(!arbitrary.verify(1, &head("x"), &signer.sign(1, &head("x"))));
    }

    #[test]
    fn signer_debug_does_not_reveal_key_material() {
        let signer = CheckpointSigner::generate("kawach-prod");
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(rendered.contains("kawach-prod"));
    }

    #[test]
    fn anchors_round_trip_and_report_the_highest_count() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = FileAnchor::new(dir.path().join("anchors.jsonl"));
        assert!(anchor.latest("kawach-prod").unwrap().is_none());

        for count in [10u64, 25, 17] {
            anchor
                .publish(&AnchorRecord {
                    instance: "kawach-prod".into(),
                    entry_count: count,
                    head: head(&count.to_string()),
                    at: "2026-01-01T00:00:00Z".into(),
                })
                .unwrap();
        }
        // 17 was published last, but 25 is the highest-water mark. Taking the last line
        // would let an append-only adversary roll the anchor backwards to hide a
        // truncation.
        assert_eq!(anchor.latest("kawach-prod").unwrap().unwrap().entry_count, 25);
    }

    #[test]
    fn anchors_are_scoped_per_instance() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = FileAnchor::new(dir.path().join("anchors.jsonl"));
        anchor
            .publish(&AnchorRecord {
                instance: "other".into(),
                entry_count: 99,
                head: head("o"),
                at: "2026-01-01T00:00:00Z".into(),
            })
            .unwrap();
        assert!(anchor.latest("kawach-prod").unwrap().is_none());
    }
}
