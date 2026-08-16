//! # KAWACH audit
//!
//! The tamper-evident audit log (DESIGN.md §7, invariant **I5**).
//!
//! This crate is what turns `kawach-core`'s capability tokens from a well-typed
//! intention into an enforced one. [`AuditLog`] implements
//! [`kawach_core::AuditAnchor`], so from here on:
//!
//! * a [`kawach_core::CommitToken`] cannot be minted without a durable, chained record
//!   of the confirmation that authorised it, and
//! * a [`kawach_core::ReadWitness`] cannot be issued without a durable, chained record
//!   of the intent to read — written *before* the read happens.
//!
//! ## What is actually guaranteed
//!
//! Being precise about this matters more than the feature list:
//!
//! | Attack | Detected by |
//! |---|---|
//! | Edit an entry in place | the chain — recomputed hash differs |
//! | Insert, delete, or reorder entries | the chain — `prev` no longer matches |
//! | Replace the log with one from another instance | genesis binding |
//! | Rewrite the whole chain from genesis | **signatures only** |
//! | Truncate the tail | **anchors only** |
//! | Delete the log entirely | **anchors only** |
//!
//! The last three are not detectable by a hash chain, whatever the marketing on
//! comparable tools says. They need a secret the adversary does not hold
//! ([`CheckpointSigner`]) or a second system they do not control ([`Anchor`]).
//!
//! And the honest ceiling: this is **tamper-evident**, not tamper-proof. An adversary
//! with local root can delete the file. The guarantee is that you will find out.

pub mod checkpoint;
pub mod event;
pub mod hash;
pub mod log;
pub mod verify;

pub use checkpoint::{Anchor, AnchorRecord, CheckpointSigner, CheckpointVerifier, FileAnchor};
pub use event::{Actor, AuditEvent};
pub use hash::{canonical_entry, CanonicalPayload, EntryHash};
pub use log::{read_records, AuditLog, AuditRecord, CheckpointPolicy};
pub use verify::{
    verify_against_anchor, verify_file, verify_records, verify_signatures, ChainStatus,
    VerificationReport,
};
