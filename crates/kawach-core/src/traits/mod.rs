//! The three extension points (DESIGN.md §5.3).
//!
//! ```text
//! SecretBackend    owns PUBLICATION      — list, describe, stage, promote, restore
//! RotationProvider owns the HOME SYSTEM  — provision, verify, drain, revoke, observe
//! DiscoverySource  owns SCANNING         — emit findings from a location
//! ```
//!
//! The engine owns the *protocol* between the first two: the state machine, the
//! write-ahead journal, the audit records, and the compensation logic. This split is
//! deliberate. The common alternative — one `Rotator` per credential type that also
//! writes to the store — forces every provider author to reimplement two-phase commit
//! and crash recovery, and getting that wrong is the outage. Here a provider author
//! writes a handful of individually testable methods and inherits a machine-checked
//! state machine.
//!
//! ## Contract for implementors
//!
//! Every implementation of these traits must satisfy:
//!
//! 1. **Idempotency.** Effectful methods are keyed by a
//!    [`CredentialHandle`](crate::refs::CredentialHandle) or
//!    [`VersionId`](crate::refs::VersionId) and must be safe to retry. `provision`
//!    called twice for one handle must not create two credentials; `revoke` on an
//!    already-revoked handle must succeed. This is what makes "resume the interrupted
//!    step" sound after a crash (DESIGN.md §6.3).
//! 2. **No plaintext egress.** Errors must carry [`SafeDetail`](crate::error::SafeDetail),
//!    never a raw foreign string that might embed a credential. Raw response buffers
//!    must be zeroized after parsing.
//! 3. **Honest capability reporting.** A backend that cannot read back a written value
//!    must say so in [`BackendCapabilities`](crate::model::BackendCapabilities). The
//!    engine's crash-recovery strategy depends on it; over-claiming here turns a
//!    recoverable state into a wrong assumption.
//! 4. **No mutation without a token.** The type system enforces this at the call
//!    boundary; implementors must not smuggle mutations into the read-only methods
//!    (`list`, `describe`, `preflight`, `observe`, `verify`).

mod backend;
mod discovery;
mod provider;

pub use backend::SecretBackend;
pub use discovery::{DiscoverySource, FindingSink, VecSink};
pub use provider::{Deadline, NewCredential, ProviderSettings, RotationProvider, RotationTarget};
