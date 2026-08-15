//! # KAWACH core
//!
//! *Key And Wallet Audit & Credential Hardening* — the crate that holds every
//! security-relevant type. If you are reviewing KAWACH, review this crate first and
//! most carefully; everything above it inherits its guarantees.
//!
//! The full rationale is in `DESIGN.md`. In brief, this crate exists to make three
//! classes of mistake **unrepresentable** rather than merely discouraged:
//!
//! | Mistake | Why it cannot be written |
//! |---|---|
//! | Serialising or `Display`ing a secret value | [`SecretString`] implements neither trait. It is a compile error. |
//! | Touching a secret outside the configured scope | Backend methods take [`ScopedRef`], obtainable only from [`Scope::authorize`]. |
//! | Mutating during a dry run | Mutating methods take [`CommitToken`], mintable only from [`ExecutionMode::Apply`]. |
//! | Reading a plaintext value without an audit record | [`SecretBackend::read`] takes [`ReadWitness`], issued only after a durable audit write. |
//!
//! Each of those is an *object-capability*: a value with a private constructor whose
//! possession is proof that a check happened. The check therefore cannot be forgotten,
//! because it is not a check — it is the only way to obtain an argument.
//!
//! ## Layout
//!
//! * [`secret`] — [`SecretString`], the only type permitted to hold plaintext.
//! * [`fingerprint`] — non-invertible identifiers, the only value-derived datum persisted.
//! * [`capability`] — [`CommitToken`], [`ReadWitness`], [`ExecutionMode`].
//! * [`scope`] — the deny-by-default allowlist and [`ScopedRef`].
//! * [`error`] — errors that cannot carry secret material.
//! * [`model`] — persisted metadata; every type here is safe to serialise.
//! * [`traits`] — the three plugin seams.

pub mod capability;
pub mod error;
pub mod fingerprint;
pub mod hex;
pub mod model;
pub mod refs;
mod rng;
pub mod scope;
pub mod secret;
pub mod traits;

pub use capability::{
    AuditAnchor, CommitToken, Confirmation, CoreAuditEvent, ExecutionMode, ReadIntent, ReadOutcome,
    ReadWitness,
};
pub use error::{KawachError, Result, SafeDetail};
pub use fingerprint::{Fingerprint, FingerprintKey};
pub use model::{
    BackendCapabilities, DrainPolicy, DrainReport, DrainStrategy, Finding, Location,
    ObservedCredential, Preflight, PreflightFinding, PublishedState, ScanStats, SecretMetadata,
    VerificationCheck, VerificationReport, WorldState,
};
pub use refs::{
    AuditSeq, BackendId, CredentialHandle, CredentialKind, RunId, SecretRef, SourceId, VersionId,
};
pub use scope::{BackendScope, Scope, ScopeDenial, ScopedRef};
pub use secret::{Charset, PasswordPolicy, SecretString};
pub use traits::{
    Deadline, DiscoverySource, FindingSink, NewCredential, ProviderSettings, RotationProvider,
    RotationTarget, SecretBackend, VecSink,
};
