//! # KAWACH rotation
//!
//! The rotation state machine, its write-ahead journal, and the ghost model used to
//! machine-check its safety properties. See `DESIGN.md` §6.
//!
//! This crate contains **no I/O against backends or providers** — only the protocol.
//! That is deliberate: the state machine is the part where a mistake causes an outage,
//! so it is kept small, pure, and exhaustively checkable. The engine that drives it
//! against real backends sits above this crate.
//!
//! ## The two safety properties that matter
//!
//! * **S1** — nothing is revoked before its replacement is verified. Enforced by the
//!   shape of the graph: `Completed` is reachable only through `Verified`.
//! * **S2** — at every reachable state, consumers have at least one credential that is
//!   both live and published. This is "no dropped connections", stated as an invariant
//!   and checked at every node of an exhaustive exploration.
//!
//! Both are proved over the whole reachable space in `tests/model_check.rs`, not
//! sampled. A contributor who adds an unsafe transition gets a failing build with a
//! counterexample trace.

pub mod journal;
pub mod safety;
pub mod state;

pub use journal::{list_runs, replay, Journal, JournalEntry, RecoveredRun, Record};
pub use safety::Ghost;
pub use state::{
    next, reconcile, Observation, PublishedSide, RemediationHint, RotationEvent, RotationState, Step,
};
