//! # KAWACH engine
//!
//! The driver that runs the rotation state machine against real backends and providers.
//!
//! `kawach-rotation` owns the protocol and proves its safety properties; this crate
//! owns execution. The separation is deliberate: the protocol is small, pure, and
//! exhaustively model-checked, while the engine is where I/O, partial failure, and
//! timeouts live. Keeping them apart is what lets the dangerous part be proved.
//!
//! ## What the engine guarantees
//!
//! * **A dry run cannot mutate.** It calls only the non-mutating trait methods, none of
//!   which accept a [`kawach_core::CommitToken`] — and in dry-run mode no token exists.
//!   This is checked by a test that asserts the mock world recorded zero mutations.
//! * **Every effect is preceded by a durable intent.** The transition into an in-flight
//!   state is journalled and `fsync`ed before the effect is attempted.
//! * **Infrastructure failures become state machine events**, so every failure path is
//!   one the model checker already proved safe, rather than an ad-hoc `catch`.
//! * **A crashed run is never resumed on an assumption.** Recovery reconciles against
//!   observed reality, and where the plaintext was lost with the process it compensates
//!   rather than pretending it can continue.

pub mod engine;
#[cfg(feature = "test-support")]
pub mod mock;
pub mod outcome;

pub use engine::RotationEngine;
pub use outcome::{PlannedStep, RotationOutcome, RotationPlan};
