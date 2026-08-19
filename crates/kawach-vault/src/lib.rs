//! # KAWACH Vault backend
//!
//! A [`SecretBackend`](kawach_core::SecretBackend) for HashiCorp Vault's KV v2 engine.
//!
//! Three things about this implementation are worth knowing before you use it:
//!
//! * **It cannot hold a master credential.** [`VaultAuth`] has variants for a file path,
//!   an environment variable *name*, and AppRole — all indirections. A configuration
//!   with an inline token fails to deserialise (DESIGN.md I4).
//! * **Writes use check-and-set.** A second instance that published between our read and
//!   our write causes a failed write rather than a silent clobber.
//! * **It reports its capabilities honestly.** KV v2 has no atomic promote and no native
//!   version promotion, and says so, because the engine's recovery strategy depends on
//!   the answer.

pub mod auth;
pub mod backend;
pub mod client;

pub use auth::{VaultAuth, VaultAuthMaterial};
pub use backend::VaultBackend;
pub use client::{VaultClient, VaultConfig};
