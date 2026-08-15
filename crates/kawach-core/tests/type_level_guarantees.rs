//! Compile-time proof of the negative guarantees in DESIGN.md **I1** and **I7**.
//!
//! Most of KAWACH's redaction safety comes from traits [`SecretString`] deliberately
//! does **not** implement. A prose claim ("we did not implement `Serialize`") is worth
//! nothing without a test, but "assert this does not compile" is awkward: the usual
//! tool (`trybuild`) compares compiler *stderr* text, which changes between Rust
//! releases and makes CI fail for reasons unrelated to the property under test.
//!
//! So we detect trait implementations at compile time instead, using **inherent-impl
//! precedence**: for a concrete type, an inherent associated const is preferred over a
//! blanket-trait one, but only when its bound is satisfied. Otherwise resolution falls
//! back to the trait's default. The result is a `const bool` that is `true` exactly
//! when the trait is implemented, and which can be used in a `const` assertion.
//!
//! This is deterministic, toolchain-independent, and fails at **compile time** for the
//! contributor who adds `#[derive(Serialize)]` to a secret-bearing type — not in
//! review, and not in production.
//!
//! Note the probes must be written at concrete types. Inside a generic function `T` is
//! unconstrained, the inherent impl never applies, and every answer would be `false` —
//! which is why the positive controls at the bottom of this file matter: they prove the
//! probe discriminates rather than always reporting "not implemented".

use std::fmt::Display;
use std::marker::PhantomData;

use kawach_core::secret::SecretString;
use kawach_core::{CommitToken, Fingerprint, NewCredential, SecretRef};

/// Probe type. `Probe::<T>::SERIALIZE` is `true` iff `T: Serialize`;
/// `Probe::<T>::DISPLAY` is `true` iff `T: Display`.
struct Probe<T>(PhantomData<T>);

/// Fallbacks: blanket impls that apply to every `T`, so they are what resolution finds
/// when the corresponding inherent impl's bound is not satisfied.
trait NotSerialize {
    const SERIALIZE: bool = false;
}
impl<T> NotSerialize for Probe<T> {}

trait NotDisplay {
    const DISPLAY: bool = false;
}
impl<T> NotDisplay for Probe<T> {}

/// Inherent impls: higher precedence, but only applicable when the bound holds.
impl<T: serde::Serialize> Probe<T> {
    const SERIALIZE: bool = true;
}

impl<T: Display> Probe<T> {
    const DISPLAY: bool = true;
}

// ---------------------------------------------------------------------------
// Positive controls, first: if the probe were broken and always answered "not
// implemented", every negative assertion below would pass vacuously. These fail the
// build if that ever happens.
// ---------------------------------------------------------------------------

const _: () = assert!(
    Probe::<Fingerprint>::SERIALIZE,
    "probe is vacuous: Fingerprint is Serialize and must be detected as such"
);
const _: () = assert!(
    Probe::<SecretRef>::SERIALIZE,
    "probe is vacuous: SecretRef is Serialize and must be detected as such"
);
const _: () = assert!(
    Probe::<SecretRef>::DISPLAY,
    "probe is vacuous: SecretRef is Display and must be detected as such"
);

// ---------------------------------------------------------------------------
// The guarantees themselves.
// ---------------------------------------------------------------------------

/// **I1** — a secret value cannot be serialised.
///
/// If someone adds `impl Serialize for SecretString`, or derives it, this assertion
/// fails to compile and the build stops. That is the enforcement mechanism for "no
/// secret reaches a serialised output": not a lint, not a review checklist — a compile
/// error.
const _: () = assert!(
    !Probe::<SecretString>::SERIALIZE,
    "SecretString must not implement Serialize. Serialising a secret is the leak this \
     type exists to prevent; to serialise a struct containing one, mark the field \
     #[serde(skip)]."
);

/// **I1** — a secret value cannot reach a format string.
///
/// Without `Display`, `format!("{}", secret)` is a compile error, which forces every
/// intentional exposure through the greppable `SecretString::expose` API.
const _: () = assert!(
    !Probe::<SecretString>::DISPLAY,
    "SecretString must not implement Display: it would make an interpolation of a \
     secret into a format string compile, and every log line is then one such \
     interpolation away from a leak."
);

/// **I1** — the guarantee is inherited by anything that *contains* a secret.
///
/// `NewCredential` holds a `SecretString`, so it cannot be journalled, shipped to
/// telemetry, or written into a report.
const _: () = assert!(
    !Probe::<NewCredential>::SERIALIZE,
    "NewCredential holds a secret value and must not become serialisable"
);

/// **I7** — authority to mutate cannot be persisted or replayed.
///
/// A serialisable `CommitToken` could be minted by one audited `--apply` run, stored,
/// and reused later outside the confirmation that produced it.
const _: () = assert!(
    !Probe::<CommitToken>::SERIALIZE,
    "CommitToken must not be serialisable: authority must not outlive its audited run"
);

#[test]
// The constant value *is* the point: each assertion is a compile-time claim about a
// trait impl, restated at runtime so a reader can see the probe discriminates.
#[allow(clippy::assertions_on_constants)]
fn type_level_guarantees_hold() {
    // The assertions above are evaluated by the compiler; reaching this test at all
    // means they passed. The body restates them at runtime so the discrimination is
    // visible to a reader.
    assert!(!Probe::<SecretString>::SERIALIZE);
    assert!(!Probe::<SecretString>::DISPLAY);
    assert!(!Probe::<NewCredential>::SERIALIZE);
    assert!(!Probe::<CommitToken>::SERIALIZE);

    assert!(Probe::<Fingerprint>::SERIALIZE);
    assert!(Probe::<SecretRef>::SERIALIZE);
    assert!(Probe::<SecretRef>::DISPLAY);
}
