//! The scope model: deny-by-default authority over which secrets KAWACH may touch.
//!
//! Scope enforcement is not a check a caller might forget. It is the *only* way to
//! obtain the argument type that backend methods accept:
//!
//! ```text
//! backend.describe(&secret_ref)              // does not compile: wrong type
//! backend.describe(&scope.authorize(&r)?)    // the only spelling that exists
//! ```
//!
//! A [`ScopedRef`] has a private field and no public constructor, so the only way to
//! produce one is [`Scope::authorize`], which applies the allow/deny rules. This is the
//! object-capability discipline described in DESIGN.md §5.2 applied to path authority.

use core::fmt;

use crate::error::{KawachError, Result};
use crate::refs::{BackendId, SecretRef};

/// A reference that has been checked against the configured scope.
///
/// Unforgeable outside this module. Holding one is proof that the allowlist permitted
/// this exact reference.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScopedRef {
    inner: SecretRef,
}

impl ScopedRef {
    /// The underlying reference.
    ///
    /// Named `secret_ref` rather than `as_ref` deliberately: an `AsRef` impl would let
    /// a `ScopedRef` coerce back into a plain `SecretRef` implicitly in generic code,
    /// which is precisely the erasure of authority this type exists to prevent.
    /// Discarding the capability should be an explicit, greppable call.
    #[must_use]
    pub fn secret_ref(&self) -> &SecretRef {
        &self.inner
    }

    /// The backend this reference belongs to.
    #[must_use]
    pub fn backend(&self) -> &BackendId {
        &self.inner.backend
    }

    /// The backend-specific path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.inner.path
    }
}

impl fmt::Display for ScopedRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

/// Why a reference was refused.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScopeDenial {
    /// No rules are configured for the named backend.
    UnknownBackend {
        /// The backend that has no rules.
        backend: BackendId,
    },
    /// A deny pattern matched. Deny is evaluated after allow and always wins.
    DeniedByRule {
        /// The pattern that matched.
        pattern: String,
    },
    /// No allow pattern matched. This is the default outcome — scope is an allowlist.
    NotAllowed,
}

impl fmt::Display for ScopeDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBackend { backend } => write!(f, "no scope rules for backend {backend}"),
            Self::DeniedByRule { pattern } => write!(f, "excluded by deny rule `{pattern}`"),
            Self::NotAllowed => f.write_str("not matched by any allow rule"),
        }
    }
}

/// Allow/deny patterns for one backend.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BackendScope {
    /// Patterns granting access. Empty means nothing is in scope for this backend.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Patterns revoking access. Evaluated after `allow`; always wins.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// The compiled scope for an entire KAWACH instance.
#[derive(Clone, Debug, Default)]
pub struct Scope {
    backends: Vec<(BackendId, BackendScope)>,
}

impl Scope {
    /// An empty scope. Authorizes nothing — the correct default.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Add rules for a backend.
    #[must_use]
    pub fn with_backend(mut self, backend: BackendId, rules: BackendScope) -> Self {
        self.backends.push((backend, rules));
        self
    }

    /// Whether any rules exist for `backend`.
    #[must_use]
    pub fn covers_backend(&self, backend: &BackendId) -> bool {
        self.backends.iter().any(|(id, _)| id == backend)
    }

    /// Decide whether `reference` is in scope, without constructing a capability.
    ///
    /// Use this for reporting ("here is what would be in scope"); use
    /// [`Scope::authorize`] when you intend to act.
    pub fn decide(&self, reference: &SecretRef) -> core::result::Result<(), ScopeDenial> {
        let Some((_, rules)) = self.backends.iter().find(|(id, _)| *id == reference.backend) else {
            return Err(ScopeDenial::UnknownBackend { backend: reference.backend.clone() });
        };

        // Deny is evaluated first in code but is defined as winning regardless of
        // order, so there is no rule-ordering semantics for an operator to reason
        // about — a deny rule cannot be re-enabled by a later allow.
        if let Some(pattern) = rules.deny.iter().find(|p| glob_match(p, &reference.path)) {
            return Err(ScopeDenial::DeniedByRule { pattern: pattern.clone() });
        }
        if rules.allow.iter().any(|p| glob_match(p, &reference.path)) {
            return Ok(());
        }
        Err(ScopeDenial::NotAllowed)
    }

    /// Authorize a reference, producing the capability that backend methods require.
    ///
    /// # Errors
    /// [`KawachError::OutOfScope`] with the specific denial reason.
    pub fn authorize(&self, reference: &SecretRef) -> Result<ScopedRef> {
        match self.decide(reference) {
            Ok(()) => Ok(ScopedRef { inner: reference.clone() }),
            Err(denial) => Err(KawachError::OutOfScope { reference: reference.clone(), denial }),
        }
    }

    /// Authorize every reference that is in scope, discarding the rest.
    ///
    /// For `list` results, where out-of-scope entries are expected and not an error.
    #[must_use]
    pub fn authorize_all(&self, refs: &[SecretRef]) -> Vec<ScopedRef> {
        refs.iter().filter_map(|r| self.authorize(r).ok()).collect()
    }
}

/// Match a restricted glob against a `/`-separated path.
///
/// Supported: `*` (any characters within one segment) and `**` (zero or more whole
/// segments). Deliberately **not** supported: character classes, alternation, regex.
///
/// A security allowlist is the worst possible place for an expressive pattern
/// language. Regex brings ReDoS, and — more importantly in practice — nobody reliably
/// predicts what a colleague's regex matches. The restricted grammar here is small
/// enough that its behaviour is obvious from the pattern.
#[must_use]
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let seg: Vec<&str> = path.split('/').collect();
    match_segments(&pat, &seg)
}

fn match_segments(pat: &[&str], seg: &[&str]) -> bool {
    match pat.first() {
        // Both exhausted: match.
        None => seg.is_empty(),
        Some(&"**") => {
            // `**` matches zero or more segments; try every split point.
            (0..=seg.len()).any(|skip| match_segments(&pat[1..], &seg[skip..]))
        }
        Some(p) => match seg.first() {
            None => false,
            Some(s) => match_one(p, s) && match_segments(&pat[1..], &seg[1..]),
        },
    }
}

/// Wildcard match within a single segment. `*` matches any run of non-`/` characters.
fn match_one(pattern: &str, segment: &str) -> bool {
    // Iterative two-pointer matcher with backtracking: linear in practice and immune
    // to the exponential blowup a naive recursive matcher shows on `a*a*a*a*b`.
    let (p, s) = (pattern.as_bytes(), segment.as_bytes());
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star, mut backtrack) = (usize::MAX, 0usize);

    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = pi;
            backtrack = si;
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            backtrack += 1;
            si = backtrack;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope::empty().with_backend(
            BackendId::new("vault-prod"),
            BackendScope {
                allow: vec![
                    "secret/data/app/*/db".into(),
                    "secret/data/app/*/api-keys/**".into(),
                ],
                deny: vec!["secret/data/app/*/root-*".into()],
            },
        )
    }

    fn r(path: &str) -> SecretRef {
        SecretRef::new(BackendId::new("vault-prod"), path)
    }

    #[test]
    fn single_star_stays_within_one_segment() {
        assert!(glob_match("secret/data/app/*/db", "secret/data/app/billing/db"));
        // `*` must not swallow the `/`, or an allowlist entry silently widens.
        assert!(!glob_match("secret/data/app/*/db", "secret/data/app/billing/nested/db"));
    }

    #[test]
    fn double_star_spans_segments_including_zero() {
        assert!(glob_match("a/**/c", "a/c"));
        assert!(glob_match("a/**/c", "a/b/c"));
        assert!(glob_match("a/**/c", "a/b/x/y/c"));
        assert!(glob_match("a/**", "a"));
        assert!(glob_match("a/**", "a/b/c"));
        assert!(!glob_match("a/**/c", "z/b/c"));
    }

    #[test]
    fn wildcards_compose_within_a_segment() {
        assert!(glob_match("app-*-prod", "app-billing-prod"));
        assert!(glob_match("*-*", "a-b"));
        assert!(!glob_match("app-*-prod", "app-billing-dev"));
    }

    #[test]
    fn pathological_patterns_do_not_blow_up() {
        // A naive recursive matcher takes exponential time here.
        let start = std::time::Instant::now();
        assert!(!match_one("a*a*a*a*a*a*a*b", &"a".repeat(64)));
        assert!(start.elapsed().as_millis() < 100, "matcher is not linear");
    }

    #[test]
    fn allowed_paths_authorize() {
        let s = scope();
        assert!(s.authorize(&r("secret/data/app/billing/db")).is_ok());
        assert!(s.authorize(&r("secret/data/app/billing/api-keys/stripe")).is_ok());
    }

    #[test]
    fn scope_is_deny_by_default() {
        let s = scope();
        let err = s.authorize(&r("secret/data/other/thing")).unwrap_err();
        assert!(matches!(err, KawachError::OutOfScope { denial: ScopeDenial::NotAllowed, .. }));
    }

    #[test]
    fn deny_beats_a_matching_allow() {
        // `secret/data/app/*/root-key` matches no allow rule here, so widen the allow
        // set to prove deny wins even when allow also matches.
        let s = Scope::empty().with_backend(
            BackendId::new("vault-prod"),
            BackendScope {
                allow: vec!["secret/data/app/**".into()],
                deny: vec!["secret/data/app/*/root-*".into()],
            },
        );
        let err = s.authorize(&r("secret/data/app/billing/root-key")).unwrap_err();
        assert!(matches!(err, KawachError::OutOfScope { denial: ScopeDenial::DeniedByRule { .. }, .. }));
        assert!(s.authorize(&r("secret/data/app/billing/db")).is_ok());
    }

    #[test]
    fn unknown_backends_are_refused_not_defaulted() {
        let s = scope();
        let other = SecretRef::new(BackendId::new("vault-staging"), "secret/data/app/billing/db");
        let err = s.authorize(&other).unwrap_err();
        assert!(matches!(err, KawachError::OutOfScope { denial: ScopeDenial::UnknownBackend { .. }, .. }));
    }

    #[test]
    fn an_empty_scope_authorizes_nothing() {
        assert!(Scope::empty().authorize(&r("anything")).is_err());
    }

    #[test]
    fn an_empty_allow_list_authorizes_nothing_even_with_the_backend_known() {
        let s = Scope::empty().with_backend(BackendId::new("vault-prod"), BackendScope::default());
        assert!(s.authorize(&r("secret/data/app/billing/db")).is_err());
    }

    #[test]
    fn authorize_all_filters_rather_than_failing() {
        let s = scope();
        let listed = vec![r("secret/data/app/billing/db"), r("secret/data/other/thing")];
        let allowed = s.authorize_all(&listed);
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].path(), "secret/data/app/billing/db");
    }
}
