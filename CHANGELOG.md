# Changelog

All notable changes to KAWACH are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Pre-1.0 stability:** KAWACH is pre-alpha. Until `1.0.0` the trait signatures, the
configuration schema, and the on-disk journal format may change in any release. A
`Security` section is used for changes that affect a security invariant, and those are
called out even when they are additive — an invariant that quietly changes meaning
between releases is worse than one that never existed.

---

## [Unreleased]

Phases 1–3 complete (design, security core, rotation protocol). No CLI, backends, or
providers yet; see the [phase table](README.md#phases).

### Added

#### Phase 1 — Design & threat model
- `DESIGN.md`: adversary model (A1–A6), asset inventory, trust boundaries, and an
  explicit out-of-scope section.
- Eight security invariants, each stated with its enforcement mechanism (type-level,
  runtime, or process), the test that would catch a regression, and its **residual
  risk**.
- The rotation state machine with transition semantics and crash-recovery protocol.
- Tamper-evident audit-log construction: hash chain, canonical binary encoding, and an
  analysis of what a chain does *not* stop (tail truncation) with the anchoring design
  that addresses it.
- Minimal least-privilege policies for Vault, AWS IAM, and PostgreSQL.
- A limitations section (L1–L9) and a status table separating what is enforced in code
  from what is still design intent.

#### Phase 2 — Security core (`kawach-core`)
- `SecretString`: zeroizing secret container with closure-scoped `expose()`,
  constant-time comparison, CSPRNG generation with rejection sampling, and Shannon
  entropy measurement.
- `Fingerprint` / `FingerprintKey`: 128-bit truncated HMAC-SHA-256 under an
  installation-scoped key.
- Capability tokens: `ScopedRef` (path authority), `CommitToken` (mutation authority),
  and `ReadWitness` (audited plaintext access), each with a private constructor.
- `Scope`: deny-by-default allowlist with a restricted glob grammar (`*` within a
  segment, `**` across segments; no character classes, alternation, or regex).
- `KawachError` and `SafeDetail`, which scrubs URI userinfo and high-entropy tokens out
  of foreign error text.
- The three plugin traits — `SecretBackend`, `RotationProvider`, `DiscoverySource` —
  with an implementor contract covering idempotency, no plaintext egress, and honest
  capability reporting.
- Metadata model: `SecretMetadata`, `Finding`, `Location`, `VerificationReport`,
  `DrainPolicy`, `WorldState`, and related types, none of which can hold a secret value.
- `tests/type_level_guarantees.rs`: compile-time assertions that `SecretString` and
  `NewCredential` are **not** `Serialize` and that `SecretString` is **not** `Display`,
  with positive controls proving the probe discriminates.

#### Phase 3 — Rotation protocol (`kawach-rotation`)
- The 16-state rotation machine: forward path, mirrored compensation path
  (`RestoringPublication` → `ReverseDraining` → `RevokingNew`), and three disjoint
  terminal states.
- `reconcile()`: resolves an unknown-outcome state against observed reality after a
  crash, escalating rather than guessing when the observation is inconclusive.
- `RemediationHint`: structured operator guidance on every escalation, built from fixed
  strings only so an escalation can never become a leak path.
- `Journal`: append-only, `fsync`-per-entry write-ahead log with replay, sequence-gap
  and transition-chain validation, and tolerance for a torn final line.
- `Ghost`: the ghost-state model used to check availability, with nondeterministic
  modelling of failure outcomes.
- `tests/model_check.rs`: exhaustive exploration of the reachable state × world space
  asserting safety properties S1–S5, plus a meta-test that points the checker at a
  deliberately unsafe machine and asserts it fails.

#### Repository
- `.gitignore` covering build artefacts, local KAWACH state (journals, audit log,
  fingerprint key), and credential-shaped files.
- `README.md` with the phase table, architecture, backend/provider matrix, and the
  safety statement.
- Workspace lints: `unsafe_code = "deny"`, `missing_docs`, and clippy denials for
  `dbg_macro` / `print_stdout` / `print_stderr`.

### Security
- Credential-shaped test fixtures are now assembled from fragments at run time rather
  than written as literals. A `hvs.`-prefixed literal in `error.rs` — inside the test
  asserting that errors never leak credentials — was correctly rejected by GitHub push
  protection as a HashiCorp Vault token. The fixture was changed rather than the
  repository allowlisted: a secrets-hardening tool that exempts its own repository has
  refuted its premise. Test fidelity is unchanged, since `SafeDetail` scrubs on length
  and entropy, never on vendor prefix.
- `panic = "unwind"` pinned for release builds. `panic = "abort"` would skip `Drop` and
  therefore skip zeroization of any secret live at the point of a panic.

### Fixed
- `entropy_separates_random_from_prose` was statistically flaky. Shannon entropy over 40
  draws from a 66-symbol alphabet is an estimator biased downward by collisions (~30
  distinct symbols expected), so the measurement sat near log2(30) and intermittently
  fell below the 4.5 bits/byte threshold. Now samples 4096 draws so the estimate
  converges toward log2(66) = 6.04, asserted at > 5.5.

### Known limitations
See [DESIGN.md §12](DESIGN.md#12-limitations-residual-risk-and-what-could-go-wrong). The
load-bearing ones at this stage:
- The audit log is **not implemented** — only the `AuditAnchor` seam exists. The
  capability tokens enforce ordering against that trait, not against a real hash chain.
- Without checkpoint signing and external anchoring, the designed chain would detect
  edits, reordering, and insertion, but **not tail truncation**.
- No process hardening yet: `RLIMIT_CORE`, `PR_SET_DUMPABLE`, and `mlockall` are
  designed but not applied, so I2's residual risk is larger today than the design
  intends.
- Windows cannot prevent a crash dump from containing secret material. Development on
  Windows is supported; production deployment is not recommended.

---

## Planned

Entries move from here into a release section as they land. Full scope per phase is in
the [README phase table](README.md#phases).

- **Phase 4** — Tamper-evident audit log: hash chain over canonical binary encoding,
  Ed25519 checkpoint signing, external anchoring, `kawach audit verify`.
- **Phase 5** — Rotation engine, Vault KV v2 backend, PostgreSQL A/B-role provider, and
  the zero-dropped-connections demo.
- **Phase 6** — AWS Secrets Manager backend and generic API-key provider.
- **Phase 7** — Discovery sources, detector chain, and the explainable risk model.
- **Phase 8** — CLI, declarative YAML config, and the `doctor` privilege self-audit.
- **Phase 9** — CI (build, clippy, test, gitleaks, cargo-deny), redaction tripwire,
  process hardening, `SECURITY.md`, packaging.

[Unreleased]: https://github.com/amibhai/KAWACH/commits/main
