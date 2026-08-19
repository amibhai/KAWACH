//! Fault-injecting test doubles (feature `test-support`).
//!
//! These are not stubs that return canned values. [`MockWorld`] is a small in-memory
//! model of *both* halves of a rotation — the secret backend and the credential's home
//! system — so a test can assert the properties that actually matter after a run:
//!
//! * is the old credential still live?
//! * which value do consumers read?
//! * does the published value match the one that was provisioned and verified?
//!
//! That last one is checked by fingerprint, using KAWACH's own
//! [`FingerprintKey`](kawach_core::FingerprintKey), so the doubles never hold plaintext
//! either — the same discipline the real implementations are held to.
//!
//! They also serve as the **conformance kit**: an out-of-tree provider can be dropped in
//! beside `MockBackend` and driven through the same fault matrix to check it honours the
//! idempotency and honest-capability contracts in `kawach_core::traits`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kawach_core::{
    BackendCapabilities, BackendId, CommitToken, CredentialHandle, CredentialKind, Deadline,
    DrainPolicy, DrainReport, DrainStrategy, Fingerprint, FingerprintKey, KawachError,
    NewCredential, ObservedCredential, PasswordPolicy, Preflight, PublishedState, Result,
    RotationProvider, RotationTarget, SafeDetail, ScopedRef, Scope, SecretBackend, SecretMetadata,
    SecretRef, SecretString, VerificationCheck, VerificationReport, VersionId, WorldState,
};

/// Shared in-memory model of the world both doubles act on.
#[derive(Debug)]
pub struct MockWorld {
    key: FingerprintKey,
    inner: Mutex<WorldInner>,
}

#[derive(Debug, Default)]
struct WorldInner {
    /// Handle id -> whether the target system currently accepts it.
    live: HashMap<String, bool>,
    /// Handle id -> fingerprint of the value provisioned for it.
    provisioned: HashMap<String, Fingerprint>,
    /// Version id -> fingerprint of the value written at that version.
    versions: HashMap<String, Fingerprint>,
    /// The version consumers currently read.
    published: Option<VersionId>,
    /// Staged but not yet promoted.
    staged: Option<VersionId>,
    next_version: u64,
    next_credential: u64,
    /// Every mutating call, in order. The dry-run test asserts this stays empty.
    mutations: Vec<String>,
}

impl MockWorld {
    /// A world with one live credential whose value is already published.
    ///
    /// This is the precondition a rotation assumes: something exists to replace.
    #[must_use]
    pub fn with_active_credential(handle_id: &str) -> Arc<Self> {
        let key = FingerprintKey::generate();
        let initial = SecretString::from_string("the-original-password".to_owned());
        let fingerprint = initial.fingerprint(&key);

        let mut inner = WorldInner::default();
        inner.live.insert(handle_id.to_owned(), true);
        inner.provisioned.insert(handle_id.to_owned(), fingerprint);
        inner.versions.insert("v1".to_owned(), fingerprint);
        inner.published = Some(VersionId::new("v1"));
        inner.next_version = 1;

        Arc::new(Self { key, inner: Mutex::new(inner) })
    }

    /// A world with nothing in it: no credential, nothing published.
    ///
    /// The precondition a rotation does **not** have. Used to check that the engine
    /// refuses to bootstrap.
    #[must_use]
    pub fn empty() -> Arc<Self> {
        Arc::new(Self { key: FingerprintKey::generate(), inner: Mutex::new(WorldInner::default()) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WorldInner> {
        self.inner.lock().expect("mock world mutex poisoned")
    }

    /// Whether the target system accepts this credential.
    #[must_use]
    pub fn is_live(&self, handle_id: &str) -> bool {
        self.lock().live.get(handle_id).copied().unwrap_or(false)
    }

    /// The version consumers currently read.
    #[must_use]
    pub fn published_version(&self) -> Option<VersionId> {
        self.lock().published.clone()
    }

    /// Fingerprint of the value consumers currently read.
    #[must_use]
    pub fn published_fingerprint(&self) -> Option<Fingerprint> {
        let inner = self.lock();
        inner.published.as_ref().and_then(|v| inner.versions.get(v.as_str()).copied())
    }

    /// Fingerprint of the value provisioned for a credential.
    #[must_use]
    pub fn provisioned_fingerprint(&self, handle_id: &str) -> Option<Fingerprint> {
        self.lock().provisioned.get(handle_id).copied()
    }

    /// Whether consumers read exactly the value that was provisioned for `handle_id`.
    ///
    /// The end-to-end property of a successful rotation, checked without either double
    /// ever holding a plaintext value.
    #[must_use]
    pub fn consumers_read_credential(&self, handle_id: &str) -> bool {
        match (self.published_fingerprint(), self.provisioned_fingerprint(handle_id)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Every mutating call made against this world, in order.
    #[must_use]
    pub fn mutations(&self) -> Vec<String> {
        self.lock().mutations.clone()
    }

    fn record_mutation(&self, what: impl Into<String>) {
        self.lock().mutations.push(what.into());
    }
}

/// Which operations should fail.
#[derive(Clone, Copy, Debug, Default)]
pub struct BackendFaults {
    /// `stage` returns an error.
    pub fail_stage: bool,
    /// `promote` returns an error (only reachable when `atomic_promote` is set).
    pub fail_promote: bool,
    /// `restore` returns an error, stranding the compensation path.
    pub fail_restore: bool,
    /// `observe_published` returns an error.
    pub fail_observe: bool,
}

/// An in-memory [`SecretBackend`].
#[derive(Debug)]
pub struct MockBackend {
    id: BackendId,
    world: Arc<MockWorld>,
    capabilities: BackendCapabilities,
    faults: BackendFaults,
}

impl MockBackend {
    /// A Vault-like backend: versioned, read-back capable, no separate promote step.
    #[must_use]
    pub fn vault_like(world: Arc<MockWorld>) -> Self {
        Self {
            id: BackendId::new("mock"),
            world,
            capabilities: BackendCapabilities {
                atomic_promote: false,
                versioned: true,
                readback: true,
                listing: true,
            },
            faults: BackendFaults::default(),
        }
    }

    /// An AWS-like backend, where staging and promotion are distinct.
    #[must_use]
    pub fn staging_label_like(world: Arc<MockWorld>) -> Self {
        Self {
            capabilities: BackendCapabilities { atomic_promote: true, ..Self::vault_like(world.clone()).capabilities },
            ..Self::vault_like(world)
        }
    }

    /// Inject faults.
    #[must_use]
    pub fn with_faults(mut self, faults: BackendFaults) -> Self {
        self.faults = faults;
        self
    }

    fn fail(&self, operation: &'static str) -> KawachError {
        KawachError::Backend {
            backend: self.id.clone(),
            operation,
            detail: SafeDetail::trusted_static("injected fault"),
        }
    }
}

#[async_trait]
impl SecretBackend for MockBackend {
    fn id(&self) -> &BackendId {
        &self.id
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities
    }

    async fn list(&self, _scope: &Scope) -> Result<Vec<SecretRef>> {
        Ok(vec![])
    }

    async fn describe(&self, reference: &ScopedRef) -> Result<SecretMetadata> {
        Ok(SecretMetadata::bare(reference.secret_ref().clone()))
    }

    async fn read(
        &self,
        _reference: &ScopedRef,
        _witness: &kawach_core::ReadWitness<'_>,
    ) -> Result<SecretString> {
        Err(self.fail("read"))
    }

    async fn stage(
        &self,
        _reference: &ScopedRef,
        value: SecretString,
        _commit: &CommitToken,
    ) -> Result<VersionId> {
        if self.faults.fail_stage {
            return Err(self.fail("stage"));
        }
        let fingerprint = value.fingerprint(&self.world.key);
        self.world.record_mutation("backend.stage");

        let mut inner = self.world.lock();
        inner.next_version += 1;
        let version = VersionId::new(format!("v{}", inner.next_version));
        inner.versions.insert(version.as_str().to_owned(), fingerprint);
        if self.capabilities.atomic_promote {
            inner.staged = Some(version.clone());
        } else {
            // A write is immediately current, as in Vault KV v2.
            inner.published = Some(version.clone());
        }
        Ok(version)
    }

    async fn promote(
        &self,
        _reference: &ScopedRef,
        version: &VersionId,
        _commit: &CommitToken,
    ) -> Result<()> {
        if self.faults.fail_promote {
            return Err(self.fail("promote"));
        }
        self.world.record_mutation("backend.promote");
        let mut inner = self.world.lock();
        inner.published = Some(version.clone());
        inner.staged = None;
        Ok(())
    }

    async fn restore(
        &self,
        _reference: &ScopedRef,
        version: &VersionId,
        _commit: &CommitToken,
        _witness: &kawach_core::ReadWitness<'_>,
    ) -> Result<()> {
        if self.faults.fail_restore {
            return Err(self.fail("restore"));
        }
        self.world.record_mutation("backend.restore");
        let mut inner = self.world.lock();
        // Forward write of the prior value rather than a destructive rollback, so the
        // backend's history keeps a complete record including the rollback itself.
        let Some(fingerprint) = inner.versions.get(version.as_str()).copied() else {
            return Err(self.fail("restore"));
        };
        inner.next_version += 1;
        let new_version = VersionId::new(format!("v{}", inner.next_version));
        inner.versions.insert(new_version.as_str().to_owned(), fingerprint);
        inner.published = Some(new_version);
        Ok(())
    }

    async fn observe_published(&self, _reference: &ScopedRef) -> Result<PublishedState> {
        if self.faults.fail_observe {
            return Err(self.fail("observe_published"));
        }
        let inner = self.world.lock();
        Ok(PublishedState {
            current_version: inner.published.clone(),
            current_fingerprint: inner
                .published
                .as_ref()
                .and_then(|v| inner.versions.get(v.as_str()).copied()),
            staged_version: inner.staged.clone(),
        })
    }
}

/// Which provider operations should fail, and how.
#[derive(Clone, Copy, Debug)]
pub struct ProviderFaults {
    /// `provision` returns an error.
    pub fail_provision: bool,
    /// `verify` reports a failed check. Not an error — a legitimate negative result.
    pub verification_fails: bool,
    /// `verify` returns an error (connectivity, rather than a failed check).
    pub fail_verify: bool,
    /// The forward drain never completes, so the deadline expires.
    pub drain_never_completes: bool,
    /// The compensating drain never completes.
    pub reverse_drain_never_completes: bool,
    /// Revoking the old credential fails.
    pub fail_revoke_old: bool,
    /// Revoking the new credential fails.
    pub fail_revoke_new: bool,
    /// `preflight` reports a blocking finding.
    pub preflight_blocks: bool,
}

impl Default for ProviderFaults {
    /// Everything healthy.
    fn default() -> Self {
        Self {
            fail_provision: false,
            verification_fails: false,
            fail_verify: false,
            drain_never_completes: false,
            reverse_drain_never_completes: false,
            fail_revoke_old: false,
            fail_revoke_new: false,
            preflight_blocks: false,
        }
    }
}

/// An in-memory [`RotationProvider`].
#[derive(Debug)]
pub struct MockProvider {
    kind: CredentialKind,
    world: Arc<MockWorld>,
    faults: ProviderFaults,
    active_id: String,
}

impl MockProvider {
    /// A provider whose currently active credential is `active_id`.
    #[must_use]
    pub fn new(world: Arc<MockWorld>, active_id: &str) -> Self {
        Self {
            kind: CredentialKind::new("mock_ab"),
            world,
            faults: ProviderFaults::default(),
            active_id: active_id.to_owned(),
        }
    }

    /// Inject faults.
    #[must_use]
    pub fn with_faults(mut self, faults: ProviderFaults) -> Self {
        self.faults = faults;
        self
    }

    /// A target pointing at this provider.
    #[must_use]
    pub fn target(&self, reference: ScopedRef, run: kawach_core::RunId) -> RotationTarget {
        RotationTarget {
            run,
            reference,
            kind: self.kind.clone(),
            settings: kawach_core::ProviderSettings::new(),
            policy: PasswordPolicy::default(),
            drain: DrainPolicy {
                strategy: DrainStrategy::ObserveSessions,
                deadline: std::time::Duration::from_millis(10),
                poll_interval: std::time::Duration::from_millis(1),
            },
            active: Some(CredentialHandle::new(self.kind.clone(), self.active_id.clone())),
        }
    }

    fn fail(&self, operation: &'static str) -> KawachError {
        KawachError::Provider {
            provider: self.kind.to_string(),
            operation,
            detail: SafeDetail::trusted_static("injected fault"),
        }
    }
}

#[async_trait]
impl RotationProvider for MockProvider {
    fn kind(&self) -> CredentialKind {
        self.kind.clone()
    }

    fn drain_policy(&self) -> DrainPolicy {
        DrainPolicy::default()
    }

    async fn preflight(&self, _target: &RotationTarget) -> Result<Preflight> {
        if self.faults.preflight_blocks {
            return Ok(Preflight {
                findings: vec![kawach_core::PreflightFinding {
                    id: "injected_blocker".into(),
                    blocking: true,
                    detail: "injected preflight blocker".into(),
                }],
            });
        }
        Ok(Preflight::ready())
    }

    async fn observe(&self, _target: &RotationTarget) -> Result<WorldState> {
        let inner = self.world.lock();
        Ok(WorldState {
            credentials: inner
                .live
                .iter()
                .map(|(id, live)| ObservedCredential {
                    handle: CredentialHandle::new(self.kind.clone(), id.clone()),
                    live: *live,
                    active_sessions: Some(0),
                    last_used_at: None,
                })
                .collect(),
        })
    }

    async fn provision(
        &self,
        target: &RotationTarget,
        _commit: &CommitToken,
    ) -> Result<NewCredential> {
        if self.faults.fail_provision {
            return Err(self.fail("provision"));
        }
        let value = SecretString::generate(&target.policy)?;
        let fingerprint = value.fingerprint(&self.world.key);
        self.world.record_mutation("provider.provision");

        let mut inner = self.world.lock();
        inner.next_credential += 1;
        let id = format!("cred-{}", inner.next_credential);
        inner.live.insert(id.clone(), true);
        inner.provisioned.insert(id.clone(), fingerprint);

        Ok(NewCredential { handle: CredentialHandle::new(self.kind.clone(), id), value })
    }

    async fn verify(
        &self,
        _target: &RotationTarget,
        candidate: &SecretString,
    ) -> Result<VerificationReport> {
        if self.faults.fail_verify {
            return Err(self.fail("verify"));
        }
        // Verification is read-only: it must not appear in the mutation log.
        let fingerprint = candidate.fingerprint(&self.world.key);
        let known = self.world.lock().provisioned.values().any(|f| *f == fingerprint);

        Ok(VerificationReport::from_checks(vec![
            VerificationCheck {
                id: "connect".into(),
                passed: known && !self.faults.verification_fails,
                detail: if known { "authenticated".into() } else { "unknown credential".into() },
            },
            VerificationCheck {
                id: "privilege_probe".into(),
                passed: !self.faults.verification_fails,
                detail: "read the application's table".into(),
            },
        ]))
    }

    async fn drain(
        &self,
        _target: &RotationTarget,
        handle: &CredentialHandle,
        _deadline: Deadline,
    ) -> Result<DrainReport> {
        // The old credential is the one that was active when the run began; anything
        // else is the new one, drained during compensation.
        let is_old = handle.id == self.active_id;
        let stalls = if is_old {
            self.faults.drain_never_completes
        } else {
            self.faults.reverse_drain_never_completes
        };
        Ok(DrainReport {
            complete: !stalls,
            remaining_sessions: Some(u64::from(stalls)),
            elapsed: std::time::Duration::from_millis(1),
            strategy: DrainStrategy::ObserveSessions,
        })
    }

    async fn revoke(
        &self,
        _target: &RotationTarget,
        handle: &CredentialHandle,
        _commit: &CommitToken,
    ) -> Result<()> {
        let is_old = handle.id == self.active_id;
        if (is_old && self.faults.fail_revoke_old) || (!is_old && self.faults.fail_revoke_new) {
            return Err(self.fail("revoke"));
        }
        self.world.record_mutation(format!("provider.revoke:{}", handle.id));
        // Idempotent by construction: revoking an already-revoked handle succeeds.
        self.world.lock().live.insert(handle.id.clone(), false);
        Ok(())
    }
}
