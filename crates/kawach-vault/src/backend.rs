//! The Vault KV v2 [`SecretBackend`] implementation.
//!
//! ## Capability honesty
//!
//! KV v2 has **no atomic promote**: a write is immediately what consumers read. It also
//! has no native "make version N current" operation. Both facts are reported truthfully
//! through [`BackendCapabilities`], because the engine's crash-recovery strategy depends
//! on them — a backend that over-claims here turns a recoverable state into a wrong
//! assumption (DESIGN.md L3).
//!
//! ## Concurrency
//!
//! Every write uses KV v2's check-and-set (`cas`), so a second KAWACH instance that
//! published between our read and our write causes a *failed write* rather than a silent
//! clobber. This is a genuine improvement on the advisory lock described in DESIGN.md L6
//! — it is enforced by Vault rather than by our own good behaviour — though it detects a
//! concurrent writer rather than preventing one.

use async_trait::async_trait;
use kawach_core::{
    BackendCapabilities, BackendId, CommitToken, KawachError, PublishedState, ReadWitness, Result,
    SafeDetail, Scope, ScopedRef, SecretBackend, SecretMetadata, SecretRef, SecretString, VersionId,
};
use reqwest::Method;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::client::{VaultClient, VaultConfig};

/// A Vault KV v2 secret backend.
#[derive(Debug)]
pub struct VaultBackend {
    client: VaultClient,
    mount: String,
    field: String,
    id: BackendId,
}

impl VaultBackend {
    /// Connect and authenticate.
    ///
    /// # Errors
    /// Configuration or transport failures.
    pub async fn connect(config: VaultConfig) -> Result<Self> {
        let client = VaultClient::connect(&config).await?;
        Ok(Self {
            id: BackendId::new(&config.id),
            mount: config.mount.clone(),
            field: config.field.clone(),
            client,
        })
    }

    fn data_path(&self, reference: &ScopedRef) -> String {
        format!("{}/data/{}", self.mount, reference.path().trim_start_matches('/'))
    }

    fn metadata_path(&self, reference: &ScopedRef) -> String {
        format!("{}/metadata/{}", self.mount, reference.path().trim_start_matches('/'))
    }

    fn err(&self, operation: &'static str, detail: SafeDetail) -> KawachError {
        KawachError::Backend { backend: self.id.clone(), operation, detail }
    }

    /// The version currently current, from the metadata endpoint.
    async fn current_version(&self, reference: &ScopedRef) -> Result<Option<u64>> {
        match self.client.request(Method::GET, &self.metadata_path(reference), None, "metadata").await
        {
            Ok(value) => Ok(value.pointer("/data/current_version").and_then(Value::as_u64)),
            // A path that does not exist yet is not an error; it is an empty history.
            Err(KawachError::Backend { detail, .. }) if detail.as_str().contains("404") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write `value` as a new version under check-and-set.
    async fn write_value(
        &self,
        reference: &ScopedRef,
        value: &SecretString,
        cas: Option<u64>,
        operation: &'static str,
    ) -> Result<VersionId> {
        let body = serde_json::json!({
            "data": { &self.field: value.expose_str(std::borrow::ToOwned::to_owned)? },
            "options": { "cas": cas.unwrap_or(0) },
        });

        let response =
            self.client.request(Method::POST, &self.data_path(reference), Some(body), operation).await?;

        let version = response
            .pointer("/data/version")
            .and_then(Value::as_u64)
            .ok_or_else(|| self.err(operation, SafeDetail::trusted_static("write response contained no version")))?;
        Ok(VersionId::new(version.to_string()))
    }

    /// Read a specific version's value.
    async fn read_version(
        &self,
        reference: &ScopedRef,
        version: Option<&VersionId>,
        operation: &'static str,
    ) -> Result<SecretString> {
        let path = match version {
            Some(v) => format!("{}?version={}", self.data_path(reference), v),
            None => self.data_path(reference),
        };
        let response = self.client.request(Method::GET, &path, None, operation).await?;

        let raw = response
            .pointer(&format!("/data/data/{}", self.field))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                self.err(
                    operation,
                    // Names the field, never the payload.
                    SafeDetail::new(format!("secret has no field `{}`", self.field)),
                )
            })?;
        Ok(SecretString::from_string(raw.to_owned()))
    }
}

#[async_trait]
impl SecretBackend for VaultBackend {
    fn id(&self) -> &BackendId {
        &self.id
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            // KV v2 makes a write immediately current. Claiming otherwise would make the
            // engine believe it had a staging step it does not have.
            atomic_promote: false,
            versioned: true,
            readback: true,
            listing: true,
        }
    }

    async fn list(&self, scope: &Scope) -> Result<Vec<SecretRef>> {
        let path = format!("{}/metadata?list=true", self.mount);
        let response = self
            .client
            .request(Method::GET, &path, None, "list")
            .await
            .unwrap_or(Value::Null);

        let mut refs = Vec::new();
        if let Some(keys) = response.pointer("/data/keys").and_then(Value::as_array) {
            for key in keys.iter().filter_map(Value::as_str) {
                let reference = SecretRef::new(self.id.clone(), key);
                // Enumeration legitimately surfaces paths outside the allowlist; the
                // caller decides. Returning ScopedRef here would conflate "I can see it"
                // with "I may touch it".
                if scope.decide(&reference).is_ok() {
                    refs.push(reference);
                }
            }
        }
        Ok(refs)
    }

    async fn describe(&self, reference: &ScopedRef) -> Result<SecretMetadata> {
        let response =
            self.client.request(Method::GET, &self.metadata_path(reference), None, "describe").await?;

        let parse_time = |p: &str| {
            response
                .pointer(p)
                .and_then(Value::as_str)
                .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
        };

        Ok(SecretMetadata {
            reference: reference.secret_ref().clone(),
            created_at: parse_time("/data/created_time"),
            last_changed_at: parse_time("/data/updated_time"),
            // KV v2 records no access time. Reporting `None` rather than inventing one
            // keeps the orphan-detection factor honest about what it does not know.
            last_accessed_at: None,
            current_version: response
                .pointer("/data/current_version")
                .and_then(Value::as_u64)
                .map(|v| VersionId::new(v.to_string())),
            version_count: response
                .pointer("/data/versions")
                .and_then(Value::as_object)
                .map(|v| u32::try_from(v.len()).unwrap_or(u32::MAX)),
            labels: std::collections::BTreeMap::new(),
        })
    }

    async fn read(&self, reference: &ScopedRef, _witness: &ReadWitness<'_>) -> Result<SecretString> {
        // The witness is proof an audit record already exists; requiring it by type is
        // the enforcement, so there is nothing further to check here.
        self.read_version(reference, None, "read").await
    }

    async fn stage(
        &self,
        reference: &ScopedRef,
        value: SecretString,
        _commit: &CommitToken,
    ) -> Result<VersionId> {
        // Check-and-set against the version we believe is current. If another writer
        // published in between, Vault rejects the write instead of silently clobbering.
        let cas = self.current_version(reference).await?;
        self.write_value(reference, &value, cas, "stage").await
    }

    async fn promote(
        &self,
        _reference: &ScopedRef,
        _version: &VersionId,
        _commit: &CommitToken,
    ) -> Result<()> {
        // KV v2 has no staging step: `stage` already made the value current. Doing
        // anything here would be a second, meaningless write.
        Ok(())
    }

    async fn restore(
        &self,
        reference: &ScopedRef,
        version: &VersionId,
        _commit: &CommitToken,
        _witness: &ReadWitness<'_>,
    ) -> Result<()> {
        // KV v2 has no native version promotion, so restoring means reading the prior
        // value and writing it forward. That read is why this method takes a witness.
        //
        // A forward write rather than a destructive rollback: the backend's history then
        // records the rollback as an event, instead of erasing the evidence that a
        // rotation was attempted and abandoned.
        let previous = self.read_version(reference, Some(version), "restore_read").await?;
        let cas = self.current_version(reference).await?;
        self.write_value(reference, &previous, cas, "restore_write").await?;
        Ok(())
    }

    async fn observe_published(&self, reference: &ScopedRef) -> Result<PublishedState> {
        Ok(PublishedState {
            current_version: self
                .current_version(reference)
                .await?
                .map(|v| VersionId::new(v.to_string())),
            // Deliberately absent. Filling this in would require reading the plaintext,
            // and reconciliation does not need it: the engine compares version identity.
            // An unaudited read to populate a convenience field would be a poor trade.
            current_fingerprint: None,
            // KV v2 has no staged-but-not-current concept.
            staged_version: None,
        })
    }
}
