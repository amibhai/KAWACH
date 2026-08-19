//! Minimal Vault HTTP client.
//!
//! ## Response buffers are zeroized
//!
//! DESIGN.md I2 admits that `serde_json` allocates intermediate buffers we do not
//! control. What we *do* control is the raw response body, so we own it as a `String`,
//! parse it, and wipe it — rather than letting a buffer containing a secret sit in the
//! allocator's free list waiting to be handed to the next caller. That is a real
//! mitigation with a documented limit, not a claim of perfect hygiene.

use std::sync::Mutex;
use std::time::Duration;

use kawach_core::{BackendId, KawachError, Result, SafeDetail, SecretString};
use serde_json::Value;
use zeroize::Zeroize;

use crate::auth::{VaultAuth, VaultAuthMaterial};

/// Connection settings for a Vault KV v2 mount.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// Backend identifier used in `backend:path` references.
    pub id: String,
    /// Base address, e.g. `https://vault.internal:8200`.
    pub address: String,
    /// KV v2 mount point, e.g. `secret`.
    #[serde(default = "default_mount")]
    pub mount: String,
    /// Key within the KV data map that holds the credential.
    ///
    /// KV v2 stores a map, not a scalar. Naming the field explicitly avoids the
    /// guess-the-key behaviour that makes other tools clobber neighbouring keys.
    #[serde(default = "default_field")]
    pub field: String,
    /// How to authenticate. Cannot express an inline credential; see [`VaultAuth`].
    pub auth: VaultAuth,
    /// Vault Enterprise namespace, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_mount() -> String {
    "secret".to_owned()
}
fn default_field() -> String {
    "value".to_owned()
}
fn default_timeout() -> u64 {
    30
}

/// An authenticated Vault client.
pub struct VaultClient {
    http: reqwest::Client,
    address: String,
    namespace: Option<String>,
    token: Mutex<SecretString>,
    backend_id: BackendId,
}

impl VaultClient {
    /// Authenticate and return a ready client.
    ///
    /// # Errors
    /// [`KawachError::Config`] for unreadable auth material, [`KawachError::Backend`]
    /// for transport or login failures.
    pub async fn connect(config: &VaultConfig) -> Result<Self> {
        let backend_id = BackendId::new(&config.id);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            // Vault tokens are bearer credentials: following a redirect to another host
            // would hand ours to whoever controls it.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| KawachError::Backend {
                backend: backend_id.clone(),
                operation: "build_client",
                detail: SafeDetail::from_error(&e),
            })?;

        let address = config.address.trim_end_matches('/').to_owned();

        let token = match config.auth.load()? {
            VaultAuthMaterial::Token(token) => token,
            VaultAuthMaterial::AppRole { role_id, secret_id, mount } => {
                Self::approle_login(&http, &address, config.namespace.as_deref(), &backend_id, &role_id, &secret_id, &mount)
                    .await?
            }
        };

        Ok(Self {
            http,
            address,
            namespace: config.namespace.clone(),
            token: Mutex::new(token),
            backend_id,
        })
    }

    /// Exchange AppRole credentials for a token.
    async fn approle_login(
        http: &reqwest::Client,
        address: &str,
        namespace: Option<&str>,
        backend_id: &BackendId,
        role_id: &SecretString,
        secret_id: &SecretString,
        mount: &str,
    ) -> Result<SecretString> {
        let url = format!("{address}/v1/auth/{mount}/login");
        let body = serde_json::json!({
            "role_id": role_id.expose_str(|s| s.to_owned())?,
            "secret_id": secret_id.expose_str(|s| s.to_owned())?,
        });

        let mut request = http.post(&url).json(&body);
        if let Some(ns) = namespace {
            request = request.header("X-Vault-Namespace", ns);
        }
        let response = request.send().await.map_err(|e| KawachError::Backend {
            backend: backend_id.clone(),
            operation: "approle_login",
            detail: SafeDetail::from_error(&e),
        })?;

        let value = read_json(response, backend_id, "approle_login").await?;
        let token = value
            .pointer("/auth/client_token")
            .and_then(Value::as_str)
            .ok_or_else(|| KawachError::Backend {
                backend: backend_id.clone(),
                operation: "approle_login",
                detail: SafeDetail::trusted_static("login response contained no client token"),
            })?;
        Ok(SecretString::from_string(token.to_owned()))
    }

    /// The configured backend identifier.
    #[must_use]
    pub fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }

    /// Perform an authenticated request against `/v1/{path}`.
    ///
    /// # Errors
    /// [`KawachError::Backend`] on transport failure or a non-success status.
    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        operation: &'static str,
    ) -> Result<Value> {
        let url = format!("{}/v1/{}", self.address, path.trim_start_matches('/'));

        let token = {
            let guard = self.token.lock().expect("vault token mutex poisoned");
            guard.expose_str(|s| s.to_owned())?
        };

        let mut request = self.http.request(method, &url).header("X-Vault-Token", &token);
        if let Some(ns) = &self.namespace {
            request = request.header("X-Vault-Namespace", ns);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request.send().await.map_err(|e| KawachError::Backend {
            backend: self.backend_id.clone(),
            operation,
            detail: SafeDetail::from_error(&e),
        })?;

        read_json(response, &self.backend_id, operation).await
    }
}

impl core::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultClient")
            .field("address", &self.address)
            .field("backend", &self.backend_id)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Read a response body, parse it, and wipe the buffer.
async fn read_json(
    response: reqwest::Response,
    backend: &BackendId,
    operation: &'static str,
) -> Result<Value> {
    let status = response.status();
    let mut text = response.text().await.map_err(|e| KawachError::Backend {
        backend: backend.clone(),
        operation,
        detail: SafeDetail::from_error(&e),
    })?;

    if !status.is_success() {
        // Vault reports errors as {"errors": [...]}. Those strings come from a foreign
        // system, so they go through SafeDetail's scrubber before anyone sees them.
        let summary = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("errors").map(std::string::ToString::to_string))
            .unwrap_or_else(|| format!("HTTP {status}"));
        text.zeroize();
        return Err(KawachError::Backend {
            backend: backend.clone(),
            operation,
            detail: SafeDetail::new(format!("HTTP {status}: {summary}")),
        });
    }

    // 204 No Content is a success with an empty body (KV v2 delete, some writes).
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }

    let parsed = serde_json::from_str::<Value>(&text);
    // The body may have contained a secret. We own this buffer, so we wipe it rather
    // than leaving it for the allocator to recycle.
    text.zeroize();

    parsed.map_err(|e| KawachError::Backend {
        backend: backend.clone(),
        operation,
        detail: SafeDetail::from_error(&e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_an_inline_credential_anywhere_in_the_stanza() {
        let json = r#"{
            "id": "vault-prod",
            "address": "https://vault.internal:8200",
            "auth": {"method": "token_env", "name": "VAULT_TOKEN"},
            "token": "hvs-should-not-parse"
        }"#;
        let err = serde_json::from_str::<VaultConfig>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn config_defaults_are_the_conventional_ones() {
        let json = r#"{
            "id": "vault-prod",
            "address": "https://vault.internal:8200",
            "auth": {"method": "token_env", "name": "VAULT_TOKEN"}
        }"#;
        let config: VaultConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.mount, "secret");
        assert_eq!(config.field, "value");
        assert_eq!(config.timeout_secs, 30);
    }
}
