//! Vault authentication (DESIGN.md **I4**).
//!
//! Note what this module cannot express: a token literal. [`VaultAuth`] has variants for
//! a file path, an environment variable *name*, and AppRole — every one an indirection.
//! A configuration containing an inline `token: "hvs...."` fails to deserialise with an
//! unknown-field error, so the insecure configuration is not representable rather than
//! merely discouraged.

use std::path::PathBuf;

use kawach_core::{KawachError, Result, SafeDetail, SecretString};
use zeroize::Zeroize;

/// How KAWACH authenticates to Vault.
///
/// `deny_unknown_fields` is what makes I4 enforceable: an operator who writes
/// `token: "hvs.CAESI..."` gets a parse error naming the offending key rather than a
/// working configuration with a credential in it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum VaultAuth {
    /// Read a token from a file, e.g. a Vault Agent sink.
    ///
    /// The preferred method: the agent handles renewal, and the token never appears in
    /// a process listing or an environment dump.
    TokenFile {
        /// Path to the file containing the token.
        path: PathBuf,
    },
    /// Read a token from the named environment variable.
    ///
    /// The field is the variable's **name**, not its value.
    TokenEnv {
        /// Name of the environment variable, e.g. `VAULT_TOKEN`.
        name: String,
    },
    /// AppRole login, with both halves read from files.
    AppRole {
        /// File containing the role id.
        role_id_file: PathBuf,
        /// File containing the secret id.
        secret_id_file: PathBuf,
        /// Mount path of the AppRole auth method.
        #[serde(default = "default_approle_mount")]
        mount: String,
    },
}

fn default_approle_mount() -> String {
    "approle".to_owned()
}

impl VaultAuth {
    /// Whether this method needs a login round-trip before use.
    #[must_use]
    pub fn requires_login(&self) -> bool {
        matches!(self, Self::AppRole { .. })
    }

    /// Read the material this method needs, without contacting Vault.
    ///
    /// For token methods this is the token itself. For AppRole it is the role and secret
    /// ids, which the client then exchanges for a token.
    ///
    /// # Errors
    /// [`KawachError::Config`] if a referenced file or variable is missing or empty.
    pub fn load(&self) -> Result<VaultAuthMaterial> {
        match self {
            Self::TokenFile { path } => Ok(VaultAuthMaterial::Token(read_secret_file(path)?)),
            Self::TokenEnv { name } => {
                let mut raw = std::env::var(name).map_err(|_| KawachError::Config {
                    location: format!("auth.token_env[{name}]"),
                    detail: SafeDetail::trusted_static("environment variable is not set"),
                })?;
                if raw.trim().is_empty() {
                    raw.zeroize();
                    return Err(KawachError::Config {
                        location: format!("auth.token_env[{name}]"),
                        detail: SafeDetail::trusted_static("environment variable is empty"),
                    });
                }
                let token = SecretString::from_string(raw.trim().to_owned());
                raw.zeroize();
                Ok(VaultAuthMaterial::Token(token))
            }
            Self::AppRole { role_id_file, secret_id_file, mount } => {
                Ok(VaultAuthMaterial::AppRole {
                    role_id: read_secret_file(role_id_file)?,
                    secret_id: read_secret_file(secret_id_file)?,
                    mount: mount.clone(),
                })
            }
        }
    }
}

/// Material loaded from the configured auth source. Never persisted.
#[derive(Debug)]
#[non_exhaustive]
pub enum VaultAuthMaterial {
    /// A token, ready to use.
    Token(SecretString),
    /// AppRole credentials, to be exchanged for a token.
    AppRole {
        /// The role id.
        role_id: SecretString,
        /// The secret id.
        secret_id: SecretString,
        /// AppRole mount path.
        mount: String,
    },
}

/// Read a file into a [`SecretString`], zeroizing the intermediate buffer.
///
/// `std::fs::read_to_string` allocates a `String` we do not control the lifetime of, so
/// we wipe it explicitly rather than leave a copy for the allocator to hand out later.
fn read_secret_file(path: &std::path::Path) -> Result<SecretString> {
    let mut raw = std::fs::read_to_string(path).map_err(|e| KawachError::Config {
        location: path.display().to_string(),
        detail: SafeDetail::from_error(&e),
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        raw.zeroize();
        return Err(KawachError::Config {
            location: path.display().to_string(),
            detail: SafeDetail::trusted_static("credential file is empty"),
        });
    }
    let secret = SecretString::from_string(trimmed.to_owned());
    raw.zeroize();
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inline_token_is_not_representable() {
        // The core of invariant I4: the insecure configuration does not parse.
        let yaml_like = r#"{"method":"token_env","name":"VAULT_TOKEN","token":"hvs-would-be-here"}"#;
        let err = serde_json::from_str::<VaultAuth>(yaml_like).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "an inline token must be rejected by the schema, got: {err}"
        );
    }

    #[test]
    fn the_supported_methods_are_all_indirections() {
        let file: VaultAuth =
            serde_json::from_str(r#"{"method":"token_file","path":"/run/secrets/token"}"#).unwrap();
        assert!(matches!(file, VaultAuth::TokenFile { .. }));

        let env: VaultAuth =
            serde_json::from_str(r#"{"method":"token_env","name":"VAULT_TOKEN"}"#).unwrap();
        assert!(matches!(env, VaultAuth::TokenEnv { .. }));

        let approle: VaultAuth = serde_json::from_str(
            r#"{"method":"app_role","role_id_file":"/r","secret_id_file":"/s"}"#,
        )
        .unwrap();
        assert!(approle.requires_login());
    }

    #[test]
    fn a_missing_env_var_is_a_configuration_error_naming_the_variable() {
        let auth = VaultAuth::TokenEnv { name: "KAWACH_TEST_DEFINITELY_UNSET".into() };
        let err = auth.load().unwrap_err();
        assert!(format!("{err}").contains("KAWACH_TEST_DEFINITELY_UNSET"));
    }

    #[test]
    fn a_token_file_is_read_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "  hvs-test-value\n").unwrap();

        let VaultAuthMaterial::Token(token) = VaultAuth::TokenFile { path }.load().unwrap() else {
            panic!("expected a token")
        };
        // Trailing newlines from `echo` into a token file are the classic footgun.
        assert!(token.expose_str(|s| s == "hvs-test-value").unwrap());
    }

    #[test]
    fn an_empty_credential_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "   \n").unwrap();
        assert!(VaultAuth::TokenFile { path }.load().is_err());
    }

    #[test]
    fn auth_material_debug_does_not_reveal_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "hvs-canary-token").unwrap();
        let material = VaultAuth::TokenFile { path }.load().unwrap();
        assert!(!format!("{material:?}").contains("canary"));
    }
}
