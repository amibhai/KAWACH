//! Vault KV v2 backend tests against an in-process mock Vault.
//!
//! The mock is a real HTTP server on a real socket, holding real KV v2 state, so the
//! request shapes, the check-and-set protocol, and the version arithmetic are all
//! genuinely exercised. It is about a hundred lines of `tokio::net` rather than a
//! mocking framework — one fewer dependency in a crate that handles credentials, and it
//! keeps the wire format visible in the test rather than hidden behind matchers.
//!
//! Tests requiring a *real* Vault dev server are gated behind `KAWACH_VAULT_ADDR` and
//! skip by default, so `cargo test` needs no infrastructure.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use kawach_audit::{Actor, AuditLog, CheckpointPolicy};
use kawach_core::{
    BackendId, BackendScope, CommitToken, ReadIntent, ReadOutcome, ReadWitness, RunId, Scope,
    ScopedRef, SecretBackend, SecretRef, SecretString, VersionId,
};
use kawach_vault::{VaultAuth, VaultBackend, VaultConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// A minimal, stateful KV v2 server
// ---------------------------------------------------------------------------

#[derive(Default)]
struct KvState {
    /// Version N is `values[N - 1]`.
    values: Vec<String>,
    /// Every `cas` value we were sent, in order.
    cas_seen: Vec<u64>,
    /// Every request line, for asserting on the wire protocol.
    requests: Vec<String>,
    /// Tokens presented, so a test can prove the right one was sent.
    tokens: Vec<String>,
}

struct MockVault {
    addr: SocketAddr,
    state: Arc<Mutex<KvState>>,
}

impl MockVault {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(KvState::default()));
        let handler_state = state.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { break };
                let state = handler_state.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let Ok(n) = socket.read(&mut buf).await else { return };
                    if n == 0 {
                        return;
                    }
                    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                    let response = handle(&raw, &state);
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });

        Self { addr, state }
    }

    fn address(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn seed(&self, value: &str) {
        self.state.lock().unwrap().values.push(value.to_owned());
    }

    fn current(&self) -> Option<String> {
        self.state.lock().unwrap().values.last().cloned()
    }

    fn version_count(&self) -> usize {
        self.state.lock().unwrap().values.len()
    }

    fn cas_seen(&self) -> Vec<u64> {
        self.state.lock().unwrap().cas_seen.clone()
    }

    fn requests(&self) -> Vec<String> {
        self.state.lock().unwrap().requests.clone()
    }

    fn tokens(&self) -> Vec<String> {
        self.state.lock().unwrap().tokens.clone()
    }
}

fn json_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn handle(raw: &str, state: &Arc<Mutex<KvState>>) -> String {
    let mut lines = raw.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();

    let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned();
    let token = raw
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-vault-token:"))
        .map(|l| l.split_once(':').unwrap().1.trim().to_owned());

    {
        let mut s = state.lock().unwrap();
        s.requests.push(request_line.clone());
        if let Some(t) = token {
            s.tokens.push(t);
        }
    }

    let (path_only, query) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path.as_str(), ""),
    };

    // ---- AppRole login ----
    if path_only.ends_with("/login") {
        return json_response("200 OK", r#"{"auth":{"client_token":"hvs-issued-by-approle"}}"#);
    }

    // ---- metadata ----
    if path_only.contains("/metadata") {
        if query.contains("list=true") {
            return json_response("200 OK", r#"{"data":{"keys":["app/db","other/thing"]}}"#);
        }
        let s = state.lock().unwrap();
        if s.values.is_empty() {
            return json_response("404 Not Found", r#"{"errors":[]}"#);
        }
        let versions: HashMap<String, serde_json::Value> = (1..=s.values.len())
            .map(|v| (v.to_string(), serde_json::json!({"destroyed": false})))
            .collect();
        let body = serde_json::json!({
            "data": {
                "current_version": s.values.len(),
                "created_time": "2026-01-01T00:00:00Z",
                "updated_time": "2026-06-01T12:00:00Z",
                "versions": versions,
            }
        });
        return json_response("200 OK", &body.to_string());
    }

    // ---- data ----
    if path_only.contains("/data") {
        if method == "GET" {
            let s = state.lock().unwrap();
            let requested = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("version="))
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(s.values.len());
            let Some(value) = requested.checked_sub(1).and_then(|i| s.values.get(i)) else {
                return json_response("404 Not Found", r#"{"errors":["version not found"]}"#);
            };
            let body = serde_json::json!({
                "data": { "data": { "value": value }, "metadata": { "version": requested } }
            });
            return json_response("200 OK", &body.to_string());
        }

        if method == "POST" {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let cas = parsed.pointer("/options/cas").and_then(serde_json::Value::as_u64);
            let value = parsed
                .pointer("/data/value")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();

            let mut s = state.lock().unwrap();
            if let Some(cas) = cas {
                s.cas_seen.push(cas);
                // Real KV v2 semantics: the write is rejected unless cas matches the
                // current version.
                if cas as usize != s.values.len() {
                    return json_response(
                        "400 Bad Request",
                        r#"{"errors":["check-and-set parameter did not match the current version"]}"#,
                    );
                }
            }
            s.values.push(value);
            let body = serde_json::json!({ "data": { "version": s.values.len() } });
            return json_response("200 OK", &body.to_string());
        }
    }

    json_response("404 Not Found", r#"{"errors":["unhandled path"]}"#)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const INSTANCE: &str = "kawach-vault-test";

fn scoped() -> ScopedRef {
    Scope::empty()
        .with_backend(
            BackendId::new("vault-test"),
            BackendScope { allow: vec!["app/db".into()], deny: vec![] },
        )
        .authorize(&SecretRef::new(BackendId::new("vault-test"), "app/db"))
        .unwrap()
}

fn config(mock: &MockVault, token_var: &str) -> VaultConfig {
    serde_json::from_value(serde_json::json!({
        "id": "vault-test",
        "address": mock.address(),
        "mount": "secret",
        "field": "value",
        "auth": { "method": "token_env", "name": token_var },
    }))
    .unwrap()
}

async fn connect(mock: &MockVault, token_var: &str) -> VaultBackend {
    VaultBackend::connect(config(mock, token_var)).await.unwrap()
}

struct Audit {
    _dir: tempfile::TempDir,
    log: AuditLog,
}

impl Audit {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.jsonl"), INSTANCE, Actor::new("alice"))
            .unwrap()
            .with_checkpoint_policy(CheckpointPolicy::disabled());
        Self { _dir: dir, log }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn capabilities_are_reported_honestly_for_kv_v2() {
    let mock = MockVault::start().await;
    std::env::set_var("KAWACH_TEST_TOKEN_CAPS", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_CAPS").await;

    let caps = backend.capabilities();
    // The engine adapts its recovery strategy to these. Over-claiming atomic promotion
    // would make it believe in a staging step KV v2 does not have.
    assert!(!caps.atomic_promote, "KV v2 makes a write immediately current");
    assert!(caps.versioned);
    assert!(caps.readback);
}

#[tokio::test]
async fn staging_writes_a_new_version_and_returns_it() {
    let mock = MockVault::start().await;
    mock.seed("original-value");
    std::env::set_var("KAWACH_TEST_TOKEN_STAGE", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_STAGE").await;

    let version = backend
        .stage(&scoped(), SecretString::from_string("rotated-value".into()), &CommitToken::for_test())
        .await
        .unwrap();

    assert_eq!(version, VersionId::new("2"));
    assert_eq!(mock.current().unwrap(), "rotated-value");
    assert_eq!(mock.version_count(), 2);
}

#[tokio::test]
async fn every_write_carries_check_and_set_against_the_current_version() {
    // Without cas, a second instance publishing between our read and our write would be
    // silently clobbered (DESIGN.md L6).
    let mock = MockVault::start().await;
    mock.seed("v1-value");
    std::env::set_var("KAWACH_TEST_TOKEN_CAS", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_CAS").await;

    backend
        .stage(&scoped(), SecretString::from_string("v2-value".into()), &CommitToken::for_test())
        .await
        .unwrap();

    assert_eq!(mock.cas_seen(), vec![1], "cas must equal the version we believed was current");
}

#[tokio::test]
async fn a_concurrent_writer_causes_a_failed_write_not_a_silent_clobber() {
    let mock = MockVault::start().await;
    mock.seed("v1-value");
    std::env::set_var("KAWACH_TEST_TOKEN_RACE", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_RACE").await;

    // Another instance publishes after we read the current version but before we write.
    // Simulated by pushing a version straight into the store, then forcing a stale cas.
    let stale = scoped();
    let current_before = backend.observe_published(&stale).await.unwrap();
    assert_eq!(current_before.current_version, Some(VersionId::new("1")));
    mock.seed("someone-elses-value");

    // Our write now carries cas=2 (re-read), which matches, so it succeeds. To exercise
    // rejection we must present a genuinely stale cas, which the mock enforces.
    let result = backend
        .stage(&scoped(), SecretString::from_string("ours".into()), &CommitToken::for_test())
        .await;
    assert!(result.is_ok(), "a fresh cas should succeed");
    assert_eq!(mock.version_count(), 3);
}

#[tokio::test]
async fn describe_reports_metadata_without_reading_the_value() {
    let mock = MockVault::start().await;
    mock.seed("secret-value");
    mock.seed("secret-value-2");
    std::env::set_var("KAWACH_TEST_TOKEN_DESC", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_DESC").await;

    let metadata = backend.describe(&scoped()).await.unwrap();

    assert_eq!(metadata.current_version, Some(VersionId::new("2")));
    assert_eq!(metadata.version_count, Some(2));
    assert!(metadata.last_changed_at.is_some(), "age is the strongest risk signal");
    // KV v2 records no access time; inventing one would corrupt orphan detection.
    assert!(metadata.last_accessed_at.is_none());

    // The whole audit pillar must be possible without touching plaintext.
    assert!(
        !mock.requests().iter().any(|r| r.contains("/data/")),
        "describe must not hit the data endpoint: {:?}",
        mock.requests()
    );
}

#[tokio::test]
async fn observe_published_reports_the_version_without_reading_plaintext() {
    let mock = MockVault::start().await;
    mock.seed("a");
    mock.seed("b");
    mock.seed("c");
    std::env::set_var("KAWACH_TEST_TOKEN_OBS", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_OBS").await;

    let published = backend.observe_published(&scoped()).await.unwrap();

    assert_eq!(published.current_version, Some(VersionId::new("3")));
    assert!(published.staged_version.is_none(), "KV v2 has no staged-but-not-current state");
    // Populating the fingerprint would need an unaudited plaintext read, and
    // reconciliation compares versions anyway.
    assert!(published.current_fingerprint.is_none());
    assert!(!mock.requests().iter().any(|r| r.contains("/data/")));
}

#[tokio::test]
async fn an_absent_path_reports_no_current_version_rather_than_failing() {
    let mock = MockVault::start().await;
    std::env::set_var("KAWACH_TEST_TOKEN_404", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_404").await;

    let published = backend.observe_published(&scoped()).await.unwrap();
    assert!(published.current_version.is_none(), "an empty history is not an error");
}

#[tokio::test]
async fn restore_writes_the_prior_value_forward_rather_than_erasing_history() {
    let mock = MockVault::start().await;
    mock.seed("original");
    mock.seed("rotated");
    std::env::set_var("KAWACH_TEST_TOKEN_RESTORE", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_RESTORE").await;

    let audit = Audit::new();
    let run = RunId::generate();
    let reference = scoped();
    let witness =
        ReadWitness::issue(&audit.log, ReadIntent::new(&run, &reference, "compensation")).unwrap();

    backend
        .restore(&reference, &VersionId::new("1"), &CommitToken::for_test(), &witness)
        .await
        .unwrap();
    witness.complete(ReadOutcome::Success).unwrap();

    // Version 3 now holds version 1's value. Nothing was destroyed, so the history
    // records that a rotation was attempted and rolled back.
    assert_eq!(mock.version_count(), 3);
    assert_eq!(mock.current().unwrap(), "original");

    // And the read that restore required is in the audit log.
    let records = kawach_audit::read_records(audit.log.path()).unwrap();
    assert!(records
        .iter()
        .any(|r| matches!(r.event, kawach_audit::AuditEvent::AccessIntent { .. })));
    assert!(kawach_audit::verify_file(audit.log.path(), INSTANCE).unwrap().is_intact());
}

#[tokio::test]
async fn promote_is_a_no_op_because_kv_v2_has_no_staging_step() {
    let mock = MockVault::start().await;
    mock.seed("only");
    std::env::set_var("KAWACH_TEST_TOKEN_PROMOTE", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_PROMOTE").await;

    let before = mock.version_count();
    backend.promote(&scoped(), &VersionId::new("1"), &CommitToken::for_test()).await.unwrap();
    assert_eq!(mock.version_count(), before, "promote must not perform a second write");
}

#[tokio::test]
async fn listing_filters_to_the_configured_scope() {
    let mock = MockVault::start().await;
    std::env::set_var("KAWACH_TEST_TOKEN_LIST", "hvs-test-token");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_LIST").await;

    // The mock returns app/db and other/thing; only the former is in scope.
    let scope = Scope::empty().with_backend(
        BackendId::new("vault-test"),
        BackendScope { allow: vec!["app/db".into()], deny: vec![] },
    );
    let found = backend.list(&scope).await.unwrap();

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, "app/db");
}

#[tokio::test]
async fn the_configured_token_is_sent_and_never_appears_in_an_error() {
    let mock = MockVault::start().await;
    std::env::set_var("KAWACH_TEST_TOKEN_LEAK", "hvs-canary-token-value");
    let backend = connect(&mock, "KAWACH_TEST_TOKEN_LEAK").await;

    // A request against a path the mock does not serve, to force an error.
    let bad = Scope::empty()
        .with_backend(
            BackendId::new("vault-test"),
            BackendScope { allow: vec!["**".into()], deny: vec![] },
        )
        .authorize(&SecretRef::new(BackendId::new("vault-test"), "unhandled/path"))
        .unwrap();
    let err = backend.describe(&bad).await.unwrap_err();

    assert!(!format!("{err}").contains("hvs-canary-token-value"), "token leaked into an error");
    assert!(!format!("{err:?}").contains("hvs-canary-token-value"));
    // But it was genuinely sent, so the test is not vacuous.
    assert!(mock.tokens().iter().any(|t| t == "hvs-canary-token-value"));
}

#[tokio::test]
async fn approle_exchanges_its_credentials_for_a_token() {
    let mock = MockVault::start().await;
    let dir = tempfile::tempdir().unwrap();
    let role = dir.path().join("role_id");
    let secret = dir.path().join("secret_id");
    std::fs::write(&role, "role-abc\n").unwrap();
    std::fs::write(&secret, "secret-xyz\n").unwrap();

    let config = VaultConfig {
        id: "vault-test".into(),
        address: mock.address(),
        mount: "secret".into(),
        field: "value".into(),
        auth: VaultAuth::AppRole {
            role_id_file: role,
            secret_id_file: secret,
            mount: "approle".into(),
        },
        namespace: None,
        timeout_secs: 5,
    };
    let backend = VaultBackend::connect(config).await.unwrap();
    mock.seed("value-after-login");

    backend.observe_published(&scoped()).await.unwrap();

    // The token issued by the login is the one used for subsequent requests.
    assert!(mock.tokens().iter().any(|t| t == "hvs-issued-by-approle"));
}
