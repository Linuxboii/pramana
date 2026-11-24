//! # pramana-issuer — Pramātā, the (mock) issuing authority
//!
//! Implements §9.1 issuance as a library, an HTTP service and a CLI (FR-6):
//! validate a birthdate (mocked — in production this is an out-of-band ID check),
//! commit to it, Ed25519-sign the commitment, emit a credential.
//!
//! The issuer is contacted **once** per holder. It never learns where the
//! credential is later used (§8, Figure 8.1).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pramana_core::rng::HashDrbg;
use pramana_core::{Credential, Date, IssuerKey, Params};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Issuer service state.
pub struct Issuer {
    key: IssuerKey,
    params: Params,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// Current Unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Issuer {
    /// New issuer using the system clock.
    pub fn new(key: IssuerKey) -> Self {
        Self::with_clock(key, Arc::new(unix_now))
    }

    /// New issuer with an injected clock (tests).
    pub fn with_clock(key: IssuerKey, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Issuer {
            key,
            params: Params::new(),
            clock,
        }
    }

    /// The issuer's key.
    pub fn key(&self) -> &IssuerKey {
        &self.key
    }

    /// Issue a credential for `dob` (YYYY-MM-DD).
    pub fn issue(&self, dob: &str) -> Result<Credential, String> {
        let dob = Date::parse(dob).map_err(|e| e.to_string())?;
        let now = (self.clock)();
        let today = Date::from_unix_seconds(now);
        let mut seed = [0u8; 64];
        OsRng.fill_bytes(&mut seed);
        let mut rng = HashDrbg::from_seed_material(&seed);
        self.key
            .issue(&self.params, dob, today, now, &mut rng)
            .map_err(|e| e.to_string())
    }
}

/// `POST /issue` body.
#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    /// Date of birth, `YYYY-MM-DD`.
    pub dob: String,
}

/// `GET /info` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct IssuerInfo {
    /// Display name.
    pub name: String,
    /// Ed25519 public key (hex).
    pub public_key: String,
    /// Protocol suite.
    pub suite: String,
    /// Parameter set id.
    pub params: String,
    /// Whether this is a demo authority (always true for this crate).
    pub demo: bool,
}

/// JSON error body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable code.
    pub code: String,
    /// Human-readable message.
    pub error: String,
}

fn err(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            code: code.into(),
            error: msg.into(),
        }),
    )
        .into_response()
}

async fn info(State(s): State<Arc<Issuer>>) -> Json<IssuerInfo> {
    Json(IssuerInfo {
        name: s.key.name().to_string(),
        public_key: hex::encode(s.key.public_key()),
        suite: pramana_core::SUITE.into(),
        params: pramana_core::params::PARAMS_ID.into(),
        demo: true,
    })
}

async fn issue(State(s): State<Arc<Issuer>>, body: Option<Json<IssueRequest>>) -> Response {
    let Some(Json(req)) = body else {
        return err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "expected JSON body {\"dob\": \"YYYY-MM-DD\"}",
        );
    };
    // §9.1 step 1 (mocked): a real authority would verify an identity document here.
    match s.issue(&req.dob) {
        Ok(cred) => {
            tracing::info!(issuer = s.key.name(), "issued credential");
            (StatusCode::OK, Json(cred)).into_response()
        }
        Err(e) => err(StatusCode::UNPROCESSABLE_ENTITY, "invalid_birthdate", e),
    }
}

/// Issuer HTTP routes: `GET /info`, `POST /issue`.
pub fn router(state: Arc<Issuer>) -> Router {
    Router::new()
        .route("/info", get(info))
        .route("/issue", post(issue))
        .with_state(state)
}

/// Load an issuer key file (JSON, see [`pramana_core::credential::IssuerKeyFile`]).
///
/// On Unix, refuses key files readable by group or others (like OpenSSH does for
/// private keys).
pub fn load_key_file(path: &Path) -> anyhow::Result<IssuerKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "issuer key file {} has permissions {:o}; it must not be accessible by group or others (run: chmod 600 {})",
            path.display(),
            mode & 0o777,
            path.display()
        );
    }
    let s = std::fs::read_to_string(path)?;
    let f: pramana_core::credential::IssuerKeyFile = serde_json::from_str(&s)?;
    Ok(IssuerKey::from_file(&f)?)
}

/// Write a file containing secrets: created owner-read/write only (0600) on Unix,
/// and tightened to 0600 if it already existed. On Windows the file inherits the
/// ACL of its directory (by default the user's profile is private to the user).
pub fn write_secret_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(contents.as_bytes())?;
    f.sync_all()
}

/// Write an issuer key file (mode 0600).
pub fn write_key_file(path: &Path, key: &IssuerKey) -> anyhow::Result<()> {
    write_secret_file(
        path,
        &(serde_json::to_string_pretty(&key.to_file())? + "\n"),
    )?;
    Ok(())
}

/// Resolve the issuer key from (in order) a secret from the environment, a key
/// file, or a fresh ephemeral key. Returns the key and a description of its source.
///
/// The secret may be 64 hex chars (used directly as the Ed25519 seed) or any other
/// string of at least 32 characters (e.g. a PaaS-generated secret), which is hashed
/// with SHA-256 under a domain separator to derive the seed.
pub fn resolve_key(
    name: &str,
    secret: Option<&str>,
    file: Option<&Path>,
) -> anyhow::Result<(IssuerKey, String)> {
    if let Some(s) = secret.map(str::trim).filter(|s| !s.is_empty()) {
        let mut seed = [0u8; 32];
        let source = if s.len() == 64 && hex::decode_to_slice(s, &mut seed).is_ok() {
            "hex seed from environment"
        } else {
            anyhow::ensure!(
                s.len() >= 32,
                "PRAMANA_ISSUER_KEY must be 64 hex chars or a secret of at least 32 characters"
            );
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(b"pramana/issuer-seed/v1");
            h.update(s.as_bytes());
            seed = h.finalize().into();
            "seed derived from secret in environment"
        };
        return Ok((IssuerKey::from_secret(name, &seed), source.into()));
    }
    if let Some(p) = file {
        if p.exists() {
            return Ok((load_key_file(p)?, format!("key file {}", p.display())));
        }
        let k = IssuerKey::generate(name, &mut OsRng);
        if let Some(dir) = p.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        write_key_file(p, &k)?;
        return Ok((k, format!("new key written to {}", p.display())));
    }
    Ok((
        IssuerKey::generate(name, &mut OsRng),
        "ephemeral key (credentials will not survive a restart)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Router {
        let key = IssuerKey::from_secret("Demo Authority", &[1u8; 32]);
        router(Arc::new(Issuer::with_clock(
            key,
            Arc::new(|| 1_795_000_000),
        )))
    }

    async fn call(
        app: Router,
        method: &str,
        uri: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn issues_valid_credential() {
        let (s, v) = call(app(), "POST", "/issue", r#"{"dob":"2001-04-12"}"#).await;
        assert_eq!(s, StatusCode::OK);
        let cred: Credential = serde_json::from_value(v).unwrap();
        cred.self_check(&Params::new()).unwrap();
        assert_eq!(cred.birthdate().to_string(), "2001-04-12");
    }

    #[tokio::test]
    async fn rejects_bad_dates() {
        for body in [
            r#"{"dob":"2001-02-30"}"#,
            r#"{"dob":"2099-01-01"}"#,
            r#"{"dob":"1850-01-01"}"#,
            r#"{"x":1}"#,
            "nope",
        ] {
            let (s, _) = call(app(), "POST", "/issue", body).await;
            assert!(s.is_client_error(), "{body} -> {s}");
        }
    }

    #[test]
    fn resolve_key_sources() {
        let hex_seed = "07".repeat(32);
        let (a, src) = resolve_key("X", Some(&hex_seed), None).unwrap();
        assert_eq!(src, "hex seed from environment");
        assert_eq!(
            a.public_key(),
            IssuerKey::from_secret("X", &[7u8; 32]).public_key()
        );
        let (b, src) = resolve_key(
            "X",
            Some("a-render-generated-secret-value-0123456789"),
            None,
        )
        .unwrap();
        assert!(src.contains("derived"));
        let (b2, _) = resolve_key(
            "X",
            Some("a-render-generated-secret-value-0123456789"),
            None,
        )
        .unwrap();
        assert_eq!(b.public_key(), b2.public_key());
        assert!(resolve_key("X", Some("short"), None).is_err());
        let dir = std::env::temp_dir().join(format!("pramana-key-{}", std::process::id()));
        let path = dir.join("issuer.key");
        let (c, src) = resolve_key("X", None, Some(&path)).unwrap();
        assert!(src.starts_with("new key"));
        let (c2, src) = resolve_key("X", None, Some(&path)).unwrap();
        assert!(src.starts_with("key file"));
        assert_eq!(c.public_key(), c2.public_key());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_private_and_loose_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pramana-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("issuer.key");
        write_key_file(&path, &IssuerKey::from_secret("X", &[3u8; 32])).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(load_key_file(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_key_file(&path).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn info_reports_key() {
        let (s, v) = call(app(), "GET", "/info", "").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["name"], "Demo Authority");
        assert_eq!(v["public_key"].as_str().unwrap().len(), 64);
    }
}
