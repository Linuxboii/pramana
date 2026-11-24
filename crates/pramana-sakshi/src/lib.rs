//! # pramana-sakshi — Sākṣī (साक्षी), "the witness"
//!
//! The verifier service (FR-7, PRD §14.2):
//!
//! | Route | Purpose |
//! |---|---|
//! | `POST /challenge` | issue a fresh statement `{threshold, today, nonce, verifier_id, window}` |
//! | `POST /verify` | check a proof (JSON `{proof}` or raw CBOR) → `{ok, issuer, checked_at}` |
//! | `GET /issuers` | the trust list of accepted issuer keys |
//! | `GET /audit` | the only retained artefact: `{timestamp, issuer_pk, result}` entries |
//! | `GET /health` | liveness |
//!
//! **Data-minimisation invariant (§9.3).** The verifier never receives, derives or
//! persists a birthdate, name or any stable identifier beyond what Tier A inherently
//! carries (`C_D`, which is *not* stored). Outstanding nonces are kept in memory only
//! until they are used or expire; each nonce is single-use.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pramana_core::{verify_age, AgeProof, Date, IssuerPublicKey, Params, Statement};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

pub mod cors;

/// Thresholds selectable by relying parties (G1).
pub const ALLOWED_THRESHOLDS: [u8; 4] = [13, 16, 18, 21];

/// Maximum request body (a proof is ~3 KiB CBOR / ~7.5 KiB JSON).
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Verifier configuration.
#[derive(Clone, Debug)]
pub struct VerifierConfig {
    /// This verifier's identity, bound into every proof (§7.7).
    pub verifier_id: String,
    /// Issuer keys this verifier accepts (T8 trust list).
    pub trusted: Vec<IssuerPublicKey>,
    /// Challenge validity window in seconds.
    pub ttl_secs: u64,
    /// Threshold used when the client does not choose one.
    pub default_threshold: u8,
    /// Upper bound on outstanding challenges (memory DoS guard).
    pub max_outstanding: usize,
    /// Number of audit entries retained in memory.
    pub audit_capacity: usize,
}

impl VerifierConfig {
    /// Sensible defaults for `verifier_id`.
    pub fn new(verifier_id: impl Into<String>, trusted: Vec<IssuerPublicKey>) -> Self {
        VerifierConfig {
            verifier_id: verifier_id.into(),
            trusted,
            ttl_secs: 120,
            default_threshold: 18,
            max_outstanding: 10_000,
            audit_capacity: 200,
        }
    }
}

/// One audit-log entry — the only retained artefact (§9.3).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    /// Unix time of the check.
    pub timestamp: u64,
    /// Issuer key the proof claimed (hex), if the proof decoded.
    pub issuer_pk: Option<String>,
    /// Accept / reject.
    pub result: bool,
    /// Machine-readable reason on rejection.
    pub reason: Option<String>,
}

/// `POST /challenge` body (optional).
#[derive(Debug, Default, Deserialize)]
pub struct ChallengeRequest {
    /// One of 13, 16, 18, 21.
    pub threshold_years: Option<u8>,
}

/// `POST /challenge` response (PRD §14.2).
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The full statement the wallet must prove.
    pub statement: Statement,
    /// The nonce (hex), duplicated for convenience.
    pub nonce: String,
    /// This verifier's id.
    pub verifier_id: String,
    /// Expiry (Unix seconds).
    pub expires_at: u64,
}

/// `POST /verify` JSON body.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The proof.
    pub proof: AgeProof,
}

/// `POST /verify` response (PRD §14.2). Contains no PII.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyResponse {
    /// The single boolean the relying party learns.
    pub ok: bool,
    /// The issuer that attested the birthdate (on success).
    pub issuer: Option<IssuerPublicKey>,
    /// Unix time of the check.
    pub checked_at: u64,
    /// Threshold that was proved (on success) — this *is* the statement, not new data.
    pub threshold_years: Option<u8>,
    /// Stable rejection code.
    pub reason: Option<String>,
    /// Human-readable rejection detail.
    pub detail: Option<String>,
}

/// JSON error body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable code.
    pub code: String,
    /// Message.
    pub error: String,
}

struct Inner {
    outstanding: HashMap<[u8; 32], Statement>,
    used: HashMap<[u8; 32], u64>,
    audit: VecDeque<AuditEntry>,
}

/// The verifier.
pub struct Sakshi {
    cfg: VerifierConfig,
    params: Params,
    inner: Mutex<Inner>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// Current Unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Sakshi {
    /// New verifier on the system clock.
    pub fn new(cfg: VerifierConfig) -> Self {
        Self::with_clock(cfg, Arc::new(unix_now))
    }

    /// New verifier with an injected clock (tests).
    pub fn with_clock(cfg: VerifierConfig, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Sakshi {
            cfg,
            params: Params::new(),
            inner: Mutex::new(Inner {
                outstanding: HashMap::new(),
                used: HashMap::new(),
                audit: VecDeque::new(),
            }),
            clock,
        }
    }

    /// Configuration.
    pub fn config(&self) -> &VerifierConfig {
        &self.cfg
    }

    fn purge(inner: &mut Inner, now: u64) {
        // Keep expired challenges for a grace period so late submissions get a
        // precise "expired" instead of "unknown".
        inner.outstanding.retain(|_, st| st.expires_at + 600 > now);
        inner.used.retain(|_, exp| *exp + 600 > now);
    }

    /// §9.2 step 1: issue a fresh statement.
    pub fn challenge(
        &self,
        threshold: Option<u8>,
    ) -> Result<ChallengeResponse, (StatusCode, ApiError)> {
        let threshold = threshold.unwrap_or(self.cfg.default_threshold);
        if !ALLOWED_THRESHOLDS.contains(&threshold) {
            return Err((
                StatusCode::BAD_REQUEST,
                ApiError {
                    code: "bad_threshold".into(),
                    error: format!("threshold_years must be one of {ALLOWED_THRESHOLDS:?}"),
                },
            ));
        }
        let now = (self.clock)();
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let st = Statement::new(
            threshold,
            Date::from_unix_seconds(now),
            nonce,
            self.cfg.verifier_id.clone(),
            now,
            self.cfg.ttl_secs,
        );
        let mut inner = self.inner.lock().unwrap();
        Self::purge(&mut inner, now);
        if inner.outstanding.len() >= self.cfg.max_outstanding {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                ApiError {
                    code: "busy".into(),
                    error: "too many outstanding challenges; retry shortly".into(),
                },
            ));
        }
        inner.outstanding.insert(nonce, st.clone());
        Ok(ChallengeResponse {
            nonce: hex::encode(nonce),
            verifier_id: st.verifier_id.clone(),
            expires_at: st.expires_at,
            statement: st,
        })
    }

    fn reject(
        &self,
        now: u64,
        issuer_pk: Option<String>,
        code: &str,
        detail: String,
    ) -> VerifyResponse {
        self.record(AuditEntry {
            timestamp: now,
            issuer_pk,
            result: false,
            reason: Some(code.to_string()),
        });
        VerifyResponse {
            ok: false,
            issuer: None,
            checked_at: now,
            threshold_years: None,
            reason: Some(code.to_string()),
            detail: Some(detail),
        }
    }

    fn record(&self, e: AuditEntry) {
        let mut inner = self.inner.lock().unwrap();
        inner.audit.push_back(e);
        while inner.audit.len() > self.cfg.audit_capacity {
            inner.audit.pop_front();
        }
    }

    /// §9.3: verify a proof against *this verifier's own* outstanding statement for
    /// the nonce it claims to answer. The nonce is consumed whatever the outcome.
    pub fn verify(&self, proof: &AgeProof) -> VerifyResponse {
        let now = (self.clock)();
        let pk_hex = Some(hex::encode(proof.issuer_pk));
        let st = {
            let mut inner = self.inner.lock().unwrap();
            Self::purge(&mut inner, now);
            match inner.outstanding.remove(&proof.nonce) {
                Some(st) => {
                    inner.used.insert(proof.nonce, st.expires_at);
                    Ok(st)
                }
                None if inner.used.contains_key(&proof.nonce) => Err((
                    "challenge_already_used",
                    "this challenge nonce was already answered — proofs are single-use".to_string(),
                )),
                None => Err((
                    "unknown_challenge",
                    format!(
                        "nonce was not issued by verifier {:?}",
                        self.cfg.verifier_id
                    ),
                )),
            }
        };
        let st = match st {
            Ok(st) => st,
            Err((code, detail)) => return self.reject(now, pk_hex, code, detail),
        };
        match verify_age(&self.params, proof, &st, &self.cfg.trusted, now) {
            Ok(v) => {
                self.record(AuditEntry {
                    timestamp: now,
                    issuer_pk: pk_hex,
                    result: true,
                    reason: None,
                });
                VerifyResponse {
                    ok: true,
                    issuer: Some(v.issuer),
                    checked_at: now,
                    threshold_years: Some(st.threshold_years),
                    reason: None,
                    detail: None,
                }
            }
            Err(e) => self.reject(now, pk_hex, e.code(), e.to_string()),
        }
    }

    /// Record a request whose proof could not even be decoded.
    pub fn reject_malformed(&self, detail: String) -> VerifyResponse {
        let now = (self.clock)();
        self.reject(now, None, "malformed", detail)
    }

    /// Audit log, newest last.
    pub fn audit(&self) -> Vec<AuditEntry> {
        self.inner.lock().unwrap().audit.iter().cloned().collect()
    }
}

fn api_err(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            code: code.into(),
            error: msg.into(),
        }),
    )
        .into_response()
}

async fn challenge(State(s): State<Arc<Sakshi>>, body: Option<Json<ChallengeRequest>>) -> Response {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    match s.challenge(req.threshold_years) {
        Ok(c) => Json(c).into_response(),
        Err((status, e)) => (status, Json(e)).into_response(),
    }
}

async fn verify(State(s): State<Arc<Sakshi>>, headers: HeaderMap, body: Bytes) -> Response {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // FR-8: accept the compact CBOR wire format or JSON.
    let proof: Result<AgeProof, String> = if ct.starts_with("application/cbor") {
        pramana_core::wire::from_cbor(&body)
    } else {
        serde_json::from_slice::<VerifyRequest>(&body)
            .map(|r| r.proof)
            .map_err(|e| e.to_string())
    };
    let resp = match proof {
        Ok(p) => s.verify(&p),
        Err(e) => s.reject_malformed(e),
    };
    Json(resp).into_response()
}

async fn issuers(State(s): State<Arc<Sakshi>>) -> Json<Vec<IssuerPublicKey>> {
    Json(s.cfg.trusted.clone())
}

#[derive(Serialize)]
struct AuditView {
    verifier_id: String,
    note: &'static str,
    entries: Vec<AuditEntry>,
}

async fn audit(State(s): State<Arc<Sakshi>>) -> Json<AuditView> {
    Json(AuditView {
        verifier_id: s.cfg.verifier_id.clone(),
        note: "This is everything the verifier retains: {timestamp, issuer_pk, result}. No birthdate, no name, no proof.",
        entries: s.audit(),
    })
}

#[derive(Serialize)]
struct Health {
    ok: bool,
    verifier_id: String,
    suite: &'static str,
}

async fn health(State(s): State<Arc<Sakshi>>) -> Json<Health> {
    Json(Health {
        ok: true,
        verifier_id: s.cfg.verifier_id.clone(),
        suite: pramana_core::SUITE,
    })
}

async fn fallback() -> Response {
    api_err(StatusCode::NOT_FOUND, "not_found", "no such route")
}

/// Verifier HTTP routes.
pub fn router(state: Arc<Sakshi>) -> Router {
    Router::new()
        .route("/challenge", post(challenge))
        .route("/verify", post(verify))
        .route("/issuers", get(issuers))
        .route("/audit", get(audit))
        .route("/health", get(health))
        .fallback(fallback)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Parse a trust list from `name=hex,name2=hex2` (or bare hex, named "Issuer N").
pub fn parse_trust_list(spec: &str) -> anyhow::Result<Vec<IssuerPublicKey>> {
    let mut out = vec![];
    for (i, item) in spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        let (name, hexkey) = match item.split_once('=') {
            Some((n, k)) => (n.trim().to_string(), k.trim()),
            None => (format!("Issuer {}", i + 1), item),
        };
        let mut pk = [0u8; 32];
        hex::decode_to_slice(hexkey, &mut pk)
            .map_err(|e| anyhow::anyhow!("bad issuer key {hexkey:?}: {e}"))?;
        out.push(IssuerPublicKey {
            name,
            public_key: pk,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
