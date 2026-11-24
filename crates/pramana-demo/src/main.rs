//! `pramana-demo` — one deployable process for the whole §17 demonstration:
//!
//! | Mount | Component |
//! |---|---|
//! | `/api/issuer/*` | Pramātā demo issuing authority (`GET /info`, `POST /issue`) |
//! | `/api/shop/*`   | Sākṣī verifier for `example-shop.com` (the relying party) |
//! | `/api/other/*`  | a second, independent Sākṣī (`other-site.example`) for the replay act |
//! | `/api/config`   | what the web app needs to bootstrap |
//! | `/*`            | the web app (wallet + shop + demonstration), SPA fallback |
//!
//! Configuration is entirely through environment variables (see `docs/DEPLOYMENT.md`).

use axum::http::{header, HeaderValue};
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use pramana_issuer::{resolve_key, Issuer};
use pramana_sakshi::{cors, parse_trust_list, Sakshi, VerifierConfig};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

#[derive(Parser, Debug, Clone)]
#[command(name = "pramana-demo", version, about = "Pramāṇa demonstration server")]
pub struct Config {
    /// Listen address. `PORT` (as set by most PaaS hosts) overrides the port.
    #[arg(long, env = "PRAMANA_ADDR", default_value = "0.0.0.0:8080")]
    pub addr: String,
    /// Port override (Render/Fly/Railway/Cloud Run set this).
    #[arg(long, env = "PORT")]
    pub port: Option<u16>,
    /// Directory containing the built web app (`web/dist`).
    #[arg(long, env = "PRAMANA_WEB_DIR", default_value = "web/dist")]
    pub web_dir: PathBuf,
    /// Demo issuer display name.
    #[arg(long, env = "PRAMANA_ISSUER_NAME", default_value = "Demo Authority")]
    pub issuer_name: String,
    /// Demo issuer secret seed as 64 hex chars (takes precedence over the key file).
    #[arg(long, env = "PRAMANA_ISSUER_KEY", hide_env_values = true)]
    pub issuer_key_hex: Option<String>,
    /// Demo issuer key file; created on first start if missing.
    #[arg(long, env = "PRAMANA_ISSUER_KEY_FILE")]
    pub issuer_key_file: Option<PathBuf>,
    /// Extra trusted issuers for both verifiers: `Name=hex,…`.
    #[arg(long, env = "PRAMANA_EXTRA_TRUSTED_ISSUERS", default_value = "")]
    pub extra_trusted: String,
    /// Relying-party verifier id.
    #[arg(long, env = "PRAMANA_SHOP_ID", default_value = "example-shop.com")]
    pub shop_id: String,
    /// Second verifier id (replay demonstration).
    #[arg(long, env = "PRAMANA_OTHER_ID", default_value = "other-site.example")]
    pub other_id: String,
    /// Challenge validity window in seconds.
    #[arg(long, env = "PRAMANA_CHALLENGE_TTL", default_value_t = 120)]
    pub ttl_secs: u64,
    /// Allowed CORS origins for the API (comma-separated, `*` wildcards).
    #[arg(long, env = "PRAMANA_CORS_ORIGINS", default_value = cors::DEFAULT_ORIGINS)]
    pub cors_origins: String,
    /// Probe `GET /api/health` on the configured port and exit 0/1 (container healthcheck).
    #[arg(long)]
    pub healthcheck: bool,
}

/// Content-Security-Policy: everything same-origin; `wasm-unsafe-eval` lets the
/// browser compile the wallet's WebAssembly; no inline scripts.
const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'";

pub fn build_app(cfg: &Config) -> anyhow::Result<Router> {
    let (key, source) = resolve_key(
        &cfg.issuer_name,
        cfg.issuer_key_hex.as_deref(),
        cfg.issuer_key_file.as_deref(),
    )?;
    tracing::info!(name = key.name(), public_key = %hex::encode(key.public_key()), %source, "demo issuer key");
    let mut trusted = vec![key.public()];
    trusted.extend(parse_trust_list(&cfg.extra_trusted)?);
    let issuer_info = key.public();
    let issuer = Arc::new(Issuer::new(key));

    let mk = |id: &str| {
        let mut c = VerifierConfig::new(id, trusted.clone());
        c.ttl_secs = cfg.ttl_secs;
        Arc::new(Sakshi::new(c))
    };
    let shop = mk(&cfg.shop_id);
    let other = mk(&cfg.other_id);

    let config_body = json!({
        "suite": pramana_core::SUITE,
        "issuer": { "name": issuer_info.name, "public_key": hex::encode(issuer_info.public_key) },
        "verifiers": {
            "shop": { "id": cfg.shop_id, "base": "/api/shop" },
            "other": { "id": cfg.other_id, "base": "/api/other" },
        },
        "trusted_issuers": trusted,
        "challenge_ttl_secs": cfg.ttl_secs,
        "thresholds": pramana_sakshi::ALLOWED_THRESHOLDS,
    });

    let api = Router::new()
        .nest("/issuer", pramana_issuer::router(issuer))
        .nest("/shop", pramana_sakshi::router(shop))
        .nest("/other", pramana_sakshi::router(other))
        .route(
            "/config",
            get(move || async move { Json(config_body.clone()) }),
        )
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(cors::layer(&cfg.cors_origins))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ));

    let index = cfg.web_dir.join("index.html");
    if !index.exists() {
        tracing::warn!(path = %index.display(), "web app not found — API only. Build it with `npm run build` in web/");
    }
    let spa = ServeDir::new(&cfg.web_dir).fallback(ServeFile::new(index));

    Ok(Router::new()
        .nest("/api", api)
        .fallback_service(spa)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http()))
}

/// Minimal HTTP/1.0 probe so the runtime image needs no curl.
fn healthcheck(port: &str) -> bool {
    use std::io::{Read, Write};
    let Ok(mut s) = std::net::TcpStream::connect(format!("127.0.0.1:{port}")) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(3)));
    if s.write_all(b"GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.starts_with("HTTP/1.0 200") || buf.starts_with("HTTP/1.1 200")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .init();
    let cfg = Config::parse();
    let addr = match cfg.port {
        Some(p) => {
            let host = cfg
                .addr
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or("0.0.0.0");
            format!("{host}:{p}")
        }
        None => cfg.addr.clone(),
    };
    if cfg.healthcheck {
        let port = addr.rsplit_once(':').map(|(_, p)| p).unwrap_or("8080");
        std::process::exit(if healthcheck(port) { 0 } else { 1 });
    }
    let app = build_app(&cfg)?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        "Pramāṇa demo on http://{addr}  (issuer + verifiers {} / {})",
        cfg.shop_id,
        cfg.other_id
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use pramana_core::{prove_age, Credential, Params, Statement};
    use tower::ServiceExt;

    fn cfg(web: PathBuf) -> Config {
        Config {
            addr: "127.0.0.1:0".into(),
            port: None,
            web_dir: web,
            issuer_name: "Demo Authority".into(),
            issuer_key_hex: Some("07".repeat(32)),
            issuer_key_file: None,
            extra_trusted: String::new(),
            shop_id: "example-shop.com".into(),
            other_id: "other-site.example".into(),
            ttl_secs: 120,
            cors_origins: cors::DEFAULT_ORIGINS.into(),
            healthcheck: false,
        }
    }

    async fn req(
        app: &Router,
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value, axum::http::HeaderMap) {
        let r = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("origin", "http://localhost:5173")
            .body(if method == "GET" {
                Body::empty()
            } else {
                Body::from(body.to_string())
            })
            .unwrap();
        let res = app.clone().oneshot(r).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
            headers,
        )
    }

    #[tokio::test]
    async fn end_to_end_issue_challenge_prove_verify_replay() {
        let dir = std::env::temp_dir().join(format!("pramana-web-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("index.html"),
            "<!doctype html><title>Pramana</title>",
        )
        .unwrap();
        let app = build_app(&cfg(dir.clone())).unwrap();

        let (s, conf, h) = req(&app, "GET", "/api/config", json!(null)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(conf["verifiers"]["shop"]["id"], "example-shop.com");
        assert_eq!(h["access-control-allow-origin"], "http://localhost:5173");
        assert!(h["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("wasm-unsafe-eval"));

        let (s, cred, _) = req(
            &app,
            "POST",
            "/api/issuer/issue",
            json!({"dob": "2001-04-12"}),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let cred: Credential = serde_json::from_value(cred).unwrap();

        let (_, ch, _) = req(
            &app,
            "POST",
            "/api/shop/challenge",
            json!({"threshold_years": 18}),
        )
        .await;
        let st: Statement = serde_json::from_value(ch["statement"].clone()).unwrap();
        let pf = prove_age(&Params::new(), &cred, &st).unwrap();

        let (_, v, _) = req(&app, "POST", "/api/other/verify", json!({ "proof": pf })).await;
        assert_eq!(v["ok"], false);
        assert_eq!(v["reason"], "unknown_challenge");
        let (_, v, _) = req(&app, "POST", "/api/shop/verify", json!({ "proof": pf })).await;
        assert_eq!(v["ok"], true, "{v}");
        let (_, v, _) = req(&app, "POST", "/api/shop/verify", json!({ "proof": pf })).await;
        assert_eq!(v["reason"], "challenge_already_used");

        // Error responses also carry CORS headers.
        let (s, _, h) = req(
            &app,
            "POST",
            "/api/shop/challenge",
            json!({"threshold_years": 99}),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(h["access-control-allow-origin"], "http://localhost:5173");

        // SPA fallback serves index.html for client routes.
        let (s, _, h) = req(&app, "GET", "/demo/xray", json!(null)).await;
        assert_eq!(s, StatusCode::OK);
        assert!(h["content-type"].to_str().unwrap().starts_with("text/html"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
