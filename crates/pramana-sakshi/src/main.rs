//! `pramana-sakshi` — standalone verifier service.
//!
//! ```text
//! PRAMANA_VERIFIER_ID=example-shop.com \
//! PRAMANA_TRUSTED_ISSUERS="Demo Authority=<hex pubkey>" \
//! pramana-sakshi --addr 0.0.0.0:8082
//! ```

use clap::Parser;
use pramana_sakshi::{cors, parse_trust_list, router, Sakshi, VerifierConfig};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "pramana-sakshi",
    version,
    about = "Sākṣī — the Pramāṇa age-proof verifier"
)]
struct Cli {
    /// This verifier's id (bound into every proof).
    #[arg(long, env = "PRAMANA_VERIFIER_ID", default_value = "example-shop.com")]
    verifier_id: String,
    /// Trusted issuers: `Name=hexkey,Name2=hexkey2`.
    #[arg(long, env = "PRAMANA_TRUSTED_ISSUERS")]
    trusted_issuers: String,
    /// Listen address.
    #[arg(long, env = "PRAMANA_SAKSHI_ADDR", default_value = "127.0.0.1:8082")]
    addr: String,
    /// Challenge validity window (seconds).
    #[arg(long, env = "PRAMANA_CHALLENGE_TTL", default_value_t = 120)]
    ttl_secs: u64,
    /// Allowed CORS origins (comma-separated, `*` wildcards).
    #[arg(long, env = "PRAMANA_CORS_ORIGINS", default_value = cors::DEFAULT_ORIGINS)]
    cors_origins: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let trusted = parse_trust_list(&cli.trusted_issuers)?;
    anyhow::ensure!(
        !trusted.is_empty(),
        "at least one trusted issuer is required"
    );
    let mut cfg = VerifierConfig::new(cli.verifier_id.clone(), trusted);
    cfg.ttl_secs = cli.ttl_secs;
    let app = router(Arc::new(Sakshi::new(cfg)))
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(cors::layer(&cli.cors_origins))
        .layer(tower_http::trace::TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(&cli.addr).await?;
    tracing::info!(verifier_id = %cli.verifier_id, "sākṣī listening on http://{}", cli.addr);
    axum::serve(listener, app).await?;
    Ok(())
}
