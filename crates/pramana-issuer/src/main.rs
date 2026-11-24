//! `pramana-issuer` — mock issuer CLI (PRD §14.3).
//!
//! ```text
//! pramana-issuer keygen --out issuer.key [--name "Demo Authority"]
//! pramana-issuer issue  --dob 2001-04-12 --key issuer.key --out aarav.cred
//! pramana-issuer pubkey --key issuer.key
//! pramana-issuer serve  --key issuer.key --addr 0.0.0.0:8081
//! ```

use anyhow::Context;
use clap::{Parser, Subcommand};
use pramana_core::rng::HashDrbg;
use pramana_core::{Date, IssuerKey, Params};
use pramana_issuer::{load_key_file, router, unix_now, write_key_file, Issuer};
use rand_core::{OsRng, RngCore};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "pramana-issuer",
    version,
    about = "Pramāṇa mock issuing authority (demo only)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new Ed25519 issuer key.
    Keygen {
        /// Output key file.
        #[arg(long)]
        out: PathBuf,
        /// Issuer display name.
        #[arg(long, default_value = "Demo Authority")]
        name: String,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Issue an age credential for a date of birth.
    Issue {
        /// Date of birth, YYYY-MM-DD.
        #[arg(long)]
        dob: String,
        /// Issuer key file.
        #[arg(long)]
        key: PathBuf,
        /// Output credential file (stdout if omitted).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the issuer's public key (for verifier trust lists).
    Pubkey {
        /// Issuer key file.
        #[arg(long)]
        key: PathBuf,
    },
    /// Run the issuer HTTP service (GET /info, POST /issue).
    Serve {
        /// Issuer key file.
        #[arg(long, env = "PRAMANA_ISSUER_KEY_FILE")]
        key: PathBuf,
        /// Listen address.
        #[arg(long, env = "PRAMANA_ISSUER_ADDR", default_value = "127.0.0.1:8081")]
        addr: String,
        /// Allowed CORS origins (comma-separated; `*` wildcards allowed, e.g. `https://*.pages.dev`).
        #[arg(
            long,
            env = "PRAMANA_CORS_ORIGINS",
            default_value = "http://localhost:*,http://127.0.0.1:*"
        )]
        cors_origins: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Keygen { out, name, force } => {
            if out.exists() && !force {
                anyhow::bail!("{} exists; pass --force to overwrite", out.display());
            }
            let k = IssuerKey::generate(&name, &mut OsRng);
            write_key_file(&out, &k)?;
            println!(
                "wrote {} (public key {})",
                out.display(),
                hex::encode(k.public_key())
            );
        }
        Cmd::Issue { dob, key, out } => {
            let k = load_key_file(&key).with_context(|| format!("loading {}", key.display()))?;
            let now = unix_now();
            let mut seed = [0u8; 64];
            OsRng.fill_bytes(&mut seed);
            let mut rng = HashDrbg::from_seed_material(&seed);
            let cred = k.issue(
                &Params::new(),
                Date::parse(&dob)?,
                Date::from_unix_seconds(now),
                now,
                &mut rng,
            )?;
            let json = serde_json::to_string_pretty(&cred)? + "\n";
            match out {
                Some(p) => {
                    pramana_issuer::write_secret_file(&p, &json)?;
                    eprintln!(
                        "wrote credential to {} — keep it private: it contains your witness (D, r)",
                        p.display()
                    );
                }
                None => print!("{json}"),
            }
        }
        Cmd::Pubkey { key } => {
            let k = load_key_file(&key)?;
            println!("{}", serde_json::to_string_pretty(&k.public())?);
        }
        Cmd::Serve {
            key,
            addr,
            cors_origins,
        } => {
            let k = load_key_file(&key)?;
            tracing::info!(name = k.name(), public_key = %hex::encode(k.public_key()), "issuer key loaded");
            let app = router(Arc::new(Issuer::new(k)))
                .layer(tower_http::catch_panic::CatchPanicLayer::new())
                .layer(cors::layer(&cors_origins))
                .layer(tower_http::trace::TraceLayer::new_for_http());
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            tracing::info!("issuer listening on http://{addr}");
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}

mod cors {
    use axum::http::{header, HeaderValue, Method};
    use tower_http::cors::{AllowOrigin, CorsLayer};

    /// Origin matcher supporting `*` wildcards; applied to every response
    /// (including errors and caught panics, which run inside this layer).
    pub fn layer(spec: &str) -> CorsLayer {
        let patterns: Vec<String> = spec
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let allow = AllowOrigin::predicate(move |origin: &HeaderValue, _| {
            let Ok(o) = origin.to_str() else { return false };
            patterns.iter().any(|p| wildcard(p, o))
        });
        CorsLayer::new()
            .allow_origin(allow)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    }

    fn wildcard(p: &str, s: &str) -> bool {
        if p == "*" {
            return true;
        }
        let parts: Vec<&str> = p.split('*').collect();
        if parts.len() == 1 {
            return p == s;
        }
        let mut rest = s;
        for (i, part) in parts.iter().enumerate() {
            if i == 0 {
                let Some(r) = rest.strip_prefix(part) else {
                    return false;
                };
                rest = r;
            } else if i == parts.len() - 1 {
                return rest.ends_with(part);
            } else {
                let Some(idx) = rest.find(part) else {
                    return false;
                };
                rest = &rest[idx + part.len()..];
            }
        }
        true
    }
}
