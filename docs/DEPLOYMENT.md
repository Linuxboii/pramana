# Deployment

Pramāṇa ships as **one container** (`pramana-demo`) serving the web app, the demo issuer and two verifiers on a single port. It needs no database and no external services.

## Configuration

Every option is an environment variable (or the matching CLI flag).

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | — | If set (Render, Fly, Railway, Cloud Run…), listen on this port on all interfaces. |
| `PRAMANA_ADDR` | `0.0.0.0:8080` | Listen address when `PORT` is unset. |
| `PRAMANA_ISSUER_KEY` | — | Demo issuer secret: 64 hex chars (used directly as the Ed25519 seed) **or** any secret ≥ 32 chars (hashed into a seed). Takes precedence over the key file. |
| `PRAMANA_ISSUER_KEY_FILE` | `/data/issuer.key` in the image | Key file; created on first start if missing. |
| `PRAMANA_ISSUER_NAME` | `Demo Authority` | Name shown in credentials and on the trust list. |
| `PRAMANA_WEB_DIR` | `/app/web` in the image | Built web app. |
| `PRAMANA_SHOP_ID` | `example-shop.com` | Relying-party verifier id (bound into every proof). |
| `PRAMANA_OTHER_ID` | `other-site.example` | Second verifier id (replay demonstration). |
| `PRAMANA_CHALLENGE_TTL` | `120` | Challenge validity window, seconds. |
| `PRAMANA_EXTRA_TRUSTED_ISSUERS` | — | Additional trusted issuers: `Name=<hex>,Name2=<hex>`. |
| `PRAMANA_CORS_ORIGINS` | `http://localhost:*,http://127.0.0.1:*` | Origins allowed to call `/api` cross-origin (`*` wildcards). The bundled web app is same-origin and needs nothing here. |
| `RUST_LOG` | `info,tower_http=warn` | Log filter. |

**Issuer key persistence.** Credentials are only valid while their issuer key is trusted. Without `PRAMANA_ISSUER_KEY` and without a persistent `/data`, every restart creates a new key, and wallets holding old credentials will see "the stored credential failed its self-check — request a new one". Set `PRAMANA_ISSUER_KEY` on any host with an ephemeral filesystem.

## Docker

```sh
docker build -t pramana .
docker run -d --name pramana -p 8080:8080 -v pramana-data:/data pramana
# → http://localhost:8080
```

or `docker compose up --build`. The image runs as an unprivileged user, exposes 8080, keeps state only in `/data`, and has a built-in `HEALTHCHECK` (`pramana-demo --healthcheck`, which probes `/api/health`).

## Render

The repo contains `render.yaml`. In the Render dashboard choose **New → Blueprint**, select the repository, and deploy. Render builds the Dockerfile, sets `PORT`, generates a stable `PRAMANA_ISSUER_KEY`, and health-checks `/api/health`.

## Fly.io

```sh
fly launch --copy-config --no-deploy          # accept or rename the app in fly.toml
fly secrets set PRAMANA_ISSUER_KEY=$(openssl rand -hex 32)
fly deploy
```

## Any other container host

Railway, Google Cloud Run, Azure Container Apps, a VM with Docker: build the image, expose port 8080 (or set `PORT`), set `PRAMANA_ISSUER_KEY`. Put it behind HTTPS — browsers require a secure context for many features and you should not serve credentials over plain HTTP.

## Running the services separately

The issuer and verifier are also standalone binaries (both included in the image):

```sh
pramana-issuer keygen --out /data/issuer.key
pramana-issuer serve --key /data/issuer.key --addr 0.0.0.0:8081
PRAMANA_TRUSTED_ISSUERS="Demo Authority=$(pramana-issuer pubkey --key /data/issuer.key | jq -r .public_key)" \
PRAMANA_VERIFIER_ID=shop.example PRAMANA_CORS_ORIGINS="https://shop.example" \
  pramana-sakshi --addr 0.0.0.0:8082
```

A relying party only needs `pramana-sakshi` (or the `pramana-core` library) and the issuer's public key: verification is fully offline.

## Operations

* **Health:** `GET /api/health` (demo) or `GET /health` (sakshi).
* **State:** challenges and the audit log are in memory and per process. Run a **single instance** per verifier id, or put a sticky load balancer in front: a challenge issued by one instance cannot be answered at another. (A shared nonce store is straightforward future work.)
* **Logs:** structured `tracing` output to stdout; no PII is logged.
* **Upgrades:** stateless apart from the issuer key; redeploy freely.

## Building without Docker

```sh
./scripts/build-wasm.sh
(cd web && npm ci && npm run build)
cargo build --release -p pramana-demo
PRAMANA_WEB_DIR=web/dist ./target/release/pramana-demo
```
