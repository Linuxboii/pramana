# Pramāṇa web app

The wallet, the relying-party shop and the five-act demonstration (PRD §15, §17).
Vite + React + TypeScript + Tailwind v4. Proofs are built in the browser by the
WebAssembly build of `pramana-core` (`src/wasm`, generated — not committed).

```sh
npm run wasm        # build ../crates/pramana-wasm into src/wasm (needs wasm-pack)
npm ci
npm run dev         # :5173, proxies /api to the demo server on :8080
npm run build       # → dist/, served by pramana-demo
node e2e/e2e.mjs    # browser end-to-end test against PRAMANA_URL (default http://127.0.0.1:8080)
```

| Path | Contents |
|---|---|
| `src/lib/wallet.ts` | typed bridge to the WASM wallet |
| `src/lib/api.ts` | issuer/verifier HTTP client and rejection-reason texts |
| `src/components/TryIt.tsx` | wallet + shop + consent + receipt |
| `src/components/Demonstration.tsx` | acts ①–④ |
| `src/components/XRay.tsx` | act ⑤: real vs simulated transcripts |
| `e2e/e2e.mjs` | 19-check browser test (playwright-core + installed Chrome/Edge) |
