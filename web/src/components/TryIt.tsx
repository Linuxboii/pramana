import { useEffect, useRef, useState } from 'react'
import { api, ApiError, REASONS } from '../lib/api'
import { ageOn, formatDate, short, todayIso, yearsAgo } from '../lib/store'
import type { AgeProof, AppConfig, AuditEntry, Credential, Statement, VerifyResponse } from '../lib/types'
import { wallet, WalletError } from '../lib/wallet'
import { Check, Code, Cross, Disclosure, Json, Pill, Section } from './ui'

interface Props {
  config: AppConfig
  credential: Credential | null
  setCredential: (c: Credential | null) => void
  onResult: (r: VerifyResponse) => void
}

export function TryIt({ config, credential, setCredential, onResult }: Props) {
  return (
    <Section
      id="try"
      title="Try it: buy a bottle of wine"
      intro={
        <p>
          On the left is your wallet, running the proving code as WebAssembly in this tab. On the right is a small online
          shop that must check your age. Get a credential once from the demo authority, then prove your age to the shop as
          often as you like. Nothing about your birthdate ever leaves the wallet.
        </p>
      }
    >
      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <WalletPanel credential={credential} setCredential={setCredential} issuerName={config.issuer.name} />
        <ShopPanel config={config} credential={credential} onResult={onResult} />
      </div>
    </Section>
  )
}

/* ------------------------------------------------------------------ wallet */

function WalletPanel({
  credential,
  setCredential,
  issuerName,
}: {
  credential: Credential | null
  setCredential: (c: Credential | null) => void
  issuerName: string
}) {
  const [dob, setDob] = useState('2001-04-12')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  let summary: ReturnType<typeof wallet.checkCredential> | null = null
  let invalid: string | null = null
  if (credential) {
    try {
      summary = wallet.checkCredential(credential)
    } catch (e) {
      invalid = (e as Error).message
    }
  }

  const request = async () => {
    setBusy(true)
    setError(null)
    try {
      const c = await api.issue(dob)
      wallet.checkCredential(c)
      setCredential(c)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const importFile = async (f: File) => {
    setError(null)
    try {
      const c = JSON.parse(await f.text()) as Credential
      wallet.checkCredential(c)
      setCredential(c)
    } catch (e) {
      setError(`That file is not a valid Pramāṇa credential: ${(e as Error).message}`)
    }
  }

  const exportFile = () => {
    if (!credential) return
    const blob = new Blob([JSON.stringify(credential, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'pramana-credential.json'
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <div className="panel flex min-w-0 flex-col p-6 lg:sticky lg:top-20">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-xl font-semibold">Your wallet</h3>
        <span className="text-sm text-lavender">Runs on this device</span>
      </div>

      {credential && summary ? (
        <div className="mt-5 flex flex-col">
          <div className="rounded-lg border border-gold/40 bg-gradient-to-br from-gold/15 to-transparent p-5">
            <p className="flex items-center gap-2 font-semibold text-gold-soft">
              <Check className="h-4 w-4" /> Age credential active · issued by {summary.issuer_name}
            </p>
            <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-[0.95rem]">
              <dt className="text-lavender">Birthdate</dt>
              <dd>
                {formatDate(summary.birthdate)} <span className="text-lavender">(age {ageOn(summary.birthdate, todayIso())}; only you see this)</span>
              </dd>
              <dt className="text-lavender">Commitment</dt>
              <dd className="hex">{short(summary.c_d, 14)}</dd>
              <dt className="text-lavender">Issuer key</dt>
              <dd className="hex">{short(summary.issuer_pk, 14)}</dd>
            </dl>
          </div>
          <p className="mt-4 text-[0.95rem] text-lavender">
            The authority signed a commitment <Code>C_D = D·G + r·H</Code> to your birthdate and handed you the opening{' '}
            <Code>(D, r)</Code>. You will never need to contact it again.
          </p>
          <div className="flex flex-wrap gap-2 pt-5">
            <button type="button" className="btn-quiet" onClick={exportFile}>
              Save credential file
            </button>
            <button type="button" className="btn-quiet" onClick={() => setCredential(null)}>
              Remove from wallet
            </button>
          </div>
        </div>
      ) : (
        <div className="mt-5 flex flex-1 flex-col">
          {invalid && (
            <p role="alert" className="mb-4 rounded-lg border border-vermilion/50 bg-vermilion/10 px-4 py-3 text-[0.95rem]">
              The stored credential failed its self-check ({invalid}). It was probably issued by a previous server key.
              Request a new one.
            </p>
          )}
          <p className="text-lavender">
            No credential yet. In real life an authority that already knows your birthdate — a passport office, a bank —
            would issue this. Here, {issuerName} takes your word for it.
          </p>
          <label className="mt-5 block font-semibold" htmlFor="dob">
            Date of birth
          </label>
          <input id="dob" type="date" className="field mt-1.5" value={dob} max={todayIso()} min="1900-01-01" onChange={(e) => setDob(e.target.value)} />
          <div className="mt-2 flex flex-wrap gap-2 text-sm">
            <button type="button" className="rounded-md px-2 py-1 text-lavender underline-offset-4 hover:text-parchment hover:underline" onClick={() => setDob('2001-04-12')}>
              Aarav, born 2001
            </button>
            <button type="button" className="rounded-md px-2 py-1 text-lavender underline-offset-4 hover:text-parchment hover:underline" onClick={() => setDob(yearsAgo(14))}>
              A 14-year-old
            </button>
            <button type="button" className="rounded-md px-2 py-1 text-lavender underline-offset-4 hover:text-parchment hover:underline" onClick={() => setDob(yearsAgo(19, '12-31'))}>
              Turned 18 last year
            </button>
          </div>
          {error && (
            <p role="alert" className="mt-3 text-[0.95rem] text-vermilion">
              {error}
            </p>
          )}
          <div className="mt-auto flex flex-wrap gap-2 pt-6">
            <button type="button" className="btn-gold" disabled={busy || !dob} onClick={request}>
              {busy ? 'Requesting…' : `Request credential from ${issuerName}`}
            </button>
            <button type="button" className="btn-quiet" onClick={() => fileRef.current?.click()}>
              Import file
            </button>
            <input
              ref={fileRef}
              type="file"
              accept="application/json,.json,.cred"
              className="hidden"
              onChange={(e) => e.target.files?.[0] && importFile(e.target.files[0])}
            />
          </div>
        </div>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ shop */

type Phase =
  | { kind: 'gate' }
  | { kind: 'consent'; statement: Statement }
  | { kind: 'refused'; statement: Statement; daysShort: number }
  | { kind: 'working' }
  | { kind: 'done'; statement: Statement; proof: AgeProof; result: VerifyResponse; proveMs: number; verifyMs: number }
  | { kind: 'error'; message: string }

function ShopPanel({ config, credential, onResult }: { config: AppConfig; credential: Credential | null; onResult: (r: VerifyResponse) => void }) {
  const [threshold, setThreshold] = useState(18)
  const [phase, setPhase] = useState<Phase>({ kind: 'gate' })
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const shopId = config.verifiers.shop.id

  const refreshAudit = () =>
    api
      .audit('shop')
      .then((a) => setAudit(a.entries.slice(-5).reverse()))
      .catch(() => {})
  useEffect(() => {
    refreshAudit()
  }, [])

  const begin = async () => {
    try {
      const ch = await api.challenge('shop', threshold)
      setPhase({ kind: 'consent', statement: ch.statement })
    } catch (e) {
      setPhase({ kind: 'error', message: (e as ApiError).message })
    }
  }

  const prove = async (statement: Statement) => {
    if (!credential) return
    setPhase({ kind: 'working' })
    await new Promise((r) => setTimeout(r, 30)) // let the UI paint
    try {
      const t0 = performance.now()
      const proof = wallet.prove(credential, statement)
      const proveMs = performance.now() - t0
      const t1 = performance.now()
      const result = await api.verify('shop', proof)
      const verifyMs = performance.now() - t1
      setPhase({ kind: 'done', statement, proof, result, proveMs, verifyMs })
      if (result.ok) onResult(result)
      refreshAudit()
    } catch (e) {
      if (e instanceof WalletError && e.code === 'underage') {
        setPhase({ kind: 'refused', statement, daysShort: Number(e.data.days_short) })
      } else {
        setPhase({ kind: 'error', message: (e as Error).message })
      }
    }
  }

  return (
    <div className="min-w-0 overflow-hidden rounded-xl border border-plum-line bg-night-deep">
      <div className="flex items-center gap-3 border-b border-plum-line bg-plum/60 px-4 py-2.5">
        <span className="flex gap-1.5" aria-hidden>
          <span className="h-2.5 w-2.5 rounded-full bg-plum-line" />
          <span className="h-2.5 w-2.5 rounded-full bg-plum-line" />
          <span className="h-2.5 w-2.5 rounded-full bg-plum-line" />
        </span>
        <span className="flex-1 truncate rounded-md bg-night-deep px-3 py-1 font-mono text-sm text-lavender">https://{shopId}/nilgiri-reserve</span>
      </div>

      <div className="p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-sm text-lavender">{shopId}</p>
            <h3 className="mt-1 text-2xl font-semibold">Nilgiri Reserve, 2019</h3>
            <p className="mt-1 text-lavender">Single-estate red, 750 ml · ₹2,400</p>
          </div>
          <label className="text-sm text-lavender">
            <span className="block">Shop's age rule</span>
            <select
              className="field mt-1 w-auto py-1.5"
              value={threshold}
              onChange={(e) => {
                setThreshold(Number(e.target.value))
                setPhase({ kind: 'gate' })
              }}
            >
              {config.thresholds.map((t) => (
                <option key={t} value={t}>
                  {t}+
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="mt-6 min-h-[15rem] min-w-0 rounded-lg border border-plum-line/70 p-5">
          {phase.kind === 'gate' && (
            <div>
              <p className="text-lg">
                This content is {threshold}+. <em className="text-gold-soft">Prove your age privately.</em>
              </p>
              <p className="mt-2 text-[0.95rem] text-lavender">
                The shop will send your wallet a fresh challenge. Your wallet answers with a proof that only works for this
                shop, for the next {Math.round(config.challenge_ttl_secs / 60)} minutes, once.
              </p>
              <button type="button" className="btn-gold mt-5" disabled={!credential} onClick={begin}>
                Prove your age privately
              </button>
              {!credential && <p className="mt-3 text-[0.95rem] text-gold-soft">Get a credential in your wallet first.</p>}
            </div>
          )}

          {phase.kind === 'consent' && (
            <div role="dialog" aria-labelledby="consent-title" className="reveal">
              <p id="consent-title" className="text-sm text-lavender">
                Your wallet asks
              </p>
              <blockquote className="mt-2 border-l-2 border-gold pl-4 text-lg">
                <strong>{phase.statement.verifier_id}</strong> will learn: <em>you are {phase.statement.threshold_years} or older</em>. It will
                not learn your date of birth, name, or anything that identifies you.
              </blockquote>
              <div className="mt-5 flex gap-2">
                <button type="button" className="btn-gold" onClick={() => prove(phase.statement)} autoFocus>
                  Prove
                </button>
                <button type="button" className="btn-quiet" onClick={() => setPhase({ kind: 'gate' })}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          {phase.kind === 'working' && <p className="text-lavender" aria-live="polite">Building the proof in your browser…</p>}

          {phase.kind === 'refused' && (
            <div className="reveal">
              <Pill tone="fail">No proof possible</Pill>
              <p className="mt-3">
                Your credential doesn't meet the {phase.statement.threshold_years}+ rule — you are {phase.daysShort} days short. The
                wallet sent nothing.
              </p>
              <p className="mt-2 text-[0.95rem] text-lavender">
                This isn't a policy check you could bypass: for an under-age birthdate the slack <Code>Δ = D* − D</Code> is negative,
                and a negative number has no 16-bit binary decomposition. The proof has no solution.
              </p>
              <button type="button" className="btn-quiet mt-4" onClick={() => setPhase({ kind: 'gate' })}>
                Back to the shop
              </button>
            </div>
          )}

          {phase.kind === 'error' && (
            <div role="alert">
              <Pill tone="fail">Something went wrong</Pill>
              <p className="mt-3">{phase.message}</p>
              <button type="button" className="btn-quiet mt-4" onClick={() => setPhase({ kind: 'gate' })}>
                Try again
              </button>
            </div>
          )}

          {phase.kind === 'done' && <Receipt phase={phase} credential={credential} onAgain={() => setPhase({ kind: 'gate' })} />}
        </div>

        <div className="mt-6">
          <Disclosure summary={`What ${shopId} keeps after each check`}>
            <p className="text-[0.95rem] text-lavender">
              The verifier's entire memory: a timestamp, which issuer key signed, and the result. No proof, no commitment, no
              birthdate.
            </p>
            {audit.length ? (
              <Json value={audit} maxHeight="14rem" />
            ) : (
              <p className="mt-2 text-[0.95rem]">Nothing yet — run a check above.</p>
            )}
          </Disclosure>
        </div>
      </div>
    </div>
  )
}

function Receipt({
  phase,
  credential,
  onAgain,
}: {
  phase: Extract<Phase, { kind: 'done' }>
  credential: Credential | null
  onAgain: () => void
}) {
  const { result, proof, statement } = phase
  const json = JSON.stringify(proof)
  const cborBytes = wallet.cborHex(proof).length / 2
  const dob = credential ? wallet.checkCredential(credential).birthdate : null
  const leaks = dob
    ? [
        { label: 'Your birthdate', found: json.includes(dob) },
        // D as a JSON number value (a bare substring search could hit a hex string by chance)
        { label: 'Your birthdate as a day count', found: new RegExp(`[:\\[,]${credential!.d}[,\\]}]`).test(json) },
        { label: 'Your secret randomness r', found: json.includes(credential!.r) },
      ]
    : []

  return (
    <div className="reveal min-w-0">
      {result.ok ? (
        <div className="flex items-center gap-4">
          <span className="grid h-14 w-14 place-items-center rounded-full bg-verdigris/20 text-verdigris">
            <Check className="h-8 w-8" />
          </span>
          <div>
            <p className="text-xl font-semibold">Access granted</p>
            <p className="text-lavender">
              Proved {statement.threshold_years}+ to {statement.verifier_id} in {Math.round(phase.proveMs)} ms; verified in{' '}
              {Math.round(phase.verifyMs)} ms round-trip.
            </p>
          </div>
        </div>
      ) : (
        <div className="flex items-center gap-4">
          <span className="grid h-14 w-14 place-items-center rounded-full bg-vermilion/20 text-vermilion">
            <Cross className="h-8 w-8" />
          </span>
          <div>
            <p className="text-xl font-semibold">Rejected</p>
            <p className="text-lavender">{REASONS[result.reason ?? ''] ?? result.detail}</p>
          </div>
        </div>
      )}

      <div className="mt-5 grid min-w-0 gap-3">
        <Disclosure summary="What the website received">
          <p className="text-[0.95rem] text-lavender">
            {json.length.toLocaleString()} bytes as JSON, {cborBytes.toLocaleString()} bytes as CBOR: the issuer key, the
            signed commitment, the nonce it answers, and 16 bit commitments with their OR-proofs.
          </p>
          {leaks.length > 0 && (
            <ul className="my-3 grid gap-1.5">
              {leaks.map((l) => (
                <li key={l.label} className="flex items-center justify-between gap-3 text-[0.95rem]">
                  <span>{l.label} appears in the proof</span>
                  <Pill tone={l.found ? 'fail' : 'pass'}>{l.found ? 'Found' : 'Absent'}</Pill>
                </li>
              ))}
            </ul>
          )}
          <Json value={proof} />
        </Disclosure>
        <Disclosure summary="The shop's verdict, verbatim">
          <Json value={result} maxHeight="14rem" />
        </Disclosure>
      </div>
      <button type="button" className="btn-quiet mt-5" onClick={onAgain}>
        Check again with a new challenge
      </button>
    </div>
  )
}
