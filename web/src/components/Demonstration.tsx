import { useState, type ReactNode } from 'react'
import { api, REASONS, type VerifierKey } from '../lib/api'
import { short } from '../lib/store'
import { demoCredential } from '../lib/demoCreds'
import type { AgeProof, AppConfig, CheatStrategy, Credential, Statement, VerifyResponse } from '../lib/types'
import { wallet, WalletError } from '../lib/wallet'
import { Code, Disclosure, Json, Section, StepLog, type Step } from './ui'
import { XRay } from './XRay'

function verdict(label: string, r: VerifyResponse, expectOk: boolean): Step {
  return {
    label,
    tone: r.ok ? 'pass' : 'fail',
    detail: r.ok ? (
      <>The verifier learned: {r.threshold_years}+, attested by {r.issuer?.name}.</>
    ) : (
      <>
        <Code>{r.reason}</Code> — {REASONS[r.reason ?? ''] ?? r.detail}
        {expectOk && ' (unexpected)'}
      </>
    ),
  }
}

function useRunner() {
  const [steps, setSteps] = useState<Step[]>([])
  const [running, setRunning] = useState(false)
  const run = async (fn: (push: (s: Step) => void) => Promise<void>) => {
    setSteps([])
    setRunning(true)
    const push = (s: Step) => setSteps((prev) => [...prev, s])
    try {
      await fn(push)
    } catch (e) {
      push({ label: 'The act could not finish', tone: 'fail', badge: 'Error', detail: (e as Error).message })
    } finally {
      setRunning(false)
    }
  }
  return { steps, running, run }
}

async function freshStatement(v: VerifierKey, threshold = 18): Promise<Statement> {
  return (await api.challenge(v, threshold)).statement
}

/* ------------------------------------------------------------------ acts */

function ActHonest({ config }: { config: AppConfig }) {
  const { steps, running, run } = useRunner()
  const [proof, setProof] = useState<{ pf: AgeProof; st: Statement } | null>(null)
  const go = () =>
    run(async (push) => {
      setProof(null)
      const aarav = await demoCredential('aarav')
      push({ label: 'Aarav holds a credential for 12 April 2001', tone: 'info', badge: 'Wallet' })
      const st = await freshStatement('shop')
      push({
        label: `${config.verifiers.shop.id} sends a challenge`,
        tone: 'info',
        badge: 'Statement',
        detail: (
          <>
            age ≥ {st.threshold_years} as of {st.today}, nonce <Code>{short(st.nonce, 8)}</Code>
          </>
        ),
      })
      const t0 = performance.now()
      const pf = wallet.prove(aarav, st)
      const ms = performance.now() - t0
      const ins = wallet.inspect(pf, st)
      push({
        label: `Wallet builds the proof in ${ms.toFixed(0)} ms`,
        tone: 'info',
        badge: 'Proof',
        detail: `${ins.cbor_bytes.toLocaleString()} bytes (CBOR). The string "2001-04-12" appears in it: ${JSON.stringify(pf).includes('2001-04-12') ? 'yes' : 'no'}.`,
      })
      setProof({ pf, st })
      const r = await api.verify('shop', pf)
      push(verdict('The shop verifies', r, true))
    })
  return (
    <Act
      title="The honest path"
      property="Completeness and zero-knowledge"
      body={
        <p>
          Aarav, born in 2001, proves he is at least 18. The shop accepts in well under a second. Open the proof below and
          look for his birthdate.
        </p>
      }
      onRun={go}
      running={running}
      steps={steps}
    >
      {proof && (
        <Disclosure summary="The proof blob">
          <Json value={proof.pf} />
        </Disclosure>
      )}
    </Act>
  )
}

function ActCheat({ config }: { config: AppConfig }) {
  const { steps, running, run } = useRunner()
  const go = () =>
    run(async (push) => {
      const teen = await demoCredential('teen')
      const b = wallet.checkCredential(teen).birthdate
      push({ label: `Aarav's DOB is toggled to ${b} — he is now 14`, tone: 'info', badge: 'Wallet' })
      let st = await freshStatement('shop')
      try {
        wallet.prove(teen, st)
        push({ label: 'The honest wallet built a proof', tone: 'fail', badge: 'Unexpected' })
      } catch (e) {
        const days = e instanceof WalletError ? e.data.days_short : '?'
        push({
          label: 'The honest wallet cannot build a proof',
          tone: 'fail',
          badge: 'No solution',
          detail: (
            <>
              Δ = D* − D = −{String(days)} days. A negative Δ has no decomposition into 16 bits, so the range proof has no
              solution.
            </>
          ),
        })
      }
      const attempts: [CheatStrategy, string, string][] = [
        ['wrap_around', 'Cheat 1: prove Δ mod 2¹⁶ instead', 'Every bit proof is genuine, but the bits add up to the wrong number.'],
        ['fake_digit', 'Cheat 2: keep the sum right with a fake "bit"', 'The top digit is not 0 or 1, so its OR-proof has to be guessed — and the challenge does not split.'],
      ]
      for (const [s, label, how] of attempts) {
        st = await freshStatement('shop')
        const pf = wallet.cheat(teen, st, s)
        const r = await api.verify('shop', pf)
        push({ ...verdict(label, r, false), detail: <>{how} {verdict('', r, false).detail}</> })
      }
      push({
        label: `${config.verifiers.shop.id} gained nothing from any attempt`,
        tone: 'info',
        badge: 'Soundness',
        detail: 'Forging a proof for a negative Δ means breaking the discrete logarithm in Ristretto255 — probability about 2⁻²⁵².',
      })
    })
  return (
    <Act
      title="The cheat"
      property="Soundness"
      body={<p>Make Aarav 14. The honest wallet refuses, so we try two cheating provers built to fool the verifier.</p>}
      onRun={go}
      running={running}
      steps={steps}
    />
  )
}

function ActForgery() {
  const { steps, running, run } = useRunner()
  const [editor, setEditor] = useState<{ text: string; st: Statement } | null>(null)
  const [editResult, setEditResult] = useState<Step[]>([])

  const go = () =>
    run(async (push) => {
      const aarav = await demoCredential('aarav')
      const teen = await demoCredential('teen')
      const cases: [CheatStrategy, Credential, string, string][] = [
        ['tamper_bytes', aarav, 'Flip one bit in a valid proof', 'One byte of one response changes.'],
        ['swap_commitment', teen, 'Swap in an unsigned commitment to an older birthdate', 'The range proof is perfect — for a commitment nobody signed.'],
        ['rogue_issuer', teen, 'Mint a credential with a self-made "authority" key', 'Signed by "Totally Legit Authority".'],
      ]
      for (const [s, c, label, how] of cases) {
        const st = await freshStatement('shop')
        const pf = wallet.cheat(c, st, s)
        const r = await api.verify('shop', pf)
        push({ ...verdict(label, r, false), detail: <>{how} {verdict('', r, false).detail}</> })
      }
    })

  const prepare = async () => {
    const aarav = await demoCredential('aarav')
    const st = await freshStatement('shop')
    setEditResult([])
    setEditor({ text: JSON.stringify({ proof: wallet.prove(aarav, st) }, null, 2), st })
  }

  const send = async () => {
    if (!editor) return
    const r = await api.verifyRaw('shop', editor.text)
    setEditResult([verdict('Your edited proof', r, false)])
    setEditor(null)
  }

  return (
    <Act
      title="The forgery attempt"
      property="Binding"
      body={<p>Edit proof bytes, swap the birthdate commitment, or invent an issuer. Each fails a different check.</p>}
      onRun={go}
      running={running}
      steps={steps}
    >
      <div className="rounded-lg border border-plum-line/70 p-4">
        <p className="font-semibold">Hand-edit a proof yourself</p>
        <p className="mt-1 text-[0.95rem] text-lavender">
          Get a valid proof for a fresh challenge, change any character, and send it. Leave it untouched to see it pass.
        </p>
        {editor ? (
          <>
            <label className="sr-only" htmlFor="proof-editor">
              Proof JSON
            </label>
            <textarea
              id="proof-editor"
              className="field mt-3 h-64 font-mono text-[0.75rem]"
              spellCheck={false}
              value={editor.text}
              onChange={(e) => setEditor({ ...editor, text: e.target.value })}
            />
            <button type="button" className="btn-gold mt-3" onClick={send}>
              Send to the shop
            </button>
          </>
        ) : (
          <button type="button" className="btn-quiet mt-3" onClick={prepare}>
            Load a fresh valid proof
          </button>
        )}
        <StepLog steps={editResult} />
      </div>
    </Act>
  )
}

function ActReplay({ config }: { config: AppConfig }) {
  const { steps, running, run } = useRunner()
  const { shop, other } = config.verifiers
  const go = () =>
    run(async (push) => {
      const aarav = await demoCredential('aarav')
      const st = await freshStatement('shop')
      const pf = wallet.prove(aarav, st)
      push({
        label: `A proof for ${shop.id} is captured in transit`,
        tone: 'info',
        badge: 'Captured',
        detail: (
          <>
            It answers nonce <Code>{short(st.nonce, 8)}</Code> from {shop.id}.
          </>
        ),
      })
      push(verdict(`Replay it, unchanged, at ${other.id}`, await api.verify('other', pf), false))
      const st2 = await freshStatement('other')
      const relabelled = { ...pf, nonce: st2.nonce }
      push({
        ...verdict(`Ask ${other.id} for a challenge and relabel the proof with its nonce`, await api.verify('other', relabelled), false),
      })
      push(verdict(`The rightful owner submits it to ${shop.id}`, await api.verify('shop', pf), true))
      push(verdict(`Replay it at ${shop.id} a second time`, await api.verify('shop', pf), false))
      push({
        label: 'Why the relabelled proof fails',
        tone: 'info',
        badge: '§7.7',
        detail: (
          <>
            The challenge is <Code>e = H(… verifier_id ‖ nonce ‖ window ‖ all T-values)</Code>. {other.id} recomputes e from its
            own id and nonce; the bit proofs were answered for a different e, so they cannot satisfy its equations.
          </>
        ),
      })
    })
  return (
    <Act
      title="The replay"
      property="Non-transferability"
      body={<p>Capture a valid proof and try to reuse it at a second verifier, or twice at the same one.</p>}
      onRun={go}
      running={running}
      steps={steps}
    />
  )
}

/* ------------------------------------------------------------------ frame */

function Act({
  title,
  property,
  body,
  onRun,
  running,
  steps,
  children,
}: {
  title: string
  property: string
  body: ReactNode
  onRun: () => void
  running: boolean
  steps: Step[]
  children?: ReactNode
}) {
  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="max-w-2xl">
          <h3 className="text-2xl font-semibold">{title}</h3>
          <p className="text-gold-soft">Shows: {property}</p>
          <div className="mt-2 text-lavender">{body}</div>
        </div>
        <button type="button" className="btn-gold" onClick={onRun} disabled={running}>
          {running ? 'Running…' : steps.length ? 'Run again' : 'Run this act'}
        </button>
      </div>
      <StepLog steps={steps} />
      {children && <div className="mt-6 grid min-w-0 gap-4">{children}</div>}
    </div>
  )
}

const ACTS = [
  { key: 'honest', name: 'The honest path' },
  { key: 'cheat', name: 'The cheat' },
  { key: 'forgery', name: 'The forgery attempt' },
  { key: 'replay', name: 'The replay' },
  { key: 'xray', name: 'The X-ray' },
] as const

export function Demonstration({ config }: { config: AppConfig }) {
  const [act, setAct] = useState<(typeof ACTS)[number]['key']>('honest')
  return (
    <Section
      id="demo"
      title="The demonstration"
      intro={
        <p>
          Five acts that turn the three promises — completeness, soundness, zero-knowledge — into things you can watch happen.
          Every proof below is real, built by the WebAssembly wallet and checked by a live verifier.
        </p>
      }
    >
      <div className="grid gap-8 lg:grid-cols-[15rem_minmax(0,1fr)]">
        <ol className="flex gap-2 overflow-x-auto pb-2 lg:flex-col lg:overflow-visible" role="tablist" aria-label="Acts">
          {ACTS.map((a, i) => (
            <li key={a.key} className="shrink-0">
              <button
                type="button"
                role="tab"
                aria-selected={act === a.key}
                className={`flex w-full items-baseline gap-3 rounded-lg px-3 py-2.5 text-left transition-colors ${
                  act === a.key ? 'bg-plum text-parchment' : 'text-lavender hover:bg-plum/50 hover:text-parchment'
                }`}
                onClick={() => setAct(a.key)}
              >
                <span className={`font-deva text-lg ${act === a.key ? 'text-gold' : ''}`} aria-hidden>
                  {['१', '२', '३', '४', '५'][i]}
                </span>
                <span className="whitespace-nowrap">{a.name}</span>
              </button>
            </li>
          ))}
        </ol>
        <div className="panel min-h-[24rem] min-w-0 p-6" role="tabpanel">
          {act === 'honest' && <ActHonest config={config} />}
          {act === 'cheat' && <ActCheat config={config} />}
          {act === 'forgery' && <ActForgery />}
          {act === 'replay' && <ActReplay config={config} />}
          {act === 'xray' && <XRay />}
        </div>
      </div>
    </Section>
  )
}
