import { useState } from 'react'
import { api } from '../lib/api'
import type { InteractiveTranscript, Statement, ZkSamples } from '../lib/types'
import { wallet } from '../lib/wallet'
import { demoCredential } from '../lib/demoCreds'
import { Code, Pill } from './ui'

interface Run {
  st: Statement
  a: InteractiveTranscript
  b: InteractiveTranscript
  realIs: 'a' | 'b'
  aOk: boolean
  bOk: boolean
  teenSimOk: boolean
  samples: ZkSamples
}

export function XRay() {
  const [run, setRun] = useState<Run | null>(null)
  const [busy, setBusy] = useState(false)
  const [guess, setGuess] = useState<'a' | 'b' | null>(null)
  const [error, setError] = useState<string | null>(null)

  const go = async () => {
    setBusy(true)
    setGuess(null)
    setError(null)
    try {
      const aarav = await demoCredential('aarav')
      const teen = await demoCredential('teen')
      const st = (await api.challenge('shop', 18)).statement
      await new Promise((r) => setTimeout(r, 20))
      const real = wallet.realInteractive(aarav, st)
      const sim = wallet.simulate(aarav.c_d, st)
      const realIs = crypto.getRandomValues(new Uint8Array(1))[0] & 1 ? 'a' : 'b'
      const [a, b] = realIs === 'a' ? [real, sim] : [sim, real]
      const teenSim = wallet.simulate(teen.c_d, st)
      setRun({
        st,
        a,
        b,
        realIs,
        aOk: wallet.checkInteractive(aarav.c_d, st, a).ok,
        bOk: wallet.checkInteractive(aarav.c_d, st, b).ok,
        teenSimOk: wallet.checkInteractive(teen.c_d, st, teenSim).ok,
        samples: wallet.zkSamples(aarav, st, 60),
      })
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="max-w-2xl">
          <h3 className="text-2xl font-semibold">The X-ray</h3>
          <p className="text-gold-soft">Shows: zero-knowledge, made tangible</p>
          <p className="mt-2 text-lavender">
            One transcript below came from the real prover, who knows Aarav's birthdate. The other came from a simulator
            that was given only the public commitment — no birthdate at all. Both pass every check the verifier has. If
            you can't tell them apart, neither can the verifier, so the proof cannot have taught it anything.
          </p>
        </div>
        <button type="button" className="btn-gold" onClick={go} disabled={busy}>
          {busy ? 'Running…' : run ? 'Draw new transcripts' : 'Run this act'}
        </button>
      </div>
      {error && (
        <p role="alert" className="mt-4 text-vermilion">
          {error}
        </p>
      )}

      {run && (
        <div className="reveal mt-6 grid gap-6">
          <div className="grid gap-4 md:grid-cols-2">
            {(['a', 'b'] as const).map((k) => (
              <TranscriptTable
                key={k}
                name={`Transcript ${k.toUpperCase()}`}
                tr={run[k]}
                ok={k === 'a' ? run.aOk : run.bOk}
                reveal={guess ? (run.realIs === k ? 'Real prover' : 'Simulator, no witness') : null}
              />
            ))}
          </div>

          <div className="rounded-lg border border-plum-line/70 p-4">
            {guess ? (
              <p>
                {guess === run.realIs ? 'Correct' : 'Not this time'} — transcript {run.realIs.toUpperCase()} was the real one. Any
                guess is right half the time: the two are identically distributed, which is exactly the zero-knowledge property.
              </p>
            ) : (
              <div className="flex flex-wrap items-center gap-3">
                <p className="mr-2">Which transcript came from the real prover?</p>
                <button type="button" className="btn-quiet" onClick={() => setGuess('a')}>
                  Transcript A
                </button>
                <button type="button" className="btn-quiet" onClick={() => setGuess('b')}>
                  Transcript B
                </button>
              </div>
            )}
          </div>

          <Histogram samples={run.samples} />

          <p className="text-[0.95rem] text-lavender">
            The simulator even produces an accepting transcript for the 14-year-old's commitment{' '}
            <Pill tone={run.teenSimOk ? 'pass' : 'fail'}>{run.teenSimOk ? 'Passes' : 'Fails'}</Pill>. That doesn't break
            soundness: it only works because the simulator picks the challenge <Code>e</Code> before its commitments, which a
            real verifier — or the Fiat–Shamir hash — never allows. It proves the transcript itself carries no information
            about the birthdate.
          </p>
        </div>
      )}
    </div>
  )
}

function TranscriptTable({ name, tr, ok, reveal }: { name: string; tr: InteractiveTranscript; ok: boolean; reveal: string | null }) {
  return (
    <figure className="rounded-lg border border-plum-line/70 bg-night-deep/60 p-4">
      <figcaption className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-semibold">
          {name}
          {reveal && <span className="ml-2 text-gold-soft">({reveal})</span>}
        </span>
        <Pill tone={ok ? 'pass' : 'fail'}>{ok ? 'All 16 bits verify' : 'Fails'}</Pill>
      </figcaption>
      <p className="mt-2 hex">e = {tr.challenge.slice(0, 32)}…</p>
      <div className="mt-3 overflow-x-auto">
        <table className="w-full font-mono text-[0.72rem] text-lavender">
          <thead>
            <tr className="text-left text-parchment">
              <th className="py-1 pr-2 font-semibold">i</th>
              <th className="pr-2 font-semibold">Cᵢ</th>
              <th className="pr-2 font-semibold">e₀</th>
              <th className="pr-2 font-semibold">z₀</th>
              <th className="font-semibold">z₁</th>
            </tr>
          </thead>
          <tbody>
            {tr.bits.map((b, i) => (
              <tr key={i} className="border-t border-plum-line/40">
                <td className="py-0.5 pr-2">{i}</td>
                <td className="pr-2">{b.c.slice(0, 8)}</td>
                <td className="pr-2">{b.e0.slice(0, 8)}</td>
                <td className="pr-2">{b.z0.slice(0, 8)}</td>
                <td>{b.z1.slice(0, 8)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </figure>
  )
}

function Histogram({ samples }: { samples: ZkSamples }) {
  const bucket = (v: number[]) => {
    const b = new Array(16).fill(0)
    v.forEach((x) => b[x >> 4]++)
    return b as number[]
  }
  const real = bucket(samples.real)
  const sim = bucket(samples.simulated)
  const max = Math.max(...real, ...sim)
  const W = 640
  const H = 180
  const bw = W / 16
  return (
    <figure className="rounded-lg border border-plum-line/70 p-4">
      <figcaption>
        <p className="font-semibold">
          {samples.transcripts} real and {samples.transcripts} simulated transcripts, {samples.real.length.toLocaleString()} values each
        </p>
        <p className="text-[0.95rem] text-lavender">
          Leading byte of every e₀, z₀, z₁ and Cᵢ, grouped into 16 ranges. Both are flat: χ² against uniform is{' '}
          {samples.chi2_real.toFixed(0)} (real) and {samples.chi2_simulated.toFixed(0)} (simulated), where anything under about 330
          is consistent with pure randomness.
        </p>
      </figcaption>
      <svg viewBox={`0 0 ${W} ${H + 24}`} className="mt-4 w-full" role="img" aria-label="Paired histogram of real versus simulated transcript bytes; the bars are near-identical">
        {real.map((r, i) => {
          const s = sim[i]
          const hr = (r / max) * H
          const hs = (s / max) * H
          return (
            <g key={i}>
              <rect x={i * bw + 4} y={H - hr} width={bw / 2 - 5} height={hr} rx="2" fill="var(--color-gold)">
                <title>{`Real, range ${i}: ${r}`}</title>
              </rect>
              <rect x={i * bw + bw / 2 + 1} y={H - hs} width={bw / 2 - 5} height={hs} rx="2" fill="var(--color-lavender)">
                <title>{`Simulated, range ${i}: ${s}`}</title>
              </rect>
            </g>
          )
        })}
        <line x1="0" x2={W} y1={H} y2={H} stroke="var(--color-plum-line)" />
        <text x="0" y={H + 18} fill="var(--color-lavender)" fontSize="12">
          0x00
        </text>
        <text x={W} y={H + 18} fill="var(--color-lavender)" fontSize="12" textAnchor="end">
          0xff
        </text>
      </svg>
      <div className="mt-2 flex gap-5 text-sm text-lavender">
        <span className="flex items-center gap-2">
          <span className="h-3 w-3 rounded-sm bg-gold" /> Real prover
        </span>
        <span className="flex items-center gap-2">
          <span className="h-3 w-3 rounded-sm bg-lavender" /> Simulator
        </span>
      </div>
    </figure>
  )
}
