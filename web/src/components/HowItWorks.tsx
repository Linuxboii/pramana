import { Section } from './ui'

const STEPS = [
  {
    title: 'Hide the birthdate in a commitment',
    ref: '§7.2',
    math: 'C_D = D·G + r·H',
    text: 'D is your birthdate as days since 1900. The random r makes C_D look uniformly random whatever D is, yet you can never later open it to a different date. The authority signs C_D once.',
  },
  {
    title: 'Turn “old enough” into “not negative”',
    ref: '§7.6',
    math: 'Δ = D* − D ≥ 0     C_Δ = D*·G − C_D',
    text: 'D* is the cutoff birthdate — today minus 18 years — which the website computes itself. Because commitments add, it can also compute a commitment to the slack Δ without knowing anything secret.',
  },
  {
    title: 'Prove Δ fits in 16 bits, bit by bit',
    ref: '§7.4–7.5',
    math: 'Cᵢ = bᵢ·G + rᵢ·H,  Σ 2ⁱ·Cᵢ = C_Δ',
    text: 'For each bit, an OR-proof shows it is 0 or 1 without saying which: the true branch is answered honestly, the other is simulated. The website re-adds the bit commitments itself. A negative Δ has no 16-bit form, so an under-age proof cannot exist.',
  },
  {
    title: 'Bind it to this website, this moment',
    ref: '§7.7',
    math: 'e = H(G, H, issuer, C_D, sig, D*, C_Δ, site, nonce, window, all T)',
    text: 'Instead of the website choosing a challenge interactively, both sides hash the entire statement — including the site’s fresh nonce and name. A proof answered for one site and one nonce fails everywhere else.',
  },
]

export function HowItWorks() {
  return (
    <Section
      id="how"
      title="How it works"
      intro={
        <p>
          The name comes from Nyāya epistemology: a <em>pramāṇa</em> is a valid means of knowledge. The website comes to
          know that you are old enough by inference — while being denied perception of the date beneath it. Four ideas
          make that possible. The full specification is in <code className="font-mono text-gold-soft">docs/PROTOCOL.md</code>.
        </p>
      }
    >
      <ol className="grid gap-5 md:grid-cols-2">
        {STEPS.map((s, i) => (
          <li key={s.title} className="panel p-6">
            <div className="flex items-baseline justify-between gap-3">
              <h3 className="text-xl font-semibold">
                <span className="mr-2 font-deva text-gold" aria-hidden>
                  {['१', '२', '३', '४'][i]}
                </span>
                {s.title}
              </h3>
              <span className="shrink-0 text-sm text-lavender">{s.ref}</span>
            </div>
            <p className="mt-4 overflow-x-auto rounded-lg bg-night-deep px-4 py-3 font-mono text-[0.85rem] text-gold-soft">{s.math}</p>
            <p className="mt-4 text-lavender">{s.text}</p>
          </li>
        ))}
      </ol>
      <div className="mt-8 grid gap-5 md:grid-cols-3">
        {[
          ['Completeness', 'An honest, old-enough holder’s proof always verifies.'],
          ['Soundness', 'An under-age holder forges a proof with probability about 2⁻²⁵², assuming discrete logs in Ristretto255 are hard.'],
          ['Zero-knowledge', 'A simulator with no birthdate produces identically distributed transcripts, so the proof reveals nothing more.'],
        ].map(([k, v]) => (
          <div key={k} className="rounded-xl border border-plum-line/60 p-5">
            <p className="font-semibold text-gold-soft">{k}</p>
            <p className="mt-1 text-lavender">{v}</p>
          </div>
        ))}
      </div>
      <p className="mt-8 max-w-3xl text-[0.95rem] text-lavender">
        Known limit, stated plainly: in this Tier A design the signed commitment C_D is the same in every proof, so
        colluding websites could link your visits. Tier B — re-randomisable BBS+ credentials — removes that and is
        documented as the next step.
      </p>
    </Section>
  )
}
