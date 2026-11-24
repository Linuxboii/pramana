import type { VerifyResponse } from '../lib/types'

const SPECIMEN = [
  ['Name', 'Aarav Mehta'],
  ['Date of birth', '12 April 2001'],
  ['Address', '14 Lakeview Road, Bengaluru 560001'],
  ['Licence number', 'KA01 20190042117'],
  ['Issued', '3 May 2019'],
] as const

export function Hero({ lastResult }: { lastResult: VerifyResponse | null }) {
  const view = lastResult?.ok
    ? {
        ok: true,
        issuer: lastResult.issuer?.name ?? 'Demo Authority',
        threshold_years: lastResult.threshold_years ?? 18,
      }
    : { ok: true, issuer: 'Demo Authority', threshold_years: 18 }

  return (
    <section id="top" className="mx-auto max-w-6xl px-4 pb-20 pt-14 sm:px-6 sm:pt-20">
      <div className="reveal max-w-3xl">
        <h1 className="font-deva text-[5.5rem] font-normal leading-[0.9] text-parchment sm:text-[8.5rem]" lang="sa">
          प्रमाण
        </h1>
        <p className="mt-5 text-4xl font-semibold sm:text-5xl">Prove you are old enough. Reveal nothing more.</p>
        <p className="mt-6 max-w-2xl text-lg text-lavender">
          Today a website asks for your driving licence to learn one fact: are you over 18? Pramāṇa answers that question
          with a zero-knowledge proof built in your browser. The site checks it in milliseconds and learns a single yes —
          never your birthdate, never your name.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <a href="#try" className="btn-gold">
            Prove your age in the demo
          </a>
          <a href="#demo" className="btn-quiet">
            Watch a cheater fail
          </a>
        </div>
      </div>

      <div className="mt-16 grid gap-5 lg:grid-cols-[1fr_1.15fr]" aria-label="What the website learns, compared">
        <figure className="panel reveal flex flex-col p-6" style={{ animationDelay: '150ms' }}>
          <figcaption className="text-lavender">Everything example-shop.com learns with Pramāṇa</figcaption>
          <pre className="mt-5 flex-1 overflow-x-auto rounded-lg bg-night-deep p-5 font-mono text-[0.95rem] leading-7 text-parchment">
            <span className="text-lavender">{'{'}</span>
            {'\n  '}
            <span className="text-gold-soft">"ok"</span>: <span className="text-verdigris">{String(view.ok)}</span>,
            {'\n  '}
            <span className="text-gold-soft">"issuer"</span>: "{view.issuer}",
            {'\n  '}
            <span className="text-gold-soft">"threshold_years"</span>: {view.threshold_years}
            {'\n'}
            <span className="text-lavender">{'}'}</span>
          </pre>
          <p className="mt-4 text-[0.95rem] text-lavender">
            One bit, plus which authority vouched for it. The proof it checked is about 3 KB of numbers that are
            indistinguishable from random to anyone without your secret.
          </p>
        </figure>

        <figure className="reveal rounded-xl border border-plum-line/60 p-6" style={{ animationDelay: '300ms' }}>
          <figcaption className="text-lavender">What an ID upload hands over to prove the same thing</figcaption>
          <div className="mt-5 rounded-lg bg-parchment p-5 text-night-deep shadow-[0_20px_60px_-30px_rgb(0_0_0/0.8)]">
            <div className="flex items-start justify-between gap-3 border-b border-night/15 pb-3">
              <p className="font-semibold">Driving licence</p>
              <p className="rounded bg-vermilion/15 px-2 py-0.5 text-sm font-semibold text-vermilion">Specimen</p>
            </div>
            <div className="mt-4 flex gap-5">
              <div
                aria-hidden
                className="strike-field grid h-28 w-22 shrink-0 place-items-end overflow-hidden rounded bg-night/10"
                style={{ ['--d' as string]: '900ms' }}
              >
                <svg viewBox="0 0 80 100" className="h-24 w-20 text-night/35">
                  <circle cx="40" cy="36" r="18" fill="currentColor" />
                  <path d="M6 100c4-26 18-38 34-38s30 12 34 38z" fill="currentColor" />
                </svg>
              </div>
              <dl className="grid flex-1 gap-1.5 text-[0.95rem]">
                {SPECIMEN.map(([k, v], i) => (
                  <div key={k}>
                    <dt className="text-xs text-night/60">{k}</dt>
                    <dd className="strike-field w-fit font-semibold" style={{ ['--d' as string]: `${1000 + i * 140}ms` }}>
                      {v}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
          <p className="mt-4 text-[0.95rem] text-lavender">
            A permanent, breachable copy of who you are, held by every site that asks — and a stable identifier that
            lets them link your visits. None of it is needed to answer a yes-or-no question.
          </p>
        </figure>
      </div>
    </section>
  )
}
