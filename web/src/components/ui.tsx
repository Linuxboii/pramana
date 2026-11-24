import { useState, type ReactNode } from 'react'

export function Section({ id, title, intro, children }: { id: string; title: string; intro: ReactNode; children: ReactNode }) {
  return (
    <section id={id} className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
      <div className="max-w-3xl">
        <h2 className="text-3xl font-semibold sm:text-4xl">{title}</h2>
        <div className="mt-4 text-lg text-lavender prose-pramana">{intro}</div>
      </div>
      <div className="mt-10">{children}</div>
    </section>
  )
}

export type Tone = 'pass' | 'fail' | 'info' | 'wait'

const toneClass: Record<Tone, string> = {
  pass: 'border-verdigris/50 bg-verdigris/10 text-verdigris',
  fail: 'border-vermilion/50 bg-vermilion/10 text-vermilion',
  info: 'border-plum-line bg-night-deep text-lavender',
  wait: 'border-gold/40 bg-gold/10 text-gold-soft',
}

export function Pill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-sm font-semibold ${toneClass[tone]}`}>
      {tone === 'pass' && <Check />}
      {tone === 'fail' && <Cross />}
      {children}
    </span>
  )
}

export function Check({ className = 'h-3.5 w-3.5' }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={className} aria-hidden fill="none" stroke="currentColor" strokeWidth="2.2">
      <path d="M3 8.5l3.2 3L13 4.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function Cross({ className = 'h-3.5 w-3.5' }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={className} aria-hidden fill="none" stroke="currentColor" strokeWidth="2.2">
      <path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round" />
    </svg>
  )
}

export function Disclosure({ summary, children, defaultOpen = false }: { summary: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="min-w-0 rounded-lg border border-plum-line/70">
      <button
        type="button"
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left font-semibold hover:bg-plum/50"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <span>{summary}</span>
        <svg viewBox="0 0 16 16" className={`h-4 w-4 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden>
          <path d="M3 6l5 5 5-5" fill="none" stroke="currentColor" strokeWidth="2" />
        </svg>
      </button>
      {open && <div className="min-w-0 border-t border-plum-line/70 px-4 py-4">{children}</div>}
    </div>
  )
}

export function Json({ value, maxHeight = '22rem' }: { value: unknown; maxHeight?: string }) {
  return (
    <pre className="max-w-full overflow-auto rounded-lg bg-night-deep p-4 font-mono text-[0.75rem] leading-relaxed text-lavender" style={{ maxHeight }}>
      {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
    </pre>
  )
}

export interface Step {
  label: string
  tone: Tone
  detail?: ReactNode
  badge?: string
}

export function StepLog({ steps }: { steps: Step[] }) {
  if (!steps.length) return null
  return (
    <ol className="mt-6 grid gap-3" aria-live="polite">
      {steps.map((s, i) => (
        <li key={i} className="reveal rounded-lg border border-plum-line/70 bg-night-deep/60 px-4 py-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-semibold">{s.label}</span>
            <Pill tone={s.tone}>{s.badge ?? (s.tone === 'pass' ? 'Accepted' : s.tone === 'fail' ? 'Rejected' : s.tone === 'wait' ? 'Working' : 'Info')}</Pill>
          </div>
          {s.detail && <div className="mt-1.5 text-[0.95rem] text-lavender">{s.detail}</div>}
        </li>
      ))}
    </ol>
  )
}

export function Code({ children }: { children: ReactNode }) {
  return <code className="rounded bg-night-deep px-1.5 py-0.5 font-mono text-[0.85em] text-gold-soft">{children}</code>
}
