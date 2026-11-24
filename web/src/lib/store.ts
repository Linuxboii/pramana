import type { Credential } from './types'

// The credential lives only on this device (localStorage). It contains the witness
// (D, r); it is never sent to any verifier. Encryption at rest (T10) is listed as
// future work in docs/SECURITY.md.
const KEY = 'pramana.wallet.credential.v1'

export function loadCredential(): Credential | null {
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? (JSON.parse(raw) as Credential) : null
  } catch {
    return null
  }
}

export function saveCredential(c: Credential | null) {
  try {
    if (c) localStorage.setItem(KEY, JSON.stringify(c))
    else localStorage.removeItem(KEY)
  } catch {
    /* storage unavailable (private mode): the wallet still works for this session */
  }
}

export function formatDate(iso: string): string {
  const [y, m, d] = iso.split('-').map(Number)
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC',
  })
}

export function ageOn(birth: string, today: string): number {
  const [by, bm, bd] = birth.split('-').map(Number)
  const [ty, tm, td] = today.split('-').map(Number)
  let a = ty - by
  if (tm < bm || (tm === bm && td < bd)) a -= 1
  return a
}

export function todayIso(): string {
  return new Date().toISOString().slice(0, 10)
}

export function yearsAgo(years: number, monthDay = '04-12'): string {
  return `${new Date().getUTCFullYear() - years}-${monthDay}`
}

export function short(hex: string, n = 10): string {
  return hex.length > 2 * n ? `${hex.slice(0, n)}…${hex.slice(-6)}` : hex
}
