import { api } from './api'
import { yearsAgo } from './store'
import type { Credential } from './types'

/* Credentials used by the demonstration acts are issued once per page load and kept
   in memory, independent of the wallet in "Try it". The teenager is always 14 years
   old relative to today, so the demo keeps working as time passes. */
const creds = new Map<string, Promise<Credential>>()

export function demoCredential(who: 'aarav' | 'teen'): Promise<Credential> {
  const dob = who === 'aarav' ? '2001-04-12' : yearsAgo(14)
  if (!creds.has(dob)) {
    const p = api.issue(dob)
    p.catch(() => creds.delete(dob))
    creds.set(dob, p)
  }
  return creds.get(dob)!
}
