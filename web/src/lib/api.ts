import type { AgeProof, AppConfig, AuditEntry, ChallengeResponse, Credential, VerifyResponse } from './types'

export class ApiError extends Error {
  code: string
  status: number
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      ...init,
      headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
    })
  } catch {
    throw new ApiError(0, 'network', 'The Pramāṇa server could not be reached. Check that it is running.')
  }
  const text = await res.text()
  let body: unknown = null
  try {
    body = text ? JSON.parse(text) : null
  } catch {
    body = null
  }
  if (!res.ok) {
    const b = (body ?? {}) as { code?: string; error?: string }
    throw new ApiError(res.status, b.code ?? `http_${res.status}`, b.error ?? `Request failed with status ${res.status}`)
  }
  return body as T
}

export type VerifierKey = 'shop' | 'other'

export const api = {
  config: () => request<AppConfig>('/api/config'),
  issue: (dob: string) => request<Credential>('/api/issuer/issue', { method: 'POST', body: JSON.stringify({ dob }) }),
  challenge: (v: VerifierKey, threshold_years: number) =>
    request<ChallengeResponse>(`/api/${v}/challenge`, { method: 'POST', body: JSON.stringify({ threshold_years }) }),
  verify: (v: VerifierKey, proof: AgeProof) =>
    request<VerifyResponse>(`/api/${v}/verify`, { method: 'POST', body: JSON.stringify({ proof }) }),
  verifyRaw: (v: VerifierKey, body: string) => request<VerifyResponse>(`/api/${v}/verify`, { method: 'POST', body }),
  audit: (v: VerifierKey) => request<{ verifier_id: string; entries: AuditEntry[] }>(`/api/${v}/audit`),
}

/** Plain-language explanations for every rejection code the verifier can return. */
export const REASONS: Record<string, string> = {
  malformed: 'The proof could not be decoded.',
  unsupported_version: 'The proof uses an unknown format version.',
  nonce_mismatch: 'The proof answers a different challenge.',
  invalid_statement: 'The challenge itself was malformed.',
  untrusted_issuer: 'The birthdate was signed by an authority this site does not trust.',
  bad_signature: 'The birthdate commitment does not carry a valid issuer signature.',
  not_yet_valid: 'The challenge is not valid yet.',
  expired: 'The challenge expired before the proof arrived.',
  wrong_bit_count: 'The range proof has the wrong number of bits.',
  consistency_failed: 'The bit commitments do not add up to the committed slack Δ (§7.5).',
  fiat_shamir_check_failed:
    'A bit proof fails under the challenge the verifier recomputed from its own statement (§7.4, §7.7).',
  unknown_challenge: 'This verifier never issued that challenge nonce.',
  challenge_already_used: 'That challenge was already answered. Each proof works once.',
}
