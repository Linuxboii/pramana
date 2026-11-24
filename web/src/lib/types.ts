// Wire types mirrored from pramana-core (FR-8). Cryptographic fields are lowercase hex.

export interface Credential {
  v: number
  kind: 'pramana-age-credential'
  params: string
  issuer_name: string
  issuer_pk: string
  c_d: string
  sig: string
  d: number
  r: string
  issued_at: number
}

export interface Statement {
  v: number
  threshold_years: number
  today: string
  nonce: string
  verifier_id: string
  issued_at: number
  expires_at: number
}

export interface BitProof {
  c: string
  t0: string
  t1: string
  e0: string
  z0: string
  z1: string
}

export interface AgeProof {
  v: number
  issuer_pk: string
  c_d: string
  sig: string
  nonce: string
  bits: BitProof[]
}

export interface IssuerPublicKey {
  name: string
  public_key: string
}

export interface VerifyResponse {
  ok: boolean
  issuer: IssuerPublicKey | null
  checked_at: number
  threshold_years: number | null
  reason: string | null
  detail: string | null
}

export interface ChallengeResponse {
  statement: Statement
  nonce: string
  verifier_id: string
  expires_at: number
}

export interface AppConfig {
  suite: string
  issuer: { name: string; public_key: string }
  verifiers: Record<'shop' | 'other', { id: string; base: string }>
  trusted_issuers: IssuerPublicKey[]
  challenge_ttl_secs: number
  thresholds: number[]
}

export interface AuditEntry {
  timestamp: number
  issuer_pk: string | null
  result: boolean
  reason: string | null
}

export interface Inspection {
  cutoff_date: string
  d_star: number
  c_delta: string
  challenge: string | null
  signature_ok: boolean
  consistency_ok: boolean
  bits_ok: boolean[]
  cbor_bytes: number
  json_bytes: number
}

export interface InteractiveTranscript {
  challenge: string
  bits: BitProof[]
}

export interface ZkSamples {
  real: number[]
  simulated: number[]
  transcripts: number
  chi2_real: number
  chi2_simulated: number
}

export type CheatStrategy = 'wrap_around' | 'fake_digit' | 'swap_commitment' | 'rogue_issuer' | 'tamper_bytes'
