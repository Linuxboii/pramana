// Bridge to the WebAssembly build of pramana-core. Proofs are generated here, in the
// browser; the witness (D, r) never leaves this tab.
import init, * as w from '../wasm/pramana.js'
import type {
  AgeProof,
  CheatStrategy,
  Credential,
  Inspection,
  InteractiveTranscript,
  IssuerPublicKey,
  Statement,
  ZkSamples,
} from './types'

let ready: Promise<void> | null = null

export function loadWallet(): Promise<void> {
  ready ??= init().then(() => undefined)
  return ready
}

export class WalletError extends Error {
  code: string
  data: Record<string, unknown>
  constructor(data: Record<string, unknown>) {
    super(String(data.message ?? data.code ?? 'wallet error'))
    this.code = String(data.code ?? 'error')
    this.data = data
  }
}

function call<T>(f: () => string): T {
  try {
    return JSON.parse(f()) as T
  } catch (e) {
    if (typeof e === 'string') {
      let data: Record<string, unknown>
      try {
        data = JSON.parse(e)
      } catch {
        data = { code: 'error', message: e }
      }
      throw new WalletError(data)
    }
    throw e
  }
}

const j = JSON.stringify

export const wallet = {
  params: () => call<{ suite: string; G: string; H: string; n_bits: number; H_seed: string }>(() => w.params_info()),
  checkCredential: (c: Credential) =>
    call<{ ok: boolean; issuer_name: string; issuer_pk: string; birthdate: string; issued_at: number; c_d: string }>(
      () => w.credential_check(j(c)),
    ),
  prove: (c: Credential, st: Statement) => call<AgeProof>(() => w.prove(j(c), j(st))),
  cheat: (c: Credential, st: Statement, s: CheatStrategy) => call<AgeProof>(() => w.cheat(j(c), j(st), s)),
  verifyLocal: (pf: AgeProof, st: Statement, trusted: IssuerPublicKey[]) =>
    call<{ ok: boolean; reason?: string; detail?: string }>(() =>
      w.verify_local(j(pf), j(st), j(trusted), Math.floor(Date.now() / 1000)),
    ),
  inspect: (pf: AgeProof, st: Statement) => call<Inspection>(() => w.inspect(j(pf), j(st))),
  cborHex: (pf: AgeProof): string => {
    try {
      return w.proof_to_cbor_hex(j(pf))
    } catch {
      return ''
    }
  },
  simulate: (c_d: string, st: Statement) => call<InteractiveTranscript>(() => w.simulate(c_d, j(st))),
  realInteractive: (c: Credential, st: Statement) => call<InteractiveTranscript>(() => w.real_interactive(j(c), j(st))),
  checkInteractive: (c_d: string, st: Statement, tr: InteractiveTranscript) =>
    call<{ ok: boolean; reason?: string }>(() => w.check_interactive(c_d, j(st), j(tr))),
  zkSamples: (c: Credential, st: Statement, count: number) => call<ZkSamples>(() => w.zk_samples(j(c), j(st), count)),
}
