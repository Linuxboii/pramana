import { useEffect, useState } from 'react'
import { api } from './lib/api'
import { loadCredential, saveCredential } from './lib/store'
import type { AppConfig, Credential, VerifyResponse } from './lib/types'
import { loadWallet } from './lib/wallet'
import { Hero } from './components/Hero'
import { TryIt } from './components/TryIt'
import { Demonstration } from './components/Demonstration'
import { HowItWorks } from './components/HowItWorks'
import { Footer, Header } from './components/Chrome'

export default function App() {
  const [config, setConfig] = useState<AppConfig | null>(null)
  const [bootError, setBootError] = useState<string | null>(null)
  const [walletReady, setWalletReady] = useState(false)
  const [credential, setCredentialState] = useState<Credential | null>(() => loadCredential())
  const [lastResult, setLastResult] = useState<VerifyResponse | null>(null)

  useEffect(() => {
    api
      .config()
      .then(setConfig)
      .catch((e: Error) => setBootError(e.message))
    loadWallet()
      .then(() => setWalletReady(true))
      .catch((e: Error) => setBootError(`The wallet's WebAssembly module failed to load: ${e.message}`))
  }, [])

  const setCredential = (c: Credential | null) => {
    saveCredential(c)
    setCredentialState(c)
  }

  return (
    <>
      <a href="#try" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 btn-gold">
        Skip to the live demo
      </a>
      <Header />
      <main>
        <Hero lastResult={lastResult} />
        {bootError && (
          <div role="alert" className="mx-auto mb-10 max-w-3xl rounded-xl border border-vermilion/60 bg-vermilion/10 px-5 py-4">
            <p className="font-semibold">The demo can't start.</p>
            <p className="text-lavender">{bootError}</p>
          </div>
        )}
        {config && walletReady ? (
          <>
            <TryIt config={config} credential={credential} setCredential={setCredential} onResult={setLastResult} />
            <Demonstration config={config} />
          </>
        ) : (
          !bootError && (
            <p className="py-20 text-center text-lavender" aria-live="polite">
              Loading the wallet…
            </p>
          )
        )}
        <HowItWorks />
      </main>
      <Footer suite={config?.suite} />
    </>
  )
}
