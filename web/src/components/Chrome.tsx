export function Header() {
  return (
    <header className="sticky top-0 z-40 border-b border-plum-line/60 bg-night/85 backdrop-blur">
      <nav className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3 sm:px-6" aria-label="Main">
        <a href="#top" className="flex items-baseline gap-2.5">
          <span className="font-deva text-2xl leading-none text-gold" lang="sa">
            प्रमाण
          </span>
          <span className="font-semibold tracking-wide">Pramāṇa</span>
        </a>
        <ul className="flex gap-1 text-[0.95rem] sm:gap-3">
          <li>
            <a className="rounded-md px-2 py-1 text-lavender hover:text-parchment" href="#try">
              Try it
            </a>
          </li>
          <li>
            <a className="rounded-md px-2 py-1 text-lavender hover:text-parchment" href="#demo">
              Demonstration
            </a>
          </li>
          <li className="hidden sm:block">
            <a className="rounded-md px-2 py-1 text-lavender hover:text-parchment" href="#how">
              How it works
            </a>
          </li>
        </ul>
      </nav>
    </header>
  )
}

export function Footer({ suite }: { suite?: string }) {
  return (
    <footer className="mt-24 border-t border-plum-line/60">
      <div className="mx-auto grid max-w-6xl gap-6 px-4 py-10 text-[0.95rem] text-lavender sm:grid-cols-2 sm:px-6">
        <div>
          <p>
            <span className="font-deva text-gold" lang="sa">
              गूढप्रमाण
            </span>{' '}
            Gūḍhapramāṇa, concealed proof. A reference implementation of a zero-knowledge age proof.
          </p>
          <p className="mt-2">
            The issuer here is a mock authority with a self-generated key. This is a portfolio project, not a certified
            identity product.
          </p>
        </div>
        <div className="sm:text-right">
          <p>Protocol suite</p>
          <p className="hex">{suite ?? 'gudhapramana/v1'}</p>
        </div>
      </div>
    </footer>
  )
}
