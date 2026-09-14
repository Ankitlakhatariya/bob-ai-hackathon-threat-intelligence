import { Link } from 'react-router-dom'
import { Construction } from 'lucide-react'
import { ThreatLensLogo } from '../components/logo/ThreatLensLogo'

export function UnderConstruction({ pageName }: { pageName: string }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 bg-background px-4 text-center text-foreground">
      <ThreatLensLogo size={40} withWordmark />
      <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/15 text-accent">
        <Construction className="h-6 w-6" aria-hidden="true" />
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-foreground-muted">
          Coming next
        </p>
        <h1 className="mt-2 text-2xl font-bold">{pageName}</h1>
        <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-foreground-muted">
          This module is the next build step. Navigation stays wired so links never break while the
          pages are under construction.
        </p>
      </div>
      <Link
        to="/"
        className="inline-flex items-center justify-center rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90"
      >
        Back to home
      </Link>
    </div>
  )
}