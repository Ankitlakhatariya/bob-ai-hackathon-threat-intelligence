import { Moon, ShieldCheck, Sun } from 'lucide-react'
import { ThreatLensLogo } from '../components/logo/ThreatLensLogo'
import { useTheme } from '../components/theme/ThemeProvider'

const plannedModules = [
  'Alert Intelligence',
  'Threat Correlation',
  'MITRE ATT&CK',
  'BLUF Briefs',
  'Analytics',
]

export function Home() {
  const { theme, toggle } = useTheme()
  const ThemeIcon = theme === 'dark' ? Sun : Moon

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="border-b border-border">
        <div className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4 sm:px-6">
          <ThreatLensLogo size={32} withWordmark />
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-primary/40 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
              <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
              Demo UI
            </span>
            <button
              type="button"
              onClick={toggle}
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-foreground-muted transition-colors hover:bg-surface-2 hover:text-foreground"
            >
              <ThemeIcon className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>
      </header>

      <main className="flex flex-1 items-center justify-center px-4 py-24 sm:px-6">
        <div className="mx-auto w-full max-w-3xl text-center">
          <ThreatLensLogo className="mx-auto" size={72} />
          <h1 className="mt-8 text-4xl font-bold tracking-tight sm:text-5xl">ThreatLens</h1>
          <p className="mt-3 text-lg font-medium text-accent">See the signal. Stop the threat.</p>
          <p className="mx-auto mt-6 max-w-xl text-sm leading-relaxed text-foreground-muted">
            Threat correlation and alert prioritisation assistant for the D2 problem statement.
            This screen is the frontend foundation — product pages are built next.
          </p>
          <ul className="mt-8 flex flex-wrap items-center justify-center gap-2">
            {plannedModules.map((module) => (
              <li
                key={module}
                className="rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-foreground-muted"
              >
                {module}
              </li>
            ))}
          </ul>
        </div>
      </main>

      <footer className="border-t border-border py-6 text-center text-xs text-foreground-muted">
        ThreatLens · Frontend foundation — all data displayed is simulated demo data
      </footer>
    </div>
  )
}