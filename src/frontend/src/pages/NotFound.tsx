import { Link } from 'react-router-dom'
import { Moon as MoonIcon, Sun as SunIcon } from 'lucide-react'
import { ThreatLensLogo } from '../components/logo/ThreatLensLogo'
import { useTheme } from '../components/theme/ThemeProvider'

export function NotFound() {
  const { theme, toggle } = useTheme()
  const ThemeIcon = theme === 'dark' ? MoonIcon : SunIcon

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="border-b border-border">
        <div className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4 sm:px-6">
          <ThreatLensLogo size={32} withWordmark />
          <button
            type="button"
            onClick={toggle}
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-foreground-muted transition-colors hover:bg-surface-2 hover:text-foreground"
          >
            <ThemeIcon className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </header>
      <main className="flex flex-1 items-center justify-center px-4 py-24 text-center">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-foreground-muted">404</p>
          <h1 className="mt-3 text-3xl font-bold">Page not found</h1>
          <p className="mx-auto mt-3 max-w-md text-sm text-foreground-muted">
            This route does not exist in the ThreatLens demo yet.
          </p>
          <Link
            to="/"
            className="mt-8 inline-flex items-center justify-center rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90"
          >
            Back to home
          </Link>
        </div>
      </main>
    </div>
  )
}