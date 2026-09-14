import { useId, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  ArrowLeft,
  Eye,
  EyeOff,
  FileText,
  Gauge,
  Layers,
  Loader2,
  Lock,
  Mail,
  Moon,
  ShieldCheck,
  Sun,
} from 'lucide-react'
import { ThreatLensLogo } from '../components/logo/ThreatLensLogo'
import { useTheme } from '../components/theme/ThemeProvider'
import { startDemoSession } from '../lib/demoSession'

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

type Status = 'idle' | 'submitting' | 'success'

interface FieldErrors {
  email?: string
  password?: string
}

export function Login() {
  const { theme, toggle } = useTheme()
  const ThemeIcon = theme === 'dark' ? Sun : Moon

  const navigate = useNavigate()
  const emailId = useId()
  const passwordId = useId()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [errors, setErrors] = useState<FieldErrors>({})
  const [status, setStatus] = useState<Status>('idle')
  const [sessionName, setSessionName] = useState('')

  function validate(): FieldErrors {
    const next: FieldErrors = {}
    if (!email.trim()) next.email = 'Enter your email address.'
    else if (!emailPattern.test(email.trim())) next.email = 'Enter a valid email address.'
    if (!password) next.password = 'Enter your password.'
    else if (password.length < 8) next.password = 'Password must be at least 8 characters.'
    return next
  }

  function simulateSignIn(displayName: string) {
    setStatus('submitting')
    setSessionName(displayName)
    window.setTimeout(() => {
      startDemoSession(displayName)
      setStatus('success')
      window.setTimeout(() => navigate('/dashboard'), 700)
    }, 900)
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (status !== 'idle') return
    const nextErrors = validate()
    setErrors(nextErrors)
    if (Object.keys(nextErrors).length > 0) return
    simulateSignIn(email.trim().split('@')[0])
  }

  function handleDemoAccess() {
    if (status !== 'idle') return
    setErrors({})
    simulateSignIn('Demo Analyst')
  }

  const panel = (
    <section className="hidden flex-col justify-between bg-surface/60 p-10 lg:flex">
      <div className="flex items-center">
        <Link to="/" className="rounded" aria-label="ThreatLens home">
          <ThreatLensLogo size={30} withWordmark />
        </Link>
      </div>

      <div>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-primary/40 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
          <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
          Simulated demo environment
        </span>
        <h1 className="mt-5 text-3xl font-bold leading-tight tracking-tight">
          See the signal.
          <br />
          <span className="text-accent">Stop the threat.</span>
        </h1>
        <p className="mt-4 max-w-sm text-sm leading-relaxed text-foreground-muted">
          Explore correlated incidents, risk-ranked alerts, and BLUF investigation briefs in the
          ThreatLens operations dashboard.
        </p>
        <ul className="mt-8 space-y-4">
          <li className="flex items-start gap-3 text-sm text-foreground-muted">
            <Layers className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
            Correlated incidents that explain why alerts belong together
          </li>
          <li className="flex items-start gap-3 text-sm text-foreground-muted">
            <Gauge className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
            Risk scored and ranked so the urgent thing is obvious
          </li>
          <li className="flex items-start gap-3 text-sm text-foreground-muted">
            <FileText className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
            Bottom-line-up-front briefs any analyst can act on
          </li>
        </ul>
      </div>

      <p className="text-xs text-foreground-muted">
        Demo interface with simulated data. Not connected to real security systems.
      </p>
    </section>
  )

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="grid min-h-screen lg:grid-cols-2">
        {panel}
        <section className="flex flex-col justify-center px-4 py-10 sm:px-8 lg:px-14">
          <div className="mx-auto w-full max-w-md">
            <div className="mb-8 flex items-center justify-between lg:hidden">
              <Link to="/" className="rounded" aria-label="ThreatLens home">
                <ThreatLensLogo size={28} withWordmark />
              </Link>
              <button
                type="button"
                onClick={toggle}
                aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
                className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-foreground-muted transition-colors hover:bg-surface-2 hover:text-foreground"
              >
                <ThemeIcon className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>

            <Link
              to="/"
              className="mb-4 inline-flex items-center gap-1.5 text-sm text-foreground-muted transition-colors hover:text-foreground lg:mb-6"
            >
              <ArrowLeft className="h-4 w-4" aria-hidden="true" />
              Back to home
            </Link>

            <h2 className="text-2xl font-bold tracking-tight">Sign in to the demo</h2>
            <p className="mt-2 text-sm leading-relaxed text-foreground-muted">
              Authentication is simulated. Use any email and password, or open the demo session
              directly.
            </p>

            <form onSubmit={handleSubmit} noValidate className="mt-8 space-y-5">
              <div>
                <label htmlFor={emailId} className="block text-sm font-medium">
                  Email address
                </label>
                <div className="relative mt-1.5">
                  <Mail
                    className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground-muted"
                    aria-hidden="true"
                  />
                  <input
                    id={emailId}
                    type="email"
                    autoComplete="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    aria-invalid={Boolean(errors.email)}
                    aria-describedby={errors.email ? `${emailId}-error` : undefined}
                    placeholder="analyst@example.com"
                    className={`w-full rounded-lg border bg-surface py-2.5 pl-9 pr-3 text-sm transition-colors focus:border-primary focus:outline-none ${
                      errors.email ? 'border-critical' : 'border-border'
                    }`}
                  />
                </div>
                {errors.email && (
                  <p id={`${emailId}-error`} className="mt-1.5 text-xs text-critical" role="alert">
                    {errors.email}
                  </p>
                )}
              </div>

              <div>
                <label htmlFor={passwordId} className="block text-sm font-medium">
                  Password
                </label>
                <div className="relative mt-1.5">
                  <Lock
                    className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground-muted"
                    aria-hidden="true"
                  />
                  <input
                    id={passwordId}
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    aria-invalid={Boolean(errors.password)}
                    aria-describedby={errors.password ? `${passwordId}-error` : undefined}
                    placeholder="At least 8 characters"
                    className={`w-full rounded-lg border bg-surface py-2.5 pl-9 pr-10 text-sm transition-colors focus:border-primary focus:outline-none ${
                      errors.password ? 'border-critical' : 'border-border'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((current) => !current)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-1 text-foreground-muted transition-colors hover:text-foreground"
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" aria-hidden="true" />
                    ) : (
                      <Eye className="h-4 w-4" aria-hidden="true" />
                    )}
                  </button>
                </div>
                {errors.password && (
                  <p id={`${passwordId}-error`} className="mt-1.5 text-xs text-critical" role="alert">
                    {errors.password}
                  </p>
                )}
              </div>

              <button
                type="submit"
                disabled={status !== 'idle'}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {status === 'submitting' ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    Signing in…
                  </>
                ) : (
                  'Sign in'
                )}
              </button>

              <div className="flex items-center gap-3">
                <span className="h-px flex-1 bg-border" aria-hidden="true" />
                <span className="text-xs uppercase tracking-wider text-foreground-muted">or</span>
                <span className="h-px flex-1 bg-border" aria-hidden="true" />
              </div>

              <button
                type="button"
                onClick={handleDemoAccess}
                disabled={status !== 'idle'}
                className="flex w-full items-center justify-center gap-2 rounded-lg border border-border bg-surface px-4 py-2.5 text-sm font-semibold text-foreground transition-colors hover:bg-surface-2 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" />
                Use demo access (simulated)
              </button>
            </form>

            <div aria-live="polite" className="mt-6">
              {status === 'success' && (
                <div className="rounded-lg border border-safe/40 bg-safe/10 p-3 text-sm text-safe">
                  Demo session started as {sessionName}. Opening the dashboard…
                </div>
              )}
            </div>

            <p className="mt-6 text-xs leading-relaxed text-foreground-muted">
              Demo only: no real credentials are transmitted or stored, and no authentication
              service is contacted. Client-side validation is not a security boundary.
            </p>
          </div>
        </section>
      </div>
    </div>
  )
}