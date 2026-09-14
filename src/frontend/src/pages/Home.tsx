import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowRight,
  Bell,
  CheckCircle2,
  FileText,
  FilterX,
  Gauge,
  Layers,
  Moon,
  Network,
  PlugZap,
  Radar,
  ScanSearch,
  ShieldCheck,
  Sun,
  Target,
} from 'lucide-react'
import { ThreatLensLogo } from '../components/logo/ThreatLensLogo'
import { useTheme } from '../components/theme/ThemeProvider'

const navLinks = [
  { label: 'Problem', href: '#problem' },
  { label: 'Features', href: '#features' },
  { label: 'Workflow', href: '#workflow' },
  { label: 'Benefits', href: '#benefits' },
]

const features = [
  {
    icon: Layers,
    title: 'Correlated incidents',
    body: 'Group related alerts into potential incidents so analysts investigate one story, not hundreds of fragments.',
  },
  {
    icon: Gauge,
    title: 'Risk-based prioritisation',
    body: 'A single, transparent risk score ranks alerts — attention goes to what matters first, not the loudest noise.',
  },
  {
    icon: Target,
    title: 'MITRE ATT&CK context',
    body: 'See which tactics and techniques are involved, and how they fit a wider campaign.',
  },
  {
    icon: FileText,
    title: 'BLUF investigation briefs',
    body: 'Bottom line up front: what happened, why it matters, and the recommended focus — in one readable brief.',
  },
  {
    icon: FilterX,
    title: 'False-positive triage',
    body: 'Separate genuine threats from noisy false positives before anyone burns hours chasing ghosts.',
  },
  {
    icon: PlugZap,
    title: 'Multi-source ingestion',
    body: 'One consistent view across SIEM, endpoint detection, network sensors, and threat intelligence feeds.',
  },
]

const workflowSteps = [
  {
    icon: Radar,
    step: '01',
    title: 'Ingest',
    body: 'Alerts stream in from every source into a single, normalised pipeline.',
  },
  {
    icon: Network,
    step: '02',
    title: 'Correlate',
    body: 'Related alerts are linked into potential incidents based on shared indicators.',
  },
  {
    icon: Gauge,
    step: '03',
    title: 'Prioritise',
    body: 'Risk is scored and ranked so analysts always know what is urgent.',
  },
  {
    icon: ScanSearch,
    step: '04',
    title: 'Investigate',
    body: 'Evidence, timelines, and BLUF briefs guide a fast, defensible response.',
  },
]

const benefits = [
  'Cut triage time by working on correlated incidents instead of raw alert volume',
  'Reduce blind spots with MITRE ATT&CK technique and tactic context',
  'Fewer false-positive rabbit holes — see what is actually worth investigating',
  'Clear BLUF briefs that any stakeholder can act on',
  'Prioritisation by risk and severity, not by recency or racket',
]

function SampleTag() {
  return <span className="text-xs uppercase tracking-wider text-foreground-muted">Sample</span>
}

export function Home() {
  const { theme, toggle } = useTheme()
  const ThemeIcon = theme === 'dark' ? Sun : Moon

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border bg-background/90 backdrop-blur">
        <div className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4 sm:px-6">
          <a href="#top" className="rounded">
            <ThreatLensLogo size={30} withWordmark />
          </a>
          <nav className="hidden items-center gap-6 md:flex" aria-label="Landing">
            {navLinks.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="rounded text-sm font-medium text-foreground-muted transition-colors hover:text-foreground"
              >
                {link.label}
              </a>
            ))}
          </nav>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={toggle}
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-foreground-muted transition-colors hover:bg-surface-2 hover:text-foreground"
            >
              <ThemeIcon className="h-4 w-4" aria-hidden="true" />
            </button>
            <Link
              to="/login"
              className="hidden items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 sm:inline-flex"
            >
              Launch demo
              <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </Link>
          </div>
        </div>
      </header>

      <main id="top">
        {/* Hero */}
        <section className="relative overflow-hidden">
          <div className="mx-auto w-full max-w-6xl px-4 pb-20 pt-16 sm:px-6 sm:pt-24">
            <div className="mx-auto max-w-3xl text-center">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-primary/40 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                Threat intelligence correlation & alert prioritisation
              </span>
              <h1 className="mt-6 text-4xl font-bold leading-tight tracking-tight sm:text-6xl">
                See the signal.
                <br />
                <span className="text-accent">Stop the threat.</span>
              </h1>
              <p className="mx-auto mt-6 max-w-xl text-lg leading-relaxed text-foreground-muted">
                Security teams drown in alerts while the real threats hide in the noise. ThreatLens
                correlates related alerts, filters false positives, and surfaces what actually needs
                your attention — first.
              </p>
              <div className="mt-9 flex flex-col items-center justify-center gap-3 sm:flex-row">
                <Link
                  to="/login"
                  className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 sm:w-auto"
                >
                  Launch demo
                  <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </Link>
                <a
                  href="#features"
                  className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-border bg-surface px-6 py-3 text-sm font-semibold text-foreground transition-colors hover:bg-surface-2 sm:w-auto"
                >
                  Explore workflows
                </a>
              </div>
            </div>

            <DashboardSketch />
          </div>
        </section>

        {/* Problem */}
        <section id="problem" className="scroll-mt-20 border-t border-border">
          <div className="mx-auto w-full max-w-6xl px-4 py-20 sm:px-6 sm:py-24">
            <SectionHeading
              eyebrow="The problem"
              title="Alert overload hides the signal"
              description="Analysts are flooded with raw alerts. Most are noise. The genuine threats get buried — and the window to act closes."
            />
            <div className="mt-12 grid gap-6 md:grid-cols-2">
              <ProblemCard
                icon={Bell}
                stat="Thousands"
                statNote="of alerts per day in a typical SOC — illustrative"
                title="Too many alerts to read"
                body="Security operations centers collect alerts from SIEM, endpoints, and network sensors. No human can meaningfully review that volume, so important ones slip through."
              />
              <ProblemCard
                icon={AlertTriangle}
                stat="~70%"
                statNote="of alerts are false positives — illustrative"
                title="Too much noise"
                body="The majority of raw alerts are false positives or low-risk events. Real threats get lost in the flood, and investigations stall before they start."
              />
            </div>
          </div>
        </section>

        {/* Features */}
        <section id="features" className="scroll-mt-20 border-t border-border bg-surface/40">
          <div className="mx-auto w-full max-w-6xl px-4 py-20 sm:px-6 sm:py-24">
            <SectionHeading
              eyebrow="How ThreatLens helps"
              title="From alert noise to analyst clarity"
              description="Every workflow in ThreatLens is built to answer one question: what needs attention first?"
            />
            <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {features.map((feature) => (
                <article
                  key={feature.title}
                  className="rounded-xl border border-border bg-surface p-6 transition-colors hover:border-primary/50"
                >
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/15 text-primary">
                    <feature.icon className="h-5 w-5" aria-hidden="true" />
                  </div>
                  <h3 className="mt-4 text-base font-semibold">{feature.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-foreground-muted">{feature.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        {/* Workflow */}
        <section id="workflow" className="scroll-mt-20 border-t border-border">
          <div className="mx-auto w-full max-w-6xl px-4 py-20 sm:px-6 sm:py-24">
            <SectionHeading
              eyebrow="Workflow"
              title="From stream to action in four steps"
              description="A correlation pipeline that turns scattered alerts into a prioritised, investigable picture."
            />
            <ol className="mt-12 grid gap-5 md:grid-cols-2 lg:grid-cols-4">
              {workflowSteps.map((step) => (
                <li
                  key={step.step}
                  className="relative rounded-xl border border-border bg-surface p-6"
                >
                  <span className="text-xs font-semibold uppercase tracking-wider text-foreground-muted">
                    Step {step.step}
                  </span>
                  <div className="mt-3 flex h-9 w-9 items-center justify-center rounded-lg bg-accent/15 text-accent">
                    <step.icon className="h-4.5 w-4.5" aria-hidden="true" />
                  </div>
                  <h3 className="mt-3 text-base font-semibold">{step.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-foreground-muted">{step.body}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* Benefits */}
        <section id="benefits" className="scroll-mt-20 border-t border-border bg-surface/40">
          <div className="mx-auto w-full max-w-6xl px-4 py-20 sm:px-6 sm:py-24">
            <SectionHeading
              eyebrow="For security analysts"
              title="Built for the people in the trenches"
              description="ThreatLens is designed around how analysts actually work — not around chart libraries."
            />
            <ul className="mx-auto mt-12 grid max-w-3xl gap-4">
              {benefits.map((benefit) => (
                <li key={benefit} className="flex items-start gap-3">
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-safe" aria-hidden="true" />
                  <span className="text-sm leading-relaxed text-foreground-muted">{benefit}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* CTA */}
        <section className="border-t border-border">
          <div className="mx-auto w-full max-w-6xl px-4 py-20 sm:px-6">
            <div className="rounded-2xl border border-border bg-surface p-10 text-center sm:p-14">
              <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
                Ready to see the signal?
              </h2>
              <p className="mx-auto mt-4 max-w-xl text-sm leading-relaxed text-foreground-muted">
                Explore the ThreatLens demo to see correlated incidents, risk-ranked alerts, and
                BLUF briefs — powered by clearly labelled simulation data.
              </p>
              <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
                <Link
                  to="/login"
                  className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 sm:w-auto"
                >
                  Launch demo
                  <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-border">
        <div className="mx-auto w-full max-w-6xl px-4 py-12 sm:px-6">
          <div className="flex flex-col gap-10 md:flex-row md:items-start md:justify-between">
            <div className="max-w-xs">
              <ThreatLensLogo size={30} withWordmark />
              <p className="mt-3 text-sm leading-relaxed text-foreground-muted">
                See the signal. Stop the threat. Threat correlation and alert prioritisation for
                security operations.
              </p>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-foreground-muted">
                Modules
              </p>
              <ul className="mt-3 space-y-2 text-sm text-foreground-muted">
                <li>Alert intelligence</li>
                <li>Incident correlation</li>
                <li>MITRE ATT&CK explorer</li>
                <li>BLUF briefs</li>
                <li>Analytics</li>
                <li>Settings</li>
              </ul>
            </div>
          </div>
          <div className="mt-10 flex flex-col gap-3 border-t border-border pt-6 text-xs text-foreground-muted sm:flex-row sm:items-center sm:justify-between">
            <p>
              Demo interface. All data displayed is simulated and not connected to real security
              systems.
            </p>
            <p className="font-mono">ThreatLens frontend v0.1.0</p>
          </div>
        </div>
      </footer>
    </div>
  )
}

function SectionHeading({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string
  title: string
  description: string
}) {
  return (
    <div className="mx-auto max-w-2xl text-center">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-primary">{eyebrow}</p>
      <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">{title}</h2>
      <p className="mt-4 text-base leading-relaxed text-foreground-muted">{description}</p>
    </div>
  )
}

function ProblemCard({
  icon: Icon,
  stat,
  statNote,
  title,
  body,
}: {
  icon: typeof Bell
  stat: string
  statNote: string
  title: string
  body: string
}) {
  return (
    <article className="rounded-xl border border-border bg-surface p-7">
      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-high/15 text-high">
        <Icon className="h-5 w-5" aria-hidden="true" />
      </div>
      <div className="mt-5 flex items-baseline gap-2">
        <span className="text-3xl font-bold">{stat}</span>
        <SampleTag />
      </div>
      <p className="mt-1 text-xs text-foreground-muted">{statNote}</p>
      <h3 className="mt-5 text-base font-semibold">{title}</h3>
      <p className="mt-2 text-sm leading-relaxed text-foreground-muted">{body}</p>
    </article>
  )
}

function DashboardSketch() {
  const bars = [
    { label: 'Critical', width: '12%', color: 'var(--critical)' },
    { label: 'High', width: '22%', color: 'var(--high)' },
    { label: 'Medium', width: '38%', color: 'var(--medium)' },
    { label: 'Low', width: '28%', color: 'var(--low)' },
  ]
  const feed = [
    {
      dot: 'var(--critical)',
      id: 'ALERT-2041',
      title: 'Potential credential theft',
      source: 'EDR Endpoint Agent',
    },
    {
      dot: 'var(--high)',
      id: 'ALERT-2038',
      title: 'Suspicious outbound beacon',
      source: 'Network Sensor',
    },
    {
      dot: 'var(--medium)',
      id: 'ALERT-2035',
      title: 'Unusual admin login',
      source: 'SIEM',
    },
  ]

  return (
    <div className="mt-16 overflow-hidden rounded-2xl border border-border bg-surface shadow-2xl shadow-black/40">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-low/60" aria-hidden="true" />
          <span className="text-xs font-medium uppercase tracking-wider text-foreground-muted">
            Interface preview — simulated data
          </span>
        </div>
        <ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" />
      </div>

      <div className="grid gap-px bg-border sm:grid-cols-3">
        <PreviewStat label="Open alerts" value="1,284" accent="text-foreground" />
        <PreviewStat label="Critical" value="12" accent="text-critical" />
        <PreviewStat label="Correlated incidents" value="26" accent="text-accent" />
      </div>

      <div className="grid gap-6 p-6 md:grid-cols-2">
        <div>
          <p className="text-sm font-medium text-foreground-muted">Severity distribution</p>
          <div className="mt-3 flex h-4 w-full overflow-hidden rounded-full bg-surface-2" aria-hidden="true">
            {bars.map((bar) => (
              <span key={bar.label} style={{ width: bar.width, backgroundColor: bar.color }} />
            ))}
          </div>
          <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1">
            {bars.map((bar) => (
              <li key={bar.label} className="flex items-center gap-1.5 text-xs text-foreground-muted">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: bar.color }} />
                {bar.label}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <p className="text-sm font-medium text-foreground-muted">Highest-risk alerts</p>
          <ul className="mt-3 space-y-2">
            {feed.map((item) => (
              <li
                key={item.id}
                className="flex items-center gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2.5"
              >
                <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: item.dot }} aria-hidden="true" />
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{item.title}</p>
                  <p className="truncate font-mono text-xs text-foreground-muted">
                    {item.id} · {item.source}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

function PreviewStat({ label, value, accent }: { label: string; value: string; accent: string }) {
  return (
    <div className="bg-surface px-5 py-4">
      <p className="text-xs text-foreground-muted">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${accent}`}>{value}</p>
    </div>
  )
}