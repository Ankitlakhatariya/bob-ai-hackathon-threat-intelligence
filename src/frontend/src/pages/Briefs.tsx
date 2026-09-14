import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, Check, ClipboardList, Copy, FileText, Printer, RotateCw, ShieldAlert } from 'lucide-react'
import type { Severity } from '../types/alert'
import type { Incident } from '../types/incident'
import { mockBriefs } from '../data/mockBriefs'
import { useAlerts } from '../hooks/useAlerts'
import { fetchIncidents } from '../services/mockApi'
import { SeverityBadge } from '../components/severity/SeverityBadge'

interface Priority {
  level: string
  label: string
}

const priorityOf: Record<Severity, Priority> = {
  critical: { level: 'P1', label: 'Critical — act immediately' },
  high: { level: 'P2', label: 'High — investigate today' },
  medium: { level: 'P3', label: 'Medium — priority review' },
  low: { level: 'P4', label: 'Low — routine review' },
}

const priorityOrder: Record<string, number> = { P1: 0, P2: 1, P3: 2, P4: 3 }

function formatTime(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function Briefs() {
  const { alerts, error, refetch } = useAlerts()
  const [incidents, setIncidents] = useState<Incident[] | null>(null)
  const [incidentError, setIncidentError] = useState(false)
  const [incidentAttempt, setIncidentAttempt] = useState(0)

  useEffect(() => {
    let active = true
    setIncidentError(false)
    fetchIncidents()
      .then((data) => {
        if (active) setIncidents(data)
      })
      .catch(() => {
        if (active) setIncidentError(true)
      })
    return () => {
      active = false
    }
  }, [incidentAttempt])

  const sorted = useMemo(() => {
    if (!incidents) return []
    return [...incidents].sort((a, b) => {
      const pa = priorityOrder[priorityOf[a.severity].level]
      const pb = priorityOrder[priorityOf[b.severity].level]
      return pa - pb || new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
    })
  }, [incidents])

  const dataReady = alerts !== null && incidents !== null
  const hasError = error !== null || incidentError

  function refetchAll() {
    refetch()
    setIncidentAttempt((current) => current + 1)
  }

  return (
    <div className="mx-auto max-w-6xl">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight">BLUF investigation briefs</h1>
          <p className="mt-1 text-sm text-foreground-muted">
            Bottom Line Up Front summaries. Each brief is a demo example until the AI service
            generates real ones.
          </p>
        </div>
        <button
          type="button"
          onClick={() => window.print()}
          className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-2 text-sm font-semibold text-foreground transition-colors hover:bg-surface-2 print:hidden"
        >
          <Printer className="h-4 w-4" aria-hidden="true" />
          Print / save PDF
        </button>
      </div>

      {hasError ? (
        <div
          role="alert"
          className="mt-6 flex flex-col items-start gap-3 rounded-xl border border-critical/40 bg-critical/10 p-6"
        >
          <div className="flex items-center gap-2 text-critical">
            <ShieldAlert className="h-5 w-5" aria-hidden="true" />
            <span className="text-sm font-semibold">Could not load demo briefs</span>
          </div>
          <p className="text-sm text-foreground-muted">
            The sample incidents or alerts failed to load (simulated failure).
          </p>
          <button
            type="button"
            onClick={refetchAll}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:bg-surface-2"
          >
            <RotateCw className="h-4 w-4" aria-hidden="true" />
            Retry
          </button>
        </div>
      ) : !dataReady ? (
        <BriefSkeleton />
      ) : sorted.length === 0 ? (
        <div className="mt-6 flex flex-col items-center gap-3 rounded-xl border border-border bg-surface px-5 py-16 text-center">
          <FileText className="h-8 w-8 text-foreground-muted" aria-hidden="true" />
          <p className="text-sm font-medium">No briefs available</p>
          <p className="max-w-sm text-sm text-foreground-muted">
            Briefs are generated from correlated incidents. There are none in the demo data yet.
          </p>
        </div>
      ) : (
        <div className="mt-6 space-y-6">
          {sorted.map((incident) => (
            <BriefCard key={incident.id} incident={incident} />
          ))}
          <p className="text-center text-xs text-foreground-muted">
            All briefs are simulated demo content — no real security investigation was performed.
          </p>
        </div>
      )}
    </div>
  )
}

function BriefCard({ incident }: { incident: Incident }) {
  const { alerts } = useAlerts()
  const brief = mockBriefs[incident.id]
  const [copied, setCopied] = useState(false)
  const relatedAlerts = useMemo(
    () =>
      (alerts ?? [])
        .filter((alert) => incident.alertIds.includes(alert.id))
        .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()),
    [alerts, incident.alertIds],
  )

  const timeline = useMemo(() => {
    const events = [
      { time: incident.openedAt, label: 'Incident opened' },
      ...relatedAlerts.map((alert) => ({
        time: alert.timestamp,
        label: `Alert ${alert.id} correlated into the incident`,
      })),
      { time: incident.updatedAt, label: 'Last correlation activity' },
    ]
    return events.sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime())
  }, [incident, relatedAlerts])

  const priority = priorityOf[incident.severity]

  const evidence =
    brief?.keyEvidence ?? relatedAlerts.map((alert) => `${alert.id} — ${alert.title}`)

  async function copyBrief() {
    const text = [
      `BLUF brief — ${incident.id}`,
      `${incident.title}`,
      `Priority: ${priority.level} — ${priority.label}`,
      '',
      `Bottom line: ${brief?.bottomLine ?? incident.summary}`,
      `Impact: ${brief?.impact ?? 'See incident summary (demo).'}`,
      '',
      'Key evidence:',
      ...evidence.map((item) => `- ${item}`),
      '',
      `Recommended investigation focus: ${brief?.recommendedFocus ?? 'Open the incident view and review the related sample alerts.'}`,
      `Related alerts: ${relatedAlerts.map((alert) => alert.id).join(', ') || 'none'}`,
      '',
      'Demo brief — simulated data. No real security investigation was performed.',
    ].join('\n')

    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      // clipboard unavailable — silent for demo
    }
  }

  return (
    <article className="overflow-hidden rounded-xl border border-border bg-surface print:break-inside-avoid">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-surface-2/40 px-5 py-4 print:bg-transparent">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-foreground-muted">{incident.id}</span>
          <span className="rounded-full border border-critical/40 bg-critical/15 px-2.5 py-0.5 text-xs font-bold text-critical">
            {priority.level}
          </span>
          <SeverityBadge severity={incident.severity} />
        </div>
        <div className="flex items-center gap-2 print:hidden">
          <button
            type="button"
            onClick={copyBrief}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-foreground transition-colors hover:bg-surface-2"
          >
            {copied ? (
              <Check className="h-3.5 w-3.5 text-safe" aria-hidden="true" />
            ) : (
              <Copy className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            {copied ? 'Copied' : 'Copy summary'}
          </button>
          <Link
            to="/incidents"
            className="inline-flex items-center rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-foreground transition-colors hover:bg-surface-2"
          >
            Incident view
          </Link>
        </div>
      </div>

      <div className="px-5 py-5 sm:px-6">
        <div className="flex items-center gap-2 text-accent">
          <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-accent">
            BLUF
          </span>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
            Bottom Line Up Front
          </p>
        </div>
        <h2 className="mt-2 text-lg font-semibold tracking-tight">{incident.title}</h2>
        <p className="mt-2 text-sm font-medium leading-relaxed">{brief?.bottomLine ?? incident.summary}</p>

        <div className="mt-6 grid gap-5 lg:grid-cols-3">
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground-muted">
              Threat impact
            </h3>
            <p className="mt-2 text-sm leading-relaxed text-foreground-muted">
              {brief?.impact ?? 'Impact details are part of the incident summary (demo).'}
            </p>
          </section>

          <section>
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-foreground-muted">
              <ClipboardList className="h-3.5 w-3.5" aria-hidden="true" />
              Key evidence
            </h3>
            <ul className="mt-2 space-y-1.5">
              {evidence.map((item) => (
                <li key={item} className="flex items-start gap-1.5 text-sm leading-relaxed text-foreground-muted">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" aria-hidden="true" />
                  {item}
                </li>
              ))}
            </ul>
          </section>

          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground-muted">
              Recommended investigation focus
            </h3>
            <p className="mt-2 text-sm leading-relaxed text-foreground-muted">
              {brief?.recommendedFocus ??
                'Open the incident view and review the related sample alerts (demo guidance).'}
            </p>

            <div className="mt-4">
              <p className="text-xs font-medium text-foreground-muted">Priority</p>
              <p className="mt-1 text-sm font-semibold">
                {priority.level} · {priority.label}
              </p>
            </div>
          </section>
        </div>

        <div className="mt-6 grid gap-5 border-t border-border pt-5 lg:grid-cols-2">
          <section>
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-foreground-muted">
              <Activity className="h-3.5 w-3.5" aria-hidden="true" />
              Incident timeline
            </h3>
            <ol className="mt-3 space-y-0">
              {timeline.map((event, index) => (
                <li key={`${event.time}-${index}`} className="relative flex gap-3 pb-4 last:pb-0">
                  {index < timeline.length - 1 && (
                    <span className="absolute left-[5px] top-4 h-full w-px bg-border" aria-hidden="true" />
                  )}
                  <span
                    className="mt-1 h-2.5 w-2.5 shrink-0 rounded-full bg-primary"
                    style={{ opacity: index === timeline.length - 1 ? 0.45 : 1 }}
                    aria-hidden="true"
                  />
                  <div>
                    <p className="text-sm">{event.label}</p>
                    <p className="mt-0.5 text-xs text-foreground-muted">{formatTime(event.time)}</p>
                  </div>
                </li>
              ))}
            </ol>
          </section>

          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground-muted">
              Related alerts
            </h3>
            {relatedAlerts.length === 0 ? (
              <p className="mt-3 text-sm text-foreground-muted">No related sample alerts.</p>
            ) : (
              <ul className="mt-3 space-y-2">
                {relatedAlerts.map((alert) => (
                  <li key={alert.id}>
                    <Link
                      to={`/alerts/${alert.id}`}
                      className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2.5 transition-colors hover:border-primary/50"
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">{alert.title}</span>
                        <span className="font-mono text-xs text-foreground-muted">{alert.id}</span>
                      </span>
                      <SeverityBadge severity={alert.severity} />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </article>
  )
}

function BriefSkeleton() {
  return (
    <div className="mt-6 animate-pulse space-y-6" aria-label="Loading briefs">
      {[0, 1].map((item) => (
        <div key={item} className="h-72 rounded-xl border border-border bg-surface" />
      ))}
    </div>
  )
}