import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  Activity,
  ArrowLeft,
  Check,
  CheckCircle2,
  ClipboardList,
  Copy,
  FileSearch,
  GitBranch,
  Network,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { getAlert, getRelatedAlerts } from '../services/apiClient'

import { SeverityBadge } from '../components/severity/SeverityBadge'
import { StatusBadge } from '../components/status/StatusBadge'
import type { Alert } from '../types/alert'

const riskTone = {
  low: 'var(--low)',
  medium: 'var(--medium)',
  high: 'var(--high)',
  critical: 'var(--critical)',
}

const nextSteps = [
  'Confirm the affected hosts and user accounts from the evidence below',
  'Compare the sample indicators against the threat intelligence feed',
  'Review the correlated incident for other related sample alerts',
  'Record findings in analyst notes and update the investigation status',
  'Escalate to the wider team only if the pattern repeats (demo guidance)',
]

function addMinutes(iso: string, minutes: number) {
  return new Date(new Date(iso).getTime() + minutes * 60_000).toISOString()
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

interface TimelineEvent {
  time: string
  label: string
  tone: 'primary' | 'accent' | 'neutral'
}

function buildTimeline(alert: Alert): TimelineEvent[] {
  const events: TimelineEvent[] = [
    { time: alert.timestamp, label: `Alert detected by ${alert.sourceLabel}`, tone: 'primary' },
    { time: addMinutes(alert.timestamp, 4), label: `Risk score computed (${alert.riskScore}/100)`, tone: 'neutral' },
  ]
  if (alert.relatedIncidentId) {
    events.push({
      time: addMinutes(alert.timestamp, 12),
      label: `Correlated into incident ${alert.relatedIncidentId}`,
      tone: 'accent',
    })
  }
  if (alert.status === 'investigating') {
    events.push({ time: addMinutes(alert.timestamp, 25), label: 'Investigation started (sample)', tone: 'neutral' })
  }
  if (alert.status === 'resolved') {
    events.push({ time: addMinutes(alert.timestamp, 60), label: 'Marked resolved (sample state)', tone: 'neutral' })
  }
  if (alert.status === 'false-positive') {
    events.push({
      time: addMinutes(alert.timestamp, 45),
      label: 'Reviewed and marked false positive (sample state)',
      tone: 'neutral',
    })
  }
  return events.sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime())
}

export function AlertDetail() {
  const { alertId } = useParams<{ alertId: string }>()
  const [alert, setAlert] = useState<any>(null)
  const [related, setRelated] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchAlertDetail = async () => {
    if (!alertId) return
    try {
      setLoading(true)
      const data = await getAlert(alertId)
      setAlert(data)
      try {
        const relatedData = await getRelatedAlerts(alertId)
        setRelated(relatedData.map((item: any) => item.relatedAlert).filter(Boolean))
      } catch {
        setRelated([])
      }
      setError(null)
    } catch (err: any) {
      setError(err.message || 'Could not load alert details')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlertDetail()
  }, [alertId])

  const timeline = useMemo(() => (alert ? buildTimeline(alert) : []), [alert])

  const notesKey = `threatlens-note-${alertId}`
  const [notes, setNotes] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    let initial = ''
    try {
      initial = localStorage.getItem(notesKey) ?? ''
    } catch {
      // no-op
    }
    setNotes(initial)
    setSaved(false)
  }, [notesKey])

  function saveNotes() {
    try {
      localStorage.setItem(notesKey, notes)
    } catch {
      // no-op
    }
    setSaved(true)
    window.setTimeout(() => setSaved(false), 1800)
  }

  if (loading || alert === null) {
    return <AlertDetailSkeleton />
  }

  if (error) {
    return (
      <div role="alert" className="flex flex-col items-start gap-3 rounded-xl border border-critical/40 bg-critical/10 p-6">
        <div className="flex items-center gap-2 text-critical">
          <ShieldAlert className="h-5 w-5" aria-hidden="true" />
          <span className="text-sm font-semibold">Could not load this alert</span>
        </div>
        <p className="text-sm text-foreground-muted">{error}</p>
        <button
          type="button"
          onClick={fetchAlertDetail}
          className="inline-flex items-center rounded-lg border border-border bg-surface px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:bg-surface-2"
        >
          Retry
        </button>
      </div>
    )
  }

  if (!alert) {
    return (
      <div className="flex flex-col items-center gap-4 rounded-xl border border-border bg-surface py-20 text-center">
        <FileSearch className="h-10 w-10 text-foreground-muted" aria-hidden="true" />
        <h1 className="text-xl font-bold">Alert not found</h1>
        <p className="max-w-sm text-sm text-foreground-muted">
          No sample alert matches <span className="font-mono">{alertId}</span>. It may not exist in
          the demo dataset.
        </p>
        <Link
          to="/alerts"
          className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          Back to alerts
        </Link>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-6xl">
      <Link
        to="/alerts"
        className="inline-flex items-center gap-1.5 text-sm text-foreground-muted transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden="true" />
        Back to alerts
      </Link>

      <div className="mt-4 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-bold tracking-tight sm:text-2xl">{alert.title}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-foreground-muted">{alert.id}</span>
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
          </div>
        </div>
        <span className="rounded-full border border-primary/40 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
          Sample record · no real investigation performed
        </span>
      </div>

      <div className="mt-6 grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <section className="rounded-xl border border-border bg-surface p-5">
            <h2 className="text-sm font-semibold">Summary</h2>
            <p className="mt-2 text-sm leading-relaxed text-foreground-muted">{alert.description}</p>
            <dl className="mt-5 grid gap-4 sm:grid-cols-2">
              <DetailItem label="Source" value={alert.sourceLabel} mono={false} />
              <DetailItem label="Detected" value={formatTime(alert.timestamp)} mono={false} />
              <DetailItem label="Alert ID" value={alert.id} mono />
              <DetailItem label="Risk score" value={`${alert.risk_score || alert.riskScore} / 100`} mono />
            </dl>
            <div className="mt-4">
              <p className="text-xs font-medium text-foreground-muted">Risk score</p>
              <div className="mt-1.5 flex items-center gap-3">
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-2">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${alert.risk_score || alert.riskScore}%`,
                      backgroundColor: riskTone[alert.severity as keyof typeof riskTone] || 'var(--medium)',
                    }}
                  />
                </div>
                <span className="font-mono text-sm font-semibold">{alert.risk_score || alert.riskScore}</span>
              </div>
            </div>
          </section>

          <section className="rounded-xl border border-border bg-surface p-5">
            <div className="flex items-center gap-2">
              <ClipboardList className="h-4 w-4 text-primary" aria-hidden="true" />
              <h2 className="text-sm font-semibold">Evidence</h2>
              <span className="rounded-full bg-surface-2 px-2 py-0.5 text-xs text-foreground-muted">
                sample indicators
              </span>
            </div>
            <ul className="mt-4 space-y-2">
              {alert.indicators && alert.indicators.map((indicator: string) => (
                <EvidenceRow key={indicator} value={indicator} />
              ))}
            </ul>
            <p className="mt-3 text-xs text-foreground-muted">
              Reserved example values only. Copying is for demo convenience, not real reference.
            </p>
          </section>

          <section className="rounded-xl border border-border bg-surface p-5">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" aria-hidden="true" />
              <h2 className="text-sm font-semibold">Timeline</h2>
            </div>
            <ol className="mt-4 space-y-0">
              {timeline.map((event, index) => (
                <li key={`${event.time}-${index}`} className="relative flex gap-3 pb-5 last:pb-0">
                  {index < timeline.length - 1 && (
                    <span
                      className="absolute left-[5px] top-4 h-full w-px bg-border"
                      aria-hidden="true"
                    />
                  )}
                  <span
                    className="mt-1 h-2.5 w-2.5 shrink-0 rounded-full"
                    style={{
                      backgroundColor:
                        event.tone === 'accent'
                          ? 'var(--accent)'
                          : event.tone === 'primary'
                            ? 'var(--primary)'
                            : 'var(--foreground-muted)',
                    }}
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
        </div>

        <div className="space-y-5">
          {alert.related_threat_id || alert.relatedIncidentId ? (
            <section className="rounded-xl border border-border bg-surface p-5">
              <div className="flex items-center gap-2">
                <GitBranch className="h-4 w-4 text-accent" aria-hidden="true" />
                <h2 className="text-sm font-semibold">Correlation</h2>
              </div>
              <p className="mt-3 text-sm text-foreground-muted">
                Correlated into{' '}
                <span className="font-semibold text-foreground">{alert.related_threat_id || alert.relatedIncidentId}</span>.
              </p>
              <p className="mt-2 text-sm leading-relaxed text-foreground-muted">
                The correlation engine grouped this alert with others based on shared entities.
              </p>
              <div className="mt-4">
                <Link
                  to="/incidents"
                  className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface-2 px-3 py-1.5 text-xs font-semibold text-foreground transition-colors hover:bg-surface"
                >
                  <Network className="h-3.5 w-3.5" aria-hidden="true" />
                  Open incident view
                </Link>
              </div>
            </section>
          ) : (
            <section className="rounded-xl border border-border bg-surface p-5">
              <h2 className="text-sm font-semibold">Correlation</h2>
              <p className="mt-3 text-sm leading-relaxed text-foreground-muted">
                This alert is not currently correlated into any incident.
              </p>
            </section>
          )}

          <section className="rounded-xl border border-border bg-surface p-5">
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-primary" aria-hidden="true" />
              <h2 className="text-sm font-semibold">Related alerts</h2>
            </div>
            {related.length === 0 ? (
              <p className="mt-3 text-sm text-foreground-muted">No related sample alerts.</p>
            ) : (
              <ul className="mt-3 space-y-2">
                {related.map((item) => (
                  <li key={item.id}>
                    <Link
                      to={`/alerts/${item.id}`}
                      className="block rounded-lg border border-border bg-surface-2 px-3 py-2.5 transition-colors hover:border-primary/50"
                    >
                      <p className="truncate text-sm font-medium">{item.title}</p>
                      <div className="mt-1 flex items-center gap-2">
                        <SeverityBadge severity={item.severity} />
                        <span className="font-mono text-xs text-foreground-muted">{item.id}</span>
                      </div>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="rounded-xl border border-border bg-surface p-5">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-safe" aria-hidden="true" />
              <h2 className="text-sm font-semibold">Recommended next steps</h2>
            </div>
            <p className="mt-2 text-xs text-foreground-muted">
              Suggested for the analyst — nothing here executes security actions.
            </p>
            <ul className="mt-3 space-y-2.5">
              {nextSteps.map((step) => (
                <li key={step} className="flex items-start gap-2 text-sm text-foreground-muted">
                  <Check className="mt-0.5 h-4 w-4 shrink-0 text-safe" aria-hidden="true" />
                  {step}
                </li>
              ))}
            </ul>
          </section>

          <section className="rounded-xl border border-border bg-surface p-5">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" />
              <h2 className="text-sm font-semibold">Analyst notes</h2>
            </div>
            <p className="mt-2 text-xs text-foreground-muted">
              Stored only in your browser for this demo session.
            </p>
            <label htmlFor="notes" className="sr-only">
              Analyst notes
            </label>
            <textarea
              id="notes"
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              rows={5}
              placeholder="Record observations here…"
              className="mt-3 w-full resize-y rounded-lg border border-border bg-surface-2 px-3 py-2.5 text-sm transition-colors focus:border-primary focus:outline-none"
            />
            <button
              type="button"
              onClick={saveNotes}
              className="mt-3 inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90"
            >
              {saved ? (
                <>
                  <Check className="h-4 w-4" aria-hidden="true" />
                  Saved locally
                </>
              ) : (
                'Save notes'
              )}
            </button>
          </section>
        </div>
      </div>
    </div>
  )
}

function DetailItem({ label, value, mono }: { label: string; value: string; mono: boolean }) {
  return (
    <div>
      <dt className="text-xs font-medium text-foreground-muted">{label}</dt>
      <dd className={`mt-0.5 text-sm ${mono ? 'font-mono' : ''}`}>{value}</dd>
    </div>
  )
}

function EvidenceRow({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  async function copyValue() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      // no-op
    }
  }

  return (
    <li className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2.5">
      <code className="min-w-0 truncate font-mono text-xs text-foreground">{value}</code>
      <button
        type="button"
        onClick={copyValue}
        aria-label={`Copy ${value}`}
        className="inline-flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-xs font-semibold text-foreground-muted transition-colors hover:text-primary"
      >
        {copied ? (
          <Check className="h-3.5 w-3.5 text-safe" aria-hidden="true" />
        ) : (
          <Copy className="h-3.5 w-3.5" aria-hidden="true" />
        )}
        {copied ? 'Copied' : 'Copy'}
      </button>
    </li>
  )
}

function AlertDetailSkeleton() {
  return (
    <div className="animate-pulse" aria-label="Loading alert details">
      <div className="h-4 w-24 rounded bg-surface-2" />
      <div className="mt-5 h-7 w-2/3 rounded bg-surface-2" />
      <div className="mt-6 grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <div className="h-64 rounded-xl border border-border bg-surface" />
          <div className="h-56 rounded-xl border border-border bg-surface" />
        </div>
        <div className="space-y-5">
          <div className="h-48 rounded-xl border border-border bg-surface" />
          <div className="h-56 rounded-xl border border-border bg-surface" />
        </div>
      </div>
    </div>
  )
}