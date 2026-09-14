import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, ChevronDown, ChevronUp, GitBranch, Network, RotateCw, Search, ShieldAlert } from 'lucide-react'
import { getThreats, getThreatAlerts } from '../services/apiClient'
import { severityColors } from '../lib/chartTheme'
import { SeverityBadge } from '../components/severity/SeverityBadge'

type StatusFilter = 'all' | IncidentStatus
type SeverityFilter = 'all' | Severity

const statusOptions: StatusFilter[] = ['all', 'active', 'investigating', 'resolved']
const severityOptions: SeverityFilter[] = ['all', 'critical', 'high', 'medium', 'low']

const incidentStatusStyles: Record<IncidentStatus, string> = {
  active: 'border-critical/40 bg-critical/15 text-critical',
  investigating: 'border-medium/40 bg-medium/15 text-medium',
  resolved: 'border-safe/40 bg-safe/15 text-safe',
}

const incidentStatusLabels: Record<IncidentStatus, string> = {
  active: 'Active',
  investigating: 'Investigating',
  resolved: 'Resolved',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function Incidents() {
  const [incidents, setIncidents] = useState<any[] | null>(null)
  const [incidentError, setIncidentError] = useState(false)
  const [incidentAttempt, setIncidentAttempt] = useState(0)
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState<StatusFilter>('all')
  const [severity, setSeverity] = useState<SeverityFilter>('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    setIncidentError(false)

    const params: Record<string, string> = {}
    if (search.trim()) params.search = search.trim()
    if (status !== 'all') params.status = status
    if (severity !== 'all') params.severity = severity

    getThreats(params)
      .then((data) => {
        if (active) setIncidents(data)
      })
      .catch(() => {
        if (active) setIncidentError(true)
      })
    return () => {
      active = false
    }
  }, [incidentAttempt, search, status, severity])

  const resetFilters = () => {
    setSearch('')
    setStatus('all')
    setSeverity('all')
  }

  const filtered = incidents || []
  const haveActiveFilters = search !== '' || status !== 'all' || severity !== 'all'

  return (
    <div className="mx-auto max-w-5xl">
      <div>
        <h1 className="text-xl font-bold tracking-tight">Threat correlation</h1>
        <p className="mt-1 text-sm text-foreground-muted">
          Related sample alerts grouped into potential incidents. Correlation confidence is a demo
          value.
        </p>
      </div>

      <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground-muted"
            aria-hidden="true"
          />
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search incidents…"
            aria-label="Search incidents"
            className="w-full rounded-lg border border-border bg-surface py-2.5 pl-9 pr-3 text-sm transition-colors focus:border-primary focus:outline-none"
          />
        </div>
        <FilterSelect
          label="Status"
          value={status}
          onChange={setStatus}
          options={statusOptions}
          render={(value) => (value === 'all' ? 'All statuses' : incidentStatusLabels[value])}
        />
        <FilterSelect
          label="Severity"
          value={severity}
          onChange={setSeverity}
          options={severityOptions}
          render={(value) => (value === 'all' ? 'All severities' : value)}
        />
      </div>

      <div className="mt-4 flex items-center justify-between">
        <p className="text-xs text-foreground-muted" aria-live="polite">
          {incidentError
            ? 'Sample incidents failed to load — retry before continuing.'
            : incidents === null
              ? 'Loading sample incidents…'
              : filtered.length === 0
                ? 'No incidents match the current filters.'
                : `${filtered.length} correlated incident${filtered.length === 1 ? '' : 's'} · sample data`}
        </p>
        {haveActiveFilters && (
          <button
            type="button"
            onClick={resetFilters}
            className="rounded-lg px-2 py-1 text-xs font-semibold text-primary transition-colors hover:bg-primary/10"
          >
            Reset filters
          </button>
        )}
      </div>

      <div className="mt-4 space-y-4">
        {incidentError ? (
          <div
            role="alert"
            className="flex flex-col items-start gap-3 rounded-xl border border-critical/40 bg-critical/10 p-6"
          >
            <div className="flex items-center gap-2 text-critical">
              <ShieldAlert className="h-5 w-5" aria-hidden="true" />
              <span className="text-sm font-semibold">Could not load demo incidents</span>
            </div>
            <p className="text-sm text-foreground-muted">
              The sample correlation results failed to load (simulated failure).
            </p>
            <button
              type="button"
              onClick={() => setIncidentAttempt((current) => current + 1)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:bg-surface-2"
            >
              <RotateCw className="h-4 w-4" aria-hidden="true" />
              Retry
            </button>
          </div>
        ) : incidents === null ? (
          <IncidentSkeleton />
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center gap-3 rounded-xl border border-border bg-surface px-5 py-16 text-center">
            <GitBranch className="h-8 w-8 text-foreground-muted" aria-hidden="true" />
            <p className="text-sm font-medium">No incidents found</p>
            <p className="max-w-sm text-sm text-foreground-muted">
              Nothing matches the current filters. Try widening them.
            </p>
            <button
              type="button"
              onClick={resetFilters}
              className="mt-1 inline-flex items-center justify-center rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90"
            >
              Reset filters
            </button>
          </div>
        ) : (
          filtered.map((incident) => (
            <IncidentCard
              key={incident.id}
              incident={incident}
              expanded={expandedId === incident.id}
              onToggle={() => setExpandedId((current) => (current === incident.id ? null : incident.id))}
            />
          ))
        )}
      </div>
    </div>
  )
}

function IncidentCard({
  incident,
  expanded,
  onToggle,
}: {
  incident: any
  expanded: boolean
  onToggle: () => void
}) {
  const [relatedAlerts, setRelatedAlerts] = useState<any[]>([])

  useEffect(() => {
    if (expanded) {
      let active = true
      getThreatAlerts(incident.id).then(data => {
        if (active) setRelatedAlerts(data)
      }).catch(() => {})
      return () => { active = false }
    }
  }, [expanded, incident.id])

  const timeline = useMemo(() => {
    const events = [
      { time: incident.openedAt, label: 'Incident opened — alerts began correlating' },
      ...relatedAlerts.map((alert) => ({
        time: alert.timestamp,
        label: `Sample alert ${alert.id} folded into the incident`,
      })),
      { time: incident.updatedAt || incident.updated_at || incident.openedAt, label: 'Last correlation activity' },
    ]
    return events.sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime())
  }, [incident, relatedAlerts])

  return (
    <article className="rounded-xl border border-border bg-surface">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        className="flex w-full flex-col gap-3 p-5 text-left transition-colors hover:bg-surface-2/60 sm:flex-row sm:items-start sm:justify-between"
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-foreground-muted">{incident.id}</span>
            <SeverityBadge severity={incident.severity} />
            <span
              className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${incidentStatusStyles[incident.status]}`}
            >
              {incidentStatusLabels[incident.status]}
            </span>
          </div>
          <h2 className="mt-2 text-base font-semibold">{incident.title}</h2>
          <p className="mt-1 line-clamp-2 text-sm leading-relaxed text-foreground-muted">
            {incident.summary}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-4 text-foreground-muted">
          <div className="text-right">
            <p className="text-xs">Correlation confidence</p>
            <p className="font-mono text-sm font-semibold text-foreground">{incident.confidence}%</p>
            <p className="text-[10px] uppercase tracking-wider">demo value</p>
          </div>
          <span className="rounded-lg border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-semibold">
            {incident.alert_ids?.length || 0} alerts
          </span>
          <span className="flex h-8 w-8 items-center justify-center text-foreground-muted">
            {expanded ? (
              <ChevronUp className="h-4 w-4" aria-hidden="true" />
            ) : (
              <ChevronDown className="h-4 w-4" aria-hidden="true" />
            )}
          </span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-border p-5">
          <div className="grid gap-6 lg:grid-cols-3">
            <section className="lg:col-span-2">
              <div className="flex items-center gap-2">
                <GitBranch className="h-4 w-4 text-accent" aria-hidden="true" />
                <h3 className="text-sm font-semibold">Why these alerts correlate</h3>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-foreground-muted">
                The correlation engine grouped these sample alerts based on shared patterns. Demo mapping.
              </p>

              <h3 className="mt-6 flex items-center gap-2 text-sm font-semibold">
                <Network className="h-4 w-4 text-primary" aria-hidden="true" />
                Relationship view
              </h3>
              <div className="mt-3 rounded-lg border border-border bg-surface-2/50 p-3">
                <RelationshipDiagram
                  incidentId={incident.id}
                  alerts={relatedAlerts.map((alert) => ({
                    id: alert.id,
                    severity: alert.severity,
                  }))}
                />
              </div>

              <h3 className="mt-6 text-sm font-semibold">Related sample alerts</h3>
              <ul className="mt-2 space-y-2">
                {relatedAlerts.length === 0 && (
                  <li className="text-sm text-foreground-muted">No related sample alerts.</li>
                )}
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
            </section>

            <section>
              <h3 className="flex items-center gap-2 text-sm font-semibold">
                <Activity className="h-4 w-4 text-primary" aria-hidden="true" />
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
                      <p className="mt-0.5 text-xs text-foreground-muted">{formatDate(event.time)}</p>
                    </div>
                  </li>
                ))}
              </ol>

              <div className="mt-6 rounded-lg border border-border bg-surface-2/50 p-4">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-medium text-foreground-muted">Correlation confidence</p>
                  <p className="font-mono text-xs font-semibold">{incident.confidence}%</p>
                </div>
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-surface-2">
                  <div
                    className="h-full rounded-full bg-accent"
                    style={{ width: `${incident.confidence}%` }}
                  />
                </div>
                <p className="mt-2 text-[11px] leading-relaxed text-foreground-muted">
                  Demo correlation confidence — not a score from a trained model.
                </p>
              </div>
            </section>
          </div>
        </div>
      )}
    </article>
  )
}

function RelationshipDiagram({
  incidentId,
  alerts,
}: {
  incidentId: string
  alerts: Array<{ id: string; severity: Severity }>
}) {
  const visible = alerts.slice(0, 4)
  const width = 320
  const centerX = width / 2

  return (
    <svg
      viewBox={`0 0 ${width} 116`}
      role="img"
      aria-label={`Relationship view: incident ${incidentId} linked to ${visible.length} sample alerts`}
      className="mx-auto w-full max-w-md"
    >
      <g stroke="var(--primary)" strokeWidth="1.6">
        <path d="M 8 8 L 24 8 L 24 16 L 16 16 L 16 48 L 8 48 Z" fill="none" strokeLinejoin="round" />
      </g>
      <circle cx={centerX} cy="26" r="16" fill="var(--primary)" opacity="0.18" />
      <circle cx={centerX} cy="26" r="16" fill="none" stroke="var(--primary)" strokeWidth="1.6" />
      <text x={centerX} y="30" textAnchor="middle" fontSize="10" fontWeight="bold" fill="var(--foreground)">
        {incidentId}
      </text>

      {visible.map((alert, index) => {
        const alertX =
          visible.length === 1
            ? centerX
            : centerX + (index - (visible.length - 1) / 2) * (width / visible.length)
        return (
          <g key={alert.id}>
            <line
              x1={centerX}
              y1="40"
              x2={alertX}
              y2="78"
              stroke="var(--border)"
              strokeWidth="1.5"
            />
            <circle cx={alertX} cy="92" r="10" fill={severityColors[alert.severity]} opacity="0.85" />
            <text x={alertX} y="118" textAnchor="middle" fontSize="9" fill="var(--foreground-muted)">
              {alert.id}
            </text>
          </g>
        )
      })}

      {alerts.length === 0 && (
        <text x={centerX} y="76" textAnchor="middle" fontSize="10" fill="var(--foreground-muted)">
          No related sample alerts
        </text>
      )}
      {visible.length < alerts.length && (
        <text x={centerX} y="112" textAnchor="middle" fontSize="9" fill="var(--foreground-muted)">
          +{alerts.length - visible.length} more alerts
        </text>
      )}
    </svg>
  )
}

function FilterSelect<T extends string>({
  label,
  value,
  onChange,
  options,
  render,
}: {
  label: string
  value: T
  onChange: (value: T) => void
  options: T[]
  render: (value: T) => string
}) {
  return (
    <label className="flex items-center gap-2 text-sm text-foreground-muted">
      <span className="sr-only">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value as T)}
        className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm text-foreground transition-colors focus:border-primary focus:outline-none sm:w-auto"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {render(option)}
          </option>
        ))}
      </select>
    </label>
  )
}

function IncidentSkeleton() {
  return (
    <div className="animate-pulse space-y-4" aria-label="Loading incidents">
      {[0, 1, 2].map((item) => (
        <div key={item} className="h-32 rounded-xl border border-border bg-surface" />
      ))}
    </div>
  )
}