import { useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  Activity,
  Bell,
  CheckCircle2,
  RotateCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { AlertStatus, TrendPoint, TrendRange } from '../types/alert'
import type { Incident, IncidentStatus } from '../types/incident'
import { computeSummary, severityDistribution } from '../lib/alertStats'
import { chartColors, incidentStatusColors, severityColors, statusColors } from '../lib/chartTheme'
import { getThreats, getAlertTrends, getAlerts } from '../services/apiClient'

const statusLabels: Record<AlertStatus, string> = {
  open: 'Open',
  investigating: 'Investigating',
  resolved: 'Resolved',
  'false-positive': 'False positive',
}

const incidentStatusLabels: Record<IncidentStatus, string> = {
  active: 'Active',
  investigating: 'Investigating',
  resolved: 'Resolved',
}

const sourceShortLabels: Record<string, string> = {
  'EDR Endpoint Agent': 'EDR',
  SIEM: 'SIEM',
  'Network Sensor': 'Net Sensor',
  'Threat Intel Feed': 'Threat Intel',
}

const trendOptions: { value: TrendRange; label: string }[] = [
  { value: '24h', label: 'Last 24h' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]

export function Analytics() {
  const [alerts, setAlerts] = useState<any[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [incidents, setIncidents] = useState<any[] | null>(null)
  const [incidentError, setIncidentError] = useState(false)
  const [fetchAttempt, setFetchAttempt] = useState(0)

  const [range, setRange] = useState<TrendRange>('24h')
  const [trend, setTrend] = useState<TrendPoint[] | null>(null)

  useEffect(() => {
    let active = true
    setTrend(null)
    getAlertTrends(range).then((data) => {
      if (active) setTrend(data)
    })
    return () => {
      active = false
    }
  }, [range])

  useEffect(() => {
    let active = true
    setError(null)
    setIncidentError(false)

    Promise.all([getAlerts(), getThreats()])
      .then(([alertsData, threatsData]) => {
        if (active) {
          setAlerts(alertsData)
          setIncidents(threatsData)
        }
      })
      .catch((err) => {
        if (active) {
          setError(err.message || 'Could not load analytics')
          setIncidentError(true)
        }
      })
    return () => {
      active = false
    }
  }, [fetchAttempt])

  const summary = useMemo(() => (alerts ? computeSummary(alerts) : null), [alerts])

  const sourceDistribution = useMemo(() => {
    if (!alerts) return []
    const counts = new Map<string, number>()
    for (const alert of alerts) {
      counts.set(alert.sourceLabel, (counts.get(alert.sourceLabel) ?? 0) + 1)
    }
    return [...counts.entries()]
      .map(([source, count]) => ({ source, label: sourceShortLabels[source] ?? source, count }))
      .sort((a, b) => b.count - a.count)
  }, [alerts])

  const lifecycleDistribution = useMemo(() => {
    if (!alerts) return []
    const order: AlertStatus[] = ['open', 'investigating', 'resolved', 'false-positive']
    return order.map((status) => ({
      status,
      count: alerts.filter((alert) => alert.status === status).length,
    }))
  }, [alerts])

  const incidentStatusDistribution = useMemo(() => {
    if (!incidents) return []
    const order: IncidentStatus[] = ['active', 'investigating', 'resolved']
    return order.map((status) => ({
      status,
      count: incidents.filter((incident) => incident.status === status).length,
    }))
  }, [incidents])

  const severity = useMemo(() => (alerts ? severityDistribution(alerts) : []), [alerts])

  const dataReady = alerts !== null && incidents !== null
  const hasError = error !== null || incidentError

  function refetchAll() {
    setFetchAttempt((current) => current + 1)
  }

  return (
    <div className="mx-auto max-w-6xl">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Threat analytics</h1>
          <p className="mt-1 text-sm text-foreground-muted">
            Volume and risk patterns across the sample environment. Every figure is simulated demo
            data.
          </p>
        </div>
        <div
          className="inline-flex rounded-lg border border-border bg-surface p-1"
          role="group"
          aria-label="Time range for trend chart"
        >
          {trendOptions.map((option) => (
            <button
              key={option.value}
              type="button"
              onClick={() => setRange(option.value)}
              aria-pressed={range === option.value}
              className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
                range === option.value
                  ? 'bg-primary text-primary-foreground'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {hasError ? (
        <div
          role="alert"
          className="mt-6 flex flex-col items-start gap-3 rounded-xl border border-critical/40 bg-critical/10 p-6"
        >
          <div className="flex items-center gap-2 text-critical">
            <ShieldAlert className="h-5 w-5" aria-hidden="true" />
            <span className="text-sm font-semibold">Could not load demo analytics</span>
          </div>
          <p className="text-sm text-foreground-muted">
            The sample alerts or incidents failed to load (simulated failure).
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
        <AnalyticsSkeleton />
      ) : (
        <>
          <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              icon={Bell}
              label="Alerts recorded"
              value={alerts.length}
              note="Full sample period"
            />
            <StatCard
              icon={Activity}
              label="Open alerts"
              value={summary?.totalOpen ?? 0}
              note="Awaiting triage"
              accent="text-primary"
            />
            <StatCard
              icon={ShieldAlert}
              label="Under investigation"
              value={
                (alerts.filter((alert) => alert.status === 'investigating').length ?? 0) +
                (incidents?.filter((incident) => incident.status === 'investigating').length ?? 0)
              }
              note="Alerts + incidents · sample"
              accent="text-high"
            />
            <StatCard
              icon={CheckCircle2}
              label="False positives flagged"
              value={alerts.filter((alert) => alert.status === 'false-positive').length}
              note="Reviewed as benign"
              accent="text-safe"
            />
          </div>

          <div className="mt-6 grid gap-4">
            <ChartCard
              title="Alert & incident trend"
              description={`Volume across the ${trendOptions.find((option) => option.value === range)?.label.toLowerCase() ?? 'selected'} window. Incident line follows the same escalation pattern.`}
              srSummary="Line chart of alert and incident volume over the selected sample window."
              legend={
                <div className="flex items-center gap-3 text-xs text-foreground-muted">
                  <span className="inline-flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full" style={{ backgroundColor: chartColors.accent }} aria-hidden="true" />
                    Alerts
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full" style={{ backgroundColor: chartColors.low }} aria-hidden="true" />
                    Incidents
                  </span>
                </div>
              }
            >
              {trend && trend.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trend} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                    <defs>
                      <linearGradient id="gradAnalyticsAlerts" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={chartColors.accent} stopOpacity={0.35} />
                        <stop offset="100%" stopColor={chartColors.accent} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke={chartColors.grid} strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="label"
                      tick={{ fill: chartColors.tick, fontSize: 11 }}
                      axisLine={{ stroke: chartColors.grid }}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fill: chartColors.tick, fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        borderRadius: 8,
                        color: 'var(--foreground)',
                        fontSize: 12,
                      }}
                      labelStyle={{ color: 'var(--foreground-muted)' }}
                    />
                    <Area
                      type="monotone"
                      dataKey="alerts"
                      name="Alerts"
                      stroke={chartColors.accent}
                      strokeWidth={2}
                      fill="url(#gradAnalyticsAlerts)"
                    />
                    <Area
                      type="monotone"
                      dataKey="incidents"
                      name="Incidents"
                      stroke={chartColors.low}
                      strokeWidth={2}
                      fill="transparent"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : trend === null ? (
                <ChartSkeleton />
              ) : (
                <ChartEmpty />
              )}
            </ChartCard>

            <div className="grid gap-4 md:grid-cols-2">
              <ChartCard
                title="Severity distribution"
                description="How many sample alerts fall into each severity band."
                srSummary="Bar chart of sample alerts grouped by severity: critical, high, medium, and low."
              >
                {severity.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={severity.map((entry) => ({ label: entry.severity, count: entry.count }))} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                      <CartesianGrid stroke={chartColors.grid} strokeDasharray="3 3" vertical={false} />
                      <XAxis
                        dataKey="label"
                        tick={{ fill: chartColors.tick, fontSize: 11 }}
                        axisLine={{ stroke: chartColors.grid }}
                        tickLine={false}
                      />
                      <YAxis tick={{ fill: chartColors.tick, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip
                        cursor={{ fill: 'var(--surface-2)' }}
                        contentStyle={{
                          backgroundColor: 'var(--surface-2)',
                          border: '1px solid var(--border)',
                          borderRadius: 8,
                          color: 'var(--foreground)',
                          fontSize: 12,
                        }}
                        labelStyle={{ color: 'var(--foreground-muted)' }}
                      />
                      <Bar dataKey="count" name="Alerts" radius={[4, 4, 0, 0]}>
                        {severity.map((entry) => (
                          <Cell key={entry.severity} fill={severityColors[entry.severity]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <ChartEmpty />
                )}
              </ChartCard>

              <ChartCard
                title="Source distribution"
                description="Which detection feeds produced the sample alerts."
                srSummary="Bar chart of sample alerts grouped by detection source."
              >
                {sourceDistribution.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={sourceDistribution.map((entry) => ({ label: entry.label, count: entry.count }))} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                      <CartesianGrid stroke={chartColors.grid} strokeDasharray="3 3" vertical={false} />
                      <XAxis
                        dataKey="label"
                        tick={{ fill: chartColors.tick, fontSize: 10 }}
                        axisLine={{ stroke: chartColors.grid }}
                        tickLine={false}
                        interval={0}
                        angle={-12}
                        textAnchor="end"
                        height={40}
                      />
                      <YAxis tick={{ fill: chartColors.tick, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip
                        cursor={{ fill: 'var(--surface-2)' }}
                        contentStyle={{
                          backgroundColor: 'var(--surface-2)',
                          border: '1px solid var(--border)',
                          borderRadius: 8,
                          color: 'var(--foreground)',
                          fontSize: 12,
                        }}
                        labelStyle={{ color: 'var(--foreground-muted)' }}
                      />
                      <Bar dataKey="count" name="Alerts" fill={chartColors.accent} radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <ChartEmpty />
                )}
              </ChartCard>

              <ChartCard
                title="Alert lifecycle"
                description="Where the sample alerts sit today: open, investigating, resolved, or false positive."
                srSummary="Bar chart showing investigation-state coverage across the sample alerts."
              >
                {lifecycleDistribution.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={lifecycleDistribution.map((entry) => ({ label: statusLabels[entry.status], count: entry.count }))} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                      <CartesianGrid stroke={chartColors.grid} strokeDasharray="3 3" vertical={false} />
                      <XAxis
                        dataKey="label"
                        tick={{ fill: chartColors.tick, fontSize: 10 }}
                        axisLine={{ stroke: chartColors.grid }}
                        tickLine={false}
                        interval={0}
                        angle={-12}
                        textAnchor="end"
                        height={40}
                      />
                      <YAxis tick={{ fill: chartColors.tick, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip
                        cursor={{ fill: 'var(--surface-2)' }}
                        contentStyle={{
                          backgroundColor: 'var(--surface-2)',
                          border: '1px solid var(--border)',
                          borderRadius: 8,
                          color: 'var(--foreground)',
                          fontSize: 12,
                        }}
                        labelStyle={{ color: 'var(--foreground-muted)' }}
                      />
                      <Bar dataKey="count" name="Alerts" radius={[4, 4, 0, 0]}>
                        {lifecycleDistribution.map((entry) => (
                          <Cell key={entry.status} fill={statusColors[entry.status]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <ChartEmpty />
                )}
              </ChartCard>

              <ChartCard
                title="Incident status"
                description="Correlated incidents by lifecycle — active campaigns need the most attention."
                srSummary="Bar chart of correlated incidents grouped by status."
              >
                {incidentStatusDistribution.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={incidentStatusDistribution.map((entry) => ({ label: incidentStatusLabels[entry.status], count: entry.count }))} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                      <CartesianGrid stroke={chartColors.grid} strokeDasharray="3 3" vertical={false} />
                      <XAxis
                        dataKey="label"
                        tick={{ fill: chartColors.tick, fontSize: 11 }}
                        axisLine={{ stroke: chartColors.grid }}
                        tickLine={false}
                      />
                      <YAxis tick={{ fill: chartColors.tick, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip
                        cursor={{ fill: 'var(--surface-2)' }}
                        contentStyle={{
                          backgroundColor: 'var(--surface-2)',
                          border: '1px solid var(--border)',
                          borderRadius: 8,
                          color: 'var(--foreground)',
                          fontSize: 12,
                        }}
                        labelStyle={{ color: 'var(--foreground-muted)' }}
                      />
                      <Bar dataKey="count" name="Incidents" radius={[4, 4, 0, 0]}>
                        {incidentStatusDistribution.map((entry) => (
                          <Cell key={entry.status} fill={incidentStatusColors[entry.status]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <ChartEmpty />
                )}
              </ChartCard>
            </div>
          </div>

          <section className="mt-6 rounded-xl border border-border bg-surface p-5">
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck className="h-4 w-4 text-safe" aria-hidden="true" />
              False-positive review metrics
            </h2>
            <p className="mt-1 text-xs text-foreground-muted">
              How much of the sample load is likely noise — the core alert-overload problem this
              product addresses.
            </p>
            <div className="mt-5 grid gap-4 sm:grid-cols-3">
              <MetricBar
                label="Flagged false positive"
                value={alerts.filter((alert) => alert.status === 'false-positive').length}
                total={alerts.length}
                color={chartColors.safe}
              />
              <MetricBar
                label="In the review queue"
                value={summary?.falsePositiveReview ?? 0}
                total={alerts.length}
                color={chartColors.high}
              />
              <MetricBar
                label="Resolved (actioned)"
                value={alerts.filter((alert) => alert.status === 'resolved').length}
                total={alerts.length}
                color={chartColors.low}
              />
            </div>
            <p className="mt-4 text-[11px] leading-relaxed text-foreground-muted">
              Simulated demo statistics only. Percentages are relative to the sample dataset and do
              not represent real security outcomes.
            </p>
          </section>
        </>
      )}
    </div>
  )
}

function StatCard({
  icon: Icon,
  label,
  value,
  note,
  accent = 'text-foreground',
}: {
  icon: typeof Bell
  label: string
  value: number
  note: string
  accent?: string
}) {
  return (
    <div className="rounded-xl border border-border bg-surface p-5">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-foreground-muted">{label}</p>
        <Icon className="h-4 w-4 text-foreground-muted" aria-hidden="true" />
      </div>
      <p className={`mt-2 text-3xl font-bold ${accent}`}>{value}</p>
      <p className="mt-1 text-xs text-foreground-muted">{note}</p>
    </div>
  )
}

function ChartCard({
  title,
  description,
  srSummary,
  legend,
  children,
}: {
  title: string
  description: string
  srSummary: string
  legend?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="rounded-xl border border-border bg-surface p-5">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          <p className="mt-0.5 text-xs text-foreground-muted">{description}</p>
        </div>
        {legend}
      </div>
      <div className="mt-4 h-56" role="img" aria-label={srSummary}>
        {children}
      </div>
      <p className="mt-2 text-[11px] text-foreground-muted">All figures are simulated demo data.</p>
    </section>
  )
}

function MetricBar({
  label,
  value,
  total,
  color,
}: {
  label: string
  value: number
  total: number
  color: string
}) {
  const percent = total === 0 ? 0 : Math.round((value / total) * 100)
  return (
    <div className="rounded-lg border border-border bg-surface-2/40 p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-foreground-muted">{label}</p>
        <p className="font-mono text-sm font-semibold">{percent}%</p>
      </div>
      <div className="mt-2 flex items-center gap-2">
        <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-2">
          <div className="h-full rounded-full" style={{ width: `${percent}%`, backgroundColor: color }} />
        </div>
        <span className="font-mono text-xs text-foreground-muted">
          {value}/{total}
        </span>
      </div>
    </div>
  )
}

function ChartSkeleton() {
  return (
    <div className="flex h-full animate-pulse items-end gap-2 px-2 pb-2" aria-label="Loading chart">
      {[35, 55, 40, 70, 50, 85, 60, 45, 75].map((height, index) => (
        <span
          key={index}
          className="flex-1 rounded-t bg-surface-2"
          style={{ height: `${height}%` }}
        />
      ))}
    </div>
  )
}

function ChartEmpty() {
  return (
    <p className="flex h-full w-full items-center justify-center px-4 text-center text-xs text-foreground-muted">
      No data available for this visualization.
    </p>
  )
}

function AnalyticsSkeleton() {
  return (
    <div className="mt-6 animate-pulse" aria-label="Loading analytics">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((item) => (
          <div key={item} className="h-[104px] rounded-xl border border-border bg-surface" />
        ))}
      </div>
      <div className="mt-6 h-72 rounded-xl border border-border bg-surface" />
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        {[0, 1, 2, 3].map((item) => (
          <div key={item} className="h-56 rounded-xl border border-border bg-surface" />
        ))}
      </div>
    </div>
  )
}