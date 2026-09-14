import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, Bell, Network, RotateCw, ShieldAlert } from 'lucide-react'
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
import type { SystemStatus, TrendPoint, TrendRange } from '../types/alert'
import { computeSummary, severityDistribution } from '../lib/alertStats'
import { chartColors, severityColors } from '../lib/chartTheme'
import { getDashboardOverview, getAlertTrends, getSeverityDistribution, getRecentThreats } from '../services/apiClient'
import { useThreatUpdates } from '../hooks/useThreatUpdates'
import { SeverityBadge } from '../components/severity/SeverityBadge'
import { StatusBadge } from '../components/status/StatusBadge'

const trendOptions: { value: TrendRange; label: string }[] = [
  { value: '24h', label: 'Last 24h' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]

const healthColors = {
  healthy: 'var(--safe)',
  operational: 'var(--low)',
  degraded: 'var(--high)',
}

export function Dashboard() {
  const [range, setRange] = useState<TrendRange>('24h')
  const [trend, setTrend] = useState<TrendPoint[] | null>(null)
  const [summary, setSummary] = useState<any>(null)
  const [distribution, setDistribution] = useState<any[]>([])
  const [recentAlerts, setRecentAlerts] = useState<any[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchDashboardData = async () => {
    try {
      setLoading(true)
      const [overviewData, trendData, distData, alertsData] = await Promise.all([
        getDashboardOverview(),
        getAlertTrends(range),
        getSeverityDistribution(),
        getRecentThreats()
      ])
      setSummary(overviewData)
      setTrend(trendData)
      setDistribution(distData)
      setRecentAlerts(alertsData)
      setError(null)
    } catch (err: any) {
      setError(err.message || 'Could not load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDashboardData()
  }, [range])

  // Minimal WebSocket Integration for Real-Time Threat Updates
  useThreatUpdates(() => {
    fetchDashboardData()
  })

  return (
    <div className="mx-auto max-w-6xl">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Security overview</h1>
          <p className="mt-1 text-sm text-foreground-muted">
            Sample view of the demo environment. All numbers are simulated.
          </p>
        </div>
        <div
          className="inline-flex rounded-lg border border-border bg-surface p-1"
          role="group"
          aria-label="Time range"
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

      {error ? (
        <div
          role="alert"
          className="mt-6 flex flex-col items-start gap-3 rounded-xl border border-critical/40 bg-critical/10 p-6"
        >
          <div className="flex items-center gap-2 text-critical">
            <ShieldAlert className="h-5 w-5" aria-hidden="true" />
            <span className="text-sm font-semibold">Could not load demo data</span>
          </div>
          <p className="text-sm text-foreground-muted">{error}</p>
          <button
            type="button"
            onClick={fetchDashboardData}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:bg-surface-2"
          >
            <RotateCw className="h-4 w-4" aria-hidden="true" />
            Retry
          </button>
        </div>
      ) : loading ? (
        <DashboardSkeleton />
      ) : (
        <>
          <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {summary && (
              <>
                <StatCard
                  icon={Bell}
                  label="Open alerts"
                  value={summary.totalOpen}
                  note={`${rangeLabel(range)}`}
                />
                <StatCard
                  icon={AlertTriangle}
                  label="Critical alerts"
                  value={summary.critical}
                  note="Require attention first"
                  accent="text-critical"
                />
                <StatCard
                  icon={Network}
                  label="Correlated incidents"
                  value={summary.incidentCount}
                  note="Grouped from related alerts"
                  accent="text-accent"
                />
                <StatCard
                  icon={RotateCw}
                  label="False-positive review queue"
                  value={summary.falsePositiveReview}
                  note="Low-risk items to triage"
                  accent="text-high"
                />
              </>
            )}
          </div>

          <div className="mt-6 grid gap-4 lg:grid-cols-5">
            <section className="rounded-xl border border-border bg-surface p-5 lg:col-span-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h2 className="text-sm font-semibold">Threat trend</h2>
                  <p className="mt-0.5 text-xs text-foreground-muted">
                    Alert and incident volume · sample trend
                  </p>
                </div>
                <TrendLegend />
              </div>
              <div className="mt-4 h-56">
                {trend ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={trend} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                      <defs>
                        <linearGradient id="gradAlerts" x1="0" y1="0" x2="0" y2="1">
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
                        fill="url(#gradAlerts)"
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
                ) : (
                  <ChartSkeleton />
                )}
              </div>
            </section>

            <section className="rounded-xl border border-border bg-surface p-5 lg:col-span-2">
              <h2 className="text-sm font-semibold">Risk distribution</h2>
              <p className="mt-0.5 text-xs text-foreground-muted">
                Open alerts by severity · sample
              </p>
              <div className="mt-4 h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={distribution} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
                    <CartesianGrid stroke={chartColors.grid} strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="severity"
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
                      {distribution.map((entry) => (
                        <Cell key={entry.severity} fill={severityColors[entry.severity]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </section>
          </div>

          <section className="mt-6 rounded-xl border border-border bg-surface">
            <div className="flex items-center justify-between gap-2 border-b border-border px-5 py-4">
              <div>
                <h2 className="text-sm font-semibold">Recent alerts</h2>
                <p className="mt-0.5 text-xs text-foreground-muted">Highest-recent sample alerts</p>
              </div>
              <Link
                to="/alerts"
                className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-semibold text-primary transition-colors hover:bg-primary/10"
              >
                View all alerts
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
            {recentAlerts.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-foreground-muted">
                No alerts in the demo period.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <thead>
                    <tr className="border-b border-border text-xs uppercase tracking-wider text-foreground-muted">
                      <th scope="col" className="px-5 py-2.5 font-semibold">
                        Alert
                      </th>
                      <th scope="col" className="px-4 py-2.5 font-semibold">
                        Source
                      </th>
                      <th scope="col" className="px-4 py-2.5 font-semibold">
                        Severity
                      </th>
                      <th scope="col" className="px-4 py-2.5 font-semibold">
                        Risk
                      </th>
                      <th scope="col" className="px-4 py-2.5 font-semibold">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentAlerts.map((alert) => (
                      <tr key={alert.id} className="border-b border-border/60 last:border-0">
                        <td className="px-5 py-3">
                          <p className="font-medium">{alert.title}</p>
                          <p className="mt-0.5 font-mono text-xs text-foreground-muted">{alert.id.substring(0, 8)}</p>
                        </td>
                        <td className="px-4 py-3 text-foreground-muted">{alert.source || alert.sourceLabel || 'Unknown'}</td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={alert.severity} />
                        </td>
                        <td className="px-4 py-3">
                          <RiskScore score={alert.risk_score || alert.riskScore || 0} />
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge status={alert.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="mt-6">
            <h2 className="text-sm font-semibold">System status</h2>
            <p className="mt-0.5 text-xs text-foreground-muted">Simulated health of demo feeds</p>
            <div className="mt-3 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {systemStatusCards.map((system) => (
                <div key={system.id} className="rounded-xl border border-border bg-surface p-4">
                  <div className="flex items-center gap-2.5">
                    <span
                      className="h-2.5 w-2.5 rounded-full"
                      style={{ backgroundColor: healthColors[system.health] }}
                      aria-hidden="true"
                    />
                    <p className="text-sm font-semibold">{system.name}</p>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-foreground-muted">{system.detail}</p>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  )
}

function rangeLabel(range: TrendRange) {
  return trendOptions.find((option) => option.value === range)?.label ?? 'Demo'
}

const systemStatusCards: SystemStatus[] = [
  { id: 'siem', name: 'SIEM ingestion', detail: 'QRadar · healthy · 12s lag', health: 'healthy' },
  { id: 'edr', name: 'Endpoint detection', detail: 'All agents reporting', health: 'healthy' },
  {
    id: 'network',
    name: 'Network sensors',
    detail: 'Segment 4 degraded · 1 sensor offline',
    health: 'degraded',
  },
  {
    id: 'threatintel',
    name: 'Threat intel feed',
    detail: 'Last update 3 min ago',
    health: 'healthy',
  },
  {
    id: 'correlation',
    name: 'Correlation engine',
    detail: 'Jobs running normally',
    health: 'operational',
  },
]

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

function RiskScore({ score }: { score: number }) {
  const tone =
    score >= 80
      ? severityColors.critical
      : score >= 60
        ? severityColors.high
        : score >= 40
          ? severityColors.medium
          : severityColors.low
  return (
    <span className="inline-flex items-center gap-2">
      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-surface-2">
        <span className="block h-full rounded-full" style={{ width: `${score}%`, backgroundColor: tone }} />
      </span>
      <span className="font-mono text-xs text-foreground-muted">{score}</span>
    </span>
  )
}

function TrendLegend() {
  return (
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

function DashboardSkeleton() {
  return (
    <div className="mt-6 animate-pulse" aria-label="Loading dashboard">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((item) => (
          <div key={item} className="h-[104px] rounded-xl border border-border bg-surface" />
        ))}
      </div>
      <div className="mt-6 grid gap-4 lg:grid-cols-5">
        <div className="h-72 rounded-xl border border-border bg-surface lg:col-span-3" />
        <div className="h-72 rounded-xl border border-border bg-surface lg:col-span-2" />
      </div>
    </div>
  )
}