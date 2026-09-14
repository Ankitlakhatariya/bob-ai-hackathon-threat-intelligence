import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, RotateCw, Search, ShieldAlert } from 'lucide-react'
import type { AlertSource, AlertStatus, Severity } from '../types/alert'

import { useAlerts } from '../hooks/useAlerts'
import { SeverityBadge } from '../components/severity/SeverityBadge'
import { StatusBadge } from '../components/status/StatusBadge'

const PAGE_SIZE = 8

type SeverityFilter = 'all' | Severity
type SourceFilter = 'all' | AlertSource
type StatusFilter = 'all' | AlertStatus
type SortKey = 'newest' | 'oldest' | 'risk' | 'id'

const severityOptions: SeverityFilter[] = ['all', 'critical', 'high', 'medium', 'low']
const sourceOptions: SourceFilter[] = ['all', 'siem', 'edr', 'network-sensor', 'threat-feed']
const statusOptions: StatusFilter[] = ['all', 'open', 'investigating', 'resolved', 'false-positive']

const sourceLabels: Record<AlertSource, string> = {
  siem: 'SIEM',
  edr: 'EDR',
  'network-sensor': 'Network Sensor',
  'threat-feed': 'Threat Intel',
}

function formatTimestamp(value: string) {
  return new Date(value).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

  const params: Record<string, string> = {
    limit: String(PAGE_SIZE),
    skip: String((page - 1) * PAGE_SIZE),
  }
  
  if (search.trim()) params.search = search.trim()
  if (severity !== 'all') params.severity = severity
  if (source !== 'all') params.source = source
  if (status !== 'all') params.status = status
  
  if (sortKey === 'newest') {
    params.sort_by = 'timestamp'
    params.sort_order = 'desc'
  } else if (sortKey === 'oldest') {
    params.sort_by = 'timestamp'
    params.sort_order = 'asc'
  } else if (sortKey === 'risk') {
    params.sort_by = 'risk_score'
    params.sort_order = 'desc'
  } else if (sortKey === 'id') {
    params.sort_by = 'id'
    params.sort_order = 'asc'
  }

  const { alerts, loading, error, refetch } = useAlerts(params)
  
  const visible = alerts || []
  
  // Note: Since backend doesn't return total count currently, we simulate pageCount 
  // based on whether we received a full page of items.
  const hasMore = visible.length === PAGE_SIZE
  const pageCount = hasMore ? page + 1 : page
  const currentPage = page
  const start = visible.length === 0 ? 0 : (currentPage - 1) * PAGE_SIZE + 1
  const end = (currentPage - 1) * PAGE_SIZE + visible.length

  function resetFilters() {
    setSearch('')
    setSeverity('all')
    setSource('all')
    setStatus('all')
    setPage(1)
  }

  const haveActiveFilters = search !== '' || severity !== 'all' || source !== 'all' || status !== 'all'

  return (
    <div className="mx-auto max-w-6xl">
      <div>
        <h1 className="text-xl font-bold tracking-tight">Alert intelligence</h1>
        <p className="mt-1 text-sm text-foreground-muted">
          Search and filter sample alerts. All data is simulated for the demo.
        </p>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="relative sm:col-span-2">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground-muted"
            aria-hidden="true"
          />
          <input
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value)
              setPage(1)
            }}
            placeholder="Search by ID, title, or source…"
            aria-label="Search alerts"
            className="w-full rounded-lg border border-border bg-surface py-2.5 pl-9 pr-3 text-sm transition-colors focus:border-primary focus:outline-none"
          />
        </div>

        <FilterSelect
          label="Severity"
          value={severity}
          onChange={(value) => {
            setSeverity(value)
            setPage(1)
          }}
          options={severityOptions}
          render={(value) => (value === 'all' ? 'All severities' : value)}
        />
        <FilterSelect
          label="Status"
          value={status}
          onChange={(value) => {
            setStatus(value)
            setPage(1)
          }}
          options={statusOptions}
          render={(value) => (value === 'all' ? 'All statuses' : value.replace('-', ' '))}
        />
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
        <FilterSelect
          label="Source"
          value={source}
          onChange={(value) => {
            setSource(value)
            setPage(1)
          }}
          options={sourceOptions}
          render={(value) => (value === 'all' ? 'All sources' : sourceLabels[value])}
          className="sm:min-w-44"
        />
        <label className="flex items-center gap-2 text-sm text-foreground-muted">
          Sort by
          <select
            value={sortKey}
            onChange={(event) => {
              setSortKey(event.target.value as SortKey)
              setPage(1)
            }}
            className="rounded-lg border border-border bg-surface px-3 py-2 text-sm text-foreground transition-colors focus:border-primary focus:outline-none"
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
            <option value="risk">Highest risk</option>
            <option value="id">Alert ID</option>
          </select>
        </label>
      </div>

      {error ? (
        <div
          role="alert"
          className="mt-6 flex flex-col items-start gap-3 rounded-xl border border-critical/40 bg-critical/10 p-6"
        >
          <div className="flex items-center gap-2 text-critical">
            <ShieldAlert className="h-5 w-5" aria-hidden="true" />
            <span className="text-sm font-semibold">Could not load demo alerts</span>
          </div>
          <p className="text-sm text-foreground-muted">{error}</p>
          <button
            type="button"
            onClick={refetch}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:bg-surface-2"
          >
            <RotateCw className="h-4 w-4" aria-hidden="true" />
            Retry
          </button>
        </div>
      ) : loading || alerts === null ? (
        <AlertTableSkeleton />
      ) : (
        <section className="mt-6 rounded-xl border border-border bg-surface">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-5 py-3">
            <p className="text-xs text-foreground-muted" aria-live="polite">
              {visible.length === 0
                ? 'No alerts match the current filters.'
                : `Showing ${start}–${end} alerts`}
              <span className="ml-1.5 text-foreground-muted/70">· sample data</span>
            </p>
            {haveActiveFilters && (
              <button
                type="button"
                onClick={resetFilters}
                className="rounded-lg px-2.5 py-1 text-xs font-semibold text-primary transition-colors hover:bg-primary/10"
              >
                Reset filters
              </button>
            )}
          </div>

          {visible.length === 0 ? (
            <div className="flex flex-col items-center gap-3 px-5 py-16 text-center">
              <Search className="h-8 w-8 text-foreground-muted" aria-hidden="true" />
              <p className="text-sm font-medium text-foreground">No alerts found</p>
              <p className="max-w-sm text-sm text-foreground-muted">
                Nothing matches your search and filters. Try widening them or reset to see all sample
                alerts.
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
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-xs uppercase tracking-wider text-foreground-muted">
                    <th scope="col" className="px-5 py-2.5 font-semibold">
                      Alert
                    </th>
                    <th scope="col" className="px-4 py-2.5 font-semibold">
                      Source
                    </th>
                    <th scope="col" className="px-4 py-2.5 font-semibold">
                      Detected
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
                    <th scope="col" className="px-4 py-2.5 font-semibold">
                      Incident
                    </th>
                    <th scope="col" className="px-4 py-2.5" aria-label="Open alert" />
                  </tr>
                </thead>
                <tbody>
                  {visible.map((alert) => (
                    <tr
                      key={alert.id}
                      className="border-b border-border/60 transition-colors last:border-0 hover:bg-surface-2/60"
                    >
                      <td className="px-5 py-3">
                        <Link
                          to={`/alerts/${alert.id}`}
                          className="rounded font-medium text-foreground transition-colors hover:text-primary"
                        >
                          {alert.title}
                        </Link>
                        <p className="mt-0.5 font-mono text-xs text-foreground-muted">{alert.id}</p>
                      </td>
                      <td className="px-4 py-3 text-foreground-muted">{alert.sourceLabel}</td>
                      <td className="px-4 py-3 whitespace-nowrap text-foreground-muted">
                        {formatTimestamp(alert.timestamp)}
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="px-4 py-3 font-mono text-foreground-muted">{alert.risk_score || alert.riskScore}</td>
                      <td className="px-4 py-3">
                        <StatusBadge status={alert.status} />
                      </td>
                      <td className="px-4 py-3 text-foreground-muted">
                        {alert.related_threat_id || alert.relatedIncidentId
                          ? (alert.related_threat_id || alert.relatedIncidentId)
                          : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <Link
                          to={`/alerts/${alert.id}`}
                          aria-label={`Open ${alert.id}`}
                          className="inline-flex items-center justify-center rounded-lg p-1.5 text-foreground-muted transition-colors hover:bg-surface-2 hover:text-primary"
                        >
                          <ArrowRight className="h-4 w-4" aria-hidden="true" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {pageCount > 1 && (
            <div className="flex items-center justify-between border-t border-border px-5 py-3">
              <p className="text-xs text-foreground-muted">
                Page {currentPage} of {pageCount}
              </p>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setPage((value) => Math.max(1, value - 1))}
                  disabled={currentPage === 1}
                  className="rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-foreground transition-colors hover:bg-surface-2 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={() => setPage((value) => Math.min(pageCount, value + 1))}
                  disabled={currentPage === pageCount}
                  className="rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-foreground transition-colors hover:bg-surface-2 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  )
}

function FilterSelect<T extends string>({
  label,
  value,
  onChange,
  options,
  render,
  className = '',
}: {
  label: string
  value: T
  onChange: (value: T) => void
  options: T[]
  render: (value: T) => string
  className?: string
}) {
  return (
    <label className={`flex items-center gap-2 text-sm text-foreground-muted ${className}`}>
      <span className="sr-only sm:not-sr-only">{label}</span>
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

function AlertTableSkeleton() {
  return (
    <div className="mt-6 animate-pulse rounded-xl border border-border bg-surface" aria-label="Loading alerts">
      <div className="space-y-0">
        {[0, 1, 2, 3, 4, 5].map((item) => (
          <div key={item} className="border-b border-border/60 px-5 py-4 last:border-0">
            <div className="h-3 w-1/3 rounded bg-surface-2" />
            <div className="mt-2 h-3 w-1/4 rounded bg-surface-2" />
          </div>
        ))}
      </div>
    </div>
  )
}