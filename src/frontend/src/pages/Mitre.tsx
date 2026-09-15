import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ExternalLink, RotateCw, Search, ShieldAlert, Target } from 'lucide-react'
import { getMitreTechniques, getAlerts, getThreats } from '../services/apiClient'
import { SeverityBadge } from '../components/severity/SeverityBadge'

import type { Alert } from '../types/alert'
import type { Incident } from '../types/incident'

type MitreTactic = string
type TacticFilter = 'all' | MitreTactic

const tacticOptions = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Lateral Movement',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const satisfies readonly MitreTactic[]

export function Mitre() {
  const [alerts, setAlerts] = useState<any[]>([])
  const [incidents, setIncidents] = useState<any[]>([])
  const [techniques, setTechniques] = useState<any[] | null>(null)
  const [incidentError, setIncidentError] = useState(false)
  const [incidentAttempt, setIncidentAttempt] = useState(0)

  const [search, setSearch] = useState('')
  const [tactic, setTactic] = useState<TacticFilter>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    setIncidentError(false)
    Promise.all([getMitreTechniques(), getAlerts(), getThreats()])
      .then(([techData, alertsData, threatsData]) => {
        if (active) {
          setTechniques(techData)
          setAlerts(alertsData)
          setIncidents(threatsData)
        }
      })
      .catch(() => {
        if (active) setIncidentError(true)
      })
    return () => {
      active = false
    }
  }, [incidentAttempt])

  const alertsByTechnique = useMemo(() => {
    const map = new Map<string, Alert[]>()
    for (const alert of alerts ?? []) {
      for (const techniqueId of alert.mitre_techniques || alert.mitreTechniques || []) {
        const list = map.get(techniqueId) ?? []
        list.push(alert)
        map.set(techniqueId, list)
      }
    }
    return map
  }, [alerts])

  const incidentsByTechnique = useMemo(() => {
    const map = new Map<string, Incident[]>()
    for (const incident of incidents ?? []) {
      for (const techniqueId of incident.mitre_techniques || incident.mitreTechniques || []) {
        const list = map.get(techniqueId) ?? []
        list.push(incident)
        map.set(techniqueId, list)
      }
    }
    return map
  }, [incidents])

  const filtered = useMemo(() => {
    if (!techniques) return []
    const query = search.trim().toLowerCase()
    return techniques.filter((technique: any) => {
      if (tactic !== 'all' && !technique.tactics.includes(tactic)) return false
      if (query) {
        const haystack = `${technique.id} ${technique.name}`.toLowerCase()
        if (!haystack.includes(query)) return false
      }
      return true
    })
  }, [techniques, search, tactic])

  const dataReady = techniques !== null
  const hasError = incidentError

  // Keep a valid selection whenever the list changes or data finishes loading.
  useEffect(() => {
    if (!dataReady) return
    if (filtered.length === 0) {
      setSelectedId(null)
      return
    }
    if (!filtered.some((technique) => technique.id === selectedId)) {
      setSelectedId(filtered[0].id)
    }
  }, [dataReady, filtered, selectedId])

  const selected = filtered.find((technique) => technique.id === selectedId) ?? null

  const linkedAlertCount = alerts?.filter((alert: any) => (alert.mitre_techniques?.length || alert.mitreTechniques?.length) > 0).length ?? 0
  const linkedIncidentCount = incidents?.filter((incident: any) => (incident.mitre_techniques?.length || incident.mitreTechniques?.length) > 0).length ?? 0

  function refetchAll() {
    setIncidentAttempt((current) => current + 1)
  }

  function resetFilters() {
    setSearch('')
    setTactic('all')
  }

  const haveActiveFilters = search !== '' || tactic !== 'all'

  return (
    <div className="mx-auto max-w-6xl">
      <div>
        <h1 className="text-xl font-bold tracking-tight">MITRE ATT&CK explorer</h1>
        <p className="mt-1 text-sm text-foreground-muted">
          Browse the techniques seen across sample alerts and correlated incidents. Technique
          details are verified; mappings to alerts are demo data.
        </p>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        <div className="relative sm:col-span-1">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground-muted"
            aria-hidden="true"
          />
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search by technique ID or name…"
            aria-label="Search techniques"
            className="w-full rounded-lg border border-border bg-surface py-2.5 pl-9 pr-3 text-sm transition-colors focus:border-primary focus:outline-none"
          />
        </div>

        <label className="flex items-center gap-2 text-sm text-foreground-muted">
          <span className="sr-only sm:not-sr-only">Tactic</span>
          <select
            value={tactic}
            onChange={(event) => setTactic(event.target.value as TacticFilter)}
            className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm text-foreground transition-colors focus:border-primary focus:outline-none sm:w-auto"
          >
            <option value="all">All tactics</option>
            {tacticOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-foreground-muted" aria-live="polite">
          {!dataReady
            ? 'Loading catalogue…'
            : `${filtered.length} technique${filtered.length === 1 ? '' : 's'} · ${linkedAlertCount} sample
               alerts and ${linkedIncidentCount} incidents with technique mappings`}
          <span className="ml-1.5 text-foreground-muted/70">· demo mappings</span>
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

      {hasError ? (
        <div
          role="alert"
          className="mt-6 flex flex-col items-start gap-3 rounded-xl border border-critical/40 bg-critical/10 p-6"
        >
          <div className="flex items-center gap-2 text-critical">
            <ShieldAlert className="h-5 w-5" aria-hidden="true" />
            <span className="text-sm font-semibold">Could not load demo data</span>
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
        <MitreSkeleton />
      ) : filtered.length === 0 ? (
        <div className="mt-6 flex flex-col items-center gap-3 rounded-xl border border-border bg-surface px-5 py-16 text-center">
          <Search className="h-8 w-8 text-foreground-muted" aria-hidden="true" />
          <p className="text-sm font-medium text-foreground">No techniques found</p>
          <p className="max-w-sm text-sm text-foreground-muted">
            Nothing in the catalogue matches the current search and tactic filter.
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
        <div className="mt-6 grid gap-6 lg:grid-cols-12">
          <section aria-label="Technique list" className="lg:col-span-5">
            <div className="space-y-2">
              {filtered.map((technique) => (
                <button
                  key={technique.id}
                  type="button"
                  onClick={() => setSelectedId(technique.id)}
                  aria-pressed={selected?.id === technique.id}
                  className={`w-full rounded-xl border p-4 text-left transition-colors ${
                    selected?.id === technique.id
                      ? 'border-primary/60 bg-primary/5'
                      : 'border-border bg-surface hover:border-primary/40 hover:bg-surface-2/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="font-mono text-xs text-foreground-muted">{technique.id}</p>
                      <h2 className="mt-0.5 text-sm font-semibold leading-snug">{technique.name}</h2>
                    </div>
                    <span className="shrink-0 rounded-md border border-border bg-surface-2 px-2 py-1 font-mono text-[11px] font-semibold text-foreground-muted">
                      {alertsByTechnique.get(technique.id)?.length ?? 0} alerts
                    </span>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {technique.tactics.map((item: string) => (
                      <span
                        key={item}
                        className="rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[11px] text-foreground-muted"
                      >
                        {item}
                      </span>
                    ))}
                  </div>
                </button>
              ))}
            </div>
          </section>

          <section aria-labelledby="mitre-detail-title" className="lg:col-span-7">
            <TechniqueDetail
              technique={selected}
              alerts={(selected && alertsByTechnique.get(selected.id)) ?? []}
              incidents={(selected && incidentsByTechnique.get(selected.id)) ?? []}
            />
          </section>
        </div>
      )}
    </div>
  )
}

function TechniqueDetail({
  technique,
  alerts,
  incidents,
}: {
  technique: any | null
  alerts: any[]
  incidents: any[]
}) {
  if (!technique) {
    return (
      <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-border bg-surface px-5 py-16 text-center lg:sticky lg:top-24">
        <Target className="h-8 w-8 text-foreground-muted" aria-hidden="true" />
        <p className="text-sm font-medium">Select a technique</p>
        <p className="max-w-xs text-sm text-foreground-muted">
          Pick a technique from the list to see its definition and demo mappings.
        </p>
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-border bg-surface p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-mono text-xs text-foreground-muted">{technique.id}</p>
          <h2 id="mitre-detail-title" className="mt-1 text-lg font-semibold leading-snug">
            {technique.name}
          </h2>
        </div>
        <a
          href={technique.url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border bg-surface-2 px-3 py-1.5 text-xs font-semibold text-foreground transition-colors hover:border-primary/50 hover:text-primary"
        >
          attack.mitre.org
          <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
        </a>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {technique.tactics.map((item: string) => (
          <span
            key={item}
            className="rounded-full border border-primary/40 bg-primary/10 px-2.5 py-0.5 text-xs font-semibold text-primary"
          >
            {item}
          </span>
        ))}
      </div>

      <p className="mt-4 text-sm leading-relaxed text-foreground-muted">{technique.description}</p>

      <p className="mt-3 rounded-lg bg-surface-2/60 px-3 py-2 text-[11px] leading-relaxed text-foreground-muted">
        Technique metadata above comes from the public MITRE ATT&CK knowledge base. The
        alerts and incidents linked below are demo mappings until the AI/backend team supplies
        real technique detection.
      </p>

      <div className="mt-6 grid gap-6 sm:grid-cols-2">
        <section>
          <h3 className="text-sm font-semibold">Sample alerts using this technique</h3>
          <ul className="mt-3 space-y-2">
            {alerts.length === 0 && (
              <li className="text-sm text-foreground-muted">No sample alerts mapped.</li>
            )}
            {alerts.map((alert) => (
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
          <h3 className="text-sm font-semibold">Correlated incidents</h3>
          <ul className="mt-3 space-y-2">
            {incidents.length === 0 && (
              <li className="text-sm text-foreground-muted">No sample incidents mapped.</li>
            )}
            {incidents.map((incident) => (
              <li key={incident.id}>
                <Link
                  to="/incidents"
                  className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2.5 transition-colors hover:border-primary/50"
                >
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-medium">{incident.title}</span>
                    <span className="font-mono text-xs text-foreground-muted">
                      {incident.id} · confidence {incident.confidence}%
                    </span>
                  </span>
                  <SeverityBadge severity={incident.severity} />
                </Link>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  )
}



function MitreSkeleton() {
  return (
    <div className="mt-6 grid gap-6 lg:grid-cols-12" aria-label="Loading techniques">
      <div className="space-y-3 lg:col-span-5">
        {[0, 1, 2, 3].map((item) => (
          <div key={item} className="h-24 animate-pulse rounded-xl border border-border bg-surface" />
        ))}
      </div>
      <div className="h-80 animate-pulse rounded-xl border border-border bg-surface lg:col-span-7" />
    </div>
  )
}