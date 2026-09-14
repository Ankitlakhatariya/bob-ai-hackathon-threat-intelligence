import type { Severity } from '../types/alert'
import type { Incident, IncidentStatus } from '../types/incident'
import { mockAlerts } from './mockAlerts'

const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }

interface IncidentMeta {
  title: string
  summary: string
  status: IncidentStatus
  confidence: number
  openedAt: string
}

const meta: Record<string, IncidentMeta> = {
  'INC-1001': {
    title: 'Malware delivery via email campaign',
    summary:
      'A sandboxed attachment dropped a payload whose hash matched the threat feed, followed by probing of a public web application.',
    status: 'investigating',
    confidence: 82,
    openedAt: '2026-09-13T11:52:00Z',
  },
  'INC-1002': {
    title: 'Command & control beaconing',
    summary:
      'Beacon-like traffic to a known C2 destination and a large outbound transfer from a related finance host.',
    status: 'active',
    confidence: 91,
    openedAt: '2026-09-14T00:06:00Z',
  },
  'INC-1003': {
    title: 'Credential access cluster',
    summary:
      'Brute-force burst, a successful sign-in from a new location, and access to sensitive credential stores around the same account.',
    status: 'investigating',
    confidence: 76,
    openedAt: '2026-09-13T18:02:00Z',
  },
  'INC-1004': {
    title: 'Persistence setup on endpoints',
    summary:
      'Deobfuscated script execution followed by a registry run-key change on the same endpoints, consistent with a persistence attempt.',
    status: 'resolved',
    confidence: 68,
    openedAt: '2026-09-13T09:10:00Z',
  },
}

function buildIncidents(): Incident[] {
  return Object.entries(meta).map(([id, record]) => {
    const related = mockAlerts.filter((alert) => alert.relatedIncidentId === id)
    const highest = related
      .map((alert) => alert.severity)
      .sort((a, b) => severityRank[b] - severityRank[a])[0] ?? 'low'
    const techniques = [...new Set(related.flatMap((alert) => alert.mitreTechniques))]
    const updatedAt = related
      .map((alert) => alert.timestamp)
      .sort()
      .at(-1) ?? record.openedAt

    return {
      id,
      title: record.title,
      summary: record.summary,
      severity: highest,
      status: record.status,
      confidence: record.confidence,
      openedAt: record.openedAt,
      updatedAt,
      alertIds: related.map((alert) => alert.id),
      mitreTechniques: techniques,
    }
  })
}

export const mockIncidents: Incident[] = buildIncidents()