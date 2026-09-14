import type { Alert, TrendPoint, TrendRange } from '../types/alert'
import type { Incident } from '../types/incident'
import { mockAlerts, trendData } from '../data/mockAlerts'
import { mockIncidents } from '../data/mockIncidents'

/**
 * Frontend data-access layer.
 *
 * Current state: MOCK implementation. Every function returns a Promise with a
 * short simulated latency so the UI exercises real loading states.
 *
 * FUTURE INTEGRATION (backend team): replace the body of each function with a
 * fetch() call to the matching endpoint. Endpoints below are the proposed REST
 * contract — keep their return shapes compatible with `src/types/alert.ts`.
 */

const LATENCY_MS = 500

function delay<T>(value: T, ms = LATENCY_MS): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms))
}

/**
 * GET /api/alerts
 * Response: Alert[] (future: ListEnvelope<Alert>)
 */
export function fetchAlerts(): Promise<Alert[]> {
  return delay(mockAlerts)
}

/**
 * GET /api/alerts/trend?range=24h|7d|30d
 * Response: TrendPoint[]
 */
export function fetchTrend(range: TrendRange): Promise<TrendPoint[]> {
  return delay(trendData[range], 300)
}

/**
 * GET /api/incidents
 * Response: Incident[]
 */
export function fetchIncidents(): Promise<Incident[]> {
  return delay(mockIncidents)
}

/** Convenience export so pages can map incident IDs to titles. */
export { incidentTitles } from '../data/mockAlerts'