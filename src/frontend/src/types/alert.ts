/**
 * Alert data contracts.
 *
 * These types define the shape of alert data used across the frontend and are
 * the expected contract for the future backend API. Mock sources in
 * `src/data/mockAlerts.ts` implement them today.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low'

/** Lifecycle of an alert as displayed in the product. */
export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'false-positive'

export type AlertSource = 'siem' | 'edr' | 'network-sensor' | 'threat-feed'

export interface Alert {
  /** Stable identifier, e.g. "ALERT-2041". */
  id: string
  teamId: string
  title: string
  description: string
  source: AlertSource
  /** Human-readable source label, e.g. "EDR Endpoint Agent". */
  sourceLabel: string
  /** ISO 8601 timestamp of first detection. */
  timestamp: string
  severity: Severity
  status: AlertStatus
  /** 0–100 risk score; higher = more urgent. Demo-derived, not from a real model. */
  riskScore: number
  /** Incident this alert is correlated into, if any. */
  relatedIncidentId: string | null
  /** MITRE ATT&CK technique IDs. Mappings are demo data until the AI/backend team provides results. */
  mitreTechniques: string[]
  /** Sample indicators (addresses/hashes). Uses reserved, non-routable example values only. */
  indicators: string[]
}

export type TrendRange = '24h' | '7d' | '30d'

export interface TrendPoint {
  label: string
  alerts: number
  incidents: number
}

export interface DashboardSummary {
  totalOpen: number
  critical: number
  incidentCount: number
  falsePositiveReview: number
}

export interface SystemStatus {
  id: string
  name: string
  detail: string
  health: 'operational' | 'degraded' | 'healthy'
}

/**
 * Envelope a future REST API should return for list endpoints.
 * Kept as the documented contract; mock services return data directly.
 */
export interface ListEnvelope<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

/**
 * Error shape a future REST API should return for failures.
 * Kept as the documented contract for the backend team.
 */
export interface ApiErrorBody {
  error: {
    code: string
    message: string
    details?: string
  }
}