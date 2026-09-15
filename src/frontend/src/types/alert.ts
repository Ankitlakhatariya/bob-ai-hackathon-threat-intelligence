/**
 * Alert data contracts.
 *
 * These types define the shape of alert data used across the frontend and are
 * the expected contract for the backend API.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low'

/** Lifecycle of an alert as displayed in the product. */
export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'false-positive'

export type AlertSource = 'siem' | 'edr' | 'network-sensor' | 'threat-feed'

export interface Alert {
  /** Stable identifier, e.g. "ALERT-2041". */
  id: string
  teamId?: string
  team_id?: string
  title: string
  description: string
  source: AlertSource
  /** Human-readable source label, e.g. "EDR Endpoint Agent". */
  sourceLabel?: string
  source_label?: string
  /** ISO 8601 timestamp of first detection. */
  timestamp: string
  severity: Severity
  status: AlertStatus
  /** 0–100 risk score; higher = more urgent. */
  riskScore: number
  risk_score?: number
  /** Incident this alert is correlated into, if any. */
  relatedIncidentId?: string | null
  related_threat_id?: string | null
  /** MITRE ATT&CK technique IDs. */
  mitreTechniques?: string[]
  mitre_techniques?: string[]
  /** Sample indicators (addresses/hashes). */
  indicators: string[]
  rawData?: any
  raw_data?: any
  hostname?: string
  username?: string
  source_ip?: string
  destination_ip?: string
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
  total_open?: number
  false_positive_review?: number
  incident_count?: number
}

export interface SystemStatus {
  id: string
  name: string
  detail: string
  health: 'operational' | 'degraded' | 'healthy'
}

/**
 * Envelope a REST API returns for list endpoints.
 */
export interface ListEnvelope<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

/**
 * Error shape a REST API returns for failures.
 */
export interface ApiErrorBody {
  error: {
    code: string
    message: string
    details?: string
  }
}