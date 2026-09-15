import type { Severity } from './alert'

export type IncidentStatus = 'active' | 'investigating' | 'resolved'

/**
 * A correlated incident groups related alerts into a potential security incident.
 */
export interface Incident {
  id: string
  threat_id?: string
  threatId?: string
  title: string
  summary: string
  description?: string
  explanation?: string
  severity: Severity
  status: IncidentStatus
  /** 0–100 correlation confidence. */
  confidence: number
  risk_score?: number
  riskScore?: number
  openedAt?: string
  opened_at?: string
  updatedAt?: string
  updated_at?: string
  first_seen?: string
  last_seen?: string
  /** IDs of the alerts correlated into this incident. */
  alertIds?: string[]
  alert_ids?: string[]
  /** MITRE ATT&CK technique IDs across the group. */
  mitreTechniques?: string[]
  mitre_techniques?: string[]
  affectedAssets?: string[]
  affected_assets?: string[]
  alertCount?: number
  alert_count?: number
}