import type { Severity } from './alert'

export type IncidentStatus = 'active' | 'investigating' | 'resolved'

/**
 * A correlated incident groups related alerts into a potential security
 * incident. Confidence is a clearly labelled demo value until the AI/backend
 * team provides real correlation results.
 */
export interface Incident {
  id: string
  title: string
  summary: string
  severity: Severity
  status: IncidentStatus
  /** 0–100 demo correlation confidence; not from a real model. */
  confidence: number
  openedAt: string
  updatedAt: string
  /** IDs of the alerts correlated into this incident. */
  alertIds: string[]
  /** MITRE ATT&CK technique IDs across the group (demo mappings). */
  mitreTechniques: string[]
}