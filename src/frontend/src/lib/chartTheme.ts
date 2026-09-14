import type { AlertStatus, Severity } from '../types/alert'
import type { IncidentStatus } from '../types/incident'

/**
 * Shared colour tokens for Recharts. Accent, grid and tick resolve to theme
 * variables so charts adapt to dark/light mode; severity hues stay fixed so
 * risk coding is consistent across themes.
 */
export const chartColors = {
  accent: 'var(--accent)',
  grid: 'var(--border)',
  tick: 'var(--foreground-muted)',
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  safe: '#22c55e',
  muted: '#64748b',
}

export const severityColors: Record<Severity, string> = {
  critical: chartColors.critical,
  high: chartColors.high,
  medium: chartColors.medium,
  low: chartColors.low,
}

export const statusColors: Record<AlertStatus, string> = {
  open: chartColors.low,
  investigating: chartColors.medium,
  resolved: chartColors.safe,
  'false-positive': chartColors.muted,
}

export const incidentStatusColors: Record<IncidentStatus, string> = {
  active: chartColors.critical,
  investigating: chartColors.medium,
  resolved: chartColors.safe,
}