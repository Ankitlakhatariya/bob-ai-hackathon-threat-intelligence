import type { Alert, DashboardSummary, Severity } from '../types/alert'

const OPEN_STATUSES = new Set(['open', 'investigating'])

export function computeSummary(alerts: Alert[]): DashboardSummary {
  const totalOpen = alerts.filter((alert) => OPEN_STATUSES.has(alert.status)).length
  const critical = alerts.filter(
    (alert) => alert.severity === 'critical' && OPEN_STATUSES.has(alert.status),
  ).length
  const incidentIds = new Set(
    alerts.map((alert) => alert.relatedIncidentId).filter((id): id is string => id !== null),
  )
  const falsePositiveReview = alerts.filter(
    (alert) => alert.severity === 'low' && alert.status === 'open',
  ).length

  return { totalOpen, critical, incidentCount: incidentIds.size, falsePositiveReview }
}

export function severityDistribution(alerts: Alert[]): Array<{ severity: Severity; count: number }> {
  const order: Severity[] = ['critical', 'high', 'medium', 'low']
  return order.map((severity) => ({
    severity,
    count: alerts.filter((alert) => alert.severity === severity).length,
  }))
}