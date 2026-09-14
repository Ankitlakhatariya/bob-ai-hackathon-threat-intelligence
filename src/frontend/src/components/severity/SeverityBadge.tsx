import type { Severity } from '../../types/alert'

const styles: Record<Severity, string> = {
  critical: 'border-critical/40 bg-critical/15 text-critical',
  high: 'border-high/40 bg-high/15 text-high',
  medium: 'border-medium/40 bg-medium/15 text-medium',
  low: 'border-low/40 bg-low/15 text-low',
}

const labels: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${styles[severity]}`}
    >
      {labels[severity]}
    </span>
  )
}