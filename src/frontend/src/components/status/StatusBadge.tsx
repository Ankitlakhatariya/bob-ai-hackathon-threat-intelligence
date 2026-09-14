import type { AlertStatus } from '../../types/alert'

const styles: Record<AlertStatus, string> = {
  open: 'border-low/40 bg-low/15 text-low',
  investigating: 'border-medium/40 bg-medium/15 text-medium',
  resolved: 'border-safe/40 bg-safe/15 text-safe',
  'false-positive': 'border-foreground-muted/40 bg-surface-2 text-foreground-muted',
}

const labels: Record<AlertStatus, string> = {
  open: 'Open',
  investigating: 'Investigating',
  resolved: 'Resolved',
  'false-positive': 'False positive',
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${styles[status]}`}
    >
      {labels[status]}
    </span>
  )
}