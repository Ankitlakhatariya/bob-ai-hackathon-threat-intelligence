import { useCallback, useEffect, useState } from 'react'
import type { Alert } from '../types/alert'
import { fetchAlerts } from '../services/mockApi'

export function useAlerts() {
  const [alerts, setAlerts] = useState<Alert[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let active = true
    setError(null)
    fetchAlerts()
      .then((data) => {
        if (active) setAlerts(data)
      })
      .catch(() => {
        if (active) setError('Could not load alerts (simulated failure).')
      })
    return () => {
      active = false
    }
  }, [attempt])

  const refetch = useCallback(() => setAttempt((current) => current + 1), [])

  return { alerts, loading: alerts === null && error === null, error, refetch }
}