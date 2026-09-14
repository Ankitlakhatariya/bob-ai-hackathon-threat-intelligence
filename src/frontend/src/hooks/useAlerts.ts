import { useCallback, useEffect, useState } from 'react'
import type { Alert } from '../types/alert'
import { getAlerts, ApiError } from '../services/apiClient'

export function useAlerts(params?: Record<string, string>) {
  const [alerts, setAlerts] = useState<any[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let active = true
    setError(null)
    getAlerts(params)
      .then((data) => {
        if (active) setAlerts(data)
      })
      .catch((err: any) => {
        if (active) setError(err.message || 'Could not load alerts.')
      })
    return () => {
      active = false
    }
  }, [attempt, JSON.stringify(params)])

  const refetch = useCallback(() => setAttempt((current) => current + 1), [])

  return { alerts, loading: alerts === null && error === null, error, refetch }
}