import { getAccessToken, clearAuthSession } from '../lib/authSession'

export class ApiError extends Error {
  public status: number
  public details?: any
  public retryAfter?: number

  constructor(status: number, message: string, details?: any, retryAfter?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.details = details
    this.retryAfter = retryAfter
  }
}

// Configurable base URL: In Vite dev mode, empty string uses the Vite proxy (/api -> localhost:8000).
// In production or custom environments, VITE_API_BASE_URL can point directly to the backend.
const ENV_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL
const BASE_URL = ENV_BASE_URL !== undefined ? ENV_BASE_URL : ''

interface RequestOptions extends RequestInit {
  retry?: number
  retryDelay?: number
}

/**
 * Universal JSON API request dispatcher with error handling, authentication,
 * and retry capability for transient network/server failures.
 */
async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { retry = 2, retryDelay = 500, ...fetchOptions } = options
  const token = getAccessToken()

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(fetchOptions.headers as Record<string, string> || {}),
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const url = `${BASE_URL}${endpoint}`

  let lastError: any = null
  for (let attempt = 0; attempt <= (fetchOptions.method && fetchOptions.method !== 'GET' ? 0 : retry); attempt++) {
    try {
      const response = await fetch(url, {
        ...fetchOptions,
        headers,
      })

      if (!response.ok) {
        // 401: Unauthorized
        if (response.status === 401) {
          clearAuthSession()
          // Only redirect if not already on the login or public landing page
          if (typeof window !== 'undefined' && !['/login', '/'].includes(window.location.pathname)) {
            window.location.href = '/login'
          }
          throw new ApiError(401, 'Authentication required or session expired')
        }

        // Parse structured error responses from FastAPI
        let message = 'An error occurred'
        let details: any = null
        let retryAfter: number | undefined

        const retryAfterHeader = response.headers.get('Retry-After')
        if (retryAfterHeader) {
          const parsed = parseInt(retryAfterHeader, 10)
          if (!isNaN(parsed)) retryAfter = parsed
        }

        try {
          const data = await response.json()
          details = data
          if (typeof data.detail === 'string') {
            message = data.detail
          } else if (Array.isArray(data.detail)) {
            // FastAPI 422 validation errors
            message = data.detail.map((err: any) => err.msg || `${err.loc?.join('.')}: invalid`).join(', ')
          } else if (data.detail && typeof data.detail === 'object') {
            if (data.detail.error?.message) message = data.detail.error.message
            else if (data.detail.message) message = data.detail.message
            else message = JSON.stringify(data.detail)
          } else if (data.error && data.error.message) {
            message = data.error.message
          } else if (data.message) {
            message = data.message
          }
        } catch {
          message = response.statusText || `HTTP error ${response.status}`
        }

        // Formulate friendly status-specific messages if generic
        if (response.status === 403 && message === 'An error occurred') {
          message = 'Access forbidden: your user role does not have permission for this action'
        } else if (response.status === 404 && message === 'An error occurred') {
          message = 'Requested resource not found'
        } else if (response.status === 429 && message === 'An error occurred') {
          message = retryAfter
            ? `Too many requests. Please retry in ${retryAfter} seconds.`
            : 'Rate limit reached. Please slow down.'
        } else if (response.status >= 500 && message === 'An error occurred') {
          message = 'Internal server error. Please retry shortly.'
        }

        const apiErr = new ApiError(response.status, message, details, retryAfter)

        // Retry on 502/503/504 or 429 if attempts remain and request is idempotent
        if (
          attempt < retry &&
          (!fetchOptions.method || fetchOptions.method === 'GET') &&
          [502, 503, 504].includes(response.status)
        ) {
          await new Promise((r) => setTimeout(r, retryDelay * Math.pow(2, attempt)))
          continue
        }

        throw apiErr
      }

      if (response.status === 204) {
        return {} as T
      }

      return await response.json()
    } catch (err: any) {
      lastError = err
      if (err instanceof ApiError) {
        throw err
      }
      // Network failure retry for GET requests
      if (attempt < retry && (!fetchOptions.method || fetchOptions.method === 'GET')) {
        await new Promise((r) => setTimeout(r, retryDelay * Math.pow(2, attempt)))
        continue
      }
      throw new ApiError(0, err.message || 'Network connection failed. Is the backend running?')
    }
  }

  throw lastError
}

// ============================================================================
// 1. Authentication
// ============================================================================

export async function login(email: string, password: string) {
  return request<any>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
}

export async function register(payload: { email: string; password: string; full_name?: string; role?: string }) {
  return request<any>('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function getAuthMe() {
  return request<any>('/api/v1/auth/me')
}

export async function refreshAuthToken(refreshToken: string) {
  return request<any>('/api/v1/auth/refresh', {
    method: 'POST',
    body: JSON.stringify({ refresh_token: refreshToken }),
  })
}

export async function logoutUser() {
  return request<any>('/api/v1/auth/logout', { method: 'POST' })
}

// ============================================================================
// 2. Dashboard
// ============================================================================

export async function getDashboardOverview() {
  return request<any>('/api/v1/dashboard/overview')
}

export async function getAlertTrends(_range: string = '24h') {
  return request<any[]>('/api/v1/dashboard/alert-trends')
}

export async function getThreatTrends() {
  return request<any[]>('/api/v1/dashboard/threat-trends')
}

export async function getSeverityDistribution() {
  return request<any[]>('/api/v1/dashboard/severity-distribution')
}

export async function getTopTechniques() {
  return request<any[]>('/api/v1/dashboard/top-techniques')
}

export async function getRecentThreats() {
  return request<any[]>('/api/v1/dashboard/recent-threats')
}

export async function getSystemStatus() {
  return request<any[]>('/api/v1/dashboard/system-status')
}

// ============================================================================
// 3. Alerts
// ============================================================================

export async function getAlerts(params?: Record<string, string>) {
  const qs = params ? new URLSearchParams(params).toString() : ''
  return request<any[]>(`/api/v1/alerts${qs ? '?' + qs : ''}`)
}

export async function getAlert(id: string) {
  return request<any>(`/api/v1/alerts/${encodeURIComponent(id)}`)
}

export async function createAlert(payload: any) {
  return request<any>('/api/v1/alerts', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function bulkIngestAlerts(alerts: any[]) {
  return request<any>('/api/v1/alerts/bulk', {
    method: 'POST',
    body: JSON.stringify(alerts),
  })
}

export async function getRelatedAlerts(id: string) {
  return request<any[]>(`/api/v1/alerts/${encodeURIComponent(id)}/related`)
}

export async function updateAlert(id: string, payload: any) {
  return request<any>(`/api/v1/alerts/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export async function deleteAlert(id: string) {
  return request<any>(`/api/v1/alerts/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })
}

// ============================================================================
// 4. Threats / Incidents
// ============================================================================

export async function getThreats(params?: Record<string, string>) {
  const qs = params ? new URLSearchParams(params).toString() : ''
  return request<any[]>(`/api/v1/threats${qs ? '?' + qs : ''}`)
}

export async function getThreat(id: string) {
  return request<any>(`/api/v1/threats/${encodeURIComponent(id)}`)
}

export async function getThreatAlerts(id: string) {
  return request<any[]>(`/api/v1/threats/${encodeURIComponent(id)}/alerts`)
}

export async function getThreatTimeline(id: string) {
  return request<any[]>(`/api/v1/threats/${encodeURIComponent(id)}/timeline`)
}

export async function getThreatRisk(id: string) {
  return request<any>(`/api/v1/threats/${encodeURIComponent(id)}/risk`)
}

export async function getThreatMitre(id: string) {
  return request<any[]>(`/api/v1/threats/${encodeURIComponent(id)}/mitre`)
}

export async function getPrioritizedThreats(params?: Record<string, string>) {
  const qs = params ? new URLSearchParams(params).toString() : ''
  return request<any[]>(`/api/v1/threats/prioritized${qs ? '?' + qs : ''}`)
}

export async function triggerCorrelation() {
  return request<any>('/api/v1/threats/correlate', { method: 'POST' })
}

// ============================================================================
// 5. Investigations
// ============================================================================

export async function getInvestigations(params?: Record<string, string>) {
  const qs = params ? new URLSearchParams(params).toString() : ''
  return request<any[]>(`/api/v1/investigations${qs ? '?' + qs : ''}`)
}

export async function getInvestigation(id: string) {
  return request<any>(`/api/v1/investigations/${encodeURIComponent(id)}`)
}

export async function createInvestigation(payload: any) {
  return request<any>('/api/v1/investigations', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function updateInvestigation(id: string, payload: any) {
  return request<any>(`/api/v1/investigations/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

// ============================================================================
// 6. Threat Intelligence
// ============================================================================

export async function getIndicators(params?: Record<string, string>) {
  const qs = params ? new URLSearchParams(params).toString() : ''
  return request<any[]>(`/api/v1/intelligence/indicators${qs ? '?' + qs : ''}`)
}

export async function getIndicator(id: string) {
  return request<any>(`/api/v1/intelligence/indicators/${encodeURIComponent(id)}`)
}

export async function lookupIndicator(indicator: string) {
  return request<any>(`/api/v1/intelligence/lookup/${encodeURIComponent(indicator)}`)
}

export async function createIndicator(payload: any) {
  return request<any>('/api/v1/intelligence/indicators', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

// ============================================================================
// 7. MITRE ATT&CK
// ============================================================================

export async function getMitreTactics() {
  return request<any[]>('/api/v1/mitre/tactics')
}

export async function getMitreTechniques(params?: Record<string, string>) {
  const qs = params ? new URLSearchParams(params).toString() : ''
  return request<any[]>(`/api/v1/mitre/techniques${qs ? '?' + qs : ''}`)
}

export async function getMitreTechnique(id: string) {
  return request<any>(`/api/v1/mitre/techniques/${encodeURIComponent(id)}`)
}

// ============================================================================
// 8. BLUF Briefs
// ============================================================================

export async function getBlufReports() {
  return request<Record<string, any>>('/api/v1/bluf')
}

export async function getBlufReport(threatId: string) {
  return request<any>(`/api/v1/bluf/${encodeURIComponent(threatId)}`)
}

export async function generateBluf(threatId: string) {
  return request<any>(`/api/v1/bluf/${encodeURIComponent(threatId)}/generate`, {
    method: 'POST',
  })
}

// ============================================================================
// 9. AI / LLM Threat Analysis
// ============================================================================

export async function analyzeThreatAI(threatId: string) {
  return request<any>(`/api/v1/ai/analyze-threat/${encodeURIComponent(threatId)}`, {
    method: 'POST',
  })
}

export async function getThreatAnalysisHistory(threatId: string) {
  return request<any[]>(`/api/v1/threats/${encodeURIComponent(threatId)}/analysis`)
}

